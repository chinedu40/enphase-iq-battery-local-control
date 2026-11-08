"""Request a local gateway JWT using Enphase's published cloud login recipe.

Protocol: https://enphase.com/fr-fr/media/8802 and pyenphase v4.0.6 auth.py.
The caller decides whether to retain account credentials and must validate the
returned JWT against the pinned gateway. Decoded JWT claims are unverified hints.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import ssl
from datetime import UTC, datetime
from typing import Any

import aiohttp

_LOGIN_URL = "https://enlighten.enphaseenergy.com/login/login.json?"
_TOKEN_URL = "https://entrez.enphaseenergy.com/tokens"
_MAX_RESPONSE_BYTES = 128 * 1024
_MAX_TOKEN_CHARACTERS = 32 * 1024
_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10.0)


class CloudAuthError(Exception):
    """A cloud authentication failure with a safe, credential-free message."""


class CloudInvalidAuth(CloudAuthError):
    """Enphase rejected the supplied account credentials."""


class CloudMFARequired(CloudAuthError):
    """The automatic recipe needs browser sign-in or additional verification."""


class CloudCommunicationError(CloudAuthError):
    """The public Enphase authentication service could not be reached."""


class CloudTokenError(CloudAuthError):
    """Enphase did not return a usable JWT for the requested gateway."""


def _interactive_sign_in() -> CloudMFARequired:
    return CloudMFARequired(
        "Enphase requires browser sign-in or additional verification. "
        "Obtain a gateway token in the Enphase token portal and enter it manually."
    )


async def _post(
    session: aiohttp.ClientSession,
    url: str,
    *,
    data: dict[str, str] | None = None,
    payload: dict[str, str] | None = None,
) -> tuple[int, bytes, bool]:
    """Make exactly one bounded POST with normal public certificate verification."""
    try:
        async with session.post(
            url,
            data=data,
            json=payload,
            headers={"Accept": "application/json"},
            ssl=True,
            allow_redirects=False,
            raise_for_status=False,
            timeout=_REQUEST_TIMEOUT,
        ) as response:
            if (
                response.content_length is not None
                and response.content_length > _MAX_RESPONSE_BYTES
            ):
                raise CloudTokenError("The Enphase authentication response was too large.")
            body = bytearray()
            async for chunk in response.content.iter_chunked(16 * 1024):
                body.extend(chunk)
                if len(body) > _MAX_RESPONSE_BYTES:
                    raise CloudTokenError("The Enphase authentication response was too large.")
            content_type = response.headers.get("Content-Type", "").lower()
            is_html = "text/html" in content_type or body.lstrip().startswith(b"<")
            return response.status, bytes(body), is_html
    except (TimeoutError, aiohttp.ClientError, OSError, ssl.SSLError, RuntimeError):
        raise CloudCommunicationError(
            "Could not connect securely to Enphase. Check internet access and try again later."
        ) from None


def _check_status(status: int) -> None:
    if 300 <= status < 400:
        raise _interactive_sign_in()
    if status in (400, 401, 403):
        raise CloudInvalidAuth(
            "Enphase rejected the sign-in request. Check the account details, "
            "or enter a token manually if the account requires additional verification."
        )
    if status == 429 or status >= 500:
        raise CloudCommunicationError(
            "Enphase authentication is temporarily unavailable. Try again later."
        )
    if status != 200:
        raise CloudTokenError("Enphase did not return a usable authentication response.")


def _login_session(raw: bytes, *, is_html: bool) -> str:
    if is_html:
        raise _interactive_sign_in()
    try:
        reply = json.loads(raw)
    except (UnicodeError, ValueError, RecursionError):
        raise CloudTokenError("Enphase returned an invalid sign-in response.") from None
    if not isinstance(reply, dict):
        raise CloudTokenError("Enphase returned an invalid sign-in response.")
    # The published recipe requires session_id. MFA sign-ins may omit it; do not
    # invent a challenge exchange or encourage disabling account protection.
    session_id = reply.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip() or len(session_id) > 4096:
        raise _interactive_sign_in()
    return session_id


def _decode_segment(segment: str) -> Any:
    encoded = segment.encode("ascii")
    encoded += b"=" * (-len(encoded) % 4)
    return json.loads(base64.b64decode(encoded, altchars=b"-_", validate=True))


def _token_hint_checks(raw: bytes, serial: str, *, is_html: bool) -> str:
    if is_html:
        raise _interactive_sign_in()
    try:
        token = raw.decode("utf-8").strip()
        if len(token) > _MAX_TOKEN_CHARACTERS or not re.fullmatch(
            r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token
        ):
            raise ValueError
        header, claims = (_decode_segment(part) for part in token.split(".")[:2])
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise ValueError
        expiry = claims.get("exp")
        if isinstance(expiry, bool) or not isinstance(expiry, (int, float)):
            raise ValueError
        if not math.isfinite(expiry):
            raise ValueError
        expires_at = datetime.fromtimestamp(expiry, tz=UTC)
        if expires_at <= datetime.now(UTC):
            raise ValueError
        if "aud" in claims:
            audience = claims["aud"]
            if isinstance(audience, str):
                if audience != serial:
                    raise ValueError
            elif (
                not isinstance(audience, list)
                or not all(isinstance(item, str) for item in audience)
                or serial not in audience
            ):
                raise ValueError
    except (UnicodeError, ValueError, binascii.Error, RecursionError, OverflowError, OSError):
        raise CloudTokenError(
            "Enphase did not return a current token for this gateway. "
            "Obtain a gateway token in the Enphase token portal."
        ) from None
    return token


async def request_gateway_token(
    session: aiohttp.ClientSession, username: str, password: str, serial: str
) -> str:
    """Return one new local JWT, without retaining credentials or retrying POSTs.

    The caller must supply an ordinary public-HTTPS session, never a session with
    custom gateway authentication headers or certificate settings. No account
    credentials, response bodies, session identifiers or JWTs are logged.
    """
    if not isinstance(serial, str) or re.fullmatch(r"[0-9]{12}", serial) is None:
        raise CloudTokenError("Enter the gateway's 12-digit serial number.")
    if (
        not isinstance(username, str)
        or not username.strip()
        or not isinstance(password, str)
        or not password
    ):
        raise CloudInvalidAuth("Enter the Enphase account username and password.")
    username = username.strip()
    status, raw, is_html = await _post(
        session,
        _LOGIN_URL,
        data={"user[email]": username, "user[password]": password},
    )
    _check_status(status)
    session_id = _login_session(raw, is_html=is_html)
    status, raw, is_html = await _post(
        session,
        _TOKEN_URL,
        payload={"session_id": session_id, "serial_num": serial, "username": username},
    )
    _check_status(status)
    return _token_hint_checks(raw, serial, is_html=is_html)
