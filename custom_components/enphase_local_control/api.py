"""Local-only, authenticated IQ Gateway transport.

The gateway validates the supplied token.  Decoded JWT dates below are unverified
display hints, not proof of authentication or permission to control a gateway.
The caller owns the aiohttp session, command serialization and release policy.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import math
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree

import aiohttp

_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_JWT_PAYLOAD_BYTES = 16 * 1024


class EnphaseApiError(Exception):
    """An error whose message is safe to show without exposing credentials."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class AuthenticationError(EnphaseApiError):
    """The gateway rejected the access token."""


class PermissionDeniedError(EnphaseApiError):
    """The authenticated user lacks access to the requested resource."""


class CommunicationError(EnphaseApiError):
    """The gateway could not be reached or did not answer in time."""


class InvalidResponseError(EnphaseApiError):
    """The gateway returned an unexpected status, format or schema."""


class CertificateError(EnphaseApiError):
    """The gateway certificate could not be verified or did not match its pin."""


class CommandError(EnphaseApiError):
    """The command was rejected or its acknowledgement did not match."""


@dataclass(frozen=True, slots=True)
class TokenMetadata:
    """Unverified token dates; only the gateway can establish token validity."""

    expires_at: datetime | None = None
    issued_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class GatewayIdentity:
    """Identity fields advertised by the local info.xml response."""

    serial: str | None = None
    model: str | None = None
    firmware: str | None = None


def _jwt_date(value: object) -> datetime | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        if not math.isfinite(value):
            return None
        return datetime.fromtimestamp(value, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def decode_token_metadata(token: str) -> TokenMetadata:
    """Read only exp/iat hints without verifying or retaining other claims."""
    parts = token.split(".")
    if len(parts) != 3 or len(parts[1]) > _MAX_JWT_PAYLOAD_BYTES:
        return TokenMetadata()
    try:
        payload = parts[1].encode("ascii")
        payload += b"=" * (-len(payload) % 4)
        decoded = base64.b64decode(payload, altchars=b"-_", validate=True)
        claims = json.loads(decoded)
    except (UnicodeError, ValueError, binascii.Error, RecursionError):
        return TokenMetadata()
    if not isinstance(claims, dict):
        return TokenMetadata()
    return TokenMetadata(
        expires_at=_jwt_date(claims.get("exp")),
        issued_at=_jwt_date(claims.get("iat")),
    )


def _base_url(host: str) -> str:
    """Accept an HTTPS host/authority, never credentials, paths or HTTP."""
    if not isinstance(host, str):
        raise ValueError("Enter the local gateway host name or IP address.")
    value = host.strip()
    if not value or any(character.isspace() for character in value):
        raise ValueError("Enter the local gateway host name or IP address.")
    # An unbracketed IPv6 literal has no port; urlsplit needs brackets.
    if "://" not in value:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            if address.version == 6:
                value = f"[{value}]"
        value = "https://" + value
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("Enter a valid local gateway host and port.") from None
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or "\\" in parsed.netloc
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("Use an HTTPS gateway host without a path or credentials.")
    return "https://" + parsed.netloc.rstrip("/")


def _fingerprint(value: str | None) -> aiohttp.Fingerprint | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CertificateError("The SHA-256 certificate fingerprint is invalid.")
    normalized = re.sub(r"[:\s]", "", value)
    if not re.fullmatch(r"[0-9a-fA-F]{64}", normalized):
        raise CertificateError("The SHA-256 certificate fingerprint is invalid.")
    return aiohttp.Fingerprint(bytes.fromhex(normalized))


def _integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class GatewayClient:
    """Use a caller-owned session to access one local HTTPS gateway.

    No request follows redirects, disables certificate verification, calls a
    cloud endpoint or retries a command.  A previously trusted certificate pin may be provided by
    the caller; without one, aiohttp uses normal certificate trust verification.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        token: str,
        *,
        fingerprint: str | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._session = session
        self._base_url = _base_url(host)
        self.replace_token(token)
        self._ssl = _fingerprint(fingerprint)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("The request timeout must be a positive number.")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("The request timeout must be a positive number.")
        self._timeout = aiohttp.ClientTimeout(total=float(timeout))

    def replace_token(self, token: str) -> None:
        """Replace credentials after a separately validated renewal; send no request."""
        if not isinstance(token, str) or not token.strip() or "\r" in token or "\n" in token:
            raise AuthenticationError("Provide a single-line gateway access token.")
        self._token = token.strip()
        self.token_metadata = decode_token_metadata(self._token)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        authenticated: bool = True,
    ) -> bytes:
        try:
            async with self._session.request(
                method,
                self._base_url + path,
                headers={
                    **({"Authorization": "Bearer " + self._token} if authenticated else {}),
                    "Accept": "application/json, application/xml;q=0.9",
                },
                json=payload,
                timeout=self._timeout,
                ssl=self._ssl,
                allow_redirects=False,
                raise_for_status=False,
            ) as response:
                self._check_status(response.status, method)
                if (
                    response.content_length is not None
                    and response.content_length > _MAX_RESPONSE_BYTES
                ):
                    raise InvalidResponseError("The gateway response was too large.")
                body = bytearray()
                async for chunk in response.content.iter_chunked(16 * 1024):
                    body.extend(chunk)
                    if len(body) > _MAX_RESPONSE_BYTES:
                        raise InvalidResponseError("The gateway response was too large.")
                return bytes(body)
        except (
            aiohttp.ServerFingerprintMismatch,
            aiohttp.ClientConnectorCertificateError,
            aiohttp.ClientConnectorSSLError,
            ssl.SSLError,
        ):
            raise CertificateError("The gateway certificate could not be verified.") from None
        except (TimeoutError, aiohttp.ClientError, OSError):
            raise CommunicationError("The local gateway did not respond successfully.") from None

    @staticmethod
    def _check_status(status: int, method: str) -> None:
        if status == 401:
            raise AuthenticationError("The gateway access token was rejected.", status=status)
        if status == 403:
            raise PermissionDeniedError(
                "The gateway denied access to this resource.", status=status
            )
        if 200 <= status < 300:
            return
        if method == "POST":
            raise CommandError("The gateway did not acknowledge the command.", status=status)
        if status >= 500:
            raise CommunicationError("The gateway reported a server error.", status=status)
        raise InvalidResponseError(
            "The gateway returned an unexpected HTTP status.", status=status
        )

    async def _json(
        self, method: str, path: str, *, payload: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        raw = await self._request(method, path, payload=payload)
        try:
            result = json.loads(raw)
        except (UnicodeError, ValueError, RecursionError):
            raise InvalidResponseError("The gateway returned invalid JSON.") from None
        if not isinstance(result, dict):
            raise InvalidResponseError("The gateway returned an invalid JSON object.")
        return result

    async def get_scheduler(self) -> dict[str, Any]:
        """Read modes, retaining unknown codes so an override can be released."""
        data = await self._json("GET", "/ivp/sc/sched")
        current = data.get("acb_current_mode")
        debug = data.get("acb_debug_mode")
        labels = data.get("sched_mode_key")
        if (
            not _integer(current)
            or not _integer(debug)
            or not isinstance(labels, list)
            or not labels
            or not all(isinstance(label, str) and label.strip() for label in labels)
            or not 0 <= current <= 255
            or not -1 <= debug <= 255
        ):
            raise InvalidResponseError("The gateway returned invalid scheduler fields.")
        return data

    async def set_override(self, mode: int) -> dict[str, Any]:
        """Send one override request; the caller must verify and restore it."""
        if not _integer(mode) or not -1 <= mode <= 255:
            raise CommandError("The requested override mode is invalid.")
        data = await self._json("POST", "/ivp/sc/sched", payload={"acb_debug_mode": mode})
        acknowledged = data.get("acb_debug_mode")
        if not _integer(acknowledged) or acknowledged != mode:
            raise CommandError("The gateway acknowledgement did not match the requested mode.")
        return data

    async def get_status(self) -> dict[str, Any]:
        """Read optional secondary-control telemetry without changing settings."""
        return await self._json("GET", "/ivp/sc/status")

    async def get_info(self, *, authenticated: bool = True) -> GatewayIdentity:
        """Read optional identity metadata; unavailable info raises a safe error."""
        raw = await self._request("GET", "/info.xml", authenticated=authenticated)
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
            raise InvalidResponseError("The gateway returned unsupported XML content.")
        try:
            root = ElementTree.fromstring(raw)
        except (ElementTree.ParseError, ValueError, LookupError):
            raise InvalidResponseError("The gateway returned invalid identity XML.") from None
        if root.tag.rsplit("}", 1)[-1] != "envoy_info":
            raise InvalidResponseError("The gateway returned invalid identity fields.")
        # Handle optional XML namespaces without changing the advertised values.
        for element in root.iter():
            element.tag = element.tag.rsplit("}", 1)[-1]

        def text_at(*paths: str) -> str | None:
            for path in paths:
                text = root.findtext(path)
                if text and text.strip():
                    return text.strip()
            return None

        return GatewayIdentity(
            serial=text_at("device/sn", "device/serial_number", "device/serialNumber"),
            model=text_at("device/model", "device/pn", "device/part_number"),
            firmware=text_at("device/software", "device/software_version"),
        )


async def async_get_gateway_identity(
    session: aiohttp.ClientSession, host: str, *, fingerprint: str
) -> GatewayIdentity:
    """Read public identity over an already trusted pin without any JWT header."""
    # Reuse the bounded transport/XML parser. This inert placeholder is never
    # transmitted: authenticated=False omits Authorization entirely.
    client = GatewayClient(session, host, "public-metadata-read", fingerprint=fingerprint)
    return await client.get_info(authenticated=False)


# Earlier design notes used this name; keep one common exception identity.
GatewayError = EnphaseApiError
GatewayInfo = GatewayIdentity
