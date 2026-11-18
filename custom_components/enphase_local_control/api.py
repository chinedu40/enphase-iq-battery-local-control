"""Local-only, authenticated IQ Gateway transport.

The gateway validates the supplied token.  Decoded JWT dates below are unverified
display hints, not proof of authentication or permission to control a gateway.
The caller owns the aiohttp session, command serialization and release policy.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import ipaddress
import json
import logging
import math
import re
import ssl
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree

import aiohttp

_LOGGER = logging.getLogger(__name__)

_MAX_RESPONSE_BYTES = 1024 * 1024
_MAX_JWT_PAYLOAD_BYTES = 16 * 1024
_MAX_HEADER_BYTES = 64 * 1024
_CLOSE_TIMEOUT = 1.0
# Some IQ Gateway firmware (observed on D8.3.5427) answers /ivp/sc/sched with
# the status line "HTTP/1.1 0" followed by normal headers and a valid body.
# aiohttp rightly rejects that line, so such paths use a minimal reader instead.
_STATUS_LINE = re.compile(rb"HTTP/1\.[01] ([0-9]{1,3})(?: [^\r\n]*)?")


def _is_bad_status_line(err: BaseException) -> bool:
    """Recognize aiohttp's parser rejection of a malformed response status line."""
    return (
        isinstance(err, aiohttp.ClientResponseError)
        and "bad status line" in str(err.message).casefold()
    )


def _describe(err: BaseException) -> str:
    """Summarize an error for debug logs without request headers or credentials."""
    if isinstance(err, aiohttp.ClientResponseError):
        # Its repr includes RequestInfo headers, which carry the Authorization token.
        return f"{type(err).__name__}: status={err.status} message={err.message!r}"
    return f"{type(err).__name__}: {err}"


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
        self._pin = self._ssl.fingerprint if self._ssl is not None else None
        # Paths whose replies carried an unparseable status line. Learned only
        # from a read, so a command is never resent to discover the quirk.
        self._raw_paths: set[str] = set()
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
        if path in self._raw_paths:
            return await self._raw_request(
                method, path, payload=payload, authenticated=authenticated
            )
        try:
            return await self._aiohttp_request(
                method, path, payload=payload, authenticated=authenticated
            )
        except _BadStatusLine:
            if method != "GET":
                # The command may already have been applied. Never resend it;
                # the controller reconciles by reading the scheduler back.
                raise CommandError("The gateway acknowledgement could not be read.") from None
            _LOGGER.debug(
                "Gateway sent a malformed HTTP status line for %s; "
                "using the tolerant reader for this path",
                path,
            )
            self._raw_paths.add(path)
            return await self._raw_request(
                method, path, payload=payload, authenticated=authenticated
            )

    async def _aiohttp_request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None,
        authenticated: bool,
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
        ) as err:
            _LOGGER.debug("%s %s failed TLS checks: %s", method, path, _describe(err))
            raise CertificateError("The gateway certificate could not be verified.") from None
        except (TimeoutError, aiohttp.ClientError, OSError) as err:
            if _is_bad_status_line(err):
                raise _BadStatusLine from None
            _LOGGER.debug("%s %s failed: %s", method, path, _describe(err))
            raise CommunicationError("The local gateway did not respond successfully.") from None

    def _raw_ssl_context(self) -> ssl.SSLContext:
        if self._pin is None:
            # Same trust policy as aiohttp without a pin: normal verification.
            return ssl.create_default_context()
        # Mirror aiohttp.Fingerprint: the pin replaces CA and hostname checks
        # and is compared below before any request byte is written.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    async def _raw_request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None,
        authenticated: bool,
    ) -> bytes:
        """Send one request over a dedicated TLS connection and parse leniently.

        Only the status line is treated leniently: a status of 0 is accepted as
        success when the gateway also sends a body; callers still validate it.
        """
        address = urlsplit(self._base_url)
        body = b"" if payload is None else json.dumps(payload).encode()
        lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {address.netloc}",
            "Accept: application/json, application/xml;q=0.9",
            "Connection: close",
        ]
        if authenticated:
            lines.append("Authorization: Bearer " + self._token)
        if payload is not None:
            lines.append("Content-Type: application/json")
        if payload is not None or method == "POST":
            lines.append(f"Content-Length: {len(body)}")
        request = ("\r\n".join(lines) + "\r\n\r\n").encode() + body

        writer: asyncio.StreamWriter | None = None
        try:
            async with asyncio.timeout(self._timeout.total):
                reader, writer = await asyncio.open_connection(
                    host=address.hostname,
                    port=address.port or 443,
                    ssl=self._raw_ssl_context(),
                    server_hostname=address.hostname,
                    limit=_MAX_HEADER_BYTES,
                    ssl_shutdown_timeout=_CLOSE_TIMEOUT,
                )
                if self._pin is not None:
                    tls = writer.get_extra_info("ssl_object")
                    der = tls.getpeercert(binary_form=True) if tls is not None else None
                    if not isinstance(der, bytes) or hashlib.sha256(der).digest() != self._pin:
                        raise CertificateError("The gateway certificate could not be verified.")
                writer.write(request)
                await writer.drain()
                status, headers = await _read_head(reader)
                self._check_status(200 if status == 0 else status, method)
                if status == 0:
                    _LOGGER.debug("%s %s: accepted HTTP status 0 from the gateway", method, path)
                return await _read_body(reader, headers)
        except EnphaseApiError:
            raise
        except ssl.SSLError as err:
            _LOGGER.debug("%s %s failed TLS checks: %s", method, path, _describe(err))
            raise CertificateError("The gateway certificate could not be verified.") from None
        except (TimeoutError, OSError, EOFError, asyncio.IncompleteReadError) as err:
            _LOGGER.debug("%s %s failed: %s", method, path, _describe(err))
            raise CommunicationError("The local gateway did not respond successfully.") from None
        except asyncio.LimitOverrunError:
            raise InvalidResponseError("The gateway response headers were too large.") from None
        finally:
            if writer is not None:
                await _close_writer(writer)

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


class _BadStatusLine(Exception):
    """Internal signal: aiohttp could not parse the response status line."""


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    with suppress(Exception):
        writer.close()
    with suppress(Exception):
        async with asyncio.timeout(_CLOSE_TIMEOUT):
            await writer.wait_closed()


async def _read_head(reader: asyncio.StreamReader) -> tuple[int, dict[str, str]]:
    head = await reader.readuntil(b"\r\n\r\n")
    if len(head) > _MAX_HEADER_BYTES:
        raise InvalidResponseError("The gateway response headers were too large.")
    status_line, *header_lines = head[:-4].split(b"\r\n")
    match = _STATUS_LINE.fullmatch(status_line)
    if match is None:
        raise InvalidResponseError("The gateway returned an unexpected HTTP status.")
    headers: dict[str, str] = {}
    for line in header_lines:
        name, separator, value = line.partition(b":")
        if not separator or not name.strip():
            raise InvalidResponseError("The gateway returned malformed HTTP headers.")
        try:
            key = name.strip().decode("ascii").casefold()
            text = value.strip().decode("latin-1")
        except UnicodeError:
            raise InvalidResponseError("The gateway returned malformed HTTP headers.") from None
        headers[key] = f"{headers[key]}, {text}" if key in headers else text
    return int(match.group(1)), headers


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
    encoding = headers.get("transfer-encoding", "").casefold()
    if encoding:
        if encoding != "chunked":
            raise InvalidResponseError("The gateway used an unsupported transfer encoding.")
        return await _read_chunked(reader)
    length = headers.get("content-length")
    if length is not None:
        if not length.isdigit():
            raise InvalidResponseError("The gateway returned malformed HTTP headers.")
        size = int(length)
        if size > _MAX_RESPONSE_BYTES:
            raise InvalidResponseError("The gateway response was too large.")
        return await reader.readexactly(size)
    body = bytearray()
    while chunk := await reader.read(16 * 1024):
        body.extend(chunk)
        if len(body) > _MAX_RESPONSE_BYTES:
            raise InvalidResponseError("The gateway response was too large.")
    return bytes(body)


async def _read_chunked(reader: asyncio.StreamReader) -> bytes:
    body = bytearray()
    while True:
        size_line = (await reader.readuntil(b"\r\n"))[:-2].split(b";", 1)[0].strip()
        if not size_line or not re.fullmatch(rb"[0-9a-fA-F]{1,8}", size_line):
            raise InvalidResponseError("The gateway returned a malformed chunked body.")
        size = int(size_line, 16)
        if size == 0:
            # Discard optional trailers up to the terminating blank line.
            while await reader.readuntil(b"\r\n") != b"\r\n":
                pass
            return bytes(body)
        if len(body) + size > _MAX_RESPONSE_BYTES:
            raise InvalidResponseError("The gateway response was too large.")
        body.extend(await reader.readexactly(size))
        if await reader.readexactly(2) != b"\r\n":
            raise InvalidResponseError("The gateway returned a malformed chunked body.")


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
