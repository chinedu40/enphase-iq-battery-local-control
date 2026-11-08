"""Inspect an untrusted TLS certificate without sending application data.

This probe establishes no manufacturer or gateway identity. The returned names
are unverified certificate claims for an explicit first-use trust decision. Only
after that decision should a caller use the fingerprint for authenticated APIs.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import re
import ssl
import unicodedata
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.x509.oid import NameOID

from .api import CertificateError, CommunicationError, _base_url

_MAX_PROBE_TIMEOUT = 30.0
_CLOSE_TIMEOUT = 1.0
_MAX_CERTIFICATE_BYTES = 128 * 1024
_MAX_DISPLAY_CHARACTERS = 512


@dataclass(frozen=True, slots=True)
class CertificateDetails:
    """A leaf fingerprint and unverified, bounded certificate display claims."""

    fingerprint: str
    subject: str
    issuer: str
    serial_hint: str | None


def _display_name(name: x509.Name) -> str:
    """Keep display names printable and prevent injected Markdown constructs."""
    text = name.rfc4514_string()
    text = "".join(
        " "
        if unicodedata.category(character).startswith("C") or character in "[]<>`"
        else character
        for character in text
    )
    return " ".join(text.split())[:_MAX_DISPLAY_CHARACTERS] or "(not provided)"


def _certificate_details(der: bytes) -> CertificateDetails:
    if not der or len(der) > _MAX_CERTIFICATE_BYTES:
        raise CertificateError("The gateway did not provide a usable TLS certificate.")
    try:
        certificate = x509.load_der_x509_certificate(der)
        # Do not retrieve AIA, CRL, or any other URLs contained in extensions.
        subject = _display_name(certificate.subject)
        issuer = _display_name(certificate.issuer)
        serial_hint = None
        for attribute in certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            match = re.match(r"^([0-9]{12})(?=[^0-9]|$)", attribute.value)
            if match:
                serial_hint = match.group(1)
                break
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise CertificateError("The gateway returned an invalid TLS certificate.") from None
    return CertificateDetails(
        fingerprint=hashlib.sha256(der).hexdigest(),
        subject=subject,
        issuer=issuer,
        serial_hint=serial_hint,
    )


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    # Closing errors must not hide the original outcome; do not wait indefinitely
    # for a peer that declines a TLS close-notify handshake.
    with suppress(Exception):
        writer.close()
    with suppress(Exception):
        async with asyncio.timeout(_CLOSE_TIMEOUT):
            await writer.wait_closed()


async def probe_certificate(host: str, *, timeout: float = 10.0) -> CertificateDetails:
    """Read one public TLS leaf certificate, without HTTP, cookies or credentials.

    Certificate verification is disabled only for this isolated unauthenticated
    probe. No application bytes are sent and no shared SSL context is modified.
    """
    address = urlsplit(_base_url(host))
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("The certificate probe timeout must be a positive number.")
    effective_timeout = min(float(timeout), _MAX_PROBE_TIMEOUT)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(effective_timeout):
            _, writer = await asyncio.open_connection(
                host=address.hostname,
                port=address.port or 443,
                ssl=context,
                server_hostname=address.hostname,
                ssl_handshake_timeout=effective_timeout,
                ssl_shutdown_timeout=_CLOSE_TIMEOUT,
            )
            tls = writer.get_extra_info("ssl_object")
            der = tls.getpeercert(binary_form=True) if tls is not None else None
            if not isinstance(der, bytes):
                raise CertificateError("The gateway did not provide a TLS certificate.")
            return _certificate_details(der)
    except ssl.SSLError:
        raise CertificateError("The gateway TLS certificate could not be read.") from None
    except (TimeoutError, OSError, EOFError):
        raise CommunicationError(
            "The local gateway did not complete the certificate probe."
        ) from None
    finally:
        if writer is not None:
            await _close_writer(writer)
