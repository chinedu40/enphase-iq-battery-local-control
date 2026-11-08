"""Use synthetic certificates and fake streams; never contact a real gateway."""

from __future__ import annotations

import asyncio
import hashlib
import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import AuthorityInformationAccessOID, NameOID

from custom_components.enphase_local_control import certificate
from custom_components.enphase_local_control.api import CertificateError, CommunicationError


def certificate_der(
    common_name: str = "122600012345.800-00000-r01.example.invalid",
) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Cloud.HSM.TA")]))
        .public_key(key.public_key())
        .serial_number(123)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier("https://must-not-fetch.invalid/issuer"),
                    )
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def connection(monkeypatch):
    tls = MagicMock()
    tls.getpeercert.return_value = certificate_der()
    writer = MagicMock()
    writer.get_extra_info.return_value = tls
    writer.wait_closed = AsyncMock()
    writer.drain = AsyncMock()
    reader = MagicMock()
    connector = AsyncMock(return_value=(reader, writer))
    monkeypatch.setattr(certificate.asyncio, "open_connection", connector)
    return connector, reader, writer, tls


async def test_probe_hashes_whole_der_and_never_sends_application_data(connection):
    connector, reader, writer, tls = connection

    details = await certificate.probe_certificate("192.0.2.60")

    assert details.fingerprint == hashlib.sha256(tls.getpeercert.return_value).hexdigest()
    assert len(details.fingerprint) == 64
    assert details.subject == "CN=122600012345.800-00000-r01.example.invalid"
    assert details.issuer == "CN=Cloud.HSM.TA"
    assert details.serial_hint == "122600012345"
    tls.getpeercert.assert_called_once_with(binary_form=True)
    writer.get_extra_info.assert_called_once_with("ssl_object")
    writer.write.assert_not_called()
    writer.writelines.assert_not_called()
    writer.drain.assert_not_awaited()
    reader.assert_not_called()
    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()
    kwargs = connector.call_args.kwargs
    assert kwargs["host"] == "192.0.2.60"
    assert kwargs["port"] == 443
    assert kwargs["ssl"].verify_mode == ssl.CERT_NONE
    assert kwargs["ssl"].check_hostname is False
    assert kwargs["ssl_handshake_timeout"] == 10
    assert "Authorization" not in repr(kwargs)
    # The AIA URL in this synthetic certificate caused no extra connection.
    connector.assert_awaited_once()


@pytest.mark.parametrize(
    ("host", "hostname", "port"),
    [
        ("https://envoy.local:8443/", "envoy.local", 8443),
        ("2001:db8::60", "2001:db8::60", 443),
    ],
)
async def test_probe_uses_validated_host_and_port(connection, host, hostname, port):
    connector, _, _, _ = connection
    await certificate.probe_certificate(host)
    assert connector.call_args.kwargs["host"] == hostname
    assert connector.call_args.kwargs["port"] == port


@pytest.mark.parametrize(
    "host",
    ["http://envoy.local", "https://user:password@envoy.local", "envoy.local/private", ""],
)
async def test_invalid_host_never_opens_a_connection(connection, host):
    connector, _, _, _ = connection
    with pytest.raises(ValueError):
        await certificate.probe_certificate(host)
    connector.assert_not_awaited()


@pytest.mark.parametrize("timeout", [False, 0, -1, float("inf"), float("nan"), "10"])
async def test_invalid_timeout_never_opens_a_connection(connection, timeout):
    connector, _, _, _ = connection
    with pytest.raises(ValueError):
        await certificate.probe_certificate("envoy.local", timeout=timeout)
    connector.assert_not_awaited()


async def test_probe_timeout_has_a_maximum(connection):
    connector, _, _, _ = connection
    await certificate.probe_certificate("envoy.local", timeout=3600)
    assert connector.call_args.kwargs["ssl_handshake_timeout"] == 30


@pytest.mark.parametrize("der", [None, b"", b"not a certificate", b"x" * (128 * 1024 + 1)])
async def test_bad_certificate_is_safe_and_connection_is_closed(connection, der):
    _, _, writer, tls = connection
    tls.getpeercert.return_value = der
    with pytest.raises(CertificateError) as error:
        await certificate.probe_certificate("envoy.local")
    assert "not a certificate" not in str(error.value)
    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()


async def test_missing_tls_is_safe_and_connection_is_closed(connection):
    _, _, writer, _ = connection
    writer.get_extra_info.return_value = None
    with pytest.raises(CertificateError):
        await certificate.probe_certificate("envoy.local")
    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()


@pytest.mark.parametrize(
    ("failure", "error_type"),
    [
        (ConnectionRefusedError("private network details"), CommunicationError),
        (TimeoutError("private network details"), CommunicationError),
        (ssl.SSLError("private TLS details"), CertificateError),
    ],
)
async def test_connection_errors_have_safe_messages(connection, failure, error_type):
    connector, _, writer, _ = connection
    connector.side_effect = failure
    with pytest.raises(error_type) as error:
        await certificate.probe_certificate("envoy.local")
    assert "private" not in str(error.value)
    assert error.value.__suppress_context__
    writer.close.assert_not_called()


async def test_actual_timeout_cancels_a_stalled_handshake(connection):
    connector, _, _, _ = connection
    cancelled = asyncio.Event()

    async def stalled_handshake(**_kwargs):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    connector.side_effect = stalled_handshake
    with pytest.raises(CommunicationError):
        await certificate.probe_certificate("envoy.local", timeout=0.01)
    assert cancelled.is_set()


async def test_shutdown_is_bounded_and_does_not_mask_result(connection, monkeypatch):
    _, _, writer, _ = connection
    cancelled = asyncio.Event()

    async def stalled_shutdown():
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    writer.wait_closed.side_effect = stalled_shutdown
    monkeypatch.setattr(certificate, "_CLOSE_TIMEOUT", 0.01)
    details = await certificate.probe_certificate("envoy.local")
    assert details.serial_hint == "122600012345"
    assert cancelled.is_set()
    writer.close.assert_called_once_with()


async def test_shutdown_error_does_not_mask_certificate_error(connection):
    _, _, writer, tls = connection
    tls.getpeercert.return_value = b"invalid DER"
    writer.wait_closed.side_effect = OSError("private shutdown details")
    with pytest.raises(CertificateError):
        await certificate.probe_certificate("envoy.local")
    writer.close.assert_called_once_with()


async def test_probe_cancellation_is_not_misreported(connection):
    _, _, writer, tls = connection
    tls.getpeercert.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await certificate.probe_certificate("envoy.local")
    writer.close.assert_called_once_with()
    writer.wait_closed.assert_awaited_once_with()


@pytest.mark.parametrize(
    ("common_name", "hint"),
    [("1234567890123.example", None), ("Gateway", None), ("123456789012", "123456789012")],
)
async def test_serial_hint_is_only_a_leading_twelve_digit_claim(connection, common_name, hint):
    _, _, _, tls = connection
    tls.getpeercert.return_value = certificate_der(common_name)
    assert (await certificate.probe_certificate("envoy.local")).serial_hint == hint


async def test_untrusted_subject_cannot_inject_controls_or_markdown_images(connection):
    _, _, _, tls = connection
    tls.getpeercert.return_value = certificate_der(
        "123456789012.\n\u202e![image](https://example.invalid)`"
    )
    details = await certificate.probe_certificate("envoy.local")
    assert details.serial_hint == "123456789012"
    assert "\n" not in details.subject
    assert "\u202e" not in details.subject
    assert "[" not in details.subject
    assert "]" not in details.subject
    assert "`" not in details.subject


def test_display_name_is_bounded():
    name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "X" * 800)])
    assert len(certificate._display_name(name)) == 512
