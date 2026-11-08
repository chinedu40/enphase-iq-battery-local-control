"""Exercise the transport without Home Assistant or a live gateway."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import json
import ssl
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiohttp
import pytest

# Loading this file directly avoids executing the HA integration's __init__.py.
_API_PATH = Path(__file__).parents[1] / "custom_components" / "enphase_local_control" / "api.py"
_SPEC = importlib.util.spec_from_file_location("enphase_transport_under_test", _API_PATH)
assert _SPEC is not None and _SPEC.loader is not None
api = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = api
_SPEC.loader.exec_module(api)

TOKEN = "example-token-never-send-to-a-real-device"
SCHEDULER = {
    "acb_current_mode": 1,
    "acb_debug_mode": -1,
    "sched_mode_key": ["ID - Idle", "ZN - Zero Net", "CG - Charge From Grid"],
    "ENC_agg_soc": 7,
    "Num_of_enc": 3,
}


class FakeContent:
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def iter_chunked(self, size: int):
        for position in range(0, len(self.body), size):
            yield self.body[position : position + size]


class FakeResponse:
    def __init__(
        self,
        data: Any = None,
        *,
        status: int = 200,
        raw: bytes | None = None,
        declared_length: int | None = None,
    ) -> None:
        self.status = status
        self.body = json.dumps(data).encode() if raw is None else raw
        self.content = FakeContent(self.body)
        self.content_length = declared_length


class FakeContext:
    def __init__(self, result: FakeResponse | BaseException) -> None:
        self.result = result

    async def __aenter__(self):
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result

    async def __aexit__(self, *_args):
        return False


class FakeSession:
    def __init__(self, *responses: FakeResponse | BaseException) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def request(self, method: str, url: str, **kwargs: Any) -> FakeContext:
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self.responses:
            raise AssertionError("An unexpected extra request was made")
        return FakeContext(self.responses.pop(0))


@pytest.mark.asyncio
async def test_scheduler_uses_direct_bearer_https_and_preserves_fields():
    session = FakeSession(FakeResponse(SCHEDULER))
    client = api.GatewayClient(session, "192.168.1.20", TOKEN, timeout=4)

    result = await client.get_scheduler()

    assert result == SCHEDULER
    assert len(session.calls) == 1
    call = session.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://192.168.1.20/ivp/sc/sched"
    assert call["headers"]["Authorization"] == "Bearer " + TOKEN
    assert call["allow_redirects"] is False
    assert call["raise_for_status"] is False
    assert call["ssl"] is not False
    assert call["timeout"].total == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "changes",
    [
        {"acb_current_mode": True},
        {"acb_current_mode": "2"},
        {"acb_current_mode": -1},
        {"acb_current_mode": 256},
        {"acb_debug_mode": -2},
        {"acb_debug_mode": 256},
        {"acb_debug_mode": True},
        {"acb_debug_mode": None},
        {"sched_mode_key": []},
        {"sched_mode_key": ["Idle", " "]},
    ],
)
async def test_scheduler_rejects_invalid_schema(changes):
    session = FakeSession(FakeResponse({**SCHEDULER, **changes}))
    client = api.GatewayClient(session, "envoy.local", TOKEN)

    with pytest.raises(api.InvalidResponseError):
        await client.get_scheduler()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [99, 255])
async def test_scheduler_preserves_unrecognized_mode_codes_for_recovery(mode):
    scheduler = {**SCHEDULER, "acb_current_mode": mode, "acb_debug_mode": mode}
    session = FakeSession(FakeResponse(scheduler))
    client = api.GatewayClient(session, "envoy.local", TOKEN)

    assert await client.get_scheduler() == scheduler
    assert len(session.calls) == 1
    assert session.calls[0]["method"] == "GET"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [2, -1])
async def test_command_sends_one_post_and_acknowledges_without_readback(mode):
    session = FakeSession(FakeResponse({"acb_debug_mode": mode}))
    client = api.GatewayClient(session, "envoy.local", TOKEN)

    assert await client.set_override(mode) == {"acb_debug_mode": mode}
    assert len(session.calls) == 1
    assert session.calls[0]["method"] == "POST"
    assert session.calls[0]["json"] == {"acb_debug_mode": mode}


@pytest.mark.asyncio
@pytest.mark.parametrize("ack", [{}, {"acb_debug_mode": 1}, {"acb_debug_mode": True}])
async def test_command_rejects_missing_or_mismatched_ack(ack):
    session = FakeSession(FakeResponse(ack))
    client = api.GatewayClient(session, "envoy.local", TOKEN)

    with pytest.raises(api.CommandError):
        await client.set_override(2)
    assert len(session.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [True, -2, "2", 256])
async def test_invalid_command_is_not_sent(mode):
    session = FakeSession()
    client = api.GatewayClient(session, "envoy.local", TOKEN)
    with pytest.raises(api.CommandError):
        await client.set_override(mode)
    assert not session.calls


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "status", "error"),
    [
        ("GET", 401, api.AuthenticationError),
        ("POST", 401, api.AuthenticationError),
        ("GET", 403, api.PermissionDeniedError),
        ("POST", 403, api.PermissionDeniedError),
        ("GET", 404, api.InvalidResponseError),
        ("GET", 500, api.CommunicationError),
        ("POST", 400, api.CommandError),
        ("POST", 500, api.CommandError),
        ("GET", 302, api.InvalidResponseError),
    ],
)
async def test_http_errors_are_distinct_redacted_and_not_retried(method, status, error):
    session = FakeSession(FakeResponse(status=status, raw=TOKEN.encode()))
    client = api.GatewayClient(session, "envoy.local", TOKEN)
    with pytest.raises(error) as caught:
        if method == "POST":
            await client.set_override(2)
        else:
            await client.get_scheduler()
    assert caught.value.status == status
    assert TOKEN not in str(caught.value)
    assert len(session.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("raw", [TOKEN.encode(), b"[]", b"null", b"\xff"])
async def test_invalid_response_text_is_never_in_errors(raw):
    client = api.GatewayClient(FakeSession(FakeResponse(raw=raw)), "envoy.local", TOKEN)
    with pytest.raises(api.InvalidResponseError) as caught:
        await client.get_scheduler()
    assert TOKEN not in str(caught.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", [TimeoutError(TOKEN), aiohttp.ClientConnectionError(TOKEN)])
async def test_uncertain_post_transport_failure_is_not_retried(failure):
    session = FakeSession(failure)
    client = api.GatewayClient(session, "envoy.local", TOKEN)
    with pytest.raises(api.CommunicationError) as caught:
        await client.set_override(2)
    assert TOKEN not in str(caught.value)
    assert len(session.calls) == 1


@pytest.mark.asyncio
async def test_cancellation_is_propagated_to_caller():
    client = api.GatewayClient(FakeSession(asyncio.CancelledError()), "envoy.local", TOKEN)
    with pytest.raises(asyncio.CancelledError):
        await client.get_scheduler()


@pytest.mark.asyncio
async def test_supplied_sha256_pin_and_mismatch():
    expected = b"\x12" * 32
    pin = ":".join(["12"] * 32)
    mismatch = aiohttp.ServerFingerprintMismatch(expected, b"\x34" * 32, "envoy.local", 443)
    session = FakeSession(mismatch)
    client = api.GatewayClient(session, "envoy.local", TOKEN, fingerprint=pin)
    with pytest.raises(api.CertificateError):
        await client.get_scheduler()
    assert isinstance(session.calls[0]["ssl"], aiohttp.Fingerprint)
    assert session.calls[0]["ssl"].fingerprint == expected


@pytest.mark.asyncio
async def test_tls_errors_do_not_fall_back_to_unverified_tls():
    session = FakeSession(ssl.SSLError(TOKEN))
    client = api.GatewayClient(session, "envoy.local", TOKEN)
    with pytest.raises(api.CertificateError) as caught:
        await client.get_scheduler()
    assert TOKEN not in str(caught.value)
    assert len(session.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("declared", [None, 2 * 1024 * 1024])
async def test_response_size_limit_applies_to_chunked_and_declared_bodies(declared):
    session = FakeSession(FakeResponse(raw=b"x" * (1024 * 1024 + 1), declared_length=declared))
    client = api.GatewayClient(session, "envoy.local", TOKEN)
    with pytest.raises(api.InvalidResponseError):
        await client.get_scheduler()


@pytest.mark.asyncio
async def test_identity_and_optional_telemetry_reads():
    xml = b"""<envoy_info><device><sn>example123</sn><pn>model123</pn>
        <software>D8.3.example</software></device></envoy_info>"""
    telemetry = {"nameplate": {"ENC": [9600, 0, 0]}, "response": {"f_state": 12}}
    session = FakeSession(FakeResponse(raw=xml), FakeResponse(telemetry))
    client = api.GatewayClient(session, "https://envoy.local:443/", TOKEN)
    assert await client.get_info() == api.GatewayIdentity("example123", "model123", "D8.3.example")
    assert await client.get_status() == telemetry
    assert [call["method"] for call in session.calls] == ["GET", "GET"]


@pytest.mark.asyncio
async def test_namespaced_identity_xml():
    raw = b'<envoy_info xmlns="urn:example"><device><sn>example123</sn></device></envoy_info>'
    client = api.GatewayClient(FakeSession(FakeResponse(raw=raw)), "envoy.local", TOKEN)
    assert await client.get_info() == api.GatewayIdentity(serial="example123")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "raw", [b"<bad", b'<!DOCTYPE x [<!ENTITY x "value">]><x/>', b"<html>Sign in</html>"]
)
async def test_invalid_or_entity_xml_is_rejected(raw):
    client = api.GatewayClient(FakeSession(FakeResponse(raw=raw)), "envoy.local", TOKEN)
    with pytest.raises(api.InvalidResponseError):
        await client.get_info()


@pytest.mark.parametrize(
    "host",
    [
        "http://envoy.local",
        "https://user:password@envoy.local",
        "https://envoy.local/ivp/sc/sched",
        "https://envoy.local?token=secret",
        "https://envoy.local#fragment",
        "https://envoy.local:99999",
        "",
    ],
)
def test_invalid_hosts_are_rejected_without_network(host):
    session = FakeSession()
    with pytest.raises(ValueError):
        api.GatewayClient(session, host, TOKEN)
    assert not session.calls


def test_invalid_fingerprint_and_token_are_rejected():
    with pytest.raises(api.CertificateError):
        api.GatewayClient(FakeSession(), "envoy.local", TOKEN, fingerprint="ab" * 20)
    with pytest.raises(api.AuthenticationError):
        api.GatewayClient(FakeSession(), "envoy.local", "token\r\ninjected-header")


def test_metadata_is_optional_unverified_and_contains_only_dates():
    payload = (
        base64.urlsafe_b64encode(
            json.dumps(
                {"exp": 2000000000, "iat": 1000000000, "private_claim": "never-exposed"}
            ).encode()
        )
        .decode()
        .rstrip("=")
    )
    metadata = api.decode_token_metadata("unverified." + payload + ".signature")
    assert metadata.expires_at == datetime.fromtimestamp(2000000000, tz=UTC)
    assert metadata.issued_at == datetime.fromtimestamp(1000000000, tz=UTC)
    assert "never-exposed" not in repr(metadata)
    assert api.decode_token_metadata("not-a-token") == api.TokenMetadata()
    assert api.decode_token_metadata("x.%%%.x") == api.TokenMetadata()


@pytest.mark.parametrize("expiry", [True, "2000000000", float("nan"), 10**400])
def test_malformed_expiry_metadata_does_not_crash_or_establish_validity(expiry):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": expiry}).encode()).decode().rstrip("=")
    assert api.decode_token_metadata("x." + payload + ".x") == api.TokenMetadata()


@pytest.mark.asyncio
async def test_unbracketed_ipv6_uses_https_authority():
    session = FakeSession(FakeResponse(SCHEDULER))
    client = api.GatewayClient(session, "fd00::20", TOKEN)
    await client.get_scheduler()
    assert session.calls[0]["url"] == "https://[fd00::20]/ivp/sc/sched"


@pytest.mark.asyncio
async def test_public_identity_discovery_uses_pin_without_authorization():
    raw = b"<envoy_info><device><sn>122600012345</sn></device></envoy_info>"
    session = FakeSession(FakeResponse(raw=raw))
    pin = "ab" * 32
    info = await api.async_get_gateway_identity(session, "envoy.local", fingerprint=pin)
    assert info.serial == "122600012345"
    call = session.calls[0]
    assert call["url"] == "https://envoy.local/info.xml"
    assert call["method"] == "GET"
    assert "Authorization" not in call["headers"]
    assert isinstance(call["ssl"], aiohttp.Fingerprint)
    assert call["ssl"].fingerprint == bytes.fromhex(pin)
    assert call["allow_redirects"] is False


@pytest.mark.asyncio
async def test_replacing_token_updates_next_read_without_network_side_effects():
    session = FakeSession(FakeResponse(SCHEDULER))
    client = api.GatewayClient(session, "envoy.local", TOKEN)
    claims = (
        base64.urlsafe_b64encode(json.dumps({"exp": 2100000000}).encode()).decode().rstrip("=")
    )
    replacement = "header." + claims + ".signature"
    client.replace_token(replacement)
    assert session.calls == []
    assert client.token_metadata.expires_at == datetime.fromtimestamp(2100000000, tz=UTC)
    with pytest.raises(api.AuthenticationError):
        client.replace_token("invalid\r\nheader")
    await client.get_scheduler()
    assert session.calls[0]["headers"]["Authorization"] == "Bearer " + replacement
