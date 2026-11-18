"""Gateways that answer with the malformed status line ``HTTP/1.1 0``.

Observed on IQ Gateway firmware D8.3.5427 for /ivp/sc/sched: normal headers and
a valid JSON body follow, but aiohttp rejects the status line.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import logging
import sys
from pathlib import Path
from typing import Any

import aiohttp
import pytest
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

_API_PATH = Path(__file__).parents[1] / "custom_components" / "enphase_local_control" / "api.py"
_SPEC = importlib.util.spec_from_file_location("enphase_status_zero_under_test", _API_PATH)
assert _SPEC is not None and _SPEC.loader is not None
api = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = api
_SPEC.loader.exec_module(api)

TOKEN = "example-token-never-send-to-a-real-device"
CERT = b"fake-der-certificate"
PIN = hashlib.sha256(CERT).hexdigest()
SCHEDULER = {
    "acb_current_mode": 1,
    "acb_debug_mode": -1,
    "sched_mode_key": ["ID - Idle", "ZN - Zero Net", "CG - Charge From Grid"],
}


def _bad_status_error(method: str = "GET") -> aiohttp.ClientResponseError:
    url = URL("https://gateway.local/ivp/sc/sched")
    info = aiohttp.RequestInfo(
        url, method, CIMultiDictProxy(CIMultiDict({"Authorization": "Bearer " + TOKEN})), url
    )
    return aiohttp.ClientResponseError(
        info,
        (),
        status=400,
        message="Bad status line:\n  Invalid status code:\n\n  b'HTTP/1.1 0'\n              ^",
    )


class FakeSession:
    """aiohttp session stand-in that raises preset errors."""

    def __init__(self, *errors: BaseException) -> None:
        self.errors = list(errors)
        self.calls: list[str] = []

    def request(self, method: str, url: str, **_kwargs: Any):
        self.calls.append(method)
        error = self.errors.pop(0)

        class _Context:
            async def __aenter__(self):
                raise error

            async def __aexit__(self, *_args):
                return False

        return _Context()


class FakeTLS:
    def __init__(self, der: bytes) -> None:
        self.der = der

    def getpeercert(self, binary_form: bool = False) -> bytes:
        assert binary_form
        return self.der


class FakeWriter:
    def __init__(self, der: bytes) -> None:
        self.tls = FakeTLS(der)
        self.sent = bytearray()
        self.closed = False

    def get_extra_info(self, name: str):
        return self.tls if name == "ssl_object" else None

    def write(self, data: bytes) -> None:
        self.sent.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class FakeConnector:
    """Replace asyncio.open_connection; each call serves the next raw response."""

    def __init__(self, *responses: bytes, der: bytes = CERT) -> None:
        self.responses = list(responses)
        self.der = der
        self.writers: list[FakeWriter] = []
        self.kwargs: list[dict[str, Any]] = []

    async def __call__(self, **kwargs: Any):
        self.kwargs.append(kwargs)
        reader = asyncio.StreamReader(limit=kwargs["limit"])
        reader.feed_data(self.responses.pop(0))
        reader.feed_eof()
        writer = FakeWriter(self.der)
        self.writers.append(writer)
        return reader, writer


def _reply(body: Any, *, status: bytes = b"0", extra: bytes = b"") -> bytes:
    raw = json.dumps(body).encode()
    return (
        b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n"
        b"Content-Length: " + str(len(raw)).encode() + b"\r\n" + extra + b"\r\n" + raw
    )


@pytest.fixture
def connector(monkeypatch):
    def install(*responses: bytes, der: bytes = CERT) -> FakeConnector:
        fake = FakeConnector(*responses, der=der)
        monkeypatch.setattr(api.asyncio, "open_connection", fake)
        return fake

    return install


def _client(session: FakeSession, fingerprint: str | None = PIN):
    return api.GatewayClient(session, "gateway.local", TOKEN, fingerprint=fingerprint)


async def test_read_falls_back_once_then_uses_tolerant_reader(connector):
    session = FakeSession(_bad_status_error())
    fake = connector(_reply(SCHEDULER), _reply(SCHEDULER | {"acb_debug_mode": 2}))
    client = _client(session)

    assert await client.get_scheduler() == SCHEDULER
    assert (await client.get_scheduler())["acb_debug_mode"] == 2
    # aiohttp is tried only once; the learned path then goes straight to the reader.
    assert session.calls == ["GET"]
    request = bytes(fake.writers[0].sent)
    assert request.startswith(b"GET /ivp/sc/sched HTTP/1.1\r\n")
    assert b"Host: gateway.local\r\n" in request
    assert b"Authorization: Bearer " + TOKEN.encode() + b"\r\n" in request
    assert b"Connection: close\r\n" in request
    assert fake.kwargs[0]["host"] == "gateway.local"
    assert fake.kwargs[0]["port"] == 443
    assert all(writer.closed for writer in fake.writers)


async def test_unlearned_command_is_never_resent(connector):
    session = FakeSession(_bad_status_error("POST"))
    fake = connector()
    with pytest.raises(api.CommandError):
        await _client(session).set_override(2)
    assert session.calls == ["POST"]
    assert fake.writers == []


async def test_learned_command_is_sent_exactly_once(connector):
    session = FakeSession(_bad_status_error())
    fake = connector(_reply(SCHEDULER), _reply(SCHEDULER | {"acb_debug_mode": 3}))
    client = _client(session)
    await client.get_scheduler()

    assert (await client.set_override(3))["acb_debug_mode"] == 3
    assert session.calls == ["GET"]
    assert len(fake.writers) == 2
    request = bytes(fake.writers[1].sent)
    head, body = request.split(b"\r\n\r\n", 1)
    assert head.startswith(b"POST /ivp/sc/sched HTTP/1.1\r\n")
    assert b"Content-Type: application/json" in head
    assert f"Content-Length: {len(body)}".encode() in head
    assert json.loads(body) == {"acb_debug_mode": 3}


async def test_learned_command_with_wrong_ack_is_rejected(connector):
    session = FakeSession(_bad_status_error())
    connector(_reply(SCHEDULER), _reply(SCHEDULER | {"acb_debug_mode": 1}))
    client = _client(session)
    await client.get_scheduler()
    with pytest.raises(api.CommandError):
        await client.set_override(3)


async def test_pin_mismatch_sends_nothing(connector):
    session = FakeSession(_bad_status_error())
    fake = connector(_reply(SCHEDULER), der=b"some-other-certificate")
    with pytest.raises(api.CertificateError):
        await _client(session).get_scheduler()
    assert fake.writers[0].sent == bytearray()
    assert fake.writers[0].closed


async def test_without_pin_uses_normal_certificate_verification(connector):
    session = FakeSession(_bad_status_error())
    fake = connector(_reply(SCHEDULER))
    await _client(session, fingerprint=None).get_scheduler()
    context = fake.kwargs[0]["ssl"]
    assert context.check_hostname is True
    assert context.verify_mode.name == "CERT_REQUIRED"


async def test_chunked_body_and_reason_phrase(connector):
    raw = json.dumps(SCHEDULER).encode()
    reply = (
        b"HTTP/1.1 0 \r\nTransfer-Encoding: chunked\r\n\r\n"
        + f"{len(raw[:10]):x}\r\n".encode()
        + raw[:10]
        + b"\r\n"
        + f"{len(raw[10:]):x};ext=1\r\n".encode()
        + raw[10:]
        + b"\r\n0\r\n\r\n"
    )
    connector(reply)
    assert await _client(FakeSession(_bad_status_error())).get_scheduler() == SCHEDULER


async def test_body_until_close_without_length(connector):
    connector(
        b"HTTP/1.1 0\r\nContent-Type: application/json\r\n\r\n" + json.dumps(SCHEDULER).encode()
    )
    assert await _client(FakeSession(_bad_status_error())).get_scheduler() == SCHEDULER


@pytest.mark.parametrize(
    ("status", "error"),
    [
        (b"401 Unauthorized", api.AuthenticationError),
        (b"403", api.PermissionDeniedError),
        (b"500", api.CommunicationError),
        (b"404", api.InvalidResponseError),
    ],
)
async def test_real_statuses_keep_their_meaning(connector, status, error):
    connector(_reply({}, status=status))
    with pytest.raises(error):
        await _client(FakeSession(_bad_status_error())).get_scheduler()


@pytest.mark.parametrize(
    "reply",
    [
        b"garbage\r\n\r\n{}",
        b"HTTP/2 0\r\n\r\n{}",
        b"HTTP/1.1 0\r\nno-colon-header\r\n\r\n{}",
        b"HTTP/1.1 0\r\nContent-Length: -1\r\n\r\n{}",
        b"HTTP/1.1 0\r\nTransfer-Encoding: gzip\r\n\r\n{}",
        b"HTTP/1.1 0\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n{}\r\n0\r\n\r\n",
        b"HTTP/1.1 0\r\nContent-Length: 2\r\n\r\nno",
    ],
)
async def test_malformed_replies_are_rejected(connector, reply):
    connector(reply)
    with pytest.raises(api.InvalidResponseError):
        await _client(FakeSession(_bad_status_error())).get_scheduler()


async def test_truncated_reply_is_a_communication_error(connector):
    connector(b"HTTP/1.1 0\r\nContent-Length: 500\r\n\r\n{}")
    with pytest.raises(api.CommunicationError):
        await _client(FakeSession(_bad_status_error())).get_scheduler()


@pytest.mark.parametrize("chunked", [False, True])
async def test_size_limit_applies(connector, monkeypatch, chunked):
    monkeypatch.setattr(api, "_MAX_RESPONSE_BYTES", 32)
    big = b"x" * 64
    if chunked:
        reply = b"HTTP/1.1 0\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n" + big + b"\r\n0\r\n\r\n"
    else:
        reply = b"HTTP/1.1 0\r\n\r\n" + big
    connector(reply)
    with pytest.raises(api.InvalidResponseError):
        await _client(FakeSession(_bad_status_error())).get_scheduler()


async def test_oversized_headers_are_rejected(connector, monkeypatch):
    monkeypatch.setattr(api, "_MAX_HEADER_BYTES", 64)
    connector(b"HTTP/1.1 0\r\nX-Pad: " + b"a" * 200 + b"\r\n\r\n{}")
    with pytest.raises(api.InvalidResponseError):
        await _client(FakeSession(_bad_status_error())).get_scheduler()


async def test_other_client_errors_are_unchanged_and_logs_are_redacted(connector, caplog):
    url = URL("https://gateway.local/ivp/sc/sched")
    info = aiohttp.RequestInfo(
        url, "GET", CIMultiDictProxy(CIMultiDict({"Authorization": "Bearer " + TOKEN})), url
    )
    other = aiohttp.ClientResponseError(info, (), status=400, message="Invalid header value")
    fake = connector()
    caplog.set_level(logging.DEBUG, logger=_SPEC.name)
    with pytest.raises(api.CommunicationError):
        await _client(FakeSession(other)).get_scheduler()
    assert fake.writers == []
    assert "Invalid header value" in caplog.text
    assert TOKEN not in caplog.text


async def test_fallback_logs_never_contain_the_token(connector, caplog):
    connector(_reply(SCHEDULER))
    caplog.set_level(logging.DEBUG, logger=_SPEC.name)
    await _client(FakeSession(_bad_status_error())).get_scheduler()
    assert "malformed HTTP status line" in caplog.text
    assert TOKEN not in caplog.text


async def test_controller_reconciles_unreadable_ack_without_resending(connector):
    controller_path = _API_PATH.with_name("controller.py")
    spec = importlib.util.spec_from_file_location(
        "enphase_status_zero_controller", controller_path
    )
    assert spec is not None and spec.loader is not None
    controller = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = controller
    spec.loader.exec_module(controller)

    # A command sent before any read has revealed the quirk: aiohttp cannot
    # parse the POST reply, and the controller's readback hits it on GET too.
    session = FakeSession(_bad_status_error("POST"), _bad_status_error())
    fake = connector(_reply(SCHEDULER | {"acb_debug_mode": 2}))
    mode = controller.ModeController(_client(session))

    result = await mode._write_locked(controller.CHARGE_FROM_GRID)

    assert result.reconciled is True
    assert result.state.debug_mode == controller.CHARGE_FROM_GRID
    # One POST via aiohttp (reply unreadable), then a single read via the
    # tolerant reader. The command itself is never sent a second time.
    assert session.calls == ["POST", "GET"]
    assert len(fake.writers) == 1
    assert bytes(fake.writers[0].sent).startswith(b"GET ")
