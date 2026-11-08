"""Test Enphase cloud login using synthetic responses; never authenticate live."""

from __future__ import annotations

import asyncio
import base64
import json
import ssl
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp
import pytest

from custom_components.enphase_local_control import cloud_auth

USERNAME = "test-account@example.invalid"
PASSWORD = "private-password-%+&@ value"
SESSION_ID = "private-cloud-session"
SERIAL = "123456789012"


def jwt_token(**changes: Any) -> str:
    claims = {
        "aud": SERIAL,
        "exp": int((datetime.now(UTC) + timedelta(days=365)).timestamp()),
        **changes,
    }

    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{encode({'alg': 'ES256', 'typ': 'JWT'})}.{encode(claims)}.synthetic_signature"


class FakeContent:
    def __init__(self, body: bytes):
        self.body = body

    async def iter_chunked(self, size: int):
        for offset in range(0, len(self.body), size):
            yield self.body[offset : offset + size]


class Response:
    def __init__(
        self,
        value: Any = None,
        *,
        raw: bytes | None = None,
        status: int = 200,
        content_type: str = "application/json",
        declared_length: int | None = None,
    ):
        self.status = status
        self.body = json.dumps(value).encode() if raw is None else raw
        self.content = FakeContent(self.body)
        self.content_length = declared_length
        self.headers = {"Content-Type": content_type}
        self.exited = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        self.exited = True
        return False


class ErrorContext:
    def __init__(self, error: BaseException):
        self.error = error

    async def __aenter__(self):
        raise self.error

    async def __aexit__(self, *_args):
        return False


class Session:
    def __init__(self, *responses: Response | BaseException):
        self.responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if not self.responses:
            raise AssertionError("Unexpected additional request")
        response = self.responses.pop(0)
        return ErrorContext(response) if isinstance(response, BaseException) else response


def good_login():
    return Response({"session_id": SESSION_ID, "is_consumer": True, "manager_token": "unused"})


def good_token():
    return Response(raw=jwt_token().encode(), content_type="text/plain")


async def request(session):
    return await cloud_auth.request_gateway_token(session, USERNAME, PASSWORD, SERIAL)


async def test_exact_official_protocol_with_public_tls_and_no_role_guessing(caplog):
    login, token_response = good_login(), good_token()
    session = Session(login, token_response)

    token = await request(session)

    assert token == token_response.body.decode()
    assert len(session.calls) == 2
    login_call, token_call = session.calls
    assert login_call["url"] == "https://enlighten.enphaseenergy.com/login/login.json?"
    assert login_call["data"] == {"user[email]": USERNAME, "user[password]": PASSWORD}
    assert login_call["json"] is None
    assert token_call["url"] == "https://entrez.enphaseenergy.com/tokens"
    assert token_call["json"] == {
        "session_id": SESSION_ID,
        "serial_num": SERIAL,
        "username": USERNAME,
    }
    assert token_call["data"] is None
    assert PASSWORD not in repr(token_call)
    for call in session.calls:
        assert call["ssl"] is True
        assert call["allow_redirects"] is False
        assert call["raise_for_status"] is False
        assert call["timeout"].total == 10
        assert call["headers"] == {"Accept": "application/json"}
    assert login.exited and token_response.exited
    assert all(secret not in caplog.text for secret in (USERNAME, PASSWORD, SESSION_ID, token))


async def test_trim_username_but_preserve_exact_password():
    session = Session(good_login(), good_token())
    await cloud_auth.request_gateway_token(session, f" {USERNAME} ", f" {PASSWORD} ", SERIAL)
    assert session.calls[0]["data"]["user[email]"] == USERNAME
    assert session.calls[0]["data"]["user[password]"] == f" {PASSWORD} "


@pytest.mark.parametrize(
    "serial", ["123", "1234567890123", "１２３４５６７８９０１２", "12345678901x", None]
)
async def test_invalid_serial_is_rejected_before_credentials_are_sent(serial):
    session = Session()
    with pytest.raises(cloud_auth.CloudTokenError):
        await cloud_auth.request_gateway_token(session, USERNAME, PASSWORD, serial)
    assert not session.calls


@pytest.mark.parametrize(
    ("username", "password"),
    [("", PASSWORD), (" ", PASSWORD), (None, PASSWORD), (USERNAME, ""), (USERNAME, None)],
)
async def test_missing_credentials_are_rejected_without_requests(username, password):
    session = Session()
    with pytest.raises(cloud_auth.CloudInvalidAuth):
        await cloud_auth.request_gateway_token(session, username, password, SERIAL)
    assert not session.calls


@pytest.mark.parametrize("stage", ["login", "token"])
@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (400, cloud_auth.CloudInvalidAuth),
        (401, cloud_auth.CloudInvalidAuth),
        (403, cloud_auth.CloudInvalidAuth),
        (302, cloud_auth.CloudMFARequired),
        (404, cloud_auth.CloudTokenError),
        (429, cloud_auth.CloudCommunicationError),
        (500, cloud_auth.CloudCommunicationError),
    ],
)
async def test_http_errors_are_static_redacted_and_never_followed_or_retried(
    stage, status, error_type
):
    failure = Response(raw=f"{USERNAME} {PASSWORD} {SESSION_ID}".encode(), status=status)
    session = Session(*([good_login(), failure] if stage == "token" else [failure]))
    with pytest.raises(error_type) as error:
        await request(session)
    assert all(secret not in str(error.value) for secret in (USERNAME, PASSWORD, SESSION_ID))
    assert len(session.calls) == (2 if stage == "token" else 1)
    assert failure.exited


@pytest.mark.parametrize(
    "reply",
    [
        {"mfa_required": True},
        {"session_id": None},
        {"session_id": 123},
        {"session_id": " "},
        {"session_id": "s" * 4097},
    ],
)
async def test_missing_usable_session_requires_manual_browser_login(reply):
    session = Session(Response(reply))
    with pytest.raises(cloud_auth.CloudMFARequired):
        await request(session)
    assert len(session.calls) == 1


@pytest.mark.parametrize("raw", [b"[]", b"null", b"not JSON", b"\xff"])
async def test_malformed_login_does_not_send_token_request(raw):
    session = Session(Response(raw=raw))
    with pytest.raises(cloud_auth.CloudTokenError):
        await request(session)
    assert len(session.calls) == 1


@pytest.mark.parametrize("stage", ["login", "token"])
async def test_html_sign_in_requires_manual_token_including_mfa(stage):
    html = Response(raw=b"<html>Additional verification</html>", content_type="text/html")
    session = Session(*([good_login(), html] if stage == "token" else [html]))
    with pytest.raises(cloud_auth.CloudMFARequired):
        await request(session)
    assert len(session.calls) == (2 if stage == "token" else 1)


@pytest.mark.parametrize("stage", ["login", "token"])
@pytest.mark.parametrize(
    "failure",
    [
        TimeoutError("private credential details"),
        aiohttp.ClientConnectionError("private credential details"),
        ssl.SSLError("private credential details"),
        RuntimeError("Session is closed: private credential details"),
    ],
)
async def test_network_failure_is_safe_and_post_is_never_retried(stage, failure):
    session = Session(*([good_login(), failure] if stage == "token" else [failure]))
    with pytest.raises(cloud_auth.CloudCommunicationError) as error:
        await request(session)
    assert "private" not in str(error.value)
    assert error.value.__suppress_context__
    assert len(session.calls) == (2 if stage == "token" else 1)


async def test_cancellation_propagates_without_a_retry():
    session = Session(good_login(), asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await request(session)
    assert len(session.calls) == 2


@pytest.mark.parametrize("declared", [True, False])
@pytest.mark.parametrize("stage", ["login", "token"])
async def test_response_size_is_bounded_even_without_content_length(declared, stage):
    failure = Response(
        raw=b"x" * (128 * 1024 + 1),
        declared_length=128 * 1024 + 1 if declared else None,
    )
    session = Session(*([good_login(), failure] if stage == "token" else [failure]))
    with pytest.raises(cloud_auth.CloudTokenError):
        await request(session)
    assert failure.exited


@pytest.mark.parametrize(
    "claims",
    [
        {"exp": 0},
        {"exp": True},
        {"exp": None},
        {"exp": "2000000000"},
        {"exp": float("inf")},
        {"exp": float("nan")},
        {"exp": 10**100},
        {"aud": "999999999999"},
        {"aud": []},
        {"aud": None},
        {"aud": [SERIAL, 123]},
        {"aud": 123456789012},
    ],
)
async def test_unusable_unverified_token_hints_are_rejected(claims):
    token = jwt_token(**claims)
    session = Session(good_login(), Response(raw=token.encode()))
    with pytest.raises(cloud_auth.CloudTokenError) as error:
        await request(session)
    assert token not in str(error.value)


@pytest.mark.parametrize("audience", [SERIAL, [SERIAL], ["another-audience", SERIAL]])
async def test_matching_string_or_array_audience_is_accepted_as_hint_only(audience):
    token = jwt_token(aud=audience)
    session = Session(good_login(), Response(raw=f" \n{token}\n".encode()))
    assert await request(session) == token


async def test_absent_audience_is_left_for_authoritative_gateway_validation():
    original = jwt_token()
    header, encoded, signature = original.split(".")
    claims = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    del claims["aud"]
    encoded = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    token = f"{header}.{encoded}.{signature}"
    session = Session(good_login(), Response(raw=token.encode()))
    assert await request(session) == token


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"not a JWT",
        b"e30.e30.signature",
        b"e30.***.signature",
        b"\xff",
        b"a.b.c.d",
        b"a" * 32769,
        b'{"token":"do-not-guess-a-new-protocol"}',
    ],
)
async def test_malformed_token_response_has_no_response_text_in_error(raw):
    session = Session(good_login(), Response(raw=raw))
    with pytest.raises(cloud_auth.CloudTokenError):
        await request(session)
