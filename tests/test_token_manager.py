"""Renewal scheduling and guarded persistence, using only in-memory fakes."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.enphase_local_control import token_manager as module
from custom_components.enphase_local_control.api import (
    AuthenticationError,
    CertificateError,
    TokenMetadata,
)
from custom_components.enphase_local_control.cloud_auth import (
    CloudCommunicationError,
    CloudInvalidAuth,
    CloudMFARequired,
)


@pytest.fixture
def env(monkeypatch):
    clock = [datetime(2026, 10, 23, 12, tzinfo=UTC)]
    monkeypatch.setattr(module.dt_util, "utcnow", lambda: clock[0])
    entry = SimpleNamespace(
        unique_id="122600012345",
        data={
            "host": "192.0.2.60",
            "serial": "122600012345",
            "certificate_fingerprint": "ab" * 32,
            "token": "old-gateway-token",
            "auth_method": "automatic",
            "remember_credentials": True,
            "username": "homeowner@example.invalid",
            "password": "test-password",
        },
        async_start_reauth=MagicMock(),
    )
    client = MagicMock()
    client.token_metadata = TokenMetadata(
        expires_at=clock[0] + timedelta(days=20),
        issued_at=clock[0] - timedelta(days=345),
    )

    def replace(token):
        client.token_metadata = TokenMetadata(
            expires_at=clock[0] + timedelta(days=365), issued_at=clock[0]
        )

    client.replace_token.side_effect = replace
    validator = MagicMock()
    validator.get_info = AsyncMock(return_value=SimpleNamespace(serial=entry.unique_id))
    validator.get_scheduler = AsyncMock(return_value={"acb_debug_mode": -1})
    validator_factory = MagicMock(return_value=validator)
    monkeypatch.setattr(module, "GatewayClient", validator_factory)
    request = AsyncMock(return_value="new-gateway-token")
    monkeypatch.setattr(module, "request_gateway_token", request)

    def update(config_entry, *, data):
        config_entry.data = data
        return True

    hass = SimpleNamespace(
        config_entries=SimpleNamespace(async_update_entry=MagicMock(side_effect=update))
    )
    entry.async_create_background_task = lambda _hass, coroutine, _name: asyncio.create_task(
        coroutine
    )
    session = object()
    manager = module.TokenManager(hass, entry, client, session)
    return SimpleNamespace(
        now=clock,
        entry=entry,
        client=client,
        validator=validator,
        validator_factory=validator_factory,
        request=request,
        hass=hass,
        session=session,
        manager=manager,
    )


async def test_due_token_is_validated_pinned_and_replaced_atomically(env):
    old_data = dict(env.entry.data)
    assert await env.manager.async_ensure_token()
    env.request.assert_awaited_once_with(
        env.session, old_data["username"], old_data["password"], old_data["serial"]
    )
    env.validator_factory.assert_called_once_with(
        env.session,
        old_data["host"],
        "new-gateway-token",
        fingerprint=old_data["certificate_fingerprint"],
    )
    env.validator.get_info.assert_awaited_once()
    env.validator.get_scheduler.assert_awaited_once()
    env.validator.set_override.assert_not_called()
    assert env.entry.data == old_data | {"token": "new-gateway-token"}
    env.client.replace_token.assert_called_once_with("new-gateway-token")
    assert env.manager.last_error is None
    assert not await env.manager.async_ensure_token()
    assert env.request.await_count == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"auth_method": "manual"},
        {"remember_credentials": False},
        {"remember_credentials": 1},
        {"remember_credentials": None},
        {"username": ""},
        {"password": ""},
        {"certificate_fingerprint": ""},
    ],
)
async def test_no_renewal_without_explicit_complete_opt_in(env, changes):
    env.entry.data |= changes
    assert not await env.manager.async_ensure_token(force=True)
    env.request.assert_not_awaited()
    env.client.replace_token.assert_not_called()


async def test_year_token_renews_only_within_thirty_days(env):
    env.client.token_metadata = TokenMetadata(
        issued_at=env.now[0] - timedelta(days=334),
        expires_at=env.now[0] + timedelta(days=31),
    )
    assert not await env.manager.async_ensure_token()
    env.now[0] += timedelta(days=2)
    assert await env.manager.async_ensure_token()


async def test_twelve_hour_token_uses_ten_percent_early_window(env):
    env.client.token_metadata = TokenMetadata(
        issued_at=env.now[0], expires_at=env.now[0] + timedelta(hours=12)
    )
    assert not await env.manager.async_ensure_token()
    env.now[0] += timedelta(hours=10, minutes=40)
    assert not await env.manager.async_ensure_token()
    env.now[0] += timedelta(minutes=10)
    assert await env.manager.async_ensure_token()
    assert env.request.await_count == 1


async def test_missing_issue_time_uses_fixed_first_observed_time(env):
    env.client.token_metadata = TokenMetadata(expires_at=env.now[0] + timedelta(hours=6))
    assert not await env.manager.async_ensure_token()
    env.now[0] += timedelta(hours=5, minutes=20)
    assert not await env.manager.async_ensure_token()
    env.now[0] += timedelta(minutes=5)
    assert await env.manager.async_ensure_token()


async def test_force_bypasses_fresh_expiry_but_not_consent(env):
    env.client.token_metadata = TokenMetadata(
        issued_at=env.now[0], expires_at=env.now[0] + timedelta(days=365)
    )
    assert not await env.manager.async_ensure_token()
    assert await env.manager.async_ensure_token(force=True)


async def test_unknown_expiry_requires_explicit_force(env):
    env.client.token_metadata = TokenMetadata()
    assert not await env.manager.async_ensure_token()
    assert await env.manager.async_ensure_token(force=True)


async def test_cloud_failure_keeps_working_token_and_waits_twenty_four_hours(env):
    env.request.side_effect = CloudCommunicationError("Cloud unavailable")
    old = dict(env.entry.data)
    assert not await env.manager.async_ensure_token()
    assert env.entry.data == old
    env.client.replace_token.assert_not_called()
    assert env.manager.next_retry_at == env.now[0] + timedelta(hours=24)
    assert not await env.manager.async_ensure_token(force=True)
    assert env.request.await_count == 1
    env.now[0] += timedelta(hours=24, seconds=1)
    assert not await env.manager.async_ensure_token()
    assert env.request.await_count == 2


async def test_short_lifetime_cloud_failure_has_short_retry(env):
    env.client.token_metadata = TokenMetadata(
        issued_at=env.now[0] - timedelta(hours=11, minutes=20),
        expires_at=env.now[0] + timedelta(minutes=40),
    )
    env.request.side_effect = CloudCommunicationError("Cloud unavailable")
    assert not await env.manager.async_ensure_token()
    assert env.manager.next_retry_at == env.now[0] + timedelta(minutes=20)


@pytest.mark.parametrize("error_type", [CloudInvalidAuth, CloudMFARequired])
async def test_account_auth_failures_start_one_reauth_without_repeated_logins(env, error_type):
    env.request.side_effect = error_type("Account needs attention")
    assert not await env.manager.async_ensure_token()
    assert env.manager.needs_reauth
    env.entry.async_start_reauth.assert_called_once_with(env.hass)
    env.now[0] += timedelta(days=3)
    assert not await env.manager.async_ensure_token(force=True)
    assert env.request.await_count == 1
    assert env.entry.data["token"] == "old-gateway-token"


async def test_changed_credentials_unblock_cloud_renewal(env):
    env.request.side_effect = CloudInvalidAuth("Invalid account")
    assert not await env.manager.async_ensure_token()
    env.entry.data = env.entry.data | {"password": "replacement-password"}
    env.request.side_effect = None
    assert await env.manager.async_ensure_token()
    assert not env.manager.needs_reauth
    assert env.request.await_count == 2


@pytest.mark.parametrize(
    "local_error",
    [
        AuthenticationError("Candidate token rejected"),
        CertificateError("Pinned certificate changed"),
    ],
)
async def test_candidate_validation_failure_preserves_saved_token_and_pin(env, local_error):
    env.validator.get_info.side_effect = local_error
    before = dict(env.entry.data)
    assert not await env.manager.async_ensure_token()
    assert env.entry.data == before
    env.hass.config_entries.async_update_entry.assert_not_called()
    env.client.replace_token.assert_not_called()
    env.entry.async_start_reauth.assert_not_called()


async def test_candidate_must_match_gateway_serial(env):
    env.validator.get_info.return_value = SimpleNamespace(serial="different-gateway")
    assert not await env.manager.async_ensure_token()
    env.validator.get_scheduler.assert_not_awaited()
    env.client.replace_token.assert_not_called()
    assert env.entry.data["token"] == "old-gateway-token"


async def test_candidate_scheduler_read_must_succeed(env):
    env.validator.get_scheduler.side_effect = AuthenticationError("Scheduler rejected token")
    assert not await env.manager.async_ensure_token()
    env.client.replace_token.assert_not_called()
    assert env.entry.data["token"] == "old-gateway-token"


@pytest.mark.parametrize(
    "changed",
    [
        {"password": "edited-password"},
        {"remember_credentials": False},
        {"certificate_fingerprint": "cd" * 32},
        {"host": "192.0.2.61"},
        {"token": "user-replaced-token"},
    ],
)
async def test_connection_changes_while_minting_cannot_be_overwritten(env, changed):
    async def mint(*_args):
        env.entry.data = env.entry.data | changed
        return "new-gateway-token"

    env.request.side_effect = mint
    assert not await env.manager.async_ensure_token()
    env.validator_factory.assert_not_called()
    env.client.replace_token.assert_not_called()
    for key, value in changed.items():
        assert env.entry.data[key] == value


async def test_changes_during_local_validation_cannot_be_overwritten(env):
    async def read_scheduler():
        env.entry.data = env.entry.data | {"certificate_fingerprint": "cd" * 32}
        return {}

    env.validator.get_scheduler.side_effect = read_scheduler
    assert not await env.manager.async_ensure_token()
    assert env.entry.data["certificate_fingerprint"] == "cd" * 32
    assert env.entry.data["token"] == "old-gateway-token"
    env.client.replace_token.assert_not_called()


async def test_cancellation_during_mint_preserves_credentials(env):
    entered = asyncio.Event()

    async def blocked_mint(*_args):
        entered.set()
        await asyncio.Event().wait()

    env.request.side_effect = blocked_mint
    task = asyncio.create_task(env.manager.async_ensure_token())
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert env.entry.data["token"] == "old-gateway-token"
    env.client.replace_token.assert_not_called()


async def test_simultaneous_forced_renewals_share_one_cloud_request(env):
    entered, release = asyncio.Event(), asyncio.Event()

    async def mint(*_args):
        entered.set()
        await release.wait()
        return "new-gateway-token"

    env.request.side_effect = mint
    first = asyncio.create_task(env.manager.async_ensure_token(force=True))
    await entered.wait()
    second = asyncio.create_task(env.manager.async_ensure_token(force=True))
    await asyncio.sleep(0)
    release.set()
    assert await asyncio.gather(first, second) == [True, True]
    assert env.request.await_count == 1
    env.client.replace_token.assert_called_once()


async def test_same_candidate_does_not_cause_renewal_loop(env):
    env.request.return_value = "old-gateway-token"
    assert not await env.manager.async_ensure_token()
    assert env.manager.next_retry_at is not None
    assert not await env.manager.async_ensure_token(force=True)
    assert env.request.await_count == 1
    env.client.replace_token.assert_not_called()


async def test_background_lifecycle_is_independent_of_entity_listeners(env, monkeypatch):
    callbacks = []

    def schedule(_hass, delay, callback):
        cancel = MagicMock()
        callbacks.append((delay, callback, cancel))
        return cancel

    monkeypatch.setattr(module, "async_call_later", schedule)
    await env.manager.async_start()
    await env.manager.async_start()
    assert len(callbacks) == 1
    env.request.assert_not_awaited()
    callbacks[0][1](env.now[0])
    task = env.manager._task
    assert task is not None
    await task
    assert env.request.await_count == 1
    assert len(callbacks) == 2
    await env.manager.async_stop()
    callbacks[-1][2].assert_called_once()
    assert env.manager._task is None


async def test_stop_cancels_inflight_background_without_persistence(env, monkeypatch):
    callbacks = []
    monkeypatch.setattr(
        module,
        "async_call_later",
        lambda _hass, _delay, callback: callbacks.append(callback) or MagicMock(),
    )
    entered = asyncio.Event()

    async def mint(*_args):
        entered.set()
        await asyncio.Event().wait()

    env.request.side_effect = mint
    await env.manager.async_start()
    callbacks[0](env.now[0])
    await entered.wait()
    await env.manager.async_stop()
    assert env.entry.data["token"] == "old-gateway-token"
    env.client.replace_token.assert_not_called()
    assert len(callbacks) == 1


async def test_unexpected_background_failure_is_redacted_and_backed_off(env, monkeypatch, caplog):
    callbacks = []
    monkeypatch.setattr(
        module,
        "async_call_later",
        lambda _hass, delay, callback: callbacks.append((delay, callback)) or MagicMock(),
    )
    before = dict(env.entry.data)
    secret = "private password, session and JWT response details"
    env.request.side_effect = ValueError(secret)
    await env.manager.async_start()
    callbacks[0][1](env.now[0])
    await env.manager._task

    assert isinstance(env.manager.last_error, CloudCommunicationError)
    assert secret not in str(env.manager.last_error)
    assert env.manager.last_error.__context__ is None
    assert secret not in caplog.text
    assert env.manager.next_retry_at > env.now[0]
    assert callbacks[-1][0] > 1
    assert env.entry.data == before
    env.hass.config_entries.async_update_entry.assert_not_called()
    env.client.replace_token.assert_not_called()
    env.validator.set_override.assert_not_called()
    # A subsequent scheduled check during backoff makes no second cloud call.
    callbacks[-1][1](env.now[0])
    await env.manager._task
    assert env.request.await_count == 1
    await env.manager.async_stop()


async def test_unexpected_obsolete_failure_does_not_back_off_new_credentials(env):
    async def obsolete_request(*_args):
        env.entry.data = env.entry.data | {"password": "new-account-password"}
        raise ValueError("obsolete sensitive response")

    env.request.side_effect = obsolete_request
    await env.manager._background_check()
    assert env.manager.last_error is None
    assert env.manager.next_retry_at is None
    env.client.replace_token.assert_not_called()
    env.hass.config_entries.async_update_entry.assert_not_called()


async def test_background_cancellation_stays_cancellation_without_backoff(env):
    env.request.side_effect = asyncio.CancelledError()
    with pytest.raises(asyncio.CancelledError):
        await env.manager._background_check()
    assert env.manager.last_error is None
    assert env.manager.next_retry_at is None
    env.client.replace_token.assert_not_called()
    env.hass.config_entries.async_update_entry.assert_not_called()
