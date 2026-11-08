"""Opt-in cloud token renewal with pinned, read-only local validation."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import datetime, timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_TOKEN, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_call_later
from homeassistant.util import dt as dt_util

from .api import GatewayClient, GatewayError
from .cloud_auth import (
    CloudAuthError,
    CloudCommunicationError,
    CloudInvalidAuth,
    CloudMFARequired,
    CloudTokenError,
    request_gateway_token,
)
from .const import CONF_FINGERPRINT, CONF_SERIAL

_MAX_CHECK_INTERVAL = timedelta(minutes=15)
_MAX_EARLY_WINDOW = timedelta(days=30)
_LONG_RETRY = timedelta(hours=24)
_SHORT_RETRY = timedelta(hours=1)
_MIN_RETRY = timedelta(seconds=60)


class TokenManager:
    """Renew only with explicit permission to retain account credentials.

    The live gateway token is kept during cloud failures. A replacement is
    installed only after pinned reads confirm the same gateway and scheduler.
    No method changes a scheduler mode or certificate trust.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: GatewayClient,
        session: Any,
    ) -> None:
        self.hass = hass
        self.entry = entry
        self.client = client
        self.session = session
        self._lock = asyncio.Lock()
        self._running = False
        self._cancel_check = None
        self._task: asyncio.Task | None = None
        self._credential_binding: tuple | None = None
        self._blocked_binding: tuple | None = None
        self._next_retry_at: datetime | None = None
        self._observed_token: str | None = None
        self._observed_at: datetime | None = None
        self._generation = 0
        self.last_error: Exception | None = None

    @property
    def next_retry_at(self) -> datetime | None:
        """Next permitted cloud retry, for non-secret diagnostics."""
        return self._next_retry_at

    @property
    def enabled(self) -> bool:
        """Whether complete, explicitly remembered credentials permit renewal."""
        return self._can_renew(self.entry.data)

    @property
    def renewal_blocked(self) -> bool:
        """Whether these credentials require explicit reauthentication."""
        return self._blocked_binding == self._credentials(self.entry.data)

    @property
    def needs_reauth(self) -> bool:
        return self.renewal_blocked

    @staticmethod
    def _credentials(data: Any) -> tuple:
        return (
            data.get("auth_method"),
            data.get("remember_credentials") is True,
            data.get(CONF_USERNAME),
            data.get(CONF_PASSWORD),
            data.get(CONF_SERIAL),
        )

    @staticmethod
    def _can_renew(data: Any) -> bool:
        return (
            data.get("auth_method") == "automatic"
            and data.get("remember_credentials") is True
            and all(
                isinstance(data.get(key), str) and bool(data[key].strip())
                for key in (
                    CONF_USERNAME,
                    CONF_PASSWORD,
                    CONF_SERIAL,
                    CONF_HOST,
                    CONF_FINGERPRINT,
                )
            )
        )

    def _due_at(self, now: datetime) -> datetime | None:
        token = self.entry.data.get(CONF_TOKEN)
        if token != self._observed_token:
            self._observed_token = token
            self._observed_at = now
        metadata = self.client.token_metadata
        expiry = metadata.expires_at
        if expiry is None:
            return None
        issued = metadata.issued_at
        if issued is None or issued >= expiry:
            issued = self._observed_at or now
        lifetime = max(timedelta(0), expiry - issued)
        window = min(_MAX_EARLY_WINDOW, lifetime / 10)
        return expiry - window

    def _retry_delay(self, now: datetime) -> timedelta:
        expiry = self.client.token_metadata.expires_at
        if expiry is None:
            return _LONG_RETRY
        remaining = expiry - now
        if remaining <= timedelta(days=2):
            return min(_SHORT_RETRY, max(_MIN_RETRY, remaining / 2))
        return min(_LONG_RETRY, max(_MIN_RETRY, remaining / 2))

    async def async_ensure_token(self, force: bool = False) -> bool:
        """Renew if due; false means the existing token was retained.

        Force bypasses expiry scheduling, for an authenticated-read 401. It does
        not bypass credential opt-in, failure backoff, or permanent auth blocks.
        Original cloud or candidate-validation errors are available via
        ``last_error``; they never replace a still-working local credential.
        """
        generation = self._generation
        async with self._lock:
            if force and generation != self._generation:
                # Another overlapping 401 handler already installed a validated
                # token while this caller waited. Reuse it instead of minting twice.
                return True
            now = dt_util.utcnow()
            data = dict(self.entry.data)
            credentials = self._credentials(data)
            if credentials != self._credential_binding:
                self._credential_binding = credentials
                self._blocked_binding = None
                self._next_retry_at = None
                self.last_error = None
            if not self._can_renew(data) or self._blocked_binding == credentials:
                return False
            if self._next_retry_at is not None and now < self._next_retry_at:
                return False
            due_at = self._due_at(now)
            if not force and (due_at is None or now < due_at):
                return False

            expected_unique_id = self.entry.unique_id
            try:
                candidate = await request_gateway_token(
                    self.session,
                    data[CONF_USERNAME],
                    data[CONF_PASSWORD],
                    data[CONF_SERIAL],
                )
                # A settings change during cloud I/O cancels this attempt before
                # any candidate is sent to an obsolete local connection.
                if not self._unchanged(data, expected_unique_id):
                    return False
                validator = GatewayClient(
                    self.session,
                    data[CONF_HOST],
                    candidate,
                    fingerprint=data[CONF_FINGERPRINT],
                )
                identity = await validator.get_info()
                if identity.serial != data[CONF_SERIAL]:
                    raise CloudTokenError("The replacement token identified a different gateway.")
                await validator.get_scheduler()
            except (CloudInvalidAuth, CloudMFARequired) as err:
                # Re-check before starting reauth: an old request must not block
                # newly saved credentials or change their flow state.
                if self._unchanged(data, expected_unique_id):
                    self.last_error = err
                    self._blocked_binding = credentials
                    self.entry.async_start_reauth(self.hass)
                return False
            except (CloudAuthError, GatewayError) as err:
                if self._unchanged(data, expected_unique_id):
                    self.last_error = err
                    self._next_retry_at = now + self._retry_delay(now)
                return False

            # Cancellation before this point cannot alter the saved/live token.
            # There is no await between the final guard, config update and live
            # replacement, so another flow cannot interleave these operations.
            if not self._unchanged(data, expected_unique_id):
                return False
            if candidate == data.get(CONF_TOKEN):
                self._next_retry_at = now + self._retry_delay(now)
                return False
            self.hass.config_entries.async_update_entry(
                self.entry, data=data | {CONF_TOKEN: candidate}
            )
            self.client.replace_token(candidate)
            self._generation += 1
            self._observed_token = candidate
            self._observed_at = now
            self._next_retry_at = None
            self.last_error = None
            # Defend against a cloud service returning an already-renewal-due
            # token without creating a cloud request loop.
            due_at = self._due_at(now)
            if due_at is not None and due_at <= now:
                self._next_retry_at = now + self._retry_delay(now)
            return True

    def _unchanged(self, data: dict[str, Any], unique_id: str | None) -> bool:
        return self.entry.unique_id == unique_id and dict(self.entry.data) == data

    async def async_start(self) -> None:
        """Start an independent periodic check; never rely on entity listeners."""
        if self._running:
            return
        self._running = True
        self._schedule_check(soon=True)

    @callback
    def _schedule_check(self, *, soon: bool = False) -> None:
        if not self._running:
            return
        if self._cancel_check is not None:
            self._cancel_check()
        now = dt_util.utcnow()
        delay = _MAX_CHECK_INTERVAL.total_seconds()
        if soon:
            delay = 1.0
        elif self._can_renew(self.entry.data) and not self.renewal_blocked:
            due_at = self._next_retry_at or self._due_at(now)
            if due_at is not None:
                delay = max(1.0, min(delay, (due_at - now).total_seconds()))
        self._cancel_check = async_call_later(self.hass, delay, self._run_check)

    @callback
    def _run_check(self, _now: datetime) -> None:
        self._cancel_check = None
        if self._running:
            self._task = self.entry.async_create_background_task(
                self.hass, self._background_check(), "Enphase gateway token renewal"
            )

    async def _background_check(self) -> None:
        data = dict(self.entry.data)
        unique_id = self.entry.unique_id
        try:
            await self.async_ensure_token()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Unexpected transport/library failures must not leak response or
            # credential details through a task traceback or trigger a 1 s loop.
            # An obsolete request must not delay newly saved credentials.
            if self._unchanged(data, unique_id):
                self.last_error = CloudCommunicationError(
                    "Automatic Enphase token renewal could not be completed. "
                    "The current gateway token was retained; renewal will retry later."
                )
                now = dt_util.utcnow()
                self._next_retry_at = now + self._retry_delay(now)
        finally:
            self._task = None
            self._schedule_check()

    async def async_stop(self) -> None:
        """Cancel renewal checks without changing a token or battery mode."""
        self._running = False
        if self._cancel_check is not None:
            self._cancel_check()
            self._cancel_check = None
        task = self._task
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
