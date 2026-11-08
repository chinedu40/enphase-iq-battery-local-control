"""Shared, Home Assistant independent controller for the local scheduler.

The gateway has one override value. Switches are views of that confirmed value,
not independent booleans. No command is replayed on startup or reconnect.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Protocol

ZERO_NET = 1
CHARGE_FROM_GRID = 2
DISCHARGE_TO_GRID = 3
RESTRICT_DISCHARGE = 4
RETURN_TO_NORMAL = -1
SUPPORTED_MODES = (ZERO_NET, CHARGE_FROM_GRID, DISCHARGE_TO_GRID, RESTRICT_DISCHARGE)

_EXPECTED_LABELS = {
    ZERO_NET: frozenset({"zeronet", "znzeronet"}),
    CHARGE_FROM_GRID: frozenset({"chargefromgrid", "cgchargefromgrid"}),
    DISCHARGE_TO_GRID: frozenset({"dischargetogrid", "dgdischargetogrid"}),
}
_RESTRICT_DISCHARGE_LABELS = frozenset({"nodischarge", "ndnodischarge"})


class SchedulerClient(Protocol):
    """Small API surface needed by the mode controller."""

    async def get_scheduler(self) -> Mapping[str, Any]:
        """Return the current scheduler response."""

    async def set_override(self, mode: int) -> Any:
        """Write an override once; the controller performs readback."""


class ControllerError(Exception):
    """Base error for local controller validation."""


class InvalidMode(ControllerError):
    """A caller requested a mode outside the supported switches."""


class UnsupportedModes(ControllerError):
    """The gateway's mode labels do not match the verified code mapping."""


class InvalidSchedulerResponse(ControllerError):
    """The scheduler response cannot establish its current override."""


class CommandNotConfirmed(ControllerError):
    """A successful write was not confirmed by the gateway's readback."""

    def __init__(self, requested_mode: int, observed_mode: int) -> None:
        self.requested_mode = requested_mode
        self.observed_mode = observed_mode
        super().__init__(f"Requested override {requested_mode}; gateway reports {observed_mode}")


@dataclass(frozen=True)
class SchedulerState:
    """A confirmed scheduler response, including unsupported external modes."""

    raw: Mapping[str, Any]
    debug_mode: int
    current_mode: int
    mode_labels: tuple[str, ...]
    modes_supported: bool
    mode_schema_error: str | None = None

    @property
    def selected_mode(self) -> int:
        """Use actual mode when the gateway has no explicit override."""
        return self.current_mode if self.debug_mode == RETURN_TO_NORMAL else self.debug_mode

    def supports_mode(self, mode: int) -> bool:
        """Require the established base mapping and the optional label for code 4."""
        if not self.modes_supported or mode not in SUPPORTED_MODES:
            return False
        if mode != RESTRICT_DISCHARGE:
            return True
        return mode < len(self.mode_labels) and (
            _normalize_label(self.mode_labels[mode]) in _RESTRICT_DISCHARGE_LABELS
        )


@dataclass(frozen=True)
class CommandResult:
    """The result of a command after confirmation or reconciliation."""

    state: SchedulerState
    changed: bool
    reconciled: bool = False


def _validate_mode(mode: int) -> None:
    if type(mode) is not int or mode not in SUPPORTED_MODES:
        raise InvalidMode(f"Unsupported switch mode: {mode!r}")


def _normalize_label(label: str) -> str:
    return re.sub(r"[^a-z0-9]", "", label.casefold())


def _scheduler_state(payload: Mapping[str, Any]) -> SchedulerState:
    if not isinstance(payload, Mapping):
        raise InvalidSchedulerResponse("Scheduler response is not an object")
    debug_mode = payload.get("acb_debug_mode")
    current_mode = payload.get("acb_current_mode")
    if type(debug_mode) is not int or type(current_mode) is not int:
        raise InvalidSchedulerResponse("Scheduler mode values must be integers")

    labels = payload.get("sched_mode_key")
    schema_error: str | None = None
    if not isinstance(labels, list) or not all(isinstance(item, str) for item in labels):
        mode_labels: tuple[str, ...] = ()
        schema_error = "Scheduler mode labels are missing or invalid"
    else:
        mode_labels = tuple(labels)
        for code, accepted in _EXPECTED_LABELS.items():
            if code >= len(mode_labels):
                schema_error = f"Scheduler mode label {code} is missing"
                break
            if _normalize_label(mode_labels[code]) not in accepted:
                schema_error = f"Scheduler mode label {code} does not match the verified mapping"
                break

    return SchedulerState(
        raw=deepcopy(dict(payload)),
        debug_mode=debug_mode,
        current_mode=current_mode,
        mode_labels=mode_labels,
        modes_supported=schema_error is None,
        mode_schema_error=schema_error,
    )


class ModeController:
    """Serialize polling and commands for one gateway.

    ``available`` describes whether the last read established a live response;
    ``state`` retains the last confirmed response for diagnostics. Callers must
    not present retained data as live when available is false. API errors are
    propagated unchanged so an adapter can distinguish reauth from connectivity.
    """

    def __init__(self, client: SchedulerClient) -> None:
        self._client = client
        self._lock = asyncio.Lock()
        self.state: SchedulerState | None = None
        self.available = False
        self.last_error: Exception | None = None

    @property
    def debug_mode(self) -> int | None:
        """Last confirmed override, including -1 and external modes."""
        return self.state.debug_mode if self.state is not None else None

    @property
    def current_mode(self) -> int | None:
        """Last confirmed actual controller mode; not a switch state."""
        return self.state.current_mode if self.state is not None else None

    @property
    def modes_supported(self) -> bool:
        return self.state is not None and self.state.modes_supported

    @property
    def selected_mode(self) -> int | None:
        """Last confirmed selected mode, with automatic actual-mode fallback."""
        return self.state.selected_mode if self.state is not None else None

    def is_on(self, mode: int) -> bool | None:
        """Derive switches from the override or actual mode in automatic control."""
        _validate_mode(mode)
        state = self.state
        if not self.available or state is None or not state.supports_mode(mode):
            return None
        selected = state.selected_mode
        # Even if an optional label for code 4 is missing, the confirmed
        # selection is distinct from each verified alternative. Keep those
        # switches usable without claiming that code 4 is No Discharge.
        if selected != RESTRICT_DISCHARGE and not 0 <= selected < len(state.mode_labels):
            return None
        return selected == mode

    async def _read_locked(self) -> SchedulerState:
        try:
            state = _scheduler_state(await self._client.get_scheduler())
        except asyncio.CancelledError:
            self.available = False
            raise
        except Exception as err:
            self.available = False
            self.last_error = err
            raise
        self.state = state
        self.available = True
        self.last_error = None
        return state

    async def async_refresh(self) -> SchedulerState:
        """Read current state; this never writes or reapplies an override."""
        async with self._lock:
            return await self._read_locked()

    async def async_turn_on(self, mode: int) -> CommandResult:
        """Select one override directly, then confirm it from the gateway."""
        _validate_mode(mode)
        async with self._lock:
            state = await self._read_locked()
            self._require_supported(state, mode)
            if state.debug_mode == mode:
                return CommandResult(state, changed=False)
            return await self._write_locked(mode)

    async def async_turn_off(self, mode: int) -> CommandResult:
        """Return an active non-Zero-Net switch to Zero Net."""
        _validate_mode(mode)
        async with self._lock:
            state = await self._read_locked()
            if mode == ZERO_NET or state.selected_mode != mode:
                return CommandResult(state, changed=False)
            self._require_supported(state, mode)
            return await self._write_locked(ZERO_NET)

    async def async_return_to_automatic(self) -> CommandResult:
        """Release a local override without depending on its mode-label mapping.

        This explicit maintenance command is never called automatically during
        setup, reconnect, unload, or shutdown.
        """
        async with self._lock:
            state = await self._read_locked()
            if state.debug_mode == RETURN_TO_NORMAL:
                return CommandResult(state, changed=False)
            return await self._write_locked(RETURN_TO_NORMAL)

    @staticmethod
    def _require_supported(state: SchedulerState, mode: int) -> None:
        if not state.modes_supported:
            raise UnsupportedModes(state.mode_schema_error or "Unsupported mode mapping")
        if not state.supports_mode(mode):
            raise UnsupportedModes(
                f"Scheduler mode label {mode} is missing or does not match the verified mapping"
            )

    async def _write_locked(self, mode: int) -> CommandResult:
        try:
            await self._client.set_override(mode)
        except asyncio.CancelledError:
            # The POST may have reached the gateway. A subsequent refresh or
            # command will reconcile; reconnect never automatically reasserts it.
            self.available = False
            raise
        except Exception as write_error:
            # A timeout can occur after application. Read once before deciding,
            # and never blindly repeat an uncertain write.
            try:
                state = await self._read_locked()
            except Exception as read_error:
                raise read_error from write_error
            if state.debug_mode == mode:
                if mode == RESTRICT_DISCHARGE:
                    self._require_supported(state, mode)
                return CommandResult(state, changed=True, reconciled=True)
            self.last_error = write_error
            raise

        state = await self._read_locked()
        if state.debug_mode != mode:
            err = CommandNotConfirmed(mode, state.debug_mode)
            self.last_error = err
            raise err
        if mode == RESTRICT_DISCHARGE:
            self._require_supported(state, mode)
        return CommandResult(state, changed=True)
