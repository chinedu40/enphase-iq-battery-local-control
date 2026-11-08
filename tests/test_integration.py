"""Exercise the integration through Home Assistant's actual entity services."""

from copy import deepcopy
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from homeassistant.const import EVENT_STATE_CHANGED, STATE_OFF, STATE_ON, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers import issue_registry as ir
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.enphase_local_control.api import (
    AuthenticationError,
    CertificateError,
    CommunicationError,
    PermissionDeniedError,
)
from custom_components.enphase_local_control.cloud_auth import CloudCommunicationError
from custom_components.enphase_local_control.const import DOMAIN
from custom_components.enphase_local_control.diagnostics import (
    async_get_config_entry_diagnostics,
)

pytestmark = pytest.mark.usefixtures("enable_custom_integrations")

HOST = "192.0.2.60"
TOKEN = "test-private-token-must-never-appear-in-diagnostics"
SERIAL = "122600012345"
SWITCH_KEYS = ("charge_from_grid", "discharge_to_grid", "zero_net", "restrict_discharge")
MODE_LABELS = [
    "ID - Idle",
    "ZN - Zero Net",
    "CG - Charge From Grid",
    "DG - Discharge to Grid",
    "ND - No Discharge",
    "DL - Discharge to Load",
    "CP - Charge From PV",
]


class RecordingGateway:
    """In-memory gateway; every command is observable and no socket is opened."""

    def __init__(self, *, current_mode: int = 1, debug_mode: int = -1) -> None:
        self.payload = {
            "acb_current_mode": current_mode,
            "acb_debug_mode": debug_mode,
            "sched_mode_key": MODE_LABELS.copy(),
        }
        self.commands: list[int] = []
        self.reads = 0
        self.read_error: Exception | None = None
        self.token_metadata = SimpleNamespace(expires_at=None, issued_at=None)

    async def get_info(self):
        return SimpleNamespace(serial=SERIAL, model="IQ Gateway", firmware="D8.3.5286")

    async def get_scheduler(self):
        self.reads += 1
        if self.read_error is not None:
            raise self.read_error
        return deepcopy(self.payload)

    async def get_status(self):
        return {}

    async def set_override(self, mode: int):
        self.commands.append(mode)
        self.payload["acb_debug_mode"] = mode
        if mode != -1:
            self.payload["acb_current_mode"] = mode
        return {"acb_debug_mode": mode}


async def setup_gateway(hass: HomeAssistant, gateway: RecordingGateway):
    """Set up a genuine config entry and all integration platforms."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="IQ Gateway",
        unique_id=SERIAL,
        data={
            "host": HOST,
            "token": TOKEN,
            "serial": SERIAL,
            "model": "IQ Gateway",
            "firmware": "D8.3.5286",
        },
    )
    entry.add_to_hass(hass)
    with patch("custom_components.enphase_local_control.GatewayClient", return_value=gateway):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


def entity_id(hass: HomeAssistant, entry: MockConfigEntry, key: str) -> str:
    """Locate an entity without relying on generated or translated names."""
    entries = er.async_entries_for_config_entry(er.async_get(hass), entry.entry_id)
    matches = [item.entity_id for item in entries if item.translation_key == key]
    assert len(matches) == 1, [(item.entity_id, item.translation_key) for item in entries]
    return matches[0]


def assert_switches(hass: HomeAssistant, entry: MockConfigEntry, active: str) -> None:
    for key in SWITCH_KEYS:
        state = hass.states.get(entity_id(hass, entry, key))
        assert state is not None
        assert state.state == (STATE_ON if key == active else STATE_OFF)


async def call_switch(hass: HomeAssistant, target: str, service: str) -> None:
    await hass.services.async_call("switch", service, {"entity_id": target}, blocking=True)
    await hass.async_block_till_done()


async def test_setup_and_unload_never_write(hass: HomeAssistant) -> None:
    """Startup observes an existing mode, and unload leaves the battery alone."""
    gateway = RecordingGateway(current_mode=1, debug_mode=-1)
    entry = await setup_gateway(hass, gateway)

    assert gateway.reads >= 1
    assert gateway.commands == []
    assert_switches(hass, entry, "zero_net")

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    assert gateway.commands == []


async def test_switches_are_exclusive_and_active_off_falls_back_to_zero_net(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway()
    entry = await setup_gateway(hass, gateway)
    charge = entity_id(hass, entry, "charge_from_grid")
    discharge = entity_id(hass, entry, "discharge_to_grid")
    zero_net = entity_id(hass, entry, "zero_net")
    restrict = entity_id(hass, entry, "restrict_discharge")
    observed = {
        target: hass.states.get(target).state for target in (charge, discharge, zero_net, restrict)
    }
    selected_counts = []

    @callback
    def record_state_event(event):
        target = event.data["entity_id"]
        if target in observed and event.data["new_state"] is not None:
            observed[target] = event.data["new_state"].state
            selected_counts.append(sum(value == STATE_ON for value in observed.values()))

    remove_listener = hass.bus.async_listen(EVENT_STATE_CHANGED, record_state_event)

    await call_switch(hass, charge, "turn_on")
    assert gateway.commands == [2]
    assert_switches(hass, entry, "charge_from_grid")

    # Automations commonly turn an entire group off. An already-off switch
    # must not erase the active charging choice.
    await call_switch(hass, discharge, "turn_off")
    assert gateway.commands == [2]
    assert_switches(hass, entry, "charge_from_grid")

    await call_switch(hass, restrict, "turn_on")
    assert gateway.commands == [2, 4]
    assert_switches(hass, entry, "restrict_discharge")

    await call_switch(hass, charge, "turn_off")
    assert gateway.commands == [2, 4]
    assert_switches(hass, entry, "restrict_discharge")

    await call_switch(hass, restrict, "turn_off")
    assert gateway.commands == [2, 4, 1]
    assert_switches(hass, entry, "zero_net")

    await call_switch(hass, zero_net, "turn_off")
    assert gateway.commands == [2, 4, 1]
    assert_switches(hass, entry, "zero_net")

    await call_switch(hass, discharge, "turn_on")
    assert gateway.commands == [2, 4, 1, 3]
    assert_switches(hass, entry, "discharge_to_grid")

    await call_switch(hass, charge, "turn_off")
    assert gateway.commands == [2, 4, 1, 3]
    assert_switches(hass, entry, "discharge_to_grid")

    await call_switch(hass, discharge, "turn_off")
    assert gateway.commands == [2, 4, 1, 3, 1]
    assert_switches(hass, entry, "zero_net")
    remove_listener()
    assert selected_counts
    assert all(count <= 1 for count in selected_counts)


@pytest.mark.parametrize("label", [None, "Discharge to Load"])
async def test_incompatible_restrict_switch_is_unavailable_but_verified_modes_work(
    hass: HomeAssistant, label: str | None
) -> None:
    gateway = RecordingGateway(current_mode=4, debug_mode=4)
    if label is None:
        del gateway.payload["sched_mode_key"][4:]
    else:
        gateway.payload["sched_mode_key"][4] = label
    entry = await setup_gateway(hass, gateway)
    restrict = entity_id(hass, entry, "restrict_discharge")
    assert hass.states.get(restrict).state == STATE_UNAVAILABLE
    for key in SWITCH_KEYS[:-1]:
        assert hass.states.get(entity_id(hass, entry, key)).state == STATE_OFF
    await call_switch(hass, restrict, "turn_on")
    await call_switch(hass, restrict, "turn_off")
    assert gateway.commands == []

    zero_net = entity_id(hass, entry, "zero_net")
    await call_switch(hass, zero_net, "turn_on")
    assert gateway.commands == [1]
    assert hass.states.get(zero_net).state == STATE_ON
    assert hass.states.get(restrict).state == STATE_UNAVAILABLE


async def test_only_explicit_automatic_button_writes_minus_one(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway(current_mode=2, debug_mode=2)
    entry = await setup_gateway(hass, gateway)
    assert_switches(hass, entry, "charge_from_grid")
    assert gateway.commands == []

    # This maintenance action is disabled by default. Enabling it is explicit,
    # and its ensuing integration reload must also remain read-only.
    registry = er.async_get(hass)
    registry.async_update_entity(entity_id(hass, entry, "return_to_automatic"), disabled_by=None)
    with patch("custom_components.enphase_local_control.GatewayClient", return_value=gateway):
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()
    assert gateway.commands == []

    await hass.services.async_call(
        "button",
        "press",
        {"entity_id": entity_id(hass, entry, "return_to_automatic")},
        blocking=True,
    )
    await hass.async_block_till_done()
    assert gateway.commands == [-1]


async def test_unrecognised_runtime_mode_is_unavailable(hass: HomeAssistant) -> None:
    gateway = RecordingGateway()
    entry = await setup_gateway(hass, gateway)
    gateway.payload.update(acb_current_mode=99, acb_debug_mode=99)

    await entry.runtime_data.async_request_refresh()
    await hass.async_block_till_done()

    for key in SWITCH_KEYS:
        assert hass.states.get(entity_id(hass, entry, key)).state == STATE_UNAVAILABLE
    assert gateway.commands == []


async def test_diagnostics_redacts_credentials(hass: HomeAssistant) -> None:
    gateway = RecordingGateway()
    entry = await setup_gateway(hass, gateway)
    email = "private-email-for-diagnostics@example.invalid"
    password = "private-account-password-must-not-appear"
    hass.config_entries.async_update_entry(
        entry,
        data=dict(entry.data)
        | {
            "auth_method": "automatic",
            "remember_credentials": True,
            "username": email,
            "password": password,
            "certificate_fingerprint": "a1" * 32,
        },
    )
    result = await async_get_config_entry_diagnostics(hass, entry)
    for secret in (TOKEN, HOST, SERIAL, email, password):
        assert secret not in repr(result)
    assert result["automatic_renewal_enabled"] is True
    assert gateway.commands == []


async def test_connection_loss_and_recovery_never_replay_a_mode(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway(current_mode=2, debug_mode=2)
    entry = await setup_gateway(hass, gateway)
    gateway.read_error = CommunicationError("Gateway is offline")
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    for key in SWITCH_KEYS:
        assert hass.states.get(entity_id(hass, entry, key)).state == STATE_UNAVAILABLE

    # Another controller changed the mode while this integration was offline.
    # Recovery must publish that truth rather than reassert the stale UI state.
    gateway.read_error = None
    gateway.payload.update(acb_current_mode=3, acb_debug_mode=3)
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert_switches(hass, entry, "discharge_to_grid")
    assert gateway.commands == []


async def test_command_authentication_failure_requests_reauth_without_replaying(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway()
    entry = await setup_gateway(hass, gateway)
    gateway.read_error = AuthenticationError("The token has expired", status=401)

    with patch.object(entry, "async_start_reauth") as start_reauth:
        with pytest.raises(HomeAssistantError, match="Replace the gateway JWT"):
            await call_switch(hass, entity_id(hass, entry, "charge_from_grid"), "turn_on")
        await hass.async_block_till_done()
    start_reauth.assert_called_once_with(hass)
    for key in SWITCH_KEYS:
        assert hass.states.get(entity_id(hass, entry, key)).state == STATE_UNAVAILABLE
    assert gateway.commands == []

    gateway.read_error = None
    gateway.payload.update(acb_current_mode=3, acb_debug_mode=3)
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert_switches(hass, entry, "discharge_to_grid")
    assert gateway.commands == []


@pytest.mark.parametrize("failure", ["permission_denied", "ack_without_application"])
async def test_rejected_or_unconfirmed_command_never_optimistically_selects(
    hass: HomeAssistant, failure: str
) -> None:
    gateway = RecordingGateway()
    entry = await setup_gateway(hass, gateway)

    async def rejected_command(mode: int):
        gateway.commands.append(mode)
        if failure == "permission_denied":
            raise PermissionDeniedError("Control access was denied", status=403)
        # An apparently successful HTTP acknowledgement is insufficient: the
        # fresh scheduler still reports the pre-command Zero Net state.
        return {"acb_debug_mode": mode}

    gateway.set_override = AsyncMock(side_effect=rejected_command)
    with pytest.raises(HomeAssistantError, match="not confirmed"):
        await call_switch(hass, entity_id(hass, entry, "charge_from_grid"), "turn_on")
    await hass.async_block_till_done()
    gateway.set_override.assert_awaited_once_with(2)
    assert gateway.commands == [2]
    assert_switches(hass, entry, "zero_net")


async def test_mapping_change_blocks_controls_but_keeps_explicit_release_available(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway(current_mode=2, debug_mode=2)
    entry = await setup_gateway(hass, gateway)
    registry = er.async_get(hass)
    automatic = entity_id(hass, entry, "return_to_automatic")
    registry.async_update_entity(automatic, disabled_by=None)
    with patch("custom_components.enphase_local_control.GatewayClient", return_value=gateway):
        assert await hass.config_entries.async_reload(entry.entry_id)
        await hass.async_block_till_done()

    gateway.payload["sched_mode_key"][3] = "A firmware-defined different mode"
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    for key in SWITCH_KEYS:
        assert hass.states.get(entity_id(hass, entry, key)).state == STATE_UNAVAILABLE
    # Home Assistant skips service targets which are unavailable. The crucial
    # observable result is that neither the stale code nor another code is sent.
    await call_switch(hass, entity_id(hass, entry, "charge_from_grid"), "turn_on")
    assert gateway.commands == []

    await hass.services.async_call("button", "press", {"entity_id": automatic}, blocking=True)
    await hass.async_block_till_done()
    assert gateway.commands == [-1]
    assert gateway.payload["acb_debug_mode"] == -1


async def test_runtime_certificate_failure_never_enrolls_or_replaces_pin(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway(current_mode=2, debug_mode=2)
    entry = await setup_gateway(hass, gateway)
    saved = dict(entry.data)
    gateway.read_error = CertificateError("Certificate changed")
    with patch(
        "custom_components.enphase_local_control.config_flow.probe_certificate",
        new_callable=AsyncMock,
    ) as probe:
        await entry.runtime_data.async_refresh()
        await hass.async_block_till_done()
        probe.assert_not_awaited()
    for key in SWITCH_KEYS:
        assert hass.states.get(entity_id(hass, entry, key)).state == STATE_UNAVAILABLE
    assert entry.data == saved
    assert gateway.commands == []
    issue = (DOMAIN, f"certificate_changed_{entry.entry_id}")
    assert issue in ir.async_get(hass).issues
    gateway.read_error = None
    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert issue not in ir.async_get(hass).issues
    assert_switches(hass, entry, "charge_from_grid")
    assert gateway.commands == []


async def test_certificate_error_during_command_preserves_pin_and_requires_review(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway()
    entry = await setup_gateway(hass, gateway)
    saved = dict(entry.data)
    gateway.read_error = CertificateError("Certificate changed")
    with pytest.raises(HomeAssistantError, match="Reconfigure"):
        await call_switch(hass, entity_id(hass, entry, "charge_from_grid"), "turn_on")
    assert entry.data == saved
    assert gateway.commands == []
    assert (DOMAIN, f"certificate_changed_{entry.entry_id}") in ir.async_get(hass).issues


def automatic_entry(hass: HomeAssistant) -> MockConfigEntry:
    """Create an opted-in entry without contacting either endpoint."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="IQ Gateway",
        unique_id=SERIAL,
        data={
            "host": HOST,
            "token": TOKEN,
            "serial": SERIAL,
            "model": "IQ Gateway",
            "firmware": "D8.3.5286",
            "certificate_fingerprint": "ab" * 32,
            "auth_method": "automatic",
            "remember_credentials": True,
            "username": "homeowner@example.invalid",
            "password": "private-test-password",
        },
    )
    entry.add_to_hass(hass)
    return entry


def mocked_token_manager():
    return SimpleNamespace(
        async_ensure_token=AsyncMock(return_value=False),
        async_start=AsyncMock(),
        async_stop=AsyncMock(),
        enabled=True,
        needs_reauth=False,
        last_error=None,
        next_retry_at=None,
    )


async def test_existing_switch_registry_ids_are_reused(hass: HomeAssistant) -> None:
    entry = automatic_entry(hass)
    registry = er.async_get(hass)
    previous_ids = {}
    for key in SWITCH_KEYS[:-1]:
        previous = registry.async_get_or_create(
            "switch",
            DOMAIN,
            f"{SERIAL}_{key}",
            suggested_object_id=f"existing_{key}",
            config_entry=entry,
        )
        previous_ids[key] = previous.entity_id
    gateway = RecordingGateway()
    with (
        patch("custom_components.enphase_local_control.GatewayClient", return_value=gateway),
        patch(
            "custom_components.enphase_local_control.TokenManager",
            return_value=mocked_token_manager(),
        ),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    for key, previous_id in previous_ids.items():
        assert registry.async_get_entity_id("switch", DOMAIN, f"{SERIAL}_{key}") == previous_id
        assert hass.states.get(previous_id).state == (STATE_ON if key == "zero_net" else STATE_OFF)
    assert hass.states.get(entity_id(hass, entry, "restrict_discharge")).state == STATE_OFF
    assert gateway.commands == []


async def test_automatic_startup_ensures_token_before_first_local_read_and_stops_on_unload(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway(current_mode=2, debug_mode=2)
    entry = automatic_entry(hass)
    manager = mocked_token_manager()
    events = []
    original_info, original_scheduler = gateway.get_info, gateway.get_scheduler

    async def ensure(*, force=False):
        events.append("force" if force else "ensure")
        return False

    async def info():
        events.append("info")
        return await original_info()

    async def scheduler():
        events.append("scheduler")
        return await original_scheduler()

    manager.async_ensure_token.side_effect = ensure
    manager.async_start.side_effect = lambda: events.append("start")
    gateway.get_info = AsyncMock(side_effect=info)
    gateway.get_scheduler = AsyncMock(side_effect=scheduler)
    with (
        patch("custom_components.enphase_local_control.GatewayClient", return_value=gateway),
        patch("custom_components.enphase_local_control.TokenManager", return_value=manager),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert events == ["ensure", "info", "ensure", "scheduler", "start"]
    assert gateway.commands == []
    assert_switches(hass, entry, "charge_from_grid")
    manager.async_start.assert_awaited_once()
    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
    manager.async_stop.assert_awaited_once()
    assert gateway.commands == []


async def test_initial_local_401_forces_one_renewal_and_retries_only_read(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway()
    entry = automatic_entry(hass)
    manager = mocked_token_manager()
    manager.async_ensure_token.side_effect = [False, True, False]
    gateway.get_info = AsyncMock(
        side_effect=[
            AuthenticationError("Old token expired", status=401),
            SimpleNamespace(serial=SERIAL, model="IQ Gateway", firmware="D8.3.5286"),
        ]
    )
    with (
        patch("custom_components.enphase_local_control.GatewayClient", return_value=gateway),
        patch("custom_components.enphase_local_control.TokenManager", return_value=manager),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    assert manager.async_ensure_token.await_args_list == [call(), call(force=True), call()]
    assert gateway.get_info.await_count == 2
    assert gateway.commands == []
    assert_switches(hass, entry, "zero_net")


async def test_coordinator_401_forces_renewal_then_refreshes_without_mode_replay(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway()
    entry = await setup_gateway(hass, gateway)
    manager = mocked_token_manager()
    manager.async_ensure_token.side_effect = [False, True]
    await entry.runtime_data.token_manager.async_stop()
    entry.runtime_data.token_manager = manager
    gateway.payload.update(acb_current_mode=3, acb_debug_mode=3)
    gateway.get_scheduler = AsyncMock(
        side_effect=[
            AuthenticationError("Old token expired", status=401),
            deepcopy(gateway.payload),
        ]
    )

    await entry.runtime_data.async_refresh()
    await hass.async_block_till_done()
    assert manager.async_ensure_token.await_args_list == [call(), call(force=True)]
    assert gateway.get_scheduler.await_count == 2
    assert gateway.commands == []
    assert_switches(hass, entry, "discharge_to_grid")


async def test_command_post_401_renews_for_next_request_without_replaying_post(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway()
    entry = await setup_gateway(hass, gateway)
    manager = mocked_token_manager()
    manager.async_ensure_token.side_effect = [False, True]
    await entry.runtime_data.token_manager.async_stop()
    entry.runtime_data.token_manager = manager

    async def rejected_post(mode):
        gateway.commands.append(mode)
        raise AuthenticationError("Token expired during POST", status=401)

    gateway.set_override = AsyncMock(side_effect=rejected_post)
    with patch.object(entry, "async_start_reauth") as reauth:
        with pytest.raises(HomeAssistantError, match="no command was replayed"):
            await call_switch(hass, entity_id(hass, entry, "charge_from_grid"), "turn_on")
        await hass.async_block_till_done()
        reauth.assert_not_called()
    assert manager.async_ensure_token.await_args_list == [call(), call(force=True)]
    gateway.set_override.assert_awaited_once_with(2)
    assert gateway.commands == [2]
    assert gateway.payload["acb_debug_mode"] == -1


async def test_expired_token_and_cloud_outage_do_not_lose_old_credentials(
    hass: HomeAssistant,
) -> None:
    gateway = RecordingGateway()
    now = dt_util.utcnow()
    gateway.token_metadata = SimpleNamespace(
        issued_at=now - timedelta(days=365), expires_at=now - timedelta(minutes=1)
    )
    gateway.replace_token = MagicMock()
    gateway.get_info = AsyncMock(side_effect=AuthenticationError("Old token expired", status=401))
    entry = automatic_entry(hass)
    saved = dict(entry.data)
    with (
        patch("custom_components.enphase_local_control.GatewayClient", return_value=gateway),
        patch(
            "custom_components.enphase_local_control.token_manager.request_gateway_token",
            new=AsyncMock(side_effect=CloudCommunicationError("Cloud unavailable")),
        ) as cloud_request,
    ):
        assert not await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    # The initial failure starts backoff; the following 401 does not immediately
    # attempt another account login or overwrite the expired recovery credential.
    cloud_request.assert_awaited_once()
    gateway.get_info.assert_awaited_once()
    gateway.replace_token.assert_not_called()
    assert entry.data == saved
    assert gateway.commands == []
