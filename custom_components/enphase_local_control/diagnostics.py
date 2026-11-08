"""Only include explicit non-secret diagnostics; never dump entry data or JWTs."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, MODE_RESTRICT_DISCHARGE
from .coordinator import ModeCoordinator


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> dict:
    coordinator: ModeCoordinator = entry.runtime_data
    state = coordinator.controller.state
    expiry = coordinator.client.token_metadata.expires_at
    return {
        "integration_version": "0.4.0",
        "gateway_firmware": coordinator.info.firmware,
        "poll_interval_seconds": entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        "available": coordinator.controller.available,
        "current_mode": state.current_mode if state else None,
        "debug_mode": state.debug_mode if state else None,
        "mode_labels": list(state.mode_labels) if state else [],
        "mode_mapping_supported": state.modes_supported if state else False,
        "restrict_discharge_supported": state.supports_mode(MODE_RESTRICT_DISCHARGE)
        if state
        else False,
        "mode_mapping_error": state.mode_schema_error if state else None,
        "token_expiry_hint": expiry.isoformat() if expiry else None,
        "automatic_renewal_enabled": bool(
            coordinator.token_manager and coordinator.token_manager.enabled
        ),
        "automatic_renewal_needs_reauth": bool(
            coordinator.token_manager and coordinator.token_manager.needs_reauth
        ),
    }
