"""Modes, charge level and authentication diagnostics."""

from datetime import datetime

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import MODE_RESTRICT_DISCHARGE
from .coordinator import ModeCoordinator
from .entity import GatewayEntity


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: ModeCoordinator = entry.runtime_data
    async_add_entities(
        GatewaySensor(coordinator, key)
        for key in (
            "operating_mode",
            "local_override",
            "battery_charge",
            "token_expiry",
            "mode_support",
        )
    )


class GatewaySensor(GatewayEntity, SensorEntity):
    def __init__(self, coordinator: ModeCoordinator, key: str) -> None:
        super().__init__(coordinator, key)
        self._key = key
        self._attr_translation_key = key
        if key == "battery_charge":
            self._attr_device_class = SensorDeviceClass.BATTERY
            self._attr_native_unit_of_measurement = "%"
        elif key == "token_expiry":
            self._attr_device_class = SensorDeviceClass.TIMESTAMP
            self._attr_entity_category = EntityCategory.DIAGNOSTIC
        elif key in ("local_override", "mode_support"):
            self._attr_entity_category = EntityCategory.DIAGNOSTIC

    def _mode_label(self, code: int) -> str:
        if code == -1:
            return "Automatic Enphase control"
        labels = self.coordinator.data.mode_labels
        return labels[code] if 0 <= code < len(labels) else f"Unknown mode ({code})"

    @property
    def native_value(self) -> str | float | datetime | None:
        state = self.coordinator.data
        if self._key == "operating_mode":
            return self._mode_label(state.current_mode)
        if self._key == "local_override":
            return self._mode_label(state.debug_mode)
        if self._key == "battery_charge":
            value = state.raw.get("agg_soc", state.raw.get("ENC_agg_soc"))
            return (
                value if isinstance(value, (int, float)) and not isinstance(value, bool) else None
            )
        if self._key == "token_expiry":
            return self.coordinator.client.token_metadata.expires_at
        return "Supported" if state.modes_supported else "Mode mapping changed"

    @property
    def extra_state_attributes(self) -> dict[str, object] | None:
        state = self.coordinator.data
        if self._key == "mode_support":
            return {"restrict_discharge_supported": state.supports_mode(MODE_RESTRICT_DISCHARGE)}
        if self._key in ("operating_mode", "local_override"):
            return {
                "raw_mode": state.current_mode
                if self._key == "operating_mode"
                else state.debug_mode
            }
        return None
