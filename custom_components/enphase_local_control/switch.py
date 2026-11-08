"""Four linked switches backed by one gateway mode."""

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import SWITCH_MODES
from .coordinator import ModeCoordinator
from .entity import GatewayEntity


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    coordinator: ModeCoordinator = entry.runtime_data
    async_add_entities(ModeSwitch(coordinator, key, mode) for key, mode in SWITCH_MODES.items())


class ModeSwitch(GatewayEntity, SwitchEntity):
    """A mode selector rendered as a regular HA toggle."""

    def __init__(self, coordinator: ModeCoordinator, key: str, mode: int) -> None:
        super().__init__(coordinator, key)
        self._mode = mode
        self._attr_translation_key = key

    @property
    def is_on(self) -> bool | None:
        return self.coordinator.controller.is_on(self._mode)

    @property
    def available(self) -> bool:
        return super().available and self.is_on is not None

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.coordinator.register_switch(self)

    @callback
    def _handle_coordinator_update(self) -> None:
        self.coordinator.publish_switch_states()

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_change_mode(self._mode, turn_on=True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_change_mode(self._mode, turn_on=False)
