"""An optional maintenance action to release a local override."""

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import ModeCoordinator
from .entity import GatewayEntity


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities([ReturnToAutomaticButton(entry.runtime_data)])


class ReturnToAutomaticButton(GatewayEntity, ButtonEntity):
    _attr_translation_key = "return_to_automatic"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_entity_registry_enabled_default = False

    def __init__(self, coordinator: ModeCoordinator) -> None:
        super().__init__(coordinator, "return_to_automatic")

    async def async_press(self) -> None:
        await self.coordinator.async_return_to_automatic()
