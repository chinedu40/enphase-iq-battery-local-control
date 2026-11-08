"""Shared gateway device information."""

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, NAME
from .coordinator import ModeCoordinator


class GatewayEntity(CoordinatorEntity[ModeCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: ModeCoordinator, key: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.info.serial}_{key}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.info.serial)},
            manufacturer="Enphase",
            name=NAME,
            model=coordinator.info.model,
            sw_version=coordinator.info.firmware,
        )
