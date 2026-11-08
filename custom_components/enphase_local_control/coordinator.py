"""Share one confirmed gateway mode between all entities."""

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed, HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import AuthenticationError, CertificateError, GatewayClient, GatewayError, GatewayInfo
from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DOMAIN
from .controller import (
    CommandNotConfirmed,
    InvalidMode,
    InvalidSchedulerResponse,
    ModeController,
    SchedulerState,
    UnsupportedModes,
)
from .token_manager import TokenManager

if TYPE_CHECKING:
    from .switch import ModeSwitch

_LOGGER = logging.getLogger(__name__)


@callback
def report_certificate_issue(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Require user review; a runtime failure never enrolls a new certificate."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        f"certificate_changed_{entry.entry_id}",
        is_fixable=False,
        severity=ir.IssueSeverity.ERROR,
        translation_key="certificate_changed",
    )


class ModeCoordinator(DataUpdateCoordinator[SchedulerState]):
    """Poll once and serialize commands through the same controller."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: GatewayClient,
        info: GatewayInfo,
        *,
        token_manager: TokenManager | None = None,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=timedelta(
                seconds=entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
            ),
        )
        self.client = client
        self.info = info
        self.controller = ModeController(client)
        self.token_manager = token_manager
        self._switches: set[ModeSwitch] = set()

    async def _async_update_data(self) -> SchedulerState:
        try:
            if self.token_manager is not None:
                await self.token_manager.async_ensure_token()
            try:
                state = await self.controller.async_refresh()
            except AuthenticationError:
                if self.token_manager is None or not await self.token_manager.async_ensure_token(
                    force=True
                ):
                    raise
                state = await self.controller.async_refresh()
        except AuthenticationError as err:
            raise ConfigEntryAuthFailed("The gateway token was rejected") from err
        except CertificateError as err:
            report_certificate_issue(self.hass, self.config_entry)
            raise UpdateFailed("Review the gateway certificate using Reconfigure") from err
        except (GatewayError, InvalidSchedulerResponse) as err:
            raise UpdateFailed("The local gateway could not be read") from err
        ir.async_delete_issue(
            self.hass, DOMAIN, f"certificate_changed_{self.config_entry.entry_id}"
        )
        self._update_token_issue()
        return state

    @callback
    def register_switch(self, entity: "ModeSwitch") -> None:
        self._switches.add(entity)
        entity.async_on_remove(lambda: self._switches.discard(entity))

    @callback
    def publish_switch_states(self) -> None:
        """Publish off states before on states; HA has no multi-entity transaction."""
        for entity in sorted(self._switches, key=lambda switch: switch.is_on is True):
            entity.async_write_ha_state()

    async def async_change_mode(self, mode: int, *, turn_on: bool) -> None:
        try:
            if self.token_manager is not None:
                await self.token_manager.async_ensure_token()
            operation = (
                self.controller.async_turn_on if turn_on else self.controller.async_turn_off
            )
            result = await operation(mode)
        except AuthenticationError as err:
            self.async_set_update_error(UpdateFailed("Gateway authentication failed"))
            renewed = (
                self.token_manager is not None
                and await self.token_manager.async_ensure_token(force=True)
            )
            if not renewed:
                self.config_entry.async_start_reauth(self.hass)
            raise HomeAssistantError(
                "Authentication changed. Check the current mode, then retry; no command was replayed."
                if renewed
                else "Replace the gateway JWT in the integration settings"
            ) from err
        except CertificateError as err:
            report_certificate_issue(self.hass, self.config_entry)
            self.async_set_update_error(UpdateFailed("The gateway certificate was not verified"))
            raise HomeAssistantError("Use Reconfigure to review the gateway certificate") from err
        except (
            GatewayError,
            UnsupportedModes,
            CommandNotConfirmed,
            InvalidMode,
            InvalidSchedulerResponse,
        ) as err:
            if not self.controller.available:
                self.async_set_update_error(UpdateFailed("Gateway state could not be confirmed"))
            elif self.controller.state is not None:
                self.async_set_updated_data(self.controller.state)
            raise HomeAssistantError(
                "The requested battery mode was not confirmed. Check the gateway status."
            ) from err
        self.async_set_updated_data(result.state)

    async def async_return_to_automatic(self) -> None:
        """Release the local override through the same serialized command path."""
        try:
            if self.token_manager is not None:
                await self.token_manager.async_ensure_token()
            result = await self.controller.async_return_to_automatic()
        except AuthenticationError as err:
            self.async_set_update_error(UpdateFailed("Gateway authentication failed"))
            renewed = (
                self.token_manager is not None
                and await self.token_manager.async_ensure_token(force=True)
            )
            if not renewed:
                self.config_entry.async_start_reauth(self.hass)
            raise HomeAssistantError(
                "Authentication changed. Check the current mode, then retry; no command was replayed."
                if renewed
                else "Replace the gateway JWT in the integration settings"
            ) from err
        except CertificateError as err:
            report_certificate_issue(self.hass, self.config_entry)
            self.async_set_update_error(UpdateFailed("The gateway certificate was not verified"))
            raise HomeAssistantError("Use Reconfigure to review the gateway certificate") from err
        except (GatewayError, CommandNotConfirmed, InvalidSchedulerResponse) as err:
            self.async_set_update_error(UpdateFailed("Automatic control was not confirmed"))
            raise HomeAssistantError(
                "The gateway did not confirm return to automatic control"
            ) from err
        self.async_set_updated_data(result.state)

    @callback
    def _update_token_issue(self) -> None:
        expiry = self.client.token_metadata.expires_at
        issue_id = f"token_expiring_{self.config_entry.entry_id}"
        if expiry is not None and expiry - datetime.now(UTC) < timedelta(days=30):
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                severity=ir.IssueSeverity.WARNING,
                translation_key="token_expiring",
                translation_placeholders={"expiry": expiry.isoformat()},
            )
        else:
            ir.async_delete_issue(self.hass, DOMAIN, issue_id)
