"""Local Enphase mode controls, with no startup or shutdown control writes."""

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_TOKEN, Platform
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import AuthenticationError, CertificateError, GatewayClient, GatewayError
from .const import CONF_FINGERPRINT, CONF_SERIAL
from .coordinator import ModeCoordinator, report_certificate_issue
from .token_manager import TokenManager

PLATFORMS = [Platform.SWITCH, Platform.SENSOR, Platform.BUTTON]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Connect and read the existing gateway mode without changing it."""
    session = async_get_clientsession(hass)
    client = GatewayClient(
        session,
        entry.data[CONF_HOST],
        entry.data[CONF_TOKEN],
        fingerprint=entry.data.get(CONF_FINGERPRINT) or None,
    )
    manager = TokenManager(hass, entry, client, session)
    try:
        await manager.async_ensure_token()
        try:
            info = await client.get_info()
        except AuthenticationError:
            if not await manager.async_ensure_token(force=True):
                raise
            info = await client.get_info()
    except AuthenticationError as err:
        raise ConfigEntryAuthFailed("The gateway token was rejected") from err
    except CertificateError as err:
        report_certificate_issue(hass, entry)
        raise ConfigEntryNotReady("Review the gateway certificate using Reconfigure") from err
    except GatewayError as err:
        raise ConfigEntryNotReady("The local gateway could not be reached") from err
    if info.serial != entry.data[CONF_SERIAL]:
        raise ConfigEntryNotReady("The gateway serial number does not match this entry")
    coordinator = ModeCoordinator(hass, entry, client, info, token_manager=manager)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    await manager.async_start()
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload entities; persistent manual overrides remain in the gateway."""
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.token_manager.async_stop()
    return unloaded
