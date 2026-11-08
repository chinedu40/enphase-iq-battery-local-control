"""Constants for Enphase Local Battery Control."""

DOMAIN = "enphase_local_control"
NAME = "Enphase IQ Battery Local Control"
CONF_FINGERPRINT = "certificate_fingerprint"
CONF_SERIAL = "serial"
CONF_MODEL = "model"
CONF_FIRMWARE = "firmware"
CONF_SCAN_INTERVAL = "scan_interval"
CONF_AUTH_METHOD = "auth_method"
CONF_REMEMBER_CREDENTIALS = "remember_credentials"
AUTH_AUTOMATIC = "automatic"
AUTH_MANUAL = "manual"
DEFAULT_SCAN_INTERVAL = 30
MIN_SCAN_INTERVAL = 5
MAX_SCAN_INTERVAL = 300
MODE_ZERO_NET = 1
MODE_CHARGE = 2
MODE_DISCHARGE = 3
MODE_RESTRICT_DISCHARGE = 4
SWITCH_MODES = {
    "charge_from_grid": MODE_CHARGE,
    "discharge_to_grid": MODE_DISCHARGE,
    "zero_net": MODE_ZERO_NET,
    "restrict_discharge": MODE_RESTRICT_DISCHARGE,
}
