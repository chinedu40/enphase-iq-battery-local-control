# Enphase IQ Battery Local Control

A Home Assistant custom integration for controlling an Enphase IQ Battery through its local IQ Gateway. Choose **Charge from grid**, **Discharge to grid**, **Restrict discharge**, or **Zero Net**. Only one mode can be selected at a time. The integration can run alongside Enphase monitoring.

[![Open in Home Assistant Marketplace](https://my.home-assistant.io/badges/marketplace_repository.svg)](https://my.home-assistant.io/redirect/marketplace_repository/?owner=chinedu40&repository=enphase-iq-battery-local-control&category=integration)

## Install

**Home Assistant 2026.11 or later:** Open **Settings → Marketplace → Add from link** and add `https://github.com/chinedu40/enphase-iq-battery-local-control`. Connect GitHub if prompted, choose **Integration** if asked, and install the repository. This is a custom repository added by link. See the [Marketplace guide](https://www.home-assistant.io/integrations/marketplace/#custom-repositories).

**Home Assistant 2026.10 with HACS:** Open **HACS → ⋮ → Custom repositories**, paste the same repository URL, select **Integration**, and add it. Download the integration and restart Home Assistant when prompted. See the [HACS guide](https://www.hacs.xyz/docs/faq/custom_repositories/).

**Manual install:** From the [latest release](https://github.com/chinedu40/enphase-iq-battery-local-control/releases/latest), extract the integration ZIP and copy `custom_components/enphase_local_control` into `/config/custom_components/`. Restart Home Assistant.

If you already use an earlier ZIP build, keep the existing integration entry when upgrading. The integration domain and existing entity identities are unchanged. Check that **Restrict discharge** appears after the update and any prompted restart.

## Set up your gateway

1. Open **Settings → Devices & services → Add integration → Enphase IQ Battery Local Control**.
2. Enter the IQ Gateway's local hostname or IP address. Choose **Automatic** to obtain the gateway JWT with your Enphase account, or **Manual** to paste a JWT from the [Enphase token portal](https://entrez.enphaseenergy.com/). Use Manual if your account requires MFA or browser sign-in.
3. Review **Trust this gateway**. Check the gateway address and advertised serial against your device before confirming. Home Assistant saves the detected certificate fingerprint after successful validation. A changed certificate needs review again under **Reconfigure**.
4. For Automatic setup, enter the gateway's 12-digit serial if public discovery cannot read it. Review the operating mode and battery charge sensors before selecting a mode.

The integration saves only the JWT unless you opt in to **Remember credentials for automatic renewal**. Enabling that option stores your Enphase login in Home Assistant's configuration and backups. Use **Reconfigure** to replace a token or switch to Manual to remove stored login credentials. Owner tokens are typically valid for a year; actual expiry is shown by the **Token expiry** sensor. Enphase cloud access is used for issuing and renewing tokens. Monitoring and commands use the local gateway over HTTPS.

## Battery modes

| Switch | What it requests |
| --- | --- |
| Charge from grid | The gateway's **Charge From Grid** mode (`2`) |
| Discharge to grid | The gateway's **Discharge to Grid** mode (`3`) |
| Restrict discharge | The gateway's **No Discharge** mode (`4`), which prevents the battery from intentionally discharging. This does not limit solar export or set a wattage. |
| Zero Net | The gateway's **Zero Net** mode (`1`) |

Turning one mode on clears the other selections. Turning off the active charge, discharge, or restrict switch selects **Zero Net**. Turning off an inactive switch has no effect, and Zero Net stays selected until another mode is chosen.

These overrides stay active until changed or cleared by the gateway. If you want to release the override so Enphase resumes normal scheduling, enable the **Return to automatic Enphase control** button (disabled by default), then press it. The switches report the actual operating mode when no override is set. Home Assistant setup, reconnect, restart, and unload do not change the battery mode.

The gateway's live mode labels must match the integration's expected mapping. A gateway that does not advertise **No Discharge** at mode `4` leaves the Restrict discharge switch unavailable. Changes to the core mode mapping can make the other controls unavailable too. Check the **Mode compatibility** sensor and the gateway's firmware if this happens.

This is an independent community integration for compatible IQ Gateway firmware. It has been developed around IQ Battery 5P with a gateway exposing `/ivp/sc/sched`; compatibility can vary by firmware and account permissions. The gateway may limit the physical response based on state of charge, site settings, or grid conditions. The integration changes the local mode override without editing tariffs, reserve levels, or stored schedules. Coordinate writes if you also use Predbat or another battery controller.

## Troubleshooting

- **Gateway token rejected:** use **Reconfigure** to obtain or paste a replacement. A Home Assistant access token cannot be used here.
- **Certificate changed:** verify that the gateway address and serial are correct before trusting the new certificate.
- **Mode not confirmed:** check the **Local override** and **Operating mode** sensors before trying again. A rejected or uncertain write is never automatically replayed.
- **Removing the integration:** choose a suitable mode or return to automatic control first if you want to clear an active override.

Download diagnostics from the integration entry when reporting an issue. They exclude account credentials, gateway JWTs, and raw responses. Please omit gateway serials, tokens, passwords, and site information from any public report.

## Development

Run `python -m pip install -r requirements-test.txt`, `python -m pytest`, `ruff check .`, and `ruff format --check .` in an isolated Python 3.14 environment. Tests block network sockets and use simulated gateway and cloud responses. See [validation notes](VALIDATION.md) for the release checks and their limits.

[Enphase token authentication brief](https://enphase.com/fr-fr/media/8802) · [Home Assistant Enphase credentials guide](https://www.home-assistant.io/integrations/enphase_envoy/#credentials-andor-token-configuration) · [MIT license](LICENSE)
