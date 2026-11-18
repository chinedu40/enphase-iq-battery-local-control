# Changelog

## Unreleased

- Tolerate IQ Gateway firmware (observed on D8.3.5427) that answers `/ivp/sc/sched` with the malformed status line `HTTP/1.1 0`. A read that hits it falls back once to a minimal pinned-TLS reader for that path; commands are never resent to discover it and are sent exactly once afterwards.
- Add redacted debug logging for gateway transport failures (`custom_components.enphase_local_control`), so setup errors such as "Could not read the local gateway" can be diagnosed.

## 0.4.0

First public release of **Enphase IQ Battery Local Control**.

- Install as a custom integration in Home Assistant Marketplace or HACS.
- Switch between Charge from grid, Discharge to grid, Restrict discharge, and Zero Net. Restrict discharge uses the gateway's verified No Discharge mode.
- Preserve earlier installations' existing entities, saved certificate, and authentication settings.
- Set up using Enphase account sign-in or a manual gateway JWT, with optional remembered credentials for renewal.
