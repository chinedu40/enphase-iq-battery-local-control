# v0.4.0 validation

The release tests use Python 3.14.2, Home Assistant 2026.10.2, and simulated gateway and cloud responses with network sockets blocked. The local suite passed **291 tests and 11 subtests**, with **95% statement coverage** across the integration. Ruff lint and format checks passed.

The tests cover Home Assistant config entries, entities, and switch services. They verify mutually exclusive switching, active-switch off returning to Zero Net, retaining existing entity identities on upgrade, readback of mode changes, and avoiding command replay on reconnect or after an uncertain write. Restrict discharge is enabled only if fresh scheduler data confirms the expected No Discharge label at mode 4. A missing or changed mode 4 label does not disable the three verified original modes.

The release also retains tests for first-use certificate review, pinned TLS, manual and automatic token setup, and opt-in renewal with redacted diagnostics. Setup, renewal, reload, and unload do not issue battery control writes.

The mode mapping is based on IQ Gateway observations; other firmware and site configurations may behave differently. This release's validation does not issue live commands, change a live Home Assistant installation, or sign in to a real Enphase account.
