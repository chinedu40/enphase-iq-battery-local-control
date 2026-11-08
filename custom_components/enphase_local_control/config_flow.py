"""UI configuration and read-only connection validation."""

import re
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.config_entries import SOURCE_REAUTH, SOURCE_RECONFIGURE
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_TOKEN, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .api import (
    AuthenticationError,
    CertificateError,
    GatewayClient,
    GatewayError,
    PermissionDeniedError,
    _base_url,
    async_get_gateway_identity,
)
from .certificate import CertificateDetails, probe_certificate
from .cloud_auth import (
    CloudCommunicationError,
    CloudInvalidAuth,
    CloudMFARequired,
    CloudTokenError,
    request_gateway_token,
)
from .const import (
    AUTH_AUTOMATIC,
    AUTH_MANUAL,
    CONF_AUTH_METHOD,
    CONF_FINGERPRINT,
    CONF_FIRMWARE,
    CONF_MODEL,
    CONF_REMEMBER_CREDENTIALS,
    CONF_SCAN_INTERVAL,
    CONF_SERIAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
    NAME,
)
from .controller import ModeController, UnsupportedModes


def _token_field() -> TextSelector:
    return TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))


class EnphaseLocalControlConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Trust one observed certificate before sending gateway credentials."""

    VERSION = 1

    def __init__(self) -> None:
        self._pending_data: dict[str, Any] | None = None
        self._pending_certificate: CertificateDetails | None = None
        self._pending_binding: tuple | None = None
        self._serial_data: dict[str, Any] | None = None
        self._serial_binding: tuple | None = None

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> "LocalOptionsFlow":
        return LocalOptionsFlow()

    def _entry(self) -> config_entries.ConfigEntry | None:
        if self.source == SOURCE_REAUTH:
            return self._get_reauth_entry()
        if self.source == SOURCE_RECONFIGURE:
            return self._get_reconfigure_entry()
        return None

    def _binding(self, data: dict[str, Any]) -> tuple:
        entry = self._entry()
        return (
            _base_url(data[CONF_HOST]),
            self.source,
            entry.unique_id if entry else None,
            entry.data.get(CONF_FINGERPRINT) if entry else None,
        )

    def _clear_pending(self) -> None:
        self._pending_data = None
        self._pending_certificate = None
        self._pending_binding = None

    def _connection_form(self, errors: dict[str, str] | None = None) -> FlowResult:
        entry = self._entry()
        existing = entry.data if entry else {}
        fields: dict = {}
        if self.source == SOURCE_REAUTH:
            step_id = "reauth_confirm"
        elif self.source == SOURCE_RECONFIGURE:
            step_id = "reconfigure"
            fields[vol.Required(CONF_HOST, default=existing[CONF_HOST])] = str
        else:
            step_id = "user"
            fields[vol.Required(CONF_HOST)] = str
        method = existing.get(CONF_AUTH_METHOD, AUTH_MANUAL) if entry else AUTH_AUTOMATIC
        fields[vol.Required(CONF_AUTH_METHOD, default=method)] = SelectSelector(
            SelectSelectorConfig(
                options=[AUTH_AUTOMATIC, AUTH_MANUAL],
                mode=SelectSelectorMode.DROPDOWN,
                translation_key="auth_method",
            )
        )
        fields[vol.Optional(CONF_USERNAME)] = TextSelector(
            TextSelectorConfig(type=TextSelectorType.EMAIL)
        )
        fields[vol.Optional(CONF_PASSWORD)] = _token_field()
        fields[
            vol.Optional(
                CONF_REMEMBER_CREDENTIALS,
                default=existing.get(CONF_REMEMBER_CREDENTIALS, False),
            )
        ] = bool
        fields[vol.Optional(CONF_TOKEN)] = _token_field()
        return self.async_show_form(
            step_id=step_id, errors=errors or {}, data_schema=vol.Schema(fields)
        )

    def _input_data(self, user_input: dict[str, Any]) -> dict[str, Any]:
        entry = self._entry()
        data = dict(entry.data) if entry else {}
        data[CONF_HOST] = user_input.get(CONF_HOST, data.get(CONF_HOST))
        token = user_input.get(CONF_TOKEN, "").strip()
        method = user_input.get(CONF_AUTH_METHOD, AUTH_MANUAL)
        # Older flows submitted only a JWT. The HA schema may add the new
        # automatic default, so a token without login fields remains manual.
        if token and not user_input.get(CONF_USERNAME) and not user_input.get(CONF_PASSWORD):
            method = AUTH_MANUAL
        if method not in (AUTH_AUTOMATIC, AUTH_MANUAL):
            raise ValueError("Choose an authentication method")
        data[CONF_AUTH_METHOD] = method
        data.pop(CONF_USERNAME, None)
        data.pop(CONF_PASSWORD, None)
        data[CONF_REMEMBER_CREDENTIALS] = False
        if method == AUTH_AUTOMATIC:
            username = user_input.get(CONF_USERNAME, "").strip()
            password = user_input.get(CONF_PASSWORD, "")
            if not username or not password:
                raise ValueError("Enter the Enphase login details")
            data[CONF_USERNAME] = username
            data[CONF_PASSWORD] = password
            data[CONF_REMEMBER_CREDENTIALS] = user_input.get(CONF_REMEMBER_CREDENTIALS) is True
            data.pop(CONF_TOKEN, None)
        else:
            data[CONF_TOKEN] = token or data.get(CONF_TOKEN, "")
            if not data[CONF_TOKEN]:
                raise ValueError("Enter the gateway JWT")
        return data

    async def _submit(self, user_input: dict[str, Any]) -> FlowResult:
        try:
            data = self._input_data(user_input)
        except (ValueError, AttributeError, TypeError):
            return self._connection_form({"base": "invalid_input"})
        self._serial_data = None
        self._serial_binding = None
        return await self._begin(data)

    async def _validate(self, data: dict[str, Any]) -> dict[str, Any]:
        # This method is reached only with a previously saved or explicitly
        # accepted pin. The TLS client checks that pin before sending HTTP/JWT.
        client = GatewayClient(
            async_get_clientsession(self.hass),
            data[CONF_HOST],
            data[CONF_TOKEN],
            fingerprint=data[CONF_FINGERPRINT],
        )
        info = await client.get_info()
        if not info.serial:
            raise ValueError("The gateway did not report a serial number")
        state = await ModeController(client).async_refresh()
        if not state.modes_supported and self._entry() is None:
            raise UnsupportedModes("The gateway mode mapping has not been verified")
        return data | {
            CONF_SERIAL: info.serial,
            CONF_MODEL: info.model,
            CONF_FIRMWARE: info.firmware,
        }

    async def _finish(self, data: dict[str, Any]) -> FlowResult:
        errors: dict[str, str] = {}
        try:
            if data.get(CONF_AUTH_METHOD) == AUTH_AUTOMATIC and not data.get(CONF_TOKEN):
                if not re.fullmatch(r"[0-9]{12}", str(data.get(CONF_SERIAL, ""))):
                    try:
                        identity = await async_get_gateway_identity(
                            async_get_clientsession(self.hass),
                            data[CONF_HOST],
                            fingerprint=data[CONF_FINGERPRINT],
                        )
                    except CertificateError:
                        raise
                    except GatewayError:
                        identity = None
                    if identity is None or not re.fullmatch(r"[0-9]{12}", identity.serial or ""):
                        self._serial_data = data
                        self._serial_binding = self._binding(data)
                        return await self.async_step_gateway_serial()
                    data[CONF_SERIAL] = identity.serial
                data[CONF_TOKEN] = await request_gateway_token(
                    async_get_clientsession(self.hass),
                    data[CONF_USERNAME],
                    data[CONF_PASSWORD],
                    data[CONF_SERIAL],
                )
            validated = await self._validate(data)
            if data.get(CONF_SERIAL) and validated[CONF_SERIAL] != data[CONF_SERIAL]:
                return self.async_abort(reason="wrong_gateway")
        except CloudInvalidAuth:
            errors["base"] = "cloud_invalid_auth"
        except CloudMFARequired:
            errors["base"] = "cloud_mfa_required"
        except CloudCommunicationError:
            errors["base"] = "cloud_cannot_connect"
        except CloudTokenError:
            errors["base"] = "cloud_token_error"
        except AuthenticationError:
            errors["base"] = "invalid_auth"
        except PermissionDeniedError:
            errors["base"] = "permission_denied"
        except CertificateError:
            # A change after the probe/confirmation cannot silently select a
            # replacement. Return to connection entry for a fresh probe/trust.
            errors["base"] = "certificate_changed"
        except UnsupportedModes:
            errors["base"] = "unsupported_modes"
        except ValueError:
            errors["base"] = "invalid_input"
        except GatewayError:
            errors["base"] = "cannot_connect"
        if errors:
            self._clear_pending()
            return self._connection_form(errors)
        if validated.get(CONF_REMEMBER_CREDENTIALS) is not True:
            validated.pop(CONF_USERNAME, None)
            validated.pop(CONF_PASSWORD, None)
            validated[CONF_REMEMBER_CREDENTIALS] = False
        await self.async_set_unique_id(validated[CONF_SERIAL])
        entry = self._entry()
        if entry is not None:
            self._abort_if_unique_id_mismatch(reason="wrong_gateway")
            return self.async_update_reload_and_abort(entry, data=validated)
        self._abort_if_unique_id_configured()
        return self.async_create_entry(
            title=f"{NAME} {validated[CONF_SERIAL][-4:]}", data=validated
        )

    async def _begin(self, data: dict[str, Any]) -> FlowResult:
        self._clear_pending()
        errors: dict[str, str] = {}
        try:
            binding = self._binding(data)
            certificate = await probe_certificate(data[CONF_HOST])
        except CertificateError:
            errors["base"] = "certificate_error"
        except ValueError:
            errors["base"] = "invalid_input"
        except GatewayError:
            errors["base"] = "cannot_connect"
        if errors:
            return self._connection_form(errors)
        # Pins are trusted only when already persisted for this entry. Incoming
        # form fields must never provide a shortcut around first-use consent.
        entry = self._entry()
        saved_pin = entry.data.get(CONF_FINGERPRINT) if entry else None
        canonical_saved = (
            "".join(saved_pin.split()).replace(":", "").lower()
            if isinstance(saved_pin, str)
            else None
        )
        data = dict(data) | {CONF_FINGERPRINT: certificate.fingerprint}
        if canonical_saved == certificate.fingerprint:
            return await self._finish(data)
        self._pending_data = data
        self._pending_certificate = certificate
        self._pending_binding = binding
        return await self.async_step_trust_certificate()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            return await self._submit(user_input)
        self._clear_pending()
        return self._connection_form()

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> FlowResult:
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        if user_input is not None:
            return await self._submit(user_input)
        self._clear_pending()
        return self._connection_form()

    async def async_step_reconfigure(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        if user_input is not None:
            return await self._submit(user_input)
        self._clear_pending()
        return self._connection_form()

    async def async_step_gateway_serial(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        data = self._serial_data
        if data is None:
            return self.async_abort(reason="trust_required")
        if self._serial_binding != self._binding(data):
            self._serial_data = None
            return self.async_abort(reason="trust_expired")
        errors = {}
        if user_input is not None:
            serial = str(user_input.get(CONF_SERIAL, "")).strip()
            if re.fullmatch(r"[0-9]{12}", serial):
                self._serial_data = None
                data[CONF_SERIAL] = serial
                return await self._finish(data)
            errors["base"] = "invalid_serial"
        return self.async_show_form(
            step_id="gateway_serial",
            errors=errors,
            data_schema=vol.Schema({vol.Required(CONF_SERIAL): str}),
        )

    async def async_step_trust_certificate(
        self,
        user_input: dict[str, Any] | None = None,
    ) -> FlowResult:
        data, certificate = self._pending_data, self._pending_certificate
        if data is None or certificate is None:
            return self.async_abort(reason="trust_required")
        if self._pending_binding != self._binding(data):
            self._clear_pending()
            return self.async_abort(reason="trust_expired")
        if user_input is not None and user_input.get("trust_certificate") is True:
            self._clear_pending()
            return await self._finish(data)

        # Identity claims are unverified and displayed as inert code text.
        # Removing backticks prevents an untrusted certificate escaping that
        # formatting; no JWT or pending credential is returned to the form.
        def display(value: object) -> str:
            return "".join(c for c in str(value) if c.isprintable()).replace("`", "'")[:512]

        return self.async_show_form(
            step_id="trust_certificate",
            errors={"base": "trust_required"} if user_input is not None else {},
            description_placeholders={
                "host": display(data[CONF_HOST]),
                "subject": display(certificate.subject),
                "issuer": display(certificate.issuer),
                "serial_hint": display(certificate.serial_hint or "Not advertised"),
                "fingerprint": certificate.fingerprint,
            },
            data_schema=vol.Schema({vol.Required("trust_certificate", default=False): bool}),
        )


class LocalOptionsFlow(config_entries.OptionsFlowWithReload):
    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_SCAN_INTERVAL,
                        default=self.config_entry.options.get(
                            CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
                        ),
                    ): vol.All(
                        vol.Coerce(int), vol.Range(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL)
                    ),
                }
            ),
        )
