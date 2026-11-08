"""Verify UI configuration authenticates using reads and protects gateway identity."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.config_entries import SOURCE_REAUTH, SOURCE_RECONFIGURE, SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType, InvalidData
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.enphase_local_control.api import (
    AuthenticationError,
    CertificateError,
    CommunicationError,
    GatewayIdentity,
    TokenMetadata,
)
from custom_components.enphase_local_control.cloud_auth import (
    CloudCommunicationError,
    CloudInvalidAuth,
    CloudMFARequired,
    CloudTokenError,
)
from custom_components.enphase_local_control.const import DOMAIN

pytestmark = pytest.mark.usefixtures("enable_custom_integrations")

HOST = "192.0.2.60"
SERIAL = "122600012345"
TOKEN = "test-token-configuration-must-not-log"
PIN = "a1" * 32
NEW_PIN = "b2" * 32
USERNAME = "clinician@example.invalid"
PASSWORD = "test-cloud-password-must-never-be-displayed"
ISSUED_TOKEN = "issued-local-gateway-test-token"
INPUT = {"host": HOST, "token": TOKEN}
AUTOMATIC_INPUT = {
    "host": HOST,
    "auth_method": "automatic",
    "username": USERNAME,
    "password": PASSWORD,
    "remember_credentials": False,
}
PAYLOAD = {
    "acb_current_mode": 1,
    "acb_debug_mode": -1,
    "sched_mode_key": [
        "ID - Idle",
        "ZN - Zero Net",
        "CG - Charge From Grid",
        "DG - Discharge to Grid",
        "ND - No Discharge",
    ],
}


@pytest.fixture
def certificate_details():
    return SimpleNamespace(
        fingerprint=PIN,
        subject="CN=envoy-test.local",
        issuer="CN=Enphase test issuer",
        serial_hint=SERIAL,
    )


@pytest.fixture(autouse=True)
def certificate_probe(certificate_details):
    with patch(
        "custom_components.enphase_local_control.config_flow.probe_certificate",
        new=AsyncMock(return_value=certificate_details),
    ) as probe:
        yield probe


@pytest.fixture
def gateway():
    client = MagicMock()
    client.get_info = AsyncMock(
        return_value=GatewayIdentity(serial=SERIAL, model="IQ Gateway", firmware="D8.3.5286")
    )
    client.get_scheduler = AsyncMock(side_effect=lambda: deepcopy(PAYLOAD))
    client.set_override = AsyncMock()
    client.token_metadata = TokenMetadata()
    return client


@pytest.fixture
def mocked_flow_client(gateway):
    with (
        patch(
            "custom_components.enphase_local_control.config_flow.GatewayClient",
            return_value=gateway,
        ) as factory,
        patch(
            "custom_components.enphase_local_control.async_setup_entry",
            new=AsyncMock(return_value=True),
        ),
    ):
        yield factory


@pytest.fixture
def cloud_services():
    with (
        patch(
            "custom_components.enphase_local_control.config_flow.async_get_gateway_identity",
            new=AsyncMock(return_value=GatewayIdentity(serial=SERIAL, model="IQ Gateway")),
        ) as identity,
        patch(
            "custom_components.enphase_local_control.config_flow.request_gateway_token",
            new=AsyncMock(return_value=ISSUED_TOKEN),
        ) as request,
    ):
        yield SimpleNamespace(identity=identity, request=request)


def existing_entry(hass: HomeAssistant) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title="IQ Gateway",
        unique_id=SERIAL,
        data={
            **INPUT,
            "certificate_fingerprint": PIN,
            "serial": SERIAL,
            "model": "IQ Gateway",
            "firmware": "D8.3.5286",
        },
    )
    entry.add_to_hass(hass)
    return entry


async def test_user_flow_authenticates_read_only(
    hass: HomeAssistant, gateway, mocked_flow_client, certificate_probe, certificate_details
) -> None:
    order = []

    async def probe(host):
        assert host == HOST
        order.append("probe")
        return certificate_details

    def construct_client(*args, **kwargs):
        order.append("authenticated_client")
        return gateway

    certificate_probe.side_effect = probe
    mocked_flow_client.side_effect = construct_client
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    assert gateway.get_scheduler.await_count == 0

    result = await hass.config_entries.flow.async_configure(result["flow_id"], INPUT)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "trust_certificate"
    mocked_flow_client.assert_not_called()
    gateway.get_info.assert_not_awaited()
    gateway.get_scheduler.assert_not_awaited()
    assert TOKEN not in repr(result)
    assert order == ["probe"]
    placeholders = result["description_placeholders"]
    assert {"host", "subject", "issuer", "fingerprint", "serial_hint"} <= placeholders.keys()
    assert placeholders["host"] == HOST
    assert placeholders["fingerprint"].replace(":", "").lower() == PIN
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    await hass.async_block_till_done()
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == SERIAL
    assert result["data"]["host"] == HOST
    assert result["data"]["token"] == TOKEN
    assert result["data"]["certificate_fingerprint"] == PIN
    assert mocked_flow_client.call_args.kwargs["fingerprint"] == PIN
    assert order.index("probe") < order.index("authenticated_client")
    gateway.get_info.assert_awaited()
    gateway.get_scheduler.assert_awaited()
    gateway.set_override.assert_not_awaited()


async def test_invalid_token_stays_in_form_without_logging_token(
    hass: HomeAssistant, gateway, mocked_flow_client, caplog
) -> None:
    gateway.get_scheduler.side_effect = AuthenticationError("Token rejected", status=401)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=INPUT
    )
    assert result["step_id"] == "trust_certificate"
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.FORM
    assert "invalid_auth" in result["errors"].values()
    assert TOKEN not in caplog.text
    gateway.set_override.assert_not_awaited()


async def test_same_gateway_cannot_be_added_twice(
    hass: HomeAssistant, gateway, mocked_flow_client
) -> None:
    existing_entry(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=INPUT
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    gateway.set_override.assert_not_awaited()


async def test_reauth_cannot_silently_replace_the_gateway(
    hass: HomeAssistant, gateway, mocked_flow_client
) -> None:
    entry = existing_entry(hass)
    gateway.get_info.return_value = GatewayIdentity(
        serial="DIFFERENT-GATEWAY", model="IQ Gateway", firmware="D8.3.5286"
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    assert result["type"] == FlowResultType.FORM

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"token": "replacement-test-token"}
    )
    assert result["type"] in (FlowResultType.FORM, FlowResultType.ABORT)
    if result["type"] == FlowResultType.FORM:
        assert any(
            "mismatch" in value or "gateway" in value for value in result["errors"].values()
        )
    else:
        assert "mismatch" in result["reason"] or "gateway" in result["reason"]
    assert entry.data["token"] == TOKEN
    assert entry.unique_id == SERIAL
    gateway.set_override.assert_not_awaited()


async def test_reauth_same_gateway_updates_token_without_a_control_write(
    hass: HomeAssistant, gateway, mocked_flow_client
) -> None:
    entry = existing_entry(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    assert result["type"] == FlowResultType.FORM
    with patch.object(hass.config_entries, "async_reload", return_value=True):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"token": "replacement-test-token"}
        )
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["token"] == "replacement-test-token"
    assert entry.unique_id == SERIAL
    gateway.set_override.assert_not_awaited()


async def test_reconfigure_retains_token_and_checks_identity_read_only(
    hass: HomeAssistant, gateway, mocked_flow_client
) -> None:
    entry = existing_entry(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "reconfigure"
    with patch.object(hass.config_entries, "async_reload", return_value=True):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"host": "192.0.2.61"}
        )
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data["host"] == "192.0.2.61"
    assert entry.data["token"] == TOKEN
    assert entry.unique_id == SERIAL
    gateway.set_override.assert_not_awaited()


async def test_options_enforce_polling_bounds_and_trigger_one_reload(
    hass: HomeAssistant, gateway, mocked_flow_client
) -> None:
    entry = existing_entry(hass)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] == FlowResultType.FORM
    with pytest.raises(InvalidData):
        await hass.config_entries.options.async_configure(result["flow_id"], {"scan_interval": 0})
    with patch.object(hass.config_entries, "async_reload", return_value=True) as reload:
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], {"scan_interval": 15}
        )
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert entry.options == {"scan_interval": 15}
    reload.assert_awaited_once_with(entry.entry_id)
    mocked_flow_client.assert_not_called()
    gateway.set_override.assert_not_awaited()


async def test_unverified_mode_mapping_cannot_be_configured(
    hass: HomeAssistant, gateway, mocked_flow_client
) -> None:
    payload = deepcopy(PAYLOAD)
    payload["sched_mode_key"][3] = "No Discharge"
    gateway.get_scheduler.side_effect = None
    gateway.get_scheduler.return_value = payload
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=INPUT
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.FORM
    assert "unsupported_modes" in result["errors"].values()
    gateway.set_override.assert_not_awaited()


@pytest.mark.parametrize("source", [SOURCE_REAUTH, SOURCE_RECONFIGURE])
async def test_existing_entry_credentials_can_be_repaired_after_mapping_changes(
    hass: HomeAssistant, gateway, mocked_flow_client, source: str
) -> None:
    entry = existing_entry(hass)
    payload = deepcopy(PAYLOAD)
    payload["sched_mode_key"][3] = "An unsupported new firmware mapping"
    gateway.get_scheduler.side_effect = None
    gateway.get_scheduler.return_value = payload
    gateway.get_info.return_value = GatewayIdentity(
        serial="DIFFERENT-GATEWAY", model="IQ Gateway", firmware="D9.0.0"
    )

    async def submit_credentials():
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": source, "entry_id": entry.entry_id},
            data=entry.data if source == SOURCE_REAUTH else None,
        )
        user_input = {"token": "replacement-test-token"}
        if source == SOURCE_RECONFIGURE:
            user_input["host"] = "192.0.2.61"
        return await hass.config_entries.flow.async_configure(result["flow_id"], user_input)

    # Allowing credential repair must never bypass the existing serial identity.
    result = await submit_credentials()
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "wrong_gateway"
    assert entry.data["token"] == TOKEN
    assert entry.data["host"] == HOST

    gateway.get_info.return_value = GatewayIdentity(
        serial=SERIAL, model="IQ Gateway", firmware="D9.0.0"
    )
    with patch.object(hass.config_entries, "async_reload", return_value=True):
        result = await submit_credentials()
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.ABORT
    expected_reason = "reauth_successful" if source == SOURCE_REAUTH else "reconfigure_successful"
    assert result["reason"] == expected_reason
    assert entry.unique_id == SERIAL
    assert entry.data["token"] == "replacement-test-token"
    assert entry.data["host"] == (HOST if source == SOURCE_REAUTH else "192.0.2.61")
    assert gateway.get_info.await_count == 2
    assert gateway.get_scheduler.await_count == 2
    gateway.set_override.assert_not_awaited()


@pytest.mark.parametrize("decision", ["decline", "cancel"])
async def test_declining_or_cancelling_trust_never_authenticates_or_saves(
    hass: HomeAssistant, gateway, mocked_flow_client, decision: str
) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=INPUT
    )
    assert result["step_id"] == "trust_certificate"
    assert TOKEN not in repr(result)
    if decision == "decline":
        # The unchecked default must not be interpreted as consent.
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})
        assert result["type"] == FlowResultType.FORM
        assert result["step_id"] == "trust_certificate"
        assert TOKEN not in repr(result)
    else:
        hass.config_entries.flow.async_abort(result["flow_id"])
    mocked_flow_client.assert_not_called()
    gateway.get_info.assert_not_awaited()
    gateway.get_scheduler.assert_not_awaited()
    gateway.set_override.assert_not_awaited()
    assert hass.config_entries.async_entries(DOMAIN) == []


@pytest.mark.parametrize("source", [SOURCE_REAUTH, SOURCE_RECONFIGURE])
@pytest.mark.parametrize("saved_pin", [PIN, None])
async def test_new_or_missing_certificate_pin_requires_trust_before_entry_update(
    hass: HomeAssistant,
    gateway,
    mocked_flow_client,
    certificate_probe,
    certificate_details,
    source: str,
    saved_pin: str | None,
) -> None:
    entry = existing_entry(hass)
    old_data = dict(entry.data)
    if saved_pin is None:
        old_data.pop("certificate_fingerprint")
        hass.config_entries.async_update_entry(entry, data=old_data)
    certificate_probe.return_value = SimpleNamespace(
        **(vars(certificate_details) | {"fingerprint": NEW_PIN})
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": source, "entry_id": entry.entry_id},
        data=entry.data if source == SOURCE_REAUTH else None,
    )
    user_input = {"token": "replacement-test-token"}
    if source == SOURCE_RECONFIGURE:
        user_input["host"] = "192.0.2.61"
    result = await hass.config_entries.flow.async_configure(result["flow_id"], user_input)
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "trust_certificate"
    assert result["description_placeholders"]["fingerprint"].replace(":", "").lower() == NEW_PIN
    assert entry.data == old_data
    assert "replacement-test-token" not in repr(result)
    mocked_flow_client.assert_not_called()
    gateway.get_info.assert_not_awaited()
    gateway.get_scheduler.assert_not_awaited()

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": False}
    )
    assert result["step_id"] == "trust_certificate"
    assert entry.data == old_data
    mocked_flow_client.assert_not_called()

    with patch.object(hass.config_entries, "async_reload", return_value=True):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"trust_certificate": True}
        )
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == (
        "reauth_successful" if source == SOURCE_REAUTH else "reconfigure_successful"
    )
    assert entry.data["certificate_fingerprint"] == NEW_PIN
    assert entry.data["token"] == "replacement-test-token"
    assert entry.unique_id == SERIAL
    assert mocked_flow_client.call_args.kwargs["fingerprint"] == NEW_PIN
    gateway.set_override.assert_not_awaited()


async def test_certificate_rotation_between_probe_and_auth_requires_fresh_consent(
    hass: HomeAssistant,
    gateway,
    mocked_flow_client,
    certificate_probe,
    certificate_details,
    caplog,
) -> None:
    rotated = SimpleNamespace(**(vars(certificate_details) | {"fingerprint": NEW_PIN}))
    certificate_probe.side_effect = [certificate_details, rotated]
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=INPUT
    )
    assert result["step_id"] == "trust_certificate"
    gateway.get_info.side_effect = CertificateError("The certificate no longer matches")
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"]["base"] == "certificate_changed"
    assert mocked_flow_client.call_count == 1
    assert mocked_flow_client.call_args.kwargs["fingerprint"] == PIN
    assert TOKEN not in repr(result)

    # The rejected pending trust has been discarded. A new connection attempt
    # probes the replacement and requires another affirmative decision.
    result = await hass.config_entries.flow.async_configure(result["flow_id"], INPUT)
    assert result["step_id"] == "trust_certificate"
    assert result["description_placeholders"]["fingerprint"].replace(":", "").lower() == NEW_PIN
    assert mocked_flow_client.call_count == 1
    assert mocked_flow_client.call_args.kwargs["fingerprint"] == PIN
    gateway.get_scheduler.assert_not_awaited()
    assert hass.config_entries.async_entries(DOMAIN) == []
    assert TOKEN not in repr(result)
    assert TOKEN not in caplog.text

    # Seeing the replacement certificate is not consent to trust it.
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": False}
    )
    assert result["step_id"] == "trust_certificate"
    assert mocked_flow_client.call_count == 1

    gateway.get_info.side_effect = None
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    await hass.async_block_till_done()
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"]["certificate_fingerprint"] == NEW_PIN
    assert [call.kwargs["fingerprint"] for call in mocked_flow_client.call_args_list] == [
        PIN,
        NEW_PIN,
    ]
    gateway.set_override.assert_not_awaited()


async def test_trusting_new_certificate_does_not_allow_gateway_identity_replacement(
    hass: HomeAssistant, gateway, mocked_flow_client, certificate_probe, certificate_details
) -> None:
    entry = existing_entry(hass)
    original = dict(entry.data)
    certificate_probe.return_value = SimpleNamespace(
        **(vars(certificate_details) | {"fingerprint": NEW_PIN})
    )
    gateway.get_info.return_value = GatewayIdentity(serial="DIFFERENT-GATEWAY")
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"token": "replacement-test-token"}
    )
    assert result["step_id"] == "trust_certificate"
    mocked_flow_client.assert_not_called()
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "wrong_gateway"
    assert entry.data == original
    assert entry.unique_id == SERIAL
    gateway.set_override.assert_not_awaited()


async def test_connection_input_cannot_inject_a_pin_or_preapprove_trust(
    hass: HomeAssistant, gateway, mocked_flow_client
) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_USER},
        data={**INPUT, "certificate_fingerprint": NEW_PIN, "trust_certificate": True},
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "trust_certificate"
    assert result["description_placeholders"]["fingerprint"] == PIN
    assert TOKEN not in repr(result)
    mocked_flow_client.assert_not_called()
    gateway.get_info.assert_not_awaited()
    gateway.get_scheduler.assert_not_awaited()
    assert hass.config_entries.async_entries(DOMAIN) == []


async def test_trust_confirmation_expires_when_the_existing_pin_changes(
    hass: HomeAssistant, gateway, mocked_flow_client, certificate_probe, certificate_details
) -> None:
    entry = existing_entry(hass)
    certificate_probe.return_value = SimpleNamespace(
        **(vars(certificate_details) | {"fingerprint": NEW_PIN})
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"token": "replacement-test-token"}
    )
    assert result["step_id"] == "trust_certificate"

    # A concurrent settings update invalidates the earlier review context.
    concurrent_data = dict(entry.data) | {"certificate_fingerprint": "c3" * 32}
    hass.config_entries.async_update_entry(entry, data=concurrent_data)
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "trust_expired"
    assert entry.data == concurrent_data
    mocked_flow_client.assert_not_called()
    gateway.get_info.assert_not_awaited()
    gateway.get_scheduler.assert_not_awaited()
    gateway.set_override.assert_not_awaited()


@pytest.mark.parametrize("remember", [False, True])
async def test_automatic_token_setup_trusts_before_login_and_controls_retention(
    hass: HomeAssistant,
    gateway,
    mocked_flow_client,
    certificate_probe,
    certificate_details,
    cloud_services,
    remember: bool,
) -> None:
    order = []

    async def probe(host):
        order.append("certificate_probe")
        return certificate_details

    async def public_identity(*args, **kwargs):
        order.append("pinned_public_identity")
        assert kwargs["fingerprint"] == PIN
        return GatewayIdentity(serial=SERIAL, model="IQ Gateway")

    async def issue_token(session, username, password, serial):
        order.append("cloud_token")
        assert (username, password, serial) == (USERNAME, PASSWORD, SERIAL)
        return ISSUED_TOKEN

    def authenticated_client(session, host, token, **kwargs):
        order.append("pinned_authenticated_client")
        assert (host, token, kwargs["fingerprint"]) == (HOST, ISSUED_TOKEN, PIN)
        return gateway

    certificate_probe.side_effect = probe
    cloud_services.identity.side_effect = public_identity
    cloud_services.request.side_effect = issue_token
    mocked_flow_client.side_effect = authenticated_client
    result = await hass.config_entries.flow.async_init(DOMAIN, context={"source": SOURCE_USER})
    assert result["step_id"] == "user"
    user_input = dict(AUTOMATIC_INPUT)
    if remember:
        user_input["remember_credentials"] = True
    else:
        user_input.pop("remember_credentials")
        user_input.pop("auth_method")
    result = await hass.config_entries.flow.async_configure(result["flow_id"], user_input)
    assert result["step_id"] == "trust_certificate"
    assert order == ["certificate_probe"]
    cloud_services.identity.assert_not_awaited()
    cloud_services.request.assert_not_awaited()
    mocked_flow_client.assert_not_called()
    assert PASSWORD not in repr(result)
    assert ISSUED_TOKEN not in repr(result)

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    await hass.async_block_till_done()
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert order == [
        "certificate_probe",
        "pinned_public_identity",
        "cloud_token",
        "pinned_authenticated_client",
    ]
    assert result["result"].unique_id == SERIAL
    assert result["data"]["token"] == ISSUED_TOKEN
    assert result["data"]["certificate_fingerprint"] == PIN
    assert result["data"]["remember_credentials"] is remember
    if remember:
        assert result["data"]["username"] == USERNAME
        assert result["data"]["password"] == PASSWORD
    else:
        assert "username" not in result["data"]
        assert "password" not in result["data"]
    gateway.get_scheduler.assert_awaited_once()
    gateway.set_override.assert_not_awaited()


@pytest.mark.parametrize(
    ("error", "error_key"),
    [
        (CloudInvalidAuth("Rejected credentials"), "cloud_invalid_auth"),
        (CloudMFARequired("Browser verification required"), "cloud_mfa_required"),
        (CloudCommunicationError("Service unavailable"), "cloud_cannot_connect"),
        (CloudTokenError("No usable token returned"), "cloud_token_error"),
    ],
)
async def test_automatic_cloud_errors_do_not_persist_or_expose_credentials(
    hass: HomeAssistant,
    gateway,
    mocked_flow_client,
    cloud_services,
    caplog,
    error: Exception,
    error_key: str,
) -> None:
    cloud_services.request.side_effect = error
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=AUTOMATIC_INPUT
    )
    assert result["step_id"] == "trust_certificate"
    cloud_services.request.assert_not_awaited()
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "user"
    assert result["errors"]["base"] == error_key
    assert PASSWORD not in repr(result)
    assert ISSUED_TOKEN not in repr(result)
    assert PASSWORD not in caplog.text
    assert ISSUED_TOKEN not in caplog.text
    assert hass.config_entries.async_entries(DOMAIN) == []
    mocked_flow_client.assert_not_called()
    gateway.get_scheduler.assert_not_awaited()
    gateway.set_override.assert_not_awaited()


async def test_automatic_setup_can_request_serial_when_public_info_is_unavailable(
    hass: HomeAssistant, gateway, mocked_flow_client, cloud_services
) -> None:
    cloud_services.identity.side_effect = CommunicationError("Public info is unavailable")
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=AUTOMATIC_INPUT
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == "gateway_serial"
    cloud_services.request.assert_not_awaited()
    mocked_flow_client.assert_not_called()
    assert PASSWORD not in repr(result)

    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"serial": "invalid-serial"}
    )
    assert result["step_id"] == "gateway_serial"
    assert result["errors"]["base"] == "invalid_serial"
    cloud_services.request.assert_not_awaited()

    result = await hass.config_entries.flow.async_configure(result["flow_id"], {"serial": SERIAL})
    await hass.async_block_till_done()
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"]["serial"] == SERIAL
    assert cloud_services.request.await_args.args[-3:] == (USERNAME, PASSWORD, SERIAL)
    assert cloud_services.identity.await_count == 1
    gateway.set_override.assert_not_awaited()


@pytest.mark.parametrize("method", ["automatic", "manual"])
async def test_reauth_forgets_previously_remembered_cloud_credentials(
    hass: HomeAssistant, gateway, mocked_flow_client, cloud_services, method: str
) -> None:
    entry = existing_entry(hass)
    hass.config_entries.async_update_entry(
        entry,
        data=dict(entry.data)
        | {
            "auth_method": "automatic",
            "username": "previous@example.invalid",
            "password": "previous-password",
            "remember_credentials": True,
        },
        options={"scan_interval": 55},
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
        data=entry.data,
    )
    user_input = {"auth_method": method, "remember_credentials": False}
    if method == "automatic":
        user_input.update(username=USERNAME, password=PASSWORD)
    else:
        # A legacy JWT-only submission must still choose manual mode, even
        # when the stored entry makes the form default to automatic/remember.
        user_input = {"token": "replacement-manual-token"}
    with patch.object(hass.config_entries, "async_reload", return_value=True):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], user_input)
        await hass.async_block_till_done()
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.unique_id == SERIAL
    assert entry.data["certificate_fingerprint"] == PIN
    assert entry.data["remember_credentials"] is False
    assert "username" not in entry.data
    assert "password" not in entry.data
    assert entry.options == {"scan_interval": 55}
    cloud_services.identity.assert_not_awaited()
    if method == "automatic":
        assert entry.data["token"] == ISSUED_TOKEN
        assert cloud_services.request.await_args.args[-3:] == (USERNAME, PASSWORD, SERIAL)
    else:
        assert entry.data["token"] == "replacement-manual-token"
        cloud_services.request.assert_not_awaited()
    gateway.set_override.assert_not_awaited()


async def test_automatic_token_target_must_match_the_authenticated_gateway(
    hass: HomeAssistant, gateway, mocked_flow_client, cloud_services
) -> None:
    gateway.get_info.return_value = GatewayIdentity(serial="999999999999")
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=AUTOMATIC_INPUT
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"], {"trust_certificate": True}
    )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "wrong_gateway"
    assert hass.config_entries.async_entries(DOMAIN) == []
    assert cloud_services.request.await_args.args[-1] == SERIAL
    gateway.set_override.assert_not_awaited()


@pytest.mark.parametrize("decision", ["decline", "cancel"])
async def test_automatic_login_never_runs_when_certificate_trust_is_not_accepted(
    hass: HomeAssistant, gateway, mocked_flow_client, cloud_services, decision: str
) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}, data=AUTOMATIC_INPUT
    )
    assert result["step_id"] == "trust_certificate"
    if decision == "decline":
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"trust_certificate": False}
        )
        assert result["step_id"] == "trust_certificate"
    else:
        hass.config_entries.flow.async_abort(result["flow_id"])
    cloud_services.identity.assert_not_awaited()
    cloud_services.request.assert_not_awaited()
    mocked_flow_client.assert_not_called()
    gateway.set_override.assert_not_awaited()
    assert hass.config_entries.async_entries(DOMAIN) == []
