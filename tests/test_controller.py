"""Pure async tests for the one-mode controller; no HA or gateway required."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import unittest
from copy import deepcopy
from pathlib import Path

# Import the independent module without loading the Home Assistant integration.
_MODULE_PATH = Path(__file__).parents[1] / "custom_components/enphase_local_control/controller.py"
_SPEC = importlib.util.spec_from_file_location("enphase_test_controller", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
controller = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = controller
_SPEC.loader.exec_module(controller)


def scheduler(debug=-1, current=1):
    return {
        "acb_debug_mode": debug,
        "acb_current_mode": current,
        "sched_mode_key": [
            "ID - Idle",
            "ZN - Zero Net",
            "CG - Charge From Grid",
            "DG - Discharge to Grid",
            "ND - No Discharge",
            "DL - Discharge to Load",
        ],
        "ENC_agg_soc": 17,
    }


class FakeGateway:
    def __init__(self, debug=-1):
        self.payload = scheduler(debug)
        self.writes = []
        self.reads = 0
        self.read_error = None
        self.write_error = None
        self.apply_before_error = False
        self.ignore_write = False

    async def get_scheduler(self):
        self.reads += 1
        if self.read_error is not None:
            raise self.read_error
        return deepcopy(self.payload)

    async def set_override(self, mode):
        self.writes.append(mode)
        if not self.ignore_write and (self.write_error is None or self.apply_before_error):
            self.payload["acb_debug_mode"] = mode
        if self.write_error is not None:
            raise self.write_error
        return {"acb_debug_mode": mode}


class ModeControllerTests(unittest.IsolatedAsyncioTestCase):
    async def test_startup_refresh_and_reconnect_never_write(self):
        client = FakeGateway(3)
        mode = controller.ModeController(client)
        self.assertFalse(mode.available)
        self.assertIsNone(mode.is_on(3))
        await mode.async_refresh()
        self.assertTrue(mode.is_on(3))
        client.read_error = TimeoutError("offline")
        with self.assertRaises(TimeoutError):
            await mode.async_refresh()
        self.assertFalse(mode.available)
        self.assertEqual(mode.debug_mode, 3)
        self.assertIsNone(mode.is_on(3))
        client.read_error = None
        await mode.async_refresh()
        self.assertTrue(mode.is_on(3))
        self.assertEqual(client.writes, [])

    async def test_automatic_control_uses_actual_mode_without_startup_write(self):
        client = FakeGateway(-1)
        client.payload["acb_current_mode"] = 2
        mode = controller.ModeController(client)
        await mode.async_refresh()
        self.assertEqual(mode.current_mode, 2)
        self.assertEqual(mode.selected_mode, 2)
        self.assertEqual([mode.is_on(value) for value in (1, 2, 3)], [False, True, False])
        self.assertEqual(client.writes, [])

    async def test_normal_zero_net_startup_has_one_selected_switch(self):
        client = FakeGateway(-1)
        mode = controller.ModeController(client)
        await mode.async_refresh()
        self.assertEqual(mode.debug_mode, -1)
        self.assertEqual(mode.selected_mode, 1)
        self.assertEqual([mode.is_on(value) for value in (1, 2, 3)], [True, False, False])
        self.assertEqual(client.writes, [])

    async def test_turn_on_asserts_override_even_if_automatic_actual_mode_matches(self):
        client = FakeGateway(-1)
        client.payload["acb_current_mode"] = 2
        mode = controller.ModeController(client)
        result = await mode.async_turn_on(2)
        self.assertTrue(result.changed)
        self.assertEqual(client.writes, [2])
        self.assertEqual(mode.debug_mode, 2)

    async def test_turn_off_automatic_charge_selects_explicit_zero_net(self):
        client = FakeGateway(-1)
        client.payload["acb_current_mode"] = 2
        mode = controller.ModeController(client)
        await mode.async_turn_off(2)
        self.assertEqual(client.writes, [1])
        self.assertTrue(mode.is_on(1))

    async def test_explicit_override_takes_precedence_over_actual_mode(self):
        client = FakeGateway(3)
        client.payload["acb_current_mode"] = 2
        mode = controller.ModeController(client)
        await mode.async_refresh()
        self.assertEqual([mode.is_on(value) for value in (1, 2, 3)], [False, False, True])

    async def test_direct_mode_change_and_confirmation(self):
        client = FakeGateway(2)
        mode = controller.ModeController(client)
        result = await mode.async_turn_on(3)
        self.assertEqual(client.writes, [3])
        self.assertTrue(result.changed)
        self.assertFalse(result.reconciled)
        self.assertEqual([mode.is_on(value) for value in (1, 2, 3)], [False, False, True])
        result = await mode.async_turn_on(3)
        self.assertFalse(result.changed)
        self.assertEqual(client.writes, [3])

    async def test_off_any_active_non_zero_net_switch_selects_zero_net(self):
        for selected in (2, 3, 4):
            with self.subTest(selected=selected):
                client = FakeGateway(selected)
                mode = controller.ModeController(client)
                result = await mode.async_turn_off(selected)
                self.assertTrue(result.changed)
                self.assertEqual(client.writes, [1])
                self.assertTrue(mode.is_on(1))

    async def test_off_zero_net_and_inactive_switch_are_noops(self):
        client = FakeGateway(3)
        mode = controller.ModeController(client)
        self.assertFalse((await mode.async_turn_off(1)).changed)
        self.assertFalse((await mode.async_turn_off(2)).changed)
        self.assertTrue(mode.is_on(3))
        self.assertEqual(client.writes, [])

    async def test_stale_off_cannot_clear_new_mode(self):
        client = FakeGateway(2)
        mode = controller.ModeController(client)
        await mode.async_refresh()
        # Another caller has already changed the device since our last poll.
        client.payload["acb_debug_mode"] = 3
        await mode.async_turn_off(2)
        self.assertEqual(client.writes, [])
        self.assertTrue(mode.is_on(3))

    async def test_uncertain_write_is_reconciled_without_retry(self):
        client = FakeGateway(-1)
        client.write_error = TimeoutError("response lost")
        client.apply_before_error = True
        mode = controller.ModeController(client)
        result = await mode.async_turn_on(2)
        self.assertTrue(result.reconciled)
        self.assertTrue(mode.available)
        self.assertTrue(mode.is_on(2))
        self.assertEqual(client.writes, [2])

    async def test_failed_write_preserves_confirmed_other_mode(self):
        client = FakeGateway(1)
        original = PermissionError("forbidden")
        client.write_error = original
        mode = controller.ModeController(client)
        with self.assertRaises(PermissionError) as captured:
            await mode.async_turn_on(2)
        self.assertIs(captured.exception, original)
        self.assertTrue(mode.available)
        self.assertTrue(mode.is_on(1))
        self.assertEqual(client.writes, [2])

    async def test_timeout_without_application_does_not_retry(self):
        client = FakeGateway(1)
        original = TimeoutError("request outcome uncertain")
        client.write_error = original
        mode = controller.ModeController(client)
        with self.assertRaises(TimeoutError) as captured:
            await mode.async_turn_on(2)
        self.assertIs(captured.exception, original)
        self.assertTrue(mode.available)
        self.assertTrue(mode.is_on(1))
        self.assertEqual(client.writes, [2])

    async def test_write_and_reconciliation_failures_remain_unavailable(self):
        class FailedReconciliation(FakeGateway):
            async def set_override(self, value):
                self.writes.append(value)
                self.read_error = PermissionError("token expired during request")
                raise TimeoutError("POST response lost")

        client = FailedReconciliation(1)
        mode = controller.ModeController(client)
        with self.assertRaises(PermissionError) as captured:
            await mode.async_turn_on(2)
        self.assertIsInstance(captured.exception.__cause__, TimeoutError)
        self.assertFalse(mode.available)
        self.assertIsNone(mode.is_on(1))
        self.assertEqual(client.writes, [2])

    async def test_cancelled_write_does_not_replay_on_reconnect(self):
        entered = asyncio.Event()

        class CancelledWrite(FakeGateway):
            async def set_override(self, value):
                self.writes.append(value)
                self.payload["acb_debug_mode"] = value
                entered.set()
                await asyncio.Event().wait()

        client = CancelledWrite(1)
        mode = controller.ModeController(client)
        task = asyncio.create_task(mode.async_turn_on(2))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(mode.available)
        await mode.async_refresh()
        self.assertTrue(mode.is_on(2))
        self.assertEqual(client.writes, [2])

    async def test_successful_ack_is_insufficient_without_readback(self):
        client = FakeGateway(1)
        client.ignore_write = True
        mode = controller.ModeController(client)
        with self.assertRaises(controller.CommandNotConfirmed) as captured:
            await mode.async_turn_on(2)
        self.assertEqual(captured.exception.requested_mode, 2)
        self.assertEqual(captured.exception.observed_mode, 1)
        self.assertTrue(mode.available)
        self.assertTrue(mode.is_on(1))

    async def test_failed_readback_does_not_display_unconfirmed_selection(self):
        class ReadbackFailure(FakeGateway):
            async def set_override(self, value):
                result = await super().set_override(value)
                self.read_error = TimeoutError("offline after POST")
                return result

        client = ReadbackFailure(1)
        mode = controller.ModeController(client)
        with self.assertRaises(TimeoutError):
            await mode.async_turn_on(2)
        self.assertFalse(mode.available)
        self.assertEqual(mode.debug_mode, 1)
        self.assertIsNone(mode.is_on(2))
        self.assertEqual(client.writes, [2])

    async def test_mapping_mismatch_fails_closed_but_keeps_raw_truth(self):
        client = FakeGateway(2)
        client.payload["sched_mode_key"][2] = "HEMS Charge From Grid"
        mode = controller.ModeController(client)
        state = await mode.async_refresh()
        self.assertTrue(mode.available)
        self.assertFalse(state.modes_supported)
        self.assertEqual(state.debug_mode, 2)
        self.assertIsNone(mode.is_on(2))
        with self.assertRaises(controller.UnsupportedModes):
            await mode.async_turn_on(3)
        with self.assertRaises(controller.UnsupportedModes):
            await mode.async_turn_off(2)
        self.assertEqual(client.writes, [])

    async def test_mapping_normalizes_case_punctuation_and_spacing(self):
        client = FakeGateway()
        client.payload["sched_mode_key"] = [
            "Idle",
            "zero NET",
            "cg: charge-from-grid",
            "DG : Discharge To Grid",
        ]
        mode = controller.ModeController(client)
        self.assertTrue((await mode.async_refresh()).modes_supported)

    async def test_external_unmapped_modes_are_not_faked_as_zero_net(self):
        client = FakeGateway(42)
        mode = controller.ModeController(client)
        state = await mode.async_refresh()
        self.assertEqual(state.debug_mode, 42)
        self.assertTrue(state.modes_supported)
        self.assertEqual([mode.is_on(value) for value in (1, 2, 3)], [None] * 3)

    async def test_known_unrepresented_mode_has_no_selected_switch(self):
        client = FakeGateway(5)
        mode = controller.ModeController(client)
        await mode.async_refresh()
        self.assertEqual(mode.selected_mode, 5)
        self.assertEqual([mode.is_on(value) for value in (1, 2, 3, 4)], [False] * 4)

    async def test_restrict_discharge_selects_verified_mode_four(self):
        client = FakeGateway(2)
        client.payload["sched_mode_key"][4] = "nd : No-Discharge"
        mode = controller.ModeController(client)
        result = await mode.async_turn_on(4)
        self.assertTrue(result.changed)
        self.assertEqual(client.writes, [4])
        self.assertEqual(
            [mode.is_on(value) for value in (1, 2, 3, 4)], [False, False, False, True]
        )

    async def test_automatic_restrict_discharge_does_not_write_on_refresh(self):
        client = FakeGateway(-1)
        client.payload["acb_current_mode"] = 4
        mode = controller.ModeController(client)
        await mode.async_refresh()
        self.assertTrue(mode.is_on(4))
        self.assertEqual(client.writes, [])

        # Turning it on explicitly holds the mode; turning it off selects 1.
        await mode.async_turn_on(4)
        await mode.async_turn_off(4)
        self.assertEqual(client.writes, [4, 1])
        self.assertTrue(mode.is_on(1))

    async def test_missing_or_mismatched_mode_four_blocks_only_restrict(self):
        for label in (None, "DL - Discharge to Load", "Not No Discharge"):
            with self.subTest(label=label):
                client = FakeGateway(4)
                if label is None:
                    del client.payload["sched_mode_key"][4:]
                else:
                    client.payload["sched_mode_key"][4] = label
                mode = controller.ModeController(client)
                state = await mode.async_refresh()
                self.assertTrue(state.modes_supported)
                self.assertFalse(state.supports_mode(4))
                self.assertIsNone(mode.is_on(4))
                self.assertEqual([mode.is_on(value) for value in (1, 2, 3)], [False] * 3)

                with self.assertRaises(controller.UnsupportedModes):
                    await mode.async_turn_on(4)
                with self.assertRaises(controller.UnsupportedModes):
                    await mode.async_turn_off(4)
                self.assertEqual(client.writes, [])

                # A user can still select a positively verified alternative.
                await mode.async_turn_on(1)
                self.assertEqual(client.writes, [1])
                self.assertTrue(mode.is_on(1))

    async def test_restrict_mapping_checked_fresh_before_turn_off(self):
        client = FakeGateway(4)
        mode = controller.ModeController(client)
        await mode.async_refresh()
        self.assertTrue(mode.is_on(4))
        client.payload["sched_mode_key"][4] = "Discharge To Load"
        with self.assertRaises(controller.UnsupportedModes):
            await mode.async_turn_off(4)
        self.assertEqual(client.writes, [])
        self.assertIsNone(mode.is_on(4))

    async def test_restrict_command_does_not_confirm_if_label_changes_in_readback(self):
        class MappingChangesDuringWrite(FakeGateway):
            async def set_override(self, value):
                result = await super().set_override(value)
                self.payload["sched_mode_key"][4] = "Discharge to Load"
                return result

        client = MappingChangesDuringWrite(1)
        mode = controller.ModeController(client)
        with self.assertRaises(controller.UnsupportedModes):
            await mode.async_turn_on(4)
        self.assertEqual(client.writes, [4])
        self.assertEqual(mode.debug_mode, 4)
        self.assertIsNone(mode.is_on(4))

    async def test_late_restrict_off_does_not_cancel_a_new_mode(self):
        client = FakeGateway(4)
        mode = controller.ModeController(client)
        await asyncio.gather(mode.async_turn_on(3), mode.async_turn_off(4))
        self.assertEqual(client.writes, [3])
        self.assertTrue(mode.is_on(3))

    async def test_return_to_automatic_is_noop_if_already_released(self):
        client = FakeGateway(-1)
        mode = controller.ModeController(client)
        result = await mode.async_return_to_automatic()
        self.assertFalse(result.changed)
        self.assertEqual(client.writes, [])
        self.assertEqual(mode.debug_mode, -1)

    async def test_return_to_automatic_clears_charge_override(self):
        client = FakeGateway(2)
        mode = controller.ModeController(client)
        result = await mode.async_return_to_automatic()
        self.assertTrue(result.changed)
        self.assertEqual(client.writes, [-1])
        self.assertEqual(mode.debug_mode, -1)
        self.assertEqual(mode.selected_mode, 1)

    async def test_return_to_automatic_works_when_mode_labels_changed(self):
        client = FakeGateway(2)
        client.payload["sched_mode_key"][2] = "Changed firmware mode"
        mode = controller.ModeController(client)
        result = await mode.async_return_to_automatic()
        self.assertTrue(result.changed)
        self.assertFalse(result.state.modes_supported)
        self.assertEqual(client.writes, [-1])
        self.assertEqual(mode.debug_mode, -1)

    async def test_return_to_automatic_requires_confirmed_release(self):
        client = FakeGateway(2)
        client.ignore_write = True
        mode = controller.ModeController(client)
        with self.assertRaises(controller.CommandNotConfirmed):
            await mode.async_return_to_automatic()
        self.assertEqual(client.writes, [-1])
        self.assertEqual(mode.debug_mode, 2)

    async def test_bad_scheduler_values_make_live_state_unavailable(self):
        client = FakeGateway(1)
        mode = controller.ModeController(client)
        await mode.async_refresh()
        client.payload["acb_debug_mode"] = True
        with self.assertRaises(controller.InvalidSchedulerResponse):
            await mode.async_refresh()
        self.assertFalse(mode.available)
        self.assertEqual(mode.debug_mode, 1)

    async def test_invalid_requested_modes_never_reach_gateway(self):
        client = FakeGateway()
        mode = controller.ModeController(client)
        for invalid in (-1, 0, 5, True, "2"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(controller.InvalidMode):
                    await mode.async_turn_on(invalid)
        self.assertEqual(client.writes, [])
        self.assertEqual(client.reads, 0)

    async def test_poll_and_commands_share_one_lock(self):
        started = asyncio.Event()
        release = asyncio.Event()

        class SlowPoll(FakeGateway):
            async def get_scheduler(self):
                if self.reads == 0:
                    self.reads += 1
                    snapshot = deepcopy(self.payload)
                    started.set()
                    await release.wait()
                    return snapshot
                return await super().get_scheduler()

        client = SlowPoll(1)
        mode = controller.ModeController(client)
        poll = asyncio.create_task(mode.async_refresh())
        await started.wait()
        change = asyncio.create_task(mode.async_turn_on(2))
        await asyncio.sleep(0)
        self.assertEqual(client.writes, [])
        release.set()
        await asyncio.gather(poll, change)
        self.assertTrue(mode.is_on(2))
        self.assertEqual(client.writes, [2])

    async def test_concurrent_commands_and_late_off_are_serialized(self):
        client = FakeGateway(1)
        mode = controller.ModeController(client)
        await asyncio.gather(mode.async_turn_on(2), mode.async_turn_on(3), mode.async_turn_off(2))
        self.assertEqual(client.writes, [2, 3])
        self.assertTrue(mode.is_on(3))


if __name__ == "__main__":
    unittest.main()
