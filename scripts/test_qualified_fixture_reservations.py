import contextlib
import copy
import tempfile
from pathlib import Path
import unittest
from unittest import mock

try:
    from . import visual_platform as visual
except ImportError:
    import visual_platform as visual


class QualifiedReservationsTest(unittest.TestCase):
    def setUp(self):
        self.reservations={"android":{"memory_mib":2048,"pid":123}}
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(visual,"_resource_lock",side_effect=contextlib.nullcontext))
        self.stack.enter_context(mock.patch.object(visual,"_admit_fixture_storage",return_value={}))
        self.stack.enter_context(mock.patch.object(visual,"_read_reservations",side_effect=lambda:copy.deepcopy(self.reservations)))
        self.stack.enter_context(mock.patch.object(visual,"_write_reservations",side_effect=self.write))
        self.stack.enter_context(mock.patch.object(visual,"_resource_policy",return_value=({"max_local_vms":1,"build_headroom_mib":8192,"minimum_available_mib":2048},"product-profile")))
        self.stack.enter_context(mock.patch.object(visual.host_platform,"system",return_value="Darwin"))
        self.stack.enter_context(mock.patch.object(visual,"_tart_running_allocations",return_value=[]))
        self.stack.enter_context(mock.patch.object(visual,"_pid_running",return_value=True))
        self.stack.enter_context(mock.patch.object(visual,"_host_memory_snapshot",return_value={
            "physical_mib":24576,"available_mib":18000,"swap_used_mib":0,"pressure_critical":False}))

    def write(self,value):self.reservations=copy.deepcopy(value)

    def test_second_qualified_fixture_preserves_old_unknown_and_blocks_third(self):
        original=copy.deepcopy(self.reservations["android"])
        result=visual._admit_recovery_fixture_start("android-emulator","1"*64,2048,storage_fixture_id="new-owned")
        self.assertEqual(self.reservations["android"],original)
        key=result["reservationKey"]
        self.assertEqual(self.reservations[key],{"memory_mib":2048,"pid":0})
        self.assertEqual(result["policy"]["max_local_vms"],2)
        before=copy.deepcopy(self.reservations)
        with self.assertRaisesRegex(visual.VisualPlatformError,"VM slot limit"):
            visual._admit_recovery_fixture_start("tart-linux","2"*64,4096,storage_fixture_id="third")
        self.assertEqual(self.reservations,before)

    def test_product_profile_still_blocks_second_vm(self):
        with self.assertRaisesRegex(visual.VisualPlatformError,"VM slot limit"):
            visual._admit_visual_start("windows",4096)
        self.assertEqual(set(self.reservations),{"android"})

    def test_unknown_pending_and_dead_qualified_claims_are_never_pruned(self):
        key="recovery-test:raw-qemu-linux:"+"3"*64
        self.reservations={key:{"memory_mib":4096,"pid":99999999}}
        with mock.patch.object(visual,"_pid_running",return_value=False):
            with self.assertRaisesRegex(visual.VisualPlatformError,"VM slot limit"):
                visual._admit_visual_start("windows",4096)
        self.assertIn(key,self.reservations)
        self.reservations[key]["pid"]=0
        with self.assertRaisesRegex(visual.VisualPlatformError,"VM slot limit"):
            visual._admit_visual_start("windows",4096)
        self.assertEqual(self.reservations[key]["pid"],0)

    def test_tart_actual_allocation_is_counted_once_and_memory_headroom_still_applies(self):
        key=visual._qualified_reservation_key("tart-linux","4"*64)
        self.reservations[key]={"memory_mib":4096,"pid":456}
        self.assertEqual(visual._reservation_allocations(self.reservations),[2048])
        self.reservations[key]["pid"]=0
        self.assertEqual(visual._reservation_allocations(self.reservations),[2048,4096])
        self.reservations={"android":{"memory_mib":16384,"pid":123}}
        with self.assertRaisesRegex(visual.VisualPlatformError,"headroom"):
            visual._admit_recovery_fixture_start("android-emulator","5"*64,2048,storage_fixture_id="insufficient")


if __name__=="__main__":unittest.main()
