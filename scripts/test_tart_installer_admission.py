"""Full historical/current admission callers; all external observations controlled."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import visual_platform as visual
from scripts import test_qualified_fixture_reservations as qualified


class TartInstallerAdmissionTests(unittest.TestCase):
    setUp=qualified.QualifiedReservationsTest.setUp
    write=qualified.QualifiedReservationsTest.write
    def test_actual_bound_installer_reservation_remains_counted_when_tart_lists_no_guest(self):
        digest='7'*64
        admitted=visual._admit_recovery_fixture_start('tart-macos-installer',digest,4096,storage_fixture_id='exact-install')
        key=admitted['reservationKey'];visual._bind_visual_reservation(key,456)
        self.assertFalse(visual._reservation_is_tart(key))
        self.assertEqual(visual._reservation_allocations(self.reservations),[2048,4096])
        original=copy.deepcopy(self.reservations)
        with self.assertRaisesRegex(visual.VisualPlatformError,'VM slot limit'):
            visual._admit_recovery_fixture_start('android-emulator','8'*64,2048,storage_fixture_id='third')
        self.assertEqual(self.reservations,original)
        with mock.patch.object(visual,'_pid_running',return_value=False):
            with self.assertRaisesRegex(visual.VisualPlatformError,'VM slot limit'):
                visual._admit_recovery_fixture_start('android-emulator','9'*64,2048,storage_fixture_id='third')
        self.assertEqual(self.reservations,original)

    def test_before_whole_original_dedup_dropped_real_bound_installer_and_admitted_third(self):
        folder=Path(__file__).resolve().parents[1]/'agent_tools/tests/fixtures/tart_installer_admission'
        source=(folder/'visual_platform.before.source').read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(),json.loads((folder/'provenance.json').read_bytes())['sourceSha256'])
        spec=importlib.util.spec_from_loader('scripts._installer_before',loader=None)
        before=importlib.util.module_from_spec(spec);before.__file__=str(Path(visual.__file__))
        exec(compile(source,'<complete-original-visual-admission>','exec'),before.__dict__)
        oldkey='recovery-test:tart-macos:'+'1'*64
        oldclaims={'android':{'memory_mib':2048,'pid':123},oldkey:{'memory_mib':4096,'pid':456}}
        with mock.patch.object(before,'_resource_lock',visual._resource_lock),mock.patch.object(before,'_admit_fixture_storage',visual._admit_fixture_storage),mock.patch.object(before,'_read_reservations',return_value=copy.deepcopy(oldclaims)),mock.patch.object(before,'_write_reservations') as write,mock.patch.object(before,'_resource_policy',visual._resource_policy),mock.patch.object(before,'_host_memory_snapshot',visual._host_memory_snapshot),mock.patch.object(before,'_tart_running_allocations',return_value=[]):
            self.assertEqual(before._reservation_allocations(oldclaims),[2048])
            before._admit_recovery_fixture_start('android-emulator','2'*64,2048,storage_fixture_id='third')
            self.assertEqual(len(write.call_args.args[0]),3)
        newkey=visual._qualified_reservation_key('tart-macos-installer','1'*64)
        self.reservations={'android':oldclaims['android'],newkey:oldclaims[oldkey]}
        with self.assertRaisesRegex(visual.VisualPlatformError,'VM slot limit'):
            visual._admit_recovery_fixture_start('android-emulator','2'*64,2048,storage_fixture_id='third')
        self.assertEqual(len(self.reservations),2)

    def test_installer_requires_two_healthy_same_host_samples_and_storage_before_claim(self):
        first={'physical_mib':24576,'available_mib':18000,'swap_used_mib':0,'pressure_critical':False}
        for second in ({**first,'pressure_critical':True},{**first,'physical_mib':32768}):
            original=copy.deepcopy(self.reservations)
            with mock.patch.object(visual,'_host_memory_snapshot',side_effect=[first,second]) as observe,self.assertRaises(visual.VisualPlatformError):
                visual._admit_recovery_fixture_start('tart-macos-installer','3'*64,4096,storage_fixture_id='exact-install')
            self.assertEqual(observe.call_count,2);self.assertEqual(self.reservations,original)
        with mock.patch.object(visual,'_host_memory_snapshot',side_effect=[first,first]) as observe:
            visual._admit_recovery_fixture_start('tart-macos-installer','4'*64,4096,storage_fixture_id='exact-install')
        self.assertEqual(observe.call_count,2)
        visual._admit_fixture_storage.assert_called_with('macos','start',fixture_id='exact-install')

    def test_installer_memory_is_fixed_and_failed_storage_never_publishes_claim(self):
        original=copy.deepcopy(self.reservations)
        for memory in (1,True,8192):
            with self.subTest(memory=memory),self.assertRaises(visual.VisualPlatformError):
                visual._admit_recovery_fixture_start('tart-macos-installer','5'*64,memory,storage_fixture_id='exact-install')
        with mock.patch.object(visual,'_admit_fixture_storage',side_effect=visual.VisualPlatformError('disk_capacity_insufficient')),self.assertRaises(visual.VisualPlatformError):
            visual._admit_recovery_fixture_start('tart-macos-installer','5'*64,4096,storage_fixture_id='exact-install')
        self.assertEqual(self.reservations,original)

if __name__=='__main__':unittest.main()
