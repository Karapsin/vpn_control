"""Historical archive admission affects the actual create-only reservation."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from agent_tools import windows_msi_base_prepare as base
from agent_tools import windows_cp117_c32_archive_admission as archive
from agent_tools import windows_cp117_historical_base_archives as historical

C32 = 'c32cb108-4d48-407e-9153-40774559ba50'
NEW = '67eeeedb-a618-42d5-8e31-821650d16302'

class ReservationTests(unittest.TestCase):
    def test_fixed_historical_closures_preserve_bytes_and_allow_only_ready_proof(self):
        correlations=('45e4514a-c629-4f3b-99bc-aad599640d29','2ace6a48-ba60-4705-9200-4ff857f2aba6')
        for state in ('ready','blocked','unknown'):
            with self.subTest(state=state),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);directory=root/base._LOCAL;directory.mkdir(parents=True,mode=0o700)
                old=[]
                for corr in correlations:
                    for suffix in ('.json','.unknown-close.json'):
                        p=directory/(corr+suffix);p.write_bytes(b'{}');p.chmod(0o600);old.append(p)
                proof={'state':state,'phases':{'transfer-recovery':'archived' if state=='ready' else 'unknown','unknown-closure':'archived' if state=='ready' else 'unknown'},'replayAllowed':False,'nativeActionAllowed':False,'productAction':False}
                with mock.patch.object(base,'_pre_effect_closed',return_value=False),mock.patch.object(base,'_unknown_closure_archived',return_value=False),mock.patch.object(historical,'observe',return_value=proof):
                    if state=='ready':base._reserve(root,{'request':{'correlationId':NEW}},config=object(),target=object(),descriptor=('env','sock',1,2,'sid'))
                    else:
                        with self.assertRaises(base.WindowsMsiBasePrepareError):base._reserve(root,{'request':{'correlationId':NEW}},config=object(),target=object(),descriptor=('env','sock',1,2,'sid'))
                self.assertEqual(state=='ready',base._intent_path(root,NEW).exists())
                self.assertTrue(all(p.read_bytes()==b'{}' for p in old))

    def test_completed_c32_preserved_and_unresolved_c32_blocks(self):
        for state in ('ready', 'blocked', 'unknown'):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp); directory=root/base._LOCAL
                directory.mkdir(parents=True, mode=0o700)
                old=directory/(C32+'.json');old.write_text('{}');old.chmod(0o600)
                record={'request':{'correlationId':NEW}}
                with mock.patch.object(base,'_pre_effect_closed',return_value=False), \
                     mock.patch.object(base,'_unknown_closure_archived',return_value=False), \
                     mock.patch.object(archive,'preflight',return_value={'state':state,
                         'correlationId':C32,'replayAllowed':False,
                         'nativeActionAllowed':False,'productAction':False}) as proof:
                    if state=='ready':
                        base._reserve(root,record,config=object(),target=object(),descriptor=('env','sock',1,2,'sid'))
                        self.assertEqual(record,json.loads(base._intent_path(root,NEW).read_text()))
                    else:
                        with self.assertRaises(base.WindowsMsiBasePrepareError):
                            base._reserve(root,record,config=object(),target=object(),descriptor=('env','sock',1,2,'sid'))
                        self.assertFalse(base._intent_path(root,NEW).exists())
                self.assertEqual('{}',old.read_text())
                proof.assert_called_once()
