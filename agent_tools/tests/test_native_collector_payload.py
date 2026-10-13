"""Execute genuine fixed collector programs on owned local receipt files only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from agent_tools import native_scheduled_refresh_ssh as scheduled
from agent_tools import native_owner_gui_lifecycle_ssh as gui

@unittest.skipUnless(os.name == 'posix', 'Fixed private collector uses POSIX files')
class ActualCollectorPayloadTest(unittest.TestCase):
    def run_collector(self, module, *, large=False, failure=False, actor_type=None):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw);root.chmod(0o700)
            cid='12345678-1234-4321-8123-123456789abc';scenario=module.SCENARIO_ID
            job=root/'native-scenario-jobs'/'owned'/scenario/cid
            job.mkdir(mode=0o700,parents=True)
            binding={'scenarioId':scenario,'host':'guest','environment':'owned','correlationId':cid,
                     'bundleHash':'a'*64,'artifactIds':{'bundleManifest':'sha256-'+'a'*64,'scenarioInput':'sha256-'+'b'*64}}
            intent={**binding,'identity':{'pid':101,'startTicks':202}}
            wrapper={**binding,'pid':101,'startTicks':202,'exitCode':3 if failure else 0}
            if actor_type is not None:
                intent['identity']={k:actor_type(v) for k,v in intent['identity'].items()}
                for k in ('pid','startTicks'):wrapper[k]=actor_type(wrapper[k])
            receipt={'schema':'vpn-control.'+scenario+'.receipt','scenarioId':scenario,'correlationId':cid,
                     'result':'failed' if failure else 'passed','frames':100,'mode':'refresh-only',
                     'preflight':{'ready':True},'actualError':{'code':'ACTUAL-FAILURE','stderr':'private actual error'},
                     'allActualCases':[{'result':'passed'},{'result':'failed','actual':'kept'}],
                     'cleanup':{'state':'complete','ownerStopped':True,'workspaceRemoved':True,
                                'protectedPreserved':True,'referencesAbsent':True}}
            if large:receipt['actualOversizedData']='z'*8192
            for name,value in [('intent.json',intent),('receipt.json',wrapper),('scenario-receipt.json',receipt)]:
                path=job/name;path.write_text(json.dumps(value));path.chmod(0o600)
            saved=(job/'scenario-receipt.json').read_bytes();digest=hashlib.sha256(saved).hexdigest()
            child=subprocess.run([sys.executable,'-I','-B','-c',module._COLLECT,str(root),'guest','owned',scenario,cid,'a'*64,
                                  json.dumps(binding['artifactIds']),'101','202'],capture_output=True,timeout=5,check=True)
            self.assertLessEqual(len(child.stdout),8192)
            value=json.loads(child.stdout)
            self.assertEqual(digest,hashlib.sha256((job/'scenario-receipt.json').read_bytes()).hexdigest())
            return value,receipt
    def test_actual_scheduled_first_payload_retains_all_error_and_case_results(self):
        value,receipt=self.run_collector(scheduled,failure=True)
        self.assertEqual('collected',value['state'])
        self.assertEqual(receipt,json.loads(value.get('actualReceiptRaw',json.dumps(value))))
        self.assertEqual(3,value['exitCode'])
    def test_actual_gui_first_payload_retains_all_error_and_case_results(self):
        value,receipt=self.run_collector(gui,failure=True)
        self.assertEqual('collected',value['state'])
        self.assertEqual(receipt,json.loads(value.get('actualReceiptRaw',json.dumps(value))))
        self.assertEqual(3,value['exitCode'])
    def test_actual_collector_overflow_is_partial_unknown_original_is_retained(self):
        for module in (scheduled,gui):
            with self.subTest(scenario=module.SCENARIO_ID):
                value,receipt=self.run_collector(module,large=True)
                self.assertEqual('unknown',value['state'])
                self.assertTrue(value['partial'])
                self.assertTrue(value['originalRetained'])
                self.assertEqual('collector_output_limit',value['reason'])
                self.assertNotIn('actualReceiptRaw',value)
                self.assertRegex(value['originalReceiptSha256'],r'^[0-9a-f]{64}$')

    def test_actual_collectors_refuse_float_or_boolean_actor_identity(self):
        for module in (scheduled,gui):
            for actor in (float,bool):
                with self.subTest(scenario=module.SCENARIO_ID,actor=actor):
                    value,_=self.run_collector(module,actor_type=actor)
                    self.assertEqual('unknown',value['state'])
                    self.assertNotIn('actualReceiptRaw',value)
