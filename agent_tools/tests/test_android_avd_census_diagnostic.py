"""Routine causal diagnostics for opaque failed privileged census reads."""
import ast
import os
from pathlib import Path
import tempfile
import unittest
from agent_tools import android_avd_census_diagnostic as diagnostic
from agent_tools import android_avd_launch_recovery as census

class CensusDiagnosticTests(unittest.TestCase):
    def scope(self):
        old=ast.parse(census._CENSUS).body
        old=[n for n in old if not isinstance(n,ast.Expr) and not (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='CFG' for t in n.targets)) and not (isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ROOT' for t in n.targets))]
        scope={'CFG':{},'ROOT':Path('/fixed'),'PROC':Path('/proc')};exec(compile(ast.Module(body=old,type_ignores=[]),'<frozen-census-prefix>','exec'),scope)
        exec(diagnostic._TRACE,scope);return scope
    def test_actual_frozen_symlink_ancestry_failure_gets_finite_phase(self):
        scope=self.scope()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();target=root/'target';target.mkdir();(target/'disk').write_bytes(b'disk');route=root/'route';route.symlink_to(target,target_is_directory=True)
            scope['TAGS'][str(route/'disk')]='api29-sdk-file';scope['guard_proof']=lambda _:None;scope['metadata']=lambda _:scope['read_fixed'](route/'disk',4)
            with self.assertRaises(OSError):scope['_saved_observe']({})
            result=scope['observe']({})
            self.assertEqual('api29-sdk-file',result['phase']);self.assertEqual('parent_fds',result['reader']);self.assertIn(result['reason'],('not-directory','symlink-loop'));self.assertTrue(any(x['kind']=='symlink' for x in result['ancestry']))
            self.assertNotIn(str(root),str(result))
    def test_unsupported_os_error_is_finite_and_drops_raw_message(self):
        scope=self.scope();scope['_saved_observe']=lambda _:(_ for _ in ()).throw(OSError('private path or secret'))
        result=scope['observe']({});self.assertEqual('os-error',result['reason']);self.assertNotIn('private',str(result))
    def test_each_pass_keeps_independent_failure(self):
        scope=self.scope();scope['_saved_observe']=lambda _:(_ for _ in ()).throw(ValueError('census_host_boot_changed'))
        a=scope['observe']({});scope['_saved_observe']=lambda _:(_ for _ in ()).throw(PermissionError('private'))
        b=scope['observe']({});self.assertEqual('census_host_boot_changed',a['reason']);self.assertEqual('permission-denied',b['reason'])
    def test_shared_emulator_phase_is_identified_without_raw_paths(self):
        scope=self.scope();common='/known/sdk/emulator/emulator'
        avds={alias:{'avdDirectory':{'path':'/owned/'+alias+'.avd'},'historicalSelection':{'avd':alias},'inventory':{},'sdkFiles':{common:{}}} for alias in ('api29','api35')}
        scope['_saved_observe']=lambda _:scope['read_fixed'](Path(common),4)
        result=scope['observe']({'observations':[{'avds':avds}]})
        self.assertEqual('shared-sdk-emulator',result['phase']);self.assertNotIn(common,str(result))
