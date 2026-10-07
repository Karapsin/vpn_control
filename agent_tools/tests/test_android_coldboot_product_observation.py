"""Actual composed read-only getter regressions; no device operations."""
import ast, copy, types, unittest
from unittest import mock
from pathlib import Path
from agent_tools import android_coldboot_product_observation as getter

class GetterTests(unittest.TestCase):
    def scope(self):
        nodes=[n for n in ast.parse(getter._GETTER).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        scope={'re':__import__('re')};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-generation-getter>','exec'),scope)
        scope['GETTER']={'generation':{'child':{'pid':1396687,'startTicks':2921953},'guest':{'pid':1396692,'sessionId':1396687,'exeGeneration':[1]},'device':{'guestBootId':'174ee7f3-eb89-441d-a045-f6155921651d'}},'packageSha256':'source-apk'}
        scope['original_status']=lambda _:dict(state='guest-generation-admitted',guestAdmitted=True,**copy.deepcopy(scope['GETTER']['generation']))
        scope['getter_apk']=lambda:'source-apk'
        scope['getter_cli']=lambda words,owner=None:{'returncode':0,'stdout':{'ok':True,'final':True,'code':'OK','controllerId':'new-owner','configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','operations':[],'routing':{}}}}
        return scope
    def test_actual_getter_admits_new_generation_without_old_owner_lease_replay(self):
        result=self.scope()['current_getter'](Path('/fixed'))
        self.assertTrue(result['productAdmitted']);self.assertTrue(result['historicalUnknownsPreserved']);self.assertEqual('new-owner',result['controllerId'])
    def test_new_guest_boot_with_old_lease_rejects_before_public_getter(self):
        scope=self.scope();scope['original_status']=lambda _:dict(state='guest-generation-admitted',guestAdmitted=True,**{**copy.deepcopy(scope['GETTER']['generation']),'device':{'guestBootId':'another-boot'}})
        scope['getter_cli']=lambda *args:(_ for _ in ()).throw(AssertionError('unexpected getter'))
        with self.assertRaisesRegex(ValueError,'getter_generation_changed'):scope['current_getter'](Path('/fixed'))
    def test_pid_sid_and_binary_generation_drift_reject(self):
        for field,value in [('pid',999),('sessionId',999),('exeGeneration',[2])]:
            scope=self.scope();changed=copy.deepcopy(scope['GETTER']['generation']);changed['guest'][field]=value;scope['original_status']=lambda _:dict(state='guest-generation-admitted',guestAdmitted=True,**changed)
            with self.assertRaisesRegex(ValueError,'getter_generation_changed'):scope['current_getter'](Path('/fixed'))
    def test_apk_drift_rejects_before_getters(self):
        scope=self.scope();scope['getter_apk']=lambda:'foreign-apk'
        with self.assertRaisesRegex(ValueError,'getter_package_changed'):scope['current_getter'](Path('/fixed'))
    def test_controller_drift_between_getters_rejects(self):
        scope=self.scope();original=scope['getter_cli'];calls=[]
        def invoke(words,owner=None):
            result=original(words,owner);calls.append(words)
            if len(calls)==2:result['stdout']['controllerId']='changed'
            return result
        scope['getter_cli']=invoke
        with self.assertRaisesRegex(ValueError,'getter_owner_changed'):scope['current_getter'](Path('/fixed'))
    def test_absent_provider_is_diagnostic_not_product_admission(self):
        scope=self.scope();scope['getter_cli']=lambda *args:{'returncode':1,'stdout':{'ok':False,'code':'NOT_RUNNING','final':True}}
        result=scope['current_getter'](Path('/fixed'));self.assertFalse(result['productAdmitted']);self.assertEqual('diagnostic-only',result['state'])

    def test_actual_cli_allows_only_fixed_read_commands_and_pins_owner(self):
        scope=self.scope();scope['GETTER'].update(cli='/fixed/cli',manifest={'launcherSha256':'fixed-sha'})
        node=next(node for node in ast.parse(getter._GETTER).body if isinstance(node,ast.FunctionDef) and node.name=='getter_cli');exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual-cli-reader>','exec'),scope)
        scope['LAUNCH']={'adbPath':'/fixed/adb','environment':{'HOME':'/home/kardinal'}}
        scope['pathlib']=__import__('pathlib');scope['json']=__import__('json');scope['read_fixed']=lambda *args:{'raw':b'cli','hashScope':'full','sha256':'fixed-sha','generation':[1]}
        calls=[];scope['public_cli_environment']=lambda adb,cli,env:env
        scope['getter_binary']=lambda path,pin,args,env,limit: calls.append((args,env)) or {'returncode':0,'stdoutRaw':'{}'}
        scope['getter_cli'](['routing','show'],'new-owner')
        self.assertIn('--controller-id',calls[0][0]);self.assertIn('new-owner',calls[0][0]);self.assertEqual(['routing','show'],calls[0][0][-2:])
        with self.assertRaisesRegex(ValueError,'getter_readonly_command_required'):scope['getter_cli'](['updates','check'])
        self.assertEqual(1,len(calls))
    def test_actual_stage_drift_after_getters_rejects_without_promotion(self):
        scope=self.scope();values=iter([{'generation':[1]},{'generation':[2]}]);scope['getter_stage']=lambda:next(values)
        result=scope['observed_getter'](Path('/fixed'));self.assertEqual('getter_stage_generation_changed',result['reason']);self.assertFalse(result['productAdmitted']);self.assertEqual(4,len(result['records']))
    def test_actual_guest_generation_drift_after_public_reads_rejects(self):
        scope=self.scope();original=scope['original_status'];calls=[]
        def status(path):
            value=original(path);calls.append(path)
            if len(calls)==2:value['guest']['sessionId']=999
            return value
        scope['original_status']=status
        with self.assertRaisesRegex(ValueError,'getter_generation_changed'):scope['current_getter'](Path('/fixed'))
