"""Fixed generated diagnostic, harmless process tests only; no native actions."""
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import unittest
from unittest import mock
from agent_tools import android_api35_routing_step_diagnostic as diag
from agent_tools.tests import test_android_api35_coldboot_product_observation as original_tests

ROOT=Path(__file__).resolve().parents[2]


def scope():
    nodes=[n for n in ast.parse(diag.original._GETTER).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))and getattr(n,'name',None)not in {'getter_bounded','current_getter','observed_getter'}]
    nodes += [n for n in ast.parse(diag._MEASUREMENT).body if isinstance(n,ast.FunctionDef)]
    env=dict(os=os,time=time,subprocess=subprocess,pathlib=__import__('pathlib'),re=re,json=json,hashlib=hashlib,__PRIOR_SHA__=diag.PRIOR_SHA,ROUTING_OWNER=diag.OWNER,ROUTING_OUTER_SECONDS=.5,GETTER_RECORDS={},GETTER={'cli':'/fixed/cli','packageSha256':diag.original.APK})
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-routing-measurement>','exec'),env)
    return env


class RoutingTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        install(self,globals(),'diag')

    def argv(self):return ['/fixed/cli','--json','--android','--serial','emulator-5682','--timeout-seconds','30','--controller-id',diag.OWNER,'routing','show']

    def launch(self,code):
        original=subprocess.Popen
        def run(*a,**kw):return original([sys.executable,'-I','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return run

    def test_actual_old_outer_deadline_loses_finite_inner_timeout_new_retains(self):
        # Scaled startup .08 + inner .08 requires >.10 outer. The public
        # deadline starts after launcher startup, so equal budgets lose it.
        code="import time;time.sleep(.08);time.sleep(.08);print('{\"code\":\"TIMEOUT\"}')"
        env=scope();old=next(n for n in ast.parse(diag.original._GETTER).body if isinstance(n,ast.FunctionDef)and n.name=='getter_bounded')
        exec(compile(ast.Module(body=[old],type_ignores=[]),'<consumed-outer-deadline>','exec'),env)
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)),self.assertRaisesRegex(ValueError,'getter_command_timeout'):env['getter_bounded'](self.argv(),1,{},timeout=.10)
        self.assertEqual('',env['GETTER_RECORDS']['lastBoundedCommand']['stdoutRaw'])
        env=scope();env['ROUTING_OUTER_SECONDS']=.3
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)):
            result=env['getter_bounded'](self.argv(),1,{},timeout=.10)
        self.assertEqual({'code':'TIMEOUT'},json.loads(result['stdoutRaw']))
        self.assertEqual('terminal_collected',env['GETTER_RECORDS']['routingMeasurement']['classification'])
        self.assertTrue(env['GETTER_RECORDS']['routingMeasurement']['stdoutEof'])

    def test_live_child_and_exact_partial_bytes_retained_before_owned_kill(self):
        env=scope();env['ROUTING_OUTER_SECONDS']=.05
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch("import sys,time;sys.stderr.buffer.write(b'notice\\xff');sys.stderr.flush();time.sleep(3)")),self.assertRaisesRegex(ValueError,'getter_command_timeout'):
            env['getter_bounded'](self.argv(),1,{})
        record=env['GETTER_RECORDS']['routingPartial'];self.assertEqual(b'notice\xff',base64.b64decode(record['stderrBase64']))
        measurement=env['GETTER_RECORDS']['routingMeasurement'];self.assertEqual('child_live_at_outer_deadline',measurement['classification']);self.assertIsNone(measurement['exitCode']);self.assertFalse(measurement['stdoutEof'])

    def test_exited_parent_with_descendant_held_pipe_is_distinct(self):
        env=scope();env['ROUTING_OUTER_SECONDS']=.05
        # A harmless short-lived descendant holds stdout; no persistent job.
        code="import subprocess,sys;subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(.12)'])"
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)),self.assertRaises(ValueError):env['getter_bounded'](self.argv(),1,{})
        self.assertEqual('child_exited_pipe_open',env['GETTER_RECORDS']['routingMeasurement']['classification'])

    def test_routing_source_serial_owner_or_timeout_change_before_process(self):
        for index,value in ((0,'/foreign'),(4,'old-serial'),(6,'45'),(8,'foreign')):
            args=self.argv();args[index]=value;env=scope()
            with mock.patch.object(subprocess,'Popen')as launch,self.assertRaises(ValueError):env['getter_bounded'](args,1,{})
            launch.assert_not_called()

    def guarded(self):
        env=scope();calls=[]
        env['getter_stage']=lambda:{'exact':'stage'};env['getter_generation']=lambda _:calls.append('generation')
        env['getter_apk']=lambda:diag.original.APK
        def cli(words,owner):
            calls.append(tuple(words));return {'returncode':0,'stdout':{'ok':True,'final':True,'code':'OK','controllerId':diag.OWNER,'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','operations':[],'routing':{}}}}
        env['getter_cli']=cli;return env,calls

    def test_one_routing_only_closing_guards_diagnostic_no_admission(self):
        env,calls=self.guarded();result=env['observed_getter'](Path('/fixed'))
        self.assertEqual(1,calls.count(('routing','show')));self.assertTrue(result['closingGuardsVerified']);self.assertIs(result['productAdmitted'],False);self.assertIs(result['acceptanceComplete'],False)
        self.assertNotIn('routingAfter',result['records'])

    def test_timeout_keeps_measurement_and_closes_guards_no_replay(self):
        env,calls=self.guarded();original=env['getter_cli']
        def cli(words,owner):
            if words==['routing','show']:
                calls.append(tuple(words));env['GETTER_RECORDS']['routingPartial']={'stdoutBase64':'','stderrBase64':''};raise ValueError('getter_command_timeout')
            return original(words,owner)
        env['getter_cli']=cli;result=env['observed_getter'](Path('/fixed'))
        self.assertTrue(result['closingGuardsVerified']);self.assertIn('routingPartial',result['records']);self.assertEqual(1,calls.count(('routing','show')))

    def test_owner_revision_runtime_operations_apk_stage_closing_drift(self):
        for mutation in ('owner','revision','runtime','operations','apk','stage','generation'):
            env,calls=self.guarded();original=env['getter_cli']
            def cli(words,owner):
                value=original(words,owner)
                if mutation=='owner':value['stdout']['controllerId']='foreign'
                if mutation=='revision':value['stdout']['configurationRevision']=1
                if mutation=='runtime':value['stdout']['data']['runtimeRunning']=True
                if mutation=='operations':value['stdout']['data']['operations']=[{'final':True}]
                return value
            env['getter_cli']=cli
            if mutation=='apk':env['getter_apk']=lambda:'f'*64
            if mutation=='stage':rows=iter([{'a':1},{'a':2}]);env['getter_stage']=lambda:next(rows)
            if mutation=='generation':env['getter_generation']=lambda _:(_ for _ in ()).throw(ValueError('getter_generation_changed'))
            result=env['observed_getter'](Path('/fixed'));self.assertFalse(result['closingGuardsVerified']);self.assertIs(result['productAdmitted'],False)
            if mutation not in ('stage',):self.assertNotIn(('routing','show'),calls)

    def test_current_private_original_composition_and_authority_mutations(self):
        self.assertTrue((ROOT/diag.PRIOR).exists(),'owned synthetic historical fixture is incomplete')
        reservation=original_tests.CompositionTests().reservation();prepared=diag.prepare(ROOT,reservation)
        diag.original.validate_readonly(prepared['program']);self.assertLess(len(diag.ssh_carrier(prepared)),131072)
        self.assertNotIn('def current_getter(',prepared['program']);self.assertIn('ROUTING_OUTER_SECONDS=45',prepared['program'])
        original=diag.availability._snapshot
        for path in (Path(diag.original.__file__).absolute(),ROOT/diag.PRIOR):
            def changed(candidate):
                pin,raw=original(candidate);return pin,raw+b' ' if Path(candidate)==path else raw
            with mock.patch.object(diag.availability,'_snapshot',side_effect=changed),self.assertRaises(ValueError):diag.prepare(ROOT,reservation)


if __name__=='__main__':unittest.main()
