"""Generated large-response tests with harmless local children only."""
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
from agent_tools import android_api35_large_routing_observation as large
from agent_tools.tests import test_android_api35_coldboot_product_observation as originals

ROOT=Path(__file__).resolve().parents[2]


def scope():
    overridden={'getter_bounded','getter_cli','current_getter','observed_getter'}
    nodes=[n for n in ast.parse(large.original._GETTER).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))and getattr(n,'name',None)not in overridden]
    nodes += [n for n in ast.parse(large._OBSERVER).body if isinstance(n,ast.FunctionDef)]
    env=dict(os=os,time=time,subprocess=subprocess,pathlib=__import__('pathlib'),re=re,json=json,hashlib=hashlib,LARGE_OWNER=large.OWNER,LARGE_PHASE='routingBefore',LARGE_PUBLIC_SECONDS=300,LARGE_OUTER_SECONDS=.5,LARGE_OUTPUT_LIMIT=33554432,GETTER_RECORDS={},GETTER={'cli':'/fixed/cli','packageSha256':large.original.APK})
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-large-routing>','exec'),env);return env


def envelope(timestamp='2026-01-01T00:00:00Z'):
    return {'schemaVersion':1,'controllerId':large.OWNER,'requestId':'123','configurationRevision':0,'code':'OK','ok':True,'final':True,'data':{'routing':{'type':'vpn_control_routing_rules','version':7,'exported_at':timestamp,'rules':{'ignore_rules':False,'block_quic_udp_443':False,'proxy_packages':[],'direct_domain_suffixes':['example.test']}}}}


class LargeTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        install(self,globals(),'large')

    def argv(self):return ['/fixed/cli','--json','--android','--serial','emulator-5682','--timeout-seconds','300','--controller-id',large.OWNER,'routing','show']
    def launch(self,code):
        original=subprocess.Popen
        def run(*a,**kw):return original([sys.executable,'-I','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        return run

    def test_actual_short_budget_red_then_large_collects_finite_response(self):
        code="import time;time.sleep(.12);print('{\"code\":\"OK\"}')"
        env=scope();old=next(n for n in ast.parse(large.original._GETTER).body if isinstance(n,ast.FunctionDef)and n.name=='getter_bounded')
        exec(compile(ast.Module(body=[old],type_ignores=[]),'<old-budget>','exec'),env)
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)),self.assertRaisesRegex(ValueError,'getter_command_timeout'):env['getter_bounded'](self.argv(),1,{},timeout=.04,limit=8388608)
        env=scope()
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)):value=env['getter_bounded'](self.argv(),1,{},timeout=.04,limit=33554432)
        self.assertEqual({'code':'OK'},json.loads(value['stdoutRaw']))
        self.assertEqual(300,env['GETTER_RECORDS']['routingBefore']['publicTimeoutSeconds'])

    def test_actual_8MiB_clipping_red_then_full_chunked_payload_green(self):
        code="import sys;sys.stdout.buffer.write(b'x'*9000000)"
        env=scope();old=next(n for n in ast.parse(large.original._GETTER).body if isinstance(n,ast.FunctionDef)and n.name=='getter_bounded')
        exec(compile(ast.Module(body=[old],type_ignores=[]),'<old-cap>','exec'),env)
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)),self.assertRaisesRegex(ValueError,'getter_command_output_limit'):env['getter_bounded'](self.argv(),1,{},timeout=3,limit=8388608)
        env=scope();env['LARGE_OUTER_SECONDS']=3
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch(code)):result=env['getter_bounded'](self.argv(),1,{},limit=33554432)
        receipt=env['GETTER_RECORDS']['routingBefore']['stdout'];raw=b''.join(base64.b64decode(c)for c in receipt['chunks'])
        self.assertEqual(9000000,len(raw));self.assertEqual(result['stdoutRaw'].encode(),raw);self.assertEqual(hashlib.sha256(raw).hexdigest(),receipt['sha256'])
        self.assertNotIn('stdoutRaw',env['GETTER_RECORDS']['routingBefore']);self.assertNotIn('lastBoundedCommand',env['GETTER_RECORDS'])

    def test_actual_new_limit_and_partial_invalid_utf8_are_bounded_exact(self):
        env=scope();env['LARGE_OUTPUT_LIMIT']=1024
        with mock.patch.object(subprocess,'Popen',side_effect=self.launch("import sys;sys.stdout.buffer.write(b'\\xff'*2048)")),self.assertRaisesRegex(ValueError,'getter_command_output_limit'):
            env['getter_bounded'](self.argv(),1,{},limit=1024)
        raw=env['GETTER_RECORDS']['routingBefore']['stdout'];self.assertEqual(1025,raw['bytes']);self.assertEqual(b'\xff'*1025,b''.join(base64.b64decode(c)for c in raw['chunks']))

    def test_exported_timestamp_false_negative_red_then_only_timestamp_excluded(self):
        env=scope();a=envelope();b=envelope('2026-01-01T00:00:01Z')
        self.assertNotEqual(a['data']['routing'],b['data']['routing'])
        self.assertEqual(env['large_semantic'](a),env['large_semantic'](b))
        for change in ('type','version','rules','extra','nestedtime'):
            changed=copy.deepcopy(b)
            if change=='type':changed['data']['routing']['type']='foreign'
            elif change=='version':changed['data']['routing']['version']=True
            elif change=='rules':changed['data']['routing']['rules']['direct_domain_suffixes'].append('foreign.test')
            elif change=='extra':changed['data']['routing']['extra']=1
            else:changed['data']['routing']['rules']['exported_at']='foreign'
            try:self.assertNotEqual(env['large_semantic'](a),env['large_semantic'](changed))
            except ValueError:pass

    def test_fixed_routing_command_rejects_before_launch(self):
        for index,value in ((0,'/foreign'),(4,'oldserial'),(6,'30'),(8,'foreign')):
            env=scope();args=self.argv();args[index]=value
            with mock.patch.object(subprocess,'Popen')as launch,self.assertRaises(ValueError):env['getter_bounded'](args,1,{},limit=33554432)
            launch.assert_not_called()

    def guarded(self):
        env=scope();calls=[];env['getter_generation']=lambda _:calls.append('generation');env['getter_stage']=lambda:{'source':'pinned'};env['getter_apk']=lambda:large.original.APK
        def cli(words,owner):
            calls.append(tuple(words));value=envelope()
            if words!=['routing','show']:value['data']={'runtimeRunning':False,'runtimeObservation':'stopped','operations':[]}
            else:
                value['data']['routing']['exported_at']=str(calls.count(('routing','show')))
                env['GETTER_RECORDS'][env['LARGE_PHASE']]={'stdout':env['large_chunks'](json.dumps(value).encode()),'stderr':env['large_chunks'](b'')}
            return {'returncode':0,'stdout':value,'stdoutRaw':json.dumps(value),'stderrRaw':''}
        env['getter_cli']=cli;return env,calls

    def test_two_current_reads_semantic_equal_chunks_once_no_acceptance(self):
        env,calls=self.guarded();result=env['observed_getter'](Path('/fixed'))
        self.assertTrue(result['currentRoutingVerified']);self.assertIs(result['productAdmitted'],False);self.assertIs(result['acceptanceComplete'],False);self.assertEqual(2,calls.count(('routing','show')))
        for phase in ('routingBefore','routingAfter'):
            record=result['records'][phase];self.assertNotIn('stdoutRaw',record);self.assertNotIn('data',record['envelope']);self.assertIn('semanticSha256',record)
        self.assertEqual(result['records']['routingBefore']['semanticSha256'],result['records']['routingAfter']['semanticSha256'])

    def test_source_generation_owner_revision_rules_off_operations_stage_drift(self):
        for kind in ('generation','owner','revision','rules','runtime','operations','stage','apk','timeout'):
            env,calls=self.guarded();original=env['getter_cli']
            def cli(words,owner):
                record=original(words,owner)
                if kind=='owner':record['stdout']['controllerId']='foreign'
                if kind=='revision':record['stdout']['configurationRevision']=1
                if kind=='runtime':record['stdout']['data']['runtimeRunning']=True
                if kind=='operations':record['stdout']['data']['operations']=[{'final':False}]
                if kind=='rules' and words==['routing','show']and calls.count(('routing','show'))==2:record['stdout']['data']['routing']['rules']['ignore_rules']=True
                if kind=='timeout'and words==['routing','show']:record['stdout']['code']='TIMEOUT';record['stdout']['final']=False
                return record
            env['getter_cli']=cli
            if kind=='generation':env['getter_generation']=lambda _:(_ for _ in ()).throw(ValueError('getter_generation_changed'))
            if kind=='stage':rows=iter([{'a':1},{'a':2}]);env['getter_stage']=lambda:next(rows)
            if kind=='apk':env['getter_apk']=lambda:'f'*64
            result=env['observed_getter'](Path('/fixed'));self.assertFalse(result['currentRoutingVerified']);self.assertFalse(result['productAdmitted'])

    def test_fixed_local_composition_and_consumed_source_drift(self):
        self.assertTrue((ROOT/'.runtime/parity-evidence'/large.original.STATUS).exists(),'owned synthetic historical fixture is incomplete')
        reservation=originals.CompositionTests().reservation();prepared=large.prepare(ROOT,reservation)
        large.original.validate_readonly(prepared['program']);self.assertLess(len(large.ssh_carrier(prepared)),131072)
        self.assertIn('LARGE_PUBLIC_SECONDS=300',prepared['program']);self.assertIn('LARGE_OUTER_SECONDS=330',prepared['program']);self.assertNotIn('def current_getter(',prepared['program'])
        original=large.availability._snapshot
        def changed(path):
            pin,raw=original(path);return pin,raw+b' ' if Path(path)==Path(large.original.__file__).absolute()else raw
        with mock.patch.object(large.availability,'_snapshot',side_effect=changed),self.assertRaises(ValueError):large.prepare(ROOT,reservation)


if __name__=='__main__':unittest.main()
