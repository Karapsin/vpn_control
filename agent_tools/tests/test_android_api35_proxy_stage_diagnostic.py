"""Read-only diagnostic evidence tests; hypothesis is not native cause proof."""
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_api35_proxy_stage_diagnostic as diagnostic
from agent_tools.tests import test_android_api35_current_proxy_probe as prior
from agent_tools.tests import test_android_api35_coldboot_product_observation as original_tests
ROOT=Path(__file__).resolve().parents[2]
HISTORICAL_SOURCE = Path(__file__).parent / 'fixtures/android_api35_proxy_probe_initial.py'
HISTORICAL_SHA = 'bff6eac22e615e15e895324810c00be3fe64d62fefc5ad7f78b00d14cd745e52'
if diagnostic.SOURCE_SHA != HISTORICAL_SHA or hashlib.sha256(HISTORICAL_SOURCE.read_bytes()).hexdigest() != HISTORICAL_SHA:
    raise AssertionError('Historical probe source fixture changed')
_spec = importlib.util.spec_from_file_location('agent_tools._test_api35_initial_proxy_probe', HISTORICAL_SOURCE)
historical_probe = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(historical_probe)


def scope():
    env,calls=prior.scope();env['PROBE']['correlationId']=diagnostic.CORRELATION
    exec(diagnostic._OBSERVER.replace('__RETAINED__',repr({'stageFence':{},'resultSha256':diagnostic.RESULT_SHA})),env)
    env['probe_fence_guard']=lambda *args:None
    return env,calls


def ledger(kind='regular empty file',size=0):
    parent='1|2|4096|mtime|ctime|700|2000|2000|2|directory';leaf=f'1|3|{size}|mtime|ctime|600|2000|2000|1|{kind}'
    return ('\n'.join(['uid:2000','parent:'+parent,'file:'+leaf,'fd4:'+leaf,'empty-predicate:600|2000|1|'+str(size)+'|'+kind,'sha256:'+hashlib.sha256(b'').hexdigest()+'  /proc/self/fd/4','parent-after:'+parent,'file-after:'+leaf,'fd4-after:'+leaf])+'\n').encode()


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        install(self,globals(),'diagnostic')
        patch=mock.patch.object(prior,'probe',diagnostic.consumed)
        patch.start();self.addCleanup(patch.stop)
    def test_real_empty_fd_generated_legacy_guard_red_and_diagnostic_retains(self):
        env,_=scope();command=env['probe_stage_command']();needle="test \"$(/system/bin/stat -Lc '%a|%u|%h|%s|%F' /proc/self/fd/4 4>&4)\" = '600|2000|1|0|regular file'"
        self.assertIn(needle,command)
        # A real OS fstat/exec supplies empty-file size/nlink; the inert formatter
        # deliberately models the hypothesis's GNU-compatible %F spelling. This
        # tests the old exact guard, and is NOT actual Toybox/device evidence.
        child="import os,sys;s=os.fstat(4);print('600|2000|%d|%d|%s'%(s.st_nlink,s.st_size,'regular empty file' if s.st_size==0 else 'regular file'))"
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'empty';path.touch(mode=0o600);saved=None
            try:saved=os.dup(4)
            except OSError:pass
            opened=os.open(path,os.O_RDONLY)
            try:
                os.dup2(opened,4,inheritable=False)
                bad=subprocess.run([sys.executable,'-I','-c',child],close_fds=False,capture_output=True);self.assertNotEqual(0,bad.returncode)
                os.set_inheritable(4,True);value=subprocess.run([sys.executable,'-I','-c',child],close_fds=False,capture_output=True);self.assertEqual(0,value.returncode)
                self.assertEqual(b'600|2000|1|0|regular empty file\n',value.stdout)
                # Execute actual legacy equality predicate with the measured
                # fixture result, preserving the historical source unchanged.
                guard=needle.replace('$(/system/bin/stat -Lc \'%a|%u|%h|%s|%F\' /proc/self/fd/4 4>&4)',"$(printf '600|2000|1|0|regular empty file')")
                self.assertNotEqual(0,subprocess.run(['sh','-c',guard],capture_output=True).returncode)
            finally:
                if saved is not None:os.dup2(saved,4);os.close(saved)
                else:os.close(4)
                if opened!=4:os.close(opened)
        result=env['diagnostic_parse'](prior.reply(ledger()));self.assertFalse(result['legacyEmptyPredicateMatches']);self.assertEqual('regular empty file',result['type']);self.assertEqual(0,result['size'])
    def test_current_predicates_unknown_not_original_completion(self):
        env,_=scope()
        for kind,match in (('regular file',True),('regular empty file',False)):
            env['diagnostic_read']=lambda _:prior.reply(ledger(kind))
            result=env['observed_getter'](Path('/inert'));self.assertEqual('diagnostic-only',result['state']);self.assertTrue(result['closingGuardsVerified']);self.assertEqual(match,result['observations'][0]['legacyEmptyPredicateMatches']);self.assertEqual('unknown',result['originalOutcome']);self.assertFalse(result['stageMutationPerformed']);self.assertFalse(result['appProcessExecuted'])
    def test_path_missing_symlink_inaccessible_and_generation_change(self):
        env,_=scope()
        for blocked in ('parent-symlink','parent-absent','file-symlink','file-absent','file-inaccessible'):
            self.assertEqual(blocked,env['diagnostic_parse'](prior.reply(('uid:2000\nblocked:'+blocked+'\n').encode()))['blocked'])
        changed=ledger().replace(b'file:1|3|0',b'file:1|4|0',1)
        with self.assertRaisesRegex(ValueError,'diagnostic_stage_changed'):env['diagnostic_parse'](prior.reply(changed))
        for raw in (b'uid:2000\nuid:2000\n',b'unknown:x\n'):
            with self.assertRaises(ValueError):env['diagnostic_parse'](prior.reply(raw))
    def test_failure_closes_and_current_owner_drift_never_promotes(self):
        env,calls=scope();env['diagnostic_read']=lambda _:(_ for _ in ()).throw(ValueError('probe_command_unknown'))
        result=env['observed_getter'](Path('/inert'));self.assertTrue(result['closingGuardsVerified']);self.assertEqual([],result['observations']);self.assertEqual(2,calls.count('generation'))
        env,calls=scope();env['diagnostic_read']=lambda _:prior.reply(ledger());original=env['getter_cli']
        def drift(words,owner):
            value=original(words,owner)
            if len(calls)>3:value['stdout']['controllerId']='foreign'
            return value
        env['getter_cli']=drift;result=env['observed_getter'](Path('/inert'));self.assertFalse(result['closingGuardsVerified']);self.assertFalse(result['productAdmitted'])
    def test_fixed_script_readonly_only_original_path(self):
        env,_=scope();command=env['diagnostic_command']()
        self.assertIn('/data/local/tmp/vpn-control-os-proxy-'+diagnostic.CORRELATION+'/classes.dex',command)
        self.assertIn('exec 4<',command);self.assertNotIn('exec 4>',command)
        for forbidden in ('mkdir','chmod','base64','app_process','settings','rm ','su '):self.assertNotIn(forbidden,command)
        for part in command.split(';'):
            if '/proc/self/fd/4' in part:self.assertTrue(part.strip().endswith('4>&4'))
    def test_actual_composed_prefix_tail_single_json_and_closed_source_pins(self):
        self.assertTrue((ROOT/'.runtime/parity-evidence'/diagnostic.CAPSULE).exists(),'owned synthetic historical fixture is incomplete')
        prepared=diagnostic.prepare(ROOT,original_tests.CompositionTests().reservation());tree=ast.parse(prepared['program']);diagnostic.consumed.admission.original.validate_readonly(prepared['program']);emitted=[]
        for index in range(len(tree.body)-1,-1,-1):
            text=ast.unparse(tree.body[index])
            if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
            elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
        tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0])
        pin=[1]*9;rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700);lockinfo=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1)
        class Directory:
            name='inert-original'
            def lstat(self):return types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
        class Root:
            def __truediv__(self,_):return Directory()
        def install(ns):
            env,_=scope();proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *a,**k:8;proxy.close=lambda _:None;proxy.fstat=lambda fd:rootinfo if fd==7 else lockinfo;proxy.stat=lambda *a,**k:lockinfo
            ns.update({k:env[k] for k in ('getter_stage','getter_generation','getter_apk','getter_cli','getter_envelope')});ns.update(ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=lambda _:None,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *args:ns['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *args:None),probe_fence_guard=lambda *args:None,diagnostic_read=lambda _:prior.reply(ledger()),print=lambda line:emitted.append(json.loads(line)))
        bindings={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *args:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
        exec(compile(ast.fix_missing_locations(tree),'<exact-readonly-diagnostic-program>','exec'),bindings);self.assertEqual(1,len(emitted));self.assertTrue(emitted[0]['closingGuardsVerified']);self.assertFalse(emitted[0]['observations'][0]['legacyEmptyPredicateMatches'])
        source=diagnostic.availability._snapshot
        def drift(path):
            pin,raw=source(path);return pin,raw+b'\n' if Path(path)==Path(diagnostic.consumed.__file__).absolute() else raw
        with mock.patch.object(diagnostic.availability,'_snapshot',side_effect=drift),mock.patch.object(diagnostic.consumed,'prepare') as factory:
            with self.assertRaises(ValueError):diagnostic.prepare(ROOT,original_tests.CompositionTests().reservation())
            factory.assert_not_called()


class CurrentDependencyTests(unittest.TestCase):
    def test_current_dependency_rejected_before_prepare_factory(self):
        current = diagnostic.consumed
        self.assertNotEqual(diagnostic.SOURCE_SHA, hashlib.sha256(Path(current.__file__).read_bytes()).hexdigest())
        with mock.patch.object(current, 'prepare') as factory:
            with self.assertRaisesRegex(ValueError, 'diagnostic_consumed_source_changed'):
                diagnostic.prepare(ROOT, original_tests.CompositionTests().reservation())
            factory.assert_not_called()
