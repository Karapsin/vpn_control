"""Inert current-generation census tests, with real OS FD consumers."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_api35_current_proxy_dex_observation as dex
from agent_tools.tests import test_android_api35_coldboot_fd_observation as fd_tests
from agent_tools.tests import test_android_shell_fd_probe as shell_tests
from agent_tools.tests import test_android_api35_coldboot_product_observation as original_tests
ROOT=Path(__file__).resolve().parents[2]


def scope():
    env,calls=fd_tests.CurrentFdTests().guarded()
    exec(dex._OBSERVER.replace('__DEX_SHA__',repr(dex.DEX_SHA)),env)
    return env,calls


def report(size=4948,digest=None):
    digest=dex.DEX_SHA if digest is None else digest
    parent='1|2|4096|mtime|ctime|700|2000|2000|2|directory'
    leaf=f'1|3|{size}|mtime|ctime|600|2000|2000|1|regular file'
    return ('\n'.join([parent,leaf,leaf,digest+'  /proc/self/fd/3',parent,leaf,leaf])+'\n').encode()


class DexTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        install(self,globals(),'dex')

    def test_actual_generated_selfdup_with_real_exec_red_green(self):
        env,_=scope();command=env['dex_command']()
        # Feed the exact first generated stat/hash FD consumers to the real OS
        # CLOEXEC fixture. Removing selfdup reproduces the measured missing FD.
        parts=[x.strip() for x in command.split(';') if '/proc/self/fd/3' in x][:2]
        case={'fd':3,'mode':'with-selfdup','command':'exec 3</system/build.prop; '+'; '.join(parts)}
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'dex';path.write_bytes(b'harmless fd fixture')
            fixture=shell_tests.ShellFDProbeTests();self.assertEqual('descriptor-read',fixture.external(case,path)['state'])
            broken={**case,'command':case['command'].replace(' 3>&3','')}
            self.assertEqual('command-failed',fixture.external(broken,path)['state'])
    def test_empty_mismatch_missing_symlink_are_not_admitted(self):
        env,_=scope()
        for raw,state in ((report(),'matching'),(report(0,hashlib.sha256(b'').hexdigest()),'empty'),(report(4948,'a'*64),'mismatched'),(b'dex-absent\n','absent'),(b'dex-parent-unsafe\n','parent-unsafe'),(b'dex-file-unsafe\n','file-unsafe')):
            value=env['parse_reply'](0,raw,b'');self.assertEqual(state,value['state'])
            env['dex_read']=lambda case:value
            result=env['observed_getter'](Path('/inert'));self.assertEqual(state=='matching',result['dexAdmitted']);self.assertTrue(result['closingGuardsVerified']);self.assertFalse(result['appProcessExecuted'])
        self.assertEqual('inaccessible',env['parse_reply'](1,b'',b'private failure')['state'])
    def test_generation_drift_malformed_and_false_code_rejected(self):
        env,_=scope();raw=report().replace(b'1|3|4948',b'1|4|4948',1)
        with self.assertRaisesRegex(ValueError,'dex_generation_changed'):env['parse_reply'](0,raw,b'')
        for args in ((False,b'',b''),(0,b'x'*4097,b''),(0,report(),b'warning')):
            with self.assertRaises(ValueError):env['parse_reply'](*args)
        values=iter([env['parse_reply'](0,report(),b''),env['parse_reply'](0,report(0,hashlib.sha256(b'').hexdigest()),b'')]);env['dex_read']=lambda _:next(values)
        result=env['observed_getter'](Path('/inert'));self.assertEqual('dex_observation_changed',result['reason']);self.assertEqual(2,len(result['observations']));self.assertFalse(result['dexAdmitted'])
    def test_read_failure_and_owner_drift_do_not_suppress_closing(self):
        env,calls=scope();env['dex_read']=lambda _:(_ for _ in ()).throw(ValueError('fd_probe_command_timeout'))
        result=env['observed_getter'](Path('/inert'));self.assertTrue(result['closingGuardsVerified']);self.assertEqual(2,calls.count('generation'));self.assertFalse(result['dexAdmitted'])
        env,calls=scope();env['dex_read']=lambda _:env['parse_reply'](0,report(),b'');original=env['getter_cli']
        def cli(words,owner):
            value=original(words,owner)
            if len(calls)>3:value['stdout']['controllerId']='foreign'
            return value
        env['getter_cli']=cli;result=env['observed_getter'](Path('/inert'));self.assertFalse(result['dexAdmitted']);self.assertFalse(result['closingGuardsVerified'])
    def test_actual_shell_symlink_and_absence_branches(self):
        env,_=scope()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);parent=root/'stage';parent.mkdir(mode=0o700);link=root/'alias';link.symlink_to(parent);leaf=parent/'classes.dex';leaf.symlink_to(root/'missing')
            for path,expected in ((root/'missing','dex-absent'),(link,'dex-parent-unsafe'),(parent,'dex-file-unsafe')):
                command=env['dex_command']().replace(env['DEX_PARENT'],str(path)).replace('/system/bin/id -u','printf 2000')
                # Device UID/mode read is the sole external metadata adapter;
                # real shell tests inspect actual harmless symlinks/absence.
                command=command.replace('$(/system/bin/stat -c '+repr('%a|%u|%F')+' '+str(path)+')',"$(printf '700|2000|directory')")
                value=subprocess.run(['sh','-c',command],capture_output=True)
                self.assertEqual(0,value.returncode);self.assertEqual((expected+'\n').encode(),value.stdout);self.assertEqual(b'',value.stderr)
    def test_fixed_script_no_mutation_or_arbitrary_input(self):
        env,_=scope();command=env['dex_command']()
        for required in ('test -L','test -f','test -r','exec 3<','/proc/self/fd/3 3>&3'):
            self.assertIn(required,command)
        for forbidden in ('app_process','mkdir','chmod','settings','su ','rm ','>./','classes.dex; exec 4>'):
            self.assertNotIn(forbidden,command)
    def test_consistently_changed_original_source_rejected_before_factory(self):
        self.assertTrue((ROOT/'.runtime/parity-evidence'/dex.original.STATUS).exists(),'owned synthetic historical fixture is incomplete')
        original=dex.availability._snapshot
        def changed(path):
            pin,raw=original(path)
            return pin,raw+b'\n' if Path(path)==Path(dex.original.__file__).absolute() else raw
        with mock.patch.object(dex.availability,'_snapshot',side_effect=changed):
            with self.assertRaisesRegex(ValueError,'dex_original_source_changed'):
                dex.prepare(ROOT,original_tests.CompositionTests().reservation())
        # An unadmitted inherited factory must never execute at all.
        with mock.patch.object(dex.availability,'_snapshot',side_effect=changed),mock.patch.object(dex.original,'prepare') as factory:
            with self.assertRaisesRegex(ValueError,'dex_original_source_changed'):
                dex.prepare(ROOT,original_tests.CompositionTests().reservation())
            factory.assert_not_called()
    def test_actual_factory_prefix_tail_with_inert_external_boundaries(self):
        self.assertTrue((ROOT/'.runtime/parity-evidence'/dex.original.STATUS).exists(),'owned synthetic historical fixture is incomplete')
        prepared=dex.prepare(ROOT,original_tests.CompositionTests().reservation());tree=ast.parse(prepared['program']);emitted=[]
        for index in range(len(tree.body)-1,-1,-1):
            text=ast.unparse(tree.body[index])
            if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
            elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
        tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0])
        pin=[1]*9;rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700);lockinfo=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1)
        class Directory:
            name='inert-original-journal'
            def lstat(self):return types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
        class Root:
            def __truediv__(self,_):return Directory()
        for fail in (None,'tail','intent'):
            emitted.clear()
            def install(ns):
                env,_=scope();proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *args,**kwargs:8;proxy.close=lambda _:None;proxy.fstat=lambda number:rootinfo if number==7 else lockinfo;proxy.stat=lambda *args,**kwargs:lockinfo
                guards=[0]
                def parents(_):
                    guards[0]+=1
                    if fail=='tail' and guards[0]==4:raise ValueError('tail_changed')
                ns.update({k:env[k] for k in ('getter_stage','getter_generation','getter_apk','getter_cli','getter_envelope')})
                ns.update(ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=parents,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *args:{} if fail=='intent' else ns['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *args:None),dex_read=lambda _:ns['parse_reply'](0,report(),b''),print=lambda line:emitted.append(json.loads(line)))
            bindings={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *args:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
            if fail is None:
                exec(compile(ast.fix_missing_locations(tree),'<actual-current-census-composition>','exec'),bindings);self.assertEqual(1,len(emitted));self.assertTrue(emitted[0]['dexAdmitted']);self.assertFalse(emitted[0]['appProcessExecuted'])
            else:
                with self.assertRaises(ValueError):exec(compile(ast.fix_missing_locations(tree),'<actual-current-census-composition>','exec'),bindings)
                self.assertEqual([],emitted)
        with mock.patch.object(dex.availability,'_snapshot',side_effect=ValueError('changed')),self.assertRaises(ValueError):dex.prepare(ROOT,original_tests.CompositionTests().reservation())
