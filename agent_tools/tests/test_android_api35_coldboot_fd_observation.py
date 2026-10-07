"""Current-generation composition and real OS CLOEXEC regressions; no native."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import android_api35_coldboot_fd_observation as fd
from agent_tools.tests import test_android_shell_fd_probe as inherited_tests
from agent_tools.tests import test_android_api35_coldboot_product_observation as originals

ROOT=Path(__file__).resolve().parents[2]

def scope():
    env=dict(os=os,json=json,base64=base64,hashlib=hashlib,re=re,pathlib=__import__('pathlib'),select=__import__('select'),time=__import__('time'),subprocess=subprocess,FD_OWNER=fd.OWNER,GETTER_RECORDS={'shellFdReads':[]},GETTER={'packageSha256':fd.original.APK})
    for text in (fd._functions(Path(fd.historical.__file__).read_bytes()),fd._OBSERVER):
        nodes=[node for node in ast.parse(text).body if isinstance(node,ast.FunctionDef) or isinstance(node,ast.Assign) and node.targets[0].id in ('FORMAT','_frozen_parse_reply')]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-current-fd-program>','exec'),env)
    return env

class CurrentFdTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        install(self,globals(),'fd')

    def guarded(self):
        env=scope();calls=[];env['getter_stage']=lambda:{'full':'pinned'};env['getter_generation']=lambda _:calls.append('generation');env['getter_apk']=lambda:fd.original.APK
        def cli(words,owner):
            calls.append(tuple(words));return {'returncode':0,'stdout':{'ok':True,'code':'OK','final':True,'controllerId':fd.OWNER,'configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','operations':[]}}}
        env['getter_cli']=cli;env['getter_envelope']=lambda record,owner,revision:record['stdout'] if record['stdout']['controllerId']==owner and record['stdout']['configurationRevision']==revision else None
        return env,calls
    def test_actual_generated_scripts_cloexec_red_and_explicit_selfdup_green(self):
        env=scope();external=inherited_tests.ShellFDProbeTests()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'harmless-build-prop';path.write_bytes(b'fixed harmless ABI fixture\n');reads=[]
            for case in env['probe_commands']():reads.append({'fd':case['fd'],'mode':case['mode'],'result':external.external({**case,'command':case['command'].replace('/system/etc/hosts','/system/build.prop')},path)})
            for number in (3,4):
                group=[item for item in reads if item['fd']==number];self.assertEqual('command-failed',group[1]['result']['state']);self.assertEqual(group[0]['result'],group[2]['result'])
            result=env['classify'](reads);self.assertTrue(result['explicitSelfdupObserved']);self.assertEqual('not-tested',result['appProcessInheritance'])
    def test_all_six_fixed_source_scripts_and_old_prefix_never_composed(self):
        env=scope();self.assertEqual([(x['fd'],x['mode']) for x in fd.historical.probe_commands()],[(x['fd'],x['mode']) for x in env['probe_commands']()]);self.assertEqual(6,len(env['probe_commands']()))
        selected=fd._functions(Path(fd.historical.__file__).read_bytes());self.assertNotIn('remote_source',selected);self.assertNotIn('app_process',selected)
    def test_measured_permission_denial_is_fixture_phase_not_handoff(self):
        env,calls=self.guarded()
        denied=b"/system/bin/sh: can't open /system/build.prop: Permission denied\n"
        value=env['parse_reply'](1,b'',denied)
        self.assertEqual('fixture-unreadable',value['state'])
        env['fd_read']=lambda _:value
        result=env['observed_getter'](Path('/fixture'))
        self.assertEqual('fd_probe_fixture_unreadable',result['reason'])
        self.assertTrue(result['closingGuardsVerified']);self.assertIsNone(result['shellFdProbe'])
    def test_fixed_hosts_target_requires_readable_regular_nonsymlink(self):
        env=scope()
        for case in env['probe_commands']():
            self.assertNotIn('/system/build.prop',case['command'])
            self.assertIn('test ! -L /system/etc/hosts',case['command'])
            self.assertIn('test -f /system/etc/hosts',case['command'])
            self.assertIn('test -r /system/etc/hosts',case['command'])
            self.assertIn('exec '+str(case['fd'])+'</system/etc/hosts',case['command'])
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);regular=root/'hosts';regular.write_bytes(b'127.0.0.1 localhost\n');link=root/'link';link.symlink_to(regular)
            for target,allowed in ((regular,True),(link,False),(root,False),(root/'missing',False)):
                case=env['probe_commands']()[0]
                # Execute the exact generated pre-open guard against a harmless
                # public fixture; uid command alone is an inert fixture adapter.
                command=case['command'].split('exec 3<',1)[0].replace('/system/bin/id -u','printf 2000').replace('/system/etc/hosts',str(target))
                value=subprocess.run(['sh','-c',command],capture_output=True)
                self.assertEqual(allowed,value.returncode==0)
                if not allowed:self.assertEqual(b'fd_probe_fixture_unreadable\n',value.stderr)
    def test_probe_timeout_still_closes_guards_no_partial_positive(self):
        env,calls=self.guarded();env['fd_read']=lambda case:(_ for _ in ()).throw(ValueError('fd_probe_command_timeout'))
        result=env['observed_getter'](Path('/fixture'));self.assertEqual('diagnostic-only',result['state']);self.assertTrue(result['closingGuardsVerified']);self.assertIsNone(result['shellFdProbe']);self.assertFalse(result['productAdmitted']);self.assertEqual(2,calls.count('generation'))
    def test_owner_package_generation_operations_stage_drift_reject(self):
        for kind in ('owner','apk','generation','operations','stage'):
            env,calls=self.guarded();env['fd_read']=lambda case:{'state':'descriptor-read','exit':0,'generation':'same','sha256':'a'*64};original=env['getter_cli']
            def cli(words,owner):
                result=original(words,owner)
                if kind=='owner':result['stdout']['controllerId']='foreign'
                if kind=='operations':result['stdout']['data']['operations']=[{'final':True}]
                return result
            env['getter_cli']=cli
            if kind=='apk':env['getter_apk']=lambda:'foreign'
            if kind=='generation':env['getter_generation']=lambda _:(_ for _ in ()).throw(ValueError('getter_generation_changed'))
            if kind=='stage':values=iter([{'a':1},{'a':2}]);env['getter_stage']=lambda:next(values)
            result=env['observed_getter'](Path('/fixture'));self.assertIsNone(result['shellFdProbe']);self.assertFalse(result['productAdmitted'])
    def test_actual_fd_read_retains_raw_and_both_streams_bounded(self):
        env=scope();case=env['probe_commands']()[0]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();adb=root/'adb';adb.write_bytes(b'fixture');real_fd=os.open(adb,os.O_RDONLY);generation=[1]*9;env['LAUNCH']={'adbPath':str(adb),'adbFacts':{'generation':generation},'environment':{}}
            env['parent_fds']=lambda _:([{'fd':real_fd}],adb.name);env['close_parents']=lambda _:None;env['guard_parents']=lambda _:None;env['fp']=lambda _:generation
            proxy=types.SimpleNamespace(**vars(os));proxy.open=lambda *args,**kwargs:os.dup(real_fd);proxy.stat=lambda *args,**kwargs:adb.stat();env['os']=proxy
            real_launch=subprocess.Popen
            def launch(*args,**kwargs):return real_launch([sys.executable,'-I','-c','import sys;sys.stdout.buffer.write(b"x"*4097)'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                with mock.patch.object(subprocess,'Popen',side_effect=launch),self.assertRaisesRegex(ValueError,'fd_probe_output_limit'):env['fd_read'](case)
            finally:os.close(real_fd)
            record=env['GETTER_RECORDS']['shellFdReads'][0];self.assertEqual(b'x'*4097,base64.b64decode(record['stdoutBase64']));self.assertFalse(record['captureComplete'])
    def test_actual_full_generated_prefix_tail_emits_one_json_with_os_fd_fixture(self):
        # The routine composition fixture runs the complete composed program,
        # including admission prefix, observer and closing tail. Only external
        # device readers are substituted with real harmless OS exec fixtures.
        base='''import json\nfrom pathlib import Path\nPREFIX_VALID=True\nif not PREFIX_VALID:raise ValueError('prefix_rejected')\ndef current_getter(directory):raise AssertionError('old route')\ndef observed_getter(directory):raise AssertionError('old observer')\ndef coldboot_dispatch():\n if not PREFIX_VALID:raise ValueError('prefix_rejected')\n result=observed_getter(Path('/fixture'))\n if not PREFIX_VALID:raise ValueError('closing_prefix_rejected')\n print(json.dumps(result,separators=(',',':')))\ncoldboot_dispatch()\n'''
        program=fd.compose(base,Path(fd.historical.__file__).read_bytes(),Path(fd.__file__).read_bytes());env,calls=self.guarded();external=inherited_tests.ShellFDProbeTests();emitted=[]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'harmless-build-prop';path.write_bytes(b'fixed harmless ABI fixture\n')
            def read(case):
                result=external.external({**case,'command':case['command'].replace('/system/etc/hosts','/system/build.prop')},path);env['GETTER_RECORDS']['shellFdReads'].append({'fd':case['fd'],'mode':case['mode'],'fixture':'host-os-exec'});return result
            # Install the device adapter after all generated definitions but
            # before the sole actual tail; preserve prefix/closing assertions.
            tree=ast.parse(program);tree.body.insert(-1,ast.parse('fd_read=HOST_EXTERNAL').body[0]);env.update(HOST_EXTERNAL=read,print=lambda line:emitted.append(json.loads(line)))
            exec(compile(ast.fix_missing_locations(tree),'<full-generated-fd-observer>','exec'),env)
        self.assertEqual(1,len(emitted));self.assertEqual('current-shell-descriptors-observed',emitted[0]['state']);self.assertEqual(6,len(emitted[0]['records']['shellFdReads']));self.assertTrue(emitted[0]['closingGuardsVerified']);self.assertFalse(emitted[0]['productAdmitted']);self.assertEqual('not-tested',emitted[0]['appProcessInheritance']);self.assertNotIn(('routing','show'),calls)
        with self.assertRaisesRegex(ValueError,'prefix_rejected'):
            exec(program.replace('PREFIX_VALID = True','PREFIX_VALID = False'),dict(env))
        duplicate=ast.parse(program);duplicate.body.append(ast.parse('coldboot_dispatch()').body[0])
        with self.assertRaises(ValueError):fd.original.validate_readonly(ast.unparse(duplicate))
    def test_actual_current_generation_factory_and_source_drift(self):
        self.assertTrue((ROOT/'.runtime/parity-evidence'/fd.original.STATUS).exists(),'owned synthetic historical fixture is incomplete')
        reservation=originals.CompositionTests().reservation();prepared=fd.prepare(ROOT,reservation);fd.original.validate_readonly(prepared['program']);self.assertLess(len(fd.ssh_carrier(prepared)),131072)
        # Execute the exact prepared factory, including its unchanged dispatch
        # lock/journal prefix and post-tail guards. Only external filesystem,
        # device readers and harmless FD consumers are adapted; no native call.
        tree=ast.parse(prepared['program']);emitted=[]
        for index in range(len(tree.body)-1,-1,-1):
            text=ast.unparse(tree.body[index])
            if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
            elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
        tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0])
        external=inherited_tests.ShellFDProbeTests()
        with tempfile.TemporaryDirectory() as tmp:
            host=Path(tmp)/'hosts';host.write_bytes(b'127.0.0.1 localhost\n')
            import stat
            pin=[1]*9
            rootinfo=types.SimpleNamespace(st_uid=1000,st_mode=stat.S_IFDIR|0o700)
            lockinfo=types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o600,st_nlink=1)
            class Directory:
                name='inert-original-journal'
                def lstat(self):return types.SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o700)
            class Root:
                def __truediv__(self,_):return Directory()
            def install(namespace):
                env,calls=self.guarded()
                def read(case):return external.external({**case,'command':case['command'].replace('/system/etc/hosts','/system/build.prop')},host)
                proxy=types.SimpleNamespace(**vars(os));proxy.getuid=lambda:0;proxy.geteuid=lambda:0;proxy.open=lambda *args,**kwargs:8;proxy.close=lambda _:None;proxy.fstat=lambda number:rootinfo if number==7 else lockinfo;proxy.stat=lambda *args,**kwargs:lockinfo
                namespace.update({key:env[key] for key in ('getter_stage','getter_generation','getter_apk','getter_cli','getter_envelope')})
                namespace.update(ROOT=Root(),os=proxy,parent_fds=lambda _:([{'fd':7,'pin':pin}],None),guard_parents=lambda _:None,close_parents=lambda _:None,fp=lambda _:pin,journal_read=lambda *args:namespace['LAUNCH']['intent'],fcntl=types.SimpleNamespace(LOCK_EX=1,LOCK_NB=2,flock=lambda *args:None),fd_read=read,print=lambda line:emitted.append(json.loads(line)))
            exec(compile(ast.fix_missing_locations(tree),'<exact-prepared-prefix-observer-tail>','exec'),{'HOST_INSTALL':install,'HOST_HISTORY':lambda namespace:namespace.update(read_fixed=lambda *args:{**namespace['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None})
        self.assertEqual(1,len(emitted));self.assertEqual('current-shell-descriptors-observed',emitted[0]['state']);self.assertTrue(emitted[0]['closingGuardsVerified'])
        original=fd.availability._snapshot
        def changed(path):
            pin,raw=original(path);return pin,raw+b' ' if Path(path)==Path(fd.historical.__file__).absolute()else raw
        with mock.patch.object(fd.availability,'_snapshot',side_effect=changed),self.assertRaises(ValueError):fd.prepare(ROOT,reservation)
