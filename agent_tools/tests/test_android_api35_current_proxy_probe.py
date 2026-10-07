"""Causal OS fixtures and full generated current-probe composition; no native."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import sys
import subprocess
import types
import unittest
from unittest import mock
from agent_tools import android_api35_current_proxy_probe as probe
from agent_tools.tests import test_android_api35_coldboot_fd_observation as fd_tests
from agent_tools.tests import test_android_shell_fd_probe as shell_tests
from agent_tools.tests import test_android_api35_coldboot_product_observation as original_tests
ROOT=Path(__file__).resolve().parents[2]
CORRELATION='9833843d-6192-4715-9e7a-1e330363bb2e'


def binding():return {'correlationId':CORRELATION,'artifactSha256':probe.admission.DEX_SHA,'artifactBytes':4948,'javaSha256':probe.admission.JAVA_SHA,'sourceSha256':'a'*64,'dexBase64':base64.b64encode(b'harmless fixture bytes').decode(),'stageAuthority':probe.historical.STAGE_AUTHORITY}

def scope():
    env,calls=fd_tests.CurrentFdTests().guarded();env.update(stat=stat);env['GETTER']['generation']={'fixture':'current'}
    source=ast.parse(Path(probe.historical.__file__).read_bytes());function=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='parse_probe');function.returns=None
    for arg in function.args.args:arg.annotation=None
    exec(compile(ast.Module(body=[function],type_ignores=[]),'<frozen-binder-parser>','exec'),env)
    exec(probe._OBSERVER.replace('__PROBE__',repr(binding())),env);return env,calls


def reply(raw,code=0,stderr=b''):return {'exitCode':code,'stdoutBase64':base64.b64encode(raw).decode(),'stderrBase64':base64.b64encode(stderr).decode()}
PARENT='1|2|4096|mtime|ctime|700|2000|2000|2|directory'
FILE='1|3|4948|mtime|ctime|600|2000|2000|1|regular file'

def stage_reply():return reply(('1|2|700|2000|directory\n'+PARENT+'\n'+FILE+'\n'+FILE+'\n'+probe.admission.DEX_SHA+'  /proc/self/fd/4\n').encode())
def generation_reply():return reply(('\n'.join([PARENT,FILE,FILE,probe.admission.DEX_SHA+'  /proc/self/fd/3',PARENT,FILE,FILE])+'\n').encode())
def getter_value():return {'schema':1,'state':'observed','uid':2000,'correlationId':CORRELATION,'reads':[{'global':None,'defaultForShell':None}]*2}

def read_case(case):
    if case['mode']=='stage':return stage_reply()
    if case['mode']=='getter':return reply(json.dumps(getter_value()).encode())
    return generation_reply()


def fake_root_os():
    proxy=types.SimpleNamespace(**vars(os));directories={}
    def wrap(info):
        values={name:getattr(info,name) for name in ('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_mode','st_nlink')}
        if stat.S_ISDIR(info.st_mode) and info.st_ino in directories:
            # The remote Linux filesystem counts only child directories in
            # nlink; APFS counts regular children as well. Keep real fd/bytes.
            values['st_nlink']=2+sum(p.is_dir() for p in directories[info.st_ino].iterdir())
        return types.SimpleNamespace(**values,st_uid=0,st_gid=0)
    proxy.fstat=lambda fd:wrap(os.fstat(fd));proxy.stat=lambda *args,**kwargs:wrap(os.stat(*args,**kwargs));proxy.getuid=lambda:0;proxy.geteuid=lambda:0
    class Directory:
        def __init__(self,path):self.path=path;directories[path.stat().st_ino]=path
        def __fspath__(self):return str(self.path)
        def __truediv__(self,name):return self.path/name
        def lstat(self):return wrap(self.path.lstat())
    def mkdir(name,*args,**kwargs):
        os.mkdir(name,*args,**kwargs);parent=directories[os.fstat(kwargs['dir_fd']).st_ino];path=parent/name;directories[path.stat().st_ino]=path
    proxy.mkdir=mkdir
    def fp(i):return [i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_mode,i.st_uid,i.st_gid,i.st_nlink]
    return proxy,Directory,fp


def journal(root):
    root.mkdir(mode=0o700)
    for name in ('intent.json','attempt.json','ready.json','child.json','exec-released.json','emulator-child.json'):
        (root/name).write_bytes(b'{}\n');(root/name).chmod(0o600)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        install(self,globals(),'probe')

    def test_generated_stage_and_getter_consumers_real_fd_selfdup_red_green(self):
        env,_=scope();fixture=shell_tests.ShellFDProbeTests()
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'harmless';path.write_bytes(b'fixed harmless descriptor fixture')
            for number,command in ((4,env['probe_stage_command']()),(3,env['probe_getter_command'](FILE))):
                # Select the actual generated external stat/hash consumer bytes.
                if number==4:
                    stat_part=re.search(r"/system/bin/stat -Lc '%d\|%i\|%s\|%y\|%z\|%a\|%u\|%g\|%h\|%F' /proc/self/fd/4 4>&4",command).group()
                    hash_part='/system/bin/sha256sum /proc/self/fd/4 4>&4'
                else:
                    stat_part=re.search(r"/system/bin/stat -Lc '%d\|%i\|%s\|%y\|%z\|%a\|%u\|%g\|%h\|%F' /proc/self/fd/3 3>&3",command).group()
                    hash_part='/system/bin/sha256sum /proc/self/fd/3 3>&3'
                case={'fd':number,'mode':'with-selfdup','command':f'exec {number}</system/build.prop; '+stat_part+'; '+hash_part}
                self.assertEqual('descriptor-read',fixture.external(case,path)['state'])
                case['command']=case['command'].replace(f' {number}>&{number}','')
                self.assertEqual('command-failed',fixture.external(case,path)['state'])
            self.assertTrue(env['probe_getter_command'](FILE).endswith(CORRELATION+' 3>&3'))
    def test_complete_generated_stage_real_empty_fd_red_then_full_write_green(self):
        # Execute every stage predicate, FD open, write and SHA check. The
        # portability adapter translates Android GNU formatting and /proc FD
        # lookup to real host stat/fstat/read; it supplies no canned file facts.
        env,_=scope();data=b'x'*4948;env['PROBE'].update(dexBase64=base64.b64encode(data).decode(),artifactSha256=hashlib.sha256(data).hexdigest())
        archive=Path(__file__).parent/'fixtures/android_api35_proxy_probe_initial.py'
        if archive.exists():
            raw=archive.read_bytes();self.assertEqual('bff6eac22e615e15e895324810c00be3fe64d62fefc5ad7f78b00d14cd745e52',hashlib.sha256(raw).hexdigest())
            template=ast.literal_eval(next(n.value for n in ast.parse(raw).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='_OBSERVER' for t in n.targets)))
            old=dict(env);exec(template.replace('__PROBE__',repr(env['PROBE'])),old)
            self.assertEqual(old['probe_stage_command'](),env['probe_stage_command']().replace('|0|regular empty file','|0|regular file'))
        adapter=r"""import os,sys,stat,hashlib
kind=sys.argv[1]
def info(path):
 if path.startswith('/proc/self/fd/'):return os.fstat(int(path.rsplit('/',1)[1]))
 return os.stat(path,follow_symlinks=kind=='stat' and sys.argv[2]=='-Lc')
if kind=='stat':
 fmt=sys.argv[3]
 for path in sys.argv[4:]:
  s=info(path);t='directory' if stat.S_ISDIR(s.st_mode) else 'regular empty file' if s.st_size==0 else 'regular file'
  values={'%d':s.st_dev,'%i':s.st_ino,'%s':s.st_size,'%y':s.st_mtime_ns,'%z':s.st_ctime_ns,'%a':format(stat.S_IMODE(s.st_mode),'o'),'%u':s.st_uid,'%g':s.st_gid,'%h':s.st_nlink,'%F':t}
  print('|'.join(str(values[x]) for x in fmt.split('|')))
else:
 path=sys.argv[2];held=info(path)
 if path.startswith('/proc/self/fd/'):
  n=int(path.rsplit('/',1)[1])
  if os.path.exists('/proc/self/fd'):fd=os.open(path,os.O_RDONLY)
  else:
   import fcntl
   named=fcntl.fcntl(n,50,bytes(1024)).split(b'\0',1)[0];fd=os.open(named,os.O_RDONLY|os.O_NOFOLLOW)
 else:fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 s=os.fstat(fd)
 assert (s.st_dev,s.st_ino)==(held.st_dev,held.st_ino)
 h=hashlib.sha256()
 while True:
  raw=os.read(fd,65536)
  if not raw:break
  h.update(raw)
 os.close(fd);print(h.hexdigest()+'  '+path)
"""
        import shlex
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);tool=root/'tool.py';tool.write_text(adapter);prefix=shlex.quote(sys.executable)+' -I '+shlex.quote(str(tool))
            for old in (True,False):
                stage=root/('old' if old else 'new');command=env['probe_stage_command']();original_directory=env['probe_paths']()[0]
                command=command.replace(original_directory,str(stage)).replace('2000',str(os.getuid())).replace('/system/bin/id','/usr/bin/id').replace('/system/bin/mkdir','/bin/mkdir').replace('/system/bin/base64','/usr/bin/base64').replace('/system/bin/stat',prefix+' stat').replace('/system/bin/sha256sum',prefix+' sha')
                if old:command=command.replace('|0|regular empty file','|0|regular file')
                result=subprocess.run(['sh','-c',command],capture_output=True,timeout=10)
                if old:
                    self.assertNotEqual(0,result.returncode);self.assertEqual(b'',result.stdout);self.assertEqual(b'',result.stderr);self.assertEqual(b'',(stage/'classes.dex').read_bytes())
                else:
                    self.assertEqual(0,result.returncode,result.stderr);self.assertEqual(data,(stage/'classes.dex').read_bytes());lines=result.stdout.decode().splitlines();self.assertEqual(5,len(lines));self.assertEqual(lines[2],lines[3]);self.assertEqual(hashlib.sha256(data).hexdigest(),lines[4].split()[0]);self.assertEqual('regular file',lines[2].split('|')[-1])
    def test_actual_noclobber_exclusive_open_collision_preserves_bytes(self):
        env,_=scope();command=env['probe_stage_command']();part=command[command.index('test ! -e ./classes.dex;'):command.index('set +C;')+len('set +C;')]
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'classes.dex';p.write_bytes(b'original')
            value=subprocess.run(['sh','-c',part],cwd=tmp,capture_output=True);self.assertNotEqual(0,value.returncode);self.assertEqual(b'original',p.read_bytes())
            p.unlink();value=subprocess.run(['sh','-c',part],cwd=tmp,capture_output=True);self.assertEqual(0,value.returncode);self.assertEqual(b'',p.read_bytes())
    def test_actual_fence_create_once_partial_failure_no_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'original';journal(root);env,_=scope();proxy,Directory,fp=fake_root_os();env.update(os=proxy,fp=fp,parent_fds=lambda p:([{'fd':os.open(p.parent,os.O_RDONLY),'pin':fp(proxy.stat(p.parent))}],p.name),guard_parents=lambda chain:None,close_parents=lambda chain:[os.close(item['fd']) for item in chain])
            fence=env['probe_fence'](Directory(root));env['probe_fence_guard'](Directory(root),fence)
            self.assertTrue(fence['stageFenceDurable']);self.assertEqual(['intent.json','stage-fence.json'],sorted(p.name for p in (root/('proxy-probe-'+CORRELATION)).iterdir()))
            with self.assertRaisesRegex(ValueError,'probe_correlation_consumed'):env['probe_fence'](Directory(root))
            (root/'ready.json').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'probe_original_record_changed'):env['probe_fence_guard'](Directory(root),fence)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'original';journal(root);env,_=scope();proxy,Directory,fp=fake_root_os();proxy.write=lambda *args:(_ for _ in ()).throw(OSError('lost write'));env.update(os=proxy,fp=fp,parent_fds=lambda p:([{'fd':os.open(p.parent,os.O_RDONLY),'pin':fp(proxy.stat(p.parent))}],p.name),guard_parents=lambda chain:None,close_parents=lambda chain:[os.close(item['fd']) for item in chain])
            with self.assertRaises(OSError):env['probe_fence'](Directory(root))
            with self.assertRaisesRegex(ValueError,'probe_correlation_consumed'):env['probe_fence'](Directory(root))
    def test_fence_same_directory_inplace_record_change_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'original';journal(root);env,_=scope();proxy,Directory,fp=fake_root_os();env.update(os=proxy,fp=fp,parent_fds=lambda p:([{'fd':os.open(p.parent,os.O_RDONLY),'pin':fp(proxy.stat(p.parent))}],p.name),guard_parents=lambda chain:None,close_parents=lambda chain:[os.close(item['fd']) for item in chain])
            fence=env['probe_fence'](Directory(root));path=root/('proxy-probe-'+CORRELATION)/'stage-fence.json';path.write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError,'probe_fence_record_changed'):env['probe_fence_guard'](Directory(root),fence)
    def test_unexplained_parent_mutation_rejected_before_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'original';journal(root);env,_=scope();proxy,Directory,fp=fake_root_os()
            original_mkdir=proxy.mkdir
            def mkdir(*args,**kwargs):
                original_mkdir(*args,**kwargs);(root/'foreign').write_bytes(b'not admitted')
            proxy.mkdir=mkdir;env.update(os=proxy,fp=fp,parent_fds=lambda p:([{'fd':os.open(p.parent,os.O_RDONLY),'pin':fp(proxy.stat(p.parent))}],p.name),guard_parents=lambda chain:None,close_parents=lambda chain:[os.close(item['fd']) for item in chain])
            with self.assertRaisesRegex(ValueError,'probe_journal_parent_changed'):env['probe_fence'](Directory(root))
            self.assertFalse((root/('proxy-probe-'+CORRELATION)/'stage-fence.json').exists())
    def test_typed_schema_security_exception_and_stage_drift_unknown(self):
        env,_=scope();self.assertEqual(getter_value(),env['parse_probe_current'](reply(json.dumps(getter_value()).encode())))
        for field,value in (('schema',True),('uid',True),('correlationId','foreign')):
            data=getter_value();data[field]=value
            with self.assertRaises(ValueError):env['parse_probe_current'](reply(json.dumps(data).encode()))
        unknown={'state':'unknown','phase':'getter-first','errorType':'SecurityException'}
        with self.assertRaisesRegex(ValueError,'probe_getter_execution_unknown'):env['parse_probe_current'](reply(json.dumps(unknown).encode(),1))
        changed=generation_reply();changed['stdoutBase64']=base64.b64encode(base64.b64decode(changed['stdoutBase64']).replace(b'1|3|4948',b'1|4|4948',1)).decode()
        with self.assertRaisesRegex(ValueError,'probe_stage_generation_changed'):env['probe_generation'](changed)
    def test_lost_stage_response_retained_fence_closing_and_no_resubmit(self):
        env,calls=scope();submitted=[];consumed=[False]
        def fence(_):
            if consumed[0]:raise ValueError('probe_correlation_consumed')
            consumed[0]=True;return {'stageFenceDurable':True}
        env['probe_fence']=fence;env['probe_fence_guard']=lambda *args:None
        def read(case):submitted.append(case);raise ValueError('probe_transport_unknown')
        env['probe_read']=read
        first=env['observed_getter'](Path('/inert'));second=env['observed_getter'](Path('/inert'))
        self.assertEqual(1,len(submitted));self.assertTrue(first['closingGuardsVerified']);self.assertTrue(second['closingGuardsVerified']);self.assertIsNone(first['effectiveProxy']);self.assertEqual('probe_correlation_consumed',second['reason'])
    def test_full_observer_owner_drift_cannot_promote(self):
        env,calls=scope();env['probe_fence']=lambda _:{'stageFenceDurable':True};env['probe_fence_guard']=lambda *args:None;env['probe_read']=read_case
        result=env['observed_getter'](Path('/inert'));self.assertEqual('current-os-proxy-observed',result['state']);self.assertFalse(result['productAdmitted'])
        env,calls=scope();env['probe_fence']=lambda _:{'stageFenceDurable':True};env['probe_fence_guard']=lambda *args:None;env['probe_read']=read_case;original=env['getter_cli']
        def drift(words,owner):
            value=original(words,owner)
            if len(calls)>3:value['stdout']['controllerId']='foreign'
            return value
        env['getter_cli']=drift;result=env['observed_getter'](Path('/inert'));self.assertIsNone(result['effectiveProxy']);self.assertFalse(result['closingGuardsVerified'])
    def test_actual_prepared_program_unchanged_dispatch_prefix_tail(self):
        self.assertTrue((ROOT/'.runtime/parity-evidence'/probe.admission.original.STATUS).exists(),'owned synthetic historical fixture is incomplete')
        prepared=probe.prepare(ROOT,original_tests.CompositionTests().reservation(),CORRELATION);self.assertLess(len(probe.ssh_carrier(prepared)),131072);tree=ast.parse(prepared['program']);emitted=[]
        for index in range(len(tree.body)-1,-1,-1):
            text=ast.unparse(tree.body[index])
            if text.startswith('_failed = read_fixed('):tree.body.insert(index,ast.parse('HOST_HISTORY(globals())').body[0])
            elif text=='alias_history_guard()':tree.body.insert(index,ast.parse('alias_history_guard=HOST_ALIAS').body[0])
        tree.body.insert(-1,ast.parse('HOST_INSTALL(globals())').body[0])
        for failure in (None,'tail','mutation'):
            emitted.clear()
            with tempfile.TemporaryDirectory() as tmp:
                shared=Path(tmp)/'shared';shared.mkdir(mode=0o700);directory=shared/('android-avd-coldboot-'+probe.admission.original.CORRELATION);journal(directory)
                lock=shared/'android-avd-coldboot-api35.lock';lock.write_bytes(b'');lock.chmod(0o600)
                proxy,Directory,fp=fake_root_os();Directory(shared);Directory(directory)
                previous_fstat=proxy.fstat;previous_stat=proxy.stat;shared_inode=shared.stat().st_ino
                def principal(info):
                    if info.st_ino==shared_inode:info.st_uid=1000;info.st_gid=1000
                    return info
                proxy.fstat=lambda fd:principal(previous_fstat(fd));proxy.stat=lambda *args,**kwargs:principal(previous_stat(*args,**kwargs))
                original_mkdir=proxy.mkdir;submissions=[]
                def mkdir(*args,**kwargs):
                    original_mkdir(*args,**kwargs)
                    if failure=='mutation':(directory/'foreign').write_bytes(b'not admitted')
                proxy.mkdir=mkdir
                class Shared:
                    def __truediv__(self,name):return Directory(shared/name) if name.startswith('android-avd-coldboot-') else shared/name
                def install(ns):
                    env,_=scope();root_guards=[0]
                    def parents(path):
                        parent=path.parent;fd=os.open(parent,os.O_RDONLY);return ([{'fd':fd,'pin':fp(proxy.fstat(fd)),'path':parent}],path.name)
                    def guards(chain):
                        for item in chain:
                            self.assertEqual(item['pin'],fp(proxy.fstat(item['fd'])))
                            self.assertEqual(item['pin'],fp(proxy.stat(item['path'])))
                        if chain[-1]['path']==shared:
                            root_guards[0]+=1
                            if failure=='tail' and root_guards[0]==4:raise ValueError('tail_changed')
                    def read(case):submissions.append(case);return read_case(case)
                    ns.update({k:env[k] for k in ('getter_stage','getter_generation','getter_apk','getter_cli','getter_envelope')})
                    ns.update(ROOT=Shared(),os=proxy,parent_fds=parents,guard_parents=guards,close_parents=lambda chain:[os.close(item['fd']) for item in chain],fp=fp,journal_read=lambda *args:ns['LAUNCH']['intent'],probe_read=read,print=lambda line:emitted.append(json.loads(line)))
                bindings={'HOST_INSTALL':install,'HOST_HISTORY':lambda ns:ns.update(read_fixed=lambda *args:{**ns['CFG']['failedCensus']['pin'],'raw':b''}),'HOST_ALIAS':lambda:None}
                if failure=='tail':
                    with self.assertRaises(ValueError):exec(compile(ast.fix_missing_locations(tree),'<actual-source-composition>','exec'),bindings)
                    self.assertEqual([],emitted)
                else:
                    exec(compile(ast.fix_missing_locations(tree),'<actual-source-composition>','exec'),bindings);self.assertEqual(1,len(emitted))
                    if failure is None:
                        self.assertEqual('current-os-proxy-observed',emitted[0]['state']);self.assertTrue((directory/('proxy-probe-'+CORRELATION)/'stage-fence.json').exists());self.assertEqual(4,len(submissions))
                    else:
                        self.assertEqual('diagnostic-only',emitted[0]['state']);self.assertEqual('probe_journal_parent_changed',emitted[0]['reason']);self.assertEqual([],submissions)
        source=probe.availability._snapshot
        def drift(path):
            pin,raw=source(path);return pin,raw+b'\n' if Path(path)==Path(probe.admission.__file__).absolute() else raw
        with mock.patch.object(probe.availability,'_snapshot',side_effect=drift),mock.patch.object(probe.admission,'prepare') as factory:
            with self.assertRaises(ValueError):probe.prepare(ROOT,original_tests.CompositionTests().reservation(),CORRELATION)
            factory.assert_not_called()
