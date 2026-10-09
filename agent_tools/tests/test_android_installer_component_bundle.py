"""TempFS source closure and real child baseline tests; never native acceptance."""
import ast
import base64
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import select
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from agent_tools import android_installer_component_bundle as bundle
from agent_tools import android_component_command_transport as command
from agent_tools.tests.test_android_physical_readonly_abi import canonical_reply as physical_readonly_reply

ROOT=Path(__file__).resolve().parents[2]
OWNER='6373d143-1372-4835-a89b-baafb0959b9f'
CORRELATION='d475b822-e8b5-4a8d-a27e-ecf3a07a2d88'
# Full native API29 record8 from terminal8461474c, captured before repair.
NATIVE_API29_PROCESS_STAT='1743 (adbd) S 1 1743 0 0 -1 4210944 31534 3707353 39 414 160 163 1187 741 20 0 9 0 597 39497728 2143 18446744073709551615 1 1 0 0 0 0 0 4096 1073776376 0 0 0 17 0 0 0 2 0 0 0 0 0 0 0 0 0 0\n1665 (main) S 1 1665 0 0 -1 4210944 22942 60084 686 1801 12 21 101 71 20 0 6 0 561 1776472064 18766 18446744073709551615 1 1 0 0 0 0 4612 1 1073841400 0 0 0 17 1 0 0 115 0 0 0 0 0 0 0 0 0 0\n1664 (main) S 1 1664 0 0 -1 4210944 35268 218081 1209 3091 16 61 503 358 20 0 6 0 561 4872572928 31525 18446744073709551615 1 1 0 0 0 0 4612 1 1073841400 0 0 0 17 0 0 0 138 0 0 0 0 0 0 0 0 0 0\n'


OLD_API29_GUARD_BACKEND='def _guard_backend(selected,backend):\n    """Authenticate fixed getter/transport functions, never caller callbacks."""\n    transport=selected[\'transport\'];reader=transport.readonly\n    sources=[(transport.REMOTE+\'\\n\'+transport._bounded_source(),\n              (\'component_command\',\'command_binary\',\'command_request\',\'command_host_identity\',\'command_host_guard\',\'command_bounded\')),\n             (reader.getter_source._GETTER.replace(\'__GETTER__\',repr({})),(\'getter_stage\',)),\n             (reader.getter_source.coldboot._BOOT.replace(\'__LAUNCH__\',repr({})),(\'child_identity\',\'session_guest\',\'qemu_fact\')),\n             (reader.proven._REMOTE.replace(\'__EXTERNAL__\',repr({})),(\'external_file\',\'external_jdk\',\'external_jdk_guard\'))]\n    # Match the command factory\'s normalized AST and imported module context.\n    # Python 3.14 optimizes imported-module attributes during compilation.\n    context=\'import hashlib,json,os,pathlib,re,stat,errno,ctypes,fcntl,signal,subprocess,time,select,shutil\\nfrom pathlib import Path\\n\'\n    for raw,names in sources:\n        tree=ast.parse(raw)\n        for name in names:\n            nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name]\n            if len(nodes)!=1:raise ValueError(\'component_guard_fixed_source_changed\')\n            code=compile(context+ast.unparse(ast.Module(body=nodes,type_ignores=[])),\'<guard-fixed-function>\',\'exec\',dont_inherit=True)\n            expected=next(value for value in code.co_consts if isinstance(value,types.CodeType) and value.co_name==name)\n            actual=backend.get(name)\n            if (not isinstance(actual,types.FunctionType) or actual.__globals__ is not backend or\n                selected[\'adapter\']._semantic_code(actual.__code__)!=selected[\'adapter\']._semantic_code(expected)):\n                raise ValueError(\'component_guard_fixed_backend_required:\'+name)\n    return {name:(value,value.__code__) for name,value in backend.items() if isinstance(value,types.FunctionType)}'

class PortabilityTests(unittest.TestCase):
    def test_unsupported_fd_and_identity_apis_refuse_explicitly(self):
        with mock.patch.object(bundle.os,'name','nt'):
            with self.assertRaisesRegex(ValueError,'posix_fd_required'):bundle._parents(Path.cwd())
        with mock.patch.object(bundle.os,'getuid',None,create=True):
            with self.assertRaisesRegex(ValueError,'posix_fd_required'):bundle._parents(Path.cwd())


@unittest.skipUnless(os.name=='posix','component native carrier explicitly requires POSIX FD APIs')
class BundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        # Current public tool bodies plus the exact historical large-reader test
        # required by its source-bound collector. No checkout native ledger.
        self.source_root=self.root/'public-sources';self.source_root.mkdir(mode=0o700)
        historical=ROOT/'agent_tools/tests/fixtures/android_installer_hermetic/routing-reader-test.source'
        history_raw=bundle._read(historical)[0]
        if hashlib.sha256(history_raw).hexdigest()!='c058f6b34132d2a4411552b201a3cf2cff72b5e3717e80ed602a3c198ed62264':
            raise ValueError('historical_routing_test_source_changed')
        for name in bundle.FILES:
            path=self.source_root/name
            for parent in reversed(path.parent.parents):
                if self.source_root in parent.parents:parent.mkdir(mode=0o700,exist_ok=True)
            path.parent.mkdir(mode=0o700,exist_ok=True)
            raw=history_raw if name=='agent_tools/tests/test_android_api35_large_routing_observation.py' else bundle._read(ROOT/name)[0]
            bundle._write(path,raw)
        self.receipt=bundle.prepare(self.source_root,self.root/'stage',bundle.reviewed_tree(self.source_root)['treeSha256'])
    def tearDown(self):self.tmp.cleanup()

    def test_physical_epoch_uses_one_real_adb_carrier(self):
        selected,backend,args,_,log,_,_=self.fixture()
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        guard.enable_physical_batch()
        log.write_text('')
        facts=guard._physical()
        rows=[json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(1,len(rows), 'one continuously pinned carrier per fresh physical epoch')
        self.assertEqual('2000',facts['shellUid'])
        self.assertEqual(guard.expected,facts)

    def physical_packet(self,values=None):
        # Actual local children produce the raw payload. This protocol fixture
        # is not a guest ABI/calibration or an Android acceptance receipt.
        values=values or [(b'value\n\n',b'',0)]*10
        lines=['PHYSICAL-1 '+CORRELATION]
        for n,(out,err,status) in enumerate(values,1):
            child=subprocess.run([sys.executable,'-I','-c',
                'import sys;sys.stdout.buffer.write('+repr(out)+');sys.stderr.buffer.write('+repr(err)+');raise SystemExit('+str(status)+')'],capture_output=True,timeout=5)
            lines.extend(['\t'.join(['FRAME',str(n),str(child.returncode),str(len(child.stdout)),str(len(child.stderr)),'a'*64,'b'*64]),
                          base64.b64encode(child.stdout).decode(),base64.b64encode(child.stderr).decode()])
        return '\n'.join(lines+['EOF '+CORRELATION+' CLEANED',''])

    def test_batch_parser_preserves_actual_child_channels_and_trailing_lf(self):
        values=[(b'line\n\n',b'',0),(b'',b'error\n',7)]+[(b'\n',b'',0)]*8
        rows=bundle._physical_batch_parse(self.physical_packet(values),CORRELATION)
        self.assertEqual('line\n\n',rows[0]['stdoutRaw'])
        self.assertEqual('error\n',rows[1]['stderrRaw']);self.assertEqual(7,rows[1]['returncode'])
        self.assertEqual(list(range(1,11)),[row['ordinal'] for row in rows])

    def test_batch_parser_maximum_payload_and_partial_malformed_refusal(self):
        raw=self.physical_packet([(b'x'*16383,b'y',0)]*10)
        self.assertLessEqual(len(raw.encode()),bundle._PHYSICAL_BATCH_LIMIT)
        self.assertEqual(10,len(bundle._physical_batch_parse(raw,CORRELATION)))
        for changed in (raw[:-1],raw+'extra',raw.replace('FRAME\t2\t','FRAME\t1\t',1),
                        raw.replace('CLEANED','UNKNOWN'),raw.replace('PHYSICAL-1','PHYSICAL-2',1),
                        raw.replace('eHh4','eH\nh4',1),raw.replace('\t16383\t1\t','\t16384\t1\t',1)):
            with self.subTest(kind=hashlib.sha256(changed.encode()).hexdigest()):
                with self.assertRaises(ValueError):bundle._physical_batch_parse(changed,CORRELATION)

    def test_batch_abi_requires_complete_fixed_hash_and_boot_evidence(self):
        boot='28b8f9af-efbb-44da-9836-0237cb714df9'
        raw=physical_readonly_reply(CORRELATION,boot)
        abi=bundle._physical_abi_parse(raw,CORRELATION,boot)
        self.assertEqual(20,abi['stepSeconds'])
        for changed in (raw+'extra\n',raw.replace('/system/bin/toybox','/caller/tool'),raw.replace('PHYSICAL-READONLY-4','ERROR'),raw.replace('28b8f9af','foreign')):
            with self.assertRaises(ValueError):bundle._physical_abi_parse(changed,CORRELATION,boot)

    def test_batch_calibration_refusal_precedes_any_batch_spool_dispatch(self):
        selected,backend,args,state_path,log,_,_=self.fixture()
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        state=json.loads(state_path.read_bytes());state['batchAbiRaw']='UNSUPPORTED';state_path.write_text(json.dumps(state))
        log.write_text('')
        with self.assertRaisesRegex(ValueError,'abi_packet_reply_unknown'):guard.enable_physical_batch()
        rows=[json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual(11,len(rows));self.assertFalse(hasattr(guard,'batch_admission'))
        self.assertFalse(any('PHYSICAL-1 ' in ' '.join(row) for row in rows))
        log.write_text('')
        with self.assertRaises(FileExistsError):guard.enable_physical_batch()
        self.assertEqual(10,len(log.read_text().splitlines())) # only old readonly physical reads

    def test_batch_unknown_is_sticky_and_admission_generation_is_not_adopted(self):
        selected,backend,args,state_path,log,_,_=self.fixture()
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args);guard.enable_physical_batch()
        state=json.loads(state_path.read_bytes());state['boot']='38b8f9af-efbb-44da-9836-0237cb714df9';state_path.write_text(json.dumps(state))
        log.write_text('')
        with self.assertRaisesRegex(ValueError,'batch_abi_changed'):guard._physical()
        self.assertEqual(1,len(log.read_text().splitlines()))
        with self.assertRaisesRegex(ValueError,'batch_unknown_consumed'):guard._physical()
        self.assertEqual(1,len(log.read_text().splitlines()))

    def batch_finally_fault(self,capture_failure,transport_failure=False,closing_failure=False):
        """Actual guard/writer/children; profile observes guards without replacing them."""
        selected,backend,args,_,log,_,_=self.fixture()
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args);guard.enable_physical_batch()
        original_capture=guard._capture;real_fsync=os.fsync;calls=[];faults={};in_closing=[False]
        observed={bundle.load.__code__:'source',guard._task_guard.__func__.__code__:'task'}
        observed.update({backend[name].__code__:name for name in (
            'command_host_guard','external_jdk_guard','getter_stage','child_identity','qemu_fact','session_guest')})
        def profile(frame,event,arg):
            if event=='call' and in_closing[0] and frame.f_code in observed:calls.append(observed[frame.f_code])
        def capture(record):
            def failed_fsync(fd):
                closed=os.open(os.devnull,os.O_RDONLY);os.close(closed)
                return real_fsync(closed) # actual EBADF, not a desired mock result
            try:
                if capture_failure:
                    with mock.patch.object(os,'fsync',failed_fsync):original_capture(record)
                else:original_capture(record)
            except OSError as exc:
                faults['capture']=exc;raise
            finally:
                in_closing[0]=True
                if closing_failure:(self.root/'stage'/bundle.FILES[0]).chmod(0o644)
        guard._capture=capture
        if transport_failure:Path(backend['LAUNCH']['adbPath']).chmod(0o600)
        previous=backend['GETTER_RECORDS'];log.write_text('');old_profile=sys.getprofile()
        try:
            sys.setprofile(profile)
            with self.assertRaises((OSError,ValueError)) as failure:guard._batch_reads()
        finally:sys.setprofile(old_profile)
        self.assertIs(previous,backend['GETTER_RECORDS']);self.assertTrue(guard.batch_uncertain)
        self.assertIn('source',calls) # RED on old capture-before-closing finally
        if not closing_failure:
            for name in ('task','command_host_guard','external_jdk_guard','getter_stage','child_identity','qemu_fact','session_guest'):
                self.assertIn(name,calls)
        if transport_failure:self.assertEqual('getter_binary_changed',str(failure.exception))
        elif capture_failure:self.assertIs(faults['capture'],failure.exception)
        else:self.assertIsInstance(failure.exception,ValueError)
        files=sorted(args.output.glob('component-guard-read-[0-9][0-9][0-9][0-9][0-9].json'))
        raw=json.loads(files[-1].read_bytes())['record']
        self.assertEqual('physical-batch-transport',raw['kind'])
        if not transport_failure:self.assertTrue(raw['result']['stdoutRaw'].startswith('PHYSICAL-1 '))
        count=len(log.read_text().splitlines())
        with self.assertRaisesRegex(ValueError,'batch_unknown_consumed'):guard._batch_reads()
        self.assertEqual(count,len(log.read_text().splitlines()))
        return guard,calls,failure.exception

    def test_batch_real_capture_fsync_failure_still_closes_authority(self):
        guard,_,error=self.batch_finally_fault(True)
        self.assertEqual(9,error.errno)
        self.assertEqual([{'phase':'capture','type':'OSError','errno':9}],guard.batch_failures)

    def test_batch_capture_primary_survives_real_closing_source_failure(self):
        guard,_,error=self.batch_finally_fault(True,closing_failure=True)
        self.assertEqual(9,error.errno)
        self.assertEqual(['capture','closing'],[row['phase'] for row in guard.batch_failures])

    def test_batch_transport_primary_survives_real_capture_failure(self):
        guard,_,_=self.batch_finally_fault(True,transport_failure=True)
        self.assertEqual(['transport','capture'],[row['phase'] for row in guard.batch_failures][:2])

    def test_batch_real_closing_failure_never_promotes_captured_reply(self):
        guard,_,_=self.batch_finally_fault(False,closing_failure=True)
        self.assertEqual(['closing'],[row['phase'] for row in guard.batch_failures])

    @unittest.skipUnless(os.name=='posix','actual shell descriptor wrapper requires POSIX')
    def test_actual_generated_batch_shell_exclusive_capture_and_cleanup(self):
        guest=self.root/'guest';guest.mkdir(mode=0o700)
        helpers=self.root/'guest-bin';helpers.mkdir(mode=0o700)
        apk=self.root/'guest-base.apk';apk.write_bytes(b'actual inert package bytes')
        boot=self.root/'guest-boot';boot.write_text('28b8f9af-efbb-44da-9836-0237cb714df9\n')
        mksh=self.root/'guest-shell';shutil.copyfile('/bin/sh',mksh);mksh.chmod(0o755)
        # The complete generated shell executes unchanged. Only fixed Android
        # utility protocols, system paths and UID/GID observations are mapped;
        # private directory/file syscalls, descriptor generations, watchdog,
        # stdout/stderr, capture, guards and cleanup execute on real TempFS.
        actor='''import sys,os,stat,hashlib,base64,subprocess,pathlib,shutil
a=sys.argv[1:];op=a.pop(0)
if op=='stat':
 follow=False
 if a[0]=='-L':follow=True;a.pop(0)
 assert a.pop(0)=='-c';fmt=a.pop(0);p=a.pop(0);s=os.fstat(int(p.rsplit('/',1)[1])) if p.startswith('/dev/fd/') else os.stat(p,follow_symlinks=follow)
 fields={'%d':str(s.st_dev),'%i':str(s.st_ino),'%f':format(s.st_mode,'x'),'%u':'0' if p in (SHELL,TOY) else '2000','%g':'2000','%h':str(s.st_nlink),'%s':str(s.st_size),'%y':str(s.st_mtime_ns),'%z':str(s.st_ctime_ns),'%a':format(stat.S_IMODE(s.st_mode),'o')}
 for k,v in fields.items():fmt=fmt.replace(k,v)
 print(fmt)
elif op=='sha256sum':
 p=a[0] if a else '-';raw=sys.stdin.buffer.read() if p=='-' else pathlib.Path(APK if p=='/data/app/owned/base.apk' else p).read_bytes();print(hashlib.sha256(raw).hexdigest()+'  '+p)
elif op=='readlink':
 p=a[0]
 if p=='/proc/self/exe':print(TOY)
 elif p.startswith('/proc/') and p.endswith('/exe'):print(SHELL)
 else:print(os.readlink(p))
elif op in ('id','getprop','pm','pidof','cat'):
 raise SystemExit(subprocess.run([str(pathlib.Path(TOY).parent/op),*a]).returncode)
elif op in ('mkdir','find','wc','rm','rmdir'):
 resolved=shutil.which(op,path=os.defpath);assert resolved
 raise SystemExit(subprocess.run([resolved,*a]).returncode)
elif op=='base64':
 assert a[:2]==['-w','0'];p=pathlib.Path(a[2]);sys.stdout.buffer.write(base64.b64encode(p.read_bytes()));sys.stdout.buffer.flush()
 if p.name=='1.o' and os.environ.get('DRIFT')=='file':p.chmod(0o644)
 if p.name=='1.o' and os.environ.get('DRIFT')=='parent':
  cwd=pathlib.Path.cwd();cwd.rename(cwd.with_name(cwd.name+'-retained'));cwd.mkdir(mode=0o700)
elif op=='timeout':
 assert a[:2]==['-s','KILL'];seconds=int(a[2]);fds=[]
 for fd in (4,5):
  try:os.fstat(fd);fds.append(fd)
  except OSError:pass
 try:r=subprocess.run(a[3:],timeout=seconds,pass_fds=fds);raise SystemExit(r.returncode)
 except subprocess.TimeoutExpired:raise SystemExit(124)
else:raise SystemExit(94)
'''
        toy=helpers/'toybox';toy.write_text('#!'+sys.executable+'\nAPK='+repr(str(apk))+'\nSHELL='+repr(str(mksh))+'\nTOY='+repr(str(toy))+'\n'+actor);toy.chmod(0o755)
        simple={
            'id':"print('2000')",
            'getprop':"import sys;print({'ro.build.version.sdk':'35','ro.product.cpu.abi':'x86_64','ro.kernel.qemu.avd_name':'fixture','ro.boot.qemu.avd_name':'fixture','sys.boot_completed':'1'}[sys.argv[1]])",
            'pm':"print('package:/data/app/owned/base.apk')",
            'pidof':"import sys;print({'adbd':'11','zygote':'','zygote64':'22'}[sys.argv[1]])",
            'cat':"import sys,pathlib;arg=sys.argv[1];print((arg.split('/')[2]+' (fixture) '+' '.join(['S']+['0']*18+['100'])) if arg.startswith('/proc/') else pathlib.Path(arg).read_text(),end='\\n' if arg.startswith('/proc/') else '')",
        }
        for name,body in simple.items():
            p=helpers/name;p.write_text('#!'+sys.executable+'\n'+body+'\n');p.chmod(0o700)
        def utility_generation(path):
            value=path.stat()
            return ':'.join(str(x) for x in (value.st_dev,value.st_ino,format(value.st_mode,'x'),0,2000,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns))
        abi_raw=physical_readonly_reply(CORRELATION,boot.read_text().strip())
        frozen_generation=abi_raw.splitlines()[4].removeprefix('NAMED-SH-GENERATION ')
        for key,path in (('NAMED-SH-GENERATION',mksh),('SHELL-GENERATION',mksh),('TOYBOX-GENERATION',toy)):
            abi_raw=abi_raw.replace(key+' '+frozen_generation,key+' '+utility_generation(path))
        toy_sha=hashlib.sha256(toy.read_bytes()).hexdigest();shell_sha=hashlib.sha256(mksh.read_bytes()).hexdigest()
        abi_raw=abi_raw.replace('SHELL-HASH '+'a'*64,'SHELL-HASH '+shell_sha).replace('TOYBOX-HASH '+'a'*64,'TOYBOX-HASH '+toy_sha)
        abi_raw=abi_raw.replace('FD4 '+'a'*64,'FD4 '+toy_sha).replace('FD5 '+'a'*64,'FD5 '+toy_sha)
        abi=bundle._physical_abi_parse(abi_raw,CORRELATION,boot.read_text().strip())
        source=bundle._physical_batch_source(CORRELATION,abi)
        # Mechanical host fixture spellings only, explicitly not native ABI.
        source=source.replace('/system/bin/toybox',str(toy)).replace('/system/bin/mksh',str(mksh)).replace('/system/bin/sh',str(mksh)).replace('/system/bin/getprop',str(helpers/'getprop')).replace('/system/bin/pm',str(helpers/'pm')).replace('/data/local/tmp',str(guest)).replace('/proc/sys/kernel/random/boot_id',str(boot))
        if not Path('/proc/self/fd').exists():
            source=source.replace('/proc/$$/fd/','/dev/fd/')
        env={'PATH':str(helpers)+':'+os.defpath}
        child=subprocess.run([str(mksh),'-c',source],env=env,capture_output=True,timeout=30)
        self.assertEqual(0,child.returncode,child.stderr.decode()[-6000:])
        rows=bundle._physical_batch_parse(child.stdout.decode(),CORRELATION)
        self.assertEqual(10,len(rows));self.assertEqual('35\n',rows[0]['stdoutRaw'])
        self.assertEqual(hashlib.sha256(apk.read_bytes()).hexdigest()+'  /data/app/owned/base.apk\n',rows[-1]['stdoutRaw'])
        self.assertEqual([],list(guest.iterdir()))
        for drift in ('file','parent'):
            child=subprocess.run([str(mksh),'-c',source],env={**env,'DRIFT':drift},capture_output=True,timeout=30)
            self.assertNotEqual(0,child.returncode)
            self.assertIn(b'FRAME\t1\t',child.stdout)
            self.assertNotIn(b' CLEANED\n',child.stdout)
            with self.assertRaises(ValueError):bundle._physical_batch_parse(child.stdout.decode(),CORRELATION)
            # Only the inert TempFS owner removes the intentionally retained
            # uncertain fixtures; production never automatically replays them.
            for item in list(guest.iterdir()):shutil.rmtree(item)

    def test_actual_finite_40_file_backup_entry_and_staged_imports(self):
        from agent_tools.tests import test_android_installer_routing_backup as backup_tests
        helper=backup_tests.BackupTests();helper.case=self
        backend,request,_,log=helper.fixture()
        # Real production FILES and importer, with only the process limit/UID
        # OS assembly seam from the standalone helper fixture.
        self.assertEqual(40,len(bundle.FILES))
        if os.getuid()!=0:
            with self.assertRaisesRegex(ValueError,'routing_backup_root_required'):
                bundle.routing_backup(self.receipt,backend,request)
            output=self.root/('android-installer-component-baseline-'+request['correlationId'])/'routing-backup'
            self.assertFalse((output/'opening-routing.json').exists())
            self.assertTrue((output/'routingBefore-raw.json').is_file())
            self.assertTrue((output/'routingAfter-raw.json').is_file())
        else:
            result=bundle.routing_backup(self.receipt,backend,request)
            self.assertEqual(2,result['readCount']);self.assertEqual(7,json.loads(Path(result['path']).read_bytes())['version'])
            self.assertFalse(result['installerLeaseGranted']);self.assertTrue(result['limitsRestored'])
        self.assertEqual(2,len([json.loads(line) for line in log.read_text().splitlines() if json.loads(line)[-2:]==['routing','show']]))

    def test_full_staged_modules_load_without_repo_imports(self):
        before=sys.path[:]
        selected=bundle.modules(self.receipt)
        self.assertEqual(before,sys.path)
        self.assertEqual(len(bundle.FILES),len(bundle.load(self.receipt)))
        for value in selected.values():self.assertTrue(Path(value.__file__).is_relative_to(self.root/'stage'))
        actual=selected['lifecycle'].target_admission
        self.assertTrue(Path(actual.__file__).is_relative_to(self.root/'stage'))
        self.assertEqual(command._bounded_source(),selected['transport']._bounded_source())
        importer=selected['adapter'].__dict__['__builtins__']['__import__']
        with self.assertRaises(ImportError):importer('agent_tools.unstaged_native_module',{},None,('missing',),0)
        with self.assertRaises(ImportError):importer('pytest',{},None,(),0)

    def test_create_only_and_explicit_review(self):
        with self.assertRaises(FileExistsError):bundle.prepare(self.source_root,self.root/'stage',self.receipt['treeSha256'])
        with self.assertRaisesRegex(ValueError,'source_changed'):bundle.prepare(self.source_root,self.root/'second','0'*64)
        self.assertFalse((self.root/'second').exists())

    def test_same_byte_source_generation_replacement_refused(self):
        path=self.root/'stage'/bundle.FILES[0];raw=path.read_bytes();path.rename(path.with_suffix('.old'))
        path.write_bytes(raw);path.chmod(0o600);path.with_suffix('.old').unlink()
        with self.assertRaises(ValueError):bundle.modules(self.receipt)

    def test_same_byte_manifest_generation_replacement_refused(self):
        path=self.root/'stage/manifest.json';raw=path.read_bytes();path.rename(self.root/'old-manifest')
        path.write_bytes(raw);path.chmod(0o600)
        with self.assertRaises(ValueError):bundle.load(self.receipt)

    def test_parent_same_name_replacement_and_symlink_refused(self):
        original=self.root/'stage/scripts';original.rename(self.root/'scripts-preserved')
        shutil.copytree(self.root/'scripts-preserved',original)
        with self.assertRaises(ValueError):bundle.load(self.receipt)
        shutil.rmtree(original);original.symlink_to(self.root/'scripts-preserved',target_is_directory=True)
        with self.assertRaises((OSError,ValueError)):bundle.load(self.receipt)

    def test_extra_inventory_hardlink_and_private_mode_refused(self):
        path=self.root/'stage/private-extra';path.write_text('not reviewed')
        with self.assertRaises(ValueError):bundle.load(self.receipt)
        path.unlink();source=self.root/'stage'/bundle.FILES[0]
        os.link(source,self.root/'hardlink')
        with self.assertRaises(ValueError):bundle.load(self.receipt)
        (self.root/'hardlink').unlink();source.chmod(0o644)
        with self.assertRaises(ValueError):bundle.load(self.receipt)

    def test_namespace_source_executes_complete_staged_program(self):
        raw="NAMESPACE_SENTINEL='actual-prefix'\ndef coldboot_dispatch():\n raise AssertionError('dispatch must not run')\ncoldboot_dispatch()\n"
        prepared={'program':raw,'snapshots':{},'commandProgramSha256':hashlib.sha256(raw.encode()).hexdigest()}
        source=bundle.namespace_source(self.receipt,prepared);scope={};exec(source,scope)
        self.assertEqual('actual-prefix',scope['NAMESPACE_SENTINEL'])
        self.assertTrue(Path(scope['COMPONENT_MODULES']['adapter'].__file__).is_relative_to(self.root/'stage'))
        prepared['program']+='native_effect()\n'
        with self.assertRaises(ValueError):bundle.namespace_source(self.receipt,prepared)

    def test_transfer_measures_new_fd_pins_and_rejects_changed_payload(self):
        value=bundle.payload(self.receipt)
        received=bundle.stage_payload(value,self.root/'received',self.receipt['treeSha256'])
        self.assertEqual(bundle.load(self.receipt),bundle.load(received))
        self.assertNotEqual(self.receipt['files'],received['files'])
        selected=bundle.modules(received);self.assertTrue(Path(selected['lifecycle'].__file__).is_relative_to(self.root/'received'))
        with self.assertRaises(FileExistsError):bundle.stage_payload(value,self.root/'received',self.receipt['treeSha256'])
        changed=copy.deepcopy(value);changed['files'][bundle.FILES[0]]=base64.b64encode(b'changed source').decode()
        with self.assertRaises(ValueError):bundle.stage_payload(changed,self.root/'bad',self.receipt['treeSha256'])
        self.assertFalse((self.root/'bad').exists())
        del changed['files'][bundle.FILES[0]]
        with self.assertRaises(ValueError):bundle.stage_payload(changed,self.root/'bad',self.receipt['treeSha256'])

    def protected_production_prefix(self,receiver):
        # Execute the production census reader, exact diagnostic history statement,
        # trace wrappers and SDK alias history guard. Only task facts are TempFS.
        from agent_tools import android_avd_launch_recovery as census
        from agent_tools import android_avd_census_diagnostic as diagnostic
        from agent_tools import android_avd_sdk_alias_census as aliases
        records={}
        for name in ('failed','alias'):
            path=receiver/('android-avd-privileged-census-'+name+'.json')
            path.write_bytes((name+' protected original history\n').encode());path.chmod(0o600)
            records[name]={'generation':[path.stat().st_dev,path.stat().st_ino,path.stat().st_size,
                path.stat().st_mtime_ns,path.stat().st_ctime_ns,path.stat().st_mode,
                path.stat().st_uid,path.stat().st_gid,path.stat().st_nlink],
                'bytesRead':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'hashScope':'full'}
        tree=ast.parse(census._CENSUS.replace('__CFG__',repr({'failedCensus':{'correlationId':'failed','pin':records['failed']}})))
        self.assertEqual('capture()',ast.unparse(tree.body.pop()))
        root=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ROOT' for t in n.targets))
        root.value=ast.parse('pathlib.Path('+repr(str(receiver))+')',mode='eval').body
        historical=next(ast.literal_eval(n.value) for n in ast.walk(ast.parse(Path(diagnostic.__file__).read_text()))
            if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='historical' for t in n.targets))
        raw=ast.unparse(ast.fix_missing_locations(tree))+'\n'+historical+diagnostic._TRACE
        raw+=aliases._SAFE.replace('__KNOWN__',repr({'correlationId':'alias','capturePin':records['alias'],'files':{}}))
        raw+='\nimport ctypes,fcntl,signal,subprocess,time\nfrom pathlib import Path\nimport select,shutil\n'
        raw+=command.REMOTE+'\n'+command._bounded_source()+'\nCOMMAND_HOST=command_host_identity()\n'
        raw+='def coldboot_dispatch():\n raise AssertionError("no dispatch")\ncoldboot_dispatch()\n'
        return {'program':raw,'snapshots':{},'commandProgramSha256':hashlib.sha256(raw.encode()).hexdigest()},records

    def test_production_protected_history_prefix_root_carrier_boundary(self):
        receiver=self.root/'protected-receiver';receiver.mkdir(mode=0o700)
        prepared,records=self.protected_production_prefix(receiver)
        identity={'uid':0,'euid':0,'gid':0,'egid':0,'groups':[0]}
        facade=types.SimpleNamespace(**{name:getattr(os,name) for name in dir(os)})
        for name,key in [('getuid','uid'),('geteuid','euid'),('getgid','gid'),('getegid','egid'),('getgroups','groups')]:
            setattr(facade,name,lambda key=key:copy.deepcopy(identity[key]))
        real_open=os.open;protected={path.name for path in receiver.iterdir()}
        reads=[]
        def protected_open(path,*args,**kwargs):
            if str(path) in protected:
                reads.append((str(path),identity['uid']))
                if identity['uid']!=0:raise PermissionError('root0600 protected history')
            return real_open(path,*args,**kwargs)
        facade.open=protected_open
        def importer(name,*args,**kwargs):
            return facade if name=='os' and args and args[0] is scope else __import__(name,*args,**kwargs)
        import builtins
        scope={'__builtins__':dict(vars(builtins),__import__=importer)}
        source=bundle.carrier_source(self.receipt,prepared,CORRELATION)
        exec(source,scope)
        self.assertEqual([('android-avd-privileged-census-failed.json',0),('android-avd-privileged-census-alias.json',0)],reads)
        self.assertEqual(identity,scope['COMMAND_HOST'])
        self.assertEqual(bundle.load(self.receipt),bundle.load(scope['COMPONENT_RECEIPT']))
        # Same bytes and private modes; this initialization cannot run unprivileged.
        identity.update(uid=1000,euid=1000,gid=1000,egid=1000,groups=[1000])
        scope_builtins=scope['__builtins__'];scope.clear();scope['__builtins__']=scope_builtins
        with self.assertRaises(PermissionError):exec(source,scope)
        for name,record in records.items():
            path=receiver/('android-avd-privileged-census-'+name+'.json')
            self.assertEqual(0o600,stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(record['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())

    def test_carrier_requires_one_literal_source_bound_root(self):
        receiver=self.root/'root-binding';receiver.mkdir(mode=0o700)
        prepared,_=self.protected_production_prefix(receiver)
        for expression in ('caller_root()', "pathlib.Path('relative')", "pathlib.Path('/tmp/../unadmitted')"):
            tree=ast.parse(prepared['program'])
            node=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='ROOT' for t in n.targets))
            node.value=ast.parse(expression,mode='eval').body
            changed=copy.deepcopy(prepared);changed['program']=ast.unparse(ast.fix_missing_locations(tree))+'\n'
            changed['commandProgramSha256']=hashlib.sha256(changed['program'].encode()).hexdigest()
            with self.subTest(expression=expression),self.assertRaisesRegex(ValueError,'receiver_root_required'):
                bundle.carrier_source(self.receipt,changed,CORRELATION)
        self.assertFalse((receiver/('android-installer-component-bundle-'+CORRELATION)).exists())

    def test_root_receiver_baseline_evidence_under_exact_user_owned_root(self):
        receiver=self.root/'user-root';receiver.mkdir(mode=0o700)
        parent_inode=receiver.stat().st_ino;real_uid=os.getuid()
        proxy=types.SimpleNamespace(**vars(os))
        proxy.getuid=proxy.geteuid=proxy.getgid=proxy.getegid=lambda:0
        def info(value):
            owner=1000 if value.st_ino==parent_inode else (0 if value.st_uid==real_uid else value.st_uid)
            return types.SimpleNamespace(**{name:(owner if name in ('st_uid','st_gid') else getattr(value,name))
                for name in dir(value) if name.startswith('st_')})
        proxy.stat=lambda *args,**kwargs:info(os.stat(*args,**kwargs))
        proxy.fstat=lambda *args,**kwargs:info(os.fstat(*args,**kwargs))
        output=receiver/('android-installer-component-baseline-'+CORRELATION)
        with mock.patch.object(bundle,'os',proxy):
            with self.assertRaisesRegex(ValueError,'directory_unsafe'):bundle._new_directory(output)
            bundle._new_directory(output,receiver_root=receiver)
            self.assertEqual(0,bundle._directory(output)['generation'][3])
            bundle._write(output/'raw.json',b'complete raw baseline record\n')
            self.assertEqual(b'complete raw baseline record\n',bundle._read(output/'raw.json',True)[0])
            with self.assertRaisesRegex(ValueError,'receiver_root_changed'):
                bundle._stage(receiver/'unbound',{}, {}, '0'*64,receiver_root=self.root)
        self.assertEqual(0o700,stat.S_IMODE(output.stat().st_mode))
        self.assertEqual(0o600,stat.S_IMODE((output/'raw.json').stat().st_mode))

    @unittest.skipUnless(sys.platform=='linux' and os.getuid()==0,
                         'real protected history credential child requires Linux root')
    def test_real_posix_protected_history_carrier_child(self):
        self.root.chmod(0o755)
        receiver=self.root/'real-protected-receiver';receiver.mkdir(mode=0o700);os.chown(receiver,1000,1000)
        prepared,records=self.protected_production_prefix(receiver)
        source=bundle.carrier_source(self.receipt,prepared,CORRELATION)
        # Independent children, never a credential change in the test supervisor.
        def child(unprivileged):
            startup='import os,sys\n'
            if unprivileged:startup+='os.setgroups([1000]);os.setgid(1000);os.setuid(1000)\n'
            startup+="exec(compile(sys.stdin.buffer.read(),'<real-protected-carrier>','exec'))\n"
            return subprocess.run([sys.executable,'-I','-B','-c',startup],input=source.encode(),capture_output=True,timeout=20)
        denied=child(True)
        self.assertNotEqual(0,denied.returncode);self.assertIn(b'PermissionError',denied.stderr)
        credential_code='import os,json;print(json.dumps([os.getuid(),os.geteuid(),os.getgid(),os.getegid(),os.getgroups()]))'
        source+='\nfd=os.open('+repr(sys.executable)+',os.O_RDONLY)\ntry:\n result=command_bounded(['+repr(sys.executable)+',"-I","-B","-c",'+repr(credential_code)+'],fd,{"PATH":os.defpath},limit=4096,timeout=10)\n print(result["stdoutRaw"],end="")\nfinally:os.close(fd)\ncommand_host_guard()\n'
        accepted=child(False)
        self.assertEqual(0,accepted.returncode,accepted.stderr.decode())
        self.assertEqual([1000,1000,1000,1000,[1000]],json.loads(accepted.stdout))
        self.assertEqual(0,(receiver/('android-installer-component-bundle-'+CORRELATION)).stat().st_uid)
        for name,record in records.items():
            path=receiver/('android-avd-privileged-census-'+name+'.json')
            self.assertEqual(0,path.stat().st_uid);self.assertEqual(0o600,stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(record['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())

    def fixture(self):
        output=self.root/'output';output.mkdir(mode=0o700)
        base=self.root/'base.apk';base.write_bytes(b'actual-base-fixture-bytes')
        target=self.root/'target.apk';target.write_bytes(b'actual-target-fixture-bytes')
        sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
        state={'owner':OWNER,'revision':0,'sdk':'29','abi':'x86_64','avd':'owned-fixture',
               'uid':'2000','boot':'28b8f9af-efbb-44da-9836-0237cb714df9','ticks':100,
               'runtime':False,'operations':[{'id':CORRELATION,'final':True,'code':'OK'}]}
        state_path=self.root/'device.json';state_path.write_text(json.dumps(state))
        call_log=self.root/'calls.jsonl'
        body='''import sys,json,hashlib,pathlib,base64,re
state=json.loads(pathlib.Path(STATE).read_text());args=sys.argv[1:]
with pathlib.Path(LOG).open('a') as log:log.write(json.dumps(args)+'\\n')
if 'shell' in args or 'exec-out' in args:
 words=args[3:];words=[x for x in words if x!='-T']
 if args[2]=='exec-out':sys.stdout.buffer.write(pathlib.Path(BASE).read_bytes());sys.exit(0)
 if len(words)==1 and words[0].startswith('/system/bin/sh -c '):
  # Explicit external Android protocol seam. These rows do not prove mksh,
  # toybox, RLIMIT units, filesystem cleanup or native batch acceptance.
  if 'PHYSICAL-READONLY-4' in words[0]:
   correlation=re.search(r'WATCHDOG-CHILD ([0-9a-f-]{36})',words[0])[1]
   sys.stdout.write(state.get('batchAbiRaw',canonical_reply(correlation,state['boot'])));sys.exit(0)
  correlation=re.search(r'PHYSICAL-1 ([0-9a-f-]{36})',words[0])[1]
  processes=state.get('processCensus',''.join(name+'\\t'+str(pid)+'\\t'+str(pid)+' ('+name+') '+' '.join(['S']+['0']*18+[str(state['ticks'])])+'\\n' for pid,name in [(11,'adbd'),(22,'zygote64')]))
  values=[state['sdk'],state['abi'],state['avd'],state['avd'],'1',state['uid'],state['boot'],processes,'package:/data/app/owned/base.apk',hashlib.sha256(pathlib.Path(BASE).read_bytes()).hexdigest()+'  /data/app/owned/base.apk']
  print('PHYSICAL-1 '+correlation)
  for ordinal,value in enumerate(values,1):
   raw=(value+'\\n').encode();print('\\t'.join(['FRAME',str(ordinal),'0',str(len(raw)),'0','a'*64,'b'*64]));print(base64.b64encode(raw).decode());print('')
  print('EOF '+correlation+' CLEANED');sys.exit(0)
 elif words[:1]==['getprop']:
  values={'ro.build.version.sdk':state['sdk'],'ro.product.cpu.abi':state['abi'],'ro.kernel.qemu.avd_name':state['avd'],'ro.boot.qemu.avd_name':state['avd'],'sys.boot_completed':'1'};print(values[words[1]])
 elif words==['id','-u']:print(state['uid'])
 elif words[:1]==['cat']:print(state['boot'])
 elif words[:1]==['pm']:print('package:/data/app/owned/base.apk')
 elif words[:1]==['sha256sum']:print(hashlib.sha256(pathlib.Path(BASE).read_bytes()).hexdigest()+'  /data/app/owned/base.apk')
 elif words[:2]==['dumpsys','package']:print('versionName=2.2.2 versionCode=16840')
 elif len(words)==1 and words[0].startswith('sh -c '):
  if 'processCensus' in state:print(state['processCensus'],end='')
  else:
   for pid,name in [(11,'adbd'),(22,'zygote64')]:print(name+'\\t'+str(pid)+'\\t'+str(pid)+' ('+name+') '+' '.join(['S']+['0']*18+[str(state['ticks'])]))
 else:sys.exit(23)
else:
 owner=args[args.index('--controller-id')+1]
 data={'runtimeRunning':state['runtime'],'runtimeObservation':'stopped'}
 if args[-2:]==['operations','list']:data={'operations':state['operations']}
 elif args[-2:]==['updates','status']:data={'phase':'idle','activeOperationId':None,'installPhase':None,'installReceipt':None}
 print(json.dumps({'ok':True,'code':'OK','final':True,'controllerId':state['owner'],'configurationRevision':state['revision'],'data':data}))
'''
        program='#!'+sys.executable+'\nSTATE='+repr(str(state_path))+'\nLOG='+repr(str(call_log))+'\nBASE='+repr(str(base))+'\n'+inspect.getsource(physical_readonly_reply)+'\n'+body
        adb=self.root/'adb';adb.write_text(program);adb.chmod(0o700)
        jdk=self.root/'jdk';(jdk/'bin').mkdir(parents=True)
        java=jdk/'bin/java';java.write_text(program);java.chmod(0o700)
        stage_control=self.root/'stage-control';stage_control.write_bytes(b'actual-cli-stage')
        jdk_control=self.root/'jdk-control';jdk_control.write_bytes(b'actual-jdk-generation')
        stage_pin=bundle._read(stage_control)[1];jdk_pin=bundle._read(jdk_control)[1]
        selected=bundle.modules(self.receipt)
        cli=str(self.root/'product/bin/vpn-control')
        getter={'cli':cli,'stageId':'fixture-stage','packageSha256':sha(base),'manifestSha256':'a'*64,
                'generation':{'child':{'pid':17,'generation':'owned'},'guest':{'pid':18,'generation':'owned'}}}
        external={'selectedJdk':{'root':str(jdk),'files':{'bin/java':{'generation':bundle._pin(java.stat())}}},
                  'serial':'emulator-5684','getterIdentity':{k:getter[k] for k in ('cli','stageId','packageSha256','manifestSha256')},
                  'classpath':['fixture.jar'],'javaOptions':[],'backendSourceSha256':'c'*64}
        environment={key:'fixture' for key in ('ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER')}
        environment['PATH']=os.defpath
        osproxy=types.SimpleNamespace(**vars(os))
        osproxy.getuid=osproxy.geteuid=osproxy.getgid=osproxy.getegid=lambda:1000
        osproxy.getgroups=lambda:[1000,998]
        def popen(argv,**kwargs):
            # Portable test seam for the Linux FD executable spelling only.
            if not Path('/proc/self/fd').exists():kwargs['executable']=argv[0]
            return subprocess.Popen(argv,**kwargs)
        processproxy=types.SimpleNamespace(**vars(subprocess));processproxy.Popen=popen
        backend=dict(os=osproxy,pathlib=__import__('pathlib'),re=re,json=json,
                     select=select,time=time,subprocess=processproxy,GETTER=getter,EXTERNAL=external,
                     GETTER_RECORDS={},ROOT=self.root,LAUNCH={'adbPath':str(adb),'adbFacts':{'generation':bundle._pin(adb.stat())},
                                               'avd':'owned-fixture','device':'api29','environment':environment,'intent':{'reservation':{'leaseId':CORRELATION,'owner':'root-android'}}})
        def parents(path):
            chain,pins=bundle._parents(Path(path).parent)
            return [{'fd':fd,'path':name,'pin':pins[name]} for name,fd in chain],Path(path).name
        def guard_parents(chain):
            for item in chain:
                if bundle._pin(os.stat(item['path'],follow_symlinks=False))[:5]!=item['pin']:raise ValueError('actual_parent_changed')
        def stage():return bundle._read(stage_control)[1]
        def jdk_guard():
            if bundle._read(jdk_control)[1]!=jdk_pin:raise ValueError('external_jdk_generation_changed')
        backend.update(parent_fds=parents,guard_parents=guard_parents,close_parents=lambda chain:[os.close(x['fd']) for x in reversed(chain)],
            fp=bundle._pin,getter_stage=stage,external_jdk_guard=jdk_guard,public_cli_environment=lambda *a:environment,
            child_identity=lambda pid:copy.deepcopy(getter['generation']['child']),
            qemu_fact=lambda:{'actualQemu':'owned'},session_guest=lambda *a:copy.deepcopy(getter['generation']['guest']))
        import builtins
        fixture_import=lambda name,*args,**kwargs:backend[name] if name in backend else __import__(name,*args,**kwargs)
        backend['__builtins__']=dict(vars(builtins),__import__=fixture_import)
        context='import hashlib,json,os,pathlib,re,stat,errno,ctypes,fcntl,signal,subprocess,time,select,shutil\nfrom pathlib import Path\n'
        exec(context+ast.unparse(ast.parse(selected['transport'].REMOTE+selected['transport']._bounded_source())),backend)
        backend['COMMAND_HOST']=backend['command_host_identity']()
        backend['COMMAND_SOURCE_SHA']=hashlib.sha256(Path(selected['transport'].__file__).read_bytes()).hexdigest()
        # Run the exact owned getter/process/JDK functions against controlled
        # TempFS. Virtual native UID/GID facts are the sole platform metadata seam.
        proc=self.root/'proc';proc.mkdir();qemu=self.root/'qemu';qemu.write_bytes(b'actual-qemu-fixture');qemu.chmod(0o700)
        backend['LAUNCH'].update(qemuPath=str(qemu),port=5684)
        for pid in (17,18):
            entry=proc/str(pid);entry.mkdir()
            fields=['S','0','0','17']+['0']*15+[str(pid*100)]
            (entry/'stat').write_text(str(pid)+' (qemu) '+' '.join(fields))
            (entry/'cmdline').write_bytes((str(qemu)+'\0-avd\0owned-fixture\0-port\0'+'5684\0').encode() if pid==18 else b'owned-supervisor\0')
            (entry/'exe').symlink_to(qemu);(entry/'status').write_text('Uid:\t1000\t1000\t1000\t1000\n')
        jdk_paths=[]
        for relative in selected['transport'].readonly.proven.JDK_FILES:
            path=jdk/relative;path.parent.mkdir(parents=True,exist_ok=True)
            if relative!='bin/java':path.write_bytes(b'JAVA_VERSION="17.0.10"\n' if relative=='release' else b'actual-runtime-bytes')
            path.chmod(0o700 if relative=='bin/java' else 0o600);jdk_paths.append(path)
        root_inodes={path.stat().st_ino for path in jdk_paths}
        def native_fp(info):
            owner=0 if info.st_ino in root_inodes else 1000
            return [info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode,owner,owner,info.st_nlink]
        backend.update(fp=native_fp,stat=stat,hashlib=hashlib,PROC=proc,
                       boot=lambda:state['boot'],ticks=lambda path:int((path/'stat').read_text().rsplit(')',1)[1].split()[19]))
        backend['LAUNCH']['adbFacts']['generation']=native_fp(adb.stat())
        external.update(candidates={'jdk17':str(jdk)},jdkFiles=list(selected['transport'].readonly.proven.JDK_FILES))
        proven_tree=ast.parse(selected['transport'].readonly.proven._REMOTE.replace('__EXTERNAL__',repr({})))
        cold_tree=ast.parse(selected['transport'].readonly.getter_source.coldboot._BOOT.replace('__LAUNCH__',repr({})))
        getter_tree=ast.parse(selected['transport'].readonly.getter_source._GETTER.replace('__GETTER__',repr({})))
        needed={'external_file','external_jdk','external_jdk_guard','child_identity','session_guest','qemu_fact','getter_stage'}
        nodes=[node for tree in (proven_tree,cold_tree,getter_tree) for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in needed]
        exec(compile(context+ast.unparse(ast.Module(body=nodes,type_ignores=[])),'<actual-owned-getter-fixture>','exec'),backend)
        external['selectedJdk']=backend['external_jdk']('jdk17')
        getter['generation']={'child':backend['child_identity'](17),
                              'guest':backend['session_guest'](backend['child_identity'](17),{'qemuFact':backend['qemu_fact']()})}
        self.assertIsNotNone(getter['generation']['guest'])
        stage_dir=self.root/'android-cli-stage-fixture-stage';tree=stage_dir/'tree';(tree/'bin').mkdir(parents=True)
        launcher=tree/'bin/vpn-control';launcher.write_bytes(b'actual-product-launcher');launcher.chmod(0o700)
        getter['cli']=str(launcher);external['getterIdentity']['cli']=str(launcher)
        manifest={'directories':[{'path':'bin','mode':0o755}],
                  'files':[{'path':'bin/vpn-control','mode':0o700,'size':launcher.stat().st_size,'sha256':sha(launcher)}]}
        # Fixture modes must match the declared stage independently of inherited umask.
        for entry in manifest['directories']:
            (tree/entry['path']).chmod(entry['mode'])
            self.assertEqual(entry['mode'],stat.S_IMODE((tree/entry['path']).stat().st_mode))
        getter.update(manifest=manifest,rpmSha256='d'*64)
        for name,extra in [('intent.json',{'manifest':manifest}),('receipt.json',{'state':'published','cliPath':str(launcher)})]:
            path=stage_dir/name;path.write_text(json.dumps({'manifestSha256':getter['manifestSha256'],'rpmSha256':getter['rpmSha256'],**extra}));path.chmod(0o600)
        def read_fixed(path,limit):
            raw,pin=bundle._read(path)
            return {'raw':raw.decode(),'hashScope':'full','generation':native_fp(path.stat()),'sha256':pin['sha256']}
        def tree_facts(path):
            result={'.':{'kind':'directory','generation':native_fp(path.stat())}}
            for entry in path.rglob('*'):
                result[str(entry.relative_to(path))]={'kind':'directory' if entry.is_dir() else 'regular','generation':native_fp(entry.stat())}
            return result
        backend.update(read_fixed=read_fixed,tree_facts=tree_facts)
        stage_control=launcher;jdk_control=jdk/'lib/modules';cli=str(launcher)
        backup=output/'backup.json';backup.write_text(json.dumps({'type':'vpn_control_routing_rules','version':7,'rules':{}}));backup.chmod(0o600)
        pair={'sourceSha':'d32f719a08db57e5d40ce2bf77e0d7c5b42de557','signerSha256':'f'*64,
              'baseArtifactId':'sha256-'+sha(base),'baseSha256':sha(base),'basePath':str(base),'baseVersion':'2.2.2','baseCode':16840,
              'targetArtifactId':'sha256-'+sha(target),'targetSha256':sha(target),'targetPath':str(target),'targetVersion':'2.2.3','targetCode':16860}
        lease=self.root/'android-native-device-android-api29.lease';lease.write_text(json.dumps({'owner':'android-installer','host':'archlinux','device':'android-api29','correlationId':CORRELATION}));lease.chmod(0o600)
        intent={'host':'archlinux','device':'android-api29','schema':1,'correlationId':CORRELATION,'replayAllowed':False,'expectedOwner':OWNER,'expectedRevision':0,
                'expectedAvd':'owned-fixture','expectedApi':29,'expectedTerminal':'capture','pair':pair,
                'backupPath':str(backup),'backupSha256':sha(backup),'backupSize':backup.stat().st_size}
        intent_file=output/'intent.json';intent_file.write_text(json.dumps(intent));intent_file.chmod(0o600)
        args=types.SimpleNamespace(output=output,intent_file=intent_file,cli=Path(cli),serial='emulator-5684',
            avd='owned-fixture',api='29',expected_terminal='capture',base_apk=base,target_apk=target,
            base_sha256=sha(base),target_sha256=sha(target),base_version='2.2.2',target_version='2.2.3',
            base_code='16840',target_code='16860',adb=str(adb),cli_environment=None)
        return selected,backend,args,state_path,call_log,stage_control,jdk_control

    def test_restrictive_umask_fixture_manifest_and_actual_current_guard(self):
        previous=os.umask(0o077)
        try:
            selected,backend,args,*_=self.fixture()
            tree=self.root/'android-cli-stage-fixture-stage/tree'
            guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
            guard()
            for entry in backend['GETTER']['manifest']['directories']:
                self.assertEqual(entry['mode'],stat.S_IMODE((tree/entry['path']).stat().st_mode))
            # Keep the causal authority check: a real mode change still refuses.
            (tree/'bin').chmod(0o700)
            with self.assertRaisesRegex(ValueError,'getter_stage_directory_changed'):
                guard()
        finally:
            os.umask(previous)

    def shell_census(self,stats,roles):
        """Execute the actual fixed shell command, with only proc/pidof observations."""
        binaries=self.root/'census-bin';binaries.mkdir()
        for name,body in [('pidof','print(" ".join(map(str,ROLES.get(sys.argv[1],[]))))'),
                          ('cat','sys.stdout.write(STATS[int(sys.argv[1].split("/")[2])])')]:
            file=binaries/name
            file.write_text('#!'+sys.executable+'\nimport sys\nSTATS='+repr(stats)+'\nROLES='+repr(roles)+'\n'+body+'\n');file.chmod(0o700)
        result=subprocess.run(['/bin/sh','-c',bundle._PROCESS_READ],env={'PATH':str(binaries)+os.pathsep+os.defpath},capture_output=True,text=True)
        self.assertEqual(0,result.returncode);self.assertEqual('',result.stderr)
        return result.stdout

    def test_native_main_comm_role_census_actual_shell_and_current_guard(self):
        selected,backend,args,state_path,_,_,_=self.fixture()
        lines=NATIVE_API29_PROCESS_STAT.splitlines(keepends=True)
        stats={int(line.split()[0]):line for line in lines}
        actual=self.shell_census(stats,{'adbd':[1743],'zygote':[1665],'zygote64':[1664]})
        state=json.loads(state_path.read_bytes());state['processCensus']=actual;state_path.write_text(json.dumps(state))
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        self.assertEqual([{'role':'adbd','pid':1743,'name':'adbd','startTicks':597},
                          {'role':'zygote','pid':1665,'name':'main','startTicks':561},
                          {'role':'zygote64','pid':1664,'name':'main','startTicks':561}],guard.expected['processes'])
        guard()
        state['processCensus']=actual.replace('0 561 ','0 562 ');state_path.write_text(json.dumps(state))
        with self.assertRaisesRegex(ValueError,'component_guard_generation_changed'):guard()

    def test_role_census_old_comm_and_unknown_duplicate_malformed_refused(self):
        fields=' '.join(['S']+['0']*18+['100'])
        adbd='adbd\t11\t11 (adbd) '+fields
        zygote='zygote64\t22\t22 (zygote64) '+fields
        valid=adbd+'\n'+zygote+'\n'
        self.assertEqual({'role':'zygote64','pid':22,'name':'zygote64','startTicks':100},bundle._process_facts(valid)[1])
        self.assertEqual('zygote',bundle._process_facts(valid.replace('zygote64','zygote'))[1]['name'])
        cases=[valid.replace('zygote64\t22','unknown\t22'),
               valid.replace('zygote64\t22\t22','zygote64\t22\t23'),
               valid.replace('(zygote64)','(zygote)'),
               valid.replace('adbd\t11\t11 (adbd)','adbd\t11\t11 (main)'),
               valid.replace('zygote64\t22\t22','zygote64\t11\t11'),
               valid+zygote+'\n',valid.replace('\t',' '),
               valid.replace(' 100',' 0'),adbd+'\n',zygote+'\n',
               '22 (main) '+fields+'\n',valid+'garbage\n',valid.replace('(zygote64)','(unowned)'),valid.replace('\t22\t22','\t0\t0')]
        for raw in cases:
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError,'component_guard_process_unknown'):bundle._process_facts(raw)
        rows=[adbd]+['zygote\t'+str(pid)+'\t'+str(pid)+' (main) '+fields for pid in range(22,30)]
        with self.assertRaisesRegex(ValueError,'component_guard_process_unknown'):bundle._process_facts('\n'.join(rows))

    def actual_factory_functions(self,backend,device):
        """Hermetic full production templates; never read a live admission journal.

        The old API35 prerequisite called prepare(status) on ROOT/.rag_index.
        Its retained launch correctly rejects the current dirty source catalog.
        Source/context authentication needs actual compiler context and bodies,
        not that mutable native admission. TempFS supplies the OS observations.
        """
        from agent_tools import android_api35_coldboot_product_observation as api35
        from agent_tools import android_avd_launch_recovery as census
        reader=command.readonly
        getter=api35 if device=='api35' else reader.getter_source
        templates=(census._CENSUS.replace('__CFG__',repr({})),
                   getter.coldboot._BOOT.replace('__LAUNCH__',repr({})),
                   getter._GETTER.replace('__GETTER__',repr({})),
                   reader.proven._REMOTE.replace('__EXTERNAL__',repr({})),
                   command.REMOTE,command._bounded_source())
        # Keep all real template definitions, imports and statements. Compile
        # only: native top-level observation/dispatch is never executed here.
        program=bundle.modules(self.receipt)['adapter'].production_imports(device)+'\n'.join(templates)
        program=ast.unparse(ast.parse(program))+'\n'
        full_code=compile(program,'<hermetic-full-'+device+'-templates>','exec',dont_inherit=True)
        names={'component_command','command_binary','command_request','command_host_identity','command_host_guard','command_bounded',
               'getter_stage','child_identity','session_guest','qemu_fact','external_file','external_jdk','external_jdk_guard'}
        found=set()
        for value in full_code.co_consts:
            if isinstance(value,types.CodeType) and value.co_name in names:
                previous=backend[value.co_name]
                backend[value.co_name]=types.FunctionType(value,backend,argdefs=previous.__defaults__)
                found.add(value.co_name)
        self.assertEqual(names,found)

    def api35_fixture(self):
        selected,backend,args,state_path,log,stage,jdk=self.fixture()
        backend['LAUNCH']['device']='api35';backend['LAUNCH']['port']=5682;backend['EXTERNAL']['serial']='emulator-5682'
        args.serial='emulator-5682';args.api='35'
        state=json.loads(state_path.read_bytes());state['sdk']='35';state_path.write_text(json.dumps(state))
        cmd=backend['PROC']/'18/cmdline';cmd.write_bytes(cmd.read_bytes().replace(b'5684',b'5682'))
        backend['GETTER']['generation']={'child':backend['child_identity'](17),
            'guest':backend['session_guest'](backend['child_identity'](17),{'qemuFact':backend['qemu_fact']()})}
        intent=json.loads(args.intent_file.read_bytes());intent.update(device='android-api35',expectedApi=35)
        args.intent_file.write_text(json.dumps(intent))
        lease=self.root/'android-native-device-android-api29.lease';value=json.loads(lease.read_bytes());value['device']='android-api35'
        lease.unlink();lease=self.root/'android-native-device-android-api35.lease';lease.write_text(json.dumps(value));lease.chmod(0o600)
        return selected,backend,args,state_path,log,stage,jdk

    def test_actual_both_complete_factory_contexts_current_guard_and_lifecycle(self):
        # Both actual full programs authenticate all thirteen real function bodies.
        # Only OS observations and external child transport use the TempFS seam.
        selected,backend,args,_,log,_,_=self.fixture()
        self.actual_factory_functions(backend,'api29')
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        self.assertEqual('api29',guard.context_device);guard()
        # A separate case gives the API35 proof its own private admission journal.
        other=BundleTests();other.setUp()
        try:
            selected,backend,args,_,log,_,_=other.api35_fixture();other.actual_factory_functions(backend,'api35')
            old=next(value for value in compile(OLD_API29_GUARD_BACKEND,'<retained-api29-only-context>','exec').co_consts if isinstance(value,types.CodeType))
            historical=types.FunctionType(old,bundle.__dict__)
            with self.assertRaisesRegex(ValueError,'fixed_backend_required:component_command'):historical(selected,backend)
            # The complete API35 factory also runs the actual read-only baseline
            # before any installer intent or device lease is available.
            intent_raw=args.intent_file.read_bytes();args.intent_file.unlink()
            lease=other.root/'android-native-device-android-api35.lease';lease_raw=lease.read_bytes();lease.unlink()
            request={'host':'archlinux','device':'android-api35','correlationId':CORRELATION,'sourceSha':bundle._PRODUCT_SHA,
                'expectedOwner':OWNER,'expectedRevision':0,'expectedAvd':'owned-fixture','expectedApi':35,
                'packageSha256':backend['GETTER']['packageSha256'],'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
            baseline=bundle.baseline_read_only(other.receipt,backend,request)
            self.assertEqual('baseline-read-only',baseline['phase']);self.assertFalse(baseline['installerLeaseGranted'])
            self.assertFalse(lease.exists());self.assertFalse(args.intent_file.exists())
            args.intent_file.write_bytes(intent_raw);args.intent_file.chmod(0o600);lease.write_bytes(lease_raw);lease.chmod(0o600)
            guard=bundle.CurrentGuard(other.receipt,selected,backend,args)
            self.assertEqual('api35',guard.context_device)
            restore=selected['adapter'].install(selected['lifecycle'],selected['tls'],backend,args,guard)
            try:selected['lifecycle'].validate_intent(args)
            finally:restore()
            self.assertTrue(list(args.output.glob('component-cli-*.json')))
            rows=[json.loads(line) for line in log.read_text().splitlines()]
            self.assertTrue(any(row[-2:]==['updates','status'] for row in rows))
            self.assertFalse(any('install'in row or 'root'in row or 'unroot'in row for row in rows))
        finally:other.tearDown()

    def test_full_templates_do_not_access_live_historical_launch(self):
        from agent_tools import android_api35_coldboot_product_observation as api35
        selected,backend,args,_,_,_,_=self.api35_fixture()
        original=bundle._read
        def refuse_live(path,*args,**kwargs):
            if '.rag_index' in Path(path).parts:raise AssertionError('live native journal read')
            return original(path,*args,**kwargs)
        with (mock.patch.object(api35.coldboot,'prepare',side_effect=AssertionError('native prerequisite factory')),
              mock.patch.object(bundle,'_read',side_effect=refuse_live)):
            self.actual_factory_functions(backend,'api35')
            guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
            guard()

    def test_context_binding_refused_before_function_auth_or_baseline_output(self):
        selected,backend,args,_,log,_,_=self.fixture()
        backend['LAUNCH']['device']='api35'
        with mock.patch.object(bundle,'_guard_backend',side_effect=AssertionError('code auth reached')):
            with self.assertRaisesRegex(ValueError,'crossed_binding'):bundle.CurrentGuard(self.receipt,selected,backend,args)
            request={'host':'archlinux','device':'android-api29','correlationId':CORRELATION,'sourceSha':bundle._PRODUCT_SHA,
                'expectedOwner':OWNER,'expectedRevision':0,'expectedAvd':'owned-fixture','expectedApi':29,
                'packageSha256':backend['GETTER']['packageSha256'],'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
            with self.assertRaisesRegex(ValueError,'crossed_binding'):bundle.BaselineGuard(self.receipt,selected,backend,request)
            backend['LAUNCH']['device']='api29';request['reservation']={'unowned':'input'}
            with self.assertRaisesRegex(ValueError,'reservation_changed'):bundle.BaselineGuard(self.receipt,selected,backend,request)
        self.assertFalse(log.exists());self.assertFalse((self.root/('android-installer-component-baseline-'+CORRELATION)).exists())

    def test_api35_claim_does_not_adopt_api29_functions_or_mutated_context(self):
        selected,backend,args,_,log,_,_=self.api35_fixture()
        self.actual_factory_functions(backend,'api29')
        with self.assertRaisesRegex(ValueError,'fixed_backend_required:component_command'):bundle.CurrentGuard(self.receipt,selected,backend,args)
        self.assertFalse(log.exists())
        actual=selected['adapter'].production_imports
        selected['adapter'].production_imports=types.FunctionType(actual.__code__,dict(actual.__globals__))
        with self.assertRaisesRegex(ValueError,'context_source_changed'):bundle.CurrentGuard(self.receipt,selected,backend,args)
        selected['adapter'].production_imports=actual;selected['adapter']._PRODUCTION_IMPORTS+='import base64\n'
        with self.assertRaisesRegex(ValueError,'context_source_changed'):bundle.CurrentGuard(self.receipt,selected,backend,args)

    def test_production_carrier_then_staged_current_guard_unchanged_baseline(self):
        _,backend,args,_,log,_,_=self.fixture()
        original=backend.copy();proxy=backend['os']
        identity={'uid':0,'euid':0,'gid':0,'egid':0,'groups':[0]}
        for name,key in [('getuid','uid'),('geteuid','euid'),('getgid','gid'),('getegid','egid'),('getgroups','groups')]:
            setattr(proxy,name,lambda key=key:copy.deepcopy(identity[key]))
        proxy.setgroups=lambda groups:identity.update(groups=groups)
        proxy.setgid=lambda gid:identity.update(gid=gid,egid=gid)
        proxy.setuid=lambda uid:identity.update(uid=uid,euid=uid)
        protected={}
        prepared,records=self.protected_production_prefix(self.root)
        for name in records:protected['android-avd-privileged-census-'+name+'.json']=records[name]
        reads=[];real_open=os.open
        def opener(path,*args,**kwargs):
            if str(path) in protected:
                reads.append((str(path),identity['uid']))
                if identity['uid']!=0:raise PermissionError('protected original history')
            return real_open(path,*args,**kwargs)
        proxy.open=opener
        import builtins
        def importer(name,*args,**kwargs):
            return proxy if name=='os' and args and args[0] is backend else __import__(name,*args,**kwargs)
        backend['__builtins__']=dict(vars(builtins),__import__=importer)
        exec(bundle.carrier_source(self.receipt,prepared,CORRELATION),backend)
        # Current process/stage/JDK facts are the existing measured TempFS owned
        # getter catalogue. The production command functions remain installed.
        for name,value in original.items():
            if not name.startswith('command_') and name not in ('component_command','COMMAND_HOST'):backend[name]=value
        receipt=backend['COMPONENT_RECEIPT'];selected=backend['COMPONENT_MODULES']
        guard=bundle.CurrentGuard(receipt,selected,backend,args)
        restore=selected['adapter'].install(selected['lifecycle'],selected['tls'],backend,args,guard)
        try:selected['lifecycle'].validate_intent(args)
        finally:restore()
        self.assertEqual(0,guard.host['uid']);self.assertEqual(identity,backend['COMMAND_HOST'])
        self.assertEqual(2,len(reads));self.assertTrue(all(uid==0 for _,uid in reads))
        self.assertTrue(list(args.output.glob('component-cli-*.json')))
        rows=[json.loads(line) for line in log.read_text().splitlines()]
        self.assertTrue(any(row[-2:]==['updates','status'] for row in rows))
        self.assertFalse(any('install'in row or 'root'in row or 'unroot'in row for row in rows))

    def test_actual_staged_adapter_and_unchanged_lifecycle_installed_baseline(self):
        selected,backend,args,state_path,log,_,_=self.fixture()
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        restore=selected['adapter'].install(selected['lifecycle'],selected['tls'],backend,args,guard)
        try:
            intent=selected['lifecycle'].validate_intent(args)
            self.assertEqual(OWNER,intent['expectedOwner'])
            self.assertTrue(list(args.output.glob('component-cli-*.json')))
            rows=[json.loads(line) for line in log.read_text().splitlines()]
            self.assertTrue(any(row[-2:]==['updates','status'] for row in rows))
            self.assertFalse(any('install'in row or 'root'in row or 'unroot'in row for row in rows))
            raw=[json.loads(p.read_bytes()) for p in args.output.glob('component-guard-read-*.json')]
            self.assertTrue(any(v['record'].get('captures') for v in raw))
            self.assertTrue(all((p.stat().st_mode&0o777)==0o600 for p in args.output.glob('component-*.json')))
        finally:restore()

    def test_fresh_device_zygote_host_owner_and_stage_drift_refused(self):
        selected,backend,args,state_path,log,stage,jdk=self.fixture()
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        original=json.loads(state_path.read_bytes())
        for key,new in [('boot','d475b822-e8b5-4a8d-a27e-ecf3a07a2d88'),('ticks',101),('uid','0'),
                        ('avd','foreign'),('abi','arm64-v8a'),('owner',CORRELATION),('revision',1),
                        ('operations',[{'final':False}]),('runtime',True)]:
            state={**original,key:new};state_path.write_text(json.dumps(state))
            with self.subTest(key=key),self.assertRaises(ValueError):guard()
        state_path.write_text(json.dumps(original));backend['os'].getgroups=lambda:[1000]
        with self.assertRaisesRegex(ValueError,'host_identity_changed'):guard()
        backend['os'].getgroups=lambda:[1000,998];stage.write_bytes(b'changed-stage')
        with self.assertRaisesRegex(ValueError,'stage_file_changed'):guard()

    def test_read_only_baseline_precedes_installer_lease_and_never_calls_effect(self):
        selected,backend,args,state_path,log,_,_=self.fixture()
        (self.root/'android-native-device-android-api29.lease').unlink()
        args.intent_file.unlink()
        request={'host':'archlinux','device':'android-api29','correlationId':CORRELATION,
                 'sourceSha':bundle._PRODUCT_SHA,'expectedOwner':OWNER,'expectedRevision':0,
                 'expectedAvd':'owned-fixture','expectedApi':29,'packageSha256':backend['GETTER']['packageSha256'],
                 'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
        result=bundle.baseline_read_only(self.receipt,backend,request)
        self.assertEqual('baseline-read-only',result['phase']);self.assertFalse(result['installerLeaseGranted'])
        rows=[json.loads(line) for line in log.read_text().splitlines()]
        self.assertFalse(any('updates' in row or 'root' in row or 'unroot' in row for row in rows))
        self.assertFalse((self.root/'android-native-device-android-api29.lease').exists())
        self.assertFalse(args.intent_file.exists())
        for path in Path(result['evidenceDirectory']).glob('*.json'):
            value=json.loads(path.read_bytes());self.assertEqual('baseline-read-only',value['phase'])
            self.assertFalse(value['installerLeaseGranted'])

    def test_read_only_reservation_drift_and_wrong_source_refused(self):
        selected,backend,args,state_path,log,_,_=self.fixture()
        request={'host':'archlinux','device':'android-api29','correlationId':CORRELATION,
                 'sourceSha':bundle._PRODUCT_SHA,'expectedOwner':OWNER,'expectedRevision':0,
                 'expectedAvd':'owned-fixture','expectedApi':29,'packageSha256':backend['GETTER']['packageSha256'],
                 'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
        with self.assertRaisesRegex(ValueError,'fixed_request_required'):
            bundle.BaselineGuard(self.receipt,selected,backend,{**request,'sourceSha':'e'*40})
        guard=bundle.BaselineGuard(self.receipt,selected,backend,request)
        before=log.read_bytes();backend['LAUNCH']['intent']['reservation']={'leaseId':OWNER,'owner':'root-android'}
        with self.assertRaisesRegex(ValueError,'reservation_changed'):guard()
        self.assertEqual(before,log.read_bytes())

    def test_installer_guard_requires_actual_exact_lease_and_refuses_replacement(self):
        selected,backend,args,_,_,_,_=self.fixture()
        lease=self.root/'android-native-device-android-api29.lease'
        raw=lease.read_bytes();lease.write_text(json.dumps({'owner':'foreign','host':'archlinux','device':'android-api29','correlationId':CORRELATION}))
        with self.assertRaisesRegex(ValueError,'installer_lease_changed'):bundle.CurrentGuard(self.receipt,selected,backend,args)
        lease.write_bytes(raw);guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        lease.rename(self.root/'retained-lease');lease.write_bytes(raw);lease.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'installer_lease_changed'):guard()

    def test_package_and_jdk_drift_refused_with_raw_measurements(self):
        selected,backend,args,state_path,log,stage,jdk=self.fixture()
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        original=args.base_apk.read_bytes();args.base_apk.write_bytes(b'changed actual installed APK')
        with self.assertRaisesRegex(ValueError,'package_changed'):guard()
        args.base_apk.write_bytes(original);jdk.write_bytes(b'changed JDK control')
        with self.assertRaisesRegex(ValueError,'external_jdk_generation_changed'):guard()
        self.assertTrue(list(args.output.glob('component-guard-read-*.json')))

    def test_cross_device_installer_lease_cannot_admit_api29_carrier(self):
        selected,backend,args,_,log,_,_=self.fixture()
        intent=json.loads(args.intent_file.read_bytes());intent['device']='android-api35'
        args.intent_file.write_text(json.dumps(intent))
        (self.root/'android-native-device-android-api29.lease').unlink()
        wrong=self.root/'android-native-device-android-api35.lease'
        wrong.write_text(json.dumps({'owner':'android-installer','host':'archlinux',
                                    'device':'android-api35','correlationId':CORRELATION}));wrong.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'crossed_binding'):
            bundle.CurrentGuard(self.receipt,selected,backend,args)
        self.assertFalse(log.exists())
        self.assertFalse(list(args.output.glob('component-guard-*')))

    def test_api35_carrier_cannot_use_api29_lease_or_unlisted_serial(self):
        selected,backend,args,_,log,_,_=self.fixture()
        backend['EXTERNAL']['serial']='emulator-5682';backend['LAUNCH']['device']='api35'
        args.serial='emulator-5682';args.api='35'
        # The actual intent and lease remain API29; a crossed API35 carrier must
        # fail before both native reads and adoption of that otherwise valid lease.
        with self.assertRaisesRegex(ValueError,'crossed_binding'):
            bundle.CurrentGuard(self.receipt,selected,backend,args)
        self.assertFalse(log.exists())
        backend['EXTERNAL']['serial']='emulator-5684';backend['LAUNCH']['device']='api29';args.api='29'
        args.serial='emulator-5592'
        with self.assertRaisesRegex(ValueError,'crossed_binding'):
            bundle.CurrentGuard(self.receipt,selected,backend,args)
        self.assertFalse(log.exists())
        self.assertFalse(list(args.output.glob('component-guard-*')))

    def test_caller_getter_substitution_cannot_author_measured_success(self):
        selected,backend,args,_,_,_,_=self.fixture()
        backend['child_identity']=lambda pid:backend['GETTER']['generation']['child']
        with self.assertRaisesRegex(ValueError,'fixed_backend_required'):
            bundle.CurrentGuard(self.receipt,selected,backend,args)
        self.assertFalse(list(args.output.glob('component-guard-*')))

    def test_owned_process_real_proc_start_tick_drift_refused(self):
        selected,backend,args,_,_,_,_=self.fixture()
        guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        path=backend['PROC']/'18/stat';raw=path.read_text();path.write_text(raw.replace('1800','1801'))
        with self.assertRaisesRegex(ValueError,'owned_process_changed'):guard()

    def test_parent_race_during_create_refused_before_accepting_new_parent(self):
        parent=self.root/'race-parent';parent.mkdir(mode=0o700)
        original=os.mkdir
        def race(path,*args,**kwargs):
            result=original(path,*args,**kwargs)
            if str(path)=='racing' and 'dir_fd' in kwargs:
                parent.rename(self.root/'retained-parent');original(parent,0o700)
            return result
        with mock.patch.object(bundle.os,'mkdir',side_effect=race):
            with self.assertRaisesRegex(ValueError,'parent_changed'):bundle._new_directory(parent/'racing')
        self.assertTrue((self.root/'retained-parent/racing').is_dir())
        self.assertFalse((parent/'racing').exists())

    def test_intent_and_durable_admission_same_byte_replacement_refused(self):
        selected,backend,args,_,_,_,_=self.fixture();guard=bundle.CurrentGuard(self.receipt,selected,backend,args)
        path=args.output/'component-guard-current-admission.json';raw=path.read_bytes();path.rename(args.output/'retained-admission')
        path.write_bytes(raw);path.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'admission_changed'):guard()



    def full_context_program(self,selected,device):
        from agent_tools import android_api35_coldboot_product_observation as api35
        from agent_tools import android_avd_launch_recovery as census
        reader=command.readonly;getter=api35 if device=='api35' else reader.getter_source
        return ast.unparse(ast.parse(selected['adapter'].production_imports(device)+'\n'.join((
            census._CENSUS.replace('__CFG__',repr({})),
            getter.coldboot._BOOT.replace('__LAUNCH__',repr({})),
            getter._GETTER.replace('__GETTER__',repr({})),
            reader.proven._REMOTE.replace('__EXTERNAL__',repr({})),command.REMOTE,command._bounded_source()))))+'\n'

    def install_compiled_full_context(self,backend,program):
        names={'component_command','command_binary','command_request','command_host_identity','command_host_guard','command_bounded','getter_stage','child_identity','session_guest','qemu_fact','external_file','external_jdk','external_jdk_guard'}
        full=compile(program,'<actual-full-production-context>','exec',dont_inherit=True)
        found=set()
        for value in full.co_consts:
            if isinstance(value,types.CodeType) and value.co_name in names:
                previous=backend[value.co_name]
                backend[value.co_name]=types.FunctionType(value,backend,argdefs=previous.__defaults__)
                found.add(value.co_name)
        self.assertEqual(found,names)
        return names

    def test_complete_emitter_extra_import_context_requires_source_owned_rebinding(self):
        selected,backend,args,_,log,_,_=self.api35_fixture()
        original=self.full_context_program(selected,'api35')
        names=self.install_compiled_full_context(backend,original)
        reference={name:selected['adapter']._semantic_code(backend[name].__code__) for name in names}
        self.assertEqual(set(bundle._guard_backend(selected,backend,'api35'))&names,names)
        # Real direct assembler imports appended to the complete canonical
        # producer alter Python3.14 module-attribute instructions. Compile only;
        # no top-level observation or transport executes.
        self.install_compiled_full_context(backend,original+'import math,copy\n')
        mismatch={name for name in names if selected['adapter']._semantic_code(backend[name].__code__)!=reference[name]}
        self.assertTrue(all(isinstance(backend[name],types.FunctionType) and backend[name].__globals__ is backend for name in names))
        if mismatch:
            with self.assertRaisesRegex(ValueError,'component_guard_fixed_backend_required:'):
                bundle._guard_backend(selected,backend,'api35')
        else:
            # Older Python compilers do not make this optimization; coverage
            # stays active, without fabricating bytecode or skipping a guard.
            bundle._guard_backend(selected,backend,'api35')
        # A source-owned consumer must restore the ORIGINAL complete producer
        # CodeTypes before the genuine guard; no comparator/source waiver.
        self.install_compiled_full_context(backend,original)
        pins=bundle._guard_backend(selected,backend,'api35')
        self.assertTrue(all(pins[name][0] is backend[name] and pins[name][1] is backend[name].__code__ for name in names))
        bundle._selected_modules(self.receipt,selected)
        self.assertFalse(log.exists())

    def test_complete_emitter_rebinding_does_not_accept_foreign_globals(self):
        selected,backend,args,_,log,_,_=self.api35_fixture()
        names=self.install_compiled_full_context(backend,self.full_context_program(selected,'api35'))
        original=backend['component_command']
        backend['component_command']=types.FunctionType(original.__code__,dict(backend),argdefs=original.__defaults__)
        with self.assertRaisesRegex(ValueError,'component_guard_fixed_backend_required:component_command'):
            bundle._guard_backend(selected,backend,'api35')
        self.assertFalse(log.exists())


class CleanupReadmissionTests(unittest.TestCase):
    def campaign(self):
        from agent_tools.tests import test_android_installer_phase_guards as phase
        case=phase.InstallerPhaseGuardTests();case.setUp();self.addCleanup(case.doCleanups)
        original_children=case.product_children
        def children(*args,**kwargs):
            original_children(*args,**kwargs)
            adb=Path(case.backend['LAUNCH']['adbPath']);raw=adb.read_text()
            raw=raw.replace("if 'shell' in args or 'exec-out' in args:","if args[2:]==['reverse','--list']:print('');sys.exit(0)\nif 'shell' in args or 'exec-out' in args:")
            raw=raw.replace("elif words==['id','-u']:","elif words==['settings','get','global','http_proxy']:print('null')\n elif words==['id','-u']:")
            adb.write_text(raw);case.backend['LAUNCH']['adbFacts']['generation']=case.backend['fp'](adb.stat())
        case.product_children=children
        original=phase.FakeAdb
        class RecordedAdb(original):
            # Only OS responses are inert. Every recorded argv is emitted by
            # the actual TLS producer's command invocation, in original order.
            def record(self,words):self.records.append({'args':list(words),'exit':0,'stderr':'','stderrTruncated':False})
            def run(self,*words):
                value=super().run(*words);self.record(words);return value
            def shell(self,*words):
                value=super().shell(*words);self.record(('shell',*words));return value
            def unroot(self):
                value=super().unroot();self.record(('unroot',));return value
            def wait_for_device(self):
                value=super().wait_for_device();self.record(('wait-for-device',));return value
        with mock.patch.object(phase,'FakeAdb',RecordedAdb):receipt=case.campaign()
        census=json.loads(case.state_path.read_bytes())['processCensus'];rows=census.splitlines()
        prefix,rest=rows[0].rsplit(')',1);fields=rest.split();fields[19]=str(int(fields[19])+1)
        rows[0]=prefix+') '+' '.join(fields);case.state(processCensus='\n'.join(rows)+'\n')
        return case,receipt

    def test_actual_cleanup_adbd_epoch_separate_readmission(self):
        case,receipt=self.campaign();guard=case.guard
        expected=copy.deepcopy(guard.expected);phase_pins=copy.deepcopy(guard.phase_pins)
        with self.assertRaisesRegex(ValueError,'component_guard_generation_changed'):guard()
        successor=bundle.cleanup_readmission(guard);successor()
        self.assertEqual(expected,guard.expected);self.assertEqual(phase_pins,guard.phase_pins)
        self.assertFalse(json.loads((case.args.output/'component-cleanup-readmission.json').read_bytes())['installerEffectsAllowed'])
        with self.assertRaisesRegex(ValueError,'component_guard_generation_changed'):guard()
        case.state(owner='8cc56586-146b-45ce-afb6-33ed64a3092d')
        with self.assertRaises(ValueError):successor()

    def test_actual_cleanup_changed_terminal_and_foreign_zygote_refuse(self):
        case,receipt=self.campaign();state=json.loads(case.state_path.read_bytes())
        census=state['processCensus'];rows=census.splitlines();prefix,rest=rows[1].rsplit(')',1);fields=rest.split();fields[19]=str(int(fields[19])+1)
        rows[1]=prefix+') '+' '.join(fields);case.state(processCensus='\n'.join(rows)+'\n')
        with self.assertRaisesRegex(ValueError,'component_cleanup_foreign_generation'):bundle.cleanup_readmission(case.guard)

    def test_final_generation_closure_rejects_late_earlier_file_change(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();files=[root/name for name in ('first','later')]
            for file in files:file.write_bytes(b'original');file.chmod(0o600)
            pins={file:bundle._read(file,True)[1] for file in files}
            # A later body scan mutates the earlier file. No new pin adoption.
            files[0].write_bytes(b'foreign')
            with self.assertRaisesRegex(ValueError,'component_evidence_generation_changed'):bundle._evidence_generation_closure(pins)


if __name__=='__main__':unittest.main()
