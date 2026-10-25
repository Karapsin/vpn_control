"""Android shell owner through complete generated callers and real sockets.

The endpoint supplies Android's fixed tool commands. Source/stdio/admission and
actual process detach execute unchanged; no VM/native daemon is started here.
"""
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import uuid

from agent_tools import durable_remote_job as posix
from agent_tools import readiness_adb_jobs as jobs

if os.environ.get('VC_ADB_JOBS_BEFORE') in {'fifo', 'overflow'}:
    # Execute preserved source bytes in a fresh namespace, never a cached pyc.
    before = Path(__file__).parent/'fixtures'/'android_adb_jobs'/({'fifo':'mkfifo.before.source','overflow':'anonymous_overflow.before.source'}[os.environ['VC_ADB_JOBS_BEFORE']])
    old = types.ModuleType('agent_tools.adb_jobs_preserved_before')
    old.__package__ = 'agent_tools';old.__file__ = str(before)
    sys.modules[old.__name__] = old
    exec(compile(before.read_bytes(), str(before), 'exec'), old.__dict__)
    jobs = old


class ControlledGuest:
    def __init__(self, root):
        self.root = root
        self.parent = root/'guest'; self.parent.mkdir(mode=0o700)
        self.proc = root/'proc'; self.proc.mkdir(mode=0o700)
        self.boot = str(uuid.uuid4())
        self.socket_path=root/'adb.sock';self.binary=root/'adb';self.tools=root/'toybox';self.prop=root/'getprop'
        self.prop.write_text('#!'+sys.executable+'\nimport sys\nassert sys.argv[1:]==["ro.serialno"]\nprint("CONTROLLED_ANDROID_SERIAL")\n');self.prop.chmod(0o700)
        self.tools.write_text('#!'+sys.executable+'\n'+r'''
import hashlib,os,re,signal,stat,subprocess,sys
from pathlib import Path
sys.path.insert(0,__PROJECT__)
from agent_tools import durable_remote_job as process
command=sys.argv[1];args=sys.argv[2:]
if command=='id':
 assert args==['-u'];print(os.geteuid());raise SystemExit
if command=='cat' and len(args)==1 and args[0].startswith(__PROC__+'/'):
 path=args[0]
 if path==__PROC__+'/sys/kernel/random/boot_id':print(__BOOT__);raise SystemExit
 match=re.fullmatch(re.escape(__PROC__)+r'/([0-9]+)/stat',path)
 if match:
  pid=int(match[1]);birth=process._birth(pid)
  if birth is None:raise SystemExit(1)
  value=int(hashlib.sha256(birth.encode()).hexdigest()[:15],16)
  print(str(pid)+' (sh) S '+'0 '*18+str(value)+' 0 0');raise SystemExit
 raise SystemExit(1)
if command=='stat':
 assert args[0]=='-c';info=os.lstat(args[2]);value=args[1]
 for name,item in {'%d':str(info.st_dev),'%i':str(info.st_ino),'%u':str(info.st_uid),'%a':format(stat.S_IMODE(info.st_mode),'o'),'%h':str(info.st_nlink),'%s':str(info.st_size)}.items():value=value.replace(name,item)
 print(value);raise SystemExit
if command=='sha256sum':
 h=hashlib.sha256()
 while True:
  b=os.read(0,65536)
  if not b:break
  h.update(b)
 print(h.hexdigest()+'  -');raise SystemExit
if command=='readlink':
 assert args[0]=='-f';print(os.path.realpath(args[1]));raise SystemExit
if command=='sync':
 if hasattr(os,'sync'):os.sync()
 raise SystemExit
if command=='head' and len(args)==2 and args[0]=='-c':
 # Reproduce legal pipe read-ahead observed in Darwin head.
 limit=int(args[1]);kept=bytearray()
 while True:
  b=os.read(0,65536)
  if not b:break
  if len(kept)<limit:kept.extend(b[:limit-len(kept)])
 os.write(1,kept);raise SystemExit
if command=='mkfifo':
 os.write(2,b'mkfifo: Permission denied');raise SystemExit(1)
if command=='nohup':
 signal.signal(signal.SIGHUP,signal.SIG_IGN);os.execv(args[0],args)
if command=='setsid':
 try:os.setsid()
 except PermissionError:
  if os.fork():raise SystemExit
  os.setsid()
 os.execv(args[0],args)
path=shutil.which(command) if False else '/bin/'+command
if not os.path.exists(path):path='/usr/bin/'+command
os.execv(path,[path,*args])
'''.replace('__PROJECT__',repr(str(Path(__file__).resolve().parents[2]))).replace('__PROC__',repr(str(self.proc))).replace('__BOOT__',repr(self.boot)))
        self.tools.chmod(0o700)
        self.runtime=jobs.ShellRuntime('/bin/sh',str(self.tools),str(self.prop),str(self.proc),str(self.parent))
        self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.listener.bind(str(self.socket_path));self.listener.listen(10)
        self.stopped=False;self.requests=[];self.children=[];self.failures=[];self.lose_ack=False
        threading.Thread(target=self.serve,daemon=True).start()
        self.binary.write_text('#!'+sys.executable+'\n'+r'''
import json,os,socket,struct,sys
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(__SOCKET__)
head=json.dumps({'argv':sys.argv[1:]},separators=(',',':')).encode();s.sendall(struct.pack('!I',len(head))+head)
while True:
 b=os.read(0,65536)
 if not b:break
 s.sendall(b)
s.shutdown(socket.SHUT_WR);raw=bytearray()
while True:
 b=s.recv(65536)
 if not b:break
 raw.extend(b)
if len(raw)<12:raise SystemExit(255)
code,n,m=struct.unpack('!iii',raw[:12]);out=raw[12:12+n];err=raw[12+n:]
if len(err)!=m:raise SystemExit(254)
os.write(1,out);os.write(2,err);raise SystemExit(code)
'''.replace('__SOCKET__',repr(str(self.socket_path))))
        self.binary.chmod(0o700)
        self.connection='adb:owned:initial'
        binding=types.SimpleNamespace(adb=self.binary,server_port=5038,serial='emulator-5660')
        self.executor=jobs.AdbExecutor(binding,lambda:self.connection)

    def serve(self):
        while not self.stopped:
            try:channel,_=self.listener.accept()
            except OSError:return
            threading.Thread(target=self.handle,args=(channel,),daemon=True).start()

    def handle(self,channel):
        try:
            with channel:
                raw=bytearray()
                while True:
                    b=channel.recv(65536)
                    if not b:break
                    raw.extend(b)
                n=struct.unpack('!I',raw[:4])[0];request=json.loads(raw[4:4+n]);payload=raw[4+n:]
                argv=request['argv'];assert argv[:7]==['-H','127.0.0.1','-P','5038','-s','emulator-5660','shell'] and argv[7]=='-T'
                self.requests.append({'bytes':len(argv[-1].encode()),'input':len(payload)})
                child=subprocess.Popen(['/bin/sh','-c',argv[-1]],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.children.append(child);out,err=child.communicate(bytes(payload),timeout=30)
                if self.lose_ack and b'VCADB_ADMITTED_V1' in out:
                    self.lose_ack=False;return
                channel.sendall(struct.pack('!iii',child.returncode,len(out),len(err))+out+err)
        except BaseException as error:self.failures.append(type(error).__name__)

    def close(self):
        self.stopped=True;self.listener.close()
        # Signal only exact owned test workers still live, not coordinator/VMs.
        for path in self.parent.glob('vpn-control-jobs-*/*/owner'):
            try:
                pid=int(path.read_text().splitlines()[0])
                birth=posix._birth(pid)
                expected=path.read_text().splitlines()[1]
                if birth and str(int(hashlib.sha256(birth.encode()).hexdigest()[:15],16))==expected and os.getpgid(pid)==pid:
                    os.killpg(pid,signal.SIGKILL)
            except (OSError,ValueError):pass

    def original(self,program=None):
        guest=jobs.initialize(self.executor,'controlled-adb','controlled-avd',runtime=self.runtime)
        return jobs.OriginalJob(str(uuid.uuid4()),guest,program or jobs.counter_program(steps=8,interval='.02'),self.runtime)

    def terminal(self,original):
        deadline=time.monotonic()+15
        while time.monotonic()<deadline:
            value=jobs.observe(self.executor,original)
            if value['state']=='terminal':return value
            time.sleep(.02)
        raise AssertionError('Original guest job did not reach terminal')


@unittest.skipUnless(os.name=='posix','POSIX controlled Android endpoint')
class AdbJobTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.peer=ControlledGuest(self.root);self.addCleanup(self.peer.close)

    def test_generated_shell_original_owner_retains_complete_terminal_streams(self):
        original=self.peer.original();result=jobs.submit(self.peer.executor,original)
        self.assertEqual('pending',result['state'])
        value=self.peer.terminal(original)
        self.assertEqual(''.join('counter '+str(i)+'\n' for i in range(1,9)).encode(),value['stdout'])
        self.assertEqual(b'owner-start\nowner-terminal\n',value['stderr'])
        self.assertEqual(0,value['exitCode']);self.assertFalse(value['streamCapped'])
        path=Path(original.guest.path)/original.operation_id
        self.assertEqual('once\n',(path/'executions').read_text())
        self.assertEqual([],self.peer.failures)

    def test_native_fifo_permission_failure_is_causal_red_on_preserved_original(self):
        environment = dict(os.environ, VC_ADB_JOBS_BEFORE='fifo')
        test = __name__+'.AdbJobTests.test_generated_shell_original_owner_retains_complete_terminal_streams'
        result = subprocess.run([sys.executable, '-m', 'unittest', test], env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=25)
        self.assertEqual(1,result.returncode,result.stdout.decode())
        self.assertIn(b'Original guest job did not reach terminal',result.stdout)
        # Native shell_data_file policy denies named FIFO creation entirely.
        # The same complete generated-caller assertion passes on current source
        # in test_generated_shell_original_owner_retains_complete_terminal_streams.

    def test_pipe_read_ahead_overflow_is_causal_red_on_preserved_original(self):
        environment=dict(os.environ,VC_ADB_JOBS_BEFORE='overflow')
        test=__name__+'.AdbJobTests.test_bounded_spools_drain_overflow_without_replacing_mutation'
        result=subprocess.run([sys.executable,'-m','unittest',test],env=environment,
                              stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=20)
        self.assertEqual(1,result.returncode,result.stdout.decode())
        self.assertIn(b'True is not False',result.stdout)

    def test_lost_submission_ack_reconciles_same_original_without_replacement(self):
        original=self.peer.original();self.peer.lose_ack=True
        with self.assertRaisesRegex(jobs.AndroidJobError,'transport_unknown'):jobs.submit(self.peer.executor,original)
        self.peer.connection='adb:owned:successor'
        value=self.peer.terminal(original)
        self.assertEqual(original.operation_id,value['operationId'])
        with self.assertRaisesRegex(jobs.AndroidJobError,'transport_unknown'):jobs.submit(self.peer.executor,original)
        self.assertEqual('once\n',(Path(original.guest.path)/original.operation_id/'executions').read_text())

    def test_original_absence_proof_requires_same_private_root_generation(self):
        original=self.peer.original();value=jobs.observe(self.peer.executor,original)
        self.assertIs(True,value['provenUnsubmitted'])
        path=Path(original.guest.path);path.rename(path.with_name(path.name+'-old'));path.mkdir(mode=0o700)
        with self.assertRaisesRegex(jobs.AndroidJobError,'transport_unknown'):jobs.observe(self.peer.executor,original)

    def test_staged_source_never_reopens_after_capture_for_execution(self):
        # The exact source is captured into a private shell variable before eval.
        original=self.peer.original(jobs.FixedProgram('replace-source',b'printf "original\\n"; printf "altered" > "$J/program"',jobs._SOURCE_SHA))
        jobs.submit(self.peer.executor,original);value=self.peer.terminal(original)
        self.assertEqual(b'original\n',value['stdout'])
        self.assertEqual(0,value['exitCode'])

    def test_connection_loss_during_counter_keeps_same_guest_owner_and_progress(self):
        original=self.peer.original(jobs.counter_program(steps=40,interval='.04'))
        jobs.submit(self.peer.executor,original)
        deadline=time.monotonic()+5;before=None
        while time.monotonic()<deadline:
            before=jobs.observe(self.peer.executor,original)
            if before['state']=='running' and (Path(original.guest.path)/original.operation_id/'counter').exists():break
        self.assertEqual('running',before['state'])
        actor=before['owner'];path=Path(original.guest.path)/original.operation_id
        progress=int((path/'counter').read_text())
        # A fresh connection generation does not become a new job identity.
        self.peer.connection='adb:owned:after-disconnect'
        time.sleep(.35)
        self.assertGreater(int((path/'counter').read_text()),progress)
        after=jobs.observe(self.peer.executor,original)
        self.assertEqual(actor,after['owner'])
        terminal=self.peer.terminal(original)
        self.assertEqual(40,len(terminal['stdout'].splitlines()))
        self.assertEqual('once\n',(path/'executions').read_text())

    def test_concurrent_admission_never_launches_two_owners(self):
        original=self.peer.original();results=[]
        def launch():
            try:results.append(jobs.submit(self.peer.executor,original)['state'])
            except jobs.AndroidJobError:results.append('unknown')
        threads=[threading.Thread(target=launch) for unused in range(2)]
        for thread in threads:thread.start()
        for thread in threads:thread.join(timeout=10)
        self.assertEqual(['pending','unknown'],sorted(results))
        terminal=self.peer.terminal(original)
        self.assertEqual(8,len(terminal['stdout'].splitlines()))
        self.assertEqual('once\n',(Path(original.guest.path)/original.operation_id/'executions').read_text())

    def test_bounded_spools_drain_overflow_without_replacing_mutation(self):
        source=b'i=0; while [ "$i" -lt 2000 ]; do printf "public output\\n"; i=$((i+1)); done; printf "once\\n" > "$J/effect"'
        original=self.peer.original(jobs.FixedProgram('bounded-output',source,jobs._SOURCE_SHA,1024))
        jobs.submit(self.peer.executor,original);value=self.peer.terminal(original)
        self.assertIs(True,value['streamCapped']);self.assertEqual(1024,len(value['stdout']))
        self.assertEqual('once\n',(Path(original.guest.path)/original.operation_id/'effect').read_text())
        self.assertEqual(1,(Path(original.guest.path)/original.operation_id/'stdout.overflow').stat().st_size)

    def test_local_status_and_collection_never_touch_fixture_or_transport(self):
        original=self.peer.original();operation=original.operation_id;fixture='controlled-adb'
        path=jobs._operation_path(self.root,fixture,operation,create=True)
        binding=types.SimpleNamespace(adb=self.peer.binary,serial='emulator-5660',server_port=5038,avd_name='controlled-avd')
        jobs._admit(path,fixture,original,binding,['target','machine','connection',original.guest.boot,None,None])
        initial=jobs.workflow(self.root,'status',{'fixtureId':fixture,'operationId':operation})
        self.assertEqual('pending',initial['state'])
        jobs.submit(self.peer.executor,original);terminal=self.peer.terminal(original)
        jobs._cache(path,terminal,operation)
        requests=len(self.peer.requests)
        result=jobs.workflow(self.root,'collect',{'fixtureId':fixture,'operationId':operation})
        self.assertIs(True,result['complete']);self.assertEqual(8,len(result['stdout'].splitlines()))
        self.assertEqual(requests,len(self.peer.requests))
        blockers=jobs.active_operations(self.root,original.guest.target,original.guest.machine)
        self.assertIs(True,blockers['visibility']);self.assertEqual([],blockers['runningJobs']+blockers['unknownJobs']+blockers['reservations'])

    def test_repeat_start_observes_same_original_with_transport_only_recovery(self):
        from agent_tools import readiness_fixture_registry as registry
        from agent_tools import readiness
        original=self.peer.original();fixture_id='controlled-adb';operation=original.operation_id
        path=jobs._operation_path(self.root,fixture_id,operation,create=True)
        binding=types.SimpleNamespace(adb=self.peer.binary,serial='emulator-5660',server_port=5038,avd_name='controlled-avd')
        jobs._admit(path,fixture_id,original,binding,['target','machine','connection',original.guest.boot,None,None])
        jobs.submit(self.peer.executor,original)
        terminal=self.peer.terminal(original);jobs._cache(path,terminal,operation)
        fixture=types.SimpleNamespace(target=original.guest.target,machine=original.guest.machine,
            context=lambda **unused:object(),adapter=types.SimpleNamespace(
                support=types.SimpleNamespace(lane='android-emulator'),backend=types.SimpleNamespace(binding=binding),
                operation_scope=lambda **unused:nullcontext()))
        with mock.patch.object(registry,'registered_fixture_for_original',return_value=fixture), \
             mock.patch.object(readiness,'ensure_ready',return_value=object()) as ready, \
             mock.patch.object(jobs,'_executor',return_value=self.peer.executor):
            result=jobs.workflow(self.root,'start',{'fixtureId':fixture_id,'operationId':operation})
        self.assertEqual('terminal',result['state']);self.assertEqual(terminal['owner'],result['owner'])
        self.assertEqual(frozenset({'reconnect'}),ready.call_args.args[1].permitted_recoveries)
        self.assertEqual('once\n',(Path(original.guest.path)/operation/'executions').read_text())

    def test_public_reconcile_after_prelaunch_disconnect_submits_only_proven_absent_original(self):
        from agent_tools import readiness_fixture_registry as registry
        from agent_tools import readiness
        original=self.peer.original();fixture_id='controlled-adb';operation=original.operation_id
        path=jobs._operation_path(self.root,fixture_id,operation,create=True)
        binding=types.SimpleNamespace(adb=self.peer.binary,serial='emulator-5660',server_port=5038,avd_name='controlled-avd')
        jobs._admit(path,fixture_id,original,binding,['target','machine','connection',original.guest.boot,None,None])
        fixture=types.SimpleNamespace(target=original.guest.target,machine=original.guest.machine,
            context=lambda **unused:object(),adapter=types.SimpleNamespace(
                support=types.SimpleNamespace(lane='android-emulator'),backend=types.SimpleNamespace(binding=binding),
                operation_scope=lambda **unused:nullcontext()))
        args={'fixtureId':fixture_id,'operationId':operation}
        with mock.patch.object(registry,'registered_fixture_for_original',return_value=fixture), \
             mock.patch.object(readiness,'ensure_ready',return_value=object()), \
             mock.patch.object(jobs,'_executor',return_value=self.peer.executor):
            offline=self.root/'prelaunch-offline.sock';self.peer.socket_path.rename(offline)
            try:
                unknown=jobs.workflow(self.root,'reconcile',args)
                self.assertEqual('unknown',unknown['state'])
                self.assertFalse((Path(original.guest.path)/operation).exists())
            finally:offline.rename(self.peer.socket_path)
            restored=jobs.workflow(self.root,'reconcile',args)
        self.assertEqual(operation,restored['operationId'])
        terminal=self.peer.terminal(original)
        self.assertEqual(8,len(terminal['stdout'].splitlines()))
        self.assertEqual('once\n',(Path(original.guest.path)/operation/'executions').read_text())
        self.assertEqual(1,len(list(path.glob('retry-*.json'))))

    def test_unknown_or_incomplete_local_admission_prevents_idle_proof(self):
        original=self.peer.original();fixture='controlled-adb';operation=original.operation_id
        path=jobs._operation_path(self.root,fixture,operation,create=True)
        invisible=jobs.active_operations(self.root,original.guest.target,original.guest.machine)
        self.assertIs(False,invisible['visibility'])
        binding=types.SimpleNamespace(adb=self.peer.binary,serial='emulator-5660',server_port=5038,avd_name='controlled-avd')
        jobs._admit(path,fixture,original,binding,['target','machine','connection',original.guest.boot,None,None])
        reserved=jobs.active_operations(self.root,original.guest.target,original.guest.machine)
        self.assertEqual([operation],reserved['reservations'])
        jobs._cache(path,{'state':'unknown'},operation,reason='android_job_transport_unknown')
        unknown=jobs.active_operations(self.root,original.guest.target,original.guest.machine)
        self.assertEqual([operation],unknown['unknownJobs'])

    def test_actual_socket_outage_preserves_original_counter_then_reconnects(self):
        original=self.peer.original(jobs.counter_program(steps=40,interval='.04'))
        jobs.submit(self.peer.executor,original)
        before=jobs.observe(self.peer.executor,original)
        path=Path(original.guest.path)/original.operation_id
        deadline=time.monotonic()+5
        while not (path/'counter').exists() and time.monotonic()<deadline:time.sleep(.02)
        progress=int((path/'counter').read_text())
        offline=self.root/'adb-offline.sock';self.peer.socket_path.rename(offline)
        try:
            with self.assertRaisesRegex(jobs.AndroidJobError,'transport_unknown'):
                jobs.observe(self.peer.executor,original)
            time.sleep(.3)
            self.assertGreater(int((path/'counter').read_text()),progress)
        finally:offline.rename(self.peer.socket_path)
        self.peer.connection='adb:owned:restored'
        terminal=self.peer.terminal(original)
        self.assertEqual(40,len(terminal['stdout'].splitlines()))
        if before['owner']['pid']:
            self.assertEqual(before['owner'],terminal['owner'])
        self.assertEqual('once\n',(path/'executions').read_text())

    def test_fresh_local_client_observes_original_sealed_result(self):
        original=self.peer.original();fixture='controlled-adb';operation=original.operation_id
        path=jobs._operation_path(self.root,fixture,operation,create=True)
        binding=types.SimpleNamespace(adb=self.peer.binary,serial='emulator-5660',server_port=5038,avd_name='controlled-avd')
        jobs._admit(path,fixture,original,binding,['target','machine','connection',original.guest.boot,None,None])
        jobs.submit(self.peer.executor,original);first=self.peer.terminal(original)
        script=("from pathlib import Path;from types import SimpleNamespace;import json;from agent_tools import readiness_adb_jobs as j;"
                "o,a=j._original(Path("+repr(str(path))+"),"+repr(fixture)+","+repr(operation)+");"
                "e=j.AdbExecutor(SimpleNamespace(adb=Path(a['adb']['path']),serial=a['adb']['serial'],server_port=a['adb']['port']),lambda:'adb:owned:fresh');"
                "v=j.observe(e,o);print(json.dumps({'operationId':v['operationId'],'state':v['state'],'owner':v['owner'],'stdout':v['stdout'].decode(),'stderr':v['stderr'].decode()}))")
        result=subprocess.run([sys.executable,'-c',script],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(0,result.returncode,result.stderr);value=json.loads(result.stdout)
        self.assertEqual('terminal',value['state']);self.assertEqual(operation,value['operationId'])
        self.assertEqual(first['owner'],value['owner']);self.assertEqual(first['stdout'].decode(),value['stdout'])


if __name__=='__main__':unittest.main()
