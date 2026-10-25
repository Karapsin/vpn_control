"""Complete generated callers across real sockets; guest sudo is the sole shim.

The sudo endpoint maps root identity/filesystem ownership in a private fixture.
It exercises exact emitted receiver/verifier/wrapper bytes without host privilege.
Actual privileged native acceptance remains a separate task-owned guest check.
"""
from contextlib import contextmanager
import errno
import hashlib
import importlib
import json
import os
from pathlib import Path
import pwd
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import uuid
from unittest import mock

from agent_tools import ssh_automatic_program as automatic
from agent_tools import ssh_privileged_program as privileged
from agent_tools import ssh_transport as transport
from agent_tools.tests.test_ssh_automatic_program import PeerFixture

TOOLS = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / 'fixtures/ssh_privileged_program'


class SocketGuest:
    def __init__(self, root):
        self.root = root
        self.base = PeerFixture(root)
        self.socket = root / 'guest.sock'
        self.claims = root / 'root-claims'; self.claims.mkdir(mode=0o700)
        self.mode = root / 'sudo-mode'; self.mode.write_text('cached')
        self.sudo = root / 'sudo'
        self.sudo.write_text('#!' + sys.executable + '\n' + r'''
import json,os,pwd,sys
from pathlib import Path
mode=Path(__MODE__).read_text();args=sys.argv[1:]
while args and args[0] in ('-n','-k','-S','--'):args.pop(0)
if args[:2]==['-p','']:
 args=args[2:]
 if args[:1]==['--']:args.pop(0)
if mode=='denied':sys.stderr.write('sudo: authentication failed\n');raise SystemExit(1)
if mode=='overflow':os.write(1,b'PRIVATE-fixture-password-42'+b'X'*8388609);raise SystemExit(1)
if mode in ('consumed','echo'):
 value=bytearray()
 while not value.endswith(b'\n'):
  part=os.read(0,1)
  if not part:raise SystemExit(2)
  value.extend(part)
 if mode=='echo':os.write(1,value);os.write(2,value)
 value.clear()
if args[0] not in ('python3','/usr/bin/python3'):raise SystemExit(3)
index=args.index('-c');source=args[index+1];rest=args[index+2:]
if not rest or not rest[0].startswith('{'):
 os.execv(sys.executable,[sys.executable,'-I','-B','-c',source,*rest])
shim=r"""
import os,sys,json,pwd
from pathlib import Path
original_fstat=os.fstat;original_realpath=os.path.realpath
receipt=json.loads(sys.argv[1]);root=Path(receipt['directory'])
protected={root.stat().st_ino,(root/'program.source').stat().st_ino};ordinary=os.getuid()
os.environ['SUDO_UID']=str(ordinary);os.environ['SUDO_USER']=pwd.getpwuid(ordinary).pw_name
def root_stat(fd):
 s=original_fstat(fd)
 if s.st_uid==ordinary and s.st_ino not in protected:
  values=list(s);values[4]=0;s=os.stat_result(values)
 return s
os.fstat=root_stat
os.getuid=lambda:0;os.geteuid=lambda:0
os.path.realpath=lambda p,*a,**k:__CLAIMS__ if p=='/var/tmp' else original_realpath(p,*a,**k)
"""
# Only the sudo executable boundary emulates uid0; generated source is intact.
os.execv(sys.executable,[sys.executable,'-I','-B','-c',shim+'\n'+source,*rest])
'''.replace('__MODE__', repr(str(self.mode))).replace('__CLAIMS__', repr(str(self.claims))))
        self.sudo.chmod(0o700)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.socket)); self.listener.listen(8)
        self.stop = threading.Event(); self.events=[]; self.failures=[]
        self.thread = threading.Thread(target=self.serve, daemon=True); self.thread.start()
        self.base.binary.write_text('#!'+sys.executable+'\n'+r'''
import json,os,socket,struct,sys
request=json.dumps({'command':sys.argv[-1]},separators=(',',':')).encode()
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect(__SOCKET__)
s.sendall(struct.pack('!I',len(request))+request)
while True:
 part=os.read(0,65536)
 if not part:break
 s.sendall(part)
s.shutdown(socket.SHUT_WR);raw=bytearray()
while True:
 part=s.recv(65536)
 if not part:break
 raw.extend(part)
s.close();code,outsize,errsize=struct.unpack('!iii',raw[:12]);out=raw[12:12+outsize];err=raw[12+outsize:]
if len(err)!=errsize:raise SystemExit(98)
os.write(1,out);os.write(2,err);raise SystemExit(code)
'''.replace('__SOCKET__',repr(str(self.socket))))
        self.base.binary.chmod(0o700)

    def serve(self):
        while not self.stop.is_set():
            try: connection,_=self.listener.accept()
            except OSError: return
            threading.Thread(target=self.handle,args=(connection,),daemon=True).start()

    def handle(self,connection):
        try:
            with connection:
                # Poll, never block: Darwin can drop the wakeup for the client's
                # SHUT_WR, stranding both ends until the stage deadline kills it.
                raw=bytearray();connection.settimeout(.1)
                while True:
                    try:part=connection.recv(65536)
                    except socket.timeout:
                        if self.stop.is_set():raise
                        continue
                    if not part:break
                    raw.extend(part)
                connection.settimeout(None)
                size=struct.unpack('!I',raw[:4])[0];request=json.loads(raw[4:4+size]);payload=bytes(raw[4+size:])
                command=shlex.split(request['command']);self.events.append({'commandBytes':len(request['command'].encode()),'first':command[0]})
                if len(request['command'].encode())>60000:raise ValueError('command bound')
                if command[0] in ('sudo','/usr/bin/sudo'):command[0]=str(self.sudo)
                elif command[0] in ('python3','/usr/bin/python3'):command[0]=sys.executable
                environment=dict(os.environ);environment['PATH']=str(self.root)+os.pathsep+environment.get('PATH','')
                result=subprocess.run(command,input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,env=environment)
                connection.sendall(struct.pack('!iii',result.returncode,len(result.stdout),len(result.stderr))+result.stdout+result.stderr)
        except BaseException as error:self.failures.append(type(error).__name__)

    def close(self):
        self.stop.set();self.listener.close()

    @contextmanager
    def environment(self):
        with self.base.environment(),mock.patch.dict(os.environ,{'PATH':str(self.root)+os.pathsep+os.environ.get('PATH','')}):yield


@unittest.skipUnless(os.name=='posix' and hasattr(os,'getuid'),'POSIX coordinator')
class PrivilegedCarrierTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.root.chmod(0o700)
        self.peer=SocketGuest(self.root);self.addCleanup(self.peer.close)
        self.config=transport.load_config(self.root)

    def argv(self,source,*,password=True,force=False):
        command=(*(('sudo','-S','-p','','--') if password else ('sudo','-n','--')),'python3','-I','-B','-c','exec('+repr(source)+')','public-arg')
        return (transport.build_saved_program_argv if force else transport.build_ssh_argv)(self.config,'explicit-peer',5,command=command,ssh_binary=str(self.peer.base.binary),nested_ssh_binary=str(self.peer.base.binary))

    def source(self,size=68000):
        marker=self.root/'once'
        return ('PADDING='+repr('X'*size)+'\nimport json,sys\nfrom pathlib import Path\n'
            'p=Path('+repr(str(marker))+');p.open("a").write("once\\n")\n'
            'data=sys.stdin.buffer.read();print(json.dumps({"payload":list(data),"arguments":sys.argv[1:]}))\n')

    def run_plan(self,argv,payload):
        with self.peer.environment():
            result=transport.run_ssh(argv,input=payload,capture_output=True,timeout=15)
        self.assertFalse(self.peer.failures)
        return result

    def test_socket_complete_password_consumed_and_cached_preserves_payload(self):
        for mode in ('consumed','cached','echo'):
            with self.subTest(mode=mode):
                self.peer.mode.write_text(mode)
                marker=self.root/'once'
                if marker.exists():marker.unlink()
                secret=b'PRIVATE-fixture-password-42'
                payload=b'first arbitrary payload line\n\x00\xffsecond line\n'
                argv=self.argv(self.source())
                result=self.run_plan(argv,secret+b'\n'+payload)
                self.assertEqual(0,result.returncode,result.stderr)
                out=result.stdout.replace(b'[REDACTED]\n',b'')
                self.assertEqual(list(payload),json.loads(out)['payload'])
                self.assertEqual(['public-arg'],json.loads(out)['arguments'])
                self.assertEqual('once\n',marker.read_text())
                self.assertNotIn(secret,result.stdout+result.stderr)
                for path in (self.root/'.rag_index').rglob('*'):
                    if path.is_file():self.assertNotIn(secret,path.read_bytes())
                self.assertTrue(all(x['commandBytes']<=60000 for x in self.peer.events))
                count=len(self.peer.events)
                with self.peer.environment(),self.assertRaises((FileExistsError,ValueError)):
                    transport.run_ssh(argv,input=secret+b'\n'+payload,capture_output=True)
                self.assertEqual(count,len(self.peer.events))

    def test_socket_complete_passwordless(self):
        payload=b'\x00original binary payload\xff\n'
        result=self.run_plan(self.argv(self.source(),password=False),payload)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual(list(payload),json.loads(result.stdout)['payload'])
        self.assertEqual('once\n',(self.root/'once').read_text())

    def test_before_predicted_oversize_refuses_same_complete_caller(self):
        before=FIXTURE/'automatic.before.source'
        self.assertEqual(json.loads((FIXTURE/'provenance.json').read_bytes())['beforeimages']['ssh_automatic_program.py']['sha256'],hashlib.sha256(before.read_bytes()).hexdigest())
        directory=self.root/'before';directory.mkdir()
        (directory/'ssh_automatic_program.py').write_bytes(before.read_bytes())
        shutil.copyfile(TOOLS/'native_review_source_closure.py',directory/'native_review_source_closure.py')
        name='agent_tools._privileged_before_'+uuid.uuid4().hex
        module=types.ModuleType(name);module.__file__=str(directory/'ssh_automatic_program.py');module.__package__='agent_tools'
        with mock.patch.dict(sys.modules,{name:module}):exec(compile(before.read_bytes(),module.__file__,'exec'),module.__dict__)
        with mock.patch.object(transport,'_automatic_module',return_value=module):
            with self.assertRaisesRegex(ValueError,'oversized_command_form_unsupported'):
                self.run_plan(self.argv(self.source()),b'PRIVATE-fixture-password-42\npayload')
        self.assertFalse(self.peer.events);self.assertFalse((self.root/'once').exists())
        result=self.run_plan(self.argv(self.source()),b'PRIVATE-fixture-password-42\npayload')
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual('once\n',(self.root/'once').read_text())

    def test_short_cached_sudo_actual_before_leaks_and_fixed_frames(self):
        directory=self.root/'cached-before';directory.mkdir()
        preserved=FIXTURE/'transport_cached.before.source'
        manifest=json.loads((FIXTURE/'provenance.json').read_bytes())
        self.assertEqual(manifest['beforeimages']['ssh_transport.py.cached-password']['sha256'],hashlib.sha256(preserved.read_bytes()).hexdigest())
        (directory/'ssh_transport.py').write_bytes(preserved.read_bytes())
        for name in ('ssh_automatic_program.py','ssh_privileged_program.py','private_config_custody.py','native_review_source_closure.py'):
            shutil.copyfile(TOOLS/name,directory/name)
        name='_cached_sudo_before_'+uuid.uuid4().hex;package=types.ModuleType(name);package.__path__=[str(directory)]
        sys.modules[name]=package
        try:
            old=importlib.import_module(name+'.ssh_transport');config=old.load_config(self.root)
            source='import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())'
            command=('sudo','-S','-p','','--','python3','-I','-B','-c',source)
            before=old.build_ssh_argv(config,'explicit-peer',5,command=command,ssh_binary=str(self.peer.base.binary))
            with self.peer.environment():result=old.run_ssh(before,input=b'PRIVATE-fixture-password-42\npayload',capture_output=True,timeout=10)
            self.assertEqual(0,result.returncode,result.stderr)
            self.assertIn(b'PRIVATE-fixture-password-42',result.stdout,'Preserved inline carrier did not reproduce credential echo')
            fixed=transport.build_ssh_argv(self.config,'explicit-peer',5,command=command,ssh_binary=str(self.peer.base.binary))
            self.assertIsInstance(fixed,automatic.PlannedArgv)
            result=self.run_plan(fixed,b'PRIVATE-fixture-password-42\npayload')
            self.assertEqual(0,result.returncode,result.stderr)
            self.assertEqual(b'payload',result.stdout)
            self.assertNotIn(b'PRIVATE-fixture-password-42',result.stdout+result.stderr)
        finally:
            for key in list(sys.modules):
                if key==name or key.startswith(name+'.'):sys.modules.pop(key,None)

    def test_actual_kernel_e2big_password_carrier_file_fallback(self):
        argv=self.argv(self.source(size=32000),password=False);self.assertIsInstance(argv,transport.BoundInlineArgv)
        argmax=os.sysconf('SC_ARG_MAX');remaining=argmax-20000-sum(len(os.fsencode(k))+len(os.fsencode(v))+2 for k,v in os.environ.items());padding={};index=0
        if not 65536<=argmax<=8*1024*1024:self.skipTest('finite ARG_MAX')
        while remaining>128:
            name='VC_PRIVILEGED_BUDGET_'+str(index);value='E'*min(60000,remaining-len(name)-2)
            padding[name]=value;remaining-=len(name)+len(value)+2;index+=1
        with self.peer.environment(),mock.patch.dict(os.environ,padding):
            with self.assertRaises(OSError) as native:subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            self.assertEqual(errno.E2BIG,native.exception.errno)
            self.assertFalse(self.peer.events)
            result=transport.run_ssh(argv,input=b'payload',capture_output=True,timeout=15)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertEqual('once\n',(self.root/'once').read_text())
        journal=self.root/'.rag_index/ssh-automatic-program'/argv.saved_plan.correlation
        self.assertTrue((journal/'prelaunch-refusal.json').exists())
        self.assertEqual(2,len(self.peer.events))

    def test_unknown_auth_or_malformed_secret_does_not_disclose_or_execute(self):
        for mode,payload in (('denied',b'PRIVATE-fixture-password-42\npayload'),('cached',b'PRIVATE-fixture-password-42\r\npayload'),('cached',b'X'*514+b'\n')):
            with self.subTest(mode=mode,payload_bytes=len(payload)):
                self.peer.mode.write_text(mode)
                result=self.run_plan(self.argv(self.source()),payload)
                self.assertNotEqual(0,result.returncode)
                self.assertNotIn(b'PRIVATE-fixture-password-42',result.stdout+result.stderr)
                self.assertFalse((self.root/'once').exists())

    def test_remote_root_claim_refuses_lost_ack_reexecution(self):
        argv=self.argv(self.source())
        with self.peer.environment(),automatic.automatic_submission(argv) as submitted:
            first=subprocess.run(submitted,input=b'PRIVATE-fixture-password-42\npayload',capture_output=True,timeout=15)
            self.assertEqual(0,first.returncode,first.stderr)
            second=subprocess.run(submitted,input=b'PRIVATE-fixture-password-42\npayload',capture_output=True,timeout=15)
        self.assertNotEqual(0,second.returncode)
        self.assertIn(b'automatic_privileged_execution_already_claimed',second.stderr)
        self.assertNotIn(b'PRIVATE-fixture-password-42',second.stdout+second.stderr)
        self.assertEqual('once\n',(self.root/'once').read_text())
        claims=list(self.peer.claims.glob('vpn-control-auto-root-*/execution-intent.json'))
        self.assertEqual(1,len(claims))

    def test_source_exchange_refuses_before_root_claim_and_execution(self):
        argv=self.argv(self.source(),password=False)
        with self.peer.environment(),automatic.automatic_submission(argv) as submitted:
            receipt=json.loads((self.root/'.rag_index/ssh-automatic-program'/argv.correlation/'staged.json').read_bytes())
            path=Path(receipt['directory'])/'program.source'
            path.write_bytes(path.read_bytes()+b'\n# exchanged after staging\n')
            result=subprocess.run(submitted,input=b'payload',capture_output=True,timeout=15)
        self.assertNotEqual(0,result.returncode)
        self.assertIn(b'automatic_privileged_program_metadata',result.stderr)
        self.assertFalse((self.root/'once').exists());self.assertFalse(list(self.peer.claims.iterdir()))

    def test_credential_echo_overflow_releases_no_private_bytes(self):
        self.peer.mode.write_text('overflow')
        result=self.run_plan(self.argv(self.source()),b'PRIVATE-fixture-password-42\npayload')
        self.assertNotEqual(0,result.returncode)
        self.assertEqual(b'',result.stdout)
        self.assertNotIn(b'PRIVATE-fixture-password-42',result.stderr)
        self.assertFalse((self.root/'once').exists())

    def test_password_wait_timeout_does_not_start_sudo_or_disclose(self):
        command=privileged.execution_command(('sudo','-S','-p','','--','python3','-I'),
            privileged.loader(automatic._COMMON,password=True),'{}',(),uuid.uuid4().hex,1)
        command=(sys.executable,*command[1:])
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            process.stdin.write(b'PRIVATE-fixture-password-42');process.stdin.flush()
            process.wait(timeout=3)
            process.stdin.close();out=process.stdout.read();err=process.stderr.read()
            self.assertNotEqual(0,process.returncode);self.assertEqual(b'',out)
            self.assertNotIn(b'PRIVATE-fixture-password-42',err)
            self.assertFalse(list(self.peer.claims.iterdir()))
        finally:
            if process.poll() is None:process.kill();process.wait()
            for stream in (process.stdin,process.stdout,process.stderr):stream.close()

    def test_finite_sudo_forms_refuse_target_user_environment_and_shell(self):
        for command in (('sudo','-u','other','python3','-c','print(1)'),('sudo','-S','python3','-c','print(1)'),('sudo','-n','env','python3','-c','print(1)'),('sudo','-n','--','sh','-c','print(1)')):
            with self.subTest(command=command),self.assertRaises(privileged.PrivilegedProgramError):privileged.program(command)


if __name__=='__main__':unittest.main()
