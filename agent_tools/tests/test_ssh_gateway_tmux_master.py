"""Real inert gateway processes/sockets; no network, credentials or signals."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools import ssh_gateway_tmux_master as owner

PROC = '''def proc(pid):
    need(type(pid) is int and pid > 0, 'pid')
    p=subprocess.run(['/bin/ps','-p',str(pid),'-o','uid=','-o','lstart='],capture_output=True,check=False)
    fields=p.stdout.decode().split()
    need(p.returncode == 0 and len(fields)>1 and fields[0]==str(os.getuid()),'process_owner')
    return {'pid':pid,'startTicks':int(sha(' '.join(fields).encode())[:15],16)+1}


def boot(): return '11111111-2222-3333-4444-555555555555'


'''

FAKE_SSH = r'''#!/usr/bin/env python3
import json,os,pathlib,socket,subprocess,sys,time
args=sys.argv[1:];home=pathlib.Path.home()
if '-G' in args:
 print('hostname inert.invalid\nuser owned\nport 22\nidentityfile '+str(home/'.ssh/key')+'\nuserknownhostsfile '+str(home/'.ssh/known'))
 raise SystemExit(0)
path=pathlib.Path(args[args.index('-S')+1])
if '-O' in args:
 c=socket.socket(socket.AF_UNIX);c.connect(str(path));c.sendall(b'check');print(c.recv(256).decode(),end='');raise SystemExit(0)
assert '-M' in args and '-N' in args and 'ControlPersist=no' in args and '-f' not in args
assert 'ForkAfterAuthentication=no' in args and 'ClearAllForwardings=yes' in args
answer=subprocess.run([os.environ['SSH_ASKPASS']],capture_output=True,check=True).stdout
assert answer.rstrip(b'\n')==(home/'expected.private').read_bytes()
s=socket.socket(socket.AF_UNIX);s.bind(str(path));path.chmod(0o600);s.listen();s.settimeout(.05)
start=time.monotonic()
while time.monotonic()-start<10 and not path.with_name('inert-stop').exists():
 try:c,_=s.accept()
 except TimeoutError:continue
 c.recv(32);c.sendall(('Master running (pid='+str(os.getpid())+')\n').encode());c.close()
s.close();path.unlink();raise SystemExit(0)
'''

FAKE_TMUX = r'''#!/usr/bin/env python3
import json,os,pathlib,shlex,socket,subprocess,sys,time
args=sys.argv[1:]
if args==['-V']:print('tmux 3.4');raise SystemExit(0)
if args[0]=='_server':
 path=pathlib.Path(args[1]);name=args[2];command=shlex.split(args[3]);assert command.pop(0)=='exec'
 s=socket.socket(socket.AF_UNIX);s.bind(str(path));path.chmod(0o600);s.listen();s.settimeout(.05)
 child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 start=time.monotonic()
 while time.monotonic()-start<12:
  if child.poll() is not None:break
  try:c,_=s.accept()
  except TimeoutError:continue
  request=json.loads(c.recv(8192));action=request[0]
  response=name+'\n' if action=='list-sessions' else str(os.getpid())+' '+str(child.pid)+'\n'
  if path.with_name('inert-foreign').exists() and action=='list-sessions':response+='foreign\n'
  c.sendall(response.encode());c.close()
 if child.poll() is None:
  # No signals; inert SSH child stops at its own finite deadline, and the
  # un-released worker test fixture has a finite short gate.
  child.wait(timeout=3)
 s.close();path.unlink();raise SystemExit(0)
assert args[:2]==['-f','/dev/null'];path=pathlib.Path(args[3]);cmd=args[4:]
if cmd[0]=='new-session':
 name=cmd[cmd.index('-s')+1];command=cmd[-1]
 subprocess.Popen([sys.executable,__file__,'_server',str(path),name,command],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
 for _ in range(100):
  if path.exists():break
  time.sleep(.01)
else:
 c=socket.socket(socket.AF_UNIX);c.connect(str(path));c.sendall(json.dumps(cmd).encode());print(c.recv(4096).decode(),end='')
'''


@unittest.skipUnless(os.name == 'posix', 'POSIX fixture')
class GatewayOwnerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='vct-', dir='/tmp'); self.addCleanup(temp.cleanup)
        self.home = Path(temp.name).resolve(); self.home.chmod(0o700)
        self.home_patch = mock.patch.dict(os.environ, {'HOME': str(self.home)}); self.home_patch.start(); self.addCleanup(self.home_patch.stop)
        sshdir = self.home / '.ssh'; sshdir.mkdir(mode=0o700)
        for name, raw in [('key', b'inert-private-key'), ('known', b'inert-host-key'), ('config', b'Host arch\n HostName inert.invalid\n')]:
            path = sshdir / name; path.write_bytes(raw); path.chmod(0o600)
        (self.home / 'expected.private').write_bytes(b'inert-secret'); (self.home / 'expected.private').chmod(0o600)
        self.ssh = self.home / 'ssh'; self.ssh.write_text(FAKE_SSH); self.ssh.chmod(0o700)
        self.tmux = self.home / 'tmux'; self.tmux.write_text(FAKE_TMUX); self.tmux.chmod(0o700)
        raw = Path(owner.__file__).read_text().replace("SSH = '/usr/bin/ssh'", 'SSH = ' + repr(str(self.ssh))).replace("TMUX = '/usr/bin/tmux'", 'TMUX = ' + repr(str(self.tmux)))
        start = raw.index('def proc(pid):'); end = raw.index('def packet(raw):', start)
        raw = raw[:start] + PROC + raw[end:]
        raw = raw.replace('range(3000)', 'range(30)')
        self.raw = raw.encode()
        ns = {'subprocess': subprocess, 'os': os, 'sha': owner.sha, 'need': owner.need}; exec(PROC, ns)
        self.patches = [mock.patch.object(owner, 'SSH', str(self.ssh)), mock.patch.object(owner, 'TMUX', str(self.tmux)),
                        mock.patch.object(owner, 'proc', ns['proc']), mock.patch.object(owner, 'boot', ns['boot']),
                        mock.patch.object(owner, 'source_bytes', return_value=self.raw)]
        for patch in self.patches: patch.start(); self.addCleanup(patch.stop)
        (self.home / '.vc').mkdir(mode=0o700)
        corr = uuid4()
        self.request = {'version': 1, 'purpose': owner.PURPOSE, 'host': 'archlinux', 'correlationId': str(corr),
                        'localAuthoritySha256': 'a' * 64, 'workerSha256': owner.sha(self.raw), 'profile': 'arch',
                        'configFile': str(sshdir / 'config'), 'configuredControlPath':str(self.home / '.vc/m'),
                        'masterControlPath':str(self.home / '.vc'/('r-'+corr.hex[:15])/'m')}
        self.addCleanup(self.finish)

    def finish(self):
        try:
            job = owner.paths(self.request)[2]
            master = job / 'm'
            if hasattr(owner, 'master_path'): master = owner.master_path(self.request)
            if master.parent.exists(): (master.parent / 'inert-stop').touch()
            deadline = time.monotonic() + 4
            while time.monotonic() < deadline and (job / 't').exists(): time.sleep(.02)
        except (OSError, ValueError): pass

    def prepare(self):
        result = owner.operate('prepare', self.request)
        self.assertEqual('prepared', result.get('state'), result)
        self.anchor = result['anchorPin']; return result

    def ready(self):
        self.prepare()
        result = owner.operate('release', self.request, self.anchor, 'inert-secret')
        self.assertEqual('released', result.get('state'), result)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = owner.operate('status', self.request, self.anchor)
            if result.get('state') == 'ready': return result
            time.sleep(.02)
        self.fail('ready observation unavailable: ' + str(result))

    def test_default_known_hosts_pair_pins_present_primary_and_absent_secondary(self):
        text=self.ssh.read_text().replace("str(home/'.ssh/known'))", "str(home/'.ssh/known')+' '+str(home/'.ssh/known2'))")
        self.ssh.write_text(text)
        self.ready(); (self.home/'.ssh/known2').write_bytes(b'new-unpinned-key')
        self.assertEqual('unknown',owner.operate('status',self.request,self.anchor)['state'])

    def test_control_output_is_bounded_live_with_durable_overflow(self):
        capsule=self.home/'bounded-query'; capsule.mkdir(mode=0o700)
        with mock.patch.object(owner.tempfile,'mkdtemp',return_value=str(capsule)):
            with self.assertRaises(ValueError): owner.bounded([os.sys.executable,'-c',"import os;os.write(1,b'x'*5000)"])
        self.assertLessEqual((capsule/'stdout.private').stat().st_size,4097)
        self.assertTrue((capsule/'receipt.json').exists())

    def test_canonical_85_byte_recovery_socket_supports_real_foreground_owner(self):
        # Actual native9234 packet was85 bytes: canonical recovery accepts85.
        prefix=self.home/'.vc'; suffix='/r-'+self.request['correlationId'].replace('-','')[:15]+'/m'
        component='x'*(85-len(os.fsencode(prefix))-1-len(suffix.encode()))
        self.assertTrue(component)
        base=prefix/component; base.mkdir(mode=0o700)
        old=base/('r-'+'f'*15); old.mkdir(mode=0o700)
        self.request['configuredControlPath']=str(old/'m')
        self.request['masterControlPath']=str(base/suffix.lstrip('/'))
        self.assertEqual(85,len(os.fsencode(self.request['masterControlPath'])))
        result=self.ready(); self.assertEqual(self.request['masterControlPath'],result['controlPath'])

    def test_configured_socket_appearing_after_prepare_rejects_release(self):
        self.prepare(); foreign=socket.socket(socket.AF_UNIX); self.addCleanup(foreign.close)
        foreign.bind(self.request['configuredControlPath']); Path(self.request['configuredControlPath']).chmod(0o600)
        self.assertEqual('unknown',owner.operate('release',self.request,self.anchor,'inert-secret')['state'])
        self.assertFalse((owner.paths(self.request)[2]/'release.json').exists())
        self.assertTrue(Path(self.request['configuredControlPath']).is_socket())

    def test_original_child_birth_drift_rejects_ready(self):
        self.ready(); actual=owner.proc
        job=owner.paths(self.request)[2]; pid=json.loads((job/'child.json').read_text())['process']['pid']
        def changed(observed):
            value=actual(observed)
            return {**value,'startTicks':value['startTicks']+1} if observed==pid else value
        with mock.patch.object(owner,'proc',side_effect=changed):
            self.assertEqual('unknown',owner.operate('status',self.request,self.anchor)['state'])

    def test_ready_generation_changed_during_control_check_rejects(self):
        self.ready(); actual=owner.bounded; path=owner.paths(self.request)[2]/'ready.json'
        def changed(argv,**kw):
            result=actual(argv,**kw)
            if '-O' in argv: path.write_bytes(path.read_bytes())
            return result
        with mock.patch.object(owner,'bounded',side_effect=changed):
            self.assertEqual('unknown',owner.operate('status',self.request,self.anchor)['state'])

    def test_askpass_replacement_never_chmods_foreign_symlink_target(self):
        foreign = self.home / 'foreign-helper'; foreign.write_bytes(b'foreign'); foreign.chmod(0o600)
        # Causal swap in the real staged worker exactly after durable creation.
        insertion = "\n_original_create=create\ndef create(directory,name,raw,*args,**kwargs):\n    result=_original_create(directory,name,raw,*args,**kwargs)\n    if name=='askpass.py':\n        (directory.path/name).unlink(); (directory.path/name).symlink_to(" + repr(str(foreign)) + ")\n    return result\n\n"
        raw = self.raw.replace(b"if __name__ == '__main__':", insertion.encode() + b"if __name__ == '__main__':")
        self.request['workerSha256'] = owner.sha(raw)
        with mock.patch.object(owner, 'source_bytes', return_value=raw): self.prepare()
        self.assertEqual('released', owner.operate('release', self.request, self.anchor, 'inert-secret')['state'])
        job = owner.paths(self.request)[2]; deadline = time.monotonic()+2
        while time.monotonic()<deadline and not (job/'askpass.py').is_symlink(): time.sleep(.02)
        self.assertTrue((job/'askpass.py').is_symlink())
        self.assertEqual(0o600, foreign.stat().st_mode & 0o777)
        self.assertFalse((job/'ssh-launch.intent.json').exists())

    def test_foreground_master_ready_after_client_subprocess_ends(self):
        result = self.ready()
        self.assertFalse(result['replayAllowed']); self.assertFalse(result['adoptionAllowed'])
        first = result['readyPin']
        self.assertEqual(first, owner.operate('status', self.request, self.anchor)['readyPin'])
        job = owner.paths(self.request)[2]
        launch = json.loads((job / 'ssh-launch.intent.json').read_text())
        self.assertNotIn('inert-secret', json.dumps(launch))
        self.assertNotIn('inert-secret', (job / 'stdout.private').read_text() + (job / 'stderr.private').read_text())

    def test_lost_prepare_response_is_consumed_and_never_replayed(self):
        self.prepare()
        with mock.patch.object(owner, 'tmux', side_effect=AssertionError('no duplicate')):
            self.assertEqual('unknown', owner.operate('prepare', self.request)['state'])
        self.assertEqual('prepared', owner.operate('status', self.request, self.anchor)['state'])

    def test_lost_release_response_is_observed_and_never_replayed(self):
        self.ready()
        with mock.patch.object(owner, 'tmux', side_effect=AssertionError('no duplicate')):
            self.assertEqual('unknown', owner.operate('release', self.request, self.anchor, 'inert-secret')['state'])
        self.assertEqual('ready', owner.operate('status', self.request, self.anchor)['state'])

    def test_foreign_job_is_not_replaced(self):
        _, base, job = owner.paths(self.request); base.mkdir(mode=0o700); job.mkdir(mode=0o700)
        sentinel = job / 'foreign'; sentinel.write_bytes(b'original')
        with mock.patch.object(owner, 'tmux', side_effect=AssertionError('no effect')):
            self.assertEqual('unknown', owner.operate('prepare', self.request)['state'])
        self.assertEqual(b'original', sentinel.read_bytes())

    def test_foreign_session_rejects_without_touching_default_tmux(self):
        self.prepare(); job = owner.paths(self.request)[2]
        sentinel = self.home / 'default-tmux-sentinel'; sentinel.write_bytes(b'foreign-default')
        (job / 'inert-foreign').touch()
        self.assertEqual('unknown', owner.operate('release', self.request, self.anchor, 'inert-secret')['state'])
        self.assertEqual(b'foreign-default', sentinel.read_bytes()); self.assertFalse((job / 'release.json').exists())

    def test_changed_source_after_prepare_rejects_release(self):
        self.prepare(); job = owner.paths(self.request)[2]
        (job / 'owner.py').write_bytes((job / 'owner.py').read_bytes() + b'\n')
        with mock.patch.object(owner, 'tmux', side_effect=AssertionError('no effect')):
            self.assertEqual('unknown', owner.operate('release', self.request, self.anchor, 'inert-secret')['state'])
        self.assertFalse((job / 'release.json').exists())

    def test_changed_config_after_prepare_rejects_release(self):
        self.prepare(); path = Path(self.request['configFile']); path.write_bytes(path.read_bytes())
        self.assertEqual('unknown', owner.operate('release', self.request, self.anchor, 'inert-secret')['state'])

    def test_secret_key_body_is_never_read(self):
        inode = (self.home / '.ssh/key').stat().st_ino; actual = os.pread
        def read(fd, *args):
            if os.fstat(fd).st_ino == inode: self.fail('key body read')
            return actual(fd, *args)
        with mock.patch.object(owner.os, 'pread', side_effect=read): self.prepare()

    def test_include_and_match_configs_reject_before_ssh_config_execution(self):
        Path(self.request['configFile']).write_bytes(b'Match exec "foreign-command"\n')
        with mock.patch.object(owner, 'bounded', wraps=owner.bounded) as run:
            self.assertEqual('unknown', owner.operate('prepare', self.request)['state'])
        self.assertEqual([[str(self.tmux), '-V']], [call.args[0] for call in run.call_args_list])

    def test_existing_socket_generation_change_is_unknown_no_restart(self):
        self.ready(); job = owner.paths(self.request)[2]
        path = job / 'm' if not hasattr(owner, 'master_path') else owner.master_path(self.request)
        path.chmod(0o640)
        self.assertEqual('unknown', owner.operate('status', self.request, self.anchor)['state'])

    def test_master_end_retains_terminal_without_restart(self):
        self.ready(); job = owner.paths(self.request)[2]
        path = job / 'm' if not hasattr(owner, 'master_path') else owner.master_path(self.request)
        (path.parent / 'inert-stop').touch()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not (job / 'terminal.json').exists(): time.sleep(.02)
        result = owner.operate('status', self.request, self.anchor)
        self.assertEqual('ended', result.get('state'), result); self.assertEqual(0, result['exitCode'])
        self.assertEqual('unknown', owner.operate('prepare', self.request)['state'])

    def test_extra_command_input_rejected(self):
        self.request['command'] = ['foreign']
        self.assertEqual('unknown', owner.operate('prepare', self.request)['state'])

    def test_missing_tmux_returns_typed_blocked_without_creating_job(self):
        with mock.patch.object(owner, 'availability', return_value={'available':False,'nativeActionAllowed':False}):
            result = owner.operate('prepare', self.request)
        self.assertEqual('blocked', result.get('state'), result)
        self.assertEqual('tmux_unavailable', result.get('reason'))
        self.assertFalse(owner.paths(self.request)[2].exists())
