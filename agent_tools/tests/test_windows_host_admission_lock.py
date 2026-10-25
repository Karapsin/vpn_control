"""Real generated HOST callers serialize first admission with the VM power lock."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from types import ModuleType
import unittest
from unittest import mock

from agent_tools import readiness_windows_host_jobs as current
from agent_tools.tests import test_windows_host_jobs as owners

FIXTURE=Path(__file__).parent/'fixtures/windows_host_admission_lock'


def subject():
    if os.environ.get('VPN_CONTROL_HOST_ADMISSION_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._windows_host_admission_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary durable HOST owner required')
class AdmissionLockTests(unittest.TestCase):
    def test_complete_idle_to_effect_excludes_concurrent_first_admission(self):
        module=subject()
        with mock.patch.object(owners,'subject',module):
            fixture=owners.WindowsHostOwnerTests('runTest');fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        listener=socket.socket(socket.AF_UNIX);endpoint=fixture.root/'controlled.sock';listener.bind(str(endpoint));listener.listen();listener.settimeout(5)
        self.addCleanup(listener.close)
        # This is the same outer VM intent lock held by the actual fixed power
        # caller, followed by the complete generated inventory and a harmless
        # socket effect. No VM or lifecycle power primitive is involved.
        source=('import os,fcntl,socket,contextlib,io,json\nlock=os.open('+repr(str(fixture.vm/'intent.json'))+',os.O_RDONLY|os.O_NOFOLLOW)\n'
            'fcntl.flock(lock,fcntl.LOCK_EX)\nout=io.StringIO()\nwith contextlib.redirect_stdout(out):exec(compile('+repr(module._render(fixture.namespace,'inventory'))+',"complete-inventory","exec"),{})\n'
            'assert json.loads(out.getvalue())["idle"] is True\ns=socket.socket(socket.AF_UNIX);s.connect('+repr(str(endpoint))+')\ns.sendall(b"idle")\nassert s.recv(1)==b"x"\ns.sendall(b"effect")\nfcntl.flock(lock,fcntl.LOCK_UN)\n').encode()
        power=subprocess.Popen([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"controlled-power-caller","exec"))'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        power.stdin.write(source);power.stdin.close();power.stdin=None
        connection,_=listener.accept();self.addCleanup(connection.close);connection.settimeout(5)
        self.assertEqual(connection.recv(4),b'idle')
        with mock.patch.object(owners,'subject',module):original=fixture.original(b'print("one harmless execution")\n')
        submit=subprocess.Popen([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"generated-first-submission","exec"))'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        submit.stdin.write(module.operation_program(original,submit=True));submit.stdin.close();submit.stdin=None
        try:
            time.sleep(.35)
            published=(Path(fixture.namespace['root'])/'admissions'/(fixture.operation+'.json')).exists()
        finally:
            connection.sendall(b'x');self.assertEqual(connection.recv(6),b'effect')
            _,error=power.communicate(timeout=5);self.assertEqual(power.returncode,0,error.decode())
            raw,error=submit.communicate(timeout=5);self.assertEqual(submit.returncode,0,error.decode())
        module.validate_result(original,json.loads(raw))
        with mock.patch.object(owners,'subject',module):terminal=fixture.terminal(original)
        self.assertEqual(terminal['status']['terminal']['exitCode'],0)
        self.assertFalse(published,'new admission appeared after complete idle while the VM power lock was still held')

    def test_intent_same_bytes_inode_replacement_blocks_all_namespace_observation(self):
        fixture=owners.WindowsHostOwnerTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        path=fixture.vm/'intent.json';other=path.with_suffix('.replacement');other.write_bytes(path.read_bytes());other.chmod(0o600);os.replace(other,path)
        result=subprocess.run([sys.executable,'-I','-B','-c','import sys;exec(compile(sys.stdin.buffer.read(),"original-host-observation","exec"))'],input=current._render(fixture.namespace,'inventory'),capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0)


if __name__=='__main__':unittest.main()
