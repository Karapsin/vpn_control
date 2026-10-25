"""Real cooperating processes and durable power admission; no VM or power."""
import ast
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from agent_tools import readiness
from agent_tools import readiness_tart_macos_power_fence as fence


@unittest.skipUnless(os.name=='posix','real operator flock requires POSIX')
class PowerFenceTests(unittest.TestCase):
    def setUp(self):
        import fcntl
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.fd=os.open(self.root/'operator.lock',os.O_RDWR|os.O_CREAT,0o600)
        self.addCleanup(os.close,self.fd);self.locked=False
        def guard():
            if not self.locked:raise fence.PowerPending('test_operator_not_held')
        self.subject=fence.PowerFence(self.root,'target','machine',guard);self.addCleanup(self.subject.close)
        self.observed=readiness.Observation('target','machine','connection','boot','ordinary','session',
            transport='ready',guest='running',guest_agent=True,trusted=True,owned=True,integrity=True,
            idle_visibility=readiness.IDLE_VISIBILITY)
        self.rid='a'*64
    def reserve(self):
        return self.subject.reserve(self.rid,'shutdown',self.observed,
                                    original_run_operation='11111111-1111-4111-8111-111111111111')
    def test_missing_visibility_or_actual_lock_blocks_reservation(self):
        with self.assertRaisesRegex(fence.PowerPending,'operator_not_held'):self.reserve()
        self.locked=True
        for missing in readiness.IDLE_VISIBILITY:
            with self.assertRaisesRegex(fence.PowerPending,'idle_incomplete'):
                self.subject.reserve(self.rid,'shutdown',replace(self.observed,idle_visibility=readiness.IDLE_VISIBILITY-{missing}),
                    original_run_operation='11111111-1111-4111-8111-111111111111')
        self.assertIsNone(self.subject.inspect())
    def test_observer_authority_never_admits_a_mutation_or_clears_unknown(self):
        self.locked=True;before=self.reserve()
        with self.assertRaisesRegex(fence.PowerPending,'power_pending'):self.subject.guard_scope()
        with self.subject.observing_original(self.rid):
            self.subject.guard_scope()
            with self.assertRaisesRegex(fence.PowerPending,'power_pending'):self.subject.guard_admission()
        self.assertEqual(before,self.subject.inspect())
        self.assertEqual(before['state'],'pending')
        with self.assertRaisesRegex(fence.PowerPending,'not_admitted'):
            with self.subject.observing_original('b'*64):pass
    def test_fresh_agent_observes_original_pending_without_recovery(self):
        self.locked=True;before=self.reserve()
        another=fence.PowerFence(self.root,'target','machine',lambda:None)
        try:
            self.assertEqual(another.inspect(),before)
            with self.assertRaisesRegex(fence.PowerPending,'power_pending'):another.guard_admission()
        finally:another.close()
    def test_malformed_private_record_remains_a_finite_admission_blocker(self):
        path=self.root/('macos-power-reservation-'+self.rid+'.json')
        for raw in (b'{',b'{"action":NaN}',b'{"schemaVersion":1,"schemaVersion":1}'):
            path.write_bytes(raw);path.chmod(0o600)
            with self.assertRaisesRegex(fence.PowerPending,'reservation_invalid'):self.subject.inspect()
        path.unlink();self.locked=True
        for action in ([],{},None,True):
            with self.assertRaisesRegex(fence.PowerPending,'action_invalid'):
                self.subject.reserve(self.rid,action,self.observed,
                    original_run_operation='11111111-1111-4111-8111-111111111111')
        self.assertIsNone(self.subject.inspect())
    def test_actual_crossprocess_old_scope_race_red_current_fence_green(self):
        """The original Mac scope lock alone admits new work after lost ACK."""
        import fcntl
        before=Path(__file__).parent/'fixtures/tart_macos_power_fence/backend.before.source'
        self.assertEqual(hashlib.sha256(before.read_bytes()).hexdigest(),
                         '038f901bd043c3bebb9540e5b06027f9667736f40aa36804169d7cff07981de1')
        tree=ast.parse(before.read_bytes());cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='MacTartBackend')
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name=='operation_scope')
        # The unchanged entire production scope method supplies the actual old caller.
        method_source=textwrap.dedent('\n'.join(before.read_text().splitlines()[method.decorator_list[0].lineno-1:method.end_lineno])+'\n')
        script=r'''import contextlib,fcntl,json,os,sys,time
from pathlib import Path
from agent_tools import readiness
from agent_tools import readiness_tart_macos_power_fence as fence
from agent_tools import readiness_tart_macos as backend
root=Path(sys.argv[1]);mode=sys.argv[2]
fd=os.open(root/'operator.lock',os.O_RDWR)
class Custody:
 @contextlib.contextmanager
 def operator(self,**kwargs):
  fcntl.flock(fd,fcntl.LOCK_EX)
  try:yield
  finally:fcntl.flock(fd,fcntl.LOCK_UN)
namespace={'contextmanager':contextlib.contextmanager,'readiness':readiness,'_deadline':lambda value:value,
           'time':time,'MacBlocked':backend.MacBlocked,'rfb':backend.rfb}
exec(METHOD,namespace)
class OldCaller:
 custody=Custody()
 _host=lambda self,deadline:None
operation_scope=namespace['operation_scope']
caller=OldCaller()
try:
 with operation_scope(caller,deadline=time.monotonic()+10):
  if mode=='current':
   with_operator=fence.PowerFence(root,'target','machine',lambda:None)
   try:with_operator.guard_admission()
   finally:with_operator.close()
  (root/('mutation-'+mode)).write_text('one new job admitted')
 print('admitted')
except (fence.PowerPending,backend.MacBlocked):print('blocked')
'''
        script='METHOD='+repr(method_source)+'\n'+script
        fcntl.flock(self.fd,fcntl.LOCK_EX);self.locked=True
        children=[]
        try:
            for mode in ('before','current'):
                children.append((mode,subprocess.Popen([sys.executable,'-c',script,str(self.root),mode],
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,cwd=Path(__file__).resolve().parents[2])))
            self.reserve() # Reservation becomes durable while both real callers wait on the SAME lock.
        finally:
            self.locked=False;fcntl.flock(self.fd,fcntl.LOCK_UN)
        results={}
        try:
            for mode,child in children:
                stdout,stderr=child.communicate(timeout=15)
                results[mode]=(child.returncode,stdout.decode().strip(),stderr)
        finally:
            for _,child in children:
                if child.poll() is None:child.kill()
                child.communicate()
        for code,_,stderr in results.values():self.assertEqual(code,0,stderr)
        results={mode:result[1] for mode,result in results.items()}
        self.assertEqual(results,{'before':'admitted','current':'blocked'})
        self.assertTrue((self.root/'mutation-before').exists())
        self.assertFalse((self.root/'mutation-current').exists())
        self.assertEqual(self.subject.inspect()['state'],'pending')

if __name__=='__main__':unittest.main()
