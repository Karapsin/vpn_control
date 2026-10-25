"""The complete native S3 test caller settles quietly over real QMP/QGA sockets."""
import ast
import hashlib
import json
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools.tests import test_readiness_qemu_remote as remote

S3_SERVER=remote.SERVER.replace(
 "   if name=='query-status':value={'status':state['status'],'running':state['status']=='running'}",
 """   if 'suspendAt' in state and time.monotonic()>=state['suspendAt']:
    state.pop('suspendAt');state['status']='suspended';state['sleepTransitions']=state.get('sleepTransitions',0)+1
    (root/'endpoint-state.json').write_text(json.dumps(state))
   if name=='query-status':value={'status':state['status'],'running':state['status']=='running'}""").replace(
 "   elif name=='query-uuid':value={'UUID':machine}",
 """   elif name=='query-uuid':value={'UUID':machine}
   elif name=='guest-info':value={'supported_commands':[{'name':'guest-suspend-ram','enabled':True}]}
   elif name=='guest-suspend-ram':
    state['suspendAt']=time.monotonic()+.2;state['qgaSubmissions']=state.get('qgaSubmissions',0)+1
    (root/'endpoint-state.json').write_text(json.dumps(state));continue""")


@unittest.skipUnless(os.name=='posix' and hasattr(__import__('socket'),'SO_PEERCRED'),'Linux authenticated QMP/QGA')
class QuietS3CallerTests(unittest.TestCase):
    def caller(self, filename):
        folder=Path(__file__).parent/'fixtures/qemu_s3_quiet_settle_before'
        raw=(folder/filename).read_bytes();metadata=json.loads((folder/'provenance.json').read_bytes())
        self.assertEqual(metadata['beforeCallerSha256' if filename=='caller.before.source' else 'currentCallerSha256'],hashlib.sha256(raw).hexdigest())
        # Preserve the entire original caller artifact; execute its complete
        # unchanged S3 function, without the unrelated outer SDK job startup.
        tree=ast.parse(raw);functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='s3_precondition']
        self.assertEqual(1,len(functions))
        return ast.Module(body=functions,type_ignores=[])

    def test_complete_old_caller_misses_transition_current_settles_without_guest_ssh(self):
        for filename in ['caller.before.source','caller.current.source']:
            fixture=remote.QemuRemotePacketTests('runTest')
            with mock.patch.object(remote,'SERVER',S3_SERVER):fixture.setUp()
            try:
                enrolled=fixture.run_packet('enroll');(fixture.root/'readiness-qemu').mkdir(mode=0o700)
                state_path=fixture.root/'endpoint-state.json'
                class Backend:
                    sent=False
                    def _run(self,action,operation,deadline):
                        before=json.loads(state_path.read_bytes());ssh_before=len(fixture.ssh)
                        result=fixture.run_packet(action,pins=enrolled['pins'])
                        # A premature ordinary network observer wakes the
                        # delayed fixture transition; QMP alone cannot do so.
                        if self.sent and 'suspendAt'in before and len(fixture.ssh)>ssh_before:
                            state=json.loads(state_path.read_bytes());state.pop('suspendAt',None);state['status']='running'
                            state['sleepTransitions']=1;state['automaticWakes']=state.get('automaticWakes',0)+1
                            state_path.write_text(json.dumps(state))
                        self.sent=any((fixture.root/'readiness-qemu').glob('s3-test-*.json'))
                        return result,None
                backend=Backend();records={};ssh_before_caller=len(fixture.ssh)
                namespace={'registry':SimpleNamespace(registered_fixture=lambda *_:SimpleNamespace(adapter=SimpleNamespace(backend=backend))),
                    'ROOT':fixture.root,'ID':'owned','q':SimpleNamespace(packets=remote.subject,readiness=SimpleNamespace(IDLE_VISIBILITY=frozenset({'reservations','running_jobs','unknown_jobs','installers','lifecycle_phases','operators','protected_processes'}))),
                    'time':time,'save':lambda name,value:records.setdefault(name,value)}
                exec(compile(self.caller(filename),filename,'exec'),namespace)
                if filename=='caller.before.source':
                    with self.assertRaisesRegex(ValueError,'owned_intentional_s3_not_observed'):
                        namespace['s3_precondition']('a3926af1-0571-4fd5-aab3-b09cb62c9576')
                    self.assertEqual(1,json.loads(state_path.read_bytes())['automaticWakes'])
                else:
                    before,asleep=namespace['s3_precondition']('5bfdfd2f-0b3d-4082-942c-35e1e9ca2d24')
                    self.assertEqual('suspended',asleep['guest']);self.assertEqual(before['owner'],asleep['owner'])
                    state=json.loads(state_path.read_bytes());self.assertEqual(0,state.get('automaticWakes',0))
                    self.assertEqual(ssh_before_caller+2,len(fixture.ssh))
                self.assertEqual(1,json.loads(state_path.read_bytes())['qgaSubmissions'])
            finally:fixture.doCleanups()
