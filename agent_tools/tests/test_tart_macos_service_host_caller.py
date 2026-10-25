"""Authentic predispatch interface failure with actual canonical framed child."""
import ast
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest

from agent_tools import readiness
from agent_tools import readiness_qemu_jobs as protocol
from agent_tools import readiness_tart_macos as mac


class ServiceHostCallerTests(unittest.TestCase):
    def setUp(self):
        self.calls=[]
        self.observed=readiness.Observation('selected-tart','selected-machine','original-connection',
            '11234567-89ab-4def-8123-0123456789ab','502','100237')
        self.current=self.observed;self.raw=self.observed.boot.upper()
        def call(binding,argv,payload,deadline):
            self.calls.append((binding,argv,payload))
            return subprocess.run([sys.executable,*argv[1:]],input=payload,capture_output=True,timeout=5)
        self.backend=SimpleNamespace(binding=object(),_observe=lambda *a:(self.current,self.raw),
            custody=SimpleNamespace(ordinary_guest_call=call))
        self.executor=mac.MacGuestExecutor(self.backend,self.observed,time.monotonic()+10,self.raw)
        @contextmanager
        def guest_job_executor(**kwargs):yield self.executor
        self.backend.guest_job_executor=guest_job_executor
    def block(self,name,digest):
        path=Path(__file__).parent/('fixtures/macos_service_host_caller_'+name+'.source')
        raw=path.read_bytes();self.assertEqual(digest,hashlib.sha256(raw).hexdigest())
        tree=ast.parse(raw)
        blocks=[node for node in ast.walk(tree)if isinstance(node,ast.With)and any(
            isinstance(item.context_expr,ast.Call)and isinstance(item.context_expr.func,ast.Attribute)
            and item.context_expr.func.attr=='guest_job_executor'for item in node.items)]
        self.assertEqual(1,len(blocks))
        return compile(ast.Module(body=blocks,type_ignores=[]),'<authentic-service-host-dispatch>','exec')
    def test_full_original_dispatch_ast_before_red_current_execute_green_actual_stdin(self):
        before=self.block('before','34d3f53faabf9f9d39f348096c11d86bdeb2e9a7a773065a9155ab63a4af1765')
        fixed=self.block('fixed','6d5040a20e9fcf6d2d7b7f45401b2a0fed7a41fa8423be972c12a5df61491a86')
        source=b'import json;print(json.dumps({"state":"diagnostic","nativeQualified":False,"idleAuthority":False}))\n'
        scope={'backend':self.backend,'time':time,'source':source,'protocol':protocol}
        with self.assertRaises(AttributeError):exec(before,scope)
        self.assertEqual([],self.calls) # No dispatch/no native getter on original failure.
        exec(fixed,scope)
        reply=scope['r'];self.assertEqual(0,reply.returncode);self.assertEqual(b'',reply.stderr)
        self.assertEqual({'state':'diagnostic','nativeQualified':False,'idleAuthority':False},json.loads(reply.stdout))
        self.assertEqual(1,len(self.calls));self.assertEqual(source,self.calls[0][2])
        self.assertNotIn(source.decode(),str(self.calls[0][1]))
    def test_stale_selected_machine_session_or_packet_refuses_before_child(self):
        source='print("never dispatched")\n';argv,payload=protocol.stdin_command(source)
        for change in ({'target':'another-target'},{'machine':'another-machine'},{'session':'another-session'}):
            with self.subTest(change=change):
                self.current=replace(self.observed,**change)
                with self.assertRaisesRegex(mac.MacBlocked,'macos_ready_identity_changed'):
                    self.executor.execute(argv,payload=payload)
                self.assertEqual([],self.calls)
        self.current=self.observed
        with self.assertRaisesRegex(mac.MacBlocked,'macos_guest_program_unqualified'):
            self.executor.execute(argv,payload=payload+b'# changed')
        self.assertEqual([],self.calls)


if __name__=='__main__':unittest.main()
