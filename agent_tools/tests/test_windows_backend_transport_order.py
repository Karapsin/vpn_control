"""Whole Windows backend refuses unavailable transport before packet creation."""
import hashlib
import json
from pathlib import Path
import tempfile
import time
import types
import unittest
import subprocess
from contextlib import contextmanager
from unittest import mock
from uuid import uuid4

from agent_tools import readiness_windows as windows
from agent_tools.tests.test_readiness_windows import snapshot,SID
from agent_tools.tests.test_readiness_windows_guest import facts

FIXTURE=Path(__file__).parent/'fixtures/windows_backend_transport_order'


def before_module(directory=FIXTURE):
    raw=(directory/'windows.before.source').read_bytes()
    metadata=json.loads((directory/'provenance.json').read_text())
    if hashlib.sha256(raw).hexdigest()!=metadata['sourceSha256']:
        raise ValueError('windows_transport_order_beforeimage_changed')
    module=types.ModuleType('agent_tools._windows_backend_transport_before')
    module.__package__='agent_tools';module.__file__=str(directory/'windows.before.source')
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


class WindowsBackendTransportOrderTests(unittest.TestCase):
    def test_complete_before_spent_budget_dispatches_RED_fixed_refuses_GREEN(self):
        before=before_module(Path(__file__).parent/'fixtures/windows_backend_deadline')
        for name,module in [('before',before),('fixed',windows)]:
            with self.subTest(source=name),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);root.chmod(0o700);backend=module.WindowsBackend(root,snapshot()['binding'],SID)
                clock=[100.0]
                @contextmanager
                def admitted(*args,**kwargs):yield types.SimpleNamespace(revalidate=lambda:None,ready=None)
                def build(*args,**kwargs):clock[0]=102.0;return ['ssh']
                with mock.patch.object(module.transport,'admitted_transport',admitted),mock.patch.object(module.transport,'load_config',return_value={}),mock.patch.object(module.transport,'build_ssh_argv',side_effect=build),mock.patch.object(module.time,'monotonic',side_effect=lambda:clock[0]),mock.patch.object(module.transport,'run_ssh',return_value=subprocess.CompletedProcess([],0,b'{"state":"observed"}',b''))as dispatch:
                    if name=='before':
                        backend._run('observe',str(uuid4()),101.0)
                        self.assertEqual(.1,dispatch.call_args.kwargs['timeout'])
                    else:
                        with self.assertRaisesRegex(ValueError,'windows_deadline'):backend._run('observe',str(uuid4()),101.0)
                self.assertEqual(1 if name=='before'else 0,dispatch.call_count)

    def test_complete_before_generates_packet_RED_and_fixed_admits_first_GREEN(self):
        for name,module in [('before',before_module()),('fixed',windows)]:
            with self.subTest(source=name),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);root.chmod(0o700);backend=module.WindowsBackend(root,snapshot()['binding'],SID)
                operation=str(uuid4())
                with mock.patch.object(module.transport,'admitted_transport',side_effect=ValueError('target_transport_unavailable'))as admission:
                    with self.assertRaisesRegex(ValueError,'target_transport_unavailable'):
                        backend._run('observe',operation,time.monotonic()+180)
                saved=list(root.glob('.runtime/readiness-windows/*/observe-*.py'))
                self.assertEqual(name=='before',bool(saved))
                self.assertEqual(1,admission.call_count)
                self.assertEqual(frozenset({'transport'}),admission.call_args.kwargs['requirements'].required)
                self.assertEqual(frozenset(),admission.call_args.kwargs['requirements'].permitted_recoveries)
                if saved:
                    source=saved[0].read_bytes();compile(source,'complete Windows packet','exec')
                    self.assertIn(('OPERATION='+repr(operation)).encode(),source)

    def test_bound_lease_root_is_never_replaced_by_reenrollment(self):
        for name,module in [('before',before_module()),('fixed',windows)]:
            with self.subTest(source=name),tempfile.TemporaryDirectory()as temporary:
                root=Path(temporary);root.chmod(0o700);saved=snapshot();known=saved['guest']['root_generation']
                backend=module.WindowsBackend(root,saved['binding'],SID,lease_root_generation=known)
                session=facts();session['machine']=backend.machine;session['boot']=saved['guest']['boot']
                backend.last_facts={'guest':'running','guestAgent':True,'sessionFacts':session,**saved['host'],
                    'displayFacts':{'schemaVersion':1,'machine':backend.machine,'boot':session['boot'],'displayState':1}}
                replacement='87654321:0000000000000099:0000000000000002'
                reply={'state':'observed','lease':{'schemaVersion':1,'machine':backend.machine,'boot':session['boot'],'rootGeneration':replacement}}
                with mock.patch.object(backend,'_run',return_value=(reply,None))as dispatch:
                    executor=backend.lease_executor()
                self.assertEqual(replacement if name=='before'else known,executor.binding.root_generation)
                self.assertEqual(1 if name=='before'else 0,dispatch.call_count)


if __name__=='__main__':unittest.main()
