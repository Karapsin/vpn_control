"""Actual fixed MCP callback body; fake local/native transport effects only."""
import ast
import importlib
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from agent_tools import native_execution_context as context,mcp_server as current_server
from agent_tools.tests import test_native_engineering_entrypoint as fixture

class NativeEngineeringMcpRouteTest(unittest.TestCase):
    def callback(self):
        path=Path(os.environ.get('VPN_ENGINEERING_MCP_SOURCE',str(fixture.fixture.ROOT/'agent_tools/mcp_server.py')))
        tree=ast.parse(path.read_bytes());node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='_vm_workflow_impl')
        def module(name):
            if name=='native_execution_context':return context
            if name=='tmux_workflow_routes':return SimpleNamespace(dispatch=lambda root,action,inputs:{'legacy':True})
            raise AssertionError('Unsupported native module')
        ns={'__package__':'agent_tools','importlib':importlib,'REPO_ROOT':Path('/unused'),
            '_native_source_request':current_server._native_source_request,
            '_agent_module':module,'_error':lambda tool,message:{'tool':tool,'ok':False,'error':message}}
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),ns)
        return ns['_vm_workflow_impl']
    def test_actual_callback_preserves_typed_context_and_all_four_original_request_fields(self):
        callback=self.callback();raw={'sourceSha':'a'*40,'baseVersion':'2.2.8','targetVersion':'2.2.9','correlationId':'original',
            'engineeringContext':{'sourceRoot':'/fixed/same-git/source','artifactIds':['sha256-'+'b'*64]}}
        for operation in ('preflight','start','status','collect'):
            with self.subTest(operation=operation),patch.object(context,'dispatch_linux_engineering',return_value={'state':'unknown','replayAllowed':False}) as dispatch:
                result=callback('linux-package-tmux-'+operation,raw)
                dispatch.assert_called_once_with(Path('/unused'),operation,raw)
                self.assertFalse(result['replayAllowed'])
    def test_context_cannot_escape_fixed_operations_and_failed_qualification_has_safe_unknown(self):
        callback=self.callback();raw={'engineeringContext':{'admission':False,'command':'caller'}}
        for action in ('linux-package-tmux-availability','linux-package-tmux-resource-prepare','arch-tmux-install-start'):
            with self.subTest(action=action),patch.object(context,'dispatch_linux_engineering',side_effect=AssertionError('No producer dispatch')) as dispatch:
                self.assertFalse(callback(action,raw)['ok']);dispatch.assert_not_called()
        with patch.object(context,'dispatch_linux_engineering',side_effect=ValueError('private paths and raw authority')):
            result=callback('linux-package-tmux-start',raw)
        self.assertEqual('unknown',result['state']);self.assertFalse(result['replayAllowed'])
        self.assertFalse(result['nativeActionAllowed']);self.assertNotIn('private',str(result))
        self.assertEqual({'legacy':True},callback('linux-package-tmux-status',{'correlationId':'original'}))
