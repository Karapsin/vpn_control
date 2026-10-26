"""Whole-before RED/GREEN: a stale source-bound fixture registration is named, not hidden."""
import ast
import hashlib
import importlib
import json
from pathlib import Path
import unittest
from unittest import mock
from agent_tools import mcp_server as server
from agent_tools import readiness
from agent_tools import readiness_providers as providers
from agent_tools import readiness_tart_macos as tart_macos
from agent_tools import readiness_transport

FIXTURES = Path(__file__).parent / 'fixtures/readiness_provider_error_projection'
OPERATION = '5beada98-c094-4a8c-b81f-55ab148433d7'
VM_INPUTS = {'fixtureId': 'tart-macos-independent-v9', 'operationId': OPERATION}
SSH_IDENTITY = {'operationId': OPERATION}
GENERIC = {'ok': False, 'state': 'blocked', 'reason': 'readiness_admission_unavailable', 'replayAllowed': False}
STALE = {'ok': False, 'state': 'blocked', 'reason': 'fixture_registration_stale', 'replayAllowed': False}


def _pinned(leaf):
    raw = (FIXTURES / leaf).read_bytes()
    provenance = json.loads((FIXTURES / 'provenance.json').read_bytes())
    assert hashlib.sha256(raw).hexdigest() == provenance['files'][leaf]['sha256']
    return raw


class _Raising:
    def __init__(self, error):
        self.error = error

    def ssh_workflow(self, root, action, host, identity):
        raise self.error

    def vm_workflow(self, root, action, inputs):
        raise self.error


def facade(is_before, workflow):
    """Exact public implementation functions, undecorated, over the current helpers."""
    path = FIXTURES / 'mcp_server.before.source' if is_before else Path(server.__file__)
    raw = _pinned('mcp_server.before.source') if is_before else path.read_bytes()
    names = {'_ssh_workflow_impl', '_vm_workflow_impl', '_vm_workflow_dispatch', '_readiness_provider_refusal'}
    nodes = []
    for node in ast.parse(raw).body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            node.decorator_list = []
            nodes.append(node)
        elif isinstance(node, ast.Assign) and any(getattr(t, 'id', None) == '_STALE_REGISTRATION_REFUSALS' for t in node.targets):
            nodes.append(node)
    modules = {'readiness_workflow': workflow, 'readiness': readiness}
    load = lambda name: modules[name] if name in modules else importlib.import_module('agent_tools.' + name)
    ns = {**vars(server), '_agent_module': load}
    ns.pop('_readiness_provider_refusal', None)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), 'exec'), ns)
    return ns


class ReadinessProviderErrorProjectionTests(unittest.TestCase):
    def invoke(self, is_before, error, tool):
        ns = facade(is_before, _Raising(error))
        with mock.patch.object(readiness_transport, 'TransportAdapter',
                               side_effect=AssertionError('transport constructed')) as adapter:
            if tool == 'ssh_workflow':
                result = ns['_ssh_workflow_impl']('readiness-status', 'archlinux', 15, SSH_IDENTITY, None, None)
            else:
                result = ns['_vm_workflow_impl']('readiness-status', VM_INPUTS)
        adapter.assert_not_called()
        return result

    def test_whole_before_generic_current_names_stale_registration(self):
        for error in (tart_macos.MacBlocked('macos_custody_source_changed'),
                      providers.ProviderError('android_lifecycle_spec_changed')):
            for tool in ('vm_workflow', 'ssh_workflow'):
                with self.subTest(error=str(error), tool=tool):
                    self.assertEqual(self.invoke(True, error, tool), {'tool': tool, **GENERIC})
                    self.assertEqual(self.invoke(False, error, tool), {'tool': tool, **STALE})

    def test_other_errors_and_message_text_stay_generic(self):
        for error in (providers.ProviderError('macos_custody_source_changed: private detail'),
                      providers.ProviderError('tart_wrong_account'), ValueError('macos_custody_source_changed'),
                      OSError('disk'), RuntimeError()):
            for tool in ('vm_workflow', 'ssh_workflow'):
                with self.subTest(error=repr(error), tool=tool):
                    self.assertEqual(self.invoke(False, error, tool), {'tool': tool, **GENERIC})

    def test_readiness_blocked_keeps_its_typed_projection(self):
        error = readiness.ReadinessBlocked('integrity_mismatch', OPERATION)
        for tool in ('vm_workflow', 'ssh_workflow'):
            with self.subTest(tool=tool):
                self.assertEqual(self.invoke(False, error, tool), {'tool': tool, **error.as_dict()})


if __name__ == '__main__':
    unittest.main()
