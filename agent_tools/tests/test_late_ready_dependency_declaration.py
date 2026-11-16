"""Exact old/current source origins keep the late-ready declaration finite."""
import ast
import hashlib
import json
from pathlib import Path
import unittest

from agent_tools import affected_agent_tests as selector

_ROOT = Path(__file__).resolve().parents[2]
_CONSUMER = 'agent_tools/tests/test_ssh_gateway_tmux_ready_reconciliation.py'
_STATUS = 'agent_tools/tests/test_ssh_gateway_tmux_reconciliation_status.py'
_BEFORE = 'agent_tools/tests/fixtures/ssh_late_ready_handshake/ready.before.source'
_PROVENANCE = 'agent_tools/tests/fixtures/ssh_late_ready_handshake/provenance.json'
_BASELINE_SHA = '7adb04b07af9bfc18d72a685f48da8bd0c2a5104cd4ef35217a39cab0377ba77'
_BASELINE = 'e14f6b04726885df28c0d49313f43dbf22752b01'
# Fixed v1 helper context entered by the current controlled historical methods.
_HELPER_SCOPES = ('agent_tools/tests/ssh_gateway_historical_fixture.py',
                  'agent_tools/tests/fixtures/ssh_gateway_bound_carrier/master.private-config.before.source',
                  'agent_tools/tests/fixtures/ssh_gateway_bound_carrier/diagnostic.carrier-only.before.source',
                  'agent_tools/tests/fixtures/ssh_gateway_bound_carrier/provenance.json')
_SUPPLIERS = ('agent_tools/ssh_connection_recovery.py', 'agent_tools/ssh_expired_recovery_retirement.py', 'agent_tools/ssh_gateway_tmux_d606_diagnostic.py', 'agent_tools/ssh_gateway_tmux_master.py', 'agent_tools/ssh_gateway_tmux_master_ssh.py', 'agent_tools/ssh_gateway_tmux_ready_reconciliation.py', 'agent_tools/ssh_recovery_adoption.py', 'agent_tools/tests/test_ssh_expired_recovery_retirement.py', 'agent_tools/tests/test_ssh_gateway_tmux_d606_diagnostic.py')


class DeclarationOriginTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = (_ROOT / 'agent_tools/tests/test_ssh_gateway_tmux_ready_reconciliation.py').read_text()
        cls.before = (_ROOT / 'agent_tools/tests/fixtures/ssh_late_ready_handshake/ready.before.source').read_text()
        cls.status = (_ROOT / 'agent_tools/tests/test_ssh_gateway_tmux_reconciliation_status.py').read_text()
        cls.manifest = json.loads((_ROOT / 'agent_tools/affected_agent_test_dependencies.json').read_text())
        assert len(cls.before.encode()) == 9921 and hashlib.sha256(cls.before.encode()).hexdigest() == _BASELINE_SHA

    def selection(self, *, current=None, baseline=None):
        # This is the real selector's old/current tuple at one authentic origin.
        sources = {name: None for name in _SUPPLIERS + _HELPER_SCOPES}
        sources.update({
            _CONSUMER: (self.current if current is None else current,
                        self.before if baseline is None else baseline),
            _STATUS: self.status,
            _BEFORE: self.before,
            _PROVENANCE: None,
            'agent_tools/ssh_gateway_tmux_reconciliation_status.py': None,
            'agent_tools/__init__.py': None,
            'agent_tools/tests/__init__.py': None,
        })
        return selector.select_from_sources(sources, {_CONSUMER}, _BASELINE)

    def test_actual_baseline_and_current_versions_select_both_consumers(self):
        result = self.selection()
        self.assertEqual((_CONSUMER[:-3].replace('/', '.'), _STATUS[:-3].replace('/', '.')),
                         result.modules)

    def test_corrected_declaration_keeps_only_exact_generations_and_reviewed_scopes(self):
        # Declarations are keyed by path: CI runs the complete suite on every
        # agent-input change, so no source generation digest is pinned.
        row = self.manifest['loaders'][_CONSUMER]
        self.assertEqual({'reason', 'scopes'}, set(row))
        self.assertEqual(sorted([*_SUPPLIERS, _BEFORE, _PROVENANCE, *_HELPER_SCOPES]), sorted(row['scopes']))
        self.assertEqual(row, selector.REVIEWED_DYNAMIC_DEPENDENCIES[_CONSUMER])

    def test_authentic_before_imports_are_existing_current_static_suppliers(self):
        def imports(text):
            found = set()
            for node in ast.walk(ast.parse(text)):
                if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith('agent_tools'):
                    if node.module in ('agent_tools', 'agent_tools.tests'):
                        found.update(node.module.replace('.', '/') + '/' + name.name + '.py' for name in node.names)
                    else:
                        found.add(node.module.replace('.', '/') + '.py')
                elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                      and node.func.attr == 'import_module' and node.args
                      and isinstance(node.args[0], ast.Constant)
                      and isinstance(node.args[0].value, str)
                      and node.args[0].value.startswith('agent_tools.')):
                    found.add(node.args[0].value.replace('.', '/') + '.py')
            return found
        self.assertEqual(set(_SUPPLIERS), imports(self.before))
        self.assertTrue(imports(self.before) <= imports(self.current))


if __name__ == '__main__':
    unittest.main()
