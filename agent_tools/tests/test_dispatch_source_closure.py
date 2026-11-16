"""CI rule: each dispatch action's declared closure equals its computed source closure."""
import ast
import gzip
import hashlib
import json
from pathlib import Path
import re
import tempfile
import types
import unittest

from agent_tools import dispatch_source_closure as closure
from agent_tools.tests import red_gate

FIXTURE = Path(__file__).parent / 'fixtures' / 'dispatch_source_closure'
BY_NAME = Path(__file__).parent / 'fixtures' / 'dispatch_source_closure_by_name'


def paths(*names):
    return ['agent_tools/' + name + '.py' for name in names]


class ComputedClosureTests(unittest.TestCase):
    def tools(self, files):
        """An agent_tools directory (with scripts/ beside it) holding `files`, which may name subdirectories."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / 'agent_tools'
        for name, text in files.items():
            target = Path(temporary.name) / name if name.startswith('scripts/') else root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        return root

    def test_every_source_route_is_followed(self):
        tools = self.tools({
            'entry.py': 'from . import alpha\nfrom .beta import VALUE\nimport agent_tools.gamma\n'
                        'def lazy():\n    from agent_tools import delta\n',
            'alpha.py': 'from pathlib import Path\nBODY = Path(__file__).with_name("shipped.py").read_bytes()\n',
            'beta.py': 'VALUE = 1\nWORKER = ("agent_tools/worker.py", "data")\n',
            'gamma.py': '_INSTANCE_SOURCES = ("instance",)\n',
            'delta.py': '', 'shipped.py': '', 'worker.py': '', 'instance.py': '',
            'unrelated.py': 'from . import entry\n',
            'mentions.py': '"""Mentions unrelated.py and agent_tools/docs.md only."""\n',
        })
        self.assertEqual(paths('alpha', 'beta', 'delta', 'entry', 'gamma', 'instance', 'shipped', 'worker'),
                         closure.closure(['entry'], tools))
        self.assertEqual(paths('mentions'), closure.closure(['mentions'], tools))

    # Every route by which a dispatch runs a file without a static import (review finding 2/3): a module the MCP
    # server loads by name, a runtime by-name load, a subpackage, a resource and the guest payloads a bundle ships.
    BY_NAME_TOOLS = {
        'server.py': '_VM_NATIVE_ADAPTERS = ("adapter_a",)\n'
                     'def _agent_module(name):\n    return name\n'
                     'def route():\n    return _agent_module("adapter_b")\n'
                     'import importlib\n'
                     'def lazy():\n    return importlib.import_module(f"{__package__}.adapter_c" if __package__ else "agent_tools.adapter_c")\n'
                     'def indirect():\n    name = "adapter_d"\n    return _agent_module(name)\n',
        'adapter_a.py': '', 'adapter_b.py': '', 'adapter_c.py': '', 'adapter_d.py': '',
        'profile.py': '_PROFILE_MODULES = ("held_one", "held_two")\n'
                      'def load(sources):\n    for name in _PROFILE_MODULES:\n        sources.load(name)\n'
                      'def session(loader, root):\n    return loader.SourceSession(root, "held_entry")\n',
        'held_one.py': '', 'held_two.py': '', 'held_entry.py': '',
        'dispatcher.py': 'from pathlib import Path\nMANIFEST = Path(__file__).with_suffix(".json")\n'
                         'POLICY = Path(__file__).with_name("policy.json")\n',
        'dispatcher.json': '{}\n', 'policy.json': '{}\n',
        'driver.py': 'COLLECTOR = "collector"\nCASES = "updater/cases.py"\n',
        'collector/hold.py': 'from . import contract\n', 'collector/contract.py': '', 'collector/guard.ps1': '',
        'collector/native.cs': '', 'updater/cases.py': '', 'updater/other.py': '',
        'bundle.py': '_SCENARIOS = {"driver": ("agent_tools/owner.ps1", "agent_tools/publisher.ps1.template",'
                     ' "scripts/test_packaged_cli.py")}\nGATEWAY = "gateway.source"\n',
        'owner.ps1': '', 'publisher.ps1.template': '', 'gateway.source': '', 'scripts/test_packaged_cli.py': '',
        'unrelated.py': '', 'tests/test_server.py': 'from agent_tools import unrelated\n',
    }
    BY_NAME_EXPECTED = {
        'server': paths('adapter_a', 'adapter_b', 'adapter_c', 'adapter_d', 'server'),
        'profile': paths('held_entry', 'held_one', 'held_two', 'profile'),
        'dispatcher': ['agent_tools/dispatcher.json', 'agent_tools/dispatcher.py', 'agent_tools/policy.json'],
        'driver': ['agent_tools/collector/contract.py', 'agent_tools/collector/guard.ps1', 'agent_tools/collector/hold.py',
                   'agent_tools/collector/native.cs', 'agent_tools/driver.py', 'agent_tools/updater/cases.py'],
        'bundle': ['agent_tools/bundle.py', 'agent_tools/gateway.source', 'agent_tools/owner.ps1',
                   'agent_tools/publisher.ps1.template', 'scripts/test_packaged_cli.py'],
    }

    def test_by_name_loads_subpackages_resources_and_payloads_RED_before_GREEN(self):
        source = BY_NAME / 'dispatch_source_closure.before.source'
        provenance = json.loads((BY_NAME / 'provenance.json').read_bytes())
        self.assertEqual(provenance['sha256'], hashlib.sha256(source.read_bytes()).hexdigest())
        tools = self.tools(self.BY_NAME_TOOLS)
        if red_gate.red_required(self, source):
            before = types.ModuleType('closure_before_by_name')
            before.__file__ = str(closure.TOOLS / 'dispatch_source_closure.py')
            exec(compile(source.read_bytes(), str(source), 'exec'), before.__dict__)
            # RED: the bf8d2da2 rule followed static imports only; every by-name route stayed outside the closure.
            self.assertEqual(['server'], before.closure(['server'], tools))
            self.assertEqual(['profile'], before.closure(['profile'], tools))
            self.assertEqual(['dispatcher'], before.closure(['dispatcher'], tools))
            self.assertEqual(['driver'], before.closure(['driver'], tools))
            self.assertEqual(['bundle'], before.closure(['bundle'], tools))
        # GREEN: each route is a closure member, and an unrelated module or a test never is.
        for entry, expected in self.BY_NAME_EXPECTED.items():
            with self.subTest(entry=entry):
                self.assertEqual(expected, closure.closure([entry], tools))

    def test_actual_closures_hold_the_by_name_routes_of_the_review(self):
        routes = closure.declared(json.loads(closure.CATALOG.read_bytes()))
        windows = set(routes['scenario-status'])
        for path in ('agent_tools/readiness_vm_dispatch.py', 'agent_tools/readiness_vm_dispatch.json',
                     'agent_tools/ssh_program_execution.py', 'agent_tools/tool_action_policy.json',
                     'agent_tools/windows_system_collector/system_collector_native.cs',
                     'agent_tools/windows_system_collector/release_template.ps1',
                     'agent_tools/windows_public_updater/update_cases.py',
                     'agent_tools/windows_scenario_publisher.ps1.template', 'agent_tools/windows_ordinary_task_owner.ps1',
                     'scripts/test_packaged_cli.py'):
            self.assertIn(path, windows)
        self.assertIn('agent_tools/readiness_tart_macos_unlock_observer.py',
                      set(closure.closure(['readiness_tart_macos_unlock_qualification'], cache=closure._Cache(closure.TOOLS))),
                      '_PROFILE_MODULES')
        self.assertFalse([path for path in windows if '/tests/' in path or path.endswith('.md')])

    def test_a_missing_or_extra_member_is_a_mismatch(self):
        tools = self.tools({'entry.py': 'from . import alpha\n', 'alpha.py': '', 'other.py': ''})
        catalog = {'actions': {'exact': {'modules': ['entry'], 'closure': paths('alpha', 'entry')},
                               'missing': {'modules': ['entry'], 'closure': paths('entry')},
                               'extra': {'modules': ['entry'], 'closure': paths('alpha', 'entry', 'other')}}}
        self.assertEqual({'missing': {'missing': paths('alpha'), 'extra': []},
                          'extra': {'missing': [], 'extra': paths('other')}}, closure.mismatches(catalog, tools))
        # A shared list is named by its own content; a misnamed one is a mismatch too.
        shared = {'schemaVersion': 3, 'closures': {closure.closure_id(paths('alpha', 'entry')): paths('alpha', 'entry')},
                  'actions': {'exact': {'modules': ['entry'], 'closure': closure.closure_id(paths('alpha', 'entry'))}}}
        self.assertEqual({}, closure.mismatches(shared, tools))
        shared['closures'] = {'closure-0000000000000000': paths('alpha', 'entry')}
        shared['actions']['exact']['closure'] = 'closure-0000000000000000'
        self.assertEqual(['closures:closure-0000000000000000'], list(closure.mismatches(shared, tools)))

    def test_actual_catalog_closures_equal_the_computed_closures(self):
        found = closure.mismatches()
        self.assertEqual({}, found, 'run python3 -m agent_tools.dispatch_source_closure --write and review the diff')

    def test_preserved_hand_maintained_closures_RED_current_GREEN(self):
        raw = (FIXTURE / 'closures.before.json.gz').read_bytes()
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        extract = gzip.decompress(raw)
        self.assertEqual(provenance['extractSha256'], hashlib.sha256(extract).hexdigest())
        before = {'actions': json.loads(extract)}
        for row in before['actions'].values():
            row['closure'] = paths(*row['closure'])
        red = closure.mismatches(before)
        # The guest worker the desktop test ships was declared, but the transport
        # every SSH action imports was not: pins covered fewer files than can run.
        self.assertIn('agent_tools/ssh_transport.py', red['android-action-acceptance-collect']['missing'])
        self.assertGreater(len(red), 400)
        self.assertEqual({}, closure.mismatches())


class ProofSymbolTests(unittest.TestCase):
    """A fixed-host proof names the symbol that holds or validates the row's host literal."""

    def tools(self, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, text in files.items():
            (root / name).write_text(text)
        return root

    def row(self, kind, symbol, host='archlinux', module='entry'):
        return {'kind': 'fixed_host', 'host': host, 'modules': ['entry'], 'closure': paths('entry', 'other'),
                'proof': {'kind': kind, 'module': module, 'symbol': symbol}}

    def test_actual_catalog_proofs_name_symbols_holding_their_host(self):
        self.assertEqual({}, closure.proof_problems())

    def test_each_wrong_proof_is_named(self):
        tools = self.tools({
            'entry.py': 'HOST = "archlinux"\nOTHER = "fedora"\n'
                        'class Intent:\n    def check(self, value):\n        return value.get("host") == "archlinux"\n'
                        'def loose(value):\n    return "archlinux"\n',
            'other.py': 'HOST = "archlinux"\n', 'outside.py': 'HOST = "archlinux"\n'})
        catalog = {'actions': {
            'constant': self.row('host-constant', 'HOST'),
            'method': self.row('validated-host', 'Intent.check'),
            'wrong-host': self.row('host-constant', 'OTHER'),
            'host-changed': self.row('host-constant', 'HOST', host='fedora'),
            'missing': self.row('host-constant', 'GONE'),
            'not-compared': self.row('validated-host', 'loose'),
            'constant-as-validation': self.row('validated-host', 'HOST'),
            'outside-closure': self.row('host-constant', 'HOST', module='outside'),
            'unbound': {'kind': 'selected_host', 'modules': ['entry'], 'closure': paths('entry')}}}
        self.assertEqual({'wrong-host': 'proof_symbol_not_host_constant',
                          'host-changed': 'proof_symbol_not_host_constant',
                          'missing': 'proof_symbol_missing',
                          'not-compared': 'proof_symbol_does_not_validate_host',
                          'constant-as-validation': 'proof_symbol_does_not_validate_host',
                          'outside-closure': 'proof_module_outside_closure'},
                         closure.proof_problems(catalog, tools))

    def test_preserved_parser_accepts_an_anchor_without_the_host_RED_symbol_check_refuses_GREEN(self):
        before = Path(__file__).parent / 'fixtures' / 'committed_source' / 'readiness_vm_dispatch.before.source'
        raw = before.read_bytes()
        provenance = json.loads((before.parent / 'provenance.json').read_bytes())
        self.assertEqual(provenance['sha256'], hashlib.sha256(raw).hexdigest())
        source = (closure.TOOLS / 'ssh_fresh_nested_channel.py').read_text()
        digest = hashlib.sha256(source.encode()).hexdigest()
        line = next(n for n, text in enumerate(source.splitlines(), 1) if 'archlinux' not in text)
        # RED: the a34e07cb parser checked only that the proof digest equalled the
        # module pin; the anchored line was never read, so a line without the host
        # (or one that moved) was accepted, and any edit ended the digest instead.
        manifest = {'schemaVersion': 1, 'sourcePins': {'ssh_fresh_nested_channel': digest}, 'actions': {'a': {
            'kind': 'fixed_host', 'host': 'archlinux', 'modules': ['ssh_fresh_nested_channel'],
            'closure': ['ssh_fresh_nested_channel'],
            'proof': {'kind': 'host-constant', 'module': 'ssh_fresh_nested_channel', 'line': line, 'sha256': digest}}}}
        tree = ast.parse(raw)
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in ('_unique', '_parse_manifest')]
        namespace = {'json': json, 're': re, '_KINDS': frozenset({'fixed_host'}), '_MODULE': re.compile(r'[a-z][a-z0-9_]{0,127}\Z'),
                     '_ALIAS': re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z'), '_MANIFEST_RAW': json.dumps(manifest).encode()}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(before), 'exec'), namespace)
        self.assertEqual('archlinux', namespace['_parse_manifest']()['actions']['a']['host'])
        # GREEN: a symbol anchor must hold the host literal, and survives unrelated edits.
        tools = self.tools({'ssh_fresh_nested_channel.py': '# an unrelated line above the constant\n' + source,
                            'other.py': 'HOST = "fedora"\n'})
        row = self.row('host-constant', 'HOST', module='ssh_fresh_nested_channel')
        row['closure'] = paths('ssh_fresh_nested_channel', 'other')
        wrong = dict(row, proof={'kind': 'host-constant', 'module': 'other', 'symbol': 'HOST'})
        self.assertEqual({'wrong': 'proof_symbol_not_host_constant'},
                         closure.proof_problems({'actions': {'right': row, 'wrong': wrong}}, tools))

if __name__ == '__main__':
    unittest.main()
