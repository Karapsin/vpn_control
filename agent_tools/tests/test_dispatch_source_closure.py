"""CI rule: each dispatch action's declared closure equals its computed source closure."""
import ast
import gzip
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest

from agent_tools import dispatch_source_closure as closure

FIXTURE = Path(__file__).parent / 'fixtures' / 'dispatch_source_closure'


class ComputedClosureTests(unittest.TestCase):
    def tools(self, files):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for name, text in files.items():
            (root / name).write_text(text)
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
        self.assertEqual(['alpha', 'beta', 'delta', 'entry', 'gamma', 'instance', 'shipped', 'worker'],
                         closure.closure(['entry'], tools))
        self.assertEqual(['mentions'], closure.closure(['mentions'], tools))

    def test_a_missing_or_extra_member_is_a_mismatch(self):
        tools = self.tools({'entry.py': 'from . import alpha\n', 'alpha.py': '', 'other.py': ''})
        catalog = {'actions': {'exact': {'modules': ['entry'], 'closure': ['alpha', 'entry']},
                               'missing': {'modules': ['entry'], 'closure': ['entry']},
                               'extra': {'modules': ['entry'], 'closure': ['alpha', 'entry', 'other']}}}
        self.assertEqual({'missing': {'missing': ['alpha'], 'extra': []},
                          'extra': {'missing': [], 'extra': ['other']}}, closure.mismatches(catalog, tools))

    def test_actual_catalog_closures_equal_the_computed_closures(self):
        found = closure.mismatches()
        self.assertEqual({}, found, 'run python3 -m agent_tools.dispatch_source_closure --write and review the diff')

    def test_preserved_hand_maintained_closures_RED_current_GREEN(self):
        raw = (FIXTURE / 'closures.before.json.gz').read_bytes()
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        extract = gzip.decompress(raw)
        self.assertEqual(provenance['extractSha256'], hashlib.sha256(extract).hexdigest())
        before = {'actions': json.loads(extract)}
        red = closure.mismatches(before)
        # The guest worker the desktop test ships was declared, but the transport
        # every SSH action imports was not: pins covered fewer files than can run.
        self.assertIn('ssh_transport', red['android-action-acceptance-collect']['missing'])
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
        return {'kind': 'fixed_host', 'host': host, 'modules': ['entry'], 'closure': ['entry', 'other'],
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
            'unbound': {'kind': 'selected_host', 'modules': ['entry'], 'closure': ['entry']}}}
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
        row['closure'] = ['ssh_fresh_nested_channel', 'other']
        wrong = dict(row, proof={'kind': 'host-constant', 'module': 'other', 'symbol': 'HOST'})
        self.assertEqual({'wrong': 'proof_symbol_not_host_constant'},
                         closure.proof_problems({'actions': {'right': row, 'wrong': wrong}}, tools))

if __name__ == '__main__':
    unittest.main()
