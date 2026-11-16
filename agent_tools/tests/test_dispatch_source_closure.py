"""CI rule: each dispatch action's declared closure equals its computed source closure."""
import gzip
import hashlib
import json
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
