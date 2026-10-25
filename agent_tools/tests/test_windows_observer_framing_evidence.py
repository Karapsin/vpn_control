"""Authenticate complete native readonly-observer framing RED/GREEN evidence."""
import base64
import hashlib
import json
from pathlib import Path
import unittest

FIXTURE = Path(__file__).parent / 'fixtures' / 'windows_jobs_observer_framing'
FILES = ('status.before.source', 'status.fixed.source', 'native-failure.json', 'native-green.json')


class WindowsObserverFramingEvidenceTests(unittest.TestCase):
    def test_original_unframed_exit_and_fixed_canonical_frame_are_same_observation(self):
        provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
        self.assertEqual(1, provenance['schemaVersion'])
        self.assertEqual(set(FILES), set(provenance['sourceSha256']))
        source = {}
        for name in FILES:
            raw = (FIXTURE / name).read_bytes()
            self.assertEqual(provenance['sourceSha256'][name], hashlib.sha256(raw).hexdigest(), name)
            source[name] = raw
        before = json.loads(source['native-failure.json'])
        green = json.loads(source['native-green.json'])
        self.assertEqual(hashlib.sha256(source['status.before.source']).hexdigest(), before['sourceSha256'])
        self.assertEqual(hashlib.sha256(source['status.fixed.source']).hexdigest(), green['sourceSha256'])
        self.assertIs(True, before['terminal']['exited'])
        self.assertEqual(0, before['terminal']['exitcode'])
        unframed = json.loads(base64.b64decode(before['terminal']['out-data'], validate=True))
        self.assertNotIn('owner', unframed)
        self.assertNotIn('sourceSha256', unframed)
        self.assertEqual(unframed, green['sessionFacts'])
        self.assertEqual('observed_absent', unframed['state'])
        self.assertIs(False, unframed['rootPresent'])
        self.assertIs(True, unframed['visibilityComplete'])
        self.assertEqual([], unframed['matchingActors'])
        self.assertEqual(0, unframed['actorCount'])
        self.assertIs(False, unframed['replayAllowed'])
        old_output = [line for line in source['status.before.source'].splitlines()
                      if line.lstrip().startswith(b'[Console]::WriteLine(')]
        new_output = [line for line in source['status.fixed.source'].splitlines()
                      if line.lstrip().startswith(b'[Console]::WriteLine(')]
        self.assertEqual(2, len(old_output))
        self.assertIn(b';exit', old_output[0])
        self.assertEqual(1, len(new_output))
        self.assertEqual(new_output[0], source['status.fixed.source'].rstrip().splitlines()[-1])


if __name__ == '__main__':
    unittest.main()
