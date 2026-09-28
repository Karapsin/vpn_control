#!/usr/bin/env python3
"""Fast source and artifact checks for the hosted Linux RPM fixture pair."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from verify_linux_update_fixture import verify_fixture


ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / '.github/workflows/linux-desktop.yml'
CORRELATION = '12345678-1234-1234-1234-123456789abc'


class LinuxUpdateFixtureWorkflowTest(unittest.TestCase):
    def fixture(self, root: Path):
        source_sha = 'a' * 40
        fingerprint = 'b' * 64
        code = 'c' * 64
        builds = []
        for label, version in (('base', '2.1.19'), ('target', '2.2.0')):
            package = root / 'packages' / label / f'vpn-control-{version}-1.x86_64.rpm'
            package.parent.mkdir(parents=True)
            package.write_bytes(label.encode())
            builds.append({'label': label, 'version': version, 'sourceFingerprint': fingerprint,
                           'codeFingerprint': code, 'assets': [{'packageType': 'rpm',
                           'fileName': package.name, 'sizeBytes': package.stat().st_size,
                           'sha256': hashlib.sha256(package.read_bytes()).hexdigest()}]})
        (root / 'snapshot.json').write_text(json.dumps({'schemaVersion': 1, 'sourceHead': source_sha,
                                                        'sourceFingerprint': fingerprint}))
        (root / 'build-plan.json').write_text(json.dumps({'schemaVersion': 1, 'testOnly': True,
            'productionTrustChanged': False, 'sourceFingerprint': fingerprint, 'platform': 'linux',
            'packageFamily': 'default', 'architecture': 'x86_64',
            'stages': [{'label': 'base', 'version': '2.1.19'}, {'label': 'target', 'version': '2.2.0'}]}))
        (root / 'fixture-receipt.json').write_text(json.dumps({'schemaVersion': 1, 'testOnly': True,
            'productionTrustChanged': False, 'sourceFingerprint': fingerprint, 'architecture': 'x86_64',
            'builds': builds}))
        return source_sha

    def test_verifier_binds_exact_sha_same_source_versions_rpm_bytes_and_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = self.fixture(root)
            query = lambda path: ('vpn-control', path.name.split('-')[2], '1', 'x86_64')
            result = verify_fixture(root, sha, '2.1.19', '2.2.0', CORRELATION, rpm_query=query)
            self.assertEqual(sha, result['sourceHead'])
            self.assertEqual(CORRELATION, result['correlationId'])
            self.assertNotEqual(result['baseRpmSha256'], result['targetRpmSha256'])
            target = root / 'packages/target/vpn-control-2.2.0-1.x86_64.rpm'
            target.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'RPM bytes'):
                verify_fixture(root, sha, '2.1.19', '2.2.0', CORRELATION, rpm_query=query)

    def test_verifier_rejects_source_version_code_and_nevra_mismatches(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = self.fixture(root)
            query = lambda path: ('vpn-control', path.name.split('-')[2], '1', 'x86_64')
            with self.assertRaisesRegex(ValueError, 'source HEAD'):
                verify_fixture(root, 'd' * 40, '2.1.19', '2.2.0', CORRELATION, rpm_query=query)
            with self.assertRaisesRegex(ValueError, 'version'):
                verify_fixture(root, sha, '2.1.18', '2.2.0', CORRELATION, rpm_query=query)
            receipt = root / 'fixture-receipt.json'
            value = json.loads(receipt.read_text())
            value['builds'][1]['codeFingerprint'] = 'd' * 64
            receipt.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'code fingerprint'):
                verify_fixture(root, sha, '2.1.19', '2.2.0', CORRELATION, rpm_query=query)
            value['builds'][1]['codeFingerprint'] = 'c' * 64
            receipt.write_text(json.dumps(value))
            with self.assertRaisesRegex(ValueError, 'RPM header'):
                verify_fixture(root, sha, '2.1.19', '2.2.0', CORRELATION, rpm_query=lambda _path: ('other', '2.2.0', '1', 'x86_64'))

    def test_verifier_rejects_symlinked_package_ancestor_and_correlation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = self.fixture(root)
            query = lambda path: ('vpn-control', path.name.split('-')[2], '1', 'x86_64')
            with self.assertRaisesRegex(ValueError, 'correlationId'):
                verify_fixture(root, sha, '2.1.19', '2.2.0', 'not-a-uuid', rpm_query=query)
            base = root / 'packages/base'
            moved = root / 'moved-base'
            base.rename(moved)
            base.symlink_to(moved, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'RPM path'):
                verify_fixture(root, sha, '2.1.19', '2.2.0', CORRELATION, rpm_query=query)

    def test_workflow_dispatch_is_dev_only_and_keeps_ordinary_package_job(self):
        workflow = WORKFLOW.read_text()
        self.assertIn('workflow_dispatch:\n    inputs:\n      fixture_base_version:', workflow)
        guard = "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/dev' && inputs.fixture_base_version != ''"
        self.assertEqual(2, workflow.count(guard))
        self.assertIn("if: github.event_name != 'workflow_dispatch' || inputs.fixture_base_version == ''", workflow)
        self.assertIn('runs-on: ubuntu-latest', workflow)
        self.assertIn('scripts/verify_linux_update_fixture.py', workflow)
        self.assertIn('vpn-control-linux-update-fixture-${{ inputs.correlation_id }}', workflow)
        self.assertIn('run-name: Linux RPM fixture ${{ inputs.correlation_id', workflow)
        self.assertIn('--correlation-id "$FIXTURE_CORRELATION_ID"', workflow)
        self.assertIn('fixture-verification.json', workflow)
        self.assertNotIn('refs/heads/main', workflow)


if __name__ == '__main__':
    unittest.main()
