import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
from zipfile import ZipFile

from agent_tools import native_rpm_public_install_ssh


SHA = 'a' * 40
FINGERPRINT = 'b' * 64
CODE = 'c' * 64
JAR = 'd' * 64


def digest(data):
    return hashlib.sha256(data).hexdigest()


class LinuxRpmFixtureDeriveTest(unittest.TestCase):
    def source(self, root):
        files = root / 'hosted'
        files.mkdir()
        (files / 'packages/base').mkdir(parents=True)
        (files / 'packages/target').mkdir(parents=True)
        builds = []
        for label, version in (('base', '2.1.19'), ('target', '2.2.0')):
            rpm_name = f'vpn-control-{version}-1.x86_64.rpm'
            rpm_data = (label + '-rpm').encode()
            (files / 'packages' / label / rpm_name).write_bytes(rpm_data)
            rpm = {'packageType': 'rpm', 'fileName': rpm_name, 'platform': 'linux',
                   'displayVersion': version, 'sizeBytes': len(rpm_data), 'sha256': digest(rpm_data),
                   'downloadUrl': 'https://github.com/example/' + rpm_name}
            deb = {'packageType': 'deb', 'fileName': f'vpn-control_{version}.deb',
                   'sizeBytes': 9, 'sha256': 'e' * 64}
            builds.append({'label': label, 'version': version, 'sourceFingerprint': FINGERPRINT,
                           'codeFingerprint': CODE, 'mainJarSha256': JAR, 'assets': [deb, rpm]})
        receipt = {'schemaVersion': 1, 'testOnly': True, 'productionTrustChanged': False,
                   'sourceFingerprint': FINGERPRINT, 'builds': builds,
                   'manifest': {'schemaVersion': 1, 'assets': builds[1]['assets'],
                                'releaseNotesUrl': 'https://github.com/example/notes'}}
        (files / 'fixture-receipt.json').write_text(json.dumps(receipt))
        (files / 'snapshot.json').write_text(json.dumps({'schemaVersion': 1, 'sourceHead': SHA,
                                                         'sourceFingerprint': FINGERPRINT}))
        (files / 'build-plan.json').write_text(json.dumps({'schemaVersion': 1, 'sourceFingerprint': FINGERPRINT,
                                                           'testOnly': True, 'productionTrustChanged': False,
                                                           'platform': 'linux', 'packageFamily': 'default',
                                                           'architecture': 'x86_64'}))
        archive = root / 'hosted.zip'
        with ZipFile(archive, 'w') as zipped:
            for path in sorted(files.rglob('*')):
                if path.is_file():
                    zipped.write(path, path.relative_to(files))
        verification = root / 'verification.json'
        verification.write_text(json.dumps({'verification': 'independently-verified',
            'artifactId': 12345, 'artifactZipSha256': digest(archive.read_bytes()),
            'sourceHead': SHA, 'sourceFingerprint': FINGERPRINT,
            'baseRpmSha256': receipt['builds'][0]['assets'][1]['sha256'],
            'targetRpmSha256': receipt['builds'][1]['assets'][1]['sha256'],
            'correlationId': '12345678-1234-1234-1234-123456789abc'}))
        return files, receipt, archive, verification

    def test_original_receipt_missing_deb_fails_but_explicit_rpm_subset_admits(self):
        from agent_tools import linux_rpm_fixture_derive as derive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files, original, archive, verification = self.source(root)
            target = root / 'rpm-only'
            result = derive.derive(files, target, source_sha=SHA, hosted_artifact_id=12345,
                                   hosted_zip=archive, verification_receipt=verification)
            self.assertFalse((target / '.incomplete').exists())
            self.assertTrue((target / 'derivation.json').is_file())
            self.assertEqual('rpm-only', result['scope'])
            self.assertEqual(digest((files / 'fixture-receipt.json').read_bytes()),
                             result['originalReceiptSha256'])
            self.assertEqual(2, len(original['builds'][0]['assets']))
            self.assertEqual(1, len(json.loads((target / 'fixture-receipt.json').read_text())['builds'][0]['assets']))
            typed = {'sourceFingerprint': FINGERPRINT, 'expectedBaseVersion': '2.1.19',
                     'expectedTargetVersion': '2.2.0', 'expectedDesktopJarSha256': JAR,
                     'targetPackageSha256': digest(b'target-rpm'), 'fixtureHttpsOrigin': 'https://github.com'}
            native_rpm_public_install_ssh._fixture(target / 'source-fixture.tar', typed)
            with tarfile.open(target / 'source-fixture.tar') as archive:
                self.assertEqual({'fixture-receipt.json', 'packages/base/vpn-control-2.1.19-1.x86_64.rpm',
                                  'packages/target/vpn-control-2.2.0-1.x86_64.rpm'},
                                 {item.name for item in archive})
            self.assertEqual(2, len(original['builds'][1]['assets']))

    def test_changed_rpm_or_source_sha_rejects_before_output(self):
        from agent_tools import linux_rpm_fixture_derive as derive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files, _, archive, verification = self.source(root)
            (files / 'packages/base/vpn-control-2.1.19-1.x86_64.rpm').write_bytes(b'wrong')
            with self.assertRaises(ValueError):
                derive.derive(files, root / 'bad-bytes', source_sha=SHA, hosted_artifact_id=12345,
                              hosted_zip=archive, verification_receipt=verification)
            self.assertFalse((root / 'bad-bytes').exists())
            with self.assertRaises(ValueError):
                derive.derive(files, root / 'bad-sha', source_sha='f' * 40, hosted_artifact_id=12345,
                              hosted_zip=archive, verification_receipt=verification)
            self.assertFalse((root / 'bad-sha').exists())

    def test_forged_verification_and_partial_write_fail_without_output(self):
        from agent_tools import linux_rpm_fixture_derive as derive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files, _, archive, verification = self.source(root)
            altered = json.loads(verification.read_text())
            altered['artifactZipSha256'] = '0' * 64
            verification.write_text(json.dumps(altered))
            with self.assertRaises(ValueError):
                derive.derive(files, root / 'forged', source_sha=SHA, hosted_artifact_id=12345,
                              hosted_zip=archive, verification_receipt=verification)
            self.assertFalse((root / 'forged').exists())
            altered['artifactZipSha256'] = digest(archive.read_bytes())
            verification.write_text(json.dumps(altered))
            with mock.patch.object(tarfile.TarFile, 'addfile', side_effect=OSError('disk full')):
                with self.assertRaises(OSError):
                    derive.derive(files, root / 'partial', source_sha=SHA, hosted_artifact_id=12345,
                                  hosted_zip=archive, verification_receipt=verification)
            self.assertFalse((root / 'partial').exists())

    def test_rpm_replaced_after_initial_hash_rejects_published_tar(self):
        from agent_tools import linux_rpm_fixture_derive as derive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files, _, archive, verification = self.source(root)
            original = tarfile.TarFile.addfile
            def replace_after_receipt(target, info, stream):
                original(target, info, stream)
                if info.name == 'fixture-receipt.json':
                    (files / 'packages/base/vpn-control-2.1.19-1.x86_64.rpm').write_bytes(b'changed!')
            with mock.patch.object(tarfile.TarFile, 'addfile', replace_after_receipt):
                with self.assertRaises(ValueError):
                    derive.derive(files, root / 'changed-during-write', source_sha=SHA,
                                  hosted_artifact_id=12345, hosted_zip=archive,
                                  verification_receipt=verification)
            self.assertFalse((root / 'changed-during-write').exists())

    def test_existing_output_is_not_replaced(self):
        from agent_tools import linux_rpm_fixture_derive as derive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files, _, archive, verification = self.source(root)
            output = root / 'existing'
            output.mkdir()
            (output / 'marker').write_text('preserve')
            with self.assertRaises(ValueError):
                derive.derive(files, output, source_sha=SHA, hosted_artifact_id=12345,
                              hosted_zip=archive, verification_receipt=verification)
            self.assertEqual('preserve', (output / 'marker').read_text())

    def test_interrupted_publication_leaves_incomplete_output_and_foreign_path_untouched(self):
        from agent_tools import linux_rpm_fixture_derive as derive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files, _, archive, verification = self.source(root)
            output = root / 'rpm-only'
            foreign = root / 'foreign'
            foreign.mkdir()
            (foreign / 'keep').write_text('untouched')
            original = os.rename
            moves = 0
            def interrupt(source, destination, **kwargs):
                nonlocal moves
                if kwargs.get('dst_dir_fd') is not None:
                    moves += 1
                    if moves == 2:
                        raise OSError('interrupted publication')
                return original(source, destination, **kwargs)
            with mock.patch.object(os, 'rename', side_effect=interrupt):
                with self.assertRaisesRegex(OSError, 'interrupted publication'):
                    derive.derive(files, output, source_sha=SHA, hosted_artifact_id=12345,
                                  hosted_zip=archive, verification_receipt=verification)
            self.assertTrue((output / '.incomplete').is_file())
            self.assertFalse((output / 'derivation.json').exists())
            self.assertEqual('untouched', (foreign / 'keep').read_text())
            with self.assertRaises(ValueError):
                derive.derive(files, output, source_sha=SHA, hosted_artifact_id=12345,
                              hosted_zip=archive, verification_receipt=verification)

    def test_stage_removal_failure_cannot_mark_output_complete(self):
        from agent_tools import linux_rpm_fixture_derive as derive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files, _, archive, verification = self.source(root)
            output = root / 'rpm-only'
            original = Path.rmdir
            def fail_stage_removal(path):
                if path.name.startswith('.rpm-only-'):
                    raise OSError('stage removal failed')
                return original(path)
            with mock.patch.object(Path, 'rmdir', fail_stage_removal):
                with self.assertRaisesRegex(OSError, 'stage removal failed'):
                    derive.derive(files, output, source_sha=SHA, hosted_artifact_id=12345,
                                  hosted_zip=archive, verification_receipt=verification)
            self.assertTrue((output / '.incomplete').is_file())
            self.assertTrue((output / 'derivation.json').is_file())


if __name__ == '__main__':
    unittest.main()
