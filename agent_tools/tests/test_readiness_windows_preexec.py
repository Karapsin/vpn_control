"""Finite authenticated native evidence and proof-aware idle inventory boundaries."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from agent_tools import readiness_windows_jobs as jobs
from agent_tools import readiness_windows_preexec as preexec

FIXTURE = Path(__file__).parent / 'fixtures/windows_jobs_preexec'
PROOF_PATH = '.runtime/tool-recovery-windows/counter-libvirt/original-d82-authenticated-preexec-proof.json'


def fixtures():
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    names = provenance['sourceSha256']
    if provenance['schemaVersion'] != 1 or set(names) != {'proof.json'} | set(provenance['evidenceFiles'].values()):
        raise AssertionError('preexec fixture scope changed')
    result = {}
    for name, expected in names.items():
        raw = (FIXTURE / name).read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected:
            raise AssertionError('preexec fixture changed: ' + name)
        result[name] = raw
    return provenance, result


class PreexecTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.provenance, self.payloads = fixtures()
        for original, name in self.provenance['evidenceFiles'].items():
            self.write(original, self.payloads[name])
        self.write(PROOF_PATH, self.payloads['proof.json'])
        self.binding = jobs.WindowsJobBinding('6e848ad1-8078-4435-9abc-e3a24c6556cd',
            '2026-10-20T12:51:49.5000000Z','5468de77:000c000000007cf5:01dd60ba1e9a6e95',
            '5468de77:000b000000007cf7:01dd60ba1e9ac3fc')

    def write(self, path, raw):
        location = self.root / path
        location.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        location.write_bytes(raw)
        location.chmod(0o600)

    def digest(self):
        return hashlib.sha256((self.root / PROOF_PATH).read_bytes()).hexdigest()

    def authenticate(self):
        return preexec.authenticate_preexec_rejection(self.root, PROOF_PATH, self.digest(), self.binding)

    def rewrite_evidence(self, relative, body):
        self.write(relative, body)
        proof = json.loads((self.root / PROOF_PATH).read_bytes())
        proof['evidence'][relative] = {'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
        self.write(PROOF_PATH, json.dumps(proof, sort_keys=True).encode())

    def test_actual_original_controller_phase_and_native_custody_join_without_executing_old_source(self):
        proof = self.authenticate()
        value = proof.guard()
        self.assertEqual('d82c6b3b-882b-4667-be84-f8808b99db0e', value['operationId'])
        self.assertEqual(8812, value['controllerPid'])
        self.assertEqual('134369916462713843', value['controllerBirth'])
        self.assertEqual('9626e3774bdf1b83e9767cfea828b6a75f8b6930ce70717002f904ce2392f3fc', value['programSha256'])
        self.assertEqual(120, value['count'])
        self.assertEqual(1000, value['intervalMilliseconds'])
        self.assertEqual(self.provenance['sourceSha256']['proof.json'], proof.proof_sha256)

    def test_explicit_acceptance_is_create_only_and_pure_lookup_reauthenticates_all_evidence(self):
        before = sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*'))
        self.assertEqual((), preexec.preexec_rejections(self.root, 'trusted-fixture', self.binding))
        self.assertEqual(before, sorted(str(p.relative_to(self.root)) for p in self.root.rglob('*')))
        proof = preexec.register_preexec_rejection(self.root, 'trusted-fixture', self.binding, PROOF_PATH, self.digest())
        again = preexec.preexec_rejections(self.root, 'trusted-fixture', self.binding)
        self.assertEqual(1, len(again))
        self.assertEqual(proof.guard(), again[0].guard())
        preexec.register_preexec_rejection(self.root, 'trusted-fixture', self.binding, PROOF_PATH, self.digest())
        evidence = next(iter(self.provenance['evidenceFiles']))
        with (self.root / evidence).open('ab') as stream:
            stream.write(b' ')
        with self.assertRaises(ValueError):
            preexec.preexec_rejections(self.root, 'trusted-fixture', self.binding)

    def test_changed_original_artifacts_source_controller_or_probe_never_gain_authority(self):
        paths = self.provenance['evidenceFiles']
        packet = next(p for p in paths if p.endswith('/job-start.py'))
        diagnostic = next(p for p in paths if '/admitted-812b25d7-' in p and p.endswith('/result.json'))
        result = next(p for p in paths if 'jobs-controllers/' in p and p.endswith('/result.json'))
        scenarios = ((packet, b'# changed\n'), (diagnostic, None), (result, None))
        for path, replacement in scenarios:
            with self.subTest(path=path):
                original = (self.root / path).read_bytes()
                if replacement is None:
                    body = json.loads(original)
                    if path == diagnostic:
                        body['sessionFacts']['controllerAbsent'] = False
                    else:
                        body['jobController']['terminal']['exitcode'] = 1
                    replacement = json.dumps(body).encode()
                self.rewrite_evidence(path, replacement)
                with self.assertRaises((ValueError, SyntaxError)):
                    self.authenticate()
                self.write(path, original)
                self.write(PROOF_PATH, self.payloads['proof.json'])

    def test_claim_generation_nonce_source_acl_or_census_mutations_are_not_accepted(self):
        path = next(p for p in self.provenance['evidenceFiles'] if '/admitted-812b25d7-' in p and p.endswith('/result.json'))
        original = (self.root / path).read_bytes()
        for key, value in (('claimGeneration', 'changed'), ('claimNonce', 'changed'), ('programSha256', '0'*64),
                           ('jobGeneration', 'changed'), ('jobOwnerSid', 'S-1-5-18'), ('jobRules', []),
                           ('visibilityComplete', False), ('entries', ['owner.ps1']), ('actorCount', 1),
                           ('controllerBirth', '1'), ('machine', '00000000-0000-4000-8000-000000000000')):
            with self.subTest(key=key):
                body = json.loads(original)
                body['sessionFacts'][key] = value
                self.rewrite_evidence(path, json.dumps(body).encode())
                with self.assertRaises(ValueError):
                    self.authenticate()
                self.write(path, original)
                self.write(PROOF_PATH, self.payloads['proof.json'])

    def test_lifetime_inode_replacement_symlink_hardlink_and_forged_type_are_blocked(self):
        proof = self.authenticate()
        path = self.root / next(iter(self.provenance['evidenceFiles']))
        raw = path.read_bytes()
        path.unlink(); path.write_bytes(raw); path.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'evidence_changed'):
            proof.guard()
        link = self.root / '.runtime/link'
        link.symlink_to(self.root / PROOF_PATH)
        with self.assertRaises(Exception):
            preexec.authenticate_preexec_rejection(self.root, '.runtime/link', self.digest(), self.binding)
        link.unlink(); os.link(self.root / PROOF_PATH, link)
        with self.assertRaisesRegex(ValueError, 'evidence_unsafe'):
            self.authenticate()
        forged = preexec.PreexecRejection('{}', '0'*64, self.root, (), object())
        with self.assertRaisesRegex(ValueError, 'authority_invalid'):
            forged.guard()

    def test_only_sameboot_fixed_inventory_is_qualified_and_original_work_stays_blocked(self):
        proof = self.authenticate()
        b = self.binding
        source = preexec.inventory_source(b.machine,b.boot,b.root_generation,b.admission_generation,rejections=(proof,))
        self.assertIn(b'[NativePreexecInventory]::Run([NativeJob],', source)
        self.assertNotIn('CreateDirectory', preexec._INVENTORY)
        self.assertNotIn('CreateProcess', preexec._INVENTORY)
        self.assertNotIn('FileMode.Create', preexec._INVENTORY)
        value = {'schemaVersion':1,'machine':b.machine,'boot':b.boot,'rootGeneration':b.root_generation,
                 'admissionGeneration':b.admission_generation,'visibilityComplete':True,'terminalCount':1,
                 'blockers':[{'operationId':'00000000-0000-4000-8000-000000000001','reason':'job_original_work_not_terminal'}]}
        self.assertEqual(value, preexec.validate_inventory(value,b.machine,b.boot,b.root_generation,b.admission_generation,rejections=(proof,)))
        with self.assertRaisesRegex(ValueError, 'storage_continuity_required'):
            preexec.inventory_source(b.machine,'2026-10-21T00:00:00.0000000Z',b.root_generation,b.admission_generation,rejections=(proof,))
        with self.assertRaisesRegex(ValueError, 'storage_continuity_unqualified'):
            preexec.inventory_source(b.machine,b.boot,b.root_generation,b.admission_generation,rejections=(proof,),continuity={'trusted':True})


if __name__ == '__main__':
    unittest.main()
