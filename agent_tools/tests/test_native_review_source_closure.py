"""Real temporary-filesystem regressions for authenticated source closure."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import native_review_source_closure as closure


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'),
                     'Strict FD closure requires a POSIX filesystem host')
class SourceClosureTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.a = self.root / 'a.py'
        self.b = self.root / 'b.py'
        self.a.write_bytes(b'first source')
        self.b.write_bytes(b'second source')

    def pin(self, path):
        return {'generation': list(closure.generation(path.stat())), 'sha256': sha(path.read_bytes())}

    def manifest(self, obj, name='review.json'):
        path = self.root / name
        raw = json.dumps(obj).encode()
        path.write_bytes(raw)
        return str(path), sha(raw)

    def close(self, obj, **kwargs):
        path, digest = self.manifest(obj)
        return closure.close_review_sources(path, digest, **kwargs)

    def test_list_schema_source_and_archive(self):
        archive = self.root / 'archive-0'
        archive.write_bytes(self.a.read_bytes())
        result = self.close({'verdict':'CLEAR', 'files':[{'path':str(self.a), 'pin':self.pin(self.a), 'archive':str(archive), 'archiveSha256':sha(archive.read_bytes())}]})
        self.assertFalse(result['nativeActionAllowed'])
        self.assertEqual(result['sourceCount'], 1)

    def test_final_freeze_inputs_absolute_pin_schema(self):
        obj = {'scope':'source/local final freeze',
               'inputs':{str(self.a):self.pin(self.a),str(self.b):self.pin(self.b)}}
        result = self.close(obj)
        self.assertEqual(result['sourceCount'], 2)
        self.assertEqual(result['sourceHashes'],
                         {str(self.a):sha(self.a.read_bytes()),str(self.b):sha(self.b.read_bytes())})
        self.assertEqual(result['scope'], 'SOURCE_ONLY')
        self.assertFalse(result['nativeActionAllowed'])

    def test_final_freeze_inputs_rejects_ambiguous_or_relative_schema(self):
        for other in ('files','pins'):
            with self.subTest(other=other), self.assertRaises(ValueError):
                self.close({'inputs':{str(self.a):self.pin(self.a)},other:{str(self.a):self.pin(self.a)}})
        with self.assertRaises(ValueError):
            self.close({'inputs':{'a.py':self.pin(self.a)}})

    def test_raw_manifest_direct_absolute_pin_map(self):
        result = self.close({str(self.a):self.pin(self.a),str(self.b):self.pin(self.b)})
        self.assertEqual(result['sourceCount'], 2)
        self.assertEqual(result['scope'], 'SOURCE_ONLY')
        self.assertFalse(result['nativeActionAllowed'])
        self.assertFalse(result['productAcceptance'])

    def test_raw_manifest_rejects_mixed_malformed_or_nonabsolute_maps(self):
        for obj in ({}, {'a.py':self.pin(self.a)},
                    {str(self.a):self.pin(self.a), 'scope':'source'},
                    {str(self.a):self.pin(self.a), 'pins':{str(self.b):self.pin(self.b)}},
                    {str(self.a):self.pin(self.a), 'files':{'b.py':self.pin(self.b)}},
                    {str(self.a):self.pin(self.a), 'inputs':{str(self.b):self.pin(self.b)}},
                    {str(self.a):{'generation':[1], 'sha256':'0'*64}}):
            with self.subTest(obj=obj), self.assertRaises(ValueError):
                self.close(obj)

    def test_pins_schema(self):
        self.assertEqual(self.close({'report':{}, 'pins':{str(self.a):self.pin(self.a)}})['sourceCount'], 1)

    def test_nested_verdict_archives_with_explicit_packet(self):
        packet, digest = self.manifest({'files':{'a.py':self.pin(self.a),'b.py':self.pin(self.b)}}, 'current-packet.json')
        for key in ('review','report','verdict'):
            with self.subTest(key=key):
                result = self.close({key:{'verdict':'CLEAR_SOURCE_ONLY'},'files':{'a.py':sha(self.a.read_bytes())}}, packet_manifest_path=packet, packet_manifest_sha256=digest)
                self.assertEqual(result['sourceCount'], 2)

    def test_archive_only_missing_explicit_current_manifest_rejected(self):
        with self.assertRaises(ValueError):
            self.close({'verdict':{},'files':{'a.py':sha(self.a.read_bytes())}})

    def test_explicit_authenticated_proof_source_pins(self):
        proof, digest = self.manifest({'sourcePins':{str(self.a):self.pin(self.a)}}, 'proof.json')
        result = self.close({'review':{},'files':{'proof.json':digest}}, proof_path=proof, proof_sha256=digest)
        self.assertEqual(result['sourceCount'], 1)

    def test_early_source_mutation_during_later_read_rejected(self):
        obj = {'pins':{str(self.a):self.pin(self.a),str(self.b):self.pin(self.b)}}
        original = closure._read_all
        fired = []
        def mutate(fd):
            raw = original(fd)
            if raw == b'second source' and not fired:
                fired.append(True)
                self.a.write_bytes(b'alter source')
            return raw
        with patch.object(closure, '_read_all', side_effect=mutate):
            with self.assertRaises(ValueError):
                self.close(obj)
        self.assertEqual(fired, [True])

    def test_reject_ambiguous_schema_malformed_pin_and_unsafe_path(self):
        for obj in ({'files':[], 'pins':{}}, {'pins':{str(self.a):{'generation':[1], 'sha256':'0'*64}}}, {'files':{'../a.py':self.pin(self.a)}}):
            with self.subTest(obj=obj), self.assertRaises(ValueError):
                self.close(obj)

    def test_full_sha_and_generation_drift(self):
        p = self.pin(self.a)
        self.a.write_bytes(b'first source')
        with self.assertRaises(ValueError):
            self.close({'pins':{str(self.a):p}})
        path, digest = self.manifest({'pins':{str(self.a):self.pin(self.a)}})
        with self.assertRaises(ValueError):
            closure.close_review_sources(path, digest[:12])

    def test_credentials_denied_before_open_metadata_observation_permitted(self):
        for name in ('credentials.json','binding.json','arch-sudo.local'):
            secret = self.root / name
            secret.write_bytes(b'do not read')
            pin = self.pin(secret)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.close({'pins':{str(secret):pin}})
        meta = self.root / 'credential-metadata-observation.json'
        meta.write_bytes(b'{"contentsRead":false}')
        self.assertEqual(self.close({'pins':{str(meta):self.pin(meta)}})['sourceCount'], 1)

    def test_numbered_and_backup_private_copies_denied_before_open(self):
        names = ('binding.json.0', 'binding-0.json', 'credentials.json.1',
                 'credentials-1.json', 'credentials_2.json', 'arch-sudo.local.1',
                 'arch-sudo-1.local', 'binding.json.bak', 'binding.json.backup',
                 'credentials.json.old', 'credentials.json.orig',
                 'arch-sudo.local~', '0-binding.json.1.bak')
        for name in names:
            with self.subTest(name=name):
                candidate = self.root / name
                # Harmless explicit TempFS content only; pin collected by test.
                candidate.write_bytes(b'inert private-name fixture')
                obj = {'pins':{str(candidate):self.pin(candidate)}}
                original_open = closure.os.open
                def guarded_open(path, *args, **kwargs):
                    if str(path) == name:
                        self.fail('Known private copy was opened')
                    return original_open(path, *args, **kwargs)
                with patch.object(closure.os, 'open', side_effect=guarded_open):
                    with self.assertRaises(ValueError):
                        self.close(obj)

    def test_private_metadata_observation_names_remain_source_artifacts(self):
        for name in ('binding-metadata-observation.json',
                     'credentials-metadata-observation.json',
                     'arch-sudo-metadata-observation.json'):
            candidate = self.root / name
            candidate.write_bytes(b'{"contentsRead":false}')
            with self.subTest(name=name):
                self.assertEqual(self.close({'pins':{str(candidate):self.pin(candidate)}})['sourceCount'], 1)

    def test_symlink_and_hardlink(self):
        pin = self.pin(self.a)
        linked = self.root / 'linked.py'
        linked.symlink_to(self.a)
        with self.assertRaises((ValueError, OSError)):
            self.close({'pins':{str(linked):pin}})
        linked.unlink()
        os.link(self.a, linked)
        with self.assertRaises(ValueError):
            self.close({'pins':{str(self.a):pin}})

    def test_parent_replacement_during_later_read_rejected(self):
        folder = self.root / 'held'
        folder.mkdir()
        early = folder / 'early.py'
        early.write_bytes(b'early')
        obj = {'pins':{str(early):self.pin(early),str(self.b):self.pin(self.b)}}
        original = closure._read_all
        fired = []
        def replace(fd):
            raw = original(fd)
            if raw == b'second source' and not fired:
                fired.append(True)
                folder.rename(self.root / 'old-held')
                folder.mkdir()
                (folder / 'early.py').write_bytes(b'early')
            return raw
        with patch.object(closure, '_read_all', side_effect=replace):
            with self.assertRaises(ValueError):
                self.close(obj)
        self.assertEqual(fired, [True])

    def test_early_mutation_during_final_rehash_rejected_by_pure_pass(self):
        obj = {'pins':{str(self.a):self.pin(self.a),str(self.b):self.pin(self.b)}}
        original = closure._read_all
        reads = []
        def mutate(fd):
            raw = original(fd)
            if raw == b'second source':
                reads.append(True)
                if len(reads) == 2:
                    self.a.write_bytes(b'alter source')
            return raw
        with patch.object(closure, '_read_all', side_effect=mutate):
            with self.assertRaises(ValueError):
                self.close(obj)
        self.assertEqual(len(reads), 2)

    def test_actual_last_parent_stat_unlink_refuses_in_shared_identity_pass(self):
        held = closure._Held()
        self.addCleanup(held.close)
        held.read(str(self.a), sha(self.a.read_bytes()), tuple(self.pin(self.a)['generation']))
        original = os.stat
        parent_fd = held.parents[str(self.root.parent)][0]
        fired = []
        def unlink_after_parent_observation(path, *args, **kwargs):
            observed = original(path, *args, **kwargs)
            if path == self.root.name and kwargs.get('dir_fd') == parent_fd and not fired:
                fired.append(True)
                self.a.unlink()
            return observed
        with patch.object(os, 'stat', side_effect=unlink_after_parent_observation):
            with self.assertRaises((ValueError, OSError)):
                held.final_identity_pass()
        self.assertEqual([True], fired)
        self.assertFalse(self.a.exists())

    def test_unlisted_proof_rejected(self):
        proof, digest = self.manifest({'sourcePins':{str(self.a):self.pin(self.a)}}, 'proof.json')
        with self.assertRaises(ValueError):
            self.close({'files':{'a.py':sha(self.a.read_bytes())}}, proof_path=proof, proof_sha256=digest)

    def test_duplicate_json_keys_rejected(self):
        raw = b'{"pins":{},"pins":{}}'
        path = self.root / 'duplicates.json'
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            closure.close_review_sources(str(path), sha(raw))

    def test_causal_legacy_list_only_schema_misses_actual_packet(self):
        original = closure._schema
        def list_only(obj):
            if not isinstance(obj.get('files'), list):
                raise ValueError('legacy incorrect assumption: files must be a list')
            return original(obj)
        with patch.object(closure, '_schema', side_effect=list_only):
            result = unittest.TestResult()
            SourceClosureTest('test_nested_verdict_archives_with_explicit_packet').run(result)
        self.assertEqual(len(result.errors), 3)

    def test_causal_legacy_per_file_closing_misses_later_mutation(self):
        with patch.object(closure._Held, 'finish', return_value=None):
            result = unittest.TestResult()
            SourceClosureTest('test_early_source_mutation_during_later_read_rejected').run(result)
        self.assertEqual(len(result.failures), 1)
        self.assertIn('ValueError not raised', result.failures[0][1])

    def test_causal_rehash_without_final_pure_pass_misses_later_mutation(self):
        with patch.object(closure._Held, 'final_identity_pass', return_value=None):
            result = unittest.TestResult()
            SourceClosureTest('test_early_mutation_during_final_rehash_rejected_by_pure_pass').run(result)
        self.assertEqual(len(result.failures), 1)
        self.assertIn('ValueError not raised', result.failures[0][1])


if __name__ == '__main__':
    unittest.main()
