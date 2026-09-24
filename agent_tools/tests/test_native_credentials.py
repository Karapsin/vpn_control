from dataclasses import replace
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock

from agent_tools.native_credentials import CredentialBinding, CredentialStoreError, NativeCredentialStore


@unittest.skipUnless(os.name == 'posix' and hasattr(os, 'getuid'), 'POSIX private store required')
class NativeCredentialStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / '.runtime').mkdir(mode=0o700)
        self.store = NativeCredentialStore(self.root)
        self.binding = CredentialBinding('windows-fixture', 'fixtureuser',
            'S-1-5-21-11-22-33-1002',
            'account-login', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')

    def tearDown(self):
        self.temp.cleanup()

    def test_private_create_exact_binding_and_no_public_secret(self):
        handle = self.store.create(self.binding)
        secret = self.store.read(handle, self.binding)
        self.assertGreaterEqual(len(secret), 32)
        self.assertTrue(secret.startswith(b'V!'))
        self.assertEqual(stat.S_IMODE(self.store.path.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.store.path / handle).stat().st_mode), 0o700)
        for name in ('metadata.json', 'secret'):
            self.assertEqual(stat.S_IMODE((self.store.path / handle / name).stat().st_mode), 0o600)
        self.assertNotIn(secret.decode(), json.dumps(self.store.status(handle, self.binding)))
        for changed in (
            replace(self.binding, environment='other'), replace(self.binding, account_name='other'),
            replace(self.binding, expected_sid='S-1-5-21-1-2-3-1002'),
            replace(self.binding, purpose='other'),
            replace(self.binding, correlation_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'),
        ):
            with self.assertRaises(CredentialStoreError):
                self.store.read(handle, changed)

    def test_rejects_permissive_secret_and_link(self):
        handle = self.store.create(self.binding)
        path = self.store.path / handle / 'secret'
        path.chmod(0o644)
        with self.assertRaises(CredentialStoreError):
            self.store.read(handle, self.binding)
        path.chmod(0o600)
        data = path.read_bytes(); path.unlink()
        outside = self.root / 'outside'; outside.write_bytes(data)
        path.symlink_to(outside)
        with self.assertRaises(CredentialStoreError):
            self.store.read(handle, self.binding)

    def test_rejects_symlink_or_writable_runtime_parent(self):
        runtime=self.root/'.runtime'
        uid=os.getuid()
        with mock.patch('agent_tools.native_credentials.os.getuid',return_value=uid+1):
            with self.assertRaises(CredentialStoreError):
                self.store.create(self.binding)
        runtime.chmod(0o777)
        with self.assertRaises(CredentialStoreError):
            self.store.create(self.binding)
        runtime.chmod(0o700)
        runtime.rmdir()
        outside=self.root/'outside-runtime'; outside.mkdir(mode=0o700)
        runtime.symlink_to(outside)
        with self.assertRaises(CredentialStoreError):
            self.store.create(self.binding)

    def test_active_rotation_uses_stable_binding_and_keeps_old_handle(self):
        first = self.store.create(self.binding)
        self.store.publish_active(first, self.binding)
        next_binding = replace(self.binding, correlation_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')
        second = self.store.create(next_binding)
        self.assertEqual(self.store.active(next_binding), first)
        self.store.publish_active(second, next_binding)
        self.assertEqual(self.store.active(self.binding), second)
        self.assertTrue(self.store.read(first, self.binding))
        self.assertTrue(self.store.read(second, next_binding))
        self.assertIsNone(self.store.active(replace(next_binding, expected_sid='S-1-5-21-1-2-3-1002')))

    def test_active_index_has_unambiguous_bounded_name(self):
        one=replace(self.binding,environment='a--b',account_name='c')
        two=replace(self.binding,environment='a',account_name='b--c')
        self.assertNotEqual(self.store._active_key(one),self.store._active_key(two))
        first=self.store.create(one); second=self.store.create(two)
        self.store.publish_active(first,one); self.store.publish_active(second,two)
        self.assertEqual(self.store.active(one),first)
        self.assertEqual(self.store.active(two),second)
        self.assertEqual(len(self.store._active_key(one)),69)

    def test_failed_atomic_publish_retains_previous_reference(self):
        first = self.store.create(self.binding)
        self.store.publish_active(first, self.binding)
        next_binding = replace(self.binding, correlation_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')
        second = self.store.create(next_binding)
        with mock.patch('agent_tools.native_credentials.os.replace', side_effect=OSError('injected')):
            with self.assertRaises(OSError):
                self.store.publish_active(second, next_binding)
        self.assertEqual(self.store.active(self.binding), first)

    def test_concurrent_publish_never_exposes_partial_reference(self):
        first = self.store.create(self.binding)
        next_binding = replace(self.binding, correlation_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')
        second = self.store.create(next_binding)
        errors = []
        def publish(handle, binding):
            try:
                for _ in range(10):
                    self.store.publish_active(handle, binding)
                    self.assertIn(self.store.active(self.binding), {first, second})
            except Exception as error:
                errors.append(error)
        threads = [threading.Thread(target=publish, args=item) for item in ((first,self.binding),(second,next_binding))]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(errors, [])


class CredentialBindingPortableTests(unittest.TestCase):
    def test_binding_rejects_invalid_sid_and_correlation(self):
        binding=CredentialBinding('windows-fixture','fixtureuser','S-1-5-21-11-22-33-1002',
            'account-login','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
        binding.validate()
        with self.assertRaises(CredentialStoreError):
            replace(binding,expected_sid='S-1-5-18').validate()
        with self.assertRaises(CredentialStoreError):
            replace(binding,correlation_id='not-a-uuid').validate()

    def test_unsupported_platform_fails_closed(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); (root/'.runtime').mkdir()
            store=NativeCredentialStore(root)
            binding=CredentialBinding('windows-fixture','fixtureuser','S-1-5-21-11-22-33-1002',
                'account-login','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')
            with mock.patch('agent_tools.native_credentials.os.name','nt'):
                with self.assertRaises(CredentialStoreError):
                    store.create(binding)


if __name__ == '__main__': unittest.main()
