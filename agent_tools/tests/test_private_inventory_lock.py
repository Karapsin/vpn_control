"""Local deterministic coverage of the shared inventory ownership protocol."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import private_inventory_lock as private
from agent_tools import ssh_recovery_adoption as adoption
from agent_tools import windows_credential_recovery_ssh as publisher


@unittest.skipUnless(os.name == 'posix', 'POSIX ownership required')
class PrivateInventoryOwnershipTests(unittest.TestCase):
    def test_ownership_is_shared_by_actual_writers_and_blocks_competing_descriptor(self):
        self.assertIs(adoption._ConfigLock, private.InventoryLock)
        self.assertIs(publisher.private_inventory_lock.InventoryLock, private.InventoryLock)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with private.ownership(root) as (presented, directory, lock):
                with self.assertRaises(OSError):
                    with private.ownership(root):
                        self.fail('second descriptor acquired held inventory ownership')
                presented.guard(); directory.guard(); lock.guard()
            with private.ownership(root) as (_, _, lock):
                lock.guard()

    def test_snapshot_keeps_full_metadata_body_and_named_parent_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); path = root / 'source'
            path.write_bytes(b'private-exact-source\n'); path.chmod(0o600)
            with private.Directory(root) as directory, private.Snapshot(directory, 'source') as snapshot:
                info = path.stat(); pin = snapshot.pin()
                self.assertEqual([info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                                  info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns], pin['generation'])
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), pin['sha256'])
                path.chmod(0o400); path.chmod(0o600)
                with self.assertRaises(ValueError): snapshot.guard()

    def test_lock_named_replacement_cannot_split_ownership_silently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with private.ownership(root) as (_, _, lock):
                path = lock.snapshot.directory.path / private.InventoryLock.name
                path.rename(path.with_suffix('.old'))
                path.write_bytes(private.InventoryLock.body); path.chmod(0o600)
                with self.assertRaises(ValueError): lock.guard()

    def test_partial_lock_and_fsync_failure_never_grant_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            with private.Directory(root) as directory, private.lock_directory(directory) as locks:
                with mock.patch.object(private.os, 'fsync', side_effect=OSError('not durable')):
                    with self.assertRaises(OSError):
                        with private.InventoryLock(locks):
                            self.fail('fsync failure granted ownership')
                path = locks.path / private.InventoryLock.name
                path.write_bytes(b'partial'); path.chmod(0o600)
                with self.assertRaises(ValueError):
                    with private.InventoryLock(locks):
                        self.fail('partial lock granted ownership')


class PortablePrivateInventoryOwnershipTests(unittest.TestCase):
    def test_common_module_is_safely_importable_by_top_level_mcp_backend(self):
        environment = os.environ.copy()
        environment['PYTHONPATH'] = str(Path(private.__file__).parent)
        result = subprocess.run([sys.executable, '-c', 'import private_inventory_lock; import windows_credential_recovery_ssh; import ssh_recovery_adoption'],
                                env=environment, capture_output=True, text=True, timeout=10)
        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == '__main__':
    unittest.main()
