"""Real-descriptor original-device continuity and strict-before causal controls.

Only an original pin's historical device is projected. Current file bytes,
inode, security metadata, timestamps, filesystem IDs and ancestor observations
come from real OS calls. Synthetic probe payloads confer no native authority.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import time
import unittest
import uuid
from unittest import mock

from agent_tools import android_component_continuity as continuity


FIXTURES = Path(__file__).parent / "fixtures/android_component_continuity"
POSIX_FDS = (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and
             hasattr(os, "O_DIRECTORY") and hasattr(os, "fstatvfs"))


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def before_namespace(name, hash_key):
    source = (FIXTURES / name).read_bytes()
    provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
    if digest(source) != provenance[hash_key]:
        raise AssertionError("beforeimage changed")
    scope = {"__name__": "agent_tools.continuity_before", "__package__": "agent_tools"}
    exec(compile(source, str(FIXTURES / name), "exec"), scope)
    return scope


@unittest.skipUnless(POSIX_FDS, "requires POSIX no-follow descriptor custody")
class ContinuityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.path = self.root / "lease-archlinux-api35.json"
        self.path.write_bytes(b"owned original lease bytes\n")
        self.path.chmod(0o600)
        self.current = self.measure(self.path)
        self.old = copy.deepcopy(self.current)
        self.old_device = self.current["generation"][0] + 1000
        self.old["generation"][0] = self.old_device
        for row in self.old["parents"].values():
            if row[0] == self.current["generation"][0]:
                row[0] = self.old_device
        self.operation = str(uuid.uuid4())
        self.operation_raw = ("COMPONENT_RELEASE_CORRELATION = " + repr(self.operation)).encode()
        self.manifest = canonical([{"path": str(self.path), "pin": self.old}])

    def measure(self, path):
        parents = {}
        for parent in reversed([path.parent, *path.parent.parents]):
            parents[str(parent)] = continuity._pin(parent.stat())[:5]
        return {"generation": continuity._pin(path.stat()), "parents": parents,
                "sha256": digest(path.read_bytes())}

    def arguments(self):
        now = time.time_ns()
        proof = canonical({"operationId": self.operation, "freshNativePredicate": "fixture-only"})
        return {
            "host_binding": {"machineId": "owned-machine", "bootId": "owned-boot",
                             "uid": os.getuid(), "observedAtNs": now,
                             "probeSha256": digest(b"fixture-host-probe")},
            "filesystem_binding": {"device": self.current["generation"][0],
                                   "fsid": os.statvfs(self.path).f_fsid,
                                   "volumeId": "owned-volume", "mountPoint": "/",
                                   "observedAtNs": now,
                                   "probeSha256": digest(b"fixture-filesystem-probe")},
            "remote_proofs": [{"role": "original-operation", "operationId": self.operation,
                               "observedAtNs": now, "sha256": digest(proof), "raw": proof}],
        }

    def qualify(self, **changes):
        arguments = self.arguments()
        arguments.update(changes)
        return continuity.qualify_records(
            self.manifest, digest(self.manifest), self.operation_raw,
            digest(self.operation_raw), self.operation, [str(self.path)], **arguments)

    def test_same_remounted_original_survives_qualified_custody(self):
        # The same test is run separately with this switch for actual RED on the
        # complete authenticated beforeimage's real strict descriptor closure.
        if os.environ.get("VPN_CONTROL_CONTINUITY_BEFORE") == "1":
            old = before_namespace("bundle.before.source", "originalSha256")
            old["_evidence_generation_closure"]({str(self.path): self.old})
        before = copy.deepcopy(self.old)
        receipt = self.qualify()
        row = receipt["records"][0]
        self.assertEqual(row["originalPin"], before)
        self.assertEqual(row["currentPin"], self.current)
        self.assertEqual(self.old, before)
        self.assertEqual(receipt["deviceChange"], {"original": self.old_device,
                                                  "current": self.current["generation"][0]})
        self.assertFalse(receipt["historicalPinsChanged"])
        self.assertFalse(receipt["releaseGranted"])
        self.assertFalse(receipt["replayAllowed"])
        body = {key: value for key, value in receipt.items() if key != "receiptSha256"}
        self.assertEqual(receipt["receiptSha256"], digest(continuity._canonical(body)))

    def test_strict_reader_still_refuses_historical_device(self):
        old = before_namespace("bundle.before.source", "originalSha256")
        with self.assertRaisesRegex(ValueError, "component_evidence_generation_changed"):
            old["_evidence_generation_closure"]({str(self.path): self.old})

    def test_every_additional_leaf_metadata_change_refuses(self):
        # Native exchanges and chmod cover real changes; each other FD field is
        # also checked by altering the authenticated historical pin independently.
        original = copy.deepcopy(self.old)
        for index in range(1, 9):
            with self.subTest(field=index):
                changed = copy.deepcopy(original)
                changed["generation"][index] += 1
                self.manifest = canonical([{"path": str(self.path), "pin": changed}])
                with self.assertRaises(ValueError):
                    self.qualify()
        self.manifest = canonical([{"path": str(self.path), "pin": original}])
        self.path.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "continuity_file_metadata_changed"):
            self.qualify()

    def test_replaced_same_bytes_and_changed_content_refuse(self):
        replacement = self.root / "replacement"
        replacement.write_bytes(self.path.read_bytes())
        replacement.chmod(0o600)
        os.replace(replacement, self.path)
        with self.assertRaisesRegex(ValueError, "continuity_file_metadata_changed"):
            self.qualify()
        self.current = self.measure(self.path)
        self.old = copy.deepcopy(self.current)
        self.old["generation"][0] = self.old_device
        for row in self.old["parents"].values():
            if row[0] == self.current["generation"][0]:
                row[0] = self.old_device
        self.old["sha256"] = digest(b"different bytes with same metadata")
        self.manifest = canonical([{"path": str(self.path), "pin": self.old}])
        with self.assertRaisesRegex(ValueError, "continuity_file_bytes_changed"):
            self.qualify()

    def test_ancestor_identity_security_and_device_are_checked(self):
        original = copy.deepcopy(self.old)
        for index in range(5):
            with self.subTest(field=index):
                changed = copy.deepcopy(original)
                changed["parents"][str(self.root)][index] += 1
                self.manifest = canonical([{"path": str(self.path), "pin": changed}])
                with self.assertRaises(ValueError):
                    self.qualify()

    def test_symlink_and_parent_exchange_cannot_qualify(self):
        real = self.path.with_name("retained")
        self.path.rename(real)
        self.path.symlink_to(real.name)
        with self.assertRaises((OSError, ValueError)):
            self.qualify()

    def test_untrusted_anchor_scope_and_operation_refuse(self):
        arguments = self.arguments()
        with self.assertRaisesRegex(ValueError, "continuity_anchor_changed"):
            continuity.qualify_records(self.manifest, "0" * 64, self.operation_raw,
                                       digest(self.operation_raw), self.operation,
                                       [str(self.path)], **arguments)
        raw = b"unrelated original operation"
        with self.assertRaisesRegex(ValueError, "continuity_operation_anchor_mismatch"):
            continuity.qualify_records(self.manifest, digest(self.manifest), raw, digest(raw),
                                       self.operation, [str(self.path)], **arguments)
        with self.assertRaisesRegex(ValueError, "continuity_scope_not_anchored"):
            continuity.qualify_records(self.manifest, digest(self.manifest), self.operation_raw,
                                       digest(self.operation_raw), self.operation,
                                       [str(self.path.with_name("foreign"))], **arguments)

    def test_missing_stale_or_wrong_remote_proof_refuses(self):
        with self.assertRaisesRegex(ValueError, "continuity_remote_proof_missing"):
            self.qualify(remote_proofs=[])
        for role in ("host_binding", "filesystem_binding", "remote_proofs"):
            arguments = self.arguments()
            observation = arguments[role][0] if role == "remote_proofs" else arguments[role]
            observation["observedAtNs"] = time.time_ns() - 601_000_000_000
            with self.subTest(role=role), self.assertRaisesRegex(ValueError, "continuity_observation_stale"):
                self.qualify(**arguments)
        arguments = self.arguments()
        arguments["remote_proofs"][0]["operationId"] = str(uuid.uuid4())
        with self.assertRaisesRegex(ValueError, "continuity_remote_proof_invalid"):
            self.qualify(**arguments)

    def test_filesystem_id_device_and_host_uid_are_independently_checked(self):
        for name in ("fsid", "device"):
            arguments = self.arguments()
            arguments["filesystem_binding"][name] += 1
            with self.subTest(field=name), self.assertRaises(ValueError):
                self.qualify(**arguments)
        arguments = self.arguments()
        arguments["host_binding"]["uid"] += 1
        with self.assertRaisesRegex(ValueError, "continuity_host_binding_invalid"):
            self.qualify(**arguments)

    def test_exchange_after_read_is_detected_by_final_held_census(self):
        real_read = continuity.os.read
        changed = False
        def read(fd, count):
            nonlocal changed
            raw = real_read(fd, count)
            if raw and not changed:
                changed = True
                replacement = self.root / "replacement"
                replacement.write_bytes(self.path.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, self.path)
            return raw
        with mock.patch.object(continuity.os, "read", read):
            with self.assertRaisesRegex(ValueError, "continuity_file_changed"):
                self.qualify()

    def private8(self):
        generation = self.old["generation"]
        return {"principal": "local-lease", "format": "private8",
                "generation": [generation[0], generation[1], generation[6],
                               generation[7], generation[8], stat.S_IMODE(generation[2]),
                               generation[3], generation[5]], "sha256": self.old["sha256"]}

    def primitive_pin(self):
        return {**self.current, "parents": [row for name, row in self.current["parents"].items()
                                            if name != "/"]}

    def test_lease_receipt_checks_historical_and_current_pins_without_rebinding(self):
        receipt = self.qualify()
        result = continuity.validate_lease_receipt(receipt, str(self.path), self.private8(),
                                                   self.primitive_pin())
        self.assertEqual(result["originalPin"], self.old)
        self.assertEqual(result["currentPin"], self.current)
        self.assertEqual(result["releasePath"], str(self.path))
        self.path.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "continuity_alias_file_changed"):
            continuity.validate_lease_receipt(receipt, str(self.path), self.private8(),
                                              self.primitive_pin())

    def test_altered_receipt_and_wrong_lease_pins_refuse(self):
        receipt = self.qualify()
        altered = copy.deepcopy(receipt)
        altered["records"][0]["currentPin"]["generation"][1] += 1
        with self.assertRaisesRegex(ValueError, "continuity_receipt_changed"):
            continuity.validate_lease_receipt(altered, str(self.path), self.private8(),
                                              self.primitive_pin())
        old = self.private8()
        old["generation"][0] += 1
        with self.assertRaisesRegex(ValueError, "continuity_original_lease_changed"):
            continuity.validate_lease_receipt(receipt, str(self.path), old, self.primitive_pin())
        pin = self.primitive_pin()
        pin["parents"][-1][1] += 1
        with self.assertRaisesRegex(ValueError, "continuity_release_parent_changed"):
            continuity.validate_lease_receipt(receipt, str(self.path), self.private8(), pin)


@unittest.skipUnless(POSIX_FDS, "requires POSIX no-follow descriptor custody")
class LocalReleaseContinuityTests(unittest.TestCase):
    setUp = ContinuityTests.setUp
    measure = ContinuityTests.measure
    arguments = ContinuityTests.arguments
    qualify = ContinuityTests.qualify
    private8 = ContinuityTests.private8
    primitive_pin = ContinuityTests.primitive_pin

    def release_setup(self):
        from agent_tools import android_installer_failed_check_retirement as retirement
        from agent_tools.tests.test_android_installer_failed_check_retirement import ComponentTerminalHistoryTest
        utility = ComponentTerminalHistoryTest()
        scope, lease, pin, proof, correlation, remote, _ = utility.release_fixture(self.root)
        self.path = lease
        self.current = self.measure(lease)
        self.old = copy.deepcopy(self.current)
        self.old_device = self.current["generation"][0] + 1000
        self.old["generation"][0] = self.old_device
        for row in self.old["parents"].values():
            if row[0] == self.current["generation"][0]:
                row[0] = self.old_device
        proof["files"]["local-lease.json"] = self.private8()
        # Produce a real new admitted record under the same production admission
        # primitive, with the explicitly projected historical filesystem device.
        original = self.root / "original-continuity"
        original.mkdir(mode=0o700)
        admitted = self.root / "admitted-continuity"
        admitted.mkdir(mode=0o700)
        scope["admit_component_fenced"](original, admitted, proof, lambda: None, os.getuid())
        proof = json.loads((admitted / "component-admitted-proof.json").read_bytes())
        remote["admittedProofSha256"] = digest(retirement._canonical(proof))
        self.manifest = canonical([{"path": str(lease), "pin": self.old}])
        qualified = self.qualify()
        def fresh():
            raw, generation, sha = retirement.private_snapshot(lease, 1024)
            self.assertEqual(generation, retirement._generation(lease.stat()))
            self.assertEqual(sha, pin["sha256"])
            self.assertEqual(len(raw), 121)
            return copy.deepcopy(proof)
        return scope, lease, pin, proof, correlation, remote, fresh, qualified

    def test_same_remounted_original_local_release_captures_exact_inode(self):
        scope, lease, pin, proof, correlation, remote, fresh, qualified = self.release_setup()
        original_proof = copy.deepcopy(proof)
        if os.environ.get("VPN_CONTROL_CONTINUITY_BEFORE") == "1":
            handler = before_namespace("retirement.before.source", "retirementSha256")["release_component_fenced"]
            kwargs = {}
        else:
            handler = scope["release_component_fenced"]
            kwargs = {"continuity_receipt": qualified}
        result = handler(lease, pin, proof, correlation, fresh, "local-original", remote, **kwargs)
        self.assertTrue(result["leaseReleased"])
        self.assertFalse(lease.exists())
        captured = Path(result["retiredEvidence"]["path"])
        self.assertEqual(captured.stat().st_ino, pin["generation"][1])
        self.assertEqual(digest(captured.read_bytes()), pin["sha256"])
        self.assertEqual(proof, original_proof)
        self.assertEqual(qualified["records"][0]["originalPin"], self.old)
        self.assertEqual(result["originalOutcome"], "unknown")
        self.assertFalse(result["replayAllowed"])

    def test_missing_continuity_preserves_original_lease_before_any_fence(self):
        scope, lease, pin, proof, correlation, remote, fresh, _ = self.release_setup()
        with self.assertRaisesRegex(ValueError, "component_release_original_lease_changed"):
            scope["release_component_fenced"](lease, pin, proof, correlation, fresh,
                                               "local-original", remote)
        self.assertTrue(lease.exists())
        self.assertFalse(any(self.root.glob("component-retirement-*")))


@unittest.skipUnless(POSIX_FDS, "requires POSIX no-follow descriptor custody")
class RelocatedLeaseTests(unittest.TestCase):
    """Actual owned rename/chmod/link; APFS alias itself remains native-only.

    The source-owned native scope is replaced only inside this test by explicit
    owned trust roots and pinned synthetic probe bytes. Both physical/logical
    fixture prefixes address the same real path; no fake inode equality or
    successful native APFS behavior is manufactured.
    """
    measure = ContinuityTests.measure

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.logical = self.root / "Users"
        self.home = self.logical / "owner"
        self.nextcloud = self.home / "Nextcloud"
        self.old_directory = self.nextcloud / "projects"
        self.directory = self.home / "projects"
        self.original_path = self.old_directory / "vpn_control/.rag_index/android-native-device-leases/lease-archlinux-api35.json"
        self.original_path.parent.mkdir(parents=True, mode=0o700)
        for path in self.root.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
        self.old_directory.chmod(0o777)
        raw = canonical({"owner": "android-installer", "host": "archlinux", "device": "api35",
                         "correlationId": "0dd55704-1e80-4d62-8d9d-2f0a123e0c3b"})
        self.assertEqual(len(raw), 121)
        self.original_path.write_bytes(raw)
        self.original_path.chmod(0o600)
        self.prepare_original()
        self.original_pin = self.measure(self.original_path)
        self.old_device = self.original_pin["generation"][0] + 1000
        native_device = self.original_pin["generation"][0]
        self.original_pin["generation"][0] = self.old_device
        for pin in self.original_pin["parents"].values():
            if pin[0] == native_device:
                pin[0] = self.old_device
        self.manifest = canonical([{"path": str(self.original_path), "pin": self.original_pin}])
        self.scope = copy.deepcopy(continuity._API35_RELOCATION_SCOPE)
        self.operation_raw = ("OPERATION=" + repr(self.scope["operationId"]) +
                              ";INSTALLER=" + repr(self.scope["installerId"])).encode()
        self.old_directory.rename(self.directory)
        self.directory.chmod(0o755)
        self.old_directory.symlink_to(self.directory, target_is_directory=True)
        self.path = self.directory / self.original_path.relative_to(self.old_directory)
        self.table = self.root / "firmlinks"
        self.table.write_bytes(b"/Applications\tApplications\n/Users\tUsers\n")
        self.table.chmod(0o444)
        self.scope.update({
            "manifestSha256": digest(self.manifest), "operationSha256": digest(self.operation_raw),
            "originalPath": str(self.original_path), "currentPath": str(self.path),
            "originalMovedDirectory": str(self.old_directory), "currentMovedDirectory": str(self.directory),
            "originalDevice": self.old_device, "logicalPrefix": str(self.logical),
            "historicalLinkMode": self.old_directory.lstat().st_mode,
            "physicalPrefix": str(self.logical), "mountPoint": str(self.root),
            "firmlinkTablePath": str(self.table), "firmlinkTableUid": os.getuid(),
            "firmlinkTableGid": os.getgid(), "mountUid": os.getuid(), "platform": sys.platform,
        })
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(continuity, "_API35_RELOCATION_SCOPE", self.scope).start()

    def prepare_original(self):
        pass

    def arguments(self):
        now = time.time_ns()
        probe = plistlib.dumps({"FilesystemType": "apfs", "MountPoint": str(self.root),
                               "VolumeUUID": "11111111-2222-4333-8444-555555555555",
                               "DeviceIdentifier": "disk3s5", "DeviceNode": "/dev/disk3s5",
                               "GlobalPermissionsEnabled": True, "WholeDisk": False})
        proof = canonical({"originalOperationId": self.scope["operationId"],
                           "nativeAuthority": False, "fixtureOnly": True})
        return {"host_binding": {"machineId": "fixture-machine", "bootId": "fixture-boot",
                                 "uid": os.getuid(), "observedAtNs": now,
                                 "probeSha256": digest(b"fixture host probe")},
                "filesystem_binding": {"device": self.path.stat().st_dev,
                                       "fsid": os.statvfs(self.path).f_fsid,
                                       "volumeId": "11111111-2222-4333-8444-555555555555",
                                       "mountPoint": str(self.root), "observedAtNs": now,
                                       "probeSha256": digest(probe)},
                "filesystem_probe_raw": probe,
                "remote_proofs": [{"role": "original-operation", "operationId": self.scope["operationId"],
                                   "observedAtNs": now, "sha256": digest(proof), "raw": proof}]}

    def qualify(self, **changes):
        arguments = self.arguments()
        arguments.update(changes)
        return continuity.qualify_relocated_api35_lease(
            self.manifest, digest(self.manifest), self.operation_raw,
            digest(self.operation_raw), **arguments)

    def private8(self):
        generation = self.original_pin["generation"]
        return {"principal": "local-lease", "format": "private8",
                "generation": [generation[0], generation[1], generation[6], generation[7],
                               generation[8], stat.S_IMODE(generation[2]), generation[3], generation[5]],
                "sha256": self.original_pin["sha256"]}

    def primitive_pin(self):
        actual = self.measure(self.path)
        return {**actual, "parents": [pin for name, pin in actual["parents"].items() if name != "/"]}

    def test_same_moved_original_has_distinct_current_path_custody(self):
        if os.environ.get("VPN_CONTROL_RELOCATION_BEFORE") == "1":
            old = before_namespace("continuity.before-relocation.source", "continuityBeforeRelocationSha256")
            arguments = self.arguments()
            arguments.pop("filesystem_probe_raw")
            old["qualify_records"](self.manifest, digest(self.manifest), self.operation_raw,
                                    digest(self.operation_raw), self.scope["operationId"],
                                    [str(self.original_path)], **arguments)
        receipt = self.qualify()
        self.assertEqual(receipt["kind"], "android-component-relocated-api35-lease-custody")
        self.assertEqual(receipt["records"][0]["originalPin"], self.original_pin)
        self.assertEqual(receipt["records"][0]["currentPin"], self.measure(self.path))
        self.assertEqual(receipt["relocation"]["originalDirectoryPin"][1], self.directory.stat().st_ino)
        self.assertEqual(receipt["relocation"]["originalDirectoryPin"][2], 0o40777)
        self.assertEqual(receipt["relocation"]["currentDirectoryPin"][2], 0o40755)
        self.assertEqual(receipt["relocation"]["historicalEntry"]["target"], str(self.directory))
        self.assertFalse(receipt["historicalPinsChanged"])
        self.assertFalse(receipt["releaseGranted"])
        self.assertFalse(receipt["replayAllowed"])
        result = continuity.validate_relocated_lease_receipt(receipt, self.path,
                                                             self.private8(), self.primitive_pin())
        self.assertEqual(result["releasePath"], str(self.path))

    def test_device_only_qualifier_and_validator_remain_strict(self):
        arguments = self.arguments()
        arguments.pop("filesystem_probe_raw")
        with self.assertRaises((OSError, ValueError)):
            continuity.qualify_records(self.manifest, digest(self.manifest), self.operation_raw,
                                       digest(self.operation_raw), self.scope["operationId"],
                                       [str(self.original_path)], **arguments)
        receipt = self.qualify()
        with self.assertRaisesRegex(ValueError, "continuity_receipt_invalid"):
            continuity.validate_lease_receipt(receipt, self.path, self.private8(), self.primitive_pin())

    def test_only_explicit_directory_mode_tightening_is_allowed(self):
        for mode in (0o777, 0o775, 0o770, 0o750, 0o700):
            self.directory.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaisesRegex(ValueError, "relocated_lease_current_identity_changed"):
                self.qualify()

    def test_changed_leaf_and_replaced_current_directory_refuse(self):
        self.path.chmod(0o640)
        with self.assertRaisesRegex(ValueError, "relocated_lease_current_identity_changed"):
            self.qualify()
        self.path.chmod(0o600)
        retained = self.directory.with_name("retained-projects")
        self.directory.rename(retained)
        self.directory.mkdir(mode=0o755)
        with self.assertRaises((OSError, ValueError)):
            self.qualify()

    def test_historical_symlink_different_target_refuses_without_following(self):
        self.old_directory.unlink()
        self.old_directory.symlink_to(self.root / "foreign", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "relocated_lease_historical_entry_changed"):
            self.qualify()
        self.assertTrue(self.path.exists())

    def test_historical_symlink_exchange_during_read_refuses(self):
        original_readlink = continuity.os.readlink
        changed = False
        def readlink(name, **kwargs):
            nonlocal changed
            value = original_readlink(name, **kwargs)
            if not changed and name == "projects":
                changed = True
                self.old_directory.unlink()
                self.old_directory.symlink_to(self.directory, target_is_directory=True)
            return value
        with mock.patch.object(continuity.os, "readlink", readlink):
            with self.assertRaisesRegex(ValueError, "relocated_lease_historical_entry_changed"):
                self.qualify()

    def test_source_anchor_and_current_release_path_cannot_be_overridden(self):
        with self.assertRaisesRegex(ValueError, "relocated_lease_anchor_scope_changed"):
            continuity.qualify_relocated_api35_lease(self.manifest, "0" * 64, self.operation_raw,
                                                    digest(self.operation_raw), **self.arguments())
        receipt = self.qualify()
        with self.assertRaisesRegex(ValueError, "relocated_lease_release_scope_changed"):
            continuity.validate_relocated_lease_receipt(receipt, self.original_path,
                                                        self.private8(), self.primitive_pin())

    def test_firmlink_table_requires_exact_single_native_entry_and_security(self):
        for raw in (b"/Users\tforeign\n", b"/Users\tUsers\n/Users\tUsers\n",
                    b"Users\tUsers\n", b"/Users\tUsers\textra\n"):
            self.table.chmod(0o600)
            self.table.write_bytes(raw)
            self.table.chmod(0o444)
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.qualify()
        self.table.chmod(0o600)
        self.table.write_bytes(b"/Users\tUsers\n")
        with self.assertRaisesRegex(ValueError, "relocated_lease_firmlink_table_unsafe"):
            self.qualify()

    def test_physical_alias_requires_same_real_inode_and_filesystem(self):
        foreign = self.root / "foreign-physical"
        target = foreign / self.path.relative_to(self.logical)
        target.parent.mkdir(parents=True, mode=0o700)
        target.write_bytes(self.path.read_bytes())
        target.chmod(0o600)
        self.scope["physicalPrefix"] = str(foreign)
        with self.assertRaisesRegex(ValueError, "relocated_lease_physical_identity_changed"):
            self.qualify()

    def test_diskutil_apfs_volume_mount_and_permissions_are_bound(self):
        for field, value in (("FilesystemType", "hfs"), ("MountPoint", "/foreign"),
                             ("VolumeUUID", "22222222-2222-4333-8444-555555555555"),
                             ("GlobalPermissionsEnabled", False), ("WholeDisk", True)):
            arguments = self.arguments()
            parsed = plistlib.loads(arguments["filesystem_probe_raw"])
            parsed[field] = value
            probe = plistlib.dumps(parsed)
            arguments["filesystem_probe_raw"] = probe
            arguments["filesystem_binding"]["probeSha256"] = digest(probe)
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "relocated_lease_diskutil_binding_changed"):
                self.qualify(**arguments)

    def test_all_current_paths_revalidated_before_local_release(self):
        receipt = self.qualify()
        actual_pin = self.primitive_pin()
        original_pin = self.private8()
        self.old_directory.unlink()
        self.old_directory.symlink_to(self.root / "foreign", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "relocated_lease_historical_entry_changed"):
            continuity.validate_relocated_lease_receipt(receipt, self.path, original_pin, actual_pin)
        self.assertTrue(self.path.exists())

    def test_historical_link_owner_and_parent_security_refuse(self):
        import types
        original_stat = continuity.os.stat
        def altered(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path == "projects" and kwargs.get("follow_symlinks") is False:
                # Ordinary CI cannot chown. Only this link UID is projected;
                # lstat/readlink and all byte/inode/generation checks are real.
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                fields["st_uid"] += 1
                return types.SimpleNamespace(**fields)
            return info
        with mock.patch.object(continuity.os, "stat", altered):
            with self.assertRaisesRegex(ValueError, "relocated_lease_historical_entry_changed"):
                self.qualify()
        self.nextcloud.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "relocated_lease_historical_entry_changed"):
            self.qualify()

    def test_genuine_mount_outside_logical_ancestry_uses_measured_alias_policy(self):
        data = self.root / "Data"
        data.mkdir(mode=0o700)
        arguments = self.arguments()
        arguments["filesystem_binding"]["mountPoint"] = str(data)
        if os.environ.get("VPN_CONTROL_RELOCATION_BEFORE") == "1":
            old = before_namespace("continuity.before-relocation.source", "continuityBeforeRelocationSha256")
            arguments.pop("filesystem_probe_raw")
            old["qualify_records"](self.manifest, digest(self.manifest), self.operation_raw,
                                    digest(self.operation_raw), self.scope["operationId"],
                                    [str(self.original_path)], **arguments)
        # Portable application-decision seam: only physical alias path names are
        # projected as APFS presents them. Every identity/security/fsid value and
        # byte comes from the held real file/directory descriptors. Actual APFS
        # alias traversal remains a separate native acceptance scenario.
        scope = {**self.scope, "mountPoint": str(data), "physicalPrefix": str(data / "Users")}
        with continuity._relocation_file(self.path, 1024) as (raw, direct, guard):
            physical = copy.deepcopy(direct)
            parents = {}
            fsids = {}
            for name, pin in direct["parents"].items():
                path = Path(name)
                mapped = Path(scope["physicalPrefix"]) / path.relative_to(self.logical) if path == self.logical or self.logical in path.parents else path
                parents[str(mapped)] = pin
                fsids[str(mapped)] = direct["parentFilesystemIds"][name]
            parents[str(data)] = continuity._pin(data.stat())[:5]
            fsids[str(data)] = os.statvfs(data).f_fsid
            physical.update(parents=parents, parentFilesystemIds=fsids)
            continuity._relocation_verify_physical(raw, direct, raw, physical,
                                                   arguments["filesystem_binding"], scope)
            changed = copy.deepcopy(physical)
            changed["parents"][str(scope["physicalPrefix"])][1] += 1
            with self.assertRaisesRegex(ValueError, "relocated_lease_physical_ancestry_changed"):
                continuity._relocation_verify_physical(raw, direct, raw, changed,
                                                       arguments["filesystem_binding"], scope)
            guard()


@unittest.skipUnless(POSIX_FDS, "requires POSIX no-follow descriptor custody")
class RelocatedLocalReleaseTests(unittest.TestCase):
    setUp = RelocatedLeaseTests.setUp
    measure = RelocatedLeaseTests.measure
    arguments = RelocatedLeaseTests.arguments
    qualify = RelocatedLeaseTests.qualify
    private8 = RelocatedLeaseTests.private8
    primitive_pin = RelocatedLeaseTests.primitive_pin

    def prepare_original(self):
        from agent_tools.tests.test_android_installer_failed_check_retirement import ComponentTerminalHistoryTest
        utility = ComponentTerminalHistoryTest()
        self.primitive = utility.release_fixture(self.original_path.parent)

    def test_same_relocated_original_local_primitive_captures_exact_inode(self):
        from agent_tools import android_installer_failed_check_retirement as retirement
        scope, _, _, proof, correlation, remote, _ = self.primitive
        proof["files"]["local-lease.json"] = self.private8()
        original = self.path.parent / "original-relocated"
        original.mkdir(mode=0o700)
        admitted = self.path.parent / "admitted-relocated"
        admitted.mkdir(mode=0o700)
        scope["admit_component_fenced"](original, admitted, proof, lambda: None, os.getuid())
        proof = json.loads((admitted / "component-admitted-proof.json").read_bytes())
        original_proof = copy.deepcopy(proof)
        remote["admittedProofSha256"] = digest(retirement._canonical(proof))
        actual = self.primitive_pin()
        receipt = self.qualify()
        def fresh():
            raw, generation, sha = retirement.private_snapshot(self.path, 1024)
            self.assertEqual(generation, retirement._generation(self.path.stat()))
            self.assertEqual(sha, actual["sha256"])
            self.assertEqual(len(raw), 121)
            return copy.deepcopy(proof)
        if os.environ.get("VPN_CONTROL_RELOCATION_BEFORE") == "1":
            before = before_namespace("retirement.before-relocation.source", "retirementBeforeRelocationSha256")
            source_raw = (FIXTURES / "retirement.before-relocation.source").read_bytes()
            source = before["component_release_source"](source_raw, digest(source_raw))
            scope = {}
            exec(compile(source, "<actual-before-relocated-release>", "exec"), scope)
        result = scope["release_component_fenced"](self.path, actual, proof, correlation, fresh,
                                                    "local-original", remote, continuity_receipt=receipt)
        self.assertTrue(result["leaseReleased"])
        captured = Path(result["retiredEvidence"]["path"])
        self.assertEqual(captured.stat().st_ino, actual["generation"][1])
        self.assertEqual(digest(captured.read_bytes()), actual["sha256"])
        self.assertFalse(self.path.exists())
        self.assertEqual(proof, original_proof)
        self.assertEqual(result["originalOutcome"], "unknown")
        self.assertFalse(result["replayAllowed"])


if __name__ == "__main__":
    unittest.main()
