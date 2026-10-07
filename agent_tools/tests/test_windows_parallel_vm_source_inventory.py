"""Real TempFS/FD/port tests of the exact source observer; no native VM pass."""
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from agent_tools import windows_parallel_vm_source_inventory as inventory


@unittest.skipUnless(os.name == "posix", "privileged Arch observer requires POSIX FD semantics")
class SourceInventoryTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.source = self.root / "source.qcow2"
        self.raw = b"QFI\xfb" + b"actual source bytes" * 300
        self.source.write_bytes(self.raw)
        self.source.chmod(0o600)
        self.proc = self.root / "proc"
        (self.proc / "net").mkdir(parents=True)
        for name in ("tcp", "tcp6", "unix"):
            (self.proc / "net" / name).write_text("header\n")
        self.destinations = (str(self.root / "secondary"), str(self.root / "tertiary"))
        self.hash_calls = []
        real_hash = inventory.hash_source
        def track(fd, size, deadline):
            self.hash_calls.append(size)
            return real_hash(fd, size, deadline)
        self.hash_patch = patch.object(inventory, "hash_source", side_effect=track)
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)
        self.image_patch = patch.object(inventory, "image_metadata", return_value={
            "format": "qcow2", "backingFile": None, "virtualSizeBytes": 96 * 1024 ** 3})
        self.image_patch.start()
        self.addCleanup(self.image_patch.stop)

    def pid(self, number, birth=17, comm="python"):
        directory = self.proc / str(number)
        (directory / "fd").mkdir(parents=True)
        (directory / "stat").write_text(str(number) + " (harmless child) " + " ".join(["S"] + ["0"] * 18 + [str(birth)]))
        (directory / "comm").write_text(comm)
        (directory / "cmdline").write_bytes(b"python\0")
        return directory

    def observe(self, minimum_free_disk=0):
        return inventory.observe_source(self.source, self.root, self.proc, self.destinations,
            (2339, 5939, 2338, 5938), inventory.MACS, (), 5, minimum_free_disk)

    def test_real_source_hash_and_private_namespaces_without_clone_admission(self):
        value = self.observe()
        self.assertEqual(value["sourceSha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(value["sourceGeneration"], inventory.generation(self.source.lstat()))
        self.assertEqual(self.hash_calls, [len(self.raw)])
        self.assertEqual(value["sourceState"], "stopped-observed")
        self.assertFalse(value["nativeActionAllowed"])
        self.assertFalse(value["cloneAdmitted"])
        self.assertFalse(value["guestAccessVerified"])
        self.assertTrue(all(not Path(path).exists() for path in self.destinations))

    def test_actual_open_writer_is_found_and_hash_never_runs(self):
        pid = self.pid(42)
        held = os.open(self.source, os.O_WRONLY)
        try:
            # Only the /proc PID directory is projected on macOS; an actual
            # open source writer and stat(dev,ino) supply the detected identity.
            (pid / "fd" / str(held)).symlink_to(self.source)
            with self.assertRaisesRegex(ValueError, "source-held"):
                self.observe()
            self.assertEqual(self.hash_calls, [])
        finally:
            os.close(held)

    def observe_qemu_metadata(self, metadata):
        # Only the fixed qemu-img process result is projected. In particular,
        # the actual metadata parser, full source observer, FD, census, parent
        # guards and real source hashing remain in use.
        self.image_patch.stop()
        result = subprocess.CompletedProcess(
            ("/usr/bin/qemu-img", "info", "--output=json", str(self.source)),
            0, json.dumps(metadata).encode())
        with patch.object(inventory.subprocess, "run", return_value=result) as command:
            value = self.observe()
        self.assertEqual(command.call_args.args[0], result.args)
        return value

    def test_actual_full_observer_refuses_measured_external_data_file_before_hash(self):
        metadata = {"format": "qcow2", "virtual-size": 96 * 1024 ** 3, "dirty-flag": False,
                    "format-specific": {"type": "qcow2", "data": {
                        "compat": "1.1", "data-file": "/fixture/external.raw",
                        "data-file-raw": True, "refcount-bits": 16, "compression-type": "zlib"}}}
        with self.assertRaisesRegex(ValueError, "image-external-data"):
            self.observe_qemu_metadata(metadata)
        self.assertEqual(self.hash_calls, [])

    def test_full_observer_refuses_external_data_fields_even_empty_or_false(self):
        for key in ("data-file", "data-file-raw"):
            for value in (None, "", False):
                for location in ("image", "descriptor", "data"):
                    with self.subTest(key=key, value=value, location=location):
                        metadata = {"format": "qcow2", "virtual-size": 96 * 1024 ** 3,
                                    "format-specific": {"type": "qcow2", "data": {"compat": "1.1"}}}
                        target = {"image": metadata, "descriptor": metadata["format-specific"],
                                  "data": metadata["format-specific"]["data"]}[location]
                        target[key] = value
                        with self.assertRaisesRegex(ValueError, "image-external-data"):
                            self.observe_qemu_metadata(metadata)
                        self.assertEqual(self.hash_calls, [])

    def test_full_observer_refuses_malformed_dependency_descriptor_before_hash(self):
        descriptors = (None, [], "qcow2", {}, {"type": "raw", "data": {}},
                       {"type": "qcow2"}, {"type": "qcow2", "data": None},
                       {"type": "qcow2", "data": []}, {"type": "qcow2", "data": "unknown"})
        for descriptor in descriptors:
            with self.subTest(descriptor=descriptor):
                metadata = {"format": "qcow2", "virtual-size": 96 * 1024 ** 3,
                            "format-specific": descriptor}
                with self.assertRaisesRegex(ValueError, "image-dependency-descriptor"):
                    self.observe_qemu_metadata(metadata)
                self.assertEqual(self.hash_calls, [])

    def test_full_observer_accepts_actual_parser_standalone_qcow2_descriptor(self):
        metadata = {"format": "qcow2", "virtual-size": 96 * 1024 ** 3, "dirty-flag": False,
                    "format-specific": {"type": "qcow2", "data": {
                        "compat": "1.1", "refcount-bits": 16, "compression-type": "zlib"}}}
        value = self.observe_qemu_metadata(metadata)
        self.assertEqual(value["sourceSha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(self.hash_calls, [len(self.raw)])
        self.assertFalse(value["cloneAdmitted"])

    def test_invisible_fd_directory_never_becomes_empty_holder_admission(self):
        pid = self.pid(42)
        original = Path.iterdir
        def unavailable(path):
            if path == pid / "fd":
                raise PermissionError("measured ordinary FD census gap")
            return original(path)
        with patch.object(Path, "iterdir", unavailable):
            with self.assertRaises(PermissionError):
                self.observe()
        self.assertEqual(self.hash_calls, [])

    def test_source_argv_claim_refuses_even_before_a_disk_fd_opens(self):
        pid = self.pid(42, comm="qemu-system-x86_64")
        (pid / "cmdline").write_bytes(b"qemu-system-x86_64\0-drive\0file=" + os.fsencode(self.source) + b",format=qcow2\0")
        with self.assertRaisesRegex(ValueError, "source-held"):
            self.observe()
        self.assertEqual(self.hash_calls, [])

    def test_source_hardlink_and_symlink_refuse_before_hash(self):
        other = self.root / "hardlink"
        os.link(self.source, other)
        with self.assertRaisesRegex(ValueError, "source-file"):
            self.observe()
        other.unlink()
        self.source.unlink()
        self.source.symlink_to(other)
        with self.assertRaisesRegex(ValueError, "source-ancestry"):
            self.observe()
        self.assertEqual(self.hash_calls, [])

    def test_actual_source_mutation_after_hash_refuses_final_generation(self):
        real_hash = inventory.hash_source.side_effect
        def mutate(fd, size, deadline):
            digest = real_hash(fd, size, deadline)
            self.source.write_bytes(b"changed source")
            return digest
        with patch.object(inventory, "hash_source", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "source-generation"):
                self.observe()

    def test_actual_parent_replacement_refuses_held_file_generation(self):
        directory = self.root / "image"
        directory.mkdir()
        self.source.rename(directory / self.source.name)
        self.source = directory / self.source.name
        real_hash = inventory.hash_source.side_effect
        def replace(fd, size, deadline):
            digest = real_hash(fd, size, deadline)
            directory.rename(self.root / "old-image")
            directory.mkdir()
            self.source.write_bytes(self.raw)
            return digest
        with patch.object(inventory, "hash_source", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "source-generation"):
                self.observe()

    def test_final_qemu_generation_drift_refuses_stopped_proof(self):
        pid = self.pid(42, comm="qemu-system-x86_64-headless")
        real_hash = inventory.hash_source.side_effect
        def changed(fd, size, deadline):
            digest = real_hash(fd, size, deadline)
            (pid / "stat").write_text("42 (harmless child) " + " ".join(["S"] + ["0"] * 18 + ["18"]))
            return digest
        with patch.object(inventory, "hash_source", side_effect=changed):
            with self.assertRaisesRegex(ValueError, "closing-qemu-generation"):
                self.observe()

    def test_actual_destination_and_low_disk_refuse_without_hash(self):
        Path(self.destinations[0]).mkdir()
        with self.assertRaisesRegex(ValueError, "destination-exists"):
            self.observe()
        Path(self.destinations[0]).rmdir()
        actual = os.statvfs(self.root)
        with self.assertRaisesRegex(ValueError, "disk-free"):
            self.observe(actual.f_bavail * actual.f_frsize + 1)
        self.assertEqual(self.hash_calls, [])

    def test_real_loopback_listener_conflict_parsed_before_hash(self):
        server = socket.socket()
        self.addCleanup(server.close)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        # A projected /proc table uses the real listener's actual port; the
        # production collector reads the unprojected kernel table itself.
        (self.proc / "net" / "tcp").write_text("header\n0: 0100007F:" + format(port, "04X") + " 00000000:0000 0A\n")
        self.assertEqual(inventory.tcp_conflicts(self.proc, (port,)), [port])
        with self.assertRaisesRegex(ValueError, "port-conflict"):
            inventory.namespace_facts(self.proc, self.destinations, (port,), inventory.MACS, {"macs": []})
        self.assertEqual(self.hash_calls, [])

    def test_mac_and_unix_socket_namespace_refuse_before_hash(self):
        pid = self.pid(42, comm="qemu-system-x86_64")
        (pid / "cmdline").write_bytes(b"qemu\0-net\0nic,macaddr=" + inventory.MACS[0].encode() + b"\0")
        with self.assertRaisesRegex(ValueError, "mac-conflict"):
            self.observe()
        (pid / "cmdline").write_bytes(b"qemu\0")
        (self.proc / "net" / "unix").write_text("header\n0: 2 0 10000 1 1 123 " + self.destinations[0] + "/qga.sock\n")
        with self.assertRaisesRegex(ValueError, "socket-conflict"):
            self.observe()
        self.assertEqual(self.hash_calls, [])

    def test_remote_program_compiles_exact_functions_and_has_no_state_changes(self):
        self.hash_patch.stop()
        self.image_patch.stop()
        program = inventory.remote_program(230)
        compile(program, "fixed remote observer", "exec")
        self.assertIn("need(os.geteuid()==0,'privilege-required')", program)
        self.assertIn("/home/kardinal/vpn-control-windows-native-20260907/task.qcow2", program)
        self.assertIn("def holder_census", program)
        self.assertNotIn("mkdir(", program)
        self.assertNotIn("O_WRONLY", program)
        self.assertNotIn("qemu-system-x86_64 -", program)

    def test_private_credential_metadata_rejects_hardlink_without_hashing_bytes(self):
        directory = self.root / ".codex"
        directory.mkdir(mode=0o700)
        path = directory / "arch-sudo.local"
        path.write_bytes(b"private fixture value")
        path.chmod(0o600)
        metadata = inventory.credential_metadata(self.root)
        self.assertEqual(metadata[1], inventory.generation(path.lstat()))
        os.link(path, directory / "link")
        with self.assertRaisesRegex(ValueError, "credential-file"):
            inventory.credential_metadata(self.root)


@unittest.skipUnless(os.name == "posix", "guarded Arch transport has POSIX local evidence")
class TransportEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / ".codex").mkdir(mode=0o700)
        path = self.root / ".codex" / "arch-sudo.local"
        path.write_bytes(b"fixture-only-private-input")
        path.chmod(0o600)
        path = self.root / ".vm-hosts.local.json"
        path.write_text('{}')
        path.chmod(0o600)
        (self.root / ".runtime" / "parity-evidence").mkdir(parents=True, mode=0o700)

    def actual_transport(self, code):
        from agent_tools import ssh_transport, windows_cp117_bound_absence_completion as authority
        # Only configured route/master/native sudo are projected. The actual
        # source/config/secret guards and real child/raw/parse remain in use.
        with patch.object(authority, "_outer_authority", return_value={"receiptSha256": "a" * 64}), \
             patch.object(authority, "_verify_outer"), patch.object(ssh_transport, "load_config", return_value=object()), \
             patch.object(ssh_transport, "build_ssh_argv", return_value=[sys.executable, "-c", code]):
            return inventory.observe(self.root, host="archlinux", timeout_seconds=30)

    def test_actual_factory_boolean_schema_is_unknown_with_original_failed_raw(self):
        payload = {"schemaVersion": True, "host": "archlinux", "state": "observed", "sourceState": "stopped-observed",
                   "nativeActionAllowed": False, "cloneAdmitted": False}
        result = self.actual_transport("print(" + repr(json.dumps(payload)) + ")")
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["cloneAdmitted"])
        raw = self.root / ".runtime" / "parity-evidence" / result["evidenceLeaf"] / "transport.stdout.private"
        self.assertEqual(json.loads(raw.read_bytes()), payload)

    def test_actual_factory_long_read_uses_real_ssh_connection_bound(self):
        from agent_tools import windows_cp117_bound_absence_completion as authority
        key, known = self.root / "fixture-key", self.root / "fixture-known-hosts"
        key.write_bytes(b"fixture only; no SSH process runs")
        key.chmod(0o600)
        known.write_bytes(b"fixture only")
        known.chmod(0o600)
        config = {"schemaVersion": 1, "hosts": {"archlinux": {
            "host": "127.0.0.1", "port": 22, "user": "fixture",
            "identityFile": str(key), "knownHostsFile": str(known)}}}
        (self.root / ".vm-hosts.local.json").write_text(json.dumps(config))
        payload = {"schemaVersion": 1, "host": "archlinux", "state": "unknown",
                   "sourceState": "unknown", "reason": "fixture-observation",
                   "nativeActionAllowed": False, "cloneAdmitted": False}
        original_collect = inventory.bounded_collect
        calls = []
        def harmless_remote(argv, secret, timeout):
            # Actual config parser and SSH builder execute. Only submitting
            # the generated SSH argv is replaced with a real harmless child.
            calls.append((argv, timeout))
            return original_collect([sys.executable, "-c", "print(" + repr(json.dumps(payload)) + ")"],
                                    secret, timeout)
        with patch.object(authority, "_outer_authority", return_value={"receiptSha256": "a" * 64}), \
             patch.object(authority, "_verify_outer"), \
             patch.object(inventory, "bounded_collect", side_effect=harmless_remote):
            value = inventory.observe(self.root, host="archlinux", timeout_seconds=240)
        self.assertEqual(value["reason"], "fixture-observation")
        self.assertEqual(len(calls), 1)
        self.assertIn("ConnectTimeout=60", calls[0][0])
        self.assertEqual(calls[0][1], 240)
        self.assertFalse(value["cloneAdmitted"])

    def test_actual_factory_malformed_and_nonzero_retain_raw_unknown(self):
        for code, raw in (("print('MALFORMED_PREFIX')", b'MALFORMED_PREFIX\n'),
            ("import sys;print('NATIVE_PREFIX');sys.exit(17)", b'NATIVE_PREFIX\n')):
            with self.subTest(code=code):
                value = self.actual_transport(code)
                self.assertEqual(value["state"], "unknown")
                path = self.root / ".runtime" / "parity-evidence" / value["evidenceLeaf"] / "transport.stdout.private"
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(value["rawReceipt"]["sha256"], hashlib.sha256(raw).hexdigest())
                self.assertFalse(value["cloneAdmitted"])

    def test_actual_bounded_child_timeout_retains_prefix_without_claiming_eof(self):
        code = "import os,sys,time;sys.stdin.buffer.read();os.write(1,b'BEFORE_DEADLINE');time.sleep(.4)"
        raw, trace = inventory.bounded_collect([sys.executable, '-c', code], b'private-fixture', .15)
        self.assertEqual(raw, b'BEFORE_DEADLINE')
        self.assertEqual(trace["reason"], "transport-deadline")
        self.assertFalse(trace["stdoutEof"])
        self.assertIsNone(trace["exitCode"])
        self.assertTrue(trace["clientTerminatedForBound"])

    def test_actual_bounded_child_overflow_retains_only_original_bounded_prefix(self):
        code = "import os,sys,time;sys.stdin.buffer.read();os.write(1,b'x'*" + str(inventory.MAX_OUTPUT + 65536) + ");time.sleep(.4)"
        raw, trace = inventory.bounded_collect([sys.executable, '-c', code], b'private-fixture', 2)
        self.assertEqual(len(raw), inventory.MAX_OUTPUT + 1)
        self.assertEqual(trace["reason"], "transport-output-limit")
        self.assertFalse(trace["stdoutEof"])
        self.assertTrue(trace["clientTerminatedForBound"])

    def test_schema_bool_float_incomplete_scope_refuse_actual_factory(self):
        for schema in (True, 1.0, 2):
            payload = {"schemaVersion": schema, "host": "archlinux", "state": "unknown", "sourceState": "unknown",
                       "nativeActionAllowed": False, "cloneAdmitted": False, "reason": "observer-unavailable"}
            value = self.actual_transport("print(" + repr(json.dumps(payload)) + ")")
            self.assertEqual(value["reason"], "readonly-output-or-authority")
            self.assertFalse(value["cloneAdmitted"])

    def test_valid_unknown_producer_preserves_finite_reason_and_raw(self):
        payload = {"schemaVersion": 1, "host": "archlinux", "state": "unknown", "sourceState": "unknown",
                   "nativeActionAllowed": False, "cloneAdmitted": False, "reason": "PermissionError"}
        value = self.actual_transport("print(" + repr(json.dumps(payload)) + ")")
        self.assertEqual(value["state"], "unknown")
        self.assertEqual(value["reason"], "PermissionError")
        self.assertTrue(value["transport"]["stdoutEof"])
        self.assertEqual(value["transport"]["exitCode"], 0)


if __name__ == "__main__":
    unittest.main()
