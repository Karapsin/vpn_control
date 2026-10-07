"""Real filesystem/child coverage for the fixed adapter; no product/native pass."""
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from agent_tools import windows_packaged_cli_acceptance as adapter


CORRELATION = "b578645b-0e95-40e9-a557-9fd8b82d0e4c"


def identity(data):
    return {"sha256": hashlib.sha256(data).hexdigest(), "sizeBytes": len(data)}


def request():
    files = {name: identity(b"fixture") for name in (
        "vpn-control.exe", "vpn-control-cli.exe", "app/vpn-control.cfg", "app/vpn-control-cli.cfg",
        "app/desktopApp-2.2.2.jar", "runtime/bin/java.exe",
        "app/native/windows-amd64/vpn-control-install-helper.exe",
        "app/native/windows-amd64/vpn-control-vpn-broker.exe")}
    return {"correlationId": CORRELATION, "sourceSha": "a" * 40, "sourceFingerprint": "b" * 64,
            "packageArtifactId": "sha256-" + "c" * 64, "productVersion": "2.2.2",
            "productCode": "{CFCB6A78-7F8F-31FD-8B20-C1977A677578}", "sessionId": 1,
            "installedFiles": files, "pythonFiles": {"python.exe": identity(b"python"), "python313.dll": identity(b"dll")},
            "harnessFiles": {name: identity(b"source") for name in adapter.HARNESS_FILES}}


class AdmissionTest(unittest.TestCase):
    def test_prepare_is_typed_data_only_and_keeps_full_scope_open(self):
        source = request()
        result = adapter.prepare(source)
        self.assertFalse(result["nativeActionAllowed"])
        self.assertFalse(result["fullWindowsAcceptance"])
        self.assertIn("sole-CP117-generation", result["externalAdmissionRequired"])
        source["installedFiles"]["vpn-control.exe"]["sha256"] = "d" * 64
        self.assertNotEqual(result["installedFiles"]["vpn-control.exe"], source["installedFiles"]["vpn-control.exe"])

    def test_rejects_unsafe_inventory_and_type_coercion(self):
        for name in ("../foreign", "app/../foreign", "/absolute", "app\\file", "app/a:stream", "app/NUL.dll", "app/x."):
            with self.subTest(name=name), self.assertRaises(adapter.AcceptanceError):
                adapter._inventory({name: identity(b"x")})
        for bad in (True, 1.0, -1):
            with self.subTest(bad=bad), self.assertRaises(adapter.AcceptanceError):
                adapter._inventory({"file": {"sha256": "a" * 64, "sizeBytes": bad}})
        with self.assertRaises(adapter.AcceptanceError):
            adapter._inventory({"File": identity(b"x"), "file": identity(b"x")})

    def test_rejects_missing_roles_source_and_arbitrary_command(self):
        cases = []
        for field, bad in (("sourceSha", "dev"), ("sourceFingerprint", "x" * 64),
                           ("productVersion", "2.2.20"), ("sessionId", True), ("productCode", "anything")):
            value = request()
            value[field] = bad
            cases.append(value)
        value = request(); del value["installedFiles"]["vpn-control-cli.exe"]; cases.append(value)
        value = request(); del value["pythonFiles"]["python313.dll"]; cases.append(value)
        value = request(); value["harnessFiles"]["arbitrary.py"] = identity(b"x"); cases.append(value)
        value = request(); value["command"] = "anything"; cases.append(value)
        for value in cases:
            with self.subTest(value=list(value)), self.assertRaises(adapter.AcceptanceError):
                adapter.prepare(value)

    def test_fixed_actual_harness_argv_is_accepted_by_its_real_parser(self):
        harness = Path(__file__).resolve().parents[2] / "scripts/test_packaged_cli.py"
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing installed cli.exe"
            argv = adapter._build_argv(Path(sys.executable), harness, missing, "2.2.2")
            self.assertEqual(argv[-4:], ("--launcher", str(missing), "--expected-version", "2.2.2"))
            completed = subprocess.run(argv, capture_output=True, timeout=10)
            # The actual unchanged parser reaches the harness's first real file
            # read and rejects the missing launcher. This is composition proof,
            # not a mocked success or a native public CLI pass.
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"FileNotFoundError", completed.stderr)
            self.assertNotIn(b"unrecognized arguments", completed.stderr)

    @unittest.skipIf(os.name == "nt", "non-Windows admission refusal")
    def test_start_refuses_platform_before_creating_any_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(adapter.AcceptanceError, "windows-native-required"):
                adapter.start(request(), root)
            self.assertEqual(list(root.iterdir()), [])


class FileAdmissionTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.path = self.root / "source.py"
        self.raw = b"print('unchanged')\n"
        self.path.write_bytes(self.raw)
        self.path.chmod(0o600)

    def pin(self):
        pin = adapter._pin(self.path, identity(self.raw))
        self.addCleanup(pin.close)
        return pin

    def test_held_reader_roundtrip_and_empty_inventory_file(self):
        pin = self.pin()
        self.assertEqual(pin.bytes(128), self.raw)
        self.path = self.root / "empty"
        self.path.touch()
        pin = adapter._pin(self.path, identity(b""))
        try:
            self.assertEqual(pin.bytes(0), b"")
        finally:
            pin.close()

    def test_same_bytes_named_replacement_is_rejected(self):
        pin = self.pin()
        replacement = self.root / "replacement"
        replacement.write_bytes(self.raw)
        if os.name == "nt":
            with self.assertRaises(PermissionError):
                os.replace(replacement, self.path)
            pin.current()
            return
        os.replace(replacement, self.path)
        with self.assertRaisesRegex(adapter.AcceptanceError, "generation"):
            pin.current()

    def test_held_content_mutation_is_rejected_even_with_restored_mtime(self):
        pin = self.pin()
        before = self.path.stat()
        if os.name == "nt":
            with self.assertRaises(PermissionError):
                self.path.write_bytes(b"X" + self.raw[1:])
            pin.current()
            return
        self.path.write_bytes(b"X" + self.raw[1:])
        os.utime(self.path, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaises(adapter.AcceptanceError):
            pin.bytes(128)

    def test_digest_mismatch_and_hardlink_are_refused_before_execution(self):
        with self.assertRaisesRegex(adapter.AcceptanceError, "file-digest"):
            adapter._pin(self.path, identity(b"X" * len(self.raw)))
        os.link(self.path, self.root / "alias")
        with self.assertRaisesRegex(adapter.AcceptanceError, "type-link-size"):
            adapter._pin(self.path, identity(self.raw))

    @unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "POSIX link and FIFO boundary")
    def test_symlink_parent_and_fifo_are_refused_without_blocking(self):
        linked = self.root / "linked"
        linked.symlink_to(self.path)
        with self.assertRaises(adapter.AcceptanceError):
            adapter._pin(linked, identity(self.raw))
        directory = self.root / "parent-alias"
        directory.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(adapter.AcceptanceError):
            adapter._pin(directory / self.path.name, identity(self.raw))
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        started = time.monotonic()
        with self.assertRaises(adapter.AcceptanceError):
            adapter._pin(fifo, identity(b""))
        self.assertLess(time.monotonic() - started, 0.2)

    def test_real_parent_exchange_and_tree_addition_are_detectable(self):
        nested = self.root / "tree"
        nested.mkdir()
        self.path = nested / "source.py"
        self.path.write_bytes(self.raw)
        pin = self.pin()
        if os.name == "nt":
            with self.assertRaises(PermissionError):
                nested.rename(self.root / "old-tree")
            pin.current()
            return
        nested.rename(self.root / "old-tree")
        nested.mkdir()
        self.path.write_bytes(self.raw)
        with self.assertRaises(adapter.AcceptanceError):
            pin.current()
        self.assertEqual(adapter._tree(nested), {"source.py"})
        (nested / "unexpected.py").write_bytes(b"x")
        self.assertNotEqual(adapter._tree(nested), {"source.py"})

    def test_amd64_header_uses_real_held_bytes_and_refuses_arm(self):
        payload = bytearray(96)
        payload[:2] = b"MZ"
        struct.pack_into("<I", payload, 60, 64)
        payload[64:70] = b"PE\0\0\x64\x86"
        self.raw = bytes(payload)
        self.path.write_bytes(self.raw)
        adapter._amd64(self.pin())
        payload[68:70] = b"\x64\xaa"
        self.path = self.root / "arm.exe"
        self.raw = bytes(payload)
        self.path.write_bytes(self.raw)
        with self.assertRaisesRegex(adapter.AcceptanceError, "not-amd64"):
            adapter._amd64(self.pin())

    def test_once_file_cannot_overwrite_an_existing_intent(self):
        intent = self.root / "intent.json"
        adapter._write_new(intent, b"original")
        with self.assertRaises(FileExistsError):
            adapter._write_new(intent, b"replay")
        self.assertEqual(intent.read_bytes(), b"original")
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(intent.stat().st_mode), 0o600)


@unittest.skipIf(os.name == "nt", "portable boundary diagnostic; native guest needs actual CP117 admission")
class ActualStartRefusalTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def actual_start(self, root, code, closing=None, refuse_journal=False, portable_birth=False):
        """Only native token/MSI and Popen executable need portable seams.

        The actual prepare/start inventory/hash/PE/private sources/intent/pipes/
        observer and all post-Popen guards execute unchanged on real TempFS.
        """
        installed, python, sources, tasks = (root / x for x in ("installed", "python", "sources", "tasks"))
        plan = request()
        pe = bytearray(96); pe[:2] = b"MZ"
        struct.pack_into("<I", pe, 60, 64); pe[64:70] = b"PE\0\0\x64\x86"
        for directory, key in ((installed, "installedFiles"), (python, "pythonFiles"), (sources, "harnessFiles")):
            directory.mkdir(mode=0o700)
            for name in plan[key]:
                data = bytes(pe) if name.endswith((".exe", ".dll")) else b"sealed source fixture"
                path = directory / name; path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data); path.chmod(0o600); plan[key][name] = identity(data)
        tasks.mkdir(mode=0o700)
        children = []
        self.addCleanup(lambda: self.cleanup_children(children))
        actual_popen = subprocess.Popen
        def launch(argv, **kwargs):
            child = actual_popen([sys.executable, "-c", code], **kwargs)
            children.append(child)
            return child
        owner_calls = []
        def owner(session):
            owner_calls.append(session)
            if len(owner_calls) > 1 and closing:
                closing(children[-1])
            return {"sid": adapter.SID, "sessionId": session, "elevated": False}
        class MsiRead:
            def __call__(self, product, field, buffer, size):
                buffer.value = plan["productVersion"] if field == "VersionString" else str(installed)
                return 0
        class Msi:
            MsiGetProductInfoW = MsiRead()
        original_write = adapter._write_new
        original_birth = adapter._birth
        def birth(child):
            return 1 if portable_birth else original_birth(child)
        def write(path, data):
            if refuse_journal and path.name == "submitted.json":
                raise PermissionError("measured post-submission journal refusal")
            original_write(path, data)
        with patch.object(adapter, "INSTALL_ROOT", installed), patch.object(adapter, "PYTHON_ROOT", python), \
             patch.object(adapter, "TASK_ROOT", tasks), patch.object(adapter, "_native_owner", side_effect=owner), \
             patch.object(adapter.ctypes, "WinDLL", return_value=Msi(), create=True), \
             patch.object(adapter, "_write_new", side_effect=write), \
             patch.object(adapter, "_birth", side_effect=birth), \
             patch.object(adapter.subprocess, "Popen", side_effect=launch):
            try:
                run = adapter.start(plan, sources)
            except adapter.PostSubmissionUnknown as error:
                self.addCleanup(lambda retained=error.run: self.cleanup_run(retained))
                raise
        self.addCleanup(lambda: self.cleanup_run(run))
        return run, children

    @staticmethod
    def cleanup_children(children):
        for child in children:
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
            for stream in (child.stdout, child.stderr):
                stream.close()

    @staticmethod
    def cleanup_run(run):
        adapter._NATIVE_STARTS.pop(run, None)
        for pin in run.pins:
            pin.close()
        for stream in run.outputs.values():
            stream.close()
        if run.selector is not None:
            run.selector.close()

    def test_actual_start_closing_owner_failure_preserves_original_observer_and_raw(self):
        def closing(child):
            child.wait(timeout=5)
            raise adapter.AcceptanceError("closing-native-owner-changed")
        run, children = self.actual_start(self.root,
            "import os;os.write(1,b'PUBLIC_POST_SUBMISSION')", closing)
        self.assertIs(run.process, children[0])
        self.assertEqual(len(children), 1)
        self.assertEqual(run.process.poll(), 0)
        self.assertNotIn(run, adapter._NATIVE_STARTS)
        self.assertIsNone(run.sealed)
        self.assertFalse((run.directory / "terminal.json").exists())
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"PUBLIC_POST_SUBMISSION")
        observations = [json.loads(p.read_text()) for p in run.directory.glob("observation-*.json")]
        self.assertTrue(observations)
        result = observations[-1]
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "post-submission-admission-unknown")
        self.assertIsNone(result["exitCode"])
        self.assertFalse(result["replayAllowed"])
        self.assertEqual(result["raw"]["stdout"]["sizeBytes"], len(b"PUBLIC_POST_SUBMISSION"))
        self.assertEqual(run.observe(.1)["state"], "unknown")

    def test_actual_start_post_submission_journal_refusal_exposes_original_observer(self):
        run, children = self.actual_start(self.root,
            "import os;os.write(1,b'JOURNAL_PREFIX')", refuse_journal=True)
        self.assertIs(run.process, children[0])
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"JOURNAL_PREFIX")
        self.assertTrue(run.admission_failure)
        self.assertNotIn(run, adapter._NATIVE_STARTS)
        self.assertIsNone(run.sealed)
        self.assertFalse((run.directory / "terminal.json").exists())

    def test_actual_start_tree_closure_refusal_keeps_same_child_and_prefix(self):
        def closing(child):
            (self.root / "installed" / "unadmitted").write_bytes(b"x")
        run, children = self.actual_start(self.root,
            "import os;os.write(1,b'TREE_PREFIX')", closing, portable_birth=True)
        self.assertIs(run.process, children[0])
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"TREE_PREFIX")
        self.assertTrue(run.admission_failure)
        self.assertNotIn(run, adapter._NATIVE_STARTS)
        self.assertIsNone(run.sealed)

    def test_actual_start_held_source_pin_drift_refusal_preserves_prefix(self):
        def closing(child):
            (self.root / "sources" / adapter.HARNESS_FILES[0]).write_bytes(b"changed source")
        run, children = self.actual_start(self.root,
            "import os;os.write(1,b'SOURCE_PREFIX')", closing, portable_birth=True)
        # birth=1 is only a Darwin portability seam to reach the actual held
        # pin recheck. It is never evidence of an installed native start.
        self.assertIs(run.process, children[0])
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"SOURCE_PREFIX")
        self.assertTrue(run.admission_failure)
        self.assertNotIn(run, adapter._NATIVE_STARTS)
        self.assertIsNone(run.sealed)

    def test_actual_start_unsafe_raw_refusal_exposes_original_observer_in_exception(self):
        def closing(child):
            leaf = self.root / "tasks" / CORRELATION
            replacement = leaf / "replacement"
            replacement.write_bytes(b"foreign named raw")
            os.replace(replacement, leaf / "stdout.private")
            raise adapter.AcceptanceError("closing-native-owner-changed")
        with self.assertRaises(adapter.PostSubmissionUnknown) as caught:
            self.actual_start(self.root, "import os;os.write(1,b'HELD_ORIGINAL')", closing)
        run = caught.exception.run
        self.assertTrue(run.admission_failure)
        self.assertNotIn(run, adapter._NATIVE_STARTS)
        self.assertIsNone(run.sealed)
        self.assertFalse((run.directory / "terminal.json").exists())
        self.assertEqual(run.counts["stdout"], len(b"HELD_ORIGINAL"))
        output = run.outputs["stdout"]
        os.lseek(output.fileno(), 0, os.SEEK_SET)
        self.assertEqual(os.read(output.fileno(), 65536), b"HELD_ORIGINAL")
        self.assertFalse(output.closed)
        self.assertFalse(run.process.stdout.closed)

    def test_actual_start_refusal_deadline_keeps_live_handle_and_later_tail(self):
        def closing(child):
            raise adapter.AcceptanceError("closing-native-owner-changed")
        run, children = self.actual_start(self.root,
            "import os,time;os.write(1,b'LIVE_PREFIX');time.sleep(.4);os.write(1,b'_TAIL')", closing)
        self.assertIs(run.process, children[0])
        self.assertIsNone(run.process.poll())
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"LIVE_PREFIX")
        self.assertFalse(run.eof["stdout"])
        final = run.observe(2)
        self.assertEqual(final["state"], "unknown")
        self.assertIsNone(final["exitCode"])
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"LIVE_PREFIX_TAIL")
        self.assertIsNone(run.sealed)
        self.assertNotIn(run, adapter._NATIVE_STARTS)
        self.assertEqual(len(children), 1)

    def test_actual_start_refusal_original_exit_does_not_infer_held_pipe_eof(self):
        def closing(child):
            raise adapter.AcceptanceError("closing-native-owner-changed")
        descendant = "import os,time;time.sleep(.4);os.write(1,b'DESCENDANT_TAIL')"
        run, children = self.actual_start(self.root,
            "import subprocess,sys,os;subprocess.Popen([sys.executable,'-c'," + repr(descendant) + "]);os.write(1,b'PARENT_PREFIX')", closing)
        self.assertEqual(run.process.poll(), 0)
        self.assertFalse(run.eof["stdout"])
        self.assertIsNone(run.sealed)
        final = run.observe(2)
        self.assertTrue(final["raw"]["stdout"]["eof"])
        self.assertEqual(final["state"], "unknown")
        self.assertIsNone(final["exitCode"])
        self.assertIs(run.process, children[0])
        self.assertIn(b'DESCENDANT_TAIL', (run.directory / "stdout.private").read_bytes())

    def test_actual_start_refusal_overflow_keeps_original_handle_and_sticky_unknown(self):
        def closing(child):
            raise adapter.AcceptanceError("closing-native-owner-changed")
        run, children = self.actual_start(self.root,
            "import os;data=b'x'*" + str(adapter._MAX_STREAM + 65536) + ";os.write(1,data)", closing)
        final = run.observe(2)
        self.assertEqual(final["reason"], "raw-stream-limit")
        self.assertIsNone(final["exitCode"])
        self.assertIs(run.process, children[0])
        self.assertLessEqual(final["raw"]["stdout"]["sizeBytes"], adapter._MAX_STREAM + 65536)
        self.assertIsNone(run.sealed)
        self.assertFalse((run.directory / "terminal.json").exists())


class RealCaptureTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.runs = []
        self.addCleanup(self.cleanup_runs)

    def cleanup_runs(self):
        # Only the harmless original children created by this test are stopped.
        for run in self.runs:
            if run.process.poll() is None:
                run.process.terminate()
                run.process.wait(timeout=5)
            if run.sealed is None:
                for stream in run.outputs.values():
                    stream.close()
                for pin in run.pins:
                    pin.close()
                for name in run.eof:
                    getattr(run.process, name).close()
                if run.selector is not None:
                    run.selector.close()

    def spawn(self, code, pins=None, trees=None):
        leaf = self.root / str(len(self.runs))
        leaf.mkdir(mode=0o700)
        adapter._write_new(leaf / "intent.json", adapter._json_bytes({"correlationId": CORRELATION}))
        process = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            run = adapter.RetainedRun(process, leaf, {"correlationId": CORRELATION}, pins or [], trees)
        except Exception:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()
            raise
        self.runs.append(run)
        return run

    def test_real_child_nonzero_retains_both_raw_streams_and_eofs(self):
        run = self.spawn("import sys;sys.stdout.buffer.write(b'actual stdout');sys.stderr.buffer.write(b'actual stderr');sys.exit(7)")
        result = run.observe(5)
        self.assertEqual(result["exitCode"], 7)
        self.assertFalse(result["replayAllowed"])
        self.assertFalse(result["fullWindowsAcceptance"])
        for name, data in (("stdout", b"actual stdout"), ("stderr", b"actual stderr")):
            self.assertEqual((run.directory / (name + ".private")).read_bytes(), data)
            self.assertEqual(result["raw"][name]["sha256"], hashlib.sha256(data).hexdigest())
            self.assertTrue(result["raw"][name]["eof"])
        self.assertEqual(run.observe(0.1), result)
        self.assertEqual(adapter._retained_status(run.directory, CORRELATION), result)

    def test_retained_status_rejects_raw_tampering_and_numeric_eof(self):
        run = self.spawn("print('actual')")
        result = run.observe(5)
        path = run.directory / "stdout.private"
        path.write_bytes(b"forged")
        with self.assertRaises(adapter.AcceptanceError):
            adapter._retained_status(run.directory, CORRELATION)
        path.write_bytes(b"actual\n")
        terminal = run.directory / "terminal.json"
        altered = dict(result)
        altered["raw"]["stdout"]["eof"] = 1
        terminal.write_bytes(adapter._json_bytes(altered))
        with self.assertRaisesRegex(adapter.AcceptanceError, "terminal-raw-eof"):
            adapter._retained_status(run.directory, CORRELATION)

    def test_status_before_terminal_stays_unknown_without_another_child(self):
        run = self.spawn("import time;time.sleep(.2)")
        original = run.process
        result = adapter._retained_status(run.directory, CORRELATION)
        self.assertEqual(result["reason"], "original-handle-observation-required")
        self.assertFalse(result["replayAllowed"])
        self.assertIs(original, run.process)
        run.observe(5)

    def test_actual_deadline_keeps_prefix_and_same_original_handle(self):
        run = self.spawn("import sys,time;sys.stdout.buffer.write(b'prefix');sys.stdout.flush();time.sleep(.4);sys.stdout.buffer.write(b'-terminal')")
        first = run.observe(0.15)
        self.assertEqual(first["state"], "unknown")
        self.assertIsNone(first["exitCode"])
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"prefix")
        self.assertFalse(first["raw"]["stdout"]["eof"])
        original = run.process
        final = run.observe(5)
        self.assertIs(run.process, original)
        self.assertEqual(final["exitCode"], 0)
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"prefix-terminal")
        self.assertTrue(all(x["eof"] for x in final["raw"].values()))

    def test_actual_native_readiness_error_retains_prefix_and_unknown_observation(self):
        run = self.spawn("import os,time;os.write(1,b'PUBLIC_PREFIX');time.sleep(.15)")
        original_ready = run._ready
        def native_readiness():
            if run.counts["stdout"]:
                raise adapter.AcceptanceError("pipe-observation-unknown")
            return original_ready()
        # The only seam is the native Peek failure boundary after a genuine
        # child write/read. Actual buffers, fsync, journals and process remain.
        with patch.object(run, "_ready", side_effect=native_readiness):
            result = run.observe(2)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "pipe-observation-unknown")
        self.assertIsNone(result["exitCode"])
        self.assertEqual((run.directory / "stdout.private").read_bytes(), b"PUBLIC_PREFIX")
        self.assertFalse(result["raw"]["stdout"]["eof"])
        self.assertIsNone(run.sealed)
        self.assertTrue(list(run.directory.glob("observation-*.json")))
        self.assertFalse((run.directory / "terminal.json").exists())
        run.observe(5)

    def test_partial_constructor_intent_cannot_forge_installed_acceptance(self):
        run = self.spawn("print('PUBLIC')")
        run.intent.update(scope=adapter.SCOPE, sourceSha="a" * 40,
                          owner={"sid": adapter.SID, "elevated": False})
        if run.birth is None:
            # Darwin has no implemented birth reader. Preserve the review's
            # explicit portable birth seam so the actual producer-admission
            # defect is tested rather than masked by that unrelated unknown.
            run.birth = 1
        result = run.observe(5)
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["fullWindowsAcceptance"])
        self.assertFalse(result["replayAllowed"])

    def test_complete_declared_plan_and_caller_flags_are_not_native_start_provenance(self):
        run = self.spawn("print('PUBLIC')")
        declared = adapter.prepare(request())
        declared.update(owner={"sid": adapter.SID, "elevated": False},
                        nativeStarted=True, nativeAdmission=True,
                        argv=list(run.process.args))
        run.intent = declared
        run.nativeAdmission = True
        if run.birth is None:
            run.birth = 1
        result = run.observe(5)
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "local-collector-only")

    def test_original_child_exit_does_not_infer_pipe_eof(self):
        descendant = "import sys,time;time.sleep(.4);sys.stdout.write('descendant')"
        run = self.spawn("import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(descendant) + "]);print('parent',flush=True)")
        first = run.observe(0.15)
        self.assertIsNotNone(run.process.poll())
        self.assertEqual(first["state"], "unknown")
        self.assertIsNone(first["exitCode"])
        self.assertFalse(first["raw"]["stdout"]["eof"])
        final = run.observe(5)
        self.assertEqual(final["exitCode"], 0)
        self.assertTrue(final["raw"]["stdout"]["eof"])
        self.assertIn(b"descendant", (run.directory / "stdout.private").read_bytes())

    def test_output_named_replacement_does_not_produce_passing_receipt(self):
        run = self.spawn("import time;time.sleep(.2);print('actual')")
        original = run.directory / "stdout.private"
        replacement = run.directory / "replacement"
        replacement.write_bytes(b"fake")
        os.replace(replacement, original)
        with self.assertRaisesRegex(adapter.AcceptanceError, "raw-output-drift"):
            run.observe(5)
        self.assertFalse((run.directory / "terminal.json").exists())

    def test_source_and_extra_inventory_drift_make_actual_zero_exit_unknown(self):
        source = self.root / "source"
        source.write_bytes(b"before")
        pin = adapter._pin(source, identity(b"before"))
        run = self.spawn("import time;time.sleep(.2)", [pin])
        if os.name == "nt":
            with self.assertRaises(PermissionError):
                source.write_bytes(b"after!")
            self.assertEqual(run.observe(5)["exitCode"], 0)
            return
        source.write_bytes(b"after!")
        result = run.observe(5)
        self.assertEqual(result["exitCode"], 0)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "source-or-image-drift")
        tree = self.root / "image"
        tree.mkdir()
        (tree / "approved").write_bytes(b"x")
        run = self.spawn("import time;time.sleep(.2)", trees={tree: {"approved"}})
        (tree / "injected").write_bytes(b"x")
        self.assertEqual(run.observe(5)["state"], "unknown")

    def test_real_overflow_is_sticky_unknown_and_never_restarts(self):
        run = self.spawn("import sys;sys.stdout.buffer.write(b'x' * " + str(adapter._MAX_STREAM + 65536) + ");sys.stdout.flush()")
        first = run.observe(5)
        self.assertEqual(first["reason"], "raw-stream-limit")
        original = run.process
        second = run.observe(0.1)
        self.assertIs(run.process, original)
        self.assertEqual(second["state"], "unknown")
        self.assertLessEqual(second["raw"]["stdout"]["sizeBytes"], adapter._MAX_STREAM + 65536)
        self.assertFalse((run.directory / "terminal.json").exists())

    @unittest.skipUnless(os.name == "nt", "actual original-user/installed-MSI checks require owned Windows guest")
    def test_windows_token_reader_does_not_accept_current_foreign_ci_identity(self):
        # Generic Windows CI is not the CP117 original interactive principal.
        with self.assertRaises(adapter.AcceptanceError):
            adapter._native_owner(65535)


if __name__ == "__main__":
    unittest.main()
