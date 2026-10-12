"""Actual guest verifier tests; local interpreter/root seams never invoke Tart."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from agent_tools import macos_fixture_guest_stage as stage

SOURCE = "41ec8c4364af6904dcec07ee2631d2d821910c64"
CORRELATION = "6ec74c1c-ced7-4ff2-b0f5-15eadf7751e9"

class ExplicitVersionTest(unittest.TestCase):
    def pair(self, root):
        paths = {}
        for label, version, data in (("base", "2.2.5", b"inert base"),
                                     ("target", "2.2.6", b"inert target")):
            directory = root / "pair/packages" / label
            directory.mkdir(parents=True)
            path = directory / ("vpn-control-" + version + ".dmg")
            path.write_bytes(data)
            path.chmod(0o644)
            paths[label] = path
        return paths

    def request(self, paths):
        result = {"correlationId": CORRELATION, "sourceSha": SOURCE,
                  "guestRoot": "/Users/admin/macos-parity41ec8c4",
                  "baseVersion": "2.2.5", "targetVersion": "2.2.6"}
        for label, path in paths.items():
            result[label + "Sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            result[label + "SizeBytes"] = path.stat().st_size
        return result

    def guest(self, inputs, local_root, mode="mutate"):
        command = stage._command(inputs, mode)
        # Explicit transport seam: replace only Tart launch/interpreter and root.
        # Run the actual complete guest code and its emitted version/hash argv.
        argv = [sys.executable, "-B", *command[4:]]
        argv[argv.index(mode) + 1] = str(local_root)
        return subprocess.run(argv, capture_output=True, text=True, timeout=5, check=False)

    def test_current_pair_guest_verifier_uses_explicit_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            paths = self.pair(root)
            inputs = self.request(paths)
            result = self.guest(inputs, root)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual({label: {"sha256": inputs[label + "Sha256"],
                                     "sizeBytes": inputs[label + "SizeBytes"], "mode": 0o444}
                              for label in ("base", "target")}, json.loads(result.stdout))
            for path in paths.values():
                self.assertEqual(0o444, path.stat().st_mode & 0o777)

    def test_both_current_hashes_are_verified_before_either_mode_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            paths = self.pair(root)
            inputs = self.request(paths)
            inputs["targetSha256"] = "0" * 64
            result = self.guest(inputs, root)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("fixture digest mismatch", result.stderr)
            for path in paths.values():
                self.assertEqual(0o644, path.stat().st_mode & 0o777)

    def test_strict_versions_refuse_before_transport_or_journal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self.request(self.pair(root))
            cases = [("baseVersion", value) for value in
                     (None, 225, True, "0.2.5", "20.2.5", "2.20.5", "2.2.20",
                      "02.2.5", "2.02.5", "2.2.05", "2.2.5\n", "../2.2.5", "2.2.5;id")]
            cases += [("targetVersion", "2.2.5"), ("targetVersion", "2.2.4")]
            for key, value in cases:
                with self.subTest(key=key, value=value):
                    bad = {**inputs, key: value}
                    with self.assertRaises(ValueError):
                        stage.start(root, bad, runner=lambda *_a, **_k: self.fail("transport ran"))
                    self.assertFalse((root / ".rag_index").exists())
            for key in ("baseVersion", "targetVersion"):
                bad = dict(inputs)
                del bad[key]
                with self.assertRaises(ValueError):
                    stage.start(root, bad, runner=lambda *_a, **_k: self.fail("transport ran"))

    def test_version_order_is_numeric_with_base20_carry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self.request(self.pair(root))
            for base, target in (("2.1.19", "2.2.0"), ("2.19.19", "3.0.0"),
                                 ("2.2.9", "2.2.10")):
                with self.subTest(base=base, target=target):
                    validated = stage._request({**inputs, "baseVersion": base, "targetVersion": target})
                    self.assertEqual(base, validated["baseVersion"])
                    self.assertEqual(target, validated["targetVersion"])

    def test_same_correlation_cannot_relabel_package_versions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self.request(self.pair(root))
            calls = []
            def runner(argv, **kwargs):
                calls.append(argv)
                raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
            self.assertEqual("unknown", stage.start(root, inputs, runner=runner)["state"])
            with self.assertRaisesRegex(ValueError, "bound to different fixture inputs"):
                stage.start(root, {**inputs, "targetVersion": "2.2.7"}, runner=runner)
            self.assertEqual(1, len(calls))
            record = json.loads((root / ".rag_index/macos-fixture-guest-stage" /
                                 (CORRELATION + ".json")).read_text())
            self.assertEqual(inputs, record["request"])
            self.assertFalse(stage.collect(root, {"correlationId": CORRELATION})["replayAllowed"])

    def test_actual_mutation_response_loss_is_not_replayed_and_inspection_recovers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self.request(self.pair(root))
            calls = []
            def runner(argv, **kwargs):
                mode = argv[6]
                calls.append(mode)
                result = self.guest(inputs, root, mode)
                self.assertEqual(0, result.returncode, result.stderr)
                if len(calls) == 1:
                    raise subprocess.TimeoutExpired(argv, kwargs["timeout"])
                return result
            first = stage.start(root, inputs, runner=runner)
            self.assertEqual("unknown", first["state"])
            self.assertEqual(first, stage.start(root, inputs, runner=runner))
            self.assertEqual(["mutate"], calls)
            final = stage.status(root, {"correlationId": CORRELATION}, runner=runner)
            self.assertEqual("complete", final["state"])
            self.assertEqual(["mutate", "inspect"], calls)
            self.assertFalse(final["replayAllowed"])

    def test_guest_rejects_noncanonical_version_argv(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            paths = self.pair(root)
            command = stage._command(self.request(paths), "mutate")
            command[8] = "../2.2.5"
            command[7] = str(root)
            result = subprocess.run([sys.executable, "-B", *command[4:]],
                                    capture_output=True, text=True, timeout=5, check=False)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unsafe fixture version", result.stderr)
            for path in paths.values():
                self.assertEqual(0o644, path.stat().st_mode & 0o777)

    def test_current_target_symlink_and_unsafe_mode_do_not_mutate_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            paths = self.pair(root)
            inputs = self.request(paths)
            paths["target"].chmod(0o666)
            result = self.guest(inputs, root)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("unsafe fixture mode", result.stderr)
            self.assertEqual(0o644, paths["base"].stat().st_mode & 0o777)
            paths["target"].chmod(0o644)
            backing = paths["target"].with_suffix(".inert")
            paths["target"].rename(backing)
            paths["target"].symlink_to(backing.name)
            result = self.guest(inputs, root)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual(0o644, paths["base"].stat().st_mode & 0o777)
            self.assertEqual(0o644, backing.stat().st_mode & 0o777)

    def legacy(self, root, *, immutable=True):
        paths = self.pair(root)
        inputs = self.request(paths)
        del inputs["baseVersion"]
        del inputs["targetVersion"]
        for label, name in (("base", stage.BASE_NAME), ("target", stage.TARGET_NAME)):
            old = paths[label].with_name(name)
            paths[label].rename(old)
            paths[label] = old
            if immutable:
                old.chmod(0o444)
        journal = stage._directory(root) / (CORRELATION + ".json")
        stage._save(journal, {"state": "unknown", "request": inputs, "observation": None})
        return paths, inputs, journal

    def legacy_runner(self, root, calls):
        def runner(argv, **kwargs):
            calls.append(argv)
            self.assertEqual("inspect", argv[6])
            command = [sys.executable, "-B", *argv[4:]]
            command[command.index("inspect") + 1] = str(root)
            return subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        return runner

    def test_legacy_unknown_status_inspects_exact_old_pair_without_relabel_or_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            paths, inputs, journal = self.legacy(root)
            before = {label: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                      for label, path in paths.items()}
            calls = []
            try:
                result = stage.status(root, {"correlationId": CORRELATION},
                                      runner=self.legacy_runner(root, calls))
            except KeyError as error:
                self.fail(f"legacy observer requires invented version fields: {error}")
            self.assertEqual("complete", result["state"])
            self.assertFalse(result["replayAllowed"])
            self.assertEqual(1, len(calls))
            self.assertEqual(inputs, json.loads(journal.read_text())["request"])
            self.assertEqual(before, {label: (path.read_bytes(), path.stat().st_mode, path.stat().st_mtime_ns)
                                     for label, path in paths.items()})
            self.assertEqual(result, stage.collect(root, {"correlationId": CORRELATION}))
            self.assertEqual(result, stage.status(root, {"correlationId": CORRELATION},
                                                 runner=lambda *_a, **_k: self.fail("complete legacy ran")))

    def test_legacy_missing_mismatched_or_writable_pair_stays_unknown_read_only(self):
        for case in ("missing", "digest", "writable"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                paths, inputs, journal = self.legacy(root, immutable=case != "writable")
                if case == "missing":
                    paths["target"].unlink()
                elif case == "digest":
                    paths["target"].chmod(0o644)
                    paths["target"].write_bytes(b"wrong length")
                    paths["target"].chmod(0o444)
                original = journal.read_bytes()
                base_before = (paths["base"].read_bytes(), paths["base"].stat().st_mode)
                calls = []
                result = stage.status(root, {"correlationId": CORRELATION},
                                      runner=self.legacy_runner(root, calls))
                self.assertEqual("unknown", result["state"])
                self.assertFalse(result["ok"])
                self.assertFalse(result["replayAllowed"])
                self.assertEqual(1, len(calls))
                self.assertEqual(original, journal.read_bytes())
                self.assertEqual(base_before, (paths["base"].read_bytes(), paths["base"].stat().st_mode))

    def test_new_legacy_start_and_internal_mutate_are_refused_before_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            inputs = self.request(self.pair(root))
            del inputs["baseVersion"]
            del inputs["targetVersion"]
            with self.assertRaises(ValueError):
                stage.start(root, inputs, runner=lambda *_a, **_k: self.fail("legacy mutation ran"))
            with self.assertRaises(ValueError):
                stage._command(inputs, "mutate")
            self.assertFalse((root / ".rag_index").exists())

    def test_legacy_observer_validates_exact_original_request_before_transport(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            paths, inputs, journal = self.legacy(root)
            cases = [{**inputs, "guestRoot": "/Users/admin/macos-parityfffffff"},
                     {**inputs, "baseSizeBytes": True}, {**inputs, "targetSha256": "INVALID"},
                     {**inputs, "correlationId": "invalid"},
                     {**inputs, "baseVersion": "2.2.5"}, {**inputs, "extra": "path"}]
            for invalid in cases:
                with self.subTest(invalid=invalid):
                    with self.assertRaises(ValueError):
                        stage._command(invalid, "inspect")
            self.assertEqual(inputs, json.loads(journal.read_text())["request"])
