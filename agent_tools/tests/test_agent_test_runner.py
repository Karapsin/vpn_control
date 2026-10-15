"""Actual inert Python workers; never shell, native hosts, Gradle or live VPN."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

if os.environ.get("AGENT_TEST_RUNNER_SOURCE"):
    spec = importlib.util.spec_from_file_location("owned_test_runner", os.environ["AGENT_TEST_RUNNER_SOURCE"])
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
else:
    from agent_tools import agent_test_runner as runner


_PRIVATE_PARENT_UMASK_CHILD = "import errno\nimport hashlib\nimport json\nimport os\nfrom pathlib import Path\nimport stat\nimport sys\nimport unittest\n\nif len(sys.argv) != 6 or sys.argv[5] not in ('077', '022'):\n    raise ValueError('exact private-parent source arguments required')\nheld = []\nsource_closing = False\nresult = None\n\ndef generation(info):\n    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,\n            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)\n\ndef read_held(fd):\n    os.lseek(fd, 0, os.SEEK_SET)\n    raw = bytearray()\n    while len(raw) <= 1048576:\n        block = os.read(fd, min(65536, 1048577 - len(raw)))\n        if not block:\n            return bytes(raw)\n        raw.extend(block)\n    raise ValueError('owned source bound')\n\ndef verify(row):\n    path, fd, initial, raw = row\n    if path.resolve() != path or generation(os.stat(path, follow_symlinks=False)) != initial:\n        raise ValueError('named owned source changed')\n    if generation(os.fstat(fd)) != initial or read_held(fd) != raw or generation(os.fstat(fd)) != initial:\n        raise ValueError('held owned source changed')\n    if generation(os.stat(path, follow_symlinks=False)) != initial:\n        raise ValueError('named owned source changed after read')\n\ndef hold(name, expected):\n    path = Path(name)\n    if not path.is_absolute() or path.resolve() != path:\n        raise ValueError('physical source path required')\n    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0))\n    row = [path, fd, None, None]\n    held.append(row)\n    info = os.fstat(fd)\n    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:\n        raise ValueError('owned regular single-link source required')\n    row[2] = generation(info)\n    row[3] = read_held(fd)\n    if hashlib.sha256(row[3]).hexdigest() != expected:\n        raise ValueError('exact owned source digest required')\n    verify(row)\n    return row\n\ntry:\n    test_source = hold(sys.argv[1], sys.argv[2])\n    runner_source = hold(sys.argv[3], sys.argv[4])\n    os.environ['AGENT_TEST_RUNNER_SOURCE'] = str(runner_source[0])\n    os.umask(int(sys.argv[5], 8))\n    namespace = {'__name__': 'owned_private_parent_case', '__file__': str(test_source[0]), '__package__': None}\n    exec(compile(test_source[3], str(test_source[0]), 'exec', dont_inherit=True), namespace)\n    actual = namespace['runner']\n    if (Path(actual.__file__).resolve() != runner_source[0]\n            or actual._RUNNER_SOURCE_PATH.resolve() != runner_source[0]\n            or actual._RUNNER_SOURCE_SHA256 != sys.argv[4]\n            or actual._RUNNER_SOURCE_BYTES != runner_source[3]\n            or not actual._RUNNER_IMPLEMENTATION_MATCH):\n        raise ValueError('actual held runner implementation required')\n    case = namespace['AgentTestRunnerTests']('test_private_parent_and_symlink_rejected_before_dispatch')\n    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(unittest.TestSuite([case]))\nfinally:\n    try:\n        for row in held:\n            if row[2] is not None and row[3] is not None:\n                verify(row)\n        source_closing = len(held) == 2 and all(row[2] is not None and row[3] is not None for row in held)\n    finally:\n        closed = True\n        for row in held:\n            try:\n                os.close(row[1])\n            except OSError:\n                closed = False\n            try:\n                os.fstat(row[1])\n            except OSError as error:\n                closed = closed and error.errno == errno.EBADF\n            else:\n                closed = False\n        print(json.dumps({'umask': sys.argv[5], 'testsRun': result.testsRun if result else 0,\n                          'failures': len(result.failures) if result else 0,\n                          'errors': len(result.errors) if result else 0,\n                          'skipped': len(result.skipped) if result else 0,\n                          'sourceClosing': source_closing, 'sourceFDsClosed': closed}), flush=True)\nif not source_closing or not closed or result is None:\n    raise RuntimeError('owned child did not close completely')\nraise SystemExit(0 if result.wasSuccessful() else 1)\n"


class AgentTestRunnerTests(unittest.TestCase):
    def setUp(self):
        portable = {"test_public_projection_excludes_private_skip_reason_and_subtest_values",
                    "test_explicit_serial_stdout_supports_exact_test_id_without_private_capability",
                    "test_serial_failure_exit_and_standard_diagnostic_preserved",
                    "test_serial_custom_id_is_not_a_public_timing_identity",
                    "test_serial_public_identity_is_bound_before_class_metadata_mutation",
                    "test_timing_never_calls_custom_id_outside_normal_unittest_success",
                    "test_serial_exact_selection_never_invokes_generic_callable",
                    "test_serial_scope_rejects_arbitrary_script_and_private_writer_stays_closed"}
        if self._testMethodName not in portable and not (os.name == "posix" and hasattr(os, "O_NOFOLLOW")):
            self.skipTest("private POSIX retention")
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        os.chmod(self.root, 0o700)
        package = self.root / "agent_tools" / "tests"
        package.mkdir(parents=True)
        (package.parent / "__init__.py").write_text("")
        (package / "__init__.py").write_text("")
        self.plan = {"schemaVersion": 1, "sourceFingerprint": "a" * 64, "modules": []}
        self.sequence = 0

    def module(self, suffix, body, *, safe=False):
        name = "agent_tools.tests.test_" + suffix
        path = self.root / (name.replace(".", "/") + ".py")
        path.write_text(body)
        self.plan["modules"].append(name)
        if safe:
            self.safe[name] = {path.relative_to(self.root).as_posix(): runner.digest(path)}
        return name

    @contextlib.contextmanager
    def environment(self):
        previous = Path.cwd()
        os.chdir(self.root)
        self.safe = {}
        try:
            with mock.patch.dict(runner.ISOLATED_SOURCES, {}, clear=True):
                yield
        finally:
            os.chdir(previous)

    def invoke(self, **changes):
        self.sequence += 1
        directory = self.root / ("run%d" % self.sequence)
        with mock.patch.dict(runner.ISOLATED_SOURCES, self.safe, clear=True):
            report = runner.run_plan({**self.plan, **changes}, directory, stream=io.StringIO())
        return report, directory

    def sleeping(self, seconds=0.12):
        return "import time,unittest\nclass C(unittest.TestCase):\n def test_one(self): time.sleep(%r)\n" % seconds

    def test_frozen_script_packages_forbid_canonical_namespace_fallback(self):
        sources = {}
        for package in ("scripts", "scripts/integration"):
            directory = self.root / package
            directory.mkdir(parents=True, exist_ok=True)
            helper = directory / "reviewed_helper.py"
            helper.write_text("VALUE='frozen'\n")
            sources[helper.relative_to(self.root).as_posix()] = runner.digest(helper)
            (directory / "unreviewed_helper.py").write_text("VALUE='canonical-only'\n")
        leaf = self.root / "freeze"
        leaf.mkdir(mode=0o700)
        context = runner.source_context(self.root, leaf, sources)
        body = """import importlib,json,sys
from pathlib import Path
context,canonical=sys.argv[1:]
sys.path[:0]=[context,canonical]
escaped=[]
for package in ('scripts','scripts.integration'):
 reviewed=importlib.import_module(package+'.reviewed_helper')
 assert Path(reviewed.__file__).is_relative_to(Path(context))
 try: foreign=importlib.import_module(package+'.unreviewed_helper')
 except ModuleNotFoundError: pass
 else: escaped.append({'module':foreign.__name__,'path':foreign.__file__})
print(json.dumps(escaped))
"""
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("DYLD_INSERT_LIBRARIES", None)
        child = subprocess.run([sys.executable, "-I", "-B", "-c", body, str(context), str(self.root)],
                               cwd=self.root, env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(0, child.returncode, child.stderr)
        self.assertEqual([], json.loads(child.stdout), "canonical script imports escaped frozen closure")
        self.assertTrue(runner.sources_match(context, sources))

    def test_frozen_pinned_empty_package_marker_preserved_without_collision(self):
        marker = self.root / "agent_tools/tests/__init__.py"
        helper = self.root / "agent_tools/tests/frozen_helper.py"
        helper.write_text("VALUE='frozen'\n")
        sources = {path.relative_to(self.root).as_posix(): runner.digest(path) for path in (marker, helper)}
        leaf = self.root / "freeze"
        leaf.mkdir(mode=0o700)
        context = runner.source_context(self.root, leaf, sources)
        frozen_marker = context / "agent_tools/tests/__init__.py"
        self.assertEqual(marker.read_bytes(), frozen_marker.read_bytes())
        self.assertEqual(0o400, frozen_marker.stat().st_mode & 0o777)
        self.assertTrue(runner.sources_match(context, sources))
        body = "import sys;sys.path.insert(0,sys.argv[1]);from agent_tools.tests import frozen_helper;assert frozen_helper.VALUE=='frozen';print(frozen_helper.__file__)"
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("DYLD_INSERT_LIBRARIES", None)
        child = subprocess.run([sys.executable, "-I", "-B", "-c", body, str(context)],
                               cwd=self.root, env=env, capture_output=True, text=True, timeout=5)
        self.assertEqual(0, child.returncode, child.stderr)
        self.assertTrue(Path(child.stdout.strip()).is_relative_to(context))

    def test_actual_elapsed_timing_success_skip_failure_error_subtest_and_expected(self):
        with self.environment():
            self.module("outcomes", '''import time,unittest
class Cases(unittest.TestCase):
 def test_a_success(self): time.sleep(0.08)
 @unittest.skip('declared inert capability')
 def test_b_skip(self): pass
 def test_c_failure(self): self.fail('inert assertion')
 def test_d_error(self): raise RuntimeError('inert error')
 @unittest.expectedFailure
 def test_e_expected(self): self.fail('expected')
 @unittest.expectedFailure
 def test_f_unexpected(self): pass
 def test_g_subtests(self):
  for i in range(2):
   with self.subTest(i=i): self.assertEqual(i,2)
''')
            report, directory = self.invoke()
            self.assertEqual("failed", report["state"])
            self.assertEqual({"testsRun": 7, "failures": 3, "errors": 1, "skipped": 1,
                              "expectedFailures": 1, "unexpectedSuccesses": 1}, report["counts"])
            rows = {x["testId"].rsplit(".", 1)[-1]: x for x in report["timings"]}
            self.assertGreaterEqual(rows["test_a_success"]["elapsedSeconds"], 0.07)
            self.assertEqual("skipped", rows["test_b_skip"]["outcome"])
            self.assertEqual("declared inert capability", rows["test_b_skip"]["skipReason"])
            self.assertEqual("failure", rows["test_g_subtests"]["outcome"])
            self.assertEqual("unexpectedSuccess", rows["test_f_unexpected"]["outcome"])
            self.assertEqual(14, len((directory / "worker-0000" / "timings.jsonl").read_text().splitlines()))
            self.assertEqual(0o600, (directory / "report.json").stat().st_mode & 0o777)
            self.assertTrue(all(x["reaped"] for x in report["workers"]))

    def test_setup_and_teardown_class_failures_and_import_error_counted(self):
        with self.environment():
            self.module("fixtures", '''import time,unittest
class BrokenSetup(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  time.sleep(0.05)
  raise RuntimeError('class setup')
 def test_never(self): pass
class BrokenTeardown(unittest.TestCase):
 def test_one(self): pass
 @classmethod
 def tearDownClass(cls): raise RuntimeError('class teardown')
''')
            self.module("import_failure", "raise RuntimeError('inert import failure')\n")
            report, directory = self.invoke()
            self.assertEqual("failed", report["state"])
            self.assertEqual(2, report["counts"]["testsRun"])
            self.assertEqual(3, report["counts"]["errors"])
            fixture = next(x for x in report["timings"] if "setUpClass" in x["testId"])
            self.assertTrue(fixture["fixture"])
            self.assertGreaterEqual(fixture["elapsedSeconds"], 0.04)

    def test_module_fixture_errors_are_terminal_errors_even_zero_tests_run(self):
        with self.environment():
            self.module("module_fixture", "import time,unittest\ndef setUpModule():\n time.sleep(0.05)\n raise RuntimeError('module setup')\nclass C(unittest.TestCase):\n def test_never(self): pass\n")
            report, _ = self.invoke()
            self.assertEqual(0, report["counts"]["testsRun"])
            self.assertEqual(1, report["counts"]["errors"])
            self.assertFalse(report["successful"])
            self.assertGreaterEqual(report["timings"][0]["elapsedSeconds"], 0.04)

    def test_reviewed_workers_really_overlap_and_unknown_dependencies_serialize(self):
        with self.environment():
            self.module("safe_a", self.sleeping(0.18), safe=True)
            self.module("safe_b", self.sleeping(0.18), safe=True)
            self.module("unknown_a", self.sleeping(0.04))
            self.module("unknown_b", self.sleeping(0.04))
            report, directory = self.invoke()
            self.assertTrue(report["successful"])
            self.assertEqual(4, report["counts"]["testsRun"])
            a, b, serial = sorted(report["workers"], key=lambda x: x["startedMonotonic"])
            self.assertLess(max(a["startedMonotonic"], b["startedMonotonic"]), min(a["endedMonotonic"], b["endedMonotonic"]))
            # Actual test intervals, not merely simultaneous process launch.
            safe_rows = [x for x in report["timings"] if ".test_safe_" in x["testId"]]
            self.assertLess(max(x["startedMonotonic"] for x in safe_rows), min(x["endedMonotonic"] for x in safe_rows))
            self.assertGreaterEqual(serial["startedMonotonic"], max(a["endedMonotonic"], b["endedMonotonic"]))
            self.assertFalse(serial["isolated"])
            self.assertEqual(2, len(serial["modules"]))
            self.assertEqual(3, len({x["pid"] for x in report["workers"]}))

    def test_changed_actual_codec_dependency_disables_parallel_classification(self):
        repository = Path.cwd()
        name = "agent_tools.tests.test_linux_gui_capsule_codec"
        paths = ["agent_tools/tests/test_linux_gui_capsule_codec.py",
                 "scripts/integration/linux_owner_lifecycle_scenario.py",
                 "agent_tools/tests/fixtures/linux_gui_source_custody/codec-driver.before.source",
                 "agent_tools/tests/fixtures/linux_gui_source_custody/normal-capsule.source"]
        for relative in paths:
            destination = self.root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((repository / relative).read_bytes())
        self.assertEqual([(True, [name])], runner.worker_groups(self.root, [name]))
        # Change the actual executed method prefix while leaving the test bytes
        # unchanged. The inert assignment establishes the source decision cause;
        # no mutated producer code is executed by this classification regression.
        source = self.root / paths[1]
        body = source.read_text()
        before = next(line for line in body.splitlines(keepends=True) if line.strip().startswith("def python_command("))
        source.write_text(body.replace(before, before + "        unreviewed_prefix = True\n", 1))
        self.assertEqual([(False, [name])], runner.worker_groups(self.root, [name]))

    def test_unknown_and_changed_reviewed_source_stay_serial(self):
        with self.environment():
            name = self.module("was_safe", self.sleeping(), safe=True)
            self.module("unknown", self.sleeping())
            path = self.root / (name.replace(".", "/") + ".py")
            path.write_text(path.read_text() + "\n# changed after isolation review\n")
            report, _ = self.invoke()
            self.assertTrue(report["successful"])
            self.assertEqual(1, len(report["workers"]))
            self.assertFalse(report["workers"][0]["isolated"])

    def test_max_workers_one_serializes_reviewed_groups(self):
        with self.environment():
            self.module("a", self.sleeping(), safe=True)
            self.module("b", self.sleeping(), safe=True)
            report, _ = self.invoke(maxWorkers=1)
            first, second = report["workers"]
            self.assertLessEqual(first["endedMonotonic"], second["startedMonotonic"])

    def test_child_has_unique_temporary_runtime_and_lock_roots(self):
        with self.environment():
            body = '''import os,socket,tempfile,unittest
from pathlib import Path
class C(unittest.TestCase):
 def test_roots(self):
  roots=[Path(os.environ[k]).resolve() for k in ('TMPDIR','VPN_CONTROL_TEST_RUNTIME_ROOT','VPN_CONTROL_TEST_LOCK_ROOT')]
  self.assertEqual(3,len(set(roots)))
  self.assertEqual(roots[0],Path(tempfile.gettempdir()).resolve())
  for path in roots:
   self.assertFalse(path.is_relative_to(Path.cwd().resolve()),'worker fixtures must be outside checkout')
   self.assertEqual(0o700,path.stat().st_mode & 0o777)
   self.assertEqual(os.getuid(),path.stat().st_uid)
   self.assertEqual(os.getgid(),path.stat().st_gid)
   (path/'owned-marker').write_text('inert')
  with tempfile.TemporaryDirectory(prefix='vcss-') as raw:
   for relative in ('m','secondary/vm-r-01234567/qmp.sock','new-private-vm/guest/tpm/swtpm.sock'):
    endpoint=Path(raw)/relative
    parent=Path(raw)
    for part in Path(relative).parts[:-1]:
     parent=parent/part;parent.mkdir(mode=0o700,exist_ok=True)
    print('ACTUAL_NESTED_SOCKET_BYTES',relative,len(os.fsencode(endpoint)),flush=True)
    with socket.socket(socket.AF_UNIX) as sock: sock.bind(str(endpoint))
'''
            self.module("a", body, safe=True)
            self.module("b", body, safe=True)
            inherited = self.root / "inherited-checkout-temp"
            inherited.mkdir(mode=0o700)
            with mock.patch.dict(os.environ, {key: str(inherited) for key in ("TMPDIR", "TMP", "TEMP")}):
                report, directory = self.invoke()
            diagnostics = "".join(path.read_text() for path in directory.glob("worker-*/stdout.txt"))
            diagnostics += "".join(path.read_text() for path in directory.glob("worker-*/stderr.txt"))
            self.assertTrue(report["successful"], diagnostics)
            roots = []
            for record in report["workers"]:
                worker = directory / ("worker-%04d" % len(roots))
                receipt = json.loads((worker / "fixture-root.json").read_text())
                root = Path(receipt["path"])
                roots.append(root)
                self.assertEqual(self.plan["sourceFingerprint"], receipt["sourceFingerprint"])
                self.assertEqual(record["modules"], receipt["modules"])
                self.assertEqual(runner.digest(Path(runner.__file__)), receipt["runnerSha256"])
                self.assertEqual(record["fixtureRootGeneration"], receipt["generation"])
                self.assertEqual(str(root), record["fixtureRoot"])
                self.assertTrue(record["reaped"] and record["sessionAbsent"] and record["fixtureRootRemoved"])
                self.assertFalse(root.exists())
            self.assertEqual(2, len(set(roots)))
            self.assertTrue(inherited.is_dir())

    def test_child_short_root_keeps_actual_component_receipt_within_snapshot_limit(self):
        from agent_tools.tests import test_android_installer_component_bundle as fixture
        repository = Path(fixture.__file__).resolve().parents[2]
        with self.environment():
            body = ("import sys,unittest\nfrom pathlib import Path\n"
                    "import agent_tools,agent_tools.tests\n"
                    "agent_tools.__path__.append(%r)\nagent_tools.tests.__path__.append(%r)\n"
                    "sys.path.insert(0,%r)\n" % (str(repository / "agent_tools"),
                                               str(repository / "agent_tools/tests"), str(repository))) + '''from agent_tools.tests import test_android_installer_component_bundle as fixtures
from agent_tools import android_installer_direct_transport as direct
class C(unittest.TestCase):
 def test_actual_receipt(self):
  fixture=fixtures.BundleTests();fixture.setUp()
  try:
   raw=direct.canonical(fixture.receipt)
   print('ACTUAL_COMPONENT_RECEIPT_BYTES',len(raw),flush=True)
   direct.write_once(fixture.root,'component-receipt.json',raw)
   actual,pin=direct.snapshot(fixture.root/'component-receipt.json',65536,True)
   self.assertEqual(raw,actual)
  finally: fixture.tearDown()
'''
            self.module("receipt_limit", body)
            directory = self.root / ("long-report-" + "x" * 140)
            report = runner.run_plan(self.plan, directory, stream=io.StringIO())
            diagnostics = "".join(path.read_text() for path in directory.glob("worker-*/stdout.txt"))
            diagnostics += "".join(path.read_text() for path in directory.glob("worker-*/stderr.txt"))
            self.assertTrue(report["successful"], diagnostics)
            self.assertTrue(all(item["reaped"] and item["sessionAbsent"] for item in report["workers"]))

    def test_cleanup_retains_independent_replacement_after_generation_check(self):
        owned = self.root / "reserved"
        replacement = self.root / "independent"
        retained = self.root / "retained-original"
        for path in (owned, replacement):
            path.mkdir(mode=0o700)
        (owned / "original-marker").write_text("original")
        (replacement / "independent-marker").write_text("independent")
        generation = runner.fixture_generation(owned)
        original = runner.fixture_generation
        exchanged = []
        def exchange_after_snapshot(path):
            observed = original(path)
            if Path(path) == owned and not exchanged:
                owned.rename(retained)
                replacement.rename(owned)
                exchanged.append(True)
            return observed
        with mock.patch.object(runner, "fixture_generation", side_effect=exchange_after_snapshot):
            removed = runner.cleanup_fixture_root(owned, generation)
        self.assertEqual([True], exchanged)
        self.assertFalse(removed)
        self.assertEqual("original", (retained / "original-marker").read_text())
        markers = list(self.root.rglob("independent-marker"))
        self.assertEqual(1, len(markers))
        self.assertEqual("independent", markers[0].read_text())

    def test_abrupt_worker_exit_preserves_partial_journal_and_never_success(self):
        with self.environment():
            self.module("abrupt", "import os,unittest\nclass C(unittest.TestCase):\n def test_a(self): pass\n def test_b(self): os._exit(7)\n")
            report, directory = self.invoke()
            self.assertEqual("incomplete", report["state"])
            self.assertFalse(report["successful"])
            self.assertEqual(7, report["workers"][0]["returncode"])
            self.assertTrue(report["workers"][0]["reaped"])
            rows = [json.loads(x) for x in (directory / "worker-0000" / "timings.jsonl").read_text().splitlines()]
            self.assertEqual(["started", "finished", "started"], [x["event"] for x in rows])
            self.assertFalse(report["replayAllowed"])
            self.assertEqual(1, report["workers"][0]["partialTimingCount"])
            self.assertEqual(1, len(report["timings"]))
            self.assertTrue(report["timings"][0]["partialWorker"])

    def test_cancellation_reaps_same_worker_preserves_journal_and_refuses_replay(self):
        with self.environment():
            self.module("cancelled", self.sleeping(30))
            plan = self.root / "input.json"
            plan.write_text(json.dumps(self.plan))
            directory = self.root / "cancelled-run"
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            env.pop("DYLD_INSERT_LIBRARIES", None)
            process = subprocess.Popen([sys.executable, "-B", runner.__file__, "--plan-file", str(plan), "--report-dir", str(directory)],
                                       cwd=self.root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 5
                journal = directory / "worker-0000" / "timings.jsonl"
                while not (journal.exists() and journal.stat().st_size) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(journal.exists() and journal.stat().st_size)
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=6)
                self.assertEqual(130, process.returncode)
                report = json.loads((directory / "report.json").read_text())
                self.assertEqual("cancelled", report["state"])
                self.assertFalse(report["successful"])
                self.assertTrue(report["workers"][0]["reaped"])
                with self.assertRaises(ProcessLookupError): os.kill(report["workers"][0]["pid"], 0)
                before = (directory / "plan.json").read_bytes()
                with self.assertRaises(FileExistsError): self.invoke_existing(directory)
                self.assertEqual(before, (directory / "plan.json").read_bytes())
            finally:
                if process.poll() is None:
                    process.kill(); process.communicate()

    def invoke_existing(self, directory):
        return runner.run_plan(self.plan, directory, stream=io.StringIO())

    def test_changed_source_after_worker_cannot_claim_success(self):
        with self.environment():
            self.module("self_mutation", "import unittest\nfrom pathlib import Path\nclass C(unittest.TestCase):\n def test_one(self):\n  p=Path(__file__);p.write_text(p.read_text()+'\\n# drift\\n')\n")
            report, _ = self.invoke()
            self.assertEqual("incomplete", report["state"])
            self.assertFalse(report["successful"])

    def test_plan_rejects_commands_duplicate_modules_and_excess_workers(self):
        good = {**self.plan, "modules": ["agent_tools.tests.test_example"]}
        for changes in ({"modules": ["os"]}, {"modules": good["modules"] * 2}, {"command": "anything"},
                        {"maxWorkers": 3}, {"maxWorkers": True}, {"schemaVersion": True}, {"sourceFingerprint": "unbound"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                runner.validate_plan({**good, **changes})

    def test_public_projection_excludes_private_skip_reason_and_subtest_values(self):
        stream = io.StringIO()
        journal = runner.PublicTimingJournal(stream)
        event = {"event": "finished", "testId": "agent_tools.tests.test_public.C.test_one",
                 "elapsedSeconds": 0.125, "outcome": "skipped", "skipReason": "PRIVATE_SENTINEL",
                 "exception": "PRIVATE_SENTINEL", "path": "PRIVATE_SENTINEL"}
        journal.write(json.dumps(event))
        journal.write(json.dumps({**event, "testId": event["testId"] + " (value='PRIVATE_SENTINEL')"}))
        self.assertNotIn("PRIVATE_SENTINEL", stream.getvalue())
        records = [json.loads(line.split(" ", 1)[1]) for line in stream.getvalue().splitlines()]
        self.assertEqual({"schemaVersion", "testId", "elapsedSeconds", "outcome", "fixture"}, set(records[0]))
        self.assertEqual("unclassified-test", records[1]["testId"])

    def test_explicit_serial_stdout_supports_exact_test_id_without_private_capability(self):
        with self.environment():
            name = self.module("public", "import time,unittest\nclass C(unittest.TestCase):\n def test_one(self): time.sleep(0.04)\n @unittest.skip('PRIVATE_REASON')\n def test_skip(self): pass\n")
            script = "import importlib.util,os,sys;spec=importlib.util.spec_from_file_location('runner',sys.argv[1]);runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner);os.__dict__.pop('O_NOFOLLOW',None);sys.exit(runner.main(sys.argv[2:]))"
            result = subprocess.run([sys.executable, "-B", "-c", script, runner.__file__, "--serial-stdout", "--source-fingerprint", "a" * 64,
                                     "--test-id", name + ".C.test_one", "--test-id", name + ".C.test_skip"],
                                    cwd=self.root, capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("PRIVATE_REASON", result.stdout)
            records = [json.loads(line.split(" ", 1)[1]) for line in result.stdout.splitlines() if line.startswith("AGENT_TEST_TIMING ")]
            self.assertEqual(2, len(records))
            self.assertGreaterEqual(records[0]["elapsedSeconds"], 0.03)
            summary = json.loads(next(line.split(" ", 1)[1] for line in result.stdout.splitlines() if line.startswith("AGENT_TEST_SUMMARY ")))
            self.assertEqual(2, summary["counts"]["testsRun"])
            self.assertEqual(1, summary["counts"]["skipped"])
            self.assertEqual([], list(self.root.glob("*.json")))
            self.assertEqual([], list(self.root.rglob("timings.jsonl")))

    def test_serial_failure_exit_and_standard_diagnostic_preserved(self):
        with self.environment():
            name = self.module("public_failure", "import unittest\nclass C(unittest.TestCase):\n def test_one(self): self.fail('normal unittest diagnostic')\n")
            result = subprocess.run([sys.executable, "-B", runner.__file__, "--serial-stdout", "--source-fingerprint", "a" * 64,
                                     "--module", name], cwd=self.root, capture_output=True, text=True, timeout=5)
            self.assertEqual(1, result.returncode)
            self.assertIn("normal unittest diagnostic", result.stderr)
            self.assertNotIn("normal unittest diagnostic", result.stdout)
            self.assertIn('"outcome": "failure"', result.stdout)

    def test_serial_custom_id_is_not_a_public_timing_identity(self):
        with self.environment():
            name = self.module("custom_id", "import unittest\nclass C(unittest.TestCase):\n def id(self): return 'agent_tools.tests.test_custom_id.C.PRIVATE_SENTINEL'\n def test_one(self): pass\n")
            result = subprocess.run([sys.executable, "-B", runner.__file__, "--serial-stdout", "--source-fingerprint", "a" * 64,
                                     "--test-id", name + ".C.test_one"], cwd=self.root, capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("PRIVATE_SENTINEL", result.stdout)
            self.assertIn(name + ".C.test_one", result.stdout)

    def test_serial_public_identity_is_bound_before_class_metadata_mutation(self):
        with self.environment():
            name = self.module("metadata", "import unittest\nclass C(unittest.TestCase):\n def test_one(self):\n  type(self).__module__='agent_tools.tests.PRIVATE_SENTINEL'\n  type(self).__qualname__='PRIVATE_SENTINEL'\n  self._testMethodName='PRIVATE_SENTINEL'\n")
            result = subprocess.run([sys.executable, "-B", runner.__file__, "--serial-stdout", "--source-fingerprint", "a" * 64,
                                     "--test-id", name + ".C.test_one"], cwd=self.root, capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertNotIn("PRIVATE_SENTINEL", result.stdout)
            self.assertIn(name + ".C.test_one", result.stdout)

    def test_timing_never_calls_custom_id_outside_normal_unittest_success(self):
        with self.environment():
            name = self.module("id_effect", "import unittest\nfrom pathlib import Path\nclass C(unittest.TestCase):\n def id(self):\n  Path('id-ran.marker').write_text('owned inert side effect')\n  return 'agent_tools.tests.test_id_effect.C.test_one'\n def test_one(self): pass\n")
            result = subprocess.run([sys.executable, "-B", runner.__file__, "--serial-stdout", "--source-fingerprint", "a" * 64,
                                     "--test-id", name + ".C.test_one"], cwd=self.root, capture_output=True, text=True, timeout=5)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse((self.root / "id-ran.marker").exists())
            self.assertIn(name + ".C.test_one", result.stdout)
            if os.name == "posix" and hasattr(os, "O_NOFOLLOW"):
                report, _ = self.invoke()
                self.assertTrue(report["successful"])
                self.assertFalse((self.root / "id-ran.marker").exists())
                self.assertEqual(name + ".C.test_one", report["timings"][0]["testId"])

    def test_serial_exact_selection_never_invokes_generic_callable(self):
        with self.environment():
            name = self.module("factory", "import unittest\nfrom pathlib import Path\nclass C(unittest.TestCase):\n def test_one(self): pass\ndef launch_helper():\n Path('factory-ran.marker').write_text('owned inert effect')\n return unittest.TestSuite([C('test_one')])\n")
            result = subprocess.run([sys.executable, "-B", runner.__file__, "--serial-stdout", "--source-fingerprint", "a" * 64,
                                     "--test-id", name + ".launch_helper"], cwd=self.root, capture_output=True, text=True, timeout=5)
            self.assertFalse((self.root / "factory-ran.marker").exists())
            self.assertNotEqual(0, result.returncode)

    def test_worker_revalidates_frozen_sources_before_loading_test(self):
        with self.environment():
            self.module("preload", "import unittest\nclass C(unittest.TestCase):\n def test_one(self): pass\n", safe=True)
            original = runner.subprocess.Popen
            def change_snapshot(argv, **kwargs):
                context = Path(argv[argv.index("--worker-dir") + 1]) / "sources"
                if context.exists():
                    source = context / "agent_tools/tests/test_preload.py"
                    source.chmod(0o600)
                    source.write_text(source.read_text() + "\n# changed snapshot before worker load\n")
                return original(argv, **kwargs)
            with mock.patch.object(runner.subprocess, "Popen", side_effect=change_snapshot):
                report, directory = self.invoke()
            self.assertEqual("incomplete", report["state"])
            self.assertEqual(0, report["counts"]["testsRun"])
            self.assertFalse(report["successful"])
            self.assertTrue(report["workers"][0]["reaped"])
            self.assertTrue(report["workers"][0]["sessionAbsent"])

    def test_bound_helper_drift_during_worker_blocks_final_success(self):
        with self.environment():
            self.module("helper_drift", "import unittest\nfrom pathlib import Path\nclass C(unittest.TestCase):\n def test_one(self): Path('agent_tools/pure_helper.py').write_text('VALUE=2\\n')\n", safe=True)
            helper = self.root / "agent_tools/pure_helper.py"
            helper.write_text("VALUE=1\n")
            self.safe[self.plan["modules"][0]][helper.relative_to(self.root).as_posix()] = runner.digest(helper)
            report, _ = self.invoke()
            self.assertFalse(report["successful"])
            self.assertEqual("incomplete", report["state"])
            self.assertTrue(all(x["reaped"] and x["sessionAbsent"] for x in report["workers"]))

    def test_serial_scope_rejects_arbitrary_script_and_private_writer_stays_closed(self):
        for name in ("scripts.test_arbitrary", "os.system", "agent_tools.tests.test_one.C.test_a.extra"):
            with self.assertRaises(ValueError): runner.serial_stdout([name], "a" * 64)
        self.assertTrue(runner.SERIAL_ID.fullmatch("scripts.test_windows_fixture_stage_acl.WindowsFixtureCopiedPackageReadOnlyTests"))
        with mock.patch.object(runner.os, "name", "nt"), self.assertRaises(ValueError):
            runner.private_directory(self.root / "refused")
        self.assertFalse((self.root / "refused").exists())

    def test_private_parent_rejection_under_private_and_standard_umasks(self):
        # Execute the exact existing guard case; changing this process's umask is unnecessary.
        test_source = Path(__file__).resolve()
        runner_source = Path(runner.__file__).resolve()
        self.assertEqual(runner_source, runner._RUNNER_SOURCE_PATH.resolve())
        self.assertTrue(runner._RUNNER_IMPLEMENTATION_MATCH)
        test_sha = hashlib.sha256(test_source.read_bytes()).hexdigest()
        runner_sha = hashlib.sha256(runner_source.read_bytes()).hexdigest()
        self.assertEqual(runner._RUNNER_SOURCE_SHA256, runner_sha)
        programme = self.root / "private_parent_umask_child.py"
        descriptor = os.open(programme, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_PRIVATE_PARENT_UMASK_CHILD.encode("utf-8"))
        env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
        env.pop("DYLD_INSERT_LIBRARIES", None)
        for mask in ("077", "022"):
            with self.subTest(umask=mask):
                cache = self.root / ("umask-" + mask + "-cache")
                cache.mkdir(mode=0o700)
                self.assertEqual(0o700, cache.stat().st_mode & 0o777)
                argv = [sys.executable, "-I", "-B", "-X", "pycache_prefix=" + str(cache),
                        str(programme), str(test_source), test_sha, str(runner_source), runner_sha, mask]
                self.assertLessEqual(sum(len(os.fsencode(arg)) + 1 for arg in argv), 60000)
                child = subprocess.run(argv, cwd=self.root, env=env, capture_output=True, text=True, timeout=15)
                for suffix, text in (("stdout", child.stdout), ("stderr", child.stderr)):
                    descriptor = os.open(self.root / ("umask-" + mask + "." + suffix),
                                         os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(descriptor, "wb") as stream:
                        stream.write(text.encode("utf-8"))
                sys.stdout.write(child.stdout)
                sys.stderr.write(child.stderr)
                self.assertEqual(0, child.returncode, child.stdout + child.stderr)
                self.assertEqual([], list(cache.iterdir()), "isolated child wrote bytecode despite -B")
                self.assertEqual({"umask": mask, "testsRun": 1, "failures": 0, "errors": 0, "skipped": 0,
                                  "sourceClosing": True, "sourceFDsClosed": True}, json.loads(child.stdout))

    def test_private_parent_and_symlink_rejected_before_dispatch(self):
        with self.environment():
            self.module("a", self.sleeping())
            foreign = self.root / "foreign"
            foreign.mkdir(mode=0o755)
            foreign.chmod(0o755)
            self.assertEqual(0o755, foreign.stat().st_mode & 0o777)
            with self.assertRaises(ValueError): runner.run_plan(self.plan, foreign / "result")
            link = self.root / "link"
            link.symlink_to(foreign, target_is_directory=True)
            with self.assertRaises(ValueError): runner.run_plan(self.plan, link / "result")
            self.assertFalse((foreign / "result").exists())


if __name__ == "__main__":
    unittest.main()
