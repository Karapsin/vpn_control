"""The desktop test host job over the scenario host job, against the scenario tests' one fake QGA peer.

No VM, host or guest is contacted: FakeQga answers the publisher, the SYSTEM run and this job's two own
programs, and its system run leaves what the in-guest runner would leave in the operation root. The worker's
own admission and the cleanup program's identity rule are modelled as the guest code states them.
"""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid
import zipfile

from agent_tools import windows_desktop_test as desktop
from agent_tools import windows_desktop_test_guest as guest
from agent_tools import windows_desktop_test_host_job as desktop_job
from agent_tools import windows_scenario_host_job as job
from agent_tools.tests.test_windows_scenario_host_job import (MACHINE, PROFILE, PYTHON_ROOT, USER, FakeQga, FakeRuntime, out_data,
                                                               program_input)

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "c" * 40
# The coordinator's bundle, literally: a test below keeps the two equal.
BUNDLE_FILES = ("agent_tools/windows_scenario_host_job.py", "agent_tools/windows_desktop_test_host_job.py",
                "agent_tools/windows_ordinary_task.py", "agent_tools/windows_ordinary_process_owner.py",
                "agent_tools/windows_ordinary_task_owner.ps1", "agent_tools/windows_artifact_transfer.py",
                "agent_tools/readiness_windows_guest.py", "agent_tools/windows_scenario_publisher.ps1.template",
                "agent_tools/windows_scenario_system_run.ps1.template", "agent_tools/windows_desktop_test_guest.py")


def bundle_files():
    files = {}
    for relative in BUNDLE_FILES:
        files[relative] = (ROOT / relative).read_bytes()
    return files


class DesktopQga(FakeQga):
    """The scenario peer, plus this job's disk and cleanup programs and what the runner leaves behind."""

    def __init__(self):
        super().__init__()
        self.free_bytes = 60 * 1024 ** 3
        self.cleanup_state = "deleted"
        self.runner = "completed"
        self.results_raw = self._results()
        self.identities = {}  # path -> (volume, file index) of the endpoint the publisher created there
        self.cleanup_requests = []
        self.worker_refusal = None

    @staticmethod
    def _results():
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("test-results/TEST-com.example.Alpha.xml", '<testsuite name="com.example.Alpha" tests="1" skipped="0" failures="0" errors="0" time="0.1"><testcase name="a" classname="com.example.Alpha"/></testsuite>')
            archive.writestr("gradle-console.log", "BUILD SUCCESSFUL in 9m\n")
        return buffer.getvalue()

    def _publisher(self, m, pid):
        actors = {"bootstrapOpening": self._actor(pid), "bootstrapClosing": self._actor(pid), "guestBootClosing": True,
                  "bootstrapActorClosing": True}
        if m.get("action") == "desktop-disk":
            reply = {"schemaVersion": 1, "state": "desktop-test-disk-observed", "operationId": m["operationId"], "drive": m["drive"],
                     "freeBytes": self.free_bytes, "totalBytes": 64 * 1024 ** 3, "productOperation": False, **actors}
            return {"exited": True, "exitcode": 0, "out-data": out_data(reply)}
        if m.get("action") == "desktop-cleanup":
            # CLEANUP_TEMPLATE's rule: the file at the path must be the endpoint's (volume and file index), and its
            # size the pin's unless the push never completed (sizeKnown false); an older target always had a size.
            self.cleanup_requests.append([dict(target) for target in m["targets"]])
            rows = []
            for target in m["targets"]:
                path, state = target["path"], self.cleanup_state
                if path not in self.files:
                    state = "absent"
                elif (self.identities.get(path) != (target["volumeSerial"], target["fileIndex"])
                      or (target.get("sizeKnown", True) and len(self.files[path]) != target["sizeBytes"])):
                    state = "not-the-published-file"
                elif state == "deleted":
                    del self.files[path]
                rows.append({"path": path, "state": state})
            reply = {"schemaVersion": 1, "state": "desktop-test-archives-cleaned", "operationId": m["operationId"], "targets": rows,
                     "freeBytes": self.free_bytes, "productOperation": False, **actors}
            return {"exited": True, "exitcode": 0, "out-data": out_data(reply)}
        terminal = super()._publisher(m, pid)
        if m.get("action") == "endpoints" and terminal.get("exitcode") == 0:
            reply = json.loads(gzip.decompress(base64.b64decode(base64.b64decode(terminal["out-data"]))))
            for created in reply["endpoints"]:
                identity = created["filePin"]["nativeIdentity"]
                self.identities[created["filePin"]["path"]] = (identity["volumeSerial"], identity["fileIndex"])
        return terminal

    def _system_run(self, m, pid):
        bootstrap = json.loads(self.files[m["taskRequestPin"]["path"]])
        worker = json.loads(self.files[bootstrap["bootstrap"]["workerRequestPath"]])
        # windows_ordinary_process_owner.Owner admits its request only if that request pins the interpreter and the
        # worker's own source (owner-interpreter-source-pins); otherwise it exits 1 before any child, as the owner does.
        pinned = {pin["path"].casefold() for pin in worker["filePins"]}
        if not {bootstrap["bootstrap"]["pythonPath"].casefold(), bootstrap["bootstrap"]["workerPath"].casefold()} <= pinned:
            self.worker_refusal, self.task_exit = "owner-interpreter-source-pins", 1
        terminal = super()._system_run(m, pid)
        runner_request = json.loads(self.files[worker["qualificationArgv"][6]])
        root = runner_request["operationRoot"]
        if self.worker_refusal is not None or self.runner == "missing" or self.run_state is not None:
            return terminal
        results = self.results_raw
        digest = hashlib.sha256(results).hexdigest() if self.runner != "bad-hash" else "0" * 64
        failed = self.runner == "failed"
        summary = {"schema": guest.SUMMARY_SCHEMA, "schemaVersion": 1, "operationId": runner_request["operationId"],
                   "sourceCommit": runner_request["sourceCommit"], "outcome": "failed" if failed else "completed",
                   "failedStage": "gradle" if failed else None, "failure": "gradle-processes-survived" if failed else None,
                   "stages": [{"name": name, "outcome": "passed", "seconds": 1.0, "code": None} for name in guest.STAGES],
                   "gradle": {"exitCode": 0, "deadline": False, "seconds": 540.0}, "jdkRelease": {"JAVA_VERSION": "17.0.21"},
                   "results": {"name": guest.RESULTS_LEAF, "bytes": len(results), "sha256": digest, "xmlFiles": 1},
                   "archives": {}, "freeBytesBefore": 1, "freeBytesAfter": 2, "productProcessesBefore": [], "productProcessesAfter": [],
                   "productState": {}, "profileEntries": {"added": [], "removed": []}, "seconds": 600.0,
                   "workRoot": {"created": True, "deleted": True, "error": None}}
        self.files[root + "\\" + guest.SUMMARY_LEAF] = json.dumps(summary).encode()
        self.files[root + "\\" + guest.RESULTS_LEAF] = results
        self.files[root + "\\" + guest.PROGRESS_LEAF] = json.dumps({"operationId": runner_request["operationId"], "stage": "finished",
                                                                     "elapsedSeconds": 600}).encode()
        return terminal


@unittest.skipUnless(os.name == "posix", "the host job runs on a POSIX VM host")
class DesktopJobTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.vm = self.work / "vm"
        self.vm.mkdir(mode=0o700)
        self.artifacts = self.work / "artifacts"
        self.artifacts.mkdir(mode=0o700)
        self.qga = DesktopQga()
        self.rt = FakeRuntime(self.vm, self.qga)
        self.files = bundle_files()
        self.packages = {}
        for role in desktop_job.ARCHIVE_ROLES:
            raw = (role + "-archive ").encode() * (40000 if role == "dependencies" else 3000)
            digest = hashlib.sha256(raw).hexdigest()
            path = self.artifacts / digest
            path.write_bytes(raw)
            path.chmod(0o600)
            self.packages[role] = {"sha256": digest, "bytes": len(raw)}

    def plan(self):
        operation = str(uuid.uuid4())
        desktop_test = {"sourceCommit": COMMIT, "jdk": {"root": desktop.JDK["root"], "javaVersion": desktop.JDK["javaVersion"]},
                        "gradle": {"version": "8.10.2", "root": "gradle-8.10.2", "wrapperHash": desktop.GRADLE["wrapperHash"],
                                   "distributionUrl": desktop.GRADLE["url"]},
                        "gradleDeadlineSeconds": desktop.GRADLE_DEADLINE_SECONDS, "minimumFreeBytes": desktop.MINIMUM_FREE_BYTES}
        return json.loads(json.dumps({
            "schemaVersion": 1, "operationId": operation, "scenarioId": desktop.SCENARIO_ID, "machine": MACHINE, "bundleHash": "b" * 64,
            "user": USER, "dataDirectory": str(self.work / "home/.cache/vpn-control-windows-scenarios" / MACHINE / operation),
            "row": desktop.ROW, "files": {path: {"sha256": hashlib.sha256(raw).hexdigest(), "sizeBytes": len(raw)} for path, raw in self.files.items()},
            "stopAfter": None, "artifactDirectory": str(self.artifacts), "packages": self.packages, "product": None, "prior": {},
            "desktopTest": desktop_test}))

    def run_job(self):
        plan = self.plan()
        self.addCleanup(self.forget, plan["operationId"])
        code = desktop_job.run_job(self.rt, plan, self.files)
        path = Path(plan["dataDirectory"]) / "scenario-receipt.json"
        return plan, code, json.loads(path.read_bytes()) if path.exists() else None

    @staticmethod
    def forget(operation):
        import sys
        for name in [name for name in sys.modules if name.endswith(operation.replace("-", ""))]:
            del sys.modules[name]

    def fence(self, plan):
        return self.vm / ("direct-guest-" + plan["operationId"] + ".terminal.json")

    @staticmethod
    def workspace(plan):
        return "C:\\ProgramData\\VpnControlOrdinaryTask-" + plan["operationId"]

    def archives_left(self, plan):
        return sorted(path for path in self.qga.files if path.startswith(self.workspace(plan) + "\\desktop-test-"))

    def test_a_complete_run_publishes_runs_reads_back_and_cleans_in_order(self):
        plan, code, receipt = self.run_job()
        self.assertEqual(0, code, receipt["failure"])
        kinds = self.qga.kinds()
        self.assertEqual(["context", "desktop-disk", "initialize", "list-tree", "endpoints", "verify", "read-pins"], kinds[:7])
        self.assertEqual(["system-run", "evidence-zip", "desktop-cleanup"], kinds[-3:])
        self.assertEqual(("passed", "receipt", "vpn-control.windows-desktop-test.receipt"), (receipt["result"], receipt["stage"], receipt["schema"]))
        block = receipt["desktopTest"]
        self.assertEqual((COMMIT, "completed", 0, False), (block["sourceCommit"], block["runnerOutcome"], block["gradleExitCode"], block["gradleDeadline"]))
        self.assertEqual({"bytes": len(self.qga.results_raw), "sha256": hashlib.sha256(self.qga.results_raw).hexdigest(), "xmlFiles": 1}, block["results"])
        self.assertEqual("complete", block["cleanup"]["state"])
        self.assertEqual({role: package["sha256"] for role, package in self.packages.items()}, block["archives"])
        self.assertEqual(self.qga.results_raw, (Path(plan["dataDirectory"]) / guest.RESULTS_LEAF).read_bytes())
        self.assertEqual({"exited": True, "exitcode": 0}, json.loads(self.fence(plan).read_bytes()))
        self.assertLessEqual(len(json.dumps(receipt)), job.RECEIPT_BYTES)

    def test_the_archives_go_in_larger_chunks_and_are_deleted_by_their_pinned_identity(self):
        plan, code, _ = self.run_job()
        self.assertEqual(0, code)
        self.assertIn(desktop_job.ARCHIVE_CHUNK_BYTES, self.qga.write_sizes)
        self.assertLessEqual(max(self.qga.write_sizes), desktop_job.ARCHIVE_CHUNK_BYTES)
        cleanup = program_input(dict(self.qga.programs)["desktop-cleanup"])
        workspace = "C:\\ProgramData\\VpnControlOrdinaryTask-" + plan["operationId"]
        self.assertEqual([workspace + "\\" + guest.ARCHIVE_LEAVES[role] for role in desktop_job.ARCHIVE_ROLES],
                         [target["path"] for target in cleanup["targets"]])
        self.assertTrue(all(set(target) == {"path", "volumeSerial", "fileIndex", "sizeBytes", "sizeKnown"} and target["sizeKnown"] is True
                            for target in cleanup["targets"]))
        self.assertFalse(any(path.startswith(workspace + "\\desktop-test-") for path in self.qga.files))

    def test_the_worker_request_pins_its_interpreter_its_own_source_and_every_input_it_reads(self):
        plan, code, receipt = self.run_job()
        self.assertEqual((0, None), (code, self.qga.worker_refusal), receipt["failure"])
        seen = self.qga.requests_seen[-1]
        worker, bootstrap = seen["worker"], seen["bootstrap"]["bootstrap"]
        workspace = self.workspace(plan)
        root = PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + plan["operationId"]
        python = {PYTHON_ROOT + "\\" + name.replace("/", "\\") for name in self.qga.python_tree[0]}
        self.assertEqual((PYTHON_ROOT + "\\python.exe", workspace + "\\windows_ordinary_process_owner.py"),
                         (bootstrap["pythonPath"], bootstrap["workerPath"]))
        self.assertEqual(sorted({job.POWERSHELL_PATH, *python, bootstrap["workerPath"], workspace + "\\windows_desktop_test_guest.py",
                                 *(workspace + "\\" + guest.ARCHIVE_LEAVES[role] for role in desktop_job.ARCHIVE_ROLES),
                                 root + "\\" + guest.REQUEST_LEAF}),
                         sorted(pin["path"] for pin in worker["filePins"]), "the worker request's whole file closure")

    def test_the_worker_runs_only_the_pinned_runner_with_its_pinned_request(self):
        plan, code, _ = self.run_job()
        self.assertEqual(0, code)
        seen = self.qga.requests_seen[-1]
        worker, bootstrap = seen["worker"], seen["bootstrap"]
        workspace = "C:\\ProgramData\\VpnControlOrdinaryTask-" + plan["operationId"]
        root = PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + plan["operationId"]
        request_path = root + "\\" + guest.REQUEST_LEAF
        raw = self.qga.files[request_path]
        self.assertEqual(("qualification", 0), (worker["action"], worker["expectedExitCode"]))
        self.assertEqual([PYTHON_ROOT + "\\python.exe", "-I", "-S", "-B", workspace + "\\windows_desktop_test_guest.py", "--request",
                          request_path, "--request-sha256", hashlib.sha256(raw).hexdigest()], worker["qualificationArgv"])
        runner = guest.validate_request(json.loads(raw), windows=True)
        self.assertEqual((PROFILE + "\\vcdt-" + plan["operationId"][:8], COMMIT), (runner["workRoot"], runner["sourceCommit"]))
        pinned = {pin["path"] for pin in worker["filePins"]}
        self.assertTrue({request_path, workspace + "\\windows_desktop_test_guest.py",
                         *(workspace + "\\" + guest.ARCHIVE_LEAVES[role] for role in desktop_job.ARCHIVE_ROLES)} <= pinned)
        self.assertEqual("python-worker", bootstrap["bootstrap"]["mode"])
        self.assertFalse(any(pin["path"].startswith(workspace + "\\desktop-test-") for pin in bootstrap["filePins"]),
                         "the archives are pinned by the worker only")

    def test_a_failed_runner_stage_is_a_known_failure_with_its_results_kept_and_the_archives_cleaned(self):
        self.qga.runner = "failed"
        plan, code, receipt = self.run_job()
        self.assertEqual(1, code)
        self.assertEqual(("results", "desktop_runner:gradle:gradle-processes-survived"), (receipt["stage"], receipt["failure"]))
        self.assertEqual("complete", receipt["desktopTest"]["cleanup"]["state"])
        self.assertIsNotNone(receipt["desktopTest"]["results"])
        self.assertTrue(self.fence(plan).exists())

    def test_a_missing_summary_is_a_known_failure_and_the_evidence_and_cleanup_still_run(self):
        self.qga.runner = "missing"
        _, code, receipt = self.run_job()
        self.assertEqual((1, "desktop_runner_summary_missing"), (code, receipt["failure"]))
        self.assertEqual(["system-run", "evidence-zip", "desktop-cleanup"], self.qga.kinds()[-3:])

    def test_results_that_differ_from_the_summary_digest_are_refused(self):
        self.qga.runner = "bad-hash"
        _, code, receipt = self.run_job()
        self.assertEqual((1, "desktop_results_hash"), (code, receipt["failure"]))
        self.assertIsNone(receipt["desktopTest"]["results"])

    def test_a_parked_owner_is_unknown_and_nothing_is_cleaned_or_closed(self):
        self.qga.run_state = "owner-parked"
        plan, code, receipt = self.run_job()
        self.assertEqual(3, code)
        self.assertNotIn("desktop-cleanup", self.qga.kinds())
        self.assertEqual("not-started", receipt["desktopTest"]["cleanup"]["state"])
        self.assertFalse(self.fence(plan).exists(), "an open outcome never closes the fence")

    def test_a_fixture_without_the_scenario_python_refuses_before_any_archive_is_pushed(self):
        self.qga.trees = {}
        plan, code, receipt = self.run_job()
        self.assertEqual((1, "publish", "python_tree_absent"), (code, receipt["stage"], receipt["failure"]))
        self.assertEqual(["context", "desktop-disk", "initialize", "list-tree"], self.qga.kinds()[:4])
        self.assertNotIn("endpoints", self.qga.kinds())
        self.assertEqual(([], []), (self.qga.write_sizes, self.archives_left(plan)), "nothing was pushed, so nothing is left")

    def test_a_python_tree_past_the_worker_pin_bound_refuses_before_any_archive_is_pushed(self):
        files, _ = self.qga.python_tree
        self.qga.trees[PYTHON_ROOT] = (files, ["d%04d" % number for number in range(job.DIRECTORY_PIN_LIMIT)])
        plan, code, receipt = self.run_job()
        self.assertEqual((1, "publish", "worker_pin_bound"), (code, receipt["stage"], receipt["failure"]))
        self.assertNotIn("endpoints", self.qga.kinds())
        self.assertEqual(([], []), (self.qga.write_sizes, self.archives_left(plan)))

    def test_a_run_refused_before_launch_still_deletes_the_pushed_archives(self):
        self.qga.run_state = "refused-before-launch"
        plan, code, receipt = self.run_job()
        self.assertEqual((1, "run", "refused_before_launch:RUN_SYNTHETIC_CODE"), (code, receipt["stage"], receipt["failure"]))
        self.assertEqual(["system-run", "evidence-zip", "desktop-cleanup"], self.qga.kinds()[-3:])
        self.assertEqual(("complete", ["deleted"] * 4), (receipt["desktopTest"]["cleanup"]["state"], receipt["desktopTest"]["cleanup"]["archives"]))
        self.assertTrue(all(target["sizeKnown"] for target in self.qga.cleanup_requests[-1]), "every archive was verified")
        self.assertEqual([], self.archives_left(plan))
        self.assertTrue(self.fence(plan).exists(), "a known failure still closes the fence")

    def test_a_push_lost_inside_an_archive_deletes_every_archive_endpoint_by_its_identity(self):
        # The guest files go first in 32 KiB chunks; the second archive write is the JDK's first chunk.
        guest_chunks = sum(-(-len(self.files[relative]) // job.CHUNK_BYTES) for relative, _, _ in desktop.ROW["guestFiles"])
        self.qga.lose = lambda command, kind, ordinal: (ValueError("lost") if command == "guest-file-write" and ordinal == guest_chunks + 2
                                                        else None)
        plan, code, receipt = self.run_job()
        self.assertEqual((1, "publish", "guest_file_push_lost"), (code, receipt["stage"], receipt["failure"]))
        self.assertIn("desktop-cleanup", self.qga.kinds(), "a known failure after the endpoints were made still cleans")
        targets = self.qga.cleanup_requests[-1]
        self.assertEqual([self.workspace(plan) + "\\" + guest.ARCHIVE_LEAVES[role] for role in desktop_job.ARCHIVE_ROLES],
                         [target["path"] for target in targets])
        self.assertEqual([False] * 4, [target["sizeKnown"] for target in targets], "no archive was verified: identity alone")
        self.assertEqual(("complete", ["deleted"] * 4), (receipt["desktopTest"]["cleanup"]["state"], receipt["desktopTest"]["cleanup"]["archives"]))
        self.assertEqual([], self.archives_left(plan))

    def test_too_little_guest_disk_refuses_before_anything_is_published(self):
        self.qga.free_bytes = 1024 ** 3
        _, code, receipt = self.run_job()
        self.assertEqual((1, "publish", "desktop_disk_space_insufficient"), (code, receipt["stage"], receipt["failure"]))
        self.assertEqual(["context", "desktop-disk"], self.qga.kinds())
        self.assertEqual(sum(package["bytes"] for package in self.packages.values()) + desktop.MINIMUM_FREE_BYTES,
                         receipt["desktopTest"]["disk"]["neededBytes"])

    def test_an_archive_still_held_fails_cleanup_but_keeps_the_results(self):
        self.qga.cleanup_state = "held"
        _, code, receipt = self.run_job()
        self.assertEqual((1, "cleanup", "desktop_cleanup_incomplete"), (code, receipt["stage"], receipt["failure"]))
        self.assertEqual(["held"] * 4, receipt["desktopTest"]["cleanup"]["archives"])
        self.assertIsNotNone(receipt["desktopTest"]["results"])

    def test_a_lost_cleanup_reply_is_unknown_with_the_results_still_in_its_receipt(self):
        self.qga.lose = lambda command, kind, ordinal: ValueError("lost") if command == "guest-exec" and kind == "desktop-cleanup" else None
        plan, code, receipt = self.run_job()
        self.assertEqual((3, "cleanup"), (code, receipt["stage"]))
        self.assertEqual("unknown", receipt["desktopTest"]["cleanup"]["state"])
        self.assertIsNotNone(receipt["desktopTest"]["results"])
        self.assertFalse(self.fence(plan).exists())

    def test_the_runner_progress_is_kept_for_observers(self):
        plan, code, _ = self.run_job()
        self.assertEqual(0, code)
        progress = json.loads((Path(plan["dataDirectory"]) / "desktop-progress.json").read_bytes())
        self.assertEqual(("finished", 600), (progress["stage"], progress["elapsedSeconds"]))


class RenderedProgramTests(unittest.TestCase):
    def test_these_tests_run_the_coordinators_whole_bundle(self):
        self.assertEqual(desktop.BUNDLE_FILES, BUNDLE_FILES)

    def test_the_rendered_program_runs_this_job_over_the_scenario_job(self):
        base = (ROOT / "agent_tools/windows_scenario_host_job.py").read_text()
        mine = (ROOT / "agent_tools/windows_desktop_test_host_job.py").read_text()
        namespace = {"__name__": "rendered"}
        exec(compile(base + "\n" + mine, "rendered", "exec"), namespace)
        self.assertIs(namespace["Job"], namespace["DesktopTestJob"].__mro__[1])
        self.assertEqual(("DesktopTestJob", "rendered"), (namespace["run_job"].__code__.co_names[0], namespace["run_job"].__code__.co_filename))

    def test_the_cleanup_and_disk_programs_keep_the_boot_bound_output_contract(self):
        for template in (desktop_job.DISK_TEMPLATE, desktop_job.CLEANUP_TEMPLATE):
            first = template.splitlines()[0]
            self.assertIn("$ProgressPreference='SilentlyContinue'", first)
            self.assertEqual(1, template.count("[Console]::WriteLine(($r|ConvertTo-Json -Depth 8 -Compress))"))
            self.assertEqual(1, template.count("@@INPUT@@"))
            template.encode("ascii")


if __name__ == "__main__":
    unittest.main()
