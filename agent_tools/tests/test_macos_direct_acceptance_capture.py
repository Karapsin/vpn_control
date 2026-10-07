"""Real harmless child/FD evidence tests; no guest/product or SecurityAgent use."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from agent_tools import macos_direct_acceptance_capture as capture
from scripts.integration.macos_rollback_fixture import MacBoundary, FixtureError
from scripts.integration.macos_rollback_fixture import (
    RollbackFixture, FixtureSpec, ReceiptAuthority, Identity, Step,
)
from scripts.macos_fixture_processes import ProcessIdentity


CONTROLLER = "e82989bf-8ad3-4893-af88-8258c58e3a99"
OTHER = "4a2eeaf2-15c0-4460-bf2b-698439fef25e"
JOB = "cbe97943-aa6b-4661-a392-cd4d17869f2d"
CORRELATION = "81c0b5bd-7aec-42cc-8c66-1c4b33ba4f4e"


@unittest.skipIf(os.name == "nt", "POSIX executable/FD pipe fixture")
class DirectCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.app = self.root / "fixture.app"
        (self.app / "Contents/MacOS").mkdir(parents=True)
        self.launcher = self.app / "Contents/MacOS/vpn-control"
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.evidence = self.root / "evidence"
        self.evidence.mkdir(mode=0o700)
        self.boundary = None

    def tearDown(self):
        if self.boundary:
            self.boundary.close()
        self.temp.cleanup()

    def script(self, body):
        self.launcher.write_text(f"#!{sys.executable}\n" + body)
        self.launcher.chmod(0o700)

    def create(self):
        self.boundary = capture.DurableMacBoundary(self.app, self.state,
            self.evidence, CORRELATION, CONTROLLER)
        return self.boundary

    def public(self, *args):
        return self.boundary.public(self.app, self.state, *args)

    def terminal(self):
        record = self.boundary.records[-1]
        raw = record.manifest.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), record.manifest_sha256)
        value = json.loads(raw)
        for stream in ("stdout", "stderr"):
            reconstructed = b""
            for part in value["parts"][stream]:
                path = self.evidence / part["name"]
                b = path.read_bytes()
                self.assertEqual(hashlib.sha256(b).hexdigest(), part["sha256"])
                self.assertEqual(len(b), part["size"])
                self.assertEqual(capture._generation(path.stat()), tuple(part["generation"]))
                reconstructed += b
            self.assertEqual(reconstructed, getattr(record, stream))
        return value

    def test_actual_old_nonzero_boundary_discards_raw_new_retains_before_exception(self):
        self.script("import os\nos.write(1,b'original-public-output')\nos.write(2,b'original-private-error')\nraise SystemExit(7)\n")
        # Actual unmodified producer boundary, real child. No native launcher.
        with self.assertRaises(FixtureError):
            MacBoundary().public(self.app, self.state, "status")
        self.assertEqual(list(self.evidence.iterdir()), [])
        self.create()
        with self.assertRaisesRegex(FixtureError, "command_unknown"):
            self.public("status")
        value = self.terminal()
        self.assertEqual(value["returncode"], 7)
        self.assertEqual(self.boundary.records[0].stderr, b"original-private-error")
        self.assertTrue(value["stdoutEof"] and value["stderrEof"])
        self.assertFalse(value["jobCleanupProven"])

    def test_actual_public_constructor_and_parser_raw_is_durable_before_decode(self):
        self.script(f"import json\nprint(json.dumps({{'ok':True,'controllerId':'{CONTROLLER}','data':{{}}}}))\n")
        self.create()
        loads = json.loads
        def observed(raw, *args, **kwargs):
            self.assertTrue((self.evidence / "0000-status-raw-terminal.json").is_file())
            return loads(raw, *args, **kwargs)
        with patch.object(capture.json, "loads", observed):
            self.assertTrue(self.public("status")["ok"])
        self.terminal()

    def test_real_malformed_child_retained_then_parser_refuses(self):
        self.script("import os\nos.write(1,b'not-json\\xff')\nos.write(2,b'warning')\n")
        self.create()
        with self.assertRaisesRegex(FixtureError, "public_json"):
            self.public("updates", "status")
        self.terminal()
        self.assertEqual(self.boundary.records[0].stdout, b"not-json\xff")
        self.assertTrue(self.boundary.sticky_unknown)

    def test_real_timeout_retains_prefix_without_claiming_job_cancelled(self):
        self.script("import os,time\nos.write(1,b'before-timeout')\nos.write(2,b'stderr-before-timeout')\ntime.sleep(5)\n")
        self.create()
        with patch.object(capture, "TIMEOUT", 0.15), self.assertRaises(FixtureError):
            self.public("status")
        value = self.terminal()
        self.assertEqual(value["failure"], "timeout")
        self.assertEqual(self.boundary.records[0].stdout, b"before-timeout")
        self.assertFalse(value["jobReplayAllowed"])
        self.assertFalse(value["stdoutEof"])

    def test_real_bounded_dual_stream_cap_retains_prefix(self):
        self.script("import os\nfor x in range(200):\n os.write(1,b'x'*8192)\n os.write(2,b'y'*8192)\n")
        self.create()
        with patch.object(capture, "CAP", 32768), self.assertRaises(FixtureError):
            self.public("status")
        value = self.terminal()
        self.assertEqual(value["failure"], "output-cap")
        self.assertEqual(value["stdoutSize"] + value["stderrSize"], 32768)

    def test_actual_install_once_and_readonly_observation_after_unknown(self):
        self.script("import os\nos.write(1,b'broken')\n")
        self.create()
        with self.assertRaises(FixtureError):
            self.public("--controller-id", CONTROLLER, "--async", "updates", "install")
        with self.assertRaisesRegex(FixtureError, "no_replay"):
            self.public("--controller-id", CONTROLLER, "--async", "updates", "install")
        with self.assertRaisesRegex(FixtureError, "public_json"):
            self.public("--controller-id", CONTROLLER, "operations", "status", JOB)
        self.assertEqual(len(self.boundary.records), 2)
        self.terminal()

    def test_foreign_controller_path_and_effect_argv_refuse_before_spawn(self):
        self.script("raise SystemExit(0)\n")
        self.create()
        for args in [("--controller-id", OTHER, "--async", "updates", "install"), ("on",), ("quit",)]:
            with self.subTest(args=args), patch.object(capture.subprocess, "Popen") as spawn:
                with self.assertRaises(FixtureError):
                    self.public(*args)
                spawn.assert_not_called()
        with self.assertRaises(FixtureError):
            self.boundary.public(self.app, self.root / "foreign", "status")

    def test_actual_source_and_named_directory_drift_refuse_before_spawn(self):
        self.script("print('{}')\n")
        self.create()
        self.launcher.write_text("foreign")
        with patch.object(capture.subprocess, "Popen") as spawn, self.assertRaisesRegex(FixtureError, "launcher_changed"):
            self.public("status")
        spawn.assert_not_called()

    def test_actual_named_evidence_symlink_drift_refuses(self):
        self.script("print('{}')\n")
        self.create()
        self.evidence.rename(self.root / "saved")
        self.evidence.symlink_to(self.root / "saved", target_is_directory=True)
        with patch.object(capture.subprocess, "Popen") as spawn, self.assertRaises((OSError, FixtureError)):
            self.public("status")
        spawn.assert_not_called()

    def test_late_raw_mutation_during_source_hash_refuses_before_parser(self):
        self.script(f"import json\nprint(json.dumps({{'controllerId':'{CONTROLLER}'}}))\n")
        self.create()
        original = self.boundary._launcher_guard
        calls = 0
        def late_mutation():
            nonlocal calls
            calls += 1
            original()
            if calls == 3:
                (self.evidence / "0000-status-stdout-0000.raw").write_bytes(b"foreign")
        with patch.object(self.boundary, "_launcher_guard", late_mutation):
            with self.assertRaisesRegex(FixtureError,"closing_unknown"):
                self.public("status")
        self.assertTrue(self.boundary.sticky_unknown)

    def test_actual_final_directory_stat_raw_overwrite_refuses_before_parser(self):
        self.script("import json\nprint(json.dumps({'controllerId':" + repr(CONTROLLER) + "}))\n")
        boundary = self.create()
        original_stat = capture.os.stat
        mutations = []
        def mutate_at_final_directory(path, *args, **kwargs):
            observed = original_stat(path, *args, **kwargs)
            frames = []
            frame = sys._getframe()
            while frame:
                frames.append(frame.f_code.co_name)
                frame = frame.f_back
            if (not mutations and path == self.evidence and "generation_guard" in frames
                    and any(name.endswith(".raw") for _, name, _, _ in boundary.evidence.leaves)):
                name = next(name for _, name, _, _ in boundary.evidence.leaves if name.endswith(".raw"))
                raw_path = self.evidence / name
                before = raw_path.read_bytes()
                with raw_path.open("r+b") as stream:
                    stream.write(bytes([before[0] ^ 1]) + before[1:])
                    stream.flush()
                    os.fsync(stream.fileno())
                mutations.append(name)
            return observed
        with patch.object(capture.os, "stat", side_effect=mutate_at_final_directory):
            with self.assertRaisesRegex(FixtureError, "closing_unknown"):
                self.public("status")
        self.assertEqual(len(mutations), 1)
        self.assertTrue(boundary.sticky_unknown)
        self.assertEqual(len(boundary.records), 1)
        self.assertNotEqual((self.evidence / mutations[0]).read_bytes(), boundary.records[0].stdout)
        with patch.object(capture.subprocess, "Popen") as spawn:
            with self.assertRaises(FixtureError):
                self.public("updates", "download")
            spawn.assert_not_called()

    def test_actual_parser_final_evidence_stat_launcher_overwrite_refuses(self):
        self.script("import json\nprint(json.dumps({'controllerId':" + repr(CONTROLLER) + "}))\n")
        boundary = self.create()
        original_stat = capture.os.stat
        mutations = []
        def mutate_at_final_directory(path, *args, **kwargs):
            observed = original_stat(path, *args, **kwargs)
            frame = sys._getframe()
            frames = []
            while frame:
                frames.append(frame.f_code.co_name)
                frame = frame.f_back
            if (not mutations and path == self.evidence and "generation_guard" in frames
                    and boundary.records):
                with self.launcher.open("r+b") as stream:
                    stream.seek(-1, os.SEEK_END)
                    stream.write(b" ")
                    stream.flush()
                    os.fsync(stream.fileno())
                mutations.append(True)
            return observed
        with patch.object(capture.os, "stat", side_effect=mutate_at_final_directory):
            with self.assertRaisesRegex(FixtureError, "closing_unknown"):
                self.public("status")
        self.assertEqual(len(mutations), 1)
        self.assertTrue(boundary.sticky_unknown)

    def test_actual_launcher_final_directory_stat_overwrite_refuses(self):
        self.script("print('{}')\n")
        boundary = self.create()
        original_stat = capture.os.stat
        mutations = []
        def mutate_at_directory(path, *args, **kwargs):
            observed = original_stat(path, *args, **kwargs)
            if path == self.evidence and not mutations:
                with self.launcher.open("r+b") as stream:
                    stream.seek(-1, os.SEEK_END)
                    stream.write(b" ")
                    stream.flush()
                    os.fsync(stream.fileno())
                mutations.append(True)
            return observed
        with patch.object(capture.os, "stat", side_effect=mutate_at_directory):
            with self.assertRaisesRegex(FixtureError, "launcher_changed"):
                boundary._launcher_guard()
        self.assertEqual(len(mutations), 1)

    def test_durable_failed_install_fence_survives_second_instance(self):
        self.script("print('broken')\n")
        self.create()
        with self.assertRaises(FixtureError):
            self.public("--controller-id", CONTROLLER, "--async", "updates", "install")
        self.boundary.close()
        self.boundary = None
        with self.assertRaisesRegex(FixtureError,"evidence_not_empty"):
            self.create()

    def test_source_parent_alias_refuses_before_child(self):
        self.script("print('{}')\n")
        self.create()
        directory = self.app / "Contents/MacOS"
        directory.rename(self.app / "Contents/original")
        directory.symlink_to(self.app / "Contents/original",target_is_directory=True)
        with patch.object(capture.subprocess,"Popen") as spawn, self.assertRaises(FixtureError):
            self.public("status")
        spawn.assert_not_called()

    def test_actual_intent_write_replacement_never_executes_foreign_child(self):
        self.script("print('{}')\n")
        self.create()
        original = self.boundary.evidence.write
        marker = self.root / "foreign-executed"
        def replace_after_intent(name, raw):
            record = original(name, raw)
            if name.endswith("-intent.json"):
                self.script("from pathlib import Path\nPath(" + repr(str(marker)) +
                            ").write_text('foreign')\nprint('{}')\n")
            return record
        with patch.object(self.boundary.evidence, "write", replace_after_intent):
            with self.assertRaises(FixtureError):
                self.public("updates", "download")
        self.assertFalse(marker.exists(), "a changed launcher actually executed before refusal")

    def test_actual_unlinked_intent_refuses_before_real_child_release(self):
        marker = self.root / "original-effect"
        self.script("from pathlib import Path\nPath(" + repr(str(marker)) +
                    ").write_text('executed')\nprint('{}')\n")
        boundary = self.create()
        original = boundary.evidence.write
        def unlink_intent(name, raw):
            record = original(name, raw)
            if name.endswith("-intent.json"):
                (self.evidence / name).unlink()
            return record
        with patch.object(boundary.evidence, "write", unlink_intent):
            with self.assertRaises(FixtureError):
                self.public("updates", "download")
        self.assertFalse(marker.exists(), "a command actually ran without its named intent")
        self.assertTrue(boundary.sticky_unknown)

    def test_intent_mutation_during_last_source_body_read_refuses_before_spawn(self):
        marker = self.root / "original-effect"
        self.script("from pathlib import Path\nPath(" + repr(str(marker)) +
                    ").write_text('executed')\nprint('{}')\n")
        boundary = self.create()
        original = boundary._launcher_guard
        calls = 0
        def mutate_after_body():
            nonlocal calls
            calls += 1
            original()
            if calls == 2:
                (self.evidence / "0000-updates-download-intent.json").chmod(0o644)
        with patch.object(boundary, "_launcher_guard", mutate_after_body):
            with self.assertRaisesRegex(FixtureError, "record_changed"):
                self.public("updates", "download")
        self.assertFalse(marker.exists())
        self.assertTrue(boundary.sticky_unknown)

    def test_actual_postspawn_journal_failure_is_sticky_and_preserves_primary(self):
        self.script(f"import json\nprint(json.dumps({{'controllerId':'{CONTROLLER}'}}))\n")
        boundary = self.create()
        original = boundary.evidence.write
        def fail_child_journal(name, raw):
            if name.endswith("-child.json"):
                self.evidence.chmod(0o600)
            return original(name, raw)
        with patch.object(boundary.evidence, "write", fail_child_journal):
            with self.assertRaisesRegex(FixtureError, "direct_capture_directory_changed"):
                self.public("updates", "download")
        self.evidence.chmod(0o700)
        self.assertTrue(boundary.sticky_unknown)
        with patch.object(capture.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(FixtureError, "unknown_effect"):
                self.public("updates", "check")
            spawn.assert_not_called()

    def test_actual_terminal_journal_failure_retains_partial_and_blocks_effects(self):
        self.script(f"import json\nprint(json.dumps({{'controllerId':'{CONTROLLER}'}}))\n")
        boundary = self.create()
        original = boundary.evidence.write
        primary = FixtureError("fixture_terminal_write_failed")
        def fail_terminal(name, raw):
            if name.endswith("-raw-terminal.json"):
                raise primary
            return original(name, raw)
        with patch.object(boundary.evidence, "write", fail_terminal):
            with self.assertRaises(FixtureError) as raised:
                self.public("updates", "download")
        self.assertIs(raised.exception, primary)
        self.assertTrue(boundary.sticky_unknown)
        unknown = json.loads((self.evidence / "0000-capture-unknown.json").read_bytes())
        self.assertEqual(unknown["failure"], "capture-or-journal-unknown")
        self.assertFalse(unknown["jobReplayAllowed"])
        raw = b"".join((self.evidence / row["name"]).read_bytes()
                       for row in unknown["parts"]["stdout"])
        self.assertEqual(json.loads(raw)["controllerId"], CONTROLLER)
        with patch.object(capture.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(FixtureError, "unknown_effect"):
                self.public("updates", "check")
            spawn.assert_not_called()

    def test_whole_unchanged_rollback_public_capture_then_return_observation(self):
        # Real OS child + actual entire RollbackFixture.run. Signature, guest
        # process/receipt and immutable flag observations are explicit inert
        # fixture seams, never asserted to be authoritative native facts.
        operation = OTHER
        self.script(f'''import json,sys
controller={CONTROLLER!r}; job={JOB!r}; operation={operation!r}
tail=sys.argv[4:]
if tail==['updates','status']:
 value={{'ok':True,'final':True,'code':'OK','controllerId':controller,
  'data':{{'phase':'ready','installations':[{{'jobId':job,'phase':'failed','code':'PERSISTENCE_FAILED','final':True,'installed':False}}]}}}}
elif tail==['--controller-id',controller,'--async','updates','install']:
 value={{'ok':True,'code':'ACCEPTED','final':False,'operationId':operation,'controllerId':controller,'data':{{'handoffReady':False}}}}
elif tail==['--controller-id',controller,'operations','status',operation]:
 value={{'ok':True,'operationId':operation,'controllerId':controller,'data':{{'jobId':job,'handoffReady':True}}}}
else: raise SystemExit(41)
print(json.dumps(value))
''')
        base_package = self.root / "base.dmg"
        target_package = self.root / "target.dmg"
        base_package.write_bytes(b"fixture-base")
        target_package.write_bytes(b"fixture-target")
        plain = MacBoundary()
        base_identity = plain.identity(self.app)
        candidate_identity = Identity(10, 30, "c"*64)
        test = self
        class InertGuestBoundary(capture.DurableMacBoundary):
            owner_exited = False
            unlocked = False
            armed = False
            def verify_signature(self, app): pass  # Explicit signature OS seam.
            def owner_ready(self, app, state): return 100
            def owner_alive(self, pid, app, state): return not self.owner_exited
            def identity(self, path):
                return candidate_identity if ".vpn-control-stage-" in str(path) else super().identity(path)
            def receipt(self, job, authority, home):
                return {'jobId':job,'phase':'FAILED' if self.unlocked else 'WAITING_FOR_EXIT',
                        'code':'PERSISTENCE_FAILED' if self.unlocked else 'OK'}
            def public(self, app, state, *args):
                value = super().public(app,state,*args)
                if args[2:4] == ('operations','status'): self.owner_exited = True
                return value
            def acquire_shared_launcher_lock(self, path): return object()
            def release_shared_launcher_lock(self, token): self.unlocked = True
            def arm_immutable(self, *args): self.armed = True
            def clear_immutable(self, *args):
                test.assertTrue(self.unlocked and self.armed)
                self.armed = False
            def coordinator_absent(self, *args): return self.unlocked
        self.boundary = InertGuestBoundary(self.app,self.state,self.evidence,CORRELATION,CONTROLLER)
        spec = FixtureSpec(self.app,self.state,base_package,target_package,
            plain.sha256(base_package),plain.sha256(target_package),candidate_identity.sha256,
            base_identity,ReceiptAuthority.USER_LOCAL,self.root,timeout_seconds=0.5,poll_seconds=0.01)
        events=[]
        fixture=RollbackFixture(spec,self.boundary,events.append)
        fixture.run()
        self.assertEqual(fixture.steps,list(Step))
        self.assertEqual(len(self.boundary.records),3)
        self.assertTrue(all(x.manifest.is_file() and x.stdout_eof and x.stderr_eof for x in self.boundary.records))
        # The next observation is distinct from the scenario's cleanup/visual
        # acceptance. It cannot manufacture native GUI or package proof.
        self.public('updates','status')
        prior=ProcessIdentity(100,'Mon Oct  5 10:00:00 2026',
            (str(self.launcher),'--state-dir',str(self.state),'serve'))
        raw=f'101 Mon Oct  5 10:00:02 2026 {self.launcher} --state-dir {self.state}\n'.encode()
        result=capture.returned_gui_observation(str(self.launcher),str(self.state),prior,
            raw,self.boundary.records[-1],CONTROLLER,JOB)
        self.assertFalse(result['nativeAcceptanceGranted'])
        self.terminal()


class GuiObservationTests(unittest.TestCase):
    def fixture(self):
        launcher = "/Applications/owned.app/Contents/MacOS/vpn-control"
        state = "/Users/fixture/owned-state"
        prior = ProcessIdentity(100, "Mon Oct  5 10:00:00 2026", (launcher, "--state-dir", state, "serve"))
        ps = f" 101 Mon Oct  5 10:00:02 2026 {launcher} --state-dir {state}\n".encode()
        # Inert parser observation fixture; not fabricated native acceptance.
        status = {"ok": True, "final": True, "code": "OK", "controllerId": CONTROLLER,
            "data": {"installations": [{"jobId": JOB, "phase": "failed", "code": "PERSISTENCE_FAILED", "final": True, "installed": False}]}}
        record = capture.RawRecord((launcher,"--state-dir",state,"--json","updates","status"),
            json.dumps(status).encode(), b"", 0, True, True, None, 1, Path("/unexecuted"), "unexecuted")
        return launcher, state, prior, ps, record

    def observe(self, fixture):
        return capture.returned_gui_observation(*fixture, CONTROLLER, JOB)

    def test_actual_existing_process_and_public_recovery_composition(self):
        result = self.observe(self.fixture())
        self.assertEqual(result["guiPid"], 101)
        self.assertFalse(result["nativeAcceptanceGranted"])
        self.assertFalse(result["visibleAquaWindowProven"])

    def test_watchers_foreign_state_pid_reuse_duplicate_malformed_rows_refuse(self):
        l,s,p,ps,record = self.fixture()
        variants = [ps.replace(b" 101 ", b" 100 "), ps+ps,
            ps.replace(b"owned-state", b"other-state"), ps+b"malformed\n",
            ps.rstrip()+b" --headless-controller\n"]
        for raw in variants:
            with self.subTest(raw=raw), self.assertRaises(FixtureError):
                self.observe((l,s,p,raw,record))

    def test_missing_terminal_foreign_job_and_bad_capture_refuse(self):
        l,s,p,ps,record = self.fixture()
        for value in [replace(record, stdout_eof=False), replace(record, returncode=True),
                      replace(record, failure="timeout"), replace(record, stdout=record.stdout.replace(JOB.encode(),OTHER.encode())),
                      replace(record, stdout=record.stdout.replace(CONTROLLER.encode(),OTHER.encode()))]:
            with self.subTest(value=value), self.assertRaises(FixtureError):
                self.observe((l,s,p,ps,value))


if __name__ == "__main__":
    unittest.main()
