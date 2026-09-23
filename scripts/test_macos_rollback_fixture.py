import hashlib
import shutil
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path, PureWindowsPath
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent / "integration"))
import macos_rollback_fixture as subject
from macos_rollback_fixture import FixtureError, FixtureSpec, Identity, MacBoundary, ReceiptAuthority, RollbackFixture, Step


JOB = "11111111-1111-1111-1111-111111111111"
OPERATION = "22222222-2222-2222-2222-222222222222"
BASE = Identity(10, 20, "a" * 64)


class FakeBoundary:
    def __init__(self):
        self.clock = 0.0
        self.owner = True
        self.lock_count = 0
        self.immutable = False
        self.cleared = False
        self.coordinator = False
        self.coordinator_polls = 0
        self.receipt_value = {"jobId": JOB, "phase": "WAITING_FOR_EXIT", "code": "OK"}
        self.events = []
        self.ack = True
        self.ack_job = JOB
        self.ack_controller = "owner"
        self.status_waiting = True
        self.terminal_after_unlock = True
        self.terminal_job = JOB
        self.identity_value = BASE
        self.receipt_calls = []
    def now(self): return self.clock
    def sleep(self, seconds): self.clock += seconds
    def sha256(self, path): return "b" * 64 if "target" in str(path) else "a" * 64
    def identity(self, path):
        if ".vpn-control-stage-" in str(path): return Identity(10, 30, "c" * 64)
        return self.identity_value
    def verify_signature(self, app): self.events.append(("verify", str(app)))
    def owner_ready(self, app, state): return 99 if self.owner else 0
    def owner_alive(self, pid, app, state): return self.owner
    def receipt(self, job, authority, owner_home): self.receipt_calls.append((job, authority, owner_home)); return dict(self.receipt_value)
    def arm_immutable(self, candidate, identity, job, authority): self.immutable = True; self.events.append(("arm", str(candidate), authority))
    def clear_immutable(self, candidate, identity, job, authority):
        if not self.immutable: raise AssertionError("cleared without an armed candidate")
        self.cleared = True; self.immutable = False; self.events.append(("clear", str(candidate), authority))
    def coordinator_absent(self, job, pid):
        if self.coordinator_polls:
            self.coordinator_polls -= 1
            return False
        return not self.coordinator
    def acquire_shared_launcher_lock(self, launcher):
        self.lock_count += 1
        if self.lock_count != 1: raise AssertionError("duplicate launcher lock owner")
        return object()
    def release_shared_launcher_lock(self, token):
        if self.lock_count != 1: raise AssertionError("wrong lock release")
        self.lock_count = 0; self.owner = False; self.events.append(("unlock", ""))
    def public(self, app, state, *args):
        if not self.owner:
            raise AssertionError("second public call after handoff-flushed owner exit")
        self.events.append(("public", args))
        if args == ("updates", "status"):
            installations = []
            if self.status_waiting:
                installations = [{"jobId": JOB, "operationId": OPERATION, "phase": "waiting_for_exit", "final": False}]
            return {"ok": True, "controllerId": "owner", "data": {"phase": "ready", "installations": installations}}
        if args == ("--controller-id", "owner", "--async", "updates", "install"):
            return {"ok": True, "code": "ACCEPTED", "final": False, "operationId": OPERATION, "controllerId": "owner",
                    "data": {"handoffReady": False}}
        if args == ("--controller-id", "owner", "operations", "status", OPERATION):
            if self.ack and self.ack_controller == "owner" and self.ack_job == JOB:
                # The owner gate releases only after this exact public response is flushed.
                self.owner = False
            return {"ok": True, "operationId": OPERATION, "controllerId": self.ack_controller,
                    "data": {"jobId": self.ack_job, "handoffReady": self.ack}}
        raise AssertionError(args)
    def terminal_receipt_after_unlock(self):
        if self.terminal_after_unlock and self.lock_count == 0:
            self.receipt_value = {"jobId": self.terminal_job, "phase": "FAILED", "code": "PERSISTENCE_FAILED"}


class RollbackFixtureTest(unittest.TestCase):
    def spec(self):
        return FixtureSpec(Path("/owned/app/vpn-control.app"), Path("/owned/state"), Path("/base.dmg"), Path("/target.dmg"),
            "a" * 64, "b" * 64, "c" * 64, BASE, ReceiptAuthority.USER_LOCAL, Path("/owned/home"), timeout_seconds=1, poll_seconds=.1)
    def exercise(self, boundary):
        events = []
        fixture = RollbackFixture(self.spec(), boundary, events.append)
        original_sleep = boundary.sleep
        def sleep(seconds):
            original_sleep(seconds); boundary.terminal_receipt_after_unlock()
        boundary.sleep = sleep
        fixture.run()
        return fixture, events
    def test_happy_path_has_single_lock_exact_ack_and_terminal_cleanup_order(self):
        boundary = FakeBoundary()
        fixture, events = self.exercise(boundary)
        self.assertEqual([step for step in Step], fixture.steps)
        self.assertEqual(0, boundary.lock_count)
        self.assertTrue(boundary.cleared)
        names = [event["step"] for event in events]
        self.assertLess(names.index("handoff_acknowledged"), names.index("owner_exited"))
        self.assertLess(names.index("lock_released"), names.index("terminal"))
        self.assertLess(names.index("base_restored"), names.index("cleaned"))
        installs = [event for event in boundary.events if event == ("public", ("--controller-id", "owner", "--async", "updates", "install"))]
        self.assertEqual(1, len(installs))
        self.assertEqual(3, len([event for event in boundary.events if event[0] == "public"]))
        self.assertTrue(all(call[1] is ReceiptAuthority.USER_LOCAL for call in boundary.receipt_calls))

    def test_machine_authority_uses_machine_receipt_and_narrow_candidate_actions(self):
        boundary = FakeBoundary()
        base = self.spec()
        spec = FixtureSpec(base.app, base.state_dir, base.expected_base_package, base.expected_target_package,
            base.expected_base_package_sha256, base.expected_target_package_sha256, base.expected_target_code_sha256,
            base.expected_base_identity, ReceiptAuthority.MACHINE, Path("/"), base.timeout_seconds, base.poll_seconds)
        events = []; fixture = RollbackFixture(spec, boundary, events.append)
        original_sleep = boundary.sleep
        boundary.sleep = lambda seconds: (original_sleep(seconds), boundary.terminal_receipt_after_unlock())
        fixture.run()
        self.assertTrue(boundary.receipt_calls and all(call[1] is ReceiptAuthority.MACHINE for call in boundary.receipt_calls))
        self.assertTrue(all(event[-1] is ReceiptAuthority.MACHINE for event in boundary.events if event[0] in ("arm", "clear")))
    def test_omitted_public_ack_does_not_release_lock_or_clear_candidate(self):
        boundary = FakeBoundary(); boundary.ack = False
        with self.assertRaisesRegex(FixtureError, "same-operation public handoff"):
            self.exercise(boundary)
        self.assertEqual(1, boundary.lock_count)
        self.assertFalse(boundary.immutable, "candidate is armed only after a public ready acknowledgement")
        self.assertFalse(boundary.cleared)
    def test_watch_only_receipt_cannot_drive_owner_exit_without_public_acknowledgement(self):
        boundary = FakeBoundary(); boundary.ack = False
        with self.assertRaisesRegex(FixtureError, "same-operation public handoff"):
            self.exercise(boundary)
        self.assertTrue(boundary.owner)
        self.assertEqual(1, boundary.lock_count)
        self.assertFalse(boundary.cleared)
    def test_wrong_controller_or_job_ready_response_is_rejected_before_owner_exit(self):
        for attribute, value in (("ack_controller", "other"), ("ack_job", "33333333-3333-3333-3333-333333333333")):
            with self.subTest(attribute=attribute):
                boundary = FakeBoundary(); setattr(boundary, attribute, value)
                with self.assertRaisesRegex(FixtureError, "identity changed|handoff receipt"):
                    self.exercise(boundary)
                self.assertFalse(boundary.cleared)
    def test_terminal_receipt_before_unlock_is_not_accepted_as_rollback_completion(self):
        boundary = FakeBoundary(); boundary.terminal_after_unlock = False
        with self.assertRaisesRegex(FixtureError, "timed out waiting for exact terminal failed receipt"):
            self.exercise(boundary)
        self.assertFalse(boundary.cleared)
        self.assertTrue(boundary.immutable)
    def test_wrong_nonempty_terminal_receipt_is_rejected_without_cleanup(self):
        boundary = FakeBoundary(); boundary.terminal_job = "33333333-3333-3333-3333-333333333333"
        with self.assertRaisesRegex(FixtureError, "terminal receipt identity changed"):
            self.exercise(boundary)
        self.assertFalse(boundary.cleared)
        self.assertTrue(boundary.immutable)
    def test_coordinator_presence_blocks_flag_cleanup_after_terminal_and_restoration(self):
        boundary = FakeBoundary(); boundary.coordinator = True
        with self.assertRaisesRegex(FixtureError, "coordinator absence after terminal"):
            self.exercise(boundary)
        self.assertFalse(boundary.cleared)
        self.assertTrue(boundary.immutable)
    def test_coordinator_may_exit_after_terminal_before_flag_cleanup(self):
        boundary = FakeBoundary(); boundary.coordinator_polls = 2
        fixture, _ = self.exercise(boundary)
        self.assertEqual(Step.CLEANED, fixture.steps[-1])
        self.assertTrue(boundary.cleared)
    def test_changed_ready_owner_rejects_install_before_any_mutating_public_call(self):
        boundary = FakeBoundary()
        original = boundary.public
        def public(app, state, *args):
            response = original(app, state, *args)
            if args == ("updates", "status"):
                boundary.owner = False
            return response
        boundary.public = public
        with self.assertRaisesRegex(AssertionError, "second public call"):
            self.exercise(boundary)
    def test_wrong_restored_inode_is_rejected_before_cleanup(self):
        boundary = FakeBoundary()
        original_sleep = boundary.sleep
        def sleep(seconds):
            original_sleep(seconds); boundary.terminal_receipt_after_unlock()
            if boundary.lock_count == 0: boundary.identity_value = Identity(10, 21, "a" * 64)
        boundary.sleep = sleep
        fixture = RollbackFixture(self.spec(), boundary, lambda _: None)
        with self.assertRaisesRegex(FixtureError, "not restored"):
            fixture.run()
        self.assertFalse(boundary.cleared)

    def test_replaced_armed_candidate_is_never_cleared(self):
        boundary = FakeBoundary()
        original_sleep = boundary.sleep
        def sleep(seconds):
            original_sleep(seconds); boundary.terminal_receipt_after_unlock()
            if boundary.lock_count == 0: boundary.identity = lambda path: Identity(10, 31, "d" * 64) if ".vpn-control-stage-" in str(path) else BASE
        boundary.sleep = sleep
        with self.assertRaisesRegex(FixtureError, "armed candidate identity changed"):
            RollbackFixture(self.spec(), boundary, lambda _: None).run()
        self.assertFalse(boundary.cleared)


class MacBoundaryAuthorityTest(unittest.TestCase):
    def test_owner_ready_uses_macos_paths_even_under_windows_path_semantics(self):
        app = PureWindowsPath("/Applications/vpn-control-machine-rollback114.app")
        state = PureWindowsPath("/Users/admin/macos-machine-rollback114/state")
        owner = "/Applications/vpn-control-machine-rollback114.app/Contents/MacOS/vpn-control --state-dir /Users/admin/macos-machine-rollback114/state serve"
        raw = " 745 Tue Sep 23 16:40:02 2026 " + owner
        boundary = MacBoundary(); boundary.public = lambda *_: {"ok": True}
        with mock.patch.object(subject.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, raw, "")) as run:
            self.assertEqual(745, boundary.owner_ready(app, state))
        self.assertEqual(30, run.call_args.kwargs["timeout"])

    def test_owner_ready_rejects_launch_wrappers_and_selects_exact_owner(self):
        app = Path("/Applications/vpn-control-machine-rollback114.app"); state = Path("/Users/admin/macos-machine-rollback114/state")
        owner = f"{app}/Contents/MacOS/vpn-control --state-dir {state} serve"
        raw = "\n".join((
            f" 743 Tue Sep 23 16:40:00 2026 sudo launchctl asuser 501 sudo -n -u admin {owner}",
            f" 744 Tue Sep 23 16:40:01 2026 sudo -n -u admin {owner}",
            f" 745 Tue Sep 23 16:40:02 2026 {owner}",
        ))
        boundary = MacBoundary(); boundary.public = lambda *_: {"ok": True}
        with mock.patch.object(subject.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, raw, "")):
            self.assertEqual(745, boundary.owner_ready(app, state))
            self.assertTrue(boundary.owner_alive(745, app, state))

    def test_owner_ready_rejects_ambiguous_exact_owners(self):
        app = Path("/Applications/vpn-control-machine-rollback114.app"); state = Path("/Users/admin/macos-machine-rollback114/state")
        owner = f"{app}/Contents/MacOS/vpn-control --state-dir {state} serve"
        raw = "\n".join((f" 745 Tue Sep 23 16:40:02 2026 {owner}", f" 746 Tue Sep 23 16:40:03 2026 {owner}"))
        boundary = MacBoundary(); boundary.public = lambda *_: {"ok": True}
        with mock.patch.object(subject.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, raw, "")):
            self.assertEqual(0, boundary.owner_ready(app, state))
            self.assertFalse(boundary.owner_alive(745, app, state))

    def test_cli_rejects_authority_option_mismatch_before_fixture_construction(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"; state.mkdir()
            args = ["--app", "/owned/app.app", "--state-dir", str(state), "--base-package", "/base.dmg",
                "--target-package", "/target.dmg", "--base-package-sha256", "a" * 64,
                "--target-package-sha256", "b" * 64, "--target-code-sha256", "c" * 64,
                "--base-identity", "1:2:" + "d" * 64, "--receipt-authority", "machine",
                "--owner-home", "/owned/home", "--evidence", str(Path(temporary) / "new.jsonl")]
            with mock.patch.object(subject.sys, "platform", "darwin"), \
                 mock.patch.object(subject, "RollbackFixture", side_effect=AssertionError("fixture constructed")):
                with self.assertRaises(SystemExit): subject.main(args)

    def test_machine_receipt_uses_only_helper_not_user_home(self):
        boundary = MacBoundary()
        with mock.patch.object(boundary, "_machine", return_value='{"jobId":"' + JOB + '"}') as helper, \
             mock.patch.object(Path, "read_text", side_effect=AssertionError("fallback read")):
            self.assertEqual({"jobId": JOB}, boundary.receipt(JOB, ReceiptAuthority.MACHINE, Path("/owned/home")))
        helper.assert_called_once_with("receipt", JOB)

    def test_machine_helper_reads_only_exact_machine_status_path(self):
        seen = []
        def read_text(path): seen.append(path); return '{"jobId":"' + JOB + '"}'
        with mock.patch.object(subject.os, "geteuid", return_value=0, create=True), \
             mock.patch.object(Path, "read_text", read_text):
            self.assertEqual(0, subject._machine_helper(["--machine-helper", "receipt", "--job-id", JOB]))
        self.assertEqual([Path("/Library/Application Support/vpn-control-install-jobs") / JOB / "status.json"], seen)

    def test_failed_machine_read_never_falls_back_to_user_home(self):
        boundary = MacBoundary()
        failed = subprocess.CalledProcessError(1, ["sudo"])
        with mock.patch.object(boundary, "_machine", side_effect=failed), \
             mock.patch.object(Path, "read_text", side_effect=AssertionError("fallback read")):
            self.assertEqual({}, boundary.receipt(JOB, ReceiptAuthority.MACHINE, Path("/owned/home")))

    def test_user_local_receipt_never_invokes_machine_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary); path = home / "Library/Application Support/vpn-control-install-jobs" / JOB
            path.mkdir(parents=True); (path / "status.json").write_text('{"jobId":"' + JOB + '"}')
            boundary = MacBoundary()
            with mock.patch.object(boundary, "_machine", side_effect=AssertionError("machine helper")):
                self.assertEqual({"jobId": JOB}, boundary.receipt(JOB, ReceiptAuthority.USER_LOCAL, home))

    def test_machine_helper_rejects_bad_job_or_candidate_before_chflags(self):
        with mock.patch.object(subject.os, "geteuid", return_value=0, create=True), \
             mock.patch.object(subject.subprocess, "run") as run:
            with self.assertRaisesRegex(FixtureError, "canonical UUID"):
                subject._machine_helper(["--machine-helper", "arm", "--job-id", "bad", "--candidate", "/Applications/.vpn-control-stage-bad.app", "--identity", "1:2:" + "a" * 64])
            with self.assertRaisesRegex(FixtureError, "candidate identity changed"):
                subject._machine_helper(["--machine-helper", "arm", "--job-id", JOB, "--candidate", "/tmp/other.app", "--identity", "1:2:" + "a" * 64])
        run.assert_not_called()

    def test_machine_helper_identity_mismatch_never_chflags(self):
        candidate = Path("/Applications/.vpn-control-stage-" + JOB + ".app")
        with mock.patch.object(subject.os, "geteuid", return_value=0, create=True), \
             mock.patch.object(MacBoundary, "identity", return_value=Identity(1, 3, "a" * 64)), \
             mock.patch.object(subject.subprocess, "run") as run:
            with self.assertRaisesRegex(FixtureError, "candidate identity changed"):
                subject._machine_helper(["--machine-helper", "arm", "--job-id", JOB, "--candidate", str(candidate), "--identity", "1:2:" + "a" * 64])
        run.assert_not_called()


class CanonicalBundleIdentityTest(unittest.TestCase):
    def test_nested_bundle_digest_is_shared_and_copy_identity_is_distinct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = root / "base"
            (base / "a").mkdir(parents=True)
            (base / "z").write_bytes(b"root file")
            (base / "a" / "nested").write_bytes(b"nested file")
            expected = hashlib.sha256()
            for name, payload in (("a", None), ("a/nested", b"nested file"), ("z", b"root file")):
                expected.update(name.encode() + b"\0")
                if payload is not None:
                    expected.update(hashlib.sha256(payload).hexdigest().encode())
            boundary = MacBoundary()
            original = boundary.identity(base)
            self.assertEqual(expected.hexdigest(), original.sha256)
            copied = root / "copy"
            shutil.copytree(base, copied)
            replacement = boundary.identity(copied)
            self.assertNotEqual(original, replacement)
            self.assertEqual(original.sha256, replacement.sha256)
            (copied / "a" / "nested").write_bytes(b"changed")
            self.assertNotEqual(original.sha256, boundary.identity(copied).sha256)


if __name__ == "__main__":
    unittest.main()
