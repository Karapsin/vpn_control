import hashlib
import shutil
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "integration"))
from macos_rollback_fixture import FixtureError, FixtureSpec, Identity, MacBoundary, RollbackFixture, Step


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
    def now(self): return self.clock
    def sleep(self, seconds): self.clock += seconds
    def sha256(self, path): return "b" * 64 if "target" in str(path) else "a" * 64
    def identity(self, path):
        if ".vpn-control-stage-" in str(path): return Identity(10, 30, "c" * 64)
        return self.identity_value
    def verify_signature(self, app): self.events.append(("verify", str(app)))
    def owner_ready(self, app, state): return 99 if self.owner else 0
    def owner_alive(self, pid, app, state): return self.owner
    def receipt(self, job): return dict(self.receipt_value)
    def arm_immutable(self, candidate): self.immutable = True; self.events.append(("arm", str(candidate)))
    def clear_immutable(self, candidate):
        if not self.immutable: raise AssertionError("cleared without an armed candidate")
        self.cleared = True; self.immutable = False; self.events.append(("clear", str(candidate)))
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
            "a" * 64, "b" * 64, "c" * 64, BASE, timeout_seconds=1, poll_seconds=.1)
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
