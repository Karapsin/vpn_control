"""Exercise coordinator decisions over a real controlled provider socket."""
from dataclasses import asdict, replace
import json
import hashlib
import os
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import subprocess
import sys
import time
import unittest
from unittest import mock
from types import SimpleNamespace
from uuid import uuid4

from agent_tools import readiness as r


class Provider(socketserver.UnixStreamServer):
    def __init__(self, path):
        super().__init__(str(path), Handler)
        self.observation = r.Observation("fixture", "machine-a", "connection-a", "boot-a", "uid1000", "session-a",
                                         "ready", "running", True, "ready", "ready", True, True, True, True,
                                         r.IDLE_VISIBILITY)
        self.effects = []
        self.lost_ack = set()
        self.dont_apply = set()
        self.observe_calls = 0
        self.unsubmitted = {}
        self.attempts = []
        self.proofs = []
        self.proof_change = lambda value: value


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        request = json.loads(self.rfile.readline())
        server = self.server
        if request["method"] == "observe":
            server.observe_calls += 1
        else:
            action = request["action"]
            server.attempts.append(dict(request))
            if server.unsubmitted.get(action, 0):
                server.unsubmitted[action] -= 1
                proof = {"recoveryId": request["recoveryId"], "attempt": request.get("attempt", 1),
                         "dispatchDigest": request.get("dispatchDigest", "0" * 64), "noLaunch": True,
                         "sequence": len(server.attempts), "target": server.observation.target,
                         "machine": server.observation.machine, "boot": server.observation.boot}
                proof["proofSha256"] = hashlib.sha256(json.dumps(proof, sort_keys=True).encode()).hexdigest()
                server.proofs.append(dict(proof))
                self.wfile.write(json.dumps({"unsubmitted": server.proof_change(proof)}).encode() + b"\n")
                return
            server.effects.append((action, request["recoveryId"]))
            if action not in server.dont_apply:
                changes = {"reconnect": {"transport": "ready", "connection": "connection-b"},
                           "start": {"guest": "running", "guest_agent": True, "boot": "boot-b"},
                           "resume": {"guest": "running"}, "reboot": {"guest": "running", "boot": "boot-b"},
                           "login": {"ordinary_session": "ready"}, "wake_display": {"display": "ready"}}[action]
                server.observation = replace(server.observation, **changes)
            if action in server.lost_ack:
                return
        value = asdict(server.observation)
        value["idle_visibility"] = sorted(value["idle_visibility"])
        value["idle_blockers"] = sorted(value["idle_blockers"])
        self.wfile.write(json.dumps(value).encode() + b"\n")


class SocketAdapter:
    capabilities = r.RECOVERIES

    def __init__(self, path):
        self.path = str(path)

    def _raw_request(self, value):
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(2)
            client.connect(self.path)
            client.sendall(json.dumps(value).encode() + b"\n")
            with client.makefile("rb") as response:
                result = json.loads(response.readline())
        return result

    def _request(self, value):
        result = self._raw_request(value)
        for key in ("idle_visibility", "idle_blockers"):
            result[key] = frozenset(result[key])
        return r.Observation(**result)

    def observe(self, requirements, deadline):
        return self._request({"method": "observe"})

    def recover(self, action, recovery_identity, observed, deadline):
        self._request({"method": "recover", "action": action, "recoveryId": recovery_identity})


class ProofSocketAdapter(SocketAdapter):
    def recover(self, action, recovery_identity, observed, deadline):
        # The pre-fix core invokes this legacy entrypoint and consumes its once
        # record despite actual no-launch proof; the causal test then fails.
        self.recover_attempt(action, recovery_identity, observed, deadline, 1, "0" * 64)

    def recover_attempt(self, action, recovery_identity, observed, deadline, attempt, dispatch_digest):
        result = self._raw_request({"method": "recover", "action": action, "recoveryId": recovery_identity,
                                    "attempt": attempt, "dispatchDigest": dispatch_digest})
        if "unsubmitted" in result:
            proof = result["unsubmitted"]
            exception = getattr(r, "RecoveryUnsubmitted", RuntimeError)
            raise exception(proof["recoveryId"], proof["attempt"], proof["dispatchDigest"], proof["proofSha256"])


class Clock:
    def __init__(self):
        self.now = 1.0
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


@unittest.skipUnless(os.name == "posix", "private readiness journal requires POSIX custody")
class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="ready-")
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.path = root / "provider.sock"
        self.server = Provider(self.path)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.clock = Clock()
        self.context = r.Context("fixture", "machine-a", SocketAdapter(self.path), r.RecoveryJournal(root),
                                 clock=self.clock, sleep=self.clock.sleep)
        self.operation = str(uuid4())
        self.gui = r.Requirements(frozenset({"interactive_desktop"}), r.RECOVERIES)

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)

    def observe(self, **changes):
        self.server.observation = replace(self.server.observation, **changes)

    def test_healthy_gui_needs_no_recovery_and_binds_every_identity(self):
        ready = r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual(("fixture", "machine-a", "connection-a", "boot-a", "uid1000", "session-a"), ready.identities())
        r.revalidate(self.context, ready)
        self.assertEqual([], self.server.effects)

    def test_normal_headless_facade_recovers_agent_without_unlocking_display(self):
        from agent_tools import readiness_workflow as workflow
        self.observe(guest="paused", ordinary_session="locked", display="sleeping", credential_available=False)
        fixture = SimpleNamespace(adapter=self.context.adapter, context=lambda: self.context,
                                  required_readiness=frozenset({"guest_agent"}))
        with mock.patch.object(workflow.fixtures, "registered_fixture", return_value=fixture):
            result = workflow.vm_workflow(Path(self.directory.name), "readiness-ensure",
                                          {"fixtureId": "headless-test", "operationId": self.operation})
        self.assertEqual("ready", result["state"])
        self.assertEqual(["resume"], [a for a, _ in self.server.effects])
        self.assertEqual("locked", self.server.observation.ordinary_session)
        self.assertEqual("sleeping", self.server.observation.display)

    def test_normal_desktop_status_exposes_blocker_without_recovery_or_private_input(self):
        from agent_tools import readiness_workflow as workflow
        self.observe(ordinary_session="locked", credential_available=False)
        fixture = SimpleNamespace(adapter=self.context.adapter, context=lambda: self.context)
        with mock.patch.object(workflow.fixtures, "registered_fixture", return_value=fixture):
            result = workflow.vm_workflow(Path(self.directory.name), "readiness-status",
                                          {"fixtureId": "desktop-test", "operationId": self.operation})
        self.assertEqual("not_ready", result["state"])
        self.assertEqual("credential_unavailable", result["readinessBlocker"])
        self.assertEqual("desktop-test", result["fixtureId"])
        self.assertEqual([], self.server.effects)

    def test_locked_asleep_session_recovers_each_effect_once_despite_lost_ack(self):
        self.observe(ordinary_session="locked", display="sleeping")
        self.server.lost_ack = {"login", "wake_display"}
        r.ensure_ready(self.context, self.gui, self.operation)
        r.ensure_ready(self.context, self.gui, str(uuid4()))
        self.assertEqual(["wake_display", "login"], [a for a, _ in self.server.effects])

    def test_unacknowledged_login_observes_after_restart_never_submits_again(self):
        self.observe(ordinary_session="locked")
        self.server.lost_ack = {"login"}; self.server.dont_apply = {"login"}
        for operation in (self.operation, str(uuid4())):
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.ensure_ready(self.context, self.gui, operation)
            self.assertEqual("recovery_outcome_unknown", error.exception.reason)
        self.assertEqual(["login"], [a for a, _ in self.server.effects])

    def test_background_transport_reconnect_preserves_stopped_guest_and_locked_session(self):
        self.observe(transport="expired", guest="stopped", ordinary_session="locked")
        ready = r.ensure_ready(self.context, r.Requirements(frozenset({"transport"}), r.RECOVERIES), self.operation)
        self.assertEqual("connection-b", ready.connection)
        self.assertEqual(["reconnect"], [a for a, _ in self.server.effects])
        self.assertEqual("stopped", self.server.observation.guest)
        self.assertEqual("locked", self.server.observation.ordinary_session)

    def test_intentional_test_states_are_not_repaired(self):
        cases = [("stopped", {"guest": "stopped"}), ("paused", {"guest": "paused"}),
                 ("suspended", {"guest": "suspended"}), ("locked", {"ordinary_session": "locked"}),
                 ("signed_out", {"ordinary_session": "signed_out"}), ("sleeping", {"display": "sleeping"}),
                 ("disconnected", {"transport": "unavailable"})]
        for intentional, changes in cases:
            with self.subTest(intentional=intentional):
                old = self.server.observation
                self.observe(**changes)
                r.ensure_ready(self.context, replace(self.gui, intentional_states=frozenset({intentional})), str(uuid4()))
                self.assertEqual([], self.server.effects)
                self.server.observation = old

    def test_boot_and_session_change_refuse_old_prepared_packet(self):
        ready = r.ensure_ready(self.context, self.gui, self.operation)
        for field in ("boot", "account", "session", "connection"):
            old = self.server.observation
            self.observe(**{field: "new-generation"})
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.revalidate(self.context, ready)
            self.assertEqual("prepared_context_stale", error.exception.reason)
            self.server.observation = old
        self.assertEqual([], self.server.effects)

    def test_reboot_requires_every_idle_visibility_category_and_no_blockers(self):
        self.observe(guest="unhealthy")
        for absent in r.IDLE_VISIBILITY:
            self.observe(idle_visibility=r.IDLE_VISIBILITY - {absent})
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.ensure_ready(self.context, self.gui, str(uuid4()))
            self.assertEqual("positive_idle_proof_missing", error.exception.reason)
        for blocker in r.IDLE_VISIBILITY:
            self.observe(idle_visibility=r.IDLE_VISIBILITY, idle_blockers=frozenset({blocker}))
            with self.assertRaises(r.ReadinessBlocked):
                r.ensure_ready(self.context, self.gui, str(uuid4()))
        self.assertEqual([], self.server.effects)
        self.observe(idle_blockers=frozenset())
        ready = r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("boot-b", ready.boot)
        self.assertEqual(["reboot"], [a for a, _ in self.server.effects])

    def test_coordinator_host_and_unowned_fixture_never_receive_power_or_login(self):
        for changes in ({"owned": False}, {"coordinator_host": True}):
            self.observe(guest="stopped", **changes)
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.ensure_ready(self.context, self.gui, str(uuid4()))
            self.assertEqual("fixture_ownership_unproven", error.exception.reason)
            self.observe(owned=True, coordinator_host=False)
        self.assertEqual([], self.server.effects)

    def test_wrong_account_unknown_screen_missing_credentials_do_not_submit_input(self):
        for changes, reason in [({"ordinary_session": "wrong_account"}, "wrong_account"),
                                ({"ordinary_session": "locked", "credential_available": False}, "credential_unavailable"),
                                ({"display": "unrecognized"}, "screen_unrecognized")]:
            old = self.server.observation
            self.observe(**changes)
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.ensure_ready(self.context, self.gui, str(uuid4()))
            self.assertEqual(reason, error.exception.reason)
            self.server.observation = old
        self.assertEqual([], self.server.effects)

    def test_untrusted_or_changed_machine_never_recovers(self):
        for changes, reason in [({"trusted": False}, "trust_mismatch"), ({"integrity": False}, "integrity_mismatch"),
                                ({"machine": "foreign"}, "machine_identity_mismatch")]:
            old = self.server.observation
            self.observe(transport="dead", **changes)
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.ensure_ready(self.context, self.gui, str(uuid4()))
            self.assertEqual(reason, error.exception.reason)
            self.server.observation = old
        self.assertEqual([], self.server.effects)

    def test_original_job_reconciliation_restores_only_transport(self):
        self.observe(transport="dead", guest="suspended", ordinary_session="locked")
        for state, next_action in [("running", "observe_original"), ("terminal", "collect_original"),
                                   ("proven_unsubmitted", "prepare_original"), ("unknown", "resolve_blocker")]:
            result = r.reconcile_original(self.context, self.operation, lambda _, s=state: {"state": s})
            self.assertEqual((self.operation, False, next_action), (result["operationId"], result["replayAllowed"], result["nextAction"]))
        self.assertEqual(["reconnect"], [a for a, _ in self.server.effects])

    def test_shorter_caller_deadline_and_cancellation_are_binding(self):
        self.observe(guest="booting")
        self.context.deadline = self.clock() + 2
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("readiness_deadline", error.exception.reason)
        self.context.cancelled = lambda: True
        with self.assertRaises(r.ReadinessBlocked):
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual([], self.server.effects)

    def test_concurrent_callers_share_one_login_journal(self):
        self.observe(ordinary_session="locked")
        errors = []
        def run():
            try:
                context = replace(self.context, clock=time.monotonic, sleep=time.sleep)
                r.ensure_ready(context, self.gui, str(uuid4()))
            except Exception as error:
                errors.append(error)
        threads = [threading.Thread(target=run) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertFalse(any(t.is_alive() for t in threads))
        self.assertEqual([], errors)
        self.assertEqual(["login"], [a for a, _ in self.server.effects])

    def test_later_lock_in_same_session_gets_new_recovery_identity(self):
        for _ in range(2):
            self.observe(ordinary_session="locked")
            r.ensure_ready(self.context, self.gui, str(uuid4()))
        self.assertEqual(["login", "login"], [a for a, _ in self.server.effects])
        self.assertEqual(2, len({identity for _, identity in self.server.effects}))

    def test_provider_still_unhealthy_after_reboot_cannot_receive_second_reboot(self):
        self.observe(guest="unhealthy")
        original = self.context.adapter.recover
        def recover(*args):
            original(*args)
            self.observe(guest="unhealthy")
        self.context.adapter.recover = recover
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("reboot_limit_reached", error.exception.reason)
        self.assertEqual(["reboot"], [a for a, _ in self.server.effects])

    def test_absent_connection_and_non_boolean_admission_are_rejected(self):
        for changes, reason in [({"connection": None}, "connection_identity_missing"),
                                ({"trusted": "yes"}, "invalid_readiness_observation"),
                                ({"guest_agent": 1}, "invalid_readiness_observation")]:
            old = self.server.observation
            self.observe(**changes)
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.ensure_ready(self.context, self.gui, str(uuid4()))
            self.assertEqual(reason, error.exception.reason)
            self.server.observation = old

    def test_late_observation_never_admits_or_performs_recovery(self):
        original = self.context.adapter.observe
        def observe(*args):
            result = original(*args)
            self.clock.sleep(181)
            return result
        self.context.adapter.observe = observe
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("readiness_deadline", error.exception.reason)
        self.assertEqual([], self.server.effects)

    def test_transport_has_three_attempts_with_fixed_backoff(self):
        self.observe(transport="unavailable")
        self.server.dont_apply = {"reconnect"}
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("transport_attempts_exhausted", error.exception.reason)
        self.assertEqual(["reconnect"] * 3, [a for a, _ in self.server.effects])
        self.assertEqual(8, self.clock())  # initial1 +1/2/4 seconds

    def test_later_outages_rearm_completed_connection_recovery_for_same_original_job(self):
        for _ in range(4):
            self.observe(transport="dead")
            ready = r.ensure_ready(self.context, self.gui, self.operation)
            self.assertEqual("connection-b", ready.connection)
        self.assertEqual(["reconnect"] * 4, [a for a, _ in self.server.effects])
        self.assertEqual(4, len({identity for _, identity in self.server.effects}))

    def proof_adapter(self):
        self.context.adapter = ProofSocketAdapter(self.path)

    def test_proven_unsubmitted_packet_reprepares_same_recovery_before_effect(self):
        self.observe(display="sleeping"); self.proof_adapter()
        self.server.unsubmitted = {"wake_display": 1}
        ready = r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("boot-a", ready.boot)
        self.assertEqual(["wake_display"], [action for action, _ in self.server.effects])
        self.assertEqual([1, 2], [row["attempt"] for row in self.server.attempts])
        self.assertEqual(1, len({row["recoveryId"] for row in self.server.attempts}))
        self.assertEqual(2, len({row["dispatchDigest"] for row in self.server.attempts}))

    def test_proven_unsubmitted_dispatches_are_bounded_at_three(self):
        self.observe(display="sleeping"); self.proof_adapter()
        self.server.unsubmitted = {"wake_display": 10}
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("recovery_dispatch_attempts_exhausted", error.exception.reason)
        self.assertEqual([1, 2, 3], [row["attempt"] for row in self.server.attempts])
        self.assertEqual([], self.server.effects)

    def test_stale_or_malformed_unsubmitted_proofs_never_allow_another_dispatch(self):
        for changed in ({"recoveryId": "f" * 64}, {"dispatchDigest": "f" * 64},
                        {"attempt": 2}, {"proofSha256": "PRIVATE-MARKER"}):
            with self.subTest(changed=changed):
                # New boot/session makes this a distinct owned test transition.
                self.observe(display="sleeping", session=str(uuid4()))
                self.proof_adapter(); self.server.unsubmitted = {"wake_display": 1}
                self.server.proof_change = lambda row, extra=changed: {**row, **extra}
                before = len(self.server.attempts)
                with self.assertRaises(r.ReadinessBlocked) as error:
                    r.ensure_ready(self.context, self.gui, str(uuid4()))
                self.assertNotIn("PRIVATE-MARKER", str(error.exception))
                self.assertEqual(before + 1, len(self.server.attempts))
        self.assertEqual([], self.server.effects)

    def test_repeated_proof_hash_is_not_reused_for_a_later_dispatch(self):
        self.observe(display="sleeping"); self.proof_adapter()
        self.server.unsubmitted = {"wake_display": 3}
        self.server.proof_change = lambda row: {**row, "proofSha256": "e" * 64}
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("recovery_unsubmitted_proof_invalid", error.exception.reason)
        self.assertEqual([1, 2], [row["attempt"] for row in self.server.attempts])
        self.assertEqual([], self.server.effects)

    def test_client_death_after_durable_proof_resumes_original_attempt_sequence(self):
        self.observe(display="sleeping"); self.proof_adapter()
        self.server.unsubmitted = {"wake_display": 1}
        code = "\n".join([
            "import os,time", "from pathlib import Path", "from agent_tools import readiness as r",
            "from agent_tools.tests.test_readiness import ProofSocketAdapter",
            "c=r.Context('fixture','machine-a',ProofSocketAdapter(" + repr(str(self.path)) + "),r.RecoveryJournal(Path(" +
            repr(self.directory.name) + ")),deadline=time.monotonic()+5,progress=lambda phase:os._exit(73) if phase=='recovery_proven_unsubmitted' else None)",
            "r.ensure_ready(c,r.Requirements(frozenset({'interactive_desktop'}),r.RECOVERIES)," + repr(self.operation) + ")",
        ])
        child = subprocess.run([sys.executable, "-c", code], capture_output=True, timeout=8,
                               cwd=Path(__file__).resolve().parents[2])
        self.assertEqual(73, child.returncode, child.stderr.decode())
        self.assertEqual([], self.server.effects)
        r.ensure_ready(self.context, self.gui, str(uuid4()))
        self.assertEqual([1, 2], [row["attempt"] for row in self.server.attempts])
        self.assertEqual(1, len({row["recoveryId"] for row in self.server.attempts}))
        self.assertEqual(["wake_display"], [action for action, _ in self.server.effects])

    def test_old_v1_pending_intent_never_acquires_dispatch_permission(self):
        self.observe(display="sleeping"); self.proof_adapter()
        observed = self.server.observation
        base = json.dumps(["fixture", "machine-a", observed.boot, observed.account, observed.session, "wake_display"], separators=(",", ":"))
        key = base + ":0"; recovery = hashlib.sha256(key.encode()).hexdigest()
        with self.context.journal.locked() as journal:
            journal.record(key, {"version": 1, "action": "wake_display", "recoveryId": recovery,
                                "target": "fixture", "machine": "machine-a", "boot": observed.boot,
                                "account": observed.account, "session": observed.session})
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("recovery_outcome_unknown", error.exception.reason)
        self.assertEqual([], self.server.attempts)

    def test_reboot_proof_retry_preserves_original_budget_and_lost_ack_is_not_replayed(self):
        self.observe(guest="unhealthy"); self.proof_adapter()
        self.server.unsubmitted = {"reboot": 1}
        self.server.lost_ack = {"reboot"}
        ready = r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("boot-b", ready.boot)
        self.assertEqual([1, 2], [row["attempt"] for row in self.server.attempts])
        self.assertEqual(["reboot"], [action for action, _ in self.server.effects])
        budget_name = hashlib.sha256(("reboot-budget:" + self.operation).encode()).hexdigest() + ".json"
        budget = json.loads((Path(self.directory.name) / budget_name).read_text())
        self.assertEqual(self.server.attempts[0]["recoveryId"], budget["recoveryId"])
        self.assertEqual(self.operation, budget["operationId"])

    def test_corrupted_proof_is_rejected_after_fresh_coordinator_restart(self):
        self.observe(display="sleeping"); self.proof_adapter()
        self.server.unsubmitted = {"wake_display": 1}
        self.context.progress = lambda phase: setattr(self.context, "cancelled", lambda: True) if phase == "recovery_proven_unsubmitted" else None
        with self.assertRaises(r.ReadinessBlocked):
            r.ensure_ready(self.context, self.gui, self.operation)
        proofs = list(Path(self.directory.name).glob("unsubmitted-*.json"))
        self.assertEqual(1, len(proofs))
        value = json.loads(proofs[0].read_text()); value["dispatchDigest"] = "f" * 64
        proofs[0].write_text(json.dumps(value))
        self.context = replace(self.context, cancelled=lambda: False, progress=lambda _: None,
                               journal=r.RecoveryJournal(Path(self.directory.name)))
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, str(uuid4()))
        self.assertEqual("readiness_journal_unavailable", error.exception.reason)
        self.assertEqual(1, len(self.server.attempts))
        self.assertEqual([], self.server.effects)

    def test_restart_between_each_proof_does_not_reset_dispatch_limit(self):
        self.observe(display="sleeping"); self.proof_adapter()
        self.server.unsubmitted = {"wake_display": 10}
        for _ in range(3):
            self.context = replace(self.context, cancelled=lambda: False,
                                   journal=r.RecoveryJournal(Path(self.directory.name)))
            self.context.progress = lambda phase: setattr(self.context, "cancelled", lambda: True) if phase == "recovery_proven_unsubmitted" else None
            with self.assertRaises(r.ReadinessBlocked) as error:
                r.ensure_ready(self.context, self.gui, str(uuid4()))
            self.assertEqual("readiness_cancelled", error.exception.reason)
        self.context = replace(self.context, cancelled=lambda: False, progress=lambda _: None)
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, str(uuid4()))
        self.assertEqual("recovery_dispatch_attempts_exhausted", error.exception.reason)
        self.assertEqual([1, 2, 3], [row["attempt"] for row in self.server.attempts])
        self.assertEqual(1, len({row["recoveryId"] for row in self.server.attempts}))
        self.assertEqual([], self.server.effects)

    def test_legacy_reboot_budget_never_authorizes_new_dispatch_protocol(self):
        self.observe(guest="unhealthy"); self.proof_adapter()
        with self.context.journal.locked() as journal:
            journal.record("reboot-budget:" + self.operation,
                           {"version": 1, "operationId": self.operation, "target": "fixture", "machine": "machine-a"})
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("reboot_limit_reached", error.exception.reason)
        self.assertEqual([], self.server.attempts)

    def test_positive_booting_state_receives_cold_budget_but_caller_cap_wins(self):
        self.observe(guest="booting")
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("readiness_deadline", error.exception.reason)
        self.assertEqual(601, self.clock())
        self.context.deadline = self.clock() + 3
        with self.assertRaises(r.ReadinessBlocked):
            r.ensure_ready(self.context, self.gui, str(uuid4()))
        self.assertEqual(604, self.clock())
        self.assertEqual([], self.server.effects)

    def test_network_unknown_does_not_receive_cold_boot_budget_or_replay(self):
        self.observe(transport="unavailable", guest="booting")
        self.server.lost_ack = {"reconnect"}; self.server.dont_apply = {"reconnect"}
        with self.assertRaises(r.ReadinessBlocked) as error:
            r.ensure_ready(self.context, self.gui, self.operation)
        self.assertEqual("recovery_outcome_unknown", error.exception.reason)
        self.assertEqual(181, self.clock())
        self.assertEqual(["reconnect"], [action for action, _ in self.server.effects])


if __name__ == "__main__":
    unittest.main()
