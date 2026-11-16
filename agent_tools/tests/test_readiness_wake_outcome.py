"""A display wake gets a measured budget, and its delivered outcome is retained and settled.

Native contacts of 2026-11-09 on raw QEMU Windows clone 9059be98, desktop alias
windows-raw9059be98-desktop-v1, with three other clones building on the same host:

- 04794d9d (readiness-lease-acquire): the readiness check observed the display awake
  (35 s); its final revalidation, 36 s later, found it asleep and refused
  prepared_context_stale before anything was recorded (native failure 50f39815).
- 5d77b355 (readiness-lease-acquire): observe 41.9 s, wake 46.5 s with the input
  submitted, then the next observe ran past the 180 s budget: readiness_deadline, and
  the delivered wake (journal 22dbf542) kept no outcome (native failure d09d630d).
- 9c93fd36 (readiness-ensure, unlock) 35 minutes later: 22dbf542 was still a consumed
  dispatch without an outcome, so the call observed it to its deadline and refused
  recovery_outcome_unknown, dispatching nothing (native failure 00e5bc48).

The controlled desktop charges every packet the measured time on a fake clock and proves
a delivered wake the way the Windows backend does, from its own retained reply. The
backend's proof itself runs through the real recover/_run packet files at the end, and
once more through a registered alias's own adapter.

Natively 9c93fd36 found the session locked with its display asleep: the status right
before it (152459) shows ordinary "locked", display "sleeping" and session
1:134386955862966249, the session of journal record 22dbf542.
"""
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import types
import unittest
from unittest import mock
from uuid import UUID, uuid4, uuid5

from agent_tools import readiness as r
from agent_tools import readiness_providers as providers
from agent_tools import readiness_recovery_status as recovery_status

# Measured on clone 9059be98 (operation 5d77b355): each packet plus its admission.
OBSERVE = 41.9 + 22.0
WAKE = 46.5 + 20.0
# The day's measured maxima that WAKE_BUDGET is sized by: 3 x (68.1 + 22) + (46.5 + 22) = 338.8 s.
OBSERVE_MAX = 68.1 + 22.0
WAKE_MAX = 46.5 + 22.0
GUI = r.Requirements(frozenset({"interactive_desktop"}), frozenset({"reconnect", "wake_display", "login"}))
HEADLESS = r.Requirements(frozenset({"guest_agent"}), frozenset({"reconnect"}))
# The counter start's own readiness: guest_agent with reconnect, resume and start.
COUNTER = r.Requirements(frozenset({"guest_agent"}), frozenset({"reconnect", "resume", "start"}))
NATIVE_BUDGET = 180.0


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(0.0, seconds)


class Desktop:
    """A controlled registered Windows desktop; packets cost their measured time."""
    capabilities = frozenset({"reconnect", "wake_display", "login"})

    def __init__(self, clock):
        self.clock = clock
        self.observation = r.Observation(
            "windows:archlinux:9059be98", "9059be98", connection="qmp:2246906|qmp:2246906",
            boot="2026-11-09T10:46:24.5000000Z", account="S-1-5-21-1-2-3-1000", session="1:134386955862966249",
            transport="ready", guest="running", guest_agent=True, ordinary_session="ready", display="ready",
            trusted=True, owned=True, integrity=True, credential_available=True)
        self.effects = []
        self.delivered = set()
        self.wake_applies = True
        self.reply_lost = False
        self.retains_replies = True
        self.bookkeeping = []
        self.proof_digest = None
        self.costs = (OBSERVE, WAKE)
        self.observations = 0

    def observe(self, requirements, deadline):
        self.clock.now += self.costs[0]
        self.observations += 1
        if "interactive_desktop" in requirements.required:
            return self.observation
        return replace(self.observation, display="unknown")

    def recover(self, action, recovery_identity, observed, deadline):
        if action not in {"wake_display", "login"}:
            raise AssertionError("only a display wake and a sign-in are qualified here: " + action)
        self.clock.now += self.costs[1]
        self.effects.append((action, recovery_identity))
        if action == "login":
            self.observation = replace(self.observation, ordinary_session="ready")
            return
        if self.wake_applies:
            self.observation = replace(self.observation, display="ready")
        if self.reply_lost:
            raise ConnectionError("reply lost after the packet left")
        self.delivered.add(recovery_identity)

    def reconcile_ready(self, ready, *, deadline):
        if self.bookkeeping:
            self.bookkeeping.pop(0)()

    def reconcile_recovery(self, action, recovery_identity, observed, deadline, attempt, dispatch_digest):
        # The backend reads its own retained reply: submitted, input submitted.
        if action != "wake_display" or not self.retains_replies or recovery_identity not in self.delivered:
            return None
        proof = hashlib.sha256(("retained-wake-reply:" + recovery_identity).encode()).hexdigest()
        return r.RecoveryAcknowledged(recovery_identity, attempt, self.proof_digest or dispatch_digest, proof)

    def sleep_display(self):
        self.observation = replace(self.observation, display="sleeping")


@unittest.skipUnless(os.name == "posix", "private readiness journal requires POSIX custody")
class WakeOutcomeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="wake-outcome-")
        self.addCleanup(directory.cleanup)
        self.journal = Path(directory.name)
        self.clock = Clock()
        self.desktop = Desktop(self.clock)

    def ensure(self, requirements=GUI, *, deadline=None):
        context = r.Context(self.desktop.observation.target, self.desktop.observation.machine, self.desktop,
                            r.RecoveryJournal(self.journal), deadline=deadline, clock=self.clock, sleep=self.clock.sleep)
        return r.ensure_ready(context, requirements, str(uuid4()))

    def records(self, prefix):
        return sorted(path.name for path in self.journal.glob(prefix + "*.json"))

    def refused_acquire_after_its_wake(self):
        """5d77b355: asleep, one wake delivered, then the native 180 s budget runs out."""
        self.desktop.sleep_display()
        with self.assertRaises(r.ReadinessBlocked) as error:
            self.ensure(deadline=self.clock() + NATIVE_BUDGET)
        self.assertEqual("readiness_deadline", error.exception.reason)
        self.assertEqual(1, len(self.desktop.effects))

    def status(self):
        value = recovery_status.inspect(self.journal, target=self.desktop.observation.target,
                                        machine=self.desktop.observation.machine)
        self.assertEqual("observed", value["state"], value)
        return value

    # 04794d9d
    def test_04794d9d_display_asleep_at_revalidation_RED_refused_GREEN_woken_once(self):
        self.desktop.bookkeeping = [self.desktop.sleep_display]
        try:
            ready = self.ensure()
        except r.ReadinessBlocked as error:
            self.fail("refused " + error.reason + " although nothing was recorded and a wake is permitted")
        self.assertEqual(["wake_display"], [action for action, _ in self.desktop.effects])
        self.assertEqual(self.desktop.observation.session, ready.session)
        self.assertEqual("ready", self.desktop.observation.display)

    def test_another_generation_during_bookkeeping_still_refuses_with_nothing_sent(self):
        def relogon():
            self.desktop.observation = replace(self.desktop.observation, session="1:134386999999999999")
        self.desktop.bookkeeping = [relogon]
        with self.assertRaises(r.ReadinessBlocked) as error:
            self.ensure()
        self.assertEqual("prepared_context_stale", error.exception.reason)
        self.assertEqual([], self.desktop.effects)

    def test_fixed_a_display_that_slept_without_a_permitted_wake_refuses_with_nothing_sent(self):
        self.desktop.bookkeeping = [self.desktop.sleep_display]
        with self.assertRaises(r.ReadinessBlocked) as error:
            self.ensure(r.Requirements(frozenset({"interactive_desktop"}), frozenset({"reconnect"})))
        self.assertEqual("recovery_not_permitted", error.exception.reason)
        self.assertEqual([], self.desktop.effects)

    # 5d77b355
    def test_5d77b355_wake_under_measured_load_RED_deadline_GREEN_ready(self):
        self.desktop.sleep_display()
        try:
            self.ensure()
        except r.ReadinessBlocked as error:
            self.fail("a measured wake ran out of its budget: " + error.reason)
        elapsed = self.clock() - 1000.0
        self.assertGreater(elapsed, NATIVE_BUDGET)
        self.assertLessEqual(elapsed, getattr(r, "WAKE_BUDGET", NATIVE_BUDGET))
        self.assertEqual(1, len(self.desktop.effects))

    def test_04794d9d_at_the_measured_maxima_RED_wake_budget_below_338_8_s_GREEN_ready(self):
        # The path WAKE_BUDGET is sized by: an observation, the final revalidation that finds
        # the display asleep, the wake and the next observation, each at the day's maximum.
        self.desktop.costs = (OBSERVE_MAX, WAKE_MAX)
        self.desktop.bookkeeping = [self.desktop.sleep_display]
        ended, observe = [], self.desktop.observe

        def timed(requirements, deadline):
            value = observe(requirements, deadline)
            ended.append(round(self.clock() - 1000.0, 1))
            return value
        self.desktop.observe = timed
        try:
            self.ensure()
        except r.ReadinessBlocked as error:
            self.fail("the measured maxima ran out of the wake budget: " + error.reason)
        self.assertEqual(["wake_display"], [action for action, _ in self.desktop.effects])
        self.assertEqual([90.1, 180.2, 338.8], ended[:3])
        self.assertLess(ended[2], r.WAKE_BUDGET)

    def test_5d77b355_refused_after_its_wake_RED_no_outcome_GREEN_delivery_retained(self):
        self.refused_acquire_after_its_wake()
        self.assertEqual(1, len(self.records("acknowledged-")),
                         "the refused call left its own delivered wake without any recorded outcome")
        self.assertEqual([], self.records("completed-"))

    def test_a_caller_cap_still_wins_over_the_wake_budget(self):
        self.desktop.sleep_display()
        with self.assertRaises(r.ReadinessBlocked) as error:
            self.ensure(deadline=self.clock() + 150.0)
        self.assertEqual("readiness_deadline", error.exception.reason)
        self.assertLessEqual(self.clock() - 1000.0, 150.0 + OBSERVE)
        self.assertEqual(1, len(self.desktop.effects))

    # 9c93fd36
    def test_9c93fd36_expired_delivered_wake_RED_outcome_unknown_GREEN_new_wake_and_ready(self):
        self.refused_acquire_after_its_wake()
        self.clock.now += 35 * 60
        self.desktop.sleep_display()
        try:
            self.ensure()
        except r.ReadinessBlocked as error:
            self.fail("an expired delivered wake blocked the next ensure: " + error.reason)
        self.assertEqual(2, len(self.desktop.effects))
        self.assertEqual(2, len({identity for _, identity in self.desktop.effects}))
        self.assertEqual("ready", self.desktop.observation.display)

    def test_9c93fd36_locked_and_asleep_in_the_wakes_session_RED_outcome_unknown_GREEN_settled_then_wake_and_sign_in(self):
        # The native state: the same boot, account and session as the delivered wake, now locked and asleep.
        self.refused_acquire_after_its_wake()
        old = self.desktop.effects[0][1]
        self.clock.now += 35 * 60
        self.desktop.observation = replace(self.desktop.observation, ordinary_session="locked", display="sleeping")
        try:
            ready = self.ensure()
        except r.ReadinessBlocked as error:
            self.fail("the delivered wake of the locked session blocked its unlock: " + error.reason)
        self.assertEqual(["wake_display", "wake_display", "login"], [action for action, _ in self.desktop.effects])
        self.assertNotEqual(old, self.desktop.effects[1][1])
        self.assertEqual("acknowledged", json.loads((self.journal / ("completed-" + old + ".json")).read_bytes())["state"])
        self.assertEqual(("ready", "ready"), (self.desktop.observation.ordinary_session, self.desktop.observation.display))
        self.assertEqual(self.desktop.observation.session, ready.session)

    def test_22dbf542_pre_fix_journal_RED_outcome_unknown_GREEN_settled_from_the_retained_reply(self):
        # The pre-fix core recorded no outcome; the backend's retained reply is still there.
        self.desktop.retains_replies = False
        self.refused_acquire_after_its_wake()
        self.assertEqual([], self.records("acknowledged-"))
        self.clock.now += 35 * 60
        self.desktop.sleep_display()
        self.desktop.retains_replies = True
        try:
            self.ensure()
        except r.ReadinessBlocked as error:
            self.fail("the retained delivery reply did not settle the old wake: " + error.reason)
        self.assertEqual(2, len({identity for _, identity in self.desktop.effects}))
        completed = [json.loads((self.journal / name).read_bytes()) for name in self.records("completed-")]
        self.assertEqual(["acknowledged", "observed"], sorted(value["state"] for value in completed))

    def test_recovery_status_RED_outcome_unknown_GREEN_acknowledged_then_settled(self):
        self.refused_acquire_after_its_wake()
        row = self.status()["recoveries"]
        self.assertEqual(1, len(row))
        self.assertEqual(("acknowledged", True, False), (row[0]["state"], row[0].get("deliveryAcknowledged"),
                                                          row[0].get("completionAcknowledged")))
        self.assertEqual(0, self.status()["pendingCount"])
        self.clock.now += 35 * 60
        self.desktop.sleep_display()
        self.ensure()
        rows = {row["recoveryId"]: row for row in self.status()["recoveries"]}
        states = sorted(row["state"] for row in rows.values())
        self.assertEqual(["acknowledged_complete", "observed_complete"], states)

    # Controls: no absence, no other session, no headless observation ever settles a wake.
    def test_a_lost_wake_reply_is_never_settled_or_replayed(self):
        self.desktop.wake_applies = False
        self.desktop.reply_lost = True
        self.desktop.sleep_display()
        for _ in range(2):
            with self.assertRaises(r.ReadinessBlocked) as error:
                self.ensure()
            self.assertEqual("recovery_outcome_unknown", error.exception.reason)
        self.assertEqual(1, len(self.desktop.effects))
        self.assertEqual([], self.records("acknowledged-") + self.records("completed-"))

    def test_a_headless_observation_never_settles_a_delivered_wake(self):
        self.refused_acquire_after_its_wake()
        self.clock.now += 35 * 60
        self.desktop.sleep_display()
        self.ensure(HEADLESS)
        self.assertEqual([], self.records("completed-"))
        self.assertEqual(1, len(self.desktop.effects))

    def test_a_recorded_unsettled_wake_RED_costs_each_counter_start_an_observation_GREEN_none(self):
        # Every later headless ensure proves the same retained reply again. Recording it again
        # changes nothing, so it must not cost another observation of the normal 180 s budget.
        self.refused_acquire_after_its_wake()
        self.assertEqual(1, len(self.records("acknowledged-")))
        self.clock.now += 35 * 60
        self.desktop.sleep_display()
        self.desktop.costs = (OBSERVE_MAX, WAKE_MAX)
        for _ in range(2):
            self.desktop.observations = 0
            try:
                self.ensure(COUNTER)
            except r.ReadinessBlocked as error:
                self.fail("a recorded delivery spent the counter start's readiness budget: " + error.reason)
            # The observation and the final revalidation after reconcile_ready, as with no pending wake.
            self.assertEqual(2, self.desktop.observations)
        self.assertEqual([], self.records("completed-"))
        self.assertEqual(1, len(self.records("acknowledged-")))
        self.assertEqual(1, len(self.desktop.effects))

    def test_another_session_never_settles_the_old_sessions_wake_by_its_delivery(self):
        # Only the same boot, account and session settle a delivered wake whose display
        # sleeps again; an awake display anywhere still closes it by the original rule.
        self.refused_acquire_after_its_wake()
        old = self.desktop.effects[0][1]
        self.clock.now += 35 * 60
        self.desktop.observation = replace(self.desktop.observation, session="1:134386999999999999", display="sleeping")
        with self.assertRaises(r.ReadinessBlocked) as error:
            self.ensure(r.Requirements(frozenset({"interactive_desktop"}), frozenset({"reconnect"})))
        self.assertEqual("recovery_not_permitted", error.exception.reason)
        self.assertFalse((self.journal / ("completed-" + old + ".json")).exists())
        self.assertEqual(1, len(self.desktop.effects))

    def test_fixed_a_proof_for_another_dispatch_fails_closed(self):
        self.desktop.proof_digest = "0" * 64
        self.desktop.sleep_display()
        with self.assertRaises(r.ReadinessBlocked) as error:
            self.ensure()
        self.assertEqual("recovery_acknowledgement_invalid", error.exception.reason)
        self.assertEqual([], self.records("acknowledged-") + self.records("completed-"))

    def test_fixed_a_delivered_attempt_is_never_proven_unsubmitted_later(self):
        self.refused_acquire_after_its_wake()
        recovery = self.desktop.effects[0][1]
        dispatch = json.loads((self.journal / ("dispatch-" + recovery + "-1.json")).read_bytes())
        proof = r.RecoveryUnsubmitted(recovery, 1, dispatch["dispatchDigest"], "1" * 64)
        with r.RecoveryJournal(self.journal).locked() as journal:
            self.assertFalse(journal.record_unsubmitted(dispatch, proof))
        self.assertEqual([], self.records("unsubmitted-"))


class ProviderAcceptanceTests(unittest.TestCase):
    def test_fixed_the_windows_adapter_accepts_an_acknowledgement_only_for_its_exact_wake_dispatch(self):
        from agent_tools import readiness_windows as windows
        clock = Clock()
        observed = Desktop(clock).observation
        recovery, digest = "a" * 64, "b" * 64
        answers = {}
        backend = types.SimpleNamespace(capabilities=frozenset({"reconnect", "wake_display"}),
                                        reconcile_recovery=lambda *args: answers["value"])
        adapter = windows.WindowsAdapter("raw-qemu-windows", observed.target, observed.machine, backend)
        answers["value"] = r.RecoveryAcknowledged(recovery, 1, digest, "c" * 64)
        self.assertIs(answers["value"], adapter.reconcile_recovery("wake_display", recovery, observed, 0, 1, digest))
        with self.assertRaises(providers.ProviderError):
            adapter.reconcile_recovery("reconnect", recovery, observed, 0, 1, digest)
        with self.assertRaises(providers.ProviderError):
            adapter.reconcile_recovery("wake_display", recovery, observed, 0, 1, "d" * 64)
        answers["value"] = None
        self.assertIsNone(adapter.reconcile_recovery("wake_display", recovery, observed, 0, 1, digest))
        # The shared provider facade, pinned by the Android and macOS lanes too, is unchanged.
        answers["value"] = r.RecoveryAcknowledged(recovery, 1, digest, "c" * 64)
        shared = providers.ProviderAdapter("raw-qemu-windows", observed.target, observed.machine, backend)
        with self.assertRaises(providers.ProviderError):
            shared.reconcile_recovery("wake_display", recovery, observed, 0, 1, digest)


@unittest.skipUnless(os.name == "posix", "POSIX private-file custody")
class WindowsRetainedReplyTests(unittest.TestCase):
    """The real backend writes its packet, reply and callback; only the transport is fake."""

    def deliver(self, reply_changes=(), *, tamper=None, recovery=None):
        from agent_tools import readiness_windows as windows
        from agent_tools.tests.test_readiness_windows import snapshot, SID
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        backend = windows.WindowsBackend(root, snapshot()["binding"], SID, capabilities=frozenset({"reconnect", "wake_display"}))
        backend.last_facts = dict(snapshot()["host"])
        delivered = hashlib.sha256(b"wake 5dcaa820").hexdigest()
        operation = str(uuid5(UUID(backend.machine), delivered))
        reply = {"state": "submitted", "guest": "running", "wakeInputSubmitted": True, "machine": backend.machine,
                 "provider": "raw-qemu-windows", "operationId": operation, "hostBoot": backend.binding["context"]["hostBootId"],
                 "controlConnection": "qmp:42", "guestAgent": False, "actor": {"pid": 123, "startTicks": 456},
                 "sessionFacts": None, "displayFacts": None, "idleFacts": None, "hostWork": None}
        reply.update(dict(reply_changes))
        observed = r.Observation(backend.target, backend.machine, connection="qmp:42|qmp:42", boot="2026-10-20T09:04:39.5000000Z",
                                 account=SID, session="2:1234", transport="ready", guest="running", guest_agent=True,
                                 ordinary_session="ready", display="sleeping", trusted=True, owned=True, integrity=True)

        @contextmanager
        def admitted(*args, **kwargs):
            yield types.SimpleNamespace(revalidate=lambda: None, ready=None)

        with mock.patch.object(windows.transport, "admitted_transport", admitted), \
                mock.patch.object(windows.transport, "load_config", return_value={}), \
                mock.patch.object(windows.transport, "build_ssh_argv", return_value=["ssh"]), \
                mock.patch.object(windows.transport, "run_ssh",
                                  return_value=subprocess.CompletedProcess([], 0, json.dumps(reply).encode(), b"")):
            try:
                backend.recover("wake_display", delivered, observed, time.monotonic() + 120)
            except providers.ProviderError:
                pass
        if tamper is not None:
            tamper(root / ".runtime/readiness-windows" / operation)
        prove = getattr(backend, "reconcile_recovery", None)
        asked = recovery or delivered
        proof = prove("wake_display", asked, observed, time.monotonic() + 30, 1, "e" * 64) if callable(prove) else None
        return windows, backend, observed, asked, proof

    def test_5dcaa820_retained_reply_RED_no_proof_GREEN_proves_the_delivered_wake(self):
        windows, backend, observed, recovery, proof = self.deliver()
        self.assertIsNotNone(proof, "the backend cannot prove its own delivered wake from its retained reply")
        self.assertIs(r.RecoveryAcknowledged, type(proof))
        self.assertEqual((recovery, 1, "e" * 64), (proof.recovery_id, proof.attempt, proof.dispatch_digest))
        adapter = windows.WindowsAdapter("raw-qemu-windows", backend.target, backend.machine, backend)
        accepted = adapter.reconcile_recovery("wake_display", recovery, observed, time.monotonic() + 30, 1, "e" * 64)
        self.assertEqual(proof.proof_sha256, accepted.proof_sha256)

    def test_no_input_submitted_a_refused_reply_another_recovery_or_an_altered_reply_prove_nothing(self):
        self.assertIsNone(self.deliver({"wakeInputSubmitted": False})[4])
        self.assertIsNone(self.deliver({"state": "blocked"})[4])
        self.assertIsNone(self.deliver({"hostBoot": "00000000-0000-4000-8000-000000000000"})[4])
        self.assertIsNone(self.deliver(recovery="f" * 64)[4])

        def alter(directory):
            path = next(directory.glob("wake_display-*.stdout.private"))
            body = json.loads(path.read_bytes())
            body["guest"] = "stopped"
            path.write_bytes(json.dumps(body).encode())
        self.assertIsNone(self.deliver(tamper=alter)[4])


@unittest.skipUnless(os.name == "posix", "POSIX private-file custody")
class RegisteredAliasAdapterTests(unittest.TestCase):
    """A registered Windows alias builds WindowsAdapter, so its wake's delivery reaches the journal.

    The shared ProviderAdapter refuses the delivery proof and the core swallows that
    refusal, so a loader that builds it instead drops every acknowledgement silently.
    The managed (schema 2) loader is checked in test_windows_managed_admission.
    """
    SID = "S-1-5-21-1-2-3-1004"

    def register(self):
        from agent_tools import readiness_fixture_registry as registry
        from agent_tools import readiness_windows_registration as registration
        from agent_tools.tests.test_native_vm_spec import request
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        root.chmod(0o700)
        machine = str(uuid4())
        spec = request()
        spec["deploymentId"] = machine
        intent = {"spec": spec, "setup": {"imageName": "Windows 11 Pro", "locale": "en-US", "user": "fixtureuser",
                                          "administrator": "fixtureadmin"},
                  "context": {"hostBootId": str(uuid4()), "pending": []}, "correlationId": "a" * 32, "mode": "start",
                  "callerSha256": "b" * 64}
        for path in (root / ".rag_index", root / ".rag_index/windows-vm-deploy-intents", root / ".runtime"):
            path.mkdir(mode=0o700)
        path = root / ".rag_index/windows-vm-deploy-intents" / (machine + ".intent.json")
        path.write_text(json.dumps(intent))
        path.chmod(0o600)
        proof = registration.write_qualification(root, machine, "wake_display", evidence={"operationId": str(uuid4())})
        registration.register(root, "windows-raw-wake-v1", machine, self.SID, qualifications={"wake_display": proof})
        return registry.registered_fixture(root, "windows-raw-wake-v1")

    def test_fixed_the_registered_alias_builds_the_windows_adapter(self):
        from agent_tools import readiness_windows as windows
        fixture = self.register()
        self.assertIs(windows.WindowsAdapter, type(fixture.adapter))
        self.assertEqual(frozenset({"wake_display"}), fixture.adapter.capabilities)

    def test_fixed_a_wake_through_the_registered_alias_records_its_delivery(self):
        from agent_tools import readiness_windows as windows
        fixture = self.register()
        backend = fixture.adapter.backend
        display, sent = ["sleeping"], {}
        host = {"actor": {"pid": 123, "startTicks": 456}, "hostBoot": backend.binding["context"]["hostBootId"],
                "controlConnection": "qmp:42"}

        def observe(requirements, deadline):
            backend.last_facts = dict(host)
            return r.Observation(fixture.target, fixture.machine, connection="qmp:42|qmp:42", boot="2026-10-20T09:04:39.5000000Z",
                                 account=self.SID, session="2:1234", transport="ready", guest="running", guest_agent=True,
                                 ordinary_session="ready", display=display[0], trusted=True, owned=True, integrity=True)
        real_run = backend._run

        def run(mode, operation, deadline, **options):
            sent["operation"] = operation
            return real_run(mode, operation, deadline, **options)

        def ssh(*args, **kwargs):
            # The real wake packet was saved; its input moves the pointer and the display wakes.
            display[0] = "ready"
            reply = {**host, "state": "submitted", "guest": "running", "wakeInputSubmitted": True, "machine": backend.machine,
                     "provider": backend.provider, "operationId": sent["operation"], "guestAgent": True,
                     "sessionFacts": None, "displayFacts": None, "idleFacts": None, "hostWork": None}
            return subprocess.CompletedProcess([], 0, json.dumps(reply).encode(), b"")

        @contextmanager
        def admitted(*args, **kwargs):
            yield types.SimpleNamespace(revalidate=lambda: None, ready=None)

        backend.observe, backend._run = observe, run
        with mock.patch.object(windows.transport, "admitted_transport", admitted), \
                mock.patch.object(windows.transport, "load_config", return_value={}), \
                mock.patch.object(windows.transport, "build_ssh_argv", return_value=["ssh"]), \
                mock.patch.object(windows.transport, "run_ssh", side_effect=ssh):
            ready = r.ensure_ready(fixture.context(deadline=time.monotonic() + 120), GUI, str(uuid4()))
        self.assertEqual("2:1234", ready.session)
        journal = fixture.journal_directory
        acknowledged = sorted(path.name for path in journal.glob("acknowledged-*.json"))
        self.assertEqual(1, len(acknowledged), "the registered alias dropped its delivered wake's proof")
        recovery = acknowledged[0][len("acknowledged-"):-len("-1.json")]
        self.assertEqual("observed", json.loads((journal / ("completed-" + recovery + ".json")).read_bytes())["state"])


if __name__ == "__main__":
    unittest.main()
