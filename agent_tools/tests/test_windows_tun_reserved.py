"""windows-scoped-tun reserved cases, offline: dns-ws-ssh-cache-resources and pipe-storage-races.

The three rows (resources-grant, ssh-grant, stage-squat), their place in the scenario table and the decision table, the
stages' hooks around the request, the case module's own checks, the TUN collector's stage observation and the dedicated
driver's grant steps. Every native boundary is a declared fake or a temporary folder of this test: no prompt, broker,
pipe, route, guest or socket is touched, and nothing here proves a Windows behaviour. The native first contact is the
operator sequence in the T9 evidence report.
"""
from __future__ import annotations

import base64
import ctypes
import hashlib
import inspect
import json
import os
from pathlib import Path, PureWindowsPath
import tempfile
import types
import unittest
from unittest import mock
import uuid

from agent_tools import native_scenario_windows as windows
from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools import windows_scenario_proxy as proxy
from agent_tools import windows_ssh_relay_fixture as relay_fixture
from agent_tools import windows_tun_native_observer as tun_observer
from agent_tools import windows_tun_stages as stages
from agent_tools import windows_uac_decision as decision
from agent_tools.tests.test_windows_tun_stages import ADMIN, ORDINARY, PurePathReading, StageWorld
from agent_tools.windows_public_updater import update_receipts

try:  # Imported lazily so that, on a tree without the case module, every other test still fails for its own reason.
    from agent_tools import windows_tun_reserved_cases as reserved
except ImportError:
    reserved = None

# The reserved rows as the requirement names them, independent of the module under test.
VARIANTS = frozenset({"resources-grant", "ssh-grant", "stage-squat"})
PENDING = {"resources-grant": "Owned resources", "ssh-grant": "Owned B", "stage-squat": "Owned resources"}
REFUSED = "Owned resources refused"
SSH_TAG = "vpn-control-home-ssh"  # HomeSshRouteConfigBuilder.SSH_OUTBOUND_TAG

ROOT = Path(__file__).resolve().parents[2]
JOB = "5f5f5f5f-1111-4222-8333-944455556666"
STAGE = "C:\\ProgramData\\vpn-control-vpn-" + JOB
PIPE = "vpn-control-vpn-0a0a0a0a-2222-4333-8444-555566667777"
OWNER_PID, OWNER_BIRTH = 913, 134368653065000006
SOCKS_PORT = 40123
_T = "windows-scoped-tun."
INVALID = ctypes.c_void_p(-1).value


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


CONTROLLER = "controller-1"
ACCEPTED = {"schemaVersion": 1, "controllerId": CONTROLLER, "requestId": "7a7a7a7a-1111-4222-8333-944455556666", "ok": True,
            "code": "ACCEPTED", "final": False, "operationId": "23c36015-4482-4324-ac20-c82ac6bdd097"}
# The public CLI's exit for each ControlCode (ControlModels.kt at 93b7ac64).
CODE_EXITS = {"OK": 0, "ACCEPTED": 0, "PERMISSION_DENIED": 1, "BUSY": 1, "CONFLICT": 1, "UNSUPPORTED": 1, "CANCELLED": 130,
              "UNAVAILABLE": 2, "OUTCOME_UNKNOWN": 2, "TIMEOUT": 2}


def status(code="ACCEPTED"):
    """One `operations status` reply for the row's own operation: still pending, or final with ``code``."""
    final = code != "ACCEPTED"
    return CODE_EXITS[code], {"schemaVersion": 1, "controllerId": CONTROLLER, "operationId": ACCEPTED["operationId"],
                              "code": code, "final": final, "ok": CODE_EXITS[code] == 0}


def ask(case, state):
    """The case's step before the decision, with the row's accepted request where the case takes it."""
    if "accepted" in inspect.signature(case.before_prompt).parameters:
        return case.before_prompt(state, ACCEPTED)
    return case.before_prompt(state)


class TableTests(unittest.TestCase):
    """The reserved scenarios name built rows, each with its one approval and the files its case needs."""

    def test_both_reserved_scenarios_are_mapped_to_their_rows(self):
        table = windows.MATRIX_SCENARIOS["windows-scoped-vpn"]
        self.assertEqual((_T + "resources-grant", _T + "ssh-grant"), table["dns-ws-ssh-cache-resources"])
        self.assertEqual((_T + "stage-squat", _T + "resources-grant"), table["pipe-storage-races"])
        for name in {*table["dns-ws-ssh-cache-resources"], *table["pipe-storage-races"]}:
            with self.subTest(row=name):
                row = windows.RECIPES[name]
                self.assertIsNone(row.get("refusal"))
                self.assertEqual(({"prompt": "vpn-broker", "decision": "approve", "event": "scoped-tun-awaiting-current-input"}, True, False),
                                 (row["uac"], row.get("approveJoin"), row["denyJoin"]))
                roles = {role: path for path, role, _ in row["guestFiles"]}
                self.assertEqual("agent_tools/windows_tun_reserved_cases.py", roles["reserved"])
                self.assertEqual(name.endswith("ssh-grant"), roles.get("relay") == "agent_tools/windows_ssh_relay_fixture.py")

    def test_only_the_two_grants_take_the_collector_route_and_the_squat_none(self):
        for variant, grant in (("resources-grant", True), ("ssh-grant", True), ("stage-squat", False)):
            with self.subTest(variant=variant):
                row = windows.RECIPES[_T + variant]
                roles = {role for _, role, _ in row["guestFiles"]}
                self.assertEqual(grant, {"sampler", "collector"} <= roles)
                self.assertEqual(({"collectorStages": ("tun",), "finalStage": "tun"} if grant else {}),
                                 {key: value for key, value in row["tun"].items() if key != "variant"})
                self.assertEqual(grant, variant in dedicated_driver.TUN_GRANT_VARIANTS)
                self.assertEqual(grant, variant in proxy.TUN_GRANT_VARIANTS)
                self.assertIn(variant, dedicated_driver.TUN_VARIANTS)
                self.assertIn(variant, stages.VARIANTS)

    def test_each_reserved_row_has_its_one_approve_decision(self):
        for variant in sorted(VARIANTS):
            with self.subTest(variant=variant):
                self.assertEqual({"prompt": "vpn-broker", "decision": "approve", "event": "scoped-tun-awaiting-current-input",
                                  "field": "variant", "value": variant, "variant": None, "sidEvent": "scoped-tun-awaiting-current-input",
                                  "sidField": "expectedApprovingAdminSid"}, decision.ROWS[_T + variant])

    def test_the_driver_pins_the_case_module_and_the_relay(self):
        self.assertEqual(VARIANTS, dedicated_driver.RESERVED_VARIANTS)
        self.assertEqual(VARIANTS, proxy.TUN_RESERVED_VARIANTS)
        self.assertEqual(sha((ROOT / "agent_tools/windows_tun_reserved_cases.py").read_bytes()), dedicated_driver.RESERVED_SHA)
        self.assertEqual(sha((ROOT / "agent_tools/windows_ssh_relay_fixture.py").read_bytes()), dedicated_driver.RELAY_SHA)

    def test_a_reserved_harness_names_its_role_and_pending_location(self):
        from agent_tools.tests.test_windows_tun_stages import GeneratedInputTests
        helper = GeneratedInputTests()
        for variant in sorted(VARIANTS):
            with self.subTest(variant=variant):
                value = helper.harness(variant, dict(GeneratedInputTests.TUN))["LIFECYCLE_INPUTS"]
                self.assertEqual(PENDING[variant], value["tun"]["pendingLocation"])
                self.assertEqual(GeneratedInputTests.PATHS["file:reserved"], value["modules"]["reserved"])
                self.assertEqual(variant == "ssh-grant", "relay" in value["modules"])


class FakeCase:
    """windows_tun_reserved_cases.Case as the stages call it: each step recorded beside the owner's events."""
    REFUSED = REFUSED
    EndedBeforeJournal = getattr(reserved, "EndedBeforeJournal", type("EndedBeforeJournal", (Exception,), {}))

    def __init__(self, test, variant, terminals=(), journal_left=False, touched=False, then=None, ended=None):
        self.test, self.variant, self.pending, self.job = test, variant, PENDING[variant], JOB
        self.terminals, self.journal_left, self.touched, self.then = list(terminals), journal_left, touched, then
        self.ended = ended  # The product's final refusal, read before any journal: the case's EndedBeforeJournal.

    def log(self, step):
        self.test.calls.append((step, len(self.test.owner.events)))

    def prepare(self, state, runtime):
        self.log("prepare")
        return self.pending

    def before_prompt(self, state, accepted=None):
        self.log("before-prompt")
        if self.ended is not None:
            if self.then is not None:
                self.then()
            ended = self.EndedBeforeJournal("scoped-tun-reserved-ended-before-journal")
            ended.terminal = {"code": self.ended, "final": True, "ok": False}
            raise ended
        return {"jobId": JOB}

    def terminal(self, state, accepted, codes):
        self.log("terminal:" + ",".join(sorted(codes)))
        code = self.terminals.pop(0)
        if self.then is not None:
            self.then()
        if code not in codes:
            raise AssertionError("reserved-operation-unexpected-terminal")
        return {"code": code, "final": True}

    def journals(self, workspace):
        return {JOB: ".runtime-resource-job-" + JOB + ".json"} if self.journal_left else {}

    def squat_kept_and_removed(self):
        self.log("squat-removed")
        if self.touched:
            raise AssertionError("reserved-squat-touched")


class StagesHookTests(StageWorld):
    """windows_tun_stages around a reserved row's request: the refused capture before it, the case's hook before the
    decision event, and the squat's own terminal."""

    def runtime(self):
        runtime = super().runtime()
        result = runtime.result

        def selecting(owner, workspace, identity, *arguments, **options):
            if arguments[-3:-1] == ("locations", "select") and arguments[-1] != "Owned B":
                self.calls.append(arguments)
                self.status["selectedLocationId"] = arguments[-1]
                self.revision += 1
                return {"data": {}, "configurationRevision": self.revision}
            return result(owner, workspace, identity, *arguments, **options)
        runtime.result = selecting
        return runtime

    def begin(self, inputs=None, runtime=None, reserved_case=None):
        self.status = {"runtimeRunning": True, "activeMode": "proxy-only", "activeLocationId": "a", "selectedLocationId": "a",
                       "runtimeId": "r", "runtimeStartedAt": "t", "configuredMode": "proxy-only"}
        with mock.patch.object(stages, "Path", PurePathReading):
            return stages.begin(self.owner, self.state(), inputs or self.inputs(), runtime or self.runtime(), self.cases(),
                                self.observer, reserved=reserved_case)

    def reserved_inputs(self, variant, **changes):
        return self.inputs(variant, pendingLocation=PENDING[variant], **changes)

    def test_resources_refuses_its_capture_before_any_prompt_then_asks_once(self):
        case = FakeCase(self, "resources-grant", terminals=["UNSUPPORTED"])
        lease = self.begin(self.reserved_inputs("resources-grant"), reserved_case=case)
        kinds = [kind for kind, _ in self.owner.events]
        self.assertEqual(["scoped-tun-capture-refused-before-prompt", "scoped-tun-awaiting-current-input"], kinds)
        restarts = [call for call in self.calls if call[:1] == ("--async",)]
        self.assertEqual(2, len(restarts), "the refused capture's own restart, then the row's one request")
        selected = [call[-1] for call in self.calls if call[-3:-1] == ("locations", "select")]
        self.assertEqual([REFUSED, "Owned resources"], selected)
        steps = [call for call in self.calls if call[0] in ("prepare", "terminal:UNSUPPORTED", "before-prompt")]
        self.assertEqual([("prepare", 0), ("terminal:UNSUPPORTED", 0), ("before-prompt", 1)], steps,
                         "the case's journal step runs after the refusal and before the decision's one event")
        self.assertIs(case, lease["reserved"])
        self.assertTrue(self.owner.tun_operation_requested, "the row's own request is open")

    def test_a_capture_that_reached_a_prompt_or_left_anything_never_passes(self):
        cases = (("prompted", dict(terminals=["CANCELLED"]), "reserved-operation-unexpected-terminal"),
                 ("journal", dict(terminals=["UNSUPPORTED"], journal_left=True), "scoped-tun-refused-capture-left-a-journal"),
                 ("broker", dict(terminals=["UNSUPPORTED"], then=lambda: self.processes.append(
                     {"pid": 140, "parentPid": 71, "name": "vpn-control-vpn-broker.exe"})), "scoped-tun-unexpected-terminal-scoped-state"),
                 ("moved-a", dict(terminals=["UNSUPPORTED"], then=lambda: self.status.update(runtimeId="r2")),
                  "uac-denial-lost-active-a-or-pending-b"))
        for name, options, reason in cases:
            with self.subTest(case=name):
                self.setUp()
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.begin(self.reserved_inputs("resources-grant"), reserved_case=FakeCase(self, "resources-grant", **options))
                self.assertTrue(self.owner.tun_operation_requested, "the refused request's outcome is not shown: the owner parks")
                self.assertNotIn("scoped-tun-awaiting-current-input", [kind for kind, _ in self.owner.events])
                self.assertEqual(1, sum(1 for call in self.calls if call[:1] == ("--async",)), "never resent, never followed by the row's own")

    def test_a_reserved_row_runs_only_with_its_own_case_and_location(self):
        for inputs, case, reason in ((self.reserved_inputs("resources-grant"), None, "scoped-tun-reserved-case-binding"),
                                     (self.inputs("restart-grant"), "resources-grant", "scoped-tun-reserved-case-binding"),
                                     (self.reserved_inputs("resources-grant"), "stage-squat", "scoped-tun-reserved-case-binding"),
                                     (self.inputs("resources-grant"), "resources-grant", "scoped-tun-fixed-pending-location-admin-role"),
                                     (self.inputs("stage-squat"), "stage-squat",
                                      "scoped-tun-fixed-pending-location-admin-role")):
            with self.subTest(variant=inputs["variant"], case=case):
                self.calls.clear()
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.begin(inputs, reserved_case=None if case is None else FakeCase(self, case))
                self.assertEqual([], self.calls, "nothing was read or changed")
                self.assertFalse(getattr(self.owner, "tun_operation_requested", False))

    def test_the_squat_row_publishes_its_decision_event_only_after_its_hook(self):
        case = FakeCase(self, "stage-squat")
        self.begin(self.reserved_inputs("stage-squat"), reserved_case=case)
        self.assertEqual(["scoped-tun-awaiting-current-input"], [kind for kind, _ in self.owner.events])
        self.assertEqual([("prepare", 0), ("before-prompt", 0)], [call for call in self.calls if call[0] in ("prepare", "before-prompt")])
        self.assertEqual(1, sum(1 for call in self.calls if call[:1] == ("--async",)), "no refused capture first")

    def finish_squat(self, case):
        lease = self.begin(self.reserved_inputs("stage-squat"), reserved_case=case)
        actors = []
        cases = types.SimpleNamespace(config_bytes=lambda path: dict(lease["activeConfig"].initial),
                                      exact_actor=lambda native, actor, elevated: actors.append((actor["pid"], elevated)))
        runtime = self.runtime()
        runtime.finish_operation = lambda *args, **kwargs: self.fail("the squat reads its terminal through the case")
        return lease, stages.finish(self.owner, lease, runtime, cases, self.observer)

    def test_the_squat_passes_only_on_the_brokers_conflict_with_everything_kept(self):
        lease, outcome = self.finish_squat(FakeCase(self, "stage-squat", terminals=["CONFLICT"]))
        self.assertEqual({"terminal", "status", "nativeRecord"}, set(outcome), "a pass: no known failure, no cancellation")
        self.assertEqual("CONFLICT", lease["conflictEnd"])
        self.assertTrue(stages.settled(lease), "settled: the driver closes it like a pass")
        self.assertEqual("scoped-tun-stage-squat-refused", self.owner.events[-1][0])
        self.assertIn(("squat-removed", 1), self.calls)

    def test_a_squat_followed_touched_or_ending_otherwise_never_passes(self):
        for name, options, reason in (("ok", dict(terminals=["OK"]), "reserved-operation-unexpected-terminal"),
                                      ("touched", dict(terminals=["CONFLICT"], touched=True), "reserved-squat-touched"),
                                      ("broker-left", dict(terminals=["CONFLICT"], then=lambda: self.processes.append(
                                          {"pid": 141, "parentPid": 71, "name": "vpn-control-vpn-broker.exe"})),
                                       "scoped-tun-unexpected-terminal-scoped-state")):
            with self.subTest(case=name):
                self.setUp()
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.finish_squat(FakeCase(self, "stage-squat", **options))
                lease = self.owner.tun_operation_leases[-1]
                self.assertFalse(stages.settled(lease), "unsettled: the driver parks")
        self.setUp()
        lease, outcome = self.finish_squat(FakeCase(self, "stage-squat", terminals=["CANCELLED"]))
        self.assertEqual((True, "CANCELLED"), (outcome["cancelled"], lease["knownEnd"]), "an expired prompt is the grant's own known end")

    def test_a_request_refused_before_its_journal_closes_as_a_known_failure(self):
        """b50d0425 (2.2.19): the squat's restart was ACCEPTED and no journal came; the owner parked with the product's
        own outcome unread. A definite refusal before the journal, which the product writes ahead of UAC, left no prompt or
        broker: with A, pending B and the census as before, nothing is open and the driver closes the row."""
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-reserved-ended-before-journal$"):
            self.begin(self.reserved_inputs("stage-squat"), reserved_case=FakeCase(self, "stage-squat", ended="PERMISSION_DENIED"))
        self.assertFalse(self.owner.tun_operation_requested, "nothing is open: the driver closes the row as a known failure")
        kinds = [kind for kind, _ in self.owner.events]
        self.assertEqual(["scoped-tun-reserved-ended-before-journal"], kinds, "no decision event: nothing is asked")
        self.assertEqual({"code": "PERMISSION_DENIED", "final": True, "ok": False}, self.owner.events[-1][1]["terminal"])
        self.assertEqual(1, sum(1 for call in self.calls if call[:1] == ("--async",)), "never resent")
        lease = self.owner.tun_operation_leases[-1]
        self.assertTrue(stages.settled(lease))

    def test_a_refusal_before_the_journal_that_left_anything_keeps_the_owner_parking(self):
        cases = (("broker", lambda: self.processes.append({"pid": 142, "parentPid": 71, "name": "vpn-control-vpn-broker.exe"}),
                  False, "scoped-tun-unexpected-terminal-scoped-state"),
                 ("moved-a", lambda: self.status.update(runtimeId="r2"), False, "uac-denial-lost-active-a-or-pending-b"),
                 ("journal", None, True, "scoped-tun-reserved-journal-after-terminal"))
        for name, then, journal, reason in cases:
            with self.subTest(case=name):
                self.setUp()
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.begin(self.reserved_inputs("stage-squat"),
                               reserved_case=FakeCase(self, "stage-squat", ended="BUSY", then=then, journal_left=journal))
                self.assertTrue(self.owner.tun_operation_requested, "not shown closed: the owner parks")
                self.assertFalse(stages.settled(self.owner.tun_operation_leases[-1]))
                self.assertNotIn("scoped-tun-reserved-ended-before-journal", [kind for kind, _ in self.owner.events])


class Owner:
    """The ordinary owner as the case sees it: its root, events, park and public calls."""

    def __init__(self, root):
        self.root, self.events, self.replies, self.invoked = Path(root), [], [], []
        self.operation = str(uuid.uuid4())

    def event(self, kind, value):
        self.events.append((kind, value))

    def park(self, reason, error=None):
        raise RuntimeError("parked:" + reason)

    def invoke(self, workspace, *arguments, stdin=None):
        self.invoked.append((arguments, stdin))
        code, body = self.replies.pop(0)
        return types.SimpleNamespace(returncode=code, stdout=json.dumps(body), stderr="")


class CaseWorld(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(reserved, "no reserved case module: windows_tun_reserved_cases")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        (self.base / "fixture").mkdir()
        self.programs = self.base / "ProgramData"
        self.programs.mkdir()
        self.owner = Owner(self.base)
        self.state = {"workspace": self.workspace, "identity": "controller-1", "ready": {"advertisedSocksPort": SOCKS_PORT},
                      "inputs": {"fixtureRoot": str(self.base / "fixture")}}
        self.calls = []
        for patcher in (mock.patch.dict(os.environ, {"ProgramData": str(self.programs)}),
                        mock.patch.object(reserved.time, "sleep", lambda seconds: self.calls.append(("sleep", seconds)))):
            patcher.start()
            self.addCleanup(patcher.stop)

    def runtime(self):
        shown = {}

        def result(owner, workspace, identity, *arguments, **options):
            self.calls.append(arguments)
            if arguments[-1] == "status":
                return {"configurationRevision": 7, "data": {}}
            if arguments[-4:-1] == ("locations", "add", "--input"):
                document = json.loads(Path(arguments[-1]).read_bytes())
                shown[document["remarks"]] = document["custom_config_json"]
                return {"configurationRevision": 8}
            if arguments[-3:-1] == ("locations", "show"):
                return {"data": {"configuration": shown[arguments[-1]]}}
            return {"configurationRevision": 8}
        return types.SimpleNamespace(result=result)


class CasePreparationTests(CaseWorld):
    def test_resources_adds_its_two_custom_locations_and_the_original_rule_set(self):
        case = reserved.Case(self.owner, "resources-grant")
        self.assertEqual("Owned resources", case.prepare(self.state, self.runtime()))
        folder = self.base / reserved.FOLDER
        self.assertEqual(reserved.rules(reserved.DECOY), (folder / "rules.json").read_bytes())
        self.assertEqual(sha(reserved.rules(reserved.DECOY)), case.rules_sha256)
        added = [call[-1] for call in self.calls if call[-4:-1] == ("locations", "add", "--input")]
        names = [json.loads(Path(path).read_bytes())["remarks"] for path in added]
        self.assertEqual(["Owned resources", reserved.REFUSED], names)
        config = json.loads(json.loads(Path(added[0]).read_bytes())["custom_config_json"])
        rows = sorted((row["context"], row["type"], row["value"]) for row in tun_observer.path_rows(config))
        self.assertEqual(sorted([*reserved.URL_PATHS, ("experimental.cache_file", None, str(folder / "cache.db")),
                                 ("route.rule_set.*", "local", str(folder / "rules.json"))]), rows,
                         "every URL context once, and the two file paths the capture must stage")
        self.assertEqual("172.19.250.1/30", config["inbounds"][0]["address"][0], "the custom config brings the generated TUN")
        refused = json.loads(json.loads(Path(added[1]).read_bytes())["custom_config_json"])
        self.assertEqual({"clash_api": {"external_ui": "owned-ui"}}, refused["experimental"])

    def test_a_squat_row_adds_only_the_resources_location(self):
        reserved.Case(self.owner, "stage-squat").prepare(self.state, self.runtime())
        added = [json.loads(Path(call[-1]).read_bytes())["remarks"] for call in self.calls if call[-4:-1] == ("locations", "add", "--input")]
        self.assertEqual(["Owned resources"], added)

    def test_a_journal_before_the_row_refuses(self):
        (self.workspace / (reserved.JOURNAL_PREFIX + JOB + ".json")).write_bytes(b"{}")
        with self.assertRaisesRegex(AssertionError, "^reserved-journal-before-row$"):
            reserved.Case(self.owner, "resources-grant").prepare(self.state, self.runtime())

    def test_the_case_binds_its_variant_and_relay(self):
        for variant, relay in (("restart-grant", None), ("ssh-grant", None), ("resources-grant", relay_fixture)):
            with self.subTest(variant=variant), self.assertRaisesRegex(AssertionError, "^reserved-variant-binding$"):
                reserved.Case(self.owner, variant, relay=relay)


class BeforeDecisionTests(CaseWorld):
    """Between the request and the decision: the job's journal, and for the squat its stage folder."""

    def journal_after(self, polls, *names):
        count = {"polls": 0}

        def sleep(seconds):
            count["polls"] += 1
            if count["polls"] == polls:
                for name in names:
                    (self.workspace / name).write_bytes(b'{"job":1}')
        return sleep

    def test_the_journal_names_the_job_and_the_squat_takes_its_stage_first(self):
        case = reserved.Case(self.owner, "stage-squat")
        case.journal_baseline = {}
        with mock.patch.object(reserved.time, "sleep", self.journal_after(3, reserved.JOURNAL_PREFIX + JOB + ".json")):
            value = ask(case, self.state)
        self.assertEqual(JOB, case.job)
        stage = self.programs / ("vpn-control-vpn-" + JOB)
        self.assertEqual([reserved.CANARY], os.listdir(stage))
        self.assertEqual((JOB, str(stage)), (value["jobId"], value["squat"]["path"]))
        self.assertEqual("scoped-tun-reserved-before-decision", self.owner.events[-1][0])

    def test_a_resources_row_waits_for_its_journal_and_makes_no_folder(self):
        case = reserved.Case(self.owner, "resources-grant")
        with mock.patch.object(reserved.time, "sleep", self.journal_after(1, reserved.JOURNAL_PREFIX + JOB + ".json")):
            self.assertEqual(JOB, ask(case, self.state)["jobId"])
        self.assertEqual([], os.listdir(self.programs))
        self.assertIsNone(ask(reserved.Case(self.owner, "ssh-grant", relay=relay_fixture), self.state))

    def test_two_journals_a_bad_name_or_none_never_reach_the_decision(self):
        other = "6f6f6f6f-1111-4222-8333-944455556666"
        for names, expected in (((reserved.JOURNAL_PREFIX + JOB + ".json", reserved.JOURNAL_PREFIX + other + ".json"), "reserved-one-correlation-journal"),
                                ((reserved.JOURNAL_PREFIX + "not-a-job.json",), "reserved-journal-name")):
            with self.subTest(expected=expected):
                self.setUp()
                with mock.patch.object(reserved.time, "sleep", self.journal_after(1, *names)), \
                        self.assertRaisesRegex(AssertionError, "^" + expected + "$"):
                    ask(reserved.Case(self.owner, "stage-squat"), self.state)
                self.assertEqual([], os.listdir(self.programs), "no squat without exactly one job")

    def waiting(self, replies, journal_at_read=None):
        """No journal; the clock moves only by the case's own sleeps; each status read takes the next reply. A journal
        appears just before read number journal_at_read."""
        clock = {"now": 0.0}

        def sleep(seconds):
            clock["now"] += seconds
        self.owner.replies = list(replies)
        invoke = self.owner.invoke

        def reading(workspace, *arguments, stdin=None):
            if journal_at_read is not None and len(self.owner.invoked) + 1 == journal_at_read:
                (self.workspace / (reserved.JOURNAL_PREFIX + JOB + ".json")).write_bytes(b"{}")
            return invoke(workspace, *arguments, stdin=stdin)
        self.owner.invoke = reading
        return mock.patch.multiple(reserved.time, sleep=sleep, monotonic=lambda: clock["now"])

    def test_a_request_refused_before_its_journal_ends_the_wait_with_the_products_own_terminal(self):
        """b50d0425 (2.2.19): ACCEPTED, then no journal for 120 s, and the wait parked without reading the operation.
        Now it reads the row's own operation while it waits: a final refusal with still no journal ends the wait as the
        case's EndedBeforeJournal (which the stages close as a known failure), with that terminal in the evidence."""
        case = reserved.Case(self.owner, "stage-squat")
        with self.waiting([status(), status(), status("PERMISSION_DENIED")]):
            try:
                ask(case, self.state)
            except RuntimeError as parked:
                self.fail("the product's own refusal was never read: " + str(parked))
            except Exception as error:
                self.assertIs(reserved.EndedBeforeJournal, type(error))
                self.assertEqual("PERMISSION_DENIED", error.terminal["code"])
            else:
                self.fail("no journal, yet the case went on to the decision")
        self.assertEqual(3, len(self.owner.invoked), "one read every STATUS_SECONDS, never a resend")
        self.assertTrue(all(arguments[-3:] == ("operations", "status", ACCEPTED["operationId"]) for arguments, _ in self.owner.invoked))
        self.assertEqual(("scoped-tun-reserved-journal-wait", 3, "PERMISSION_DENIED"),
                         (self.owner.events[-1][0], self.owner.events[-1][1]["statusReads"], self.owner.events[-1][1]["lastStatus"]["code"]))
        self.assertEqual([], os.listdir(self.programs), "no squat")
        self.assertIsNone(case.job)

    def test_an_operation_still_pending_at_the_bound_parks_with_what_it_read(self):
        reads = int(reserved.JOURNAL_SECONDS // getattr(reserved, "STATUS_SECONDS", 5)) + 2
        with self.waiting([status()] * reads), self.assertRaisesRegex(
                RuntimeError, "^parked:scoped-tun-reserved-journal-absent-no-replay$"):
            ask(reserved.Case(self.owner, "stage-squat"), self.state)
        self.assertTrue(self.owner.events, "the park kept nothing of the operation it never read (b50d0425)")
        kind, value = self.owner.events[-1]
        self.assertEqual(("scoped-tun-reserved-journal-wait", "ACCEPTED", 0), (kind, value["lastStatus"]["code"], value["journals"]))
        self.assertGreater(value["statusReads"], 1)
        self.assertEqual([], os.listdir(self.programs))

    def test_an_end_that_leaves_the_outcome_open_parks(self):
        """OK with no journal, or a code the product classes as leaving the outcome open, proves nothing closed."""
        for code in ("OK", "UNAVAILABLE", "OUTCOME_UNKNOWN", "TIMEOUT"):
            with self.subTest(code=code):
                self.setUp()
                with self.waiting([status(code)]), self.assertRaisesRegex(
                        RuntimeError, "^parked:scoped-tun-reserved-ended-outcome-open-no-replay$"):
                    ask(reserved.Case(self.owner, "stage-squat"), self.state)
                self.assertEqual(code, self.owner.events[-1][1]["lastStatus"]["code"])

    def test_a_journal_written_before_the_operation_ended_is_still_the_job(self):
        case = reserved.Case(self.owner, "stage-squat")
        with self.waiting([status(), status("CONFLICT")], journal_at_read=2):
            self.assertEqual(JOB, ask(case, self.state)["jobId"], "the stages' own terminal reads that outcome")
        self.assertEqual([reserved.CANARY], os.listdir(self.programs / ("vpn-control-vpn-" + JOB)))

    def test_the_refusals_are_the_stages_own(self):
        self.assertEqual(stages.REFUSED_EXITS, reserved.REFUSALS)

    def squatted(self):
        case = reserved.Case(self.owner, "stage-squat")
        (self.workspace / (reserved.JOURNAL_PREFIX + JOB + ".json")).write_bytes(b"{}")
        ask(case, self.state)
        return case, self.programs / ("vpn-control-vpn-" + JOB)

    def test_an_untouched_squat_is_removed_by_the_case(self):
        case, stage = self.squatted()
        case.squat_kept_and_removed()
        self.assertFalse(stage.exists())
        self.assertEqual({"path": str(stage), "jobId": JOB, "deleted": False, "followed": False, "written": False,
                          "removedByCase": True}, self.owner.events[-1][1])

    def test_a_squat_written_replaced_or_grown_fails_and_stays(self):
        for name, change in (("canary", lambda stage: (stage / reserved.CANARY).write_bytes(b"product wrote here\n")),
                             ("grown", lambda stage: (stage / "config.json").write_bytes(b"{}")),
                             ("replaced", lambda stage: (os.remove(stage / reserved.CANARY), os.rmdir(stage), os.mkdir(stage),
                                                         (stage / reserved.CANARY).write_bytes(b"owned squat " + JOB.encode() + b"\n")))):
            with self.subTest(change=name):
                self.setUp()
                case, stage = self.squatted()
                change(stage)
                with self.assertRaisesRegex(AssertionError, "^reserved-squat-touched$"):
                    case.squat_kept_and_removed()
                self.assertTrue(stage.exists(), "evidence of the product's write is kept")


def observation(folder, *, paths=None, rules_sha=None, ssh=(), name=None):
    stage = STAGE if name is None else "C:\\ProgramData\\" + name
    rows = paths if paths is not None else [
        *({"context": context, "type": kind, "value": value} for context, kind, value in reserved.URL_PATHS),
        {"context": "experimental.cache_file", "type": None, "value": stage + "\\cache-0.db"},
        {"context": "route.rule_set.*", "type": "local", "value": stage + "\\resource-1.json"}]
    return {"path": stage, "name": PureWindowsPath(stage).name, "entries": ["config.json", "sing-box.exe"], "paths": rows,
            "cache": {"enabled": True, "path": stage + "\\cache-0.db"},
            "ruleSets": [{"tag": "owned-local", "path": stage + "\\resource-1.json", "sha256": rules_sha, "sizeBytes": 10}],
            "ssh": list(ssh)}


class Kernel32:
    """CreateFileW and CreateNamedPipeW as the ordinary user meets the broker's single connected instance."""

    def __init__(self, client=None, instance=None, codes=(231, 5)):
        self.client, self.instance, self.codes, self.closed, self.last = client, instance, list(codes), [], None
        outer = self

        def create(*args):
            outer.last = outer.codes[0]
            return outer.client if outer.client is not None else INVALID

        def named(*args):
            outer.last = outer.codes[1]
            return outer.instance if outer.instance is not None else INVALID
        self.CreateFileW, self.CreateNamedPipeW = Callable(create), Callable(named)
        self.CloseHandle = Callable(lambda handle: outer.closed.append(handle) or 1)


class Callable:
    def __init__(self, function):
        self.function, self.argtypes, self.restype = function, None, None

    def __call__(self, *args):
        return self.function(*args)


class WindowTests(CaseWorld):
    """Inside the grant's ready-to-off window, with the collector's ready record handed over."""

    def resources(self, **changes):
        case = reserved.Case(self.owner, "resources-grant")
        case.prepare(self.state, self.runtime())
        case.job = JOB
        ready = {"observations": {"stage": observation(case.folder, rules_sha=case.rules_sha256, **changes)},
                 "helperInvocation": {"pipeName": PIPE}}
        lease = {"nativeReady": ready, "inputs": {"variant": "resources-grant"}, "state": self.state}
        seen = []
        tun = types.SimpleNamespace(traffic=lambda owner, current: seen.append((case.folder / "rules.json").read_bytes()) or [{}] * 9)
        return case, lease, tun, seen

    def test_the_staged_capture_survives_the_originals_change_and_the_pipe_refuses_both_races(self):
        case, lease, tun, seen = self.resources()
        kernel = Kernel32()
        with mock.patch.object(reserved, "_kernel32", lambda: kernel), mock.patch.object(reserved, "_last_error", lambda: kernel.last):
            found = case.window(lease, tun)
        self.assertEqual({"secondClient": reserved.ERROR_PIPE_BUSY, "sameNameInstance": reserved.ERROR_ACCESS_DENIED}, found)
        self.assertEqual([reserved.rules(reserved.SAMPLER_TARGET)], seen, "the sampler ran once more, after the original rejects it")
        self.assertIn(("sleep", reserved.RELOAD_SECONDS), self.calls)
        kinds = [kind for kind, _ in self.owner.events]
        self.assertEqual(["scoped-tun-original-resource-changed", "scoped-tun-captured-resource-kept", "scoped-tun-pipe-races"], kinds[-3:])

    def test_a_path_outside_a_url_context_or_an_unstaged_resource_fails_the_window(self):
        url = [{"context": context, "type": kind, "value": value} for context, kind, value in reserved.URL_PATHS]
        staged = [{"context": "experimental.cache_file", "type": None, "value": STAGE + "\\cache-0.db"},
                  {"context": "route.rule_set.*", "type": "local", "value": STAGE + "\\resource-1.json"}]
        cases = (("socks-path", dict(paths=[*url, *staged, {"context": "outbounds.*", "type": "socks", "value": "/x"}]), "reserved-path-outside-url-context"),
                 ("url-rewritten", dict(paths=[dict(url[0], value="/elsewhere"), *url[1:], *staged]), "reserved-path-outside-url-context"),
                 ("url-dropped", dict(paths=[*url[1:], *staged]), "reserved-path-outside-url-context"),
                 ("untyped-path", dict(paths=[*url, *staged, {"context": "outbounds.*", "type": None, "value": None}]), "reserved-path-outside-url-context"),
                 ("rule-set-original", dict(paths=[*url, staged[0], dict(staged[1], value="C:\\Users\\u\\rules.json")]), "reserved-file-path-not-staged"),
                 ("another-job", dict(name="vpn-control-vpn-6f6f6f6f-1111-4222-8333-944455556666"), "reserved-stage-not-the-journal-job"))
        for name, changes, reason in cases:
            with self.subTest(case=name):
                self.setUp()
                case, lease, tun, seen = self.resources(**changes)
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    case.window(lease, tun)
                self.assertEqual([], seen, "no traffic once the stage is wrong")
        self.setUp()
        case, lease, tun, seen = self.resources()
        lease["nativeReady"]["observations"]["stage"]["ruleSets"][0]["sha256"] = sha(reserved.rules(reserved.SAMPLER_TARGET))
        with self.assertRaisesRegex(AssertionError, "^reserved-rule-set-not-captured$"):
            case.window(lease, tun)
        self.setUp()
        case, lease, tun, seen = self.resources()
        lease["nativeReady"]["observations"]["stage"]["cache"]["enabled"] = False
        with self.assertRaisesRegex(AssertionError, "^reserved-cache-not-staged$"):
            case.window(lease, tun)

    def test_a_runtime_reading_the_changed_original_fails_its_sampler(self):
        case, lease, tun, seen = self.resources()
        tun.traffic = lambda owner, current: (_ for _ in ()).throw(AssertionError("scoped-tun-direct-traffic"))
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-direct-traffic$"):
            case.window(lease, tun)
        self.assertNotIn("scoped-tun-captured-resource-kept", [kind for kind, _ in self.owner.events])

    def test_a_pipe_that_admits_either_race_is_closed_at_once_and_fails(self):
        for name, kernel in (("second-client", Kernel32(client=44)), ("same-name", Kernel32(instance=45)),
                             ("not-found", Kernel32(codes=(2, 5))), ("busy-instance", Kernel32(codes=(231, 231)))):
            with self.subTest(case=name):
                with mock.patch.object(reserved, "_kernel32", lambda: kernel), mock.patch.object(reserved, "_last_error", lambda: kernel.last), \
                        self.assertRaisesRegex(AssertionError, "^reserved-pipe-race-admitted$"):
                    reserved.pipe_races(self.owner, PIPE)
                self.assertEqual([handle for handle in (kernel.client, kernel.instance) if handle is not None], kernel.closed)
        with self.assertRaisesRegex(AssertionError, "^reserved-pipe-name$"):
            reserved.pipe_races(self.owner, "elsewhere")


class Relay:
    def __init__(self, snapshots):
        self.snapshots, self.socks_port = list(snapshots), 50001

    def facts(self):
        return self.snapshots.pop(0)


class SshWindowTests(CaseWorld):
    def ssh(self, *, persisted=None, stage=None, egress=8, port=SOCKS_PORT, key_owner=None):
        case = reserved.Case(self.owner, "ssh-grant", relay=relay_fixture)
        case.key = relay_fixture.ed25519_public(b"\x01" * 32)
        fingerprint = relay_fixture.fingerprint(relay_fixture.ed25519_blob(key_owner or case.key))
        session = {"ordinal": 0, "authenticated": True, "authenticatedKey": fingerprint, "auth": [{"user": "fixture", "method": "publickey", "result": "success"}],
                   "channels": [{"type": "direct-tcpip", "host": "127.0.0.1", "port": 50001, "result": "opened"}]}
        row = {"host": "127.0.0.1", "port": port, "result": "connected", "up": 1, "down": 1}
        before = {"sessions": [session], "socks": [row]}
        case.relay = Relay([before, {"sessions": [session], "socks": [row] * (1 + egress)}])
        config = self.base / "runtime-config.json"
        config.write_text(json.dumps(persisted or {"outbounds": [{"type": "ssh", "tag": reserved.SSH_TAG, "private_key_path": "C:\\k"}]}))
        own = relay_fixture.fingerprint(relay_fixture.ed25519_blob(case.key))
        stage_ssh = stage or [{"tag": reserved.SSH_TAG, "privateKeyInline": True, "privateKeyPath": False, "inlinePublicFingerprint": own}]
        lease = {"nativeReady": {"observations": {"stage": observation(None, ssh=stage_ssh)}}, "inputs": {"runtimeConfigPath": str(config)},
                 "state": self.state}
        tun = types.SimpleNamespace(traffic=lambda owner, current: [{"kind": "sample"}] * 8 + [{"kind": "terminal"}])
        return case, lease, tun

    def test_the_tun_traffic_rides_the_imported_keys_session_and_the_key_stays_out_of_the_persisted_config(self):
        case, lease, tun = self.ssh()
        self.assertEqual({"egress": 8}, case.window(lease, tun))
        value = self.owner.events[-1][1]
        self.assertEqual((True, False, True), (value["persistedKeyPath"], value["persistedInlineKey"], value["stageInlineKey"]))

    def test_any_other_key_form_or_route_fails(self):
        other = relay_fixture.ed25519_public(b"\x02" * 32)
        good = {"tag": reserved.SSH_TAG, "privateKeyInline": True, "privateKeyPath": False}
        cases = (("persisted-inline", dict(persisted={"outbounds": [{"type": "ssh", "tag": reserved.SSH_TAG, "private_key_path": "C:\\k",
                                                                    "private_key": "x"}]}), "reserved-persisted-config-gained-key"),
                 ("persisted-no-path", dict(persisted={"outbounds": [{"type": "ssh", "tag": reserved.SSH_TAG}]}), "reserved-persisted-config-gained-key"),
                 ("stage-path", dict(stage=[dict(good, privateKeyPath=True, inlinePublicFingerprint=None)]), "reserved-ssh-key-not-inline"),
                 ("stage-other-key", dict(stage=[dict(good, inlinePublicFingerprint=relay_fixture.fingerprint(relay_fixture.ed25519_blob(other)))]),
                  "reserved-ssh-key-not-inline"),
                 ("session-other-key", dict(key_owner=other), "reserved-ssh-session-not-the-imported-key"),
                 ("egress-elsewhere", dict(port=SOCKS_PORT + 1), "reserved-tun-traffic-not-through-ssh-chain"),
                 ("too-few", dict(egress=7), "reserved-tun-traffic-not-through-ssh-chain"))
        for name, changes, reason in cases:
            with self.subTest(case=name):
                case, lease, tun = self.ssh(**changes)
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    case.window(lease, tun)


class AfterOffTests(CaseWorld):
    def test_the_cache_is_the_users_again_after_the_off(self):
        case = reserved.Case(self.owner, "resources-grant")
        case.folder.mkdir()
        lease = {"offFinished": True, "state": self.state}
        with mock.patch.object(reserved.time, "sleep", lambda seconds: (case.folder / "cache.db").write_bytes(b"bbolt")):
            self.assertEqual(5, case.after_off(lease))
        self.assertEqual("scoped-tun-cache-published", self.owner.events[-1][0])

    def test_a_cache_never_published_or_empty_fails(self):
        case = reserved.Case(self.owner, "resources-grant")
        case.folder.mkdir()
        clock = iter([0.0, 0.0, reserved.PUBLISH_SECONDS + 1])
        with mock.patch.object(reserved.time, "monotonic", lambda: next(clock)), \
                self.assertRaisesRegex(AssertionError, "^reserved-cache-not-published$"):
            case.after_off({"offFinished": True, "state": self.state})
        (case.folder / "cache.db").write_bytes(b"")
        with self.assertRaisesRegex(AssertionError, "^reserved-cache-empty$"):
            case.after_off({"offFinished": True, "state": self.state})
        with self.assertRaisesRegex(AssertionError, "^reserved-after-exact-off$"):
            case.after_off({"state": self.state})


class Files:
    """update_receipts.FileObservation over a dict of stage files, as SYSTEM opens them."""

    def __init__(self, files):
        self.files, self.opened = files, []
        outer = self

        class FileObservation:
            def __init__(self, owner, path):
                outer.opened.append(path)
                self.path = path
                self.opening = {"path": path, "security": {"ownerSid": "S-1-5-32-544", "sddl": "O:BAD:PAI(A;ID;FA;;;SY)(A;ID;FA;;;BA)"}}

            def read(self, maximum):
                return outer.files[self.path]

            def close(self):
                pass
        self.FileObservation = FileObservation
        self.canonical_path = update_receipts.canonical_path


class StageObservationTests(unittest.TestCase):
    """windows_tun_native_observer: the broker's stage, as the TUN SYSTEM collector records it in its ready record."""

    def request(self, image=STAGE + "\\sing-box.exe"):
        return {"runtimeImagePath": image, "runtimeImageSha256": "d" * 64, "ownerActor": {"pid": OWNER_PID, "creationFileTime": OWNER_BIRTH},
                "context": {"programData": "C:\\ProgramData", "ordinarySid": ORDINARY}}

    def observe(self, config, files=None, request=None):
        store = Files({STAGE + "\\config.json": json.dumps(config).encode(), **(files or {})})
        with mock.patch.object(tun_observer.os, "listdir", lambda path: ["config.json", "sing-box.exe", "resource-1.json"]):
            return tun_observer.stage_observation(types.SimpleNamespace(), store, request or self.request()), store

    def test_paths_cache_rule_sets_and_the_public_half_of_an_inline_key_only(self):
        seed = b"\x07" * 32
        key = relay_fixture.openssh_private_key(seed)
        rule_bytes = b'{"rules":[{"ip_cidr":["198.18.0.2/32"]}],"version":1}\n'
        config = {"dns": {"servers": [{"type": "https", "tag": "d", "path": "/q"}]},
                  "outbounds": [{"type": "ssh", "tag": SSH_TAG, "private_key": key}, {"type": "vless", "transport": {"type": "ws", "path": "/w"}}],
                  "route": {"rule_set": [{"type": "local", "tag": "owned-local", "path": STAGE + "\\resource-1.json"},
                                         {"type": "remote", "tag": "r", "url": "https://x"}]},
                  "experimental": {"cache_file": {"enabled": True, "path": STAGE + "\\cache-0.db"}}}
        value, store = self.observe(config, {STAGE + "\\resource-1.json": rule_bytes})
        self.assertEqual(("vpn-control-vpn-" + JOB, ["config.json", "resource-1.json", "sing-box.exe"]), (value["name"], value["entries"]))
        self.assertEqual([("dns.servers.*", "https", "/q"), ("outbounds.*.transport", "ws", "/w"),
                          ("route.rule_set.*", "local", STAGE + "\\resource-1.json"), ("experimental.cache_file", None, STAGE + "\\cache-0.db")],
                         [(row["context"], row["type"], row["value"]) for row in value["paths"]])
        self.assertEqual({"enabled": True, "path": STAGE + "\\cache-0.db"}, value["cache"])
        self.assertEqual([{"tag": "owned-local", "path": STAGE + "\\resource-1.json", "sha256": sha(rule_bytes), "sizeBytes": len(rule_bytes)}],
                         value["ruleSets"])
        expected = relay_fixture.fingerprint(relay_fixture.ed25519_blob(relay_fixture.ed25519_public(seed)))
        self.assertEqual([{"tag": SSH_TAG, "privateKeyInline": True, "privateKeyPath": False, "inlinePublicFingerprint": expected}], value["ssh"])
        text = json.dumps(value)
        for line in key.splitlines()[1:-1]:
            self.assertNotIn(line, text, "no line of the key reaches the record")

    def test_a_rule_set_outside_the_stage_is_named_but_never_opened(self):
        config = {"route": {"rule_set": [{"type": "local", "tag": "owned-local", "path": "C:\\Users\\u\\rules.json"}]},
                  "outbounds": [{"type": "socks", "path": 7}]}
        value, store = self.observe(config)
        self.assertEqual([{"tag": "owned-local", "path": "C:\\Users\\u\\rules.json", "sha256": None, "sizeBytes": None}], value["ruleSets"])
        self.assertEqual([STAGE + "\\config.json"], store.opened, "SYSTEM opened only the stage's own config")
        self.assertEqual([("route.rule_set.*", "local", "C:\\Users\\u\\rules.json"), ("outbounds.*", "socks", None)],
                         [(row["context"], row["type"], row["value"]) for row in value["paths"]])

    def test_a_runtime_outside_a_broker_stage_is_refused_before_any_read(self):
        for image in ("C:\\ProgramData\\elsewhere\\sing-box.exe", "C:\\Users\\u\\vpn-control-vpn-" + JOB + "\\sing-box.exe",
                      STAGE + "\\other.exe"):
            with self.subTest(image=image), self.assertRaisesRegex(ValueError, "^tun-runtime-private-stage$"):
                self.observe({}, request=self.request(image))

    def test_only_an_openssh_container_yields_a_fingerprint(self):
        key = relay_fixture.openssh_private_key(b"\x03" * 32)
        body = base64.b64decode("".join(key.splitlines()[1:-1]))
        self.assertIsNotNone(tun_observer.public_fingerprint(key))
        for value in (None, "", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
                      key.replace("OPENSSH", "RSA"), "-----BEGIN OPENSSH PRIVATE KEY-----\n" + base64.b64encode(body[:40]).decode()
                      + "\n-----END OPENSSH PRIVATE KEY-----\n"):
            with self.subTest(value=str(value)[:40]):
                self.assertIsNone(tun_observer.public_fingerprint(value))

    def test_the_brokers_pipe_comes_from_its_own_argv_joined_to_this_owner_and_runtime(self):
        good = ["C:\\x\\vpn-control-vpn-broker.exe", PIPE, str(OWNER_PID), str(OWNER_BIRTH), ORDINARY, "d" * 64]
        for name, argv, expected in (("joined", good, {"pipeName": PIPE}),
                                     ("other-owner", good[:2] + ["914"] + good[3:], None),
                                     ("other-birth", good[:3] + ["1"] + good[4:], None),
                                     ("other-user", good[:4] + [ADMIN] + good[5:], None),
                                     ("other-runtime", good[:5] + ["e" * 64], None),
                                     ("not-a-pipe", good[:1] + ["pipe"] + good[2:], None),
                                     ("extra", good + ["x"], None)):
            with self.subTest(case=name), mock.patch.object(tun_observer, "command_line", lambda process: "line"), \
                    mock.patch.object(tun_observer, "split", lambda text, argv=argv: list(argv)):
                if expected is None:
                    with self.assertRaisesRegex(ValueError, "^tun-helper-invocation$"):
                        tun_observer.helper_invocation(self.request(), object())
                else:
                    self.assertEqual(expected, tun_observer.helper_invocation(self.request(), object()))


class DriverReservedTests(unittest.TestCase):
    """The dedicated driver's reserved route: the pinned case module, its window between the stages' sampler and the
    product's off, its after-off step after the off record, and its close; the squat with no collector or hold."""

    def setUp(self):
        from agent_tools.tests.test_windows_tun_grant import DriverGrantTests
        self.grant_tests = DriverGrantTests
        self.helper = DriverGrantTests("test_a_grant_hands_both_records_over_and_ends_only_with_its_collectors_release")
        self.helper.setUp()
        self.addCleanup(self.helper.doCleanups)

    def arm(self, variant, *, reserved_source="agent_tools/windows_tun_reserved_cases.py", hold=True):
        helper = self.helper
        helper.grant(variant=variant)
        owner = helper.owner
        calls = owner.calls
        path = owner.source("windows_tun_reserved_cases.py", reserved_source)
        owner.inputs["modules"]["reserved"] = path
        if variant == "ssh-grant":
            owner.inputs["modules"]["relay"] = owner.source("windows_ssh_relay_fixture.py", "agent_tools/windows_ssh_relay_fixture.py")
            owner.modules[owner.inputs["modules"]["relay"]] = types.SimpleNamespace(name="relay")
        owner.inputs["tun"]["pendingLocation"] = PENDING[variant]
        if not variant.endswith("grant"):
            owner.inputs["tun"].pop("samplerPath")

        class Case:
            def __init__(self, owner, variant, relay=None):
                calls.append(("reserved-case", variant, getattr(relay, "name", None)))
                self.variant = variant

            def window(self, lease, tun):
                calls.append("reserved-window")

            def after_off(self, lease):
                calls.append("reserved-after-off")

            def close(self):
                calls.append("reserved-close")
        owner.modules[path] = types.SimpleNamespace(Case=Case)
        stages_fake = owner.modules[owner.inputs["modules"]["tun"]]
        begin = stages_fake.begin

        def reserved_begin(owner, state, inputs, runtime, cases, observer, reserved=None):
            calls.append(("tun-begin-reserved", reserved.variant))
            return begin(owner, state, inputs, runtime, cases, observer)
        stages_fake.begin = reserved_begin
        if not hold:
            def squat_finish(owner, lease, runtime, cases, observer, handoff=None, receipts=None):
                calls.append(("tun-finish", handoff is None and receipts is None))
                lease.update(finished=True, conflictEnd="CONFLICT")
                return {"terminal": {"code": "CONFLICT"}, "status": {}, "nativeRecord": None}
            stages_fake.finish = squat_finish
        owner.harness({"LIFECYCLE_INPUTS": owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": helper.hold_inputs if hold else None})
        return owner

    def test_a_reserved_grant_runs_its_case_inside_the_window_and_closes_it(self):
        for variant in ("resources-grant", "ssh-grant"):
            with self.subTest(variant=variant):
                self.helper.setUp()
                owner = self.arm(variant)
                self.assertEqual(0, dedicated_driver.run(owner, "windows-proxy-lifecycle"))
                order = [("reserved-case", variant, "relay" if variant == "ssh-grant" else None), ("tun-begin-reserved", variant),
                         "tun-traffic", "reserved-window", "tun-off", "reserved-after-off", "tun-closing", "reserved-close", "stop-fixture",
                         "wait-release"]
                self.assertEqual(order, [call for call in owner.calls if call in order])

    def test_the_squat_has_no_collector_or_hold_and_closes_like_a_pass(self):
        owner = self.arm("stage-squat", hold=False)
        self.assertEqual(0, dedicated_driver.run(owner, "windows-proxy-lifecycle"))
        self.assertFalse([call for call in owner.calls if isinstance(call, tuple) and call[0] == dedicated_driver.NATIVE_NEED])
        self.assertNotIn("reserved-window", owner.calls)
        self.assertNotIn("arm", owner.calls)
        self.assertIn(("tun-finish", True), owner.calls)
        self.assertIn("reserved-close", owner.calls)
        self.assertTrue([call for call in owner.calls if isinstance(call, tuple) and call[0] == "off-actors"], "proxy A is still up: its own off runs")

    def test_a_case_module_not_the_reviewed_bytes_starts_nothing(self):
        owner = self.arm("resources-grant", reserved_source="agent_tools/windows_tun_stages.py")
        with self.assertRaisesRegex(ValueError, "^dedicated-reviewed-source-pin$"):
            dedicated_driver.run(owner, "windows-proxy-lifecycle")
        self.assertNotIn("start-runtime", owner.calls)


if __name__ == "__main__":
    unittest.main()
