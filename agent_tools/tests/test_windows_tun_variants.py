"""windows-scoped-tun configuration and fault variants: the TUN halves of the proxy rows' config and failure cases, offline.

generated-grant, custom-grant and large-grant add the proxy rows' own location documents, raise the restart prompt that
windows-uac-decision approves, and compare the runtime config the ordinary user reads in the ready window with the bytes
the TUN SYSTEM collector read for its ready record; only the generated config has a TUN, so only it runs the direct
sampler. vpn-prepare-failure is refused by the product before any prompt with A kept; vpn-commit-failure is approved,
its elevated runtime hits the owned bind conflict, and the product brings A back. Neither fault asks a collector.

No guest, socket, process, route or UAC prompt is touched: every native boundary is a declared fake, and nothing here
proves a Windows behaviour. The native first contact is the operator sequence in the T8 evidence report.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path, PureWindowsPath
import tempfile
import types
import unittest
from unittest import mock
import uuid

from agent_tools import native_scenario_windows as windows
from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools import windows_runtime_branch_cases as branch_cases
from agent_tools import windows_scenario_proxy as proxy
from agent_tools import windows_tun_stages as stages
from agent_tools import windows_uac_decision as decision
from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer
from agent_tools.tests.test_windows_tun_grant import PRODUCT_OPERATION, REQUEST_ID, SERVE_BIRTH, SERVE_PID, GrantRecords
from agent_tools.tests.test_windows_tun_stages import ADMIN, PurePathReading, StageWorld
from agent_tools.windows_system_collector import collector_contract as contract

ROOT = Path(__file__).resolve().parents[2]
PORT = 41001
CONFIG_VARIANTS = ("generated-grant", "custom-grant", "large-grant")
FAULT_VARIANTS = ("vpn-prepare-failure", "vpn-commit-failure")
NAMES = {"generated-grant": "Owned generated", "custom-grant": "Owned CUSTOM", "large-grant": "Owned large CUSTOM",
         "vpn-prepare-failure": "Owned prepare failure", "vpn-commit-failure": "Owned commit failure"}
KINDS = {"custom-grant": "custom", "large-grant": "large", "vpn-prepare-failure": "prepare-failure", "vpn-commit-failure": "commit-readiness-failure"}
_T, _P = "windows-scoped-tun.", "windows-proxy-lifecycle."


class Branches:
    """windows_runtime_branch_cases as the stages use it: its real documents and semantics, its publication declared."""

    def __init__(self):
        self.published = []
        self.custom_config, self.profile_document = branch_cases.custom_config, branch_cases.profile_document
        self.encoded, self.custom_semantics = branch_cases.encoded, branch_cases.custom_semantics

    def publish_fixture(self, owner, leaf, raw):
        self.published.append((leaf, raw))
        return PureWindowsPath("C:\\owned-root") / leaf, object()


def transformed(original, workspace, port=PORT + 7):
    """SingBoxCustomConfigTransformer's output as the proxy rows' custom_semantics admits it: the management inbound, the
    direct-probe outbound and route prefix, nothing else."""
    rules = original["route"]["rules"]
    return {**original, "inbounds": original["inbounds"] + [{"type": "mixed", "tag": "vpn-control-management", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": original["outbounds"] + [{"type": "direct", "tag": "vpn-control-direct-probe"}],
            "route": {**original["route"], "rules": [{"inbound": "vpn-control-management", "action": "sniff", "timeout": "1s"},
                                                     {"inbound": "vpn-control-management", "action": "route", "outbound": original["route"]["final"]},
                                                     {"process_name": ["vpn-control-probe-sing-box", "vpn-control-probe-sing-box.exe"], "action": "route",
                                                      "outbound": "vpn-control-direct-probe"},
                                                     {"process_path": [str(Path(workspace) / "validation" / "vpn-control-probe-sing-box.exe")],
                                                      "action": "route", "outbound": "vpn-control-direct-probe"}] + rules}}


def generated_vpn(port=PORT):
    return {"inbounds": [{"type": "tun", "tag": "tun-in", "address": ["172.19.250.1/30"], "auto_route": True, "strict_route": True},
                         {"type": "mixed", "tag": "active-verify-in", "listen": "127.0.0.1", "listen_port": 43000}],
            "outbounds": [{"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": port}, {"type": "direct", "tag": "direct"}],
            "route": {"rules": [], "final": "proxy"}}


class VariantWorld(StageWorld):
    """StageWorld with each variant's own location: added from its document, shown back, then selected."""

    def setUp(self):
        super().setUp()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.workspace = Path(temporary.name)
        self.branches = Branches()
        self.shown = {}
        self.exits = [{"pid": 77, "originalAbsent": True}]
        self.recovered = {"owner": {"pid": 70, "creationFileTime": 1}, "runtime": {"pid": 79, "creationFileTime": 9}}
        self.observer.observe_exit = lambda expected, native: [dict(row) for row in self.exits]

    def state(self):
        value = super().state()
        value.update(workspace=str(self.workspace), ready={"advertisedSocksPort": PORT},
                     inputs={"fixtureBody": "vpn-control-proxy-fixture", "runtimeImagePath": "C:\\w\\sing-box.exe", "runtimeSha256": "d" * 64})
        value["actors"]["runtime"]["creationFileTime"] = 7
        return value

    def runtime(self):
        runtime = super().runtime()
        result, test = runtime.result, self

        def asked(owner, workspace, identity, *arguments, **options):
            if arguments[-3:-1] == ("locations", "select"):
                test.calls.append(arguments)
                test.status["selectedLocationId"] = "b"
                test.revision += 1
                return {"data": {}, "configurationRevision": test.revision}
            if arguments[:2] == ("locations", "show"):
                test.calls.append(arguments)
                return {"data": {"configuration": json.dumps(test.shown[arguments[2]])}}
            if "add" in arguments:
                test.calls.append(arguments)
                path = arguments[-1]
                raw = dict(test.branches.published)[PureWindowsPath(path).name]
                document = json.loads(raw)
                test.shown[document["remarks"]] = json.loads(document["custom_config_json"]) if "custom_config_json" in document else document
                test.revision += 1
                return {"data": {}, "configurationRevision": test.revision}
            return result(owner, workspace, identity, *arguments, **options)
        runtime.result = asked
        runtime.capture_proxy_actors = lambda owner, serve, native, path, digest: test.calls.append(("capture", path, digest)) or dict(test.recovered)
        return runtime

    def inputs(self, variant="restart-deny", **changes):
        value = super().inputs(variant, **changes)
        if variant in NAMES and "pendingLocation" not in changes:
            value["pendingLocation"] = NAMES[variant]
        if variant in ("custom-grant", "large-grant") or variant in FAULT_VARIANTS:
            value.pop("samplerPath", None)
            value.pop("samplerInputPath", None)
        return value

    def begin_variant(self, variant, runtime=None, branches="default"):
        self.status = {"runtimeRunning": True, "activeMode": "proxy-only", "activeLocationId": "a", "selectedLocationId": "a",
                       "runtimeId": "r", "runtimeStartedAt": "t", "configuredMode": "proxy-only"}
        with mock.patch.object(stages, "Path", PurePathReading):
            return stages.begin(self.owner, self.state(), self.inputs(variant), runtime or self.runtime(), self.cases(), self.observer,
                                branches=self.branches if branches == "default" else branches)

    def leased(self, variant):
        """The lease begin() leaves for this variant, built here so a finish or configuration regression fails on its own
        cause on any source: active proxy A, the variant's own location pending in VPN mode, the request accepted."""
        self.status = {"runtimeRunning": True, "activeMode": "proxy-only", "activeLocationId": "a", "selectedLocationId": "a",
                       "runtimeId": "r", "runtimeStartedAt": "t", "configuredMode": "proxy-only"}
        before = {"data": dict(self.status), "restartRequired": False, "configurationRevision": 4}
        self.status.update(selectedLocationId="b", configuredMode="vpn")
        pending = {"data": dict(self.status), "restartRequired": True, "configurationRevision": 6}
        original = None if variant == "generated-grant" else branch_cases.custom_config(PORT, KINDS[variant])
        raw = branch_cases.encoded({"type": "socks", "remarks": NAMES[variant], "server": "127.0.0.1", "server_port": PORT} if original is None
                                   else branch_cases.profile_document(original, NAMES[variant]))
        lease = {"state": self.state(), "inputs": self.inputs(variant), "before": before, "pending": pending,
                 "accepted": {"operationId": str(uuid.uuid4()), "requestId": str(uuid.uuid4())}, "activeConfig": self.cases().LiveConfig(None, None, None),
                 "baseline": {"brokers": [], "runtimes": [88], "stages": [self.entries[1]], "routes": []}, "finished": False,
                 "document": {"name": NAMES[variant], "path": "C:\\owned-root\\owned-tun-profile-" + variant + ".json", "original": original,
                              "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}}
        self.owner.tun_operation_leases, self.owner.tun_operation_requested = [lease], True
        return lease

    def finish(self, lease, code, **status):
        runtime = self.runtime()
        runtime.finish_operation = lambda owner, state, accepted, codes, seconds=120: {"code": code, "final": True}
        self.status.update(status)
        actors = []
        cases = types.SimpleNamespace(config_bytes=lambda path: dict(lease["activeConfig"].initial),
                                      exact_actor=lambda native, actor, elevated: actors.append((actor["pid"], elevated)))
        return stages.finish(self.owner, lease, runtime, cases, self.observer), actors


class VariantBeginTests(VariantWorld):
    def test_each_variant_adds_its_own_document_before_selecting_it_in_vpn_mode(self):
        for variant in CONFIG_VARIANTS + FAULT_VARIANTS:
            with self.subTest(variant=variant):
                self.setUp()
                lease = self.begin_variant(variant)
                leaf = "owned-tun-profile-" + variant + ".json"
                self.assertEqual([leaf], [name for name, _ in self.branches.published])
                raw = self.branches.published[0][1]
                if variant == "generated-grant":
                    self.assertEqual({"type": "socks", "remarks": NAMES[variant], "server": "127.0.0.1", "server_port": PORT}, json.loads(raw))
                else:
                    self.assertEqual(branch_cases.encoded(branch_cases.profile_document(branch_cases.custom_config(PORT, KINDS[variant]), NAMES[variant])), raw,
                                     "the proxy row's own document")
                self.assertEqual(variant == "large-grant", len(raw) > 60000)
                tails = [call[2:] for call in self.calls if call[:1] == ("--if-revision",)]
                self.assertEqual([("locations", "add", "--input", str(PureWindowsPath("C:\\owned-root") / leaf)), ("locations", "select", NAMES[variant]),
                                  ("settings", "set", "mode", "vpn")], tails)
                self.assertEqual(variant in CONFIG_VARIANTS, ("locations", "show", NAMES[variant]) in self.calls, "a config's location reads back first")
                self.assertEqual(("--async", "restart"), self.calls[-1][-2:])
                kinds = [kind for kind, _ in self.owner.events]
                if variant == "vpn-prepare-failure":
                    self.assertEqual(["scoped-tun-request-accepted"], kinds, "no prompt follows: nothing awaits a decision")
                    self.assertFalse(self.owner.events[0][1]["promptExpected"])
                else:
                    self.assertEqual(["scoped-tun-awaiting-current-input"], kinds)
                    self.assertEqual(variant, self.owner.events[0][1]["variant"])
                self.assertEqual(NAMES[variant], lease["document"]["name"])

    def test_the_document_cases_belong_only_to_the_variants_that_add_a_location(self):
        for variant, branches, reason in (("restart-grant", "default", "scoped-tun-variant-document-cases"),
                                          ("custom-grant", None, "scoped-tun-variant-document-cases"),
                                          ("vpn-commit-failure", None, "scoped-tun-variant-document-cases")):
            with self.subTest(variant=variant):
                self.setUp()
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.begin_variant(variant, branches=branches)
                self.assertEqual([], self.calls)
        for variant, location in (("custom-grant", "Owned B"), ("vpn-prepare-failure", "Owned CUSTOM")):
            with self.subTest(variant=variant, location=location):
                self.setUp()
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-fixed-pending-location-admin-role$"), \
                        mock.patch.object(stages, "Path", PurePathReading):
                    stages.begin(self.owner, self.state(), self.inputs(variant, pendingLocation=location), self.runtime(), self.cases(),
                                 self.observer, branches=self.branches)
        # A CUSTOM config has no TUN: its row carries no direct sampler, and a sampler input is refused.
        self.setUp()
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-native-inputs-pending$"), mock.patch.object(stages, "Path", PurePathReading):
            stages.begin(self.owner, self.state(), {**self.inputs("custom-grant"), "samplerPath": "x", "samplerInputPath": "y"}, self.runtime(),
                         self.cases(), self.observer, branches=self.branches)

    def test_a_location_that_does_not_read_back_as_its_document_asks_nothing_of_the_broker(self):
        runtime = self.runtime()
        result = runtime.result

        def altered(owner, workspace, identity, *arguments, **options):
            value = result(owner, workspace, identity, *arguments, **options)
            if arguments[:2] == ("locations", "show"):
                shown = json.loads(value["data"]["configuration"])
                shown["route"]["final"] = "elsewhere"
                value = {"data": {"configuration": json.dumps(shown)}}
            return value
        runtime.result = altered
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-configuration-public-readback$"):
            self.begin_variant("custom-grant", runtime=runtime)
        self.assertFalse([call for call in self.calls if call[:1] == ("--async",)])


class PreparationFailureTests(VariantWorld):
    def test_a_preparation_failure_in_vpn_mode_is_the_rows_own_end_with_a_kept_and_nothing_scoped(self):
        lease = self.leased("vpn-prepare-failure")
        result, actors = self.finish(lease, "RUNTIME_FAILED")
        self.assertTrue(result["faultRecovered"])
        self.assertNotIn("knownFailure", result, "the variant's own end is its pass, never a known failure")
        self.assertEqual("scoped-tun-fault-recovered", self.owner.events[-1][0])
        self.assertEqual([(70, False), (77, False)], actors, "owner and the original A runtime, unelevated")
        self.assertTrue(stages.settled(lease), "nothing scoped can run: a later failure closes as a known one")
        self.processes = [row for row in self.processes if row["pid"] != 77]  # The row's own off retired A.
        self.assertEqual([], stages.closing(self.owner, lease, self.observer)["brokers"])

    def test_a_preparation_failure_that_moved_a_or_started_anything_scoped_parks(self):
        for name, change, reason in (("runtime", {"runtimeId": "r2"}, "uac-denial-lost-active-a-or-pending-b"),
                                     ("broker", None, "scoped-tun-unexpected-terminal-scoped-state")):
            with self.subTest(case=name):
                self.setUp()
                lease = self.leased("vpn-prepare-failure")
                if change is None:
                    self.processes.append({"pid": 140, "parentPid": 70, "name": "vpn-control-vpn-broker.exe"})
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.finish(lease, "RUNTIME_FAILED", **(change or {}))
                self.assertFalse(lease["finished"], "an open outcome parks")
                self.assertFalse(stages.settled(lease))

    def test_a_preparation_failure_that_came_up_or_ended_otherwise_is_never_its_pass(self):
        lease = self.leased("vpn-prepare-failure")
        with self.assertRaisesRegex(AssertionError, "^uac-denial-lost-active-a-or-pending-b$"):
            self.finish(lease, "OK", activeMode="vpn", runtimeId="vpn-b")
        self.assertFalse(lease["finished"])
        self.setUp()
        lease = self.leased("vpn-prepare-failure")
        result, _ = self.finish(lease, "CANCELLED")
        self.assertEqual("CANCELLED", result["knownFailure"], "with no prompt a CANCELLED is a known failure, never a cancelled grant")
        self.assertNotIn("faultRecovered", lease)


class CommitFailureTests(VariantWorld):
    def log(self, raw=b"FATAL start inbound/mixed[owned-conflict]: listen tcp 127.0.0.1:41001: bind: address already in use\n"):
        path = self.workspace / "runtime" / "runtime-sing-box.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)

    def test_a_commit_failure_brings_a_back_as_a_new_unelevated_runtime_with_nothing_scoped_left(self):
        lease = self.leased("vpn-commit-failure")
        self.log()
        self.processes = [row for row in self.processes if row["pid"] != 77] + [{"pid": 79, "parentPid": 70, "name": "sing-box.exe"}]
        result, actors = self.finish(lease, "RUNTIME_FAILED", runtimeId="r-recovered", runtimeStartedAt="t2")
        self.assertTrue(result["faultRecovered"])
        self.assertEqual([(70, False), (79, False)], actors, "the recovered A runs unelevated")
        self.assertEqual(self.recovered, lease["state"]["actors"], "the row's own off and census take the recovered A")
        self.assertIn(("capture", "C:\\w\\sing-box.exe", "d" * 64), self.calls)
        census = self.owner.events[-1][1]["census"]
        self.assertEqual({"brokers": [], "runtimes": [88], "routes": []}, {key: census[key] for key in ("brokers", "runtimes", "routes")})
        self.assertTrue(stages.settled(lease))

    def test_a_commit_failure_that_did_not_recover_a_parks(self):
        cases = (("same-runtime", {}, None, "scoped-tun-commit-failure-did-not-recover-active-a"),
                 ("another-location", {"runtimeId": "r2", "activeLocationId": "b"}, None, "scoped-tun-commit-failure-did-not-recover-active-a"),
                 ("vpn-mode", {"runtimeId": "r2", "activeMode": "vpn"}, None, "scoped-tun-commit-failure-did-not-recover-active-a"),
                 ("original-alive", {"runtimeId": "r2"}, lambda: self.exits.__setitem__(0, {"pid": 77, "originalAbsent": False}),
                  "scoped-tun-commit-failure-original-a-not-retired"),
                 ("no-conflict-log", {"runtimeId": "r2"}, lambda: self.log(b"started\n"), "scoped-tun-commit-failure-conflict-log-required"),
                 ("broker-left", {"runtimeId": "r2"}, lambda: self.processes.append({"pid": 141, "parentPid": 70, "name": "vpn-control-vpn-broker.exe"}),
                  "scoped-tun-unexpected-terminal-scoped-state"))
        for name, status, change, reason in cases:
            with self.subTest(case=name):
                self.setUp()
                lease = self.leased("vpn-commit-failure")
                self.log()
                self.processes.append({"pid": 79, "parentPid": 70, "name": "sing-box.exe"})
                if change is not None:
                    change()
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.finish(lease, "RUNTIME_FAILED", **status)
                self.assertFalse(lease["finished"], "an open outcome parks")

    def test_a_failure_before_the_commit_with_a_untouched_and_nothing_running_is_a_known_end(self):
        """449c0f39: approved, then RUNTIME_FAILED with A's same runtime and nothing new running. The commit was never
        reached, so there was nothing to recover; the oracle's mismatch parked the owner over serve and fixture
        (scenario-failure-with-retained-child). The product's end is final and nothing scoped exists: a known end."""
        lease = self.leased("vpn-commit-failure")
        with mock.patch.object(stages, "product_diagnostics", lambda owner, lease, runtime, terminal, timeline: {"reach": "broker-ended-before-stage"}, create=True):
            result, actors = self.finish(lease, "RUNTIME_FAILED")
        self.assertEqual("RUNTIME_FAILED", result["knownFailure"])
        self.assertNotIn("faultRecovered", result)
        self.assertEqual([(70, False), (77, False)], actors, "the same A, unelevated")
        kind, value = self.owner.events[-1]
        self.assertEqual("scoped-tun-unexpected-terminal-known", kind)
        self.assertEqual(("scoped-tun-commit-failure-did-not-recover-active-a", False, {"reach": "broker-ended-before-stage"}),
                         (value["oracle"], value["commitReached"], value["diagnosis"]))
        self.assertEqual("RUNTIME_FAILED", lease["knownEnd"])
        self.assertTrue(stages.settled(lease), "the driver closes it by the row's own steps and ends 1, instead of parking")
        self.assertEqual(77, lease["state"]["actors"]["runtime"]["pid"], "the row's off and census take the A it had")

    def test_a_failure_before_the_commit_that_left_anything_still_parks_with_the_oracles_reason(self):
        for name, change in (("new-runtime", lambda: self.processes.append({"pid": 79, "parentPid": 70, "name": "sing-box.exe"})),
                             ("broker", lambda: self.processes.append({"pid": 141, "parentPid": 70, "name": "vpn-control-vpn-broker.exe"})),
                             ("pending-b-lost", lambda: self.status.update(selectedLocationId="a"))):
            with self.subTest(left=name):
                self.setUp()
                lease = self.leased("vpn-commit-failure")
                change()
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-commit-failure-did-not-recover-active-a$"):
                    self.finish(lease, "RUNTIME_FAILED")
                self.assertFalse(lease["finished"], "an open outcome parks")
                self.assertEqual("scoped-tun-product-diagnostics", self.owner.events[-1][0], "its diagnostics are kept")

    def test_an_expired_prompt_is_a_known_end_and_a_tun_that_came_up_parks(self):
        lease = self.leased("vpn-commit-failure")
        result, _ = self.finish(lease, "CANCELLED")
        self.assertTrue(result["cancelled"])
        self.assertEqual("CANCELLED", lease["knownEnd"])
        self.setUp()
        lease = self.leased("vpn-commit-failure")
        with self.assertRaisesRegex(AssertionError, "^uac-denial-lost-active-a-or-pending-b$"):
            self.finish(lease, "OK", activeMode="vpn", runtimeId="vpn-b")
        self.assertFalse(lease["finished"], "the approved broker may still run: never known, never a collector")


class ConfigurationTests(VariantWorld):
    def ready(self, variant, actual):
        config = self.workspace / "runtime-config.json"
        raw = branch_cases.encoded(actual)
        config.write_bytes(raw)
        lease = self.leased(variant)
        lease["inputs"] = dict(lease["inputs"], runtimeConfigPath=str(config))
        lease.update(finished=True, nativeReady={"stage": "ready", "observations": {"configuration": {"sha256": hashlib.sha256(raw).hexdigest(),
                                                                                                          "sizeBytes": len(raw)}}})
        return lease, config

    def test_a_config_grant_reads_the_ready_records_bytes_as_its_own_documents_vpn_config(self):
        for variant in CONFIG_VARIANTS:
            with self.subTest(variant=variant):
                self.setUp()
                actual = generated_vpn() if variant == "generated-grant" else transformed(branch_cases.custom_config(PORT, KINDS[variant]), self.workspace)
                lease, _ = self.ready(variant, actual)
                self.assertEqual(actual, stages.configuration(self.owner, lease, self.branches))
                kind, value = self.owner.events[-1]
                self.assertEqual("scoped-tun-configuration-observed", kind)
                self.assertEqual(variant == "generated-grant", value["tunInbound"])
                self.assertEqual(variant == "generated-grant", value["directSamplerAllowed"])
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-configuration-window$"):
                    stages.configuration(self.owner, lease, self.branches)

    def test_a_config_that_is_not_the_ready_records_or_not_its_document_fails(self):
        custom = transformed(branch_cases.custom_config(PORT, "custom"), self.workspace)
        tun = dict(custom, inbounds=[{"type": "tun", "tag": "extra", "address": ["172.19.250.1/30"]}] + custom["inbounds"])
        for name, variant, actual, change, reason in (
                ("rewritten", "custom-grant", custom, lambda config: config.write_bytes(config.read_bytes().replace(b"error", b"debug")),
                 "scoped-tun-configuration-not-the-ready-record"),
                ("custom-with-a-tun", "custom-grant", tun, None, "custom-original-inbounds-changed"),
                ("generated-without-a-tun", "generated-grant", dict(generated_vpn(), inbounds=generated_vpn()["inbounds"][1:]), None,
                 "scoped-tun-generated-configuration"),
                ("generated-to-another-server", "generated-grant", generated_vpn(PORT + 1), None, "scoped-tun-generated-configuration")):
            with self.subTest(case=name):
                self.setUp()
                lease, config = self.ready(variant, actual)
                if change is not None:
                    change(config)
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    stages.configuration(self.owner, lease, self.branches)
                self.assertNotIn("configurationObserved", lease)

    def test_only_a_generated_tun_carries_the_direct_sampler_and_every_grant_ends_by_its_own_off(self):
        lease, _ = self.ready("custom-grant", transformed(branch_cases.custom_config(PORT, "custom"), self.workspace))
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-direct-traffic-window$"):
            stages.traffic(self.owner, lease)
        self.assertEqual([], self.owner.children, "no sample left the guest")
        runtime = self.runtime()
        self.status.update(activeMode="vpn", runtimeRunning=True)
        result = runtime.result

        def off(owner, workspace, identity, *arguments, **options):
            if arguments[-1] == "off":
                self.status.update(runtimeRunning=False)
                return {"code": "OK"}
            return result(owner, workspace, identity, *arguments, **options)
        runtime.result = off
        with mock.patch.object(stages, "guest_filetime", lambda: 5):
            stages.begin_off(self.owner, lease, runtime)
        self.assertTrue(lease["offRequested"])


class DriverVariantTests(unittest.TestCase):
    OPERATION = "2c731e91-c158-4e8a-b779-54076ce85229"
    EVIDENCE = "C:\\ProgramData\\tun-evidence-" + OPERATION

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        clock = types.SimpleNamespace(sleep=lambda seconds: self.owner.calls.append(("sleep", seconds)))
        for patcher in (mock.patch.object(dedicated_driver, "__file__", str(DedicatedDispatchPeer.SOURCE_ROOT / "windows_ordinary_dedicated_driver.py")),
                        mock.patch.object(dedicated_driver, "time", clock, create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def row(self, variant, *, hold="default", stages_fake=None):
        owner = self.owner = DedicatedDispatchPeer(self.root)
        self.state, _ = owner.lifecycle("find-best-success")
        self.state["serve"].pid, self.state["serve"].birth = SERVE_PID, str(SERVE_BIRTH)
        owner.inputs["variant"] = variant
        runtime = owner.inputs["runtime"]
        runtime.update(workspace=str(self.root / "workspace"), ordinaryContextArtifactId="peer-context")
        path = owner.source("windows_tun_stages.py", "agent_tools/windows_tun_stages.py")
        branches = owner.source("windows_runtime_branch_cases.py", "agent_tools/windows_runtime_branch_cases.py")
        owner.inputs["modules"].update(tun=path, branches=branches)
        owner.inputs["tun"] = {"schemaVersion": 1, "variant": variant, "installedAdmissionArtifactId": runtime["installedAdmissionArtifactId"],
                               "ordinaryContextArtifactId": "peer-context", "runtimeConfigPath": str(PureWindowsPath(runtime["workspace"]) / "runtime-config.json"),
                               "collectorSourceSha256": contract.COLLECTORS["tun"]}
        if variant == "generated-grant":
            owner.inputs["tun"]["samplerPath"] = owner.source("windows_tun_direct_sampler.py", "agent_tools/windows_tun_direct_sampler.py")
        self.branches = types.SimpleNamespace(close_fixture_files_after_off=lambda *args: owner.calls.append("close-fixture-files"))
        owner.modules[branches] = self.branches
        self.records = GrantRecords(owner.calls)
        hold_inputs = owner.tun_grant(self.records)
        if hold == "default":
            hold = hold_inputs if variant in CONFIG_VARIANTS else None
        owner.modules[path] = stages_fake or self.stages()
        owner.harness({"LIFECYCLE_INPUTS": owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": hold})

    def stages(self):
        test = self

        def calls():
            return test.owner.calls

        def begin(owner, state, inputs, runtime, cases, observer, branches=None):
            calls().append(("tun-begin", inputs["variant"], branches is test.branches))
            owner.tun_operation_requested = True
            lease = {"inputs": dict(inputs, programData="C:\\ProgramData"), "state": state, "finished": False,
                     "accepted": {"operationId": PRODUCT_OPERATION, "requestId": REQUEST_ID},
                     "baseline": {"brokers": [], "runtimes": [], "stages": [], "routes": []}}
            owner.tun_operation_leases = [lease]
            return lease

        def finish(owner, lease, runtime, cases, observer, handoff=None, receipts=None):
            calls().append(("tun-finish", handoff is not None))
            if lease["inputs"]["variant"] in FAULT_VARIANTS:
                lease["state"]["actors"] = {"owner": {"peer": "original-owner"}, "runtime": {"peer": "recovered-runtime"}}
                lease.update(finished=True, faultRecovered="RUNTIME_FAILED")
                return {"terminal": {"code": "RUNTIME_FAILED"}, "status": {}, "nativeRecord": None, "faultRecovered": True}
            test.records.records[test.EVIDENCE + "\\ready.json"] = b'{"stage":"ready"}'
            handoff(lease, "ready")
            lease.update(finished=True, nativeReady={"stage": "ready"})
            return {"terminal": {"code": "OK"}, "status": {}, "nativeRecord": lease["nativeReady"]}

        def configuration(owner, lease, branches):
            calls().append(("tun-configuration", branches is test.branches))

        def begin_off(owner, lease, runtime):
            calls().append("tun-off")
            lease["offRequested"] = True
            test.records.records[test.EVIDENCE + "\\off.json"] = b'{"stage":"off"}'

        def finish_off(owner, lease, record, receipts):
            calls().append("tun-off-record")
            lease["offFinished"] = True

        def closing(owner, lease, observer):
            calls().append("tun-closing")
            with mock.patch.object(stages, "census", lambda inputs, observer, exclude=(): {"brokers": [], "runtimes": [], "stages": [], "routes": []}):
                return stages.closing(owner, lease, observer)
        return types.SimpleNamespace(begin=begin, finish=finish, configuration=configuration, traffic=lambda owner, lease: calls().append("tun-traffic"),
                                     begin_off=begin_off, finish_off=finish_off, closing=closing, settled=stages.settled)

    def test_a_config_grant_compares_its_config_then_ends_by_its_own_off_under_its_collectors_hold(self):
        for variant in CONFIG_VARIANTS:
            with self.subTest(variant=variant):
                self.row(variant)
                self.assertEqual(0, dedicated_driver.run(self.owner, "windows-proxy-lifecycle"))
                order = ["arm", ("tun-begin", variant, True), ("tun-finish", True), ("tun-configuration", True), "tun-traffic", "tun-off", "tun-off-record",
                         "tun-closing", "close-fixture-files", "stop-fixture", ("public", "quit"), ("driver-completed", 0), "wait-release"]
                expected = [step for step in order if step != "tun-traffic" or variant == "generated-grant"]
                self.assertEqual(expected, [call for call in self.owner.calls if call in order],
                                 "only the generated TUN is sampled; the documents close after the off")
                self.assertEqual(1, len([call for call in self.owner.calls if isinstance(call, tuple) and call[0] == dedicated_driver.NATIVE_NEED]))
                self.assertEqual("released", self.owner.caller_collection_hold.state)

    def test_a_fault_variant_never_asks_a_collector_and_closes_with_the_recovered_a(self):
        for variant in FAULT_VARIANTS:
            with self.subTest(variant=variant):
                self.row(variant)
                self.assertEqual(0, dedicated_driver.run(self.owner, "windows-proxy-lifecycle"))
                calls = self.owner.calls
                self.assertNotIn("arm", calls)
                self.assertFalse([call for call in calls if isinstance(call, tuple) and call[0] == dedicated_driver.NATIVE_NEED], "no TUN came up")
                self.assertIn(("off-actors", ({"peer": "original-owner"}, {"peer": "recovered-runtime"})), calls, "the row's own off of A as recovered")
                order = [("tun-begin", variant, True), ("tun-finish", False), "tun-closing", "close-fixture-files", "stop-fixture", ("public", "quit")]
                self.assertEqual(order, [call for call in calls if call in order])
                closed = [call[1] for call in calls if isinstance(call, tuple) and call[0] == "dedicated-proxy-lifecycle-known-closed"]
                self.assertEqual(1, len(closed))
                self.assertNotIn("knownFailure", closed[0], "the fault is the variant's own end")

    def test_a_fault_variant_with_a_hold_or_a_config_grant_without_one_starts_nothing(self):
        for variant, hold, reason in (("vpn-commit-failure", "grant", "proxy-has-no-system-collector"),
                                      ("custom-grant", None, None)):
            with self.subTest(variant=variant):
                self.row(variant)
                hold_inputs = self.owner.tun_grant(self.records) if hold == "grant" else None
                self.owner.harness({"LIFECYCLE_INPUTS": self.owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": hold_inputs})
                with self.assertRaises(Exception) as caught:
                    dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
                if reason is not None:
                    self.assertEqual(reason, str(caught.exception))
                self.assertNotIn("start-runtime", self.owner.calls)
                self.assertNotIn("arm", self.owner.calls)

    def test_the_variant_sets_name_each_route(self):
        self.assertEqual(set(CONFIG_VARIANTS) | set(FAULT_VARIANTS), set(dedicated_driver.TUN_VARIANTS) - {"restart-deny", "restart-grant"}
                         - {"find-best-deny", "find-best-grant"} - dedicated_driver.RESERVED_VARIANTS)
        self.assertEqual(set(CONFIG_VARIANTS), set(dedicated_driver.TUN_GRANT_VARIANTS) - {"restart-grant", "find-best-grant", "resources-grant", "ssh-grant"})
        self.assertEqual({"restart-grant", "generated-grant"}, set(dedicated_driver.TUN_SAMPLED_VARIANTS) - {"find-best-grant", "resources-grant", "ssh-grant"})


class PlannerVariantTests(unittest.TestCase):
    def test_each_variant_is_admitted_with_its_documents_and_only_its_collector_and_sampler(self):
        for variant in CONFIG_VARIANTS + FAULT_VARIANTS:
            name = _T + variant
            with self.subTest(variant=variant):
                self.assertIn(variant, windows.TUN_VARIANTS)
                row = windows.RECIPES[name]
                self.assertIsNone(row["refusal"])
                files = {relative: role for relative, role, _ in row["guestFiles"]}
                self.assertEqual("branches", files["agent_tools/windows_runtime_branch_cases.py"], "the proxy rows' own documents")
                self.assertNotIn("agent_tools/windows_runtime_tcp_listeners.ps1", files)
                grant = variant in CONFIG_VARIANTS
                self.assertEqual(grant, "agent_tools/windows_tun_native_observer.py" in files)
                self.assertEqual(({"collectorStages": ("tun",), "finalStage": "tun"} if grant else {}),
                                 {key: value for key, value in row["tun"].items() if key != "variant"})
                self.assertEqual(variant == "generated-grant", "agent_tools/windows_tun_direct_sampler.py" in files)
                self.assertEqual(variant == "generated-grant", "samplerInput" in [role for role, _ in row["generated"]])
                self.assertEqual(tuple((role, proxy.GENERATED[role]) for role in proxy.generated_roles(variant)), row["generated"])

    def test_each_prompt_is_approved_by_the_table_and_the_preparation_failure_has_none(self):
        for variant in CONFIG_VARIANTS + FAULT_VARIANTS:
            name = _T + variant
            row = windows.RECIPES[name]
            with self.subTest(variant=variant):
                if variant == "vpn-prepare-failure":
                    self.assertNotIn("uac", row)
                    self.assertNotIn(name, decision.ROWS, "no prompt: a decision would wait on nothing")
                    continue
                self.assertEqual({"prompt": "vpn-broker", "decision": "approve", "event": "scoped-tun-awaiting-current-input"}, row["uac"])
                self.assertEqual((False, True), (row["denyJoin"], row["approveJoin"]), "a pass names the reviewed approval")
                table = decision.ROWS[name]
                self.assertEqual(("vpn-broker", "approve", "scoped-tun-awaiting-current-input", "variant", variant, "expectedApprovingAdminSid"),
                                 tuple(table[key] for key in ("prompt", "decision", "event", "field", "value", "sidField")))

    def test_the_three_scenarios_need_both_halves(self):
        table = windows.MATRIX_SCENARIOS["windows-scoped-vpn"]
        self.assertEqual((_P + "prepare-failure", _P + "commit-readiness-failure", _T + "vpn-prepare-failure", _T + "vpn-commit-failure"),
                         table["prepare-commit-recovery"])
        self.assertEqual((_P + "generated", _P + "custom", _T + "generated-grant", _T + "custom-grant"), table["generated-custom-config"])
        self.assertEqual((_P + "large", _T + "large-grant"), table["large-config"])
        for rows in (table["prepare-commit-recovery"], table["generated-custom-config"], table["large-config"]):
            self.assertTrue(all(windows.RECIPES[row].get("refusal") is None for row in rows))

    def test_the_harness_names_each_variants_location_and_documents(self):
        paths = {"productWorkspace": "C:\\ws", "installed": "C:\\app", "operationRoot": "C:\\root", "file:runtime": "C:\\w\\r.py",
                 "file:observer": "C:\\w\\o.py", "file:fixture": "C:\\w\\f.py", "file:socks": "C:\\w\\s.py", "file:https": "C:\\w\\h.py",
                 "file:certificate": "C:\\w\\c.pem", "file:privateKey": "C:\\w\\c.key", "file:trustStore": "C:\\w\\t.jks", "file:tun": "C:\\w\\t.py",
                 "file:branches": "C:\\w\\b.py", "file:sampler": "C:\\w\\sampler.py", "file:samplerInput": "C:\\w\\in.json"}
        admissions = {"installed": "i", "material": "m", "context": "c", "fixture": "f", "source": "s"}
        tun = {"administratorSid": ADMIN, "decisionId": str(uuid.uuid4()), "collectorSourceSha256": "c" * 64}
        for variant in CONFIG_VARIANTS + FAULT_VARIANTS:
            with self.subTest(variant=variant):
                hold = {"scope": "tun"} if variant in CONFIG_VARIANTS else None
                raw = proxy.harness(variant, operation="op", paths=paths, runtime_sha256="d" * 64, source_sha="e" * 40, admissions=admissions,
                                    tun=dict(tun), hold=hold).decode()
                namespace = {}
                exec(compile(raw, "harness", "exec"), namespace)
                value = namespace["LIFECYCLE_INPUTS"]
                self.assertEqual(NAMES[variant], value["tun"]["pendingLocation"])
                self.assertEqual("C:\\w\\b.py", value["modules"]["branches"])
                self.assertEqual(variant == "generated-grant", "samplerPath" in value["tun"])
                self.assertEqual(hold, namespace["SYSTEM_COLLECTOR_CLOSE_HOLD"])


if __name__ == "__main__":
    unittest.main()
