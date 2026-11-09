"""Scoped-TUN stages on the Windows scenario route, their direct sampler and their generated inputs, all offline.

No socket, process, route table or guest is touched: every native boundary is a declared fake.
"""
from __future__ import annotations

import ast
import ctypes
import json
from pathlib import Path
import socket
import subprocess
import sys
import types
import unittest
from unittest import mock
import uuid

from agent_tools import windows_scenario_proxy as proxy
from agent_tools import windows_tun_direct_sampler as sampler
from agent_tools import windows_tun_stages as stages

ORDINARY = "S-1-5-21-1-2-3-1000"
ADMIN = "S-1-5-21-1-2-3-500"
GUI = "C:\\Users\\recovery\\AppData\\Local\\vpn-control\\vpn-control.exe"
WORKSPACE = "C:\\Users\\recovery\\AppData\\Local\\VpnControlOrdinary-op\\workspace"
SAMPLER = "C:\\ProgramData\\VpnControlOrdinaryTask-op\\windows_tun_direct_sampler.py"
SAMPLER_INPUT = "C:\\ProgramData\\VpnControlOrdinaryTask-op\\tun-direct-traffic.json"
PYTHON = "C:\\Users\\recovery\\AppData\\Local\\Programs\\Python\\Python313\\python.exe"
CLI = "C:\\Users\\recovery\\AppData\\Local\\vpn-control\\vpn-control-cli.exe"
BODY = "vpn-control-proxy-fixture"


def response(body):
    return b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body


class Stream:
    def __init__(self, reply):
        self.sent, self.reply, self.timeouts = b"", reply, []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def settimeout(self, value):
        self.timeouts.append(value)

    def sendall(self, raw):
        self.sent += raw

    def recv(self, size):
        part, self.reply = self.reply[:size], self.reply[size:]
        return part


def sampler_value(**changes):
    return {"schemaVersion": 1, "expectedBodyHex": BODY.encode().hex(), "sampleCount": 3, "intervalSeconds": 0.25,
            "ioTimeoutSeconds": 5, **changes}


class DirectSamplerTests(unittest.TestCase):
    def run_sampler(self, replies, **changes):
        streams, connects, sleeps, rows = [], [], [], []

        def connect(address, timeout):
            connects.append((address, timeout))
            reply = replies[len(connects) - 1]
            if isinstance(reply, Exception):
                raise reply
            streams.append(Stream(reply))
            return streams[-1]
        code = sampler.run(sampler_value(**changes), rows.append, connect=connect, sleep=sleeps.append, monotonic=lambda: 1.0)
        return code, rows, connects, streams, sleeps

    def test_each_sample_is_plain_http_to_the_benchmark_address_with_no_socks_step(self):
        code, rows, connects, streams, sleeps = self.run_sampler([response(BODY.encode())] * 3)
        self.assertEqual(0, code)
        self.assertEqual([(("198.18.0.1", 80), 5)] * 3, connects)
        for stream in streams:
            self.assertEqual(b"GET /probe HTTP/1.1\r\nHost: 198.18.0.1\r\nConnection: close\r\n\r\n", stream.sent)
            self.assertFalse(stream.sent.startswith(b"\x05"), "no SOCKS greeting: the TUN, not a proxy port, carries it")
        self.assertEqual([0.25, 0.25], sleeps, "an interval between samples, none after the last")
        self.assertEqual([{"kind": "sample", "ordinal": index, "succeeded": True, "reason": None, "elapsedSeconds": 0.0} for index in range(3)]
                         + [{"kind": "terminal", "sampleCount": 3, "allSamplesSucceeded": True}], rows)

    def test_a_refused_connection_or_another_body_fails_the_run_and_every_sample_is_kept(self):
        code, rows, _, _, _ = self.run_sampler([response(BODY.encode()), ConnectionRefusedError(), response(b"other")])
        self.assertEqual(1, code)
        self.assertEqual([(True, None), (False, "ConnectionRefusedError"), (False, "response")],
                         [(row["succeeded"], row["reason"]) for row in rows[:-1]])
        self.assertEqual({"kind": "terminal", "sampleCount": 3, "allSamplesSucceeded": False}, rows[-1])
        for status in (b"HTTP/1.1 502 Bad Gateway", b"HTTP/1.1 200 OK"):
            with self.subTest(status=status):
                raw = status + b"\r\n\r\n" + (BODY.encode() + b"x" if status.endswith(b"OK") else BODY.encode())
                code, rows, _, _, _ = self.run_sampler([raw], sampleCount=1)
                self.assertEqual((1, "response"), (code, rows[0]["reason"]))

    def test_an_endless_reply_is_read_only_to_its_bound(self):
        code, rows, _, streams, _ = self.run_sampler([b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 200000], sampleCount=1)
        self.assertEqual(1, code)
        self.assertLess(200000 - len(streams[0].reply), 70000)

    def test_inputs_are_closed_and_bounded(self):
        for change in ({"sampleCount": 0}, {"sampleCount": 65}, {"sampleCount": True}, {"intervalSeconds": 0}, {"ioTimeoutSeconds": 11},
                       {"ioTimeoutSeconds": float("nan")}, {"expectedBodyHex": ""}, {"expectedBodyHex": "zz"}, {"expectedBodyHex": 7},
                       {"expectedBodyHex": "00" * 4097}, {"schemaVersion": 2}, {"mixedPort": 1080}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "direct-sampler-input"):
                sampler.run(sampler_value(**change), lambda row: None, connect=None)


class Recorder:
    """The ordinary owner as the stages see it: events, pins and one child at a time."""

    def __init__(self, operation=None):
        self.operation = operation or str(uuid.uuid4())
        self.request = {"operationId": self.operation, "context": {"ordinarySid": ORDINARY, "ordinarySessionId": 2},
                        "pythonRuntime": {"interpreterPath": PYTHON}}
        self.by_path = {GUI.casefold(): types.SimpleNamespace(), SAMPLER.casefold(): types.SimpleNamespace(),
                        SAMPLER_INPUT.casefold(): types.SimpleNamespace(digest=lambda raw, maximum: proxy.sampler_input("op").replace(
                            proxy.fixture_body("op").encode().hex().encode(), BODY.encode().hex().encode()))}
        self.events, self.children, self.root = [], [], Path("/owned-root")
        self.output = None

    def event(self, kind, value):
        self.events.append((kind, value))

    def child(self, label, argv):
        self.children.append((label, argv))
        return types.SimpleNamespace(ordinal=len(self.children), completed=lambda: self.output)


class StageWorld(unittest.TestCase):
    def setUp(self):
        self.processes = [{"pid": 4, "parentPid": 0, "name": "System"}, {"pid": 77, "parentPid": 70, "name": "sing-box.exe"},
                          {"pid": 88, "parentPid": 80, "name": "sing-box.exe"}]
        self.entries = ["Microsoft", "vpn-control-vpn-0f0f0f0f-0000-4000-8000-000000000001", "VpnControlOrdinaryTask-op"]
        self.routes = []
        fake_os = types.SimpleNamespace(name="nt", environ={"ProgramData": "C:\\ProgramData"}, listdir=lambda path: list(self.entries))
        for patcher in (mock.patch.object(stages, "os", fake_os), mock.patch.object(stages, "tun_routes", lambda: list(self.routes))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.observer = types.SimpleNamespace(WindowsNative=lambda: types.SimpleNamespace(processes=lambda: [dict(row) for row in self.processes]))
        self.owner = Recorder()
        self.status = {"runtimeRunning": True, "activeMode": "proxy-only", "activeLocationId": "a", "selectedLocationId": "a",
                       "runtimeId": "r", "runtimeStartedAt": "t", "configuredMode": "proxy-only"}
        self.revision = 4
        self.calls = []

    def inputs(self, variant="restart-deny", **changes):
        value = {"schemaVersion": 1, "variant": variant, "pendingLocation": "Owned B", "runtimeConfigPath": WORKSPACE + "\\runtime-config.json",
                 "guiPath": GUI, "installedAdmissionArtifactId": "sha256-" + "a" * 64, "ordinaryContextArtifactId": "windows-context-" + "b" * 64,
                 "expectedApprovingAdminSid": ADMIN, "uacDecisionId": stages.decision_id(self.owner.operation), "programData": "C:\\ProgramData",
                 "collectorSourceSha256": "c" * 64}
        if variant.endswith("grant"):
            value.update(samplerPath=SAMPLER, samplerInputPath=SAMPLER_INPUT)
        value.update(changes)
        return value

    def state(self):
        return {"workspace": WORKSPACE, "identity": "controller-1", "actors": {"owner": {"pid": 70}, "runtime": {"pid": 77}},
                "serve": types.SimpleNamespace(ordinal=3), "inputs": {"fixtureBody": BODY}}

    def runtime(self):
        test = self

        def result(owner, workspace, identity, *arguments, final=True, codes=("OK",)):
            test.calls.append(arguments)
            if arguments[-1] == "status":
                restart = test.status["configuredMode"] == "vpn" or test.status["selectedLocationId"] != test.status["activeLocationId"]
                return {"data": dict(test.status), "restartRequired": restart, "configurationRevision": test.revision}
            if arguments[:1] == ("--async",):
                return {"operationId": str(uuid.uuid4()), "requestId": str(uuid.uuid4()), "controllerId": identity, "code": "ACCEPTED", "final": False}
            if arguments[-3:] == ("locations", "select", "Owned B"):
                test.status["selectedLocationId"] = "b"
            if arguments[-4:] == ("settings", "set", "mode", "vpn"):
                test.status["configuredMode"] = "vpn"
            test.revision += 1
            return {"data": {}, "configurationRevision": test.revision}
        return types.SimpleNamespace(result=result, publish=lambda owner, path, raw: test.calls.append(("publish", path.name)))

    def cases(self):
        class LiveConfig:
            def __init__(self, owner, workspace, path):
                self.initial = {"sizeBytes": 3, "sha256": __import__("hashlib").sha256(b"{a}").hexdigest()}

            def snapshot(self):
                return self.initial

            def close(self):
                pass
        self.actors = []
        return types.SimpleNamespace(LiveConfig=LiveConfig, config_bytes=lambda path: {"sizeBytes": 3, "sha256": __import__("hashlib").sha256(b"{a}").hexdigest()},
                                     exact_actor=lambda native, actor, elevated: self.actors.append((actor["pid"], elevated)))

    def begin(self, inputs=None, runtime=None):
        # Each row starts from active proxy A with nothing pending.
        self.status = {"runtimeRunning": True, "activeMode": "proxy-only", "activeLocationId": "a", "selectedLocationId": "a",
                       "runtimeId": "r", "runtimeStartedAt": "t", "configuredMode": "proxy-only"}
        with mock.patch.object(stages, "Path", PurePathReading):
            return stages.begin(self.owner, self.state(), inputs or self.inputs(), runtime or self.runtime(), self.cases(), self.observer)

    def answering(self, returncode, body, stderr="", then=None):
        """runtime.result as the real one runs the request: its own public child completes, then its envelope check fails."""
        runtime = self.runtime()
        result = runtime.result

        def asked(owner, workspace, identity, *arguments, **options):
            if arguments[:1] != ("--async",):
                return result(owner, workspace, identity, *arguments, **options)
            self.calls.append(arguments)
            argv = (CLI, "--state-dir", workspace, "--json", "--controller-id", identity, *arguments)
            stdout = body if isinstance(body, str) else json.dumps(body)
            owner.children.append(types.SimpleNamespace(argv=argv, completed=lambda: subprocess.CompletedProcess(argv, returncode, stdout, stderr)))
            if then is not None:
                then()
            raise AssertionError("runtime-public-cli-exit-stderr")
        runtime.result = asked
        return runtime

    @staticmethod
    def reply(code, **changes):
        return {"schemaVersion": 1, "controllerId": "controller-1", "requestId": str(uuid.uuid4()), "code": code, "final": True, "ok": False,
                "configurationRevision": 6, **changes}


class PurePathReading(type(Path())):
    """Path, with the active-A beforeimage read the stages take before the restart."""

    def read_bytes(self):
        return b"{a}"


class BeginTests(StageWorld):
    def test_the_inputs_are_the_closed_route_set_and_the_one_decision_of_this_operation(self):
        lease = self.begin()
        kinds = [kind for kind, _ in self.owner.events]
        self.assertEqual(["scoped-tun-awaiting-current-input"], kinds, "published once: the decision's census requires exactly one")
        value = self.owner.events[0][1]
        self.assertEqual(("restart-deny", ADMIN, stages.decision_id(self.owner.operation)),
                         (value["variant"], value["expectedApprovingAdminSid"], value["uacDecisionId"]))
        self.assertNotIn("currentMainInputAdmissionArtifactId", value)
        self.assertEqual({"brokers": [], "runtimes": [88], "stages": ["vpn-control-vpn-0f0f0f0f-0000-4000-8000-000000000001"], "routes": []},
                         lease["baseline"], "the row's own runtime is not part of what it found")
        self.assertEqual(("--async", "restart"), self.calls[-1][-2:])
        self.assertTrue(self.owner.tun_operation_requested, "from the request on, a failure parks instead of closing as known")

    def test_a_lost_or_malformed_request_reply_leaves_the_row_parking(self):
        runtime = self.runtime()
        result = runtime.result

        def refusing(owner, workspace, identity, *arguments, **options):
            if arguments[:1] == ("--async",):
                raise AssertionError("runtime-public-cli-envelope")
            return result(owner, workspace, identity, *arguments, **options)
        runtime.result = refusing
        with mock.patch.object(stages, "Path", PurePathReading), self.assertRaisesRegex(AssertionError, "^runtime-public-cli-envelope$"):
            stages.begin(self.owner, self.state(), self.inputs(), runtime, self.cases(), self.observer)
        self.assertTrue(self.owner.tun_operation_requested, "the product may have accepted it: the outcome is open")
        self.assertEqual([], self.owner.events)

    def test_a_final_refusal_of_the_request_from_this_controller_is_a_known_end(self):
        # The owner refused at admission (BUSY), or the job ended before the reply was built: either way no operation is open.
        for code, exit_code, operation in (("BUSY", 1, None), ("RUNTIME_FAILED", 1, str(uuid.uuid4())), ("CANCELLED", 130, str(uuid.uuid4()))):
            with self.subTest(code=code):
                self.setUp()
                body = self.reply(code, **({} if operation is None else {"operationId": operation}))
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-request-refused$"):
                    self.begin(runtime=self.answering(exit_code, body))
                self.assertFalse(self.owner.tun_operation_requested, "nothing is open: the driver closes the row as a known failure")
                self.assertEqual(["scoped-tun-request-refused-known"], [kind for kind, _ in self.owner.events], "no prompt event: nothing awaits a decision")
                self.assertEqual(body, self.owner.events[0][1]["reply"])
                self.assertEqual([(70, False), (77, False)], self.actors, "owner and runtime stay unelevated")
                self.assertEqual([], getattr(self.owner, "tun_operation_leases", []))
                self.assertEqual(1, sum(1 for call in self.calls if call[:1] == ("--async",)), "the request is never sent again")

    def test_any_other_reply_to_the_request_leaves_its_outcome_open(self):
        for name, exit_code, body, stderr in (("outcome-unknown", 2, self.reply("OUTCOME_UNKNOWN", final=False, controllerId=None), ""),
                                              ("unavailable", 2, self.reply("UNAVAILABLE", controllerId=None), ""),
                                              ("local-permission", 1, self.reply("PERMISSION_DENIED", controllerId=None), ""),
                                              ("another-controller", 1, self.reply("BUSY", controllerId="controller-2"), ""),
                                              ("not-final", 1, self.reply("BUSY", final=False), ""),
                                              ("reported-done", 0, self.reply("OK", ok=True), ""),
                                              ("exit-mismatch", 2, self.reply("BUSY"), ""),
                                              ("stderr", 1, self.reply("BUSY"), "transport warning"),
                                              ("not-json", 1, "Busy.", ""),
                                              ("code-type", 1, self.reply(["BUSY"]), "")):
            with self.subTest(reply=name):
                self.setUp()
                with self.assertRaisesRegex(AssertionError, "^runtime-public-cli-exit-stderr$"):
                    self.begin(runtime=self.answering(exit_code, body, stderr))
                self.assertTrue(self.owner.tun_operation_requested, "the product may hold the operation: the owner parks")
                self.assertEqual([], self.owner.events)

    def test_a_refusal_that_moved_a_or_left_anything_scoped_still_parks(self):
        for name, change, reason in (("broker", lambda: self.processes.append({"pid": 140, "parentPid": 71, "name": "vpn-control-vpn-broker.exe"}),
                                      "scoped-tun-unexpected-terminal-scoped-state"),
                                     ("route", lambda: self.routes.append(["GetIpAddrTable", "172.19.250.1"]), "scoped-tun-unexpected-terminal-scoped-state"),
                                     ("pending-b", lambda: self.status.update(selectedLocationId="a"), "uac-denial-lost-active-a-or-pending-b")):
            with self.subTest(left=name):
                self.setUp()
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.begin(runtime=self.answering(1, self.reply("RUNTIME_FAILED", operationId=str(uuid.uuid4())), then=change))
                self.assertTrue(self.owner.tun_operation_requested)
                self.assertEqual([], self.owner.events)

    def test_another_operations_decision_or_a_caller_field_is_refused_before_any_read(self):
        for inputs, reason in ((self.inputs(uacDecisionId=stages.decision_id(str(uuid.uuid4()))), "scoped-tun-route-decision"),
                               (self.inputs(uacDecisionId=self.owner.operation), "scoped-tun-route-decision"),
                               (self.inputs(currentMainInputAdmissionArtifactId="frame"), "scoped-tun-native-inputs-pending"),
                               (self.inputs(samplerPath=SAMPLER), "scoped-tun-native-inputs-pending"),
                               ({**self.inputs("restart-grant"), "samplerPath": "C:\\elsewhere.py"}, "scoped-tun-held-sampler"),
                               (self.inputs(expectedApprovingAdminSid=ORDINARY), "scoped-tun-fixed-pending-location-admin-role"),
                               (self.inputs(pendingLocation="Owned A"), "scoped-tun-fixed-pending-location-admin-role"),
                               (self.inputs(variant="restart"), "scoped-tun-native-inputs-pending"),
                               (self.inputs(programData="C:\\Other"), "scoped-tun-current-programdata-context")):
            with self.subTest(reason=reason, keys=sorted(inputs)[:2]):
                self.calls.clear()
                with self.assertRaisesRegex(AssertionError, "^" + reason + "$"):
                    self.begin(inputs)
                self.assertEqual([], self.calls, "nothing was read or changed")
                self.assertEqual([], self.owner.events)
                self.assertFalse(getattr(self.owner, "tun_operation_requested", False), "a refusal here closes like any known failure")

    def test_a_broker_or_a_tun_route_before_the_row_refuses_before_any_change(self):
        for change in (lambda: self.processes.append({"pid": 99, "parentPid": 5, "name": "VPN-CONTROL-VPN-BROKER.EXE"}),
                       lambda: self.routes.append(["GetIpForwardTable", "172.19.250.2"])):
            with self.subTest():
                self.setUp()
                change()
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-clean-before-row$"):
                    self.begin()
                self.assertEqual([], self.calls)


class ClosingTests(StageWorld):
    def finished(self, variant="restart-deny"):
        lease = self.begin(self.inputs(variant))
        lease["finished"] = True
        # The public off retired the row's own runtime.
        self.processes = [row for row in self.processes if row["pid"] != 77]
        return lease

    def test_a_clean_closing_reads_once_after_the_public_off(self):
        lease = self.finished()
        found = stages.closing(self.owner, lease, self.observer)
        self.assertEqual({"brokers": [], "runtimes": [88], "stages": lease["baseline"]["stages"], "routes": []}, found)
        self.assertEqual("scoped-tun-closing-census", self.owner.events[-1][0])
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-closing-once$"):
            stages.closing(self.owner, lease, self.observer)

    def test_anything_scoped_left_behind_fails_the_closing(self):
        cases = {"broker": lambda: self.processes.append({"pid": 120, "parentPid": 71, "name": "vpn-control-vpn-broker.exe"}),
                 "runtime": lambda: self.processes.append({"pid": 121, "parentPid": 120, "name": "sing-box.exe"}),
                 "stage": lambda: self.entries.append("vpn-control-vpn-99999999-0000-4000-8000-000000000002"),
                 "route": lambda: self.routes.append(["GetIpAddrTable", "172.19.250.1"])}
        for name, change in cases.items():
            with self.subTest(left=name):
                self.setUp()
                lease = self.finished()
                change()
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-scoped-state-left-behind$"):
                    stages.closing(self.owner, lease, self.observer)
                self.assertNotIn("closed", lease)

    def test_a_grant_closes_only_after_its_exact_off(self):
        lease = self.finished("restart-grant")
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-closing-once$"):
            stages.closing(self.owner, lease, self.observer)
        lease["offFinished"] = True
        stages.closing(self.owner, lease, self.observer)
        unfinished = self.begin()
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-closing-once$"):
            stages.closing(self.owner, unfinished, self.observer)

    def test_an_operation_settles_on_a_denial_a_known_end_or_a_grants_exact_off(self):
        # Until it settles the driver parks on any failure; once settled a failure closes as a known one.
        def lease(variant, **changes):
            return {"inputs": {"variant": variant}, "finished": True, **changes}
        self.assertTrue(stages.settled(lease("restart-deny")))
        self.assertTrue(stages.settled(lease("restart-grant", knownEnd="CANCELLED")))
        self.assertTrue(stages.settled(lease("find-best-grant", offRequested=True, offFinished=True)))
        for value in (lease("restart-deny", finished=False), lease("restart-grant"), lease("restart-grant", nativeReady={"stage": "ready"}),
                      lease("restart-grant", offRequested=True), lease("restart-deny", finished=1)):
            with self.subTest(lease=value):
                self.assertFalse(stages.settled(value))


class FinishTests(StageWorld):
    """The public terminal of the row's own request: a denial's, or a known end that is not the variant's own."""

    def finish(self, lease, code, *, runtime_id="r"):
        runtime = self.runtime()
        waits = []

        def finish_operation(owner, state, accepted, codes, seconds=120):
            waits.append((sorted(codes), seconds))
            return {"code": code, "final": True}
        runtime.finish_operation = finish_operation
        self.status.update(runtimeId=runtime_id)
        actors = []
        cases = types.SimpleNamespace(config_bytes=lambda path: dict(lease["activeConfig"].initial),
                                      exact_actor=lambda native, actor, elevated: actors.append((actor["pid"], elevated)))
        result = stages.finish(self.owner, lease, runtime, cases, self.observer)
        self.assertEqual([(["CANCELLED", "OK", "PERMISSION_DENIED", "RUNTIME_FAILED"], 300)], waits)
        self.assertEqual([(70, False), (77, False)], actors, "owner and runtime stay unelevated")
        return result

    def test_a_denial_keeps_active_a_and_pending_b(self):
        for code in ("CANCELLED", "PERMISSION_DENIED"):
            with self.subTest(code=code):
                lease = self.begin()
                result = self.finish(lease, code)
                self.assertEqual(code, result["terminal"]["code"])
                self.assertNotIn("knownFailure", result)
                self.assertTrue(lease["finished"])

    def test_a_refused_preparation_is_known_only_when_nothing_scoped_started(self):
        lease = self.begin()
        result = self.finish(lease, "RUNTIME_FAILED")
        self.assertEqual("RUNTIME_FAILED", result["knownFailure"])
        self.assertEqual("scoped-tun-unexpected-terminal-known", self.owner.events[-1][0])
        self.assertTrue(lease["finished"])
        for name, change in (("broker", lambda: self.processes.append({"pid": 130, "parentPid": 71, "name": "vpn-control-vpn-broker.exe"})),
                             ("stage", lambda: self.entries.append("vpn-control-vpn-77777777-0000-4000-8000-000000000003")),
                             ("route", lambda: self.routes.append(["GetIpForwardTable", "172.19.250.2"]))):
            with self.subTest(left=name):
                lease = self.begin()
                change()
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-unexpected-terminal-scoped-state$"):
                    self.finish(lease, "RUNTIME_FAILED")
                self.assertFalse(lease["finished"], "an open outcome parks")
                self.setUp()

    def test_a_denial_must_keep_pending_b_selected(self):
        # A product that reselected A on the denial, with VPN mode still pending, still needs a restart: only B's selection tells.
        lease = self.begin()
        self.status.update(selectedLocationId="a")
        with self.assertRaisesRegex(AssertionError, "^uac-denial-lost-active-a-or-pending-b$"):
            self.finish(lease, "CANCELLED")
        self.assertFalse(lease["finished"], "an open outcome parks")

    def test_a_grant_that_ended_without_its_tun_closes_by_its_census_alone(self):
        # No TUN came up, so there is no off record to wait for: the census after the public off is its closing.
        for code, key in (("CANCELLED", "cancelled"), ("RUNTIME_FAILED", "knownFailure")):
            with self.subTest(code=code):
                self.setUp()
                lease = self.begin(self.inputs("restart-grant"))
                self.assertIn(key, self.finish(lease, code))
                self.processes = [row for row in self.processes if row["pid"] != 77]  # The public off retired A's runtime.
                found = stages.closing(self.owner, lease, self.observer)
                self.assertEqual({"brokers": [], "runtimes": [88], "stages": lease["baseline"]["stages"], "routes": []}, found)
                self.assertTrue(lease["closed"])
                self.assertEqual("scoped-tun-closing-census", self.owner.events[-1][0])

    def test_a_denial_that_connected_is_never_known(self):
        lease = self.begin()
        self.status.update(runtimeId="vpn-b")
        runtime = self.runtime()
        runtime.finish_operation = lambda *args, **options: {"code": "OK", "final": True}
        self.status.update(runtimeId="vpn-b", activeMode="vpn")
        cases = types.SimpleNamespace(config_bytes=lambda path: dict(lease["activeConfig"].initial), exact_actor=lambda *args, **options: None)
        with self.assertRaisesRegex(AssertionError, "^uac-denial-lost-active-a-or-pending-b$"):
            stages.finish(self.owner, lease, runtime, cases, self.observer)
        self.assertFalse(lease["finished"])


class TrafficTests(StageWorld):
    def ready(self):
        lease = self.begin(self.inputs("restart-grant"))
        lease.update(finished=True, nativeReady={"stage": "ready"})
        return lease

    def output(self, rows, code=0, stderr=""):
        self.owner.output = types.SimpleNamespace(returncode=code, stderr=stderr, stdout="".join(json.dumps(row) + "\n" for row in rows))

    def test_the_sampler_runs_held_and_only_inside_the_ready_window(self):
        lease = self.ready()
        rows = [{"kind": "sample", "ordinal": index, "succeeded": True, "reason": None, "elapsedSeconds": 0.1} for index in range(8)]
        self.output(rows + [{"kind": "terminal", "sampleCount": 8, "allSamplesSucceeded": True}])
        self.assertEqual(9, len(stages.traffic(self.owner, lease)))
        self.assertEqual([("scoped-tun-direct-traffic", [PYTHON, "-I", "-B", SAMPLER, "--input", SAMPLER_INPUT])], self.owner.children)
        self.assertEqual({"child": 1, "samples": 8, "target": "198.18.0.1:80", "socksStep": False, "replayAllowed": False}, self.owner.events[-1][1])
        lease["offRequested"] = True
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-direct-traffic-window$"):
            stages.traffic(self.owner, lease)
        for lease in (self.begin(), dict(self.ready(), nativeReady=None), dict(self.ready(), finished=False)):
            with self.subTest(), self.assertRaisesRegex(AssertionError, "^scoped-tun-direct-traffic-window$"):
                stages.traffic(self.owner, lease)
        self.assertEqual(1, len(self.owner.children), "nothing outside the window started a sampler")

    def test_a_failed_sample_or_a_short_stream_fails_the_row(self):
        good = {"kind": "sample", "ordinal": 0, "succeeded": True, "reason": None, "elapsedSeconds": 0.1}
        for rows, code in (([good, {**good, "ordinal": 1, "succeeded": False, "reason": "OSError"},
                             {"kind": "terminal", "sampleCount": 2, "allSamplesSucceeded": False}], 1),
                           ([{"kind": "terminal", "sampleCount": 0, "allSamplesSucceeded": True}], 0),
                           ([good, {"kind": "terminal", "sampleCount": 2, "allSamplesSucceeded": True}], 0)):
            with self.subTest(rows=len(rows)):
                lease = self.ready()
                self.output(rows, code)
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-direct-traffic$"):
                    stages.traffic(self.owner, lease)

    def test_the_sampler_must_expect_this_rows_own_upstream(self):
        lease = self.ready()
        lease["state"]["inputs"]["fixtureBody"] = "another-fixture"
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-sampler-owned-upstream-body$"):
            stages.traffic(self.owner, lease)
        self.assertEqual([], self.owner.children)


def ipv4(text):
    return socket.inet_aton(text)


class RouteTableTests(unittest.TestCase):
    """tun_routes over IP helper tables laid out as Windows returns them, through a declared iphlpapi."""

    def tables(self, forward, addresses):
        def table(rows, width):
            raw = len(rows).to_bytes(4, "little")
            for row in rows:
                raw += row + b"\0" * (width - len(row))
            return raw
        forward_rows = [ipv4(dest) + ipv4(mask) + b"\0" * 4 + ipv4(hop) for dest, mask, hop in forward]
        address_rows = [ipv4(address) + (7).to_bytes(4, "little") + ipv4("255.255.255.252") for address in addresses]
        return {"GetIpForwardTable": table(forward_rows, 56), "GetIpAddrTable": table(address_rows, 24)}

    def run_routes(self, tables, *, grow=False):
        calls = []

        def function(name):
            def call(buffer, size, order):
                calls.append((name, buffer is None))
                data = tables[name]
                # A table that grew between the size call and the first read asks for more once.
                needed = len(data) + (8000 if grow and calls.count((name, False)) == 1 else 0)
                if buffer is None or size._obj.value < needed:
                    size._obj.value = needed
                    return 122
                ctypes.memmove(buffer, data, len(data))
                return 0
            return call
        fake = types.SimpleNamespace(windll=types.SimpleNamespace(iphlpapi=types.SimpleNamespace(
            GetIpForwardTable=function("GetIpForwardTable"), GetIpAddrTable=function("GetIpAddrTable"))),
            c_ulong=ctypes.c_ulong, byref=ctypes.byref, create_string_buffer=ctypes.create_string_buffer)
        with mock.patch.dict(sys.modules, {"ctypes": fake}):
            return stages.tun_routes(), calls

    def test_only_routes_and_addresses_on_the_generated_tun_subnet_are_found(self):
        found, _ = self.run_routes(self.tables([("0.0.0.0", "128.0.0.0", "172.19.250.2"), ("10.0.2.0", "255.255.255.0", "0.0.0.0"),
                                                ("172.19.250.0", "255.255.255.252", "0.0.0.0"), ("172.19.251.0", "255.255.255.0", "0.0.0.0")],
                                               ["10.0.2.15", "172.19.250.1", "172.19.250.5"]))
        self.assertEqual([("GetIpAddrTable", "172.19.250.1"), ("GetIpForwardTable", "172.19.250.0"), ("GetIpForwardTable", "172.19.250.2")], found)

    def test_a_clean_guest_has_none_and_a_table_that_grew_is_read_again(self):
        found, calls = self.run_routes(self.tables([("10.0.2.0", "255.255.255.0", "0.0.0.0")], ["10.0.2.15"]))
        self.assertEqual([], found)
        found, calls = self.run_routes(self.tables([("10.0.2.0", "255.255.255.0", "0.0.0.0")], ["10.0.2.15"]), grow=True)
        self.assertEqual([], found)
        self.assertGreater(calls.count(("GetIpForwardTable", False)), 1)

    def test_a_table_that_cannot_be_read_fails_closed(self):
        tables = self.tables([], [])

        def failing(buffer, size, order):
            return 5
        fake = types.SimpleNamespace(windll=types.SimpleNamespace(iphlpapi=types.SimpleNamespace(GetIpForwardTable=failing, GetIpAddrTable=failing)),
                                     c_ulong=ctypes.c_ulong, byref=ctypes.byref, create_string_buffer=ctypes.create_string_buffer)
        with mock.patch.dict(sys.modules, {"ctypes": fake}), self.assertRaisesRegex(AssertionError, "^tun-route-table-size$"):
            stages.tun_routes()
        self.assertTrue(tables)


class GeneratedInputTests(unittest.TestCase):
    PATHS = {"productWorkspace": WORKSPACE, "installed": "C:\\Users\\recovery\\AppData\\Local\\vpn-control", "operationRoot": "C:\\root",
             "file:runtime": "C:\\w\\windows_lifecycle_runtime_stages.py", "file:observer": "C:\\w\\windows_broker_fixture_observer.py",
             "file:fixture": "C:\\w\\fixture.py", "file:socks": "C:\\w\\socks.py", "file:https": "C:\\w\\https.py",
             "file:certificate": "C:\\w\\c.pem", "file:privateKey": "C:\\w\\c.key", "file:trustStore": "C:\\w\\t.jks",
             "file:tun": "C:\\w\\windows_tun_stages.py", "file:sampler": SAMPLER, "file:samplerInput": SAMPLER_INPUT}
    ADMISSIONS = {"installed": "sha256-" + "a" * 64, "material": "m", "context": "windows-context-" + "b" * 64, "fixture": "f", "source": "s"}
    TUN = {"administratorSid": ADMIN, "decisionId": str(uuid.uuid4()), "collectorSourceSha256": "c" * 64}

    def harness(self, variant, tun):
        raw = proxy.harness(variant, operation="op", paths=self.PATHS, runtime_sha256="d" * 64, source_sha="e" * 40,
                            admissions=self.ADMISSIONS, tun=tun)
        tree = ast.parse(raw.decode("ascii"))
        return {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)}

    def test_a_tun_harness_names_the_stages_and_the_route_inputs_only(self):
        for variant in proxy.TUN_VARIANTS:
            with self.subTest(variant=variant):
                value = self.harness(variant, dict(self.TUN))["LIFECYCLE_INPUTS"]
                self.assertIsNone(self.harness(variant, dict(self.TUN))["SYSTEM_COLLECTOR_CLOSE_HOLD"])
                grant = variant in proxy.TUN_GRANT_VARIANTS
                self.assertEqual(set(stages.FIELDS) | (set(stages.SAMPLER_FIELDS) if grant else set()), set(value["tun"]))
                self.assertEqual((variant, ADMIN, self.TUN["decisionId"], "c" * 64, self.ADMISSIONS["installed"], self.ADMISSIONS["context"]),
                                 tuple(value["tun"][key] for key in ("variant", "expectedApprovingAdminSid", "uacDecisionId", "collectorSourceSha256",
                                                                     "installedAdmissionArtifactId", "ordinaryContextArtifactId")))
                self.assertEqual(WORKSPACE + "\\runtime-config.json", value["tun"]["runtimeConfigPath"])
                self.assertEqual(self.PATHS["file:tun"], value["modules"]["tun"])
                self.assertNotIn("branch", value)
                self.assertIsNone(value["gui"])
                roles = proxy.generated_roles(variant)
                self.assertEqual(grant, "samplerInput" in roles)
                self.assertNotIn("trafficInput", roles)

    def test_tun_inputs_are_closed_and_belong_only_to_tun_variants(self):
        for tun in (None, {}, {**self.TUN, "path": "C:\\x"}, {key: value for key, value in self.TUN.items() if key != "decisionId"}):
            with self.subTest(tun=tun), self.assertRaises(ValueError):
                self.harness("restart-deny", tun)
        with self.assertRaisesRegex(ValueError, "proxy_variant"):
            self.harness("find-best-success", dict(self.TUN))
        with self.assertRaisesRegex(ValueError, "proxy_variant"):
            self.harness("restart", dict(self.TUN))

    def test_the_grant_sampler_expects_the_rows_own_upstream_body(self):
        value = json.loads(proxy.sampler_input("op-1"))
        self.assertEqual(proxy.fixture_body("op-1").encode().hex(), value["expectedBodyHex"])
        self.assertEqual(0, sampler.run(value, lambda row: None, connect=lambda address, timeout: Stream(response(proxy.fixture_body("op-1").encode())),
                                        sleep=lambda seconds: None))
        files = proxy.files("restart-grant", operation="op-1", paths=self.PATHS, runtime_sha256="d" * 64, source_sha="e" * 40,
                            admissions=self.ADMISSIONS, tls={"certificate": b"c", "privateKey": b"k", "trustStore": b"t"}, tun=dict(self.TUN))
        self.assertEqual(proxy.generated_roles("restart-grant"), tuple(files))
        self.assertEqual(proxy.sampler_input("op-1"), files["samplerInput"])


if __name__ == "__main__":
    unittest.main()
