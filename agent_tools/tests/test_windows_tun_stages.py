"""Scoped-TUN stages on the Windows scenario route, their direct sampler and their generated inputs, all offline.

No process, route table or guest is touched: every native boundary is a declared fake. One sampler test uses real
sockets of its own, a loopback listener and an unassigned TEST-NET-1 source address, so nothing leaves the host.
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

        def connect(address, timeout, source_address=None):
            connects.append((address, timeout, source_address))
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
        self.assertEqual([(("198.18.0.1", 80), 5, ("172.19.250.1", 0))] * 3, connects)
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

    def test_every_sample_is_bound_to_the_generated_tun_address(self):
        # The address DesktopProxyConfigFactory gives the TUN: the first host of TUN_SUBNET, the one the closing census reads.
        network, bits = stages.TUN_SUBNET
        first = socket.inet_ntoa((int.from_bytes(socket.inet_aton(network), "big") + 1).to_bytes(4, "big"))
        self.assertEqual(((first, 0), 30), (getattr(sampler, "SOURCE", None), bits))
        _, _, connects, _, _ = self.run_sampler([response(BODY.encode())] * 3)
        self.assertEqual([(first, 0)] * 3, [source for _, _, source in connects], "no sample may pick its own source address")

    def test_with_the_tun_address_gone_the_real_socket_sends_nothing(self):
        """A TUN that went away after its ready record: the sampler's own socket, unpatched, must not reach the target.

        The target is an owned loopback listener and the TUN address an unassigned TEST-NET-1 one, so nothing leaves this
        host either way. Unbound (the e65f8814 sampler), the real connect reaches the listener as it would reach
        198.18.0.1 through the guest's default route; bound, the bind itself fails and no connection is made."""
        unassigned = ("192.0.2.1", 0)
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(unassigned)
        except OSError:
            pass
        else:
            self.skipTest("192.0.2.1 is assigned on this host")
        finally:
            probe.close()
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(0.5)
        rows = []
        with mock.patch.object(sampler, "TARGET", listener.getsockname()), mock.patch.object(sampler, "SOURCE", unassigned, create=True):
            code = sampler.run(sampler_value(sampleCount=2, ioTimeoutSeconds=1, intervalSeconds=0.02), rows.append)
        accepted = []
        try:
            while True:
                accepted.append(listener.accept()[0])
        except OSError:
            pass
        for connection in accepted:
            connection.close()
        self.assertEqual(0, len(accepted), "a sample reached the target with no TUN address to leave from")
        self.assertEqual(1, code)
        self.assertEqual([(False, "OSError")] * 2, [(row["succeeded"], row["reason"]) for row in rows[:-1]])


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

    def test_a_grant_asks_its_collector_for_the_ready_record_only_once_its_tun_came_up(self):
        # The collector finds the broker and its runtime only while they run: finish asks the driver's handoff for the
        # ready record after the product's own OK, once, and never for a grant that ended without its TUN.
        asked, reads = [], []

        def handoff(lease, stage):
            asked.append((stage, lease["finished"]))
            return {"path": "C:\\ProgramData\\tun-evidence-op\\ready.json", "sha256": "f" * 64, "sizeBytes": 9}

        def terminal(code):
            runtime = self.runtime()
            runtime.finish_operation = lambda *args, **options: {"code": code, "final": True}
            return runtime
        for code in ("CANCELLED", "RUNTIME_FAILED"):
            with self.subTest(code=code):
                self.setUp()
                asked.clear()
                lease = self.begin(self.inputs("restart-grant"))
                cases = types.SimpleNamespace(config_bytes=lambda path: dict(lease["activeConfig"].initial), exact_actor=lambda *args, **options: None)
                stages.finish(self.owner, lease, terminal(code), cases, self.observer, handoff=handoff, receipts=object())
                self.assertEqual([], asked, "no TUN came up, so there is no collector to ask")
        self.setUp()
        asked.clear()
        lease = self.begin(self.inputs("restart-grant"))
        runtime = terminal("OK")
        result = runtime.result

        def vpn_status(owner, workspace, identity, *arguments, **options):
            if arguments[-1] != "status":
                return result(owner, workspace, identity, *arguments, **options)
            return {"data": {**self.status, "activeMode": "vpn", "activeLocationId": "b", "configuredMode": "vpn"}, "restartRequired": False}
        runtime.result = vpn_status
        record = {"stage": "ready", "productOperationId": lease["accepted"]["operationId"], "observations": {"configuration": {"sha256": "9" * 64}}}

        def read(owner, current, file_record, receipts, stage):
            reads.append((file_record["path"], stage, current["finished"]))
            return record
        cases = types.SimpleNamespace(config_bytes=lambda path: dict(lease["activeConfig"].initial), exact_actor=lambda *args, **options: None)
        with mock.patch.object(stages, "read_native_record", read):
            outcome = stages.finish(self.owner, lease, runtime, cases, self.observer, handoff=handoff, receipts=object())
        self.assertEqual([("ready", False)], asked, "asked once, after the product's OK and before the lease is final")
        self.assertEqual([("C:\\ProgramData\\tun-evidence-op\\ready.json", "ready", False)], reads, "the stages read the handed record themselves")
        self.assertIs(record, outcome["nativeRecord"])
        self.assertIs(record, lease["nativeReady"])
        self.assertTrue(lease["finished"])
        self.assertFalse(stages.settled(lease), "a grant settles only at its exact off")
        self.setUp()
        lease = self.begin(self.inputs("restart-grant"))
        with self.assertRaisesRegex(AssertionError, "^actual-tun-native-file-required$"):
            stages.finish(self.owner, lease, runtime, cases, self.observer, receipts=object())

    def test_a_find_best_denial_is_its_cancelled_start_alone(self):
        # DesktopFindBestService ends at its first CANCELLED start and restores A; it starts with
        # commitSelectionOnSuccessOnly, so pending B stays selected. Any other failed start makes it try its next
        # candidate, whose own prompt follows: PERMISSION_DENIED is no denial of this prompt, only a known end.
        lease = self.begin(self.inputs("find-best-deny"))
        self.assertEqual(("--async", "find-best"), self.calls[-1])
        result = self.finish(lease, "CANCELLED")
        self.assertEqual("CANCELLED", result["terminal"]["code"])
        self.assertNotIn("knownFailure", result)
        self.assertEqual("scoped-tun-public-outcome", self.owner.events[-1][0])
        self.setUp()
        lease = self.begin(self.inputs("find-best-deny"))
        result = self.finish(lease, "PERMISSION_DENIED")
        self.assertEqual("PERMISSION_DENIED", result.get("knownFailure"), "no denial of this prompt: a known end")
        self.assertEqual("scoped-tun-unexpected-terminal-known", self.owner.events[-1][0])
        self.setUp()
        lease = self.begin(self.inputs("find-best-deny"))
        self.status.update(selectedLocationId="a")
        with self.assertRaisesRegex(AssertionError, "^uac-denial-lost-active-a-or-pending-b$"):
            self.finish(lease, "CANCELLED")
        self.assertFalse(lease["finished"], "a denial that moved the selection parks")

    def granted_find_best(self, selected, active=None):
        """A granted Find Best whose product status reports this selection and active location after its OK."""
        lease = self.begin(self.inputs("find-best-grant"))
        runtime = self.runtime()
        runtime.finish_operation = lambda *args, **options: {"code": "OK", "final": True}
        result = runtime.result

        def vpn_status(owner, workspace, identity, *arguments, **options):
            if arguments[-1] != "status":
                return result(owner, workspace, identity, *arguments, **options)
            return {"data": {**self.status, "activeMode": "vpn", "configuredMode": "vpn", "selectedLocationId": selected,
                             "activeLocationId": selected if active is None else active, "runtimeId": "vpn"}, "restartRequired": False}
        runtime.result = vpn_status
        record = {"stage": "ready", "productOperationId": lease["accepted"]["operationId"], "observations": {"configuration": {"sha256": "9" * 64}}}
        cases = types.SimpleNamespace(config_bytes=lambda path: dict(lease["activeConfig"].initial), exact_actor=lambda *args, **options: None)
        with mock.patch.object(stages, "read_native_record", lambda *args: record):
            outcome = stages.finish(self.owner, lease, runtime, cases, self.observer, handoff=lambda *args: {}, receipts=object())
        return lease, outcome

    def test_a_granted_find_best_selects_its_winner_a_or_b_and_nothing_else(self):
        # The winner is the first verified candidate by connect time; A and B reach the one owned endpoint, so either may
        # win, and only that start's success moves the selection to it. A winner A replaces the pending selection of B.
        for selected, winner in (("a", "active-a"), ("b", "pending-b")):
            with self.subTest(selected=selected):
                self.setUp()
                lease, outcome = self.granted_find_best(selected)
                expected = {"locationId": selected, "winner": winner, "pendingSelectionKept": selected == "b"}
                self.assertEqual(expected, lease.get("findBestSelection"))
                self.assertEqual(("scoped-tun-public-outcome", expected), (self.owner.events[-1][0], self.owner.events[-1][1].get("findBestSelection")))
                self.assertIsNotNone(lease["nativeReady"])
        self.setUp()
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-find-best-winner-not-an-owned-candidate$"):
            self.granted_find_best("c")
        self.setUp()
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-actual-commit-result$"):
            self.granted_find_best("b", active="a")
        self.setUp()
        lease, _ = self.granted_find_best("b")
        self.assertNotIn("findBestSelection", self.granted_restart(), "a restart has no winner")

    def granted_restart(self):
        self.setUp()
        lease = self.begin(self.inputs("restart-grant"))
        runtime = self.runtime()
        runtime.finish_operation = lambda *args, **options: {"code": "OK", "final": True}
        result = runtime.result
        runtime.result = lambda owner, workspace, identity, *arguments, **options: (
            {"data": {**self.status, "activeMode": "vpn", "configuredMode": "vpn", "activeLocationId": "b"}, "restartRequired": False}
            if arguments[-1] == "status" else result(owner, workspace, identity, *arguments, **options))
        record = {"stage": "ready", "productOperationId": lease["accepted"]["operationId"], "observations": {"configuration": {"sha256": "9" * 64}}}
        cases = types.SimpleNamespace(config_bytes=lambda path: dict(lease["activeConfig"].initial), exact_actor=lambda *args, **options: None)
        with mock.patch.object(stages, "read_native_record", lambda *args: record):
            stages.finish(self.owner, lease, runtime, cases, self.observer, handoff=lambda *args: {}, receipts=object())
        return lease

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


class NativeRecordSourceTests(unittest.TestCase):
    """A collector record's source binds to the product source the row runs, which the driver keeps on the lease.

    The ordinary worker request has no sourceSha (windows_ordinary_task.COMMON_FIELDS and the proxy action's five
    inputs): a reader that took the source from it would fail with KeyError on the first grant's ready record and
    park the owner over a live TUN, though the collector had written the right record."""

    def record(self, **changes):
        task, operation, request, controller, boot = (str(uuid.uuid4()) for _ in range(5))
        workspace = "C:\\Users\\recovery\\AppData\\Local\\VpnControlOrdinary-" + task + "\\workspace"
        # The worker request as windows_ordinary_task.worker_request builds it for windows-proxy-lifecycle.
        self.owner = types.SimpleNamespace(request={
            "schemaVersion": 1, "operationId": task, "operationRoot": "C:\\root", "filePins": [], "directoryPins": [], "treePins": [],
            "rawStreamLimitBytes": 16777216, "context": {"bootIdentifier": boot, "ordinarySid": ORDINARY, "ordinarySessionId": 2},
            "cliPath": CLI, "workspace": workspace, "productVersion": "2.2.15", "casesPath": "C:\\w\\windows_lifecycle_cases.py",
            "harnessPath": "C:\\w\\proxy-harness.py"})
        self.lease = {"inputs": {"programData": "C:\\ProgramData", "collectorSourceSha256": "b" * 64, "expectedApprovingAdminSid": ADMIN},
                      "accepted": {"operationId": operation, "requestId": request}, "state": {"identity": controller, "workspace": Path(workspace)},
                      "sourceSha": "a" * 40}
        value = {"schemaVersion": 1, "stage": "ready", "ordinaryTaskOperationId": task, "productOperationId": operation,
                 "originRequestId": request, "controllerId": controller, "collectorSourceSha256": "b" * 64, "sourceSha": "a" * 40,
                 "context": {"bootIdentifier": boot, "ordinarySid": ORDINARY, "ordinarySessionId": 2, "approvingAdminSid": ADMIN,
                             "workspace": workspace, "programData": "C:\\ProgramData"}, "observations": {}, **changes}
        raw = (json.dumps(value, sort_keys=True) + "\n").encode()
        path = "C:\\ProgramData\\tun-evidence-" + task + "\\ready.json"

        class Observation:
            def __init__(self, owner, actual):
                self.opening = {"security": {"ownerSid": "S-1-5-32-544", "sddl": "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GR;;;BU)"}}

            def read(self, maximum):
                return raw

            def close(self):
                pass
        receipts = types.SimpleNamespace(canonical_path=pathlib_windows, FileObservation=Observation, machine_security=lambda security, directory: None)
        return value, {"path": path, "sha256": __import__("hashlib").sha256(raw).hexdigest(), "sizeBytes": len(raw)}, receipts

    def test_the_record_joins_the_rows_own_source_on_a_worker_request_without_one(self):
        value, record, receipts = self.record()
        self.assertNotIn("sourceSha", self.owner.request)
        self.assertEqual(value, stages.read_native_record(self.owner, self.lease, record, receipts, "ready"))

    def test_a_record_of_another_source_is_never_joined(self):
        value, record, receipts = self.record(sourceSha="c" * 40)
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-protected-native-operation-join$"):
            stages.read_native_record(self.owner, self.lease, record, receipts, "ready")


def pathlib_windows(value):
    from pathlib import PureWindowsPath
    return PureWindowsPath(value)


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


class OffTests(StageWorld):
    """The grant's own off and the collector's off record: the record shows both original handles signaled, and only an
    exit after the product's off was asked for, while the product still ran its TUN runtime, is that off's."""
    ASKED = 134368653070000000  # The guest FILETIME taken just before the off goes out.

    def setUp(self):
        super().setUp()
        patcher = mock.patch.object(stages, "guest_filetime", lambda: self.ASKED, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def granted(self):
        lease = self.begin(self.inputs("restart-grant"))
        lease.update(finished=True, nativeReady={"stage": "ready"})
        # The TUN is up: B is active in VPN mode.
        self.status.update(activeMode="vpn", configuredMode="vpn", activeLocationId="b", selectedLocationId="b", runtimeId="vpn-b")
        return lease

    def off_runtime(self):
        runtime = self.runtime()
        result = runtime.result

        def asked(owner, workspace, identity, *arguments, **options):
            if arguments[-1] == "off":
                self.calls.append(arguments)
                self.status.update(runtimeRunning=False)
                return {"code": "OK", "final": True}
            return result(owner, workspace, identity, *arguments, **options)
        runtime.result = asked
        return runtime

    def off_record(self, helper_exit, runtime_exit):
        def row(role, pid, created, exited):
            return {"role": role, "pid": pid, "creationFileTime": created, "originalHandleSignaled": True,
                    "times": {"creationFileTime": created, "exitFileTime": exited, "kernelTime100ns": 1, "userTime100ns": 1}}
        return {"stage": "off", "originalProcesses": [row("helperActor", 931, self.ASKED - 500, helper_exit),
                                                      row("runtimeActor", 933, self.ASKED - 400, runtime_exit)]}

    def finish_off(self, lease, record):
        with mock.patch.object(stages, "read_native_record", lambda owner, current, file_record, receipts, stage: record):
            return stages.finish_off(self.owner, lease, {"path": "C:\\ProgramData\\tun-evidence-op\\off.json"}, object())

    def test_the_off_is_asked_only_while_the_products_own_tun_runtime_runs(self):
        for name, change in (("runtime-ended", {"runtimeRunning": False}), ("proxy-mode", {"activeMode": "proxy-only"})):
            with self.subTest(case=name):
                self.setUp()
                lease = self.granted()
                self.status.update(change)
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-runtime-ended-before-off$"):
                    stages.begin_off(self.owner, lease, self.off_runtime())
                self.assertNotIn(("off",), self.calls, "no off goes out over a runtime that already ended")
                self.assertFalse(lease.get("offRequested"))
                self.assertFalse(stages.settled(lease), "an open grant parks")

    def test_an_original_that_ended_before_the_off_was_asked_for_is_no_exact_off(self):
        # The collector publishes off once both handles signal, a crash included: a runtime that exited before the product's
        # own off, or a broker that did, is no stop of that off's.
        for name, helper, runtime in (("runtime-crashed", self.ASKED + 900, self.ASKED - 100),
                                      ("broker-gone", self.ASKED - 1, self.ASKED + 800), ("same-instant", self.ASKED, self.ASKED + 1)):
            with self.subTest(case=name):
                self.setUp()
                lease = self.granted()
                stages.begin_off(self.owner, lease, self.off_runtime())
                with self.assertRaisesRegex(AssertionError, "^scoped-tun-original-ended-before-the-off$"):
                    self.finish_off(lease, self.off_record(helper, runtime))
                self.assertFalse(lease.get("offFinished"))
                self.assertFalse(stages.settled(lease), "an open grant parks")

    def test_an_exact_off_is_proven_by_both_exits_after_the_request(self):
        lease = self.granted()
        stages.begin_off(self.owner, lease, self.off_runtime())
        self.assertEqual([("status",), ("off",), ("status",)], self.calls[-3:], "the product's own status, then its off, then its status")
        self.assertEqual(self.ASKED, lease["offRequestedFileTime"])
        waiting = self.owner.events[-1]
        self.assertEqual(("scoped-tun-awaiting-exact-off-observation", self.ASKED, True),
                         (waiting[0], waiting[1]["offRequestedFileTime"], waiting[1]["statusBeforeOff"]["data"]["runtimeRunning"]))
        record = self.off_record(self.ASKED + 10, self.ASKED + 20)
        self.assertIs(record, self.finish_off(lease, record))
        self.assertTrue(stages.settled(lease))
        kind, value = self.owner.events[-1]
        self.assertEqual("scoped-tun-exact-off-observed", kind)
        self.assertEqual((self.ASKED, True), (value["offRequestedFileTime"], value["exitedAfterOffRequest"]))

    def test_the_exact_off_claims_no_sibling_it_never_had(self):
        # No unrelated runtime runs beside the grant, so its off record cannot show the elevated stop spared one: the event
        # says so instead of claiming no broad process stop.
        lease = self.granted()
        stages.begin_off(self.owner, lease, self.off_runtime())
        self.finish_off(lease, self.off_record(self.ASKED + 10, self.ASKED + 20))
        value = self.owner.events[-1][1]
        self.assertNotIn("noBroadProcessStop", value)
        self.assertIs(False, value.get("siblingSurvivalObserved"))


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
    # The close hold the host job builds for a grant's one TUN collector (hold_protocol.validate_inputs' fields).
    HOLD = {"schemaVersion": 1, "collectorOperationId": "f2217b3c-82c1-4862-bab8-09b8498e7929",
            "collectorRoot": "C:\\ProgramData\\VpnControlOrdinaryTask-op\\system-collector-f2217b3c-82c1-4862-bab8-09b8498e7929",
            "scope": "tun", "stage": "off", "sourceSha": "e" * 40, "systemContractSourceSha256": "1" * 64,
            "systemWorkerSourceSha256": "2" * 64, "collectorSourceSha256": "c" * 64,
            "receiptsPath": "C:\\ProgramData\\VpnControlOrdinaryTask-op\\windows_public_updater\\update_receipts.py"}

    def harness(self, variant, tun, hold=None):
        if hold is None and variant in proxy.TUN_GRANT_VARIANTS:
            hold = dict(self.HOLD)
        raw = proxy.harness(variant, operation="op", paths=self.PATHS, runtime_sha256="d" * 64, source_sha="e" * 40,
                            admissions=self.ADMISSIONS, tun=tun, hold=hold)
        tree = ast.parse(raw.decode("ascii"))
        return {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)}

    def test_only_a_grant_names_its_collectors_close_hold(self):
        # The driver arms a hold only for a grant, whose SYSTEM collector waits on it: no other row names one.
        for variant in proxy.TUN_VARIANTS:
            with self.subTest(variant=variant):
                expected = dict(self.HOLD) if variant in proxy.TUN_GRANT_VARIANTS else None
                self.assertEqual(expected, self.harness(variant, dict(self.TUN))["SYSTEM_COLLECTOR_CLOSE_HOLD"])
        for variant, hold in (("restart-deny", dict(self.HOLD)), ("restart-grant", "hold"), ("restart-grant", [])):
            with self.subTest(variant=variant, hold=hold), self.assertRaisesRegex(ValueError, "^proxy_collector_hold$"):
                proxy.harness(variant, operation="op", paths=self.PATHS, runtime_sha256="d" * 64, source_sha="e" * 40,
                              admissions=self.ADMISSIONS, tun=dict(self.TUN), hold=hold)
        with self.assertRaisesRegex(ValueError, "^proxy_collector_hold$"):
            proxy.harness("restart-grant", operation="op", paths=self.PATHS, runtime_sha256="d" * 64, source_sha="e" * 40,
                          admissions=self.ADMISSIONS, tun=dict(self.TUN))

    def test_a_tun_harness_names_the_stages_and_the_route_inputs_only(self):
        for variant in proxy.TUN_VARIANTS:
            with self.subTest(variant=variant):
                value = self.harness(variant, dict(self.TUN))["LIFECYCLE_INPUTS"]
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
        self.assertEqual(0, sampler.run(value, lambda row: None, connect=lambda address, timeout, source_address=None: Stream(response(proxy.fixture_body("op-1").encode())),
                                        sleep=lambda seconds: None))
        files = proxy.files("restart-grant", operation="op-1", paths=self.PATHS, runtime_sha256="d" * 64, source_sha="e" * 40,
                            admissions=self.ADMISSIONS, tls={"certificate": b"c", "privateKey": b"k", "trustStore": b"t"}, tun=dict(self.TUN),
                            hold=dict(self.HOLD))
        self.assertEqual(proxy.generated_roles("restart-grant"), tuple(files))
        self.assertEqual(proxy.sampler_input("op-1"), files["samplerInput"])


if __name__ == "__main__":
    unittest.main()
