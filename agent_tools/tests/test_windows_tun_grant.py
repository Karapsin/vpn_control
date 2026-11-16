"""windows-scoped-tun.restart-grant: the approved TUN grant's collector route, offline.

The approved broker runs elevated as the approving administrator, so only the TUN SYSTEM collector proves it: its ready
record while the TUN is up and its off record once the product's own off ended exactly that broker and its runtime.
These tests cover each piece that lets the grant row run: the dedicated driver's close hold and record handoff, the
host job's discovery of the controller, broker and runtime from a SYSTEM census (tun_actors, vpn_broker), its one
collector stage on the host-job tests' fake guest peer, the publisher template's TUN observation as that peer follows
the template text, and the real windows_tun_native_observer over the request the job builds.

No guest, socket, process, route or UAC prompt is touched: every native boundary is a declared fake, and nothing here
proves a Windows behaviour. The native first contact is the operator sequence in the T7 evidence report.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PureWindowsPath
import re
import types
import unittest
from unittest import mock

from agent_tools import native_scenario_windows as windows
from agent_tools import windows_ordinary_dedicated_driver as dedicated_driver
from agent_tools import windows_scenario_host_job as job
from agent_tools import windows_tun_native_observer as tun_observer
from agent_tools import windows_tun_stages as tun_stages
from agent_tools.tests.test_windows_ordinary_task import DedicatedDispatchPeer, DedicatedParked
from agent_tools.tests.test_windows_scenario_host_job import (CLI_PATH, INSTALLED_ROOT, PROFILE, SID, VERSION, FakeRuntime, FamilyBase,
                                                               UpdateQga, encoded, out_data, process_row)
from agent_tools.windows_public_updater import update_receipts
from agent_tools.windows_system_collector import collector_contract as contract
from agent_tools.windows_system_collector import hold_protocol

ROOT = Path(__file__).resolve().parents[2]
ADMIN_SID = "S-1-5-21-1-2-3-500"
SESSION = 2
PRODUCT_OPERATION = "99999999-aaaa-4bbb-8ccc-dddddddddddd"
REQUEST_ID = "77777777-aaaa-4bbb-8ccc-dddddddddddd"
CONTROLLER = "66666666-aaaa-4bbb-8ccc-dddddddddddd"
BROKER_RELATIVE = "app/native/windows-amd64/vpn-control-vpn-broker.exe"
MANIFEST_RELATIVE = "app/native/windows-amd64/native-helpers.json"
BROKER_PATH = INSTALLED_ROOT + "\\" + BROKER_RELATIVE.replace("/", "\\")
BROKER_BYTES = b"MZ fake vpn-control-vpn-broker"
RUNTIME_BYTES = b"MZ bundled sing-box"  # FakeQga.runtime_bytes: the installed jar's runtime the job extracts.
STAGE = "C:\\ProgramData\\vpn-control-vpn-5f5f5f5f-1111-4222-8333-944455556666"
RUNTIME_PATH = STAGE + "\\sing-box.exe"
PIPE = "vpn-control-vpn-0a0a0a0a-2222-4333-8444-555566667777"
CONHOST = "C:\\Windows\\System32\\conhost.exe"
WORKER_PID, SERVE_PID, JVM_PID, BROKER_PID, CONHOST_PID, RUNTIME_PID = 902, 903, 913, 931, 932, 933
WORKER_BIRTH, SERVE_BIRTH, JVM_BIRTH = 134368653065000003, 134368653065000004, 134368653065000006
BROKER_BIRTH, CONHOST_BIRTH, RUNTIME_BIRTH = 134368653065000030, 134368653065000031, 134368653065000032
CONFIG = b'{"inbounds":[{"type":"tun"}]}'
# The guest FILETIME the stages take just before the product's own off, and the exit time GetProcessTimes reports after it.
OFF_ASKED, OFF_EXITED = 134368653080000000, 134368653080000420


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def broker_manifest(broker=BROKER_BYTES, runtime=RUNTIME_BYTES, **changes):
    """native-helpers.json as scripts/windows_native_helpers.py writes it: the broker and the installer helper, and the
    bundled runtime the broker stages."""
    helper = b"MZ fake vpn-control-install-helper"
    common = {"minimumWindowsBuild": 22621, "machine": "AMD64", "sections": [], "clrHeader": False, "imports": [], "delayImports": [],
              "dependentLoadFlags": 2048}
    artifacts = [{**common, "name": "vpn-control-install-helper.exe", "sha256": sha(helper), "sizeBytes": len(helper),
                  "operations": ["validate-only", "install-user", "install-coordinator"]},
                 {**common, "name": "vpn-control-vpn-broker.exe", "sha256": sha(broker), "sizeBytes": len(broker),
                  "operations": ["authenticated-runtime-channel"], **changes}]
    return (json.dumps({"schemaVersion": 1, "policySha256": "e" * 64, "artifacts": artifacts,
                        "runtimeAuthority": {"runtimeSha256": sha(runtime), "runtimeSizeBytes": 41943040, "authoritySourceSha256": "f" * 64}},
                       indent=2, sort_keys=True) + "\n").encode()


def tun_processes(*, cli=b"exe:" + VERSION.encode(), relaunched=True):
    """What a SYSTEM census of the CLI image and of the broker with its children finds while the grant's TUN is up: the
    serve the owner started (the worker's child), the JVM it relaunched into, the broker AppInfo started for that JVM,
    elevated as the approving administrator, its console, and the runtime it staged under ProgramData."""
    controller, birth = (JVM_PID, JVM_BIRTH) if relaunched else (SERVE_PID, SERVE_BIRTH)

    def parent(pid, born, image):
        return {"pid": pid, "openError": None, "alive": True, "creationFileTime": str(born), "image": image}
    rows = [process_row(SERVE_PID, WORKER_PID, SERVE_BIRTH, CLI_PATH, [CLI_PATH, "--state-dir", "w", "serve"], SID, 0, image_bytes=cli)]
    if relaunched:
        rows.append(process_row(JVM_PID, SERVE_PID, JVM_BIRTH, CLI_PATH, [CLI_PATH, "--state-dir", "w", "serve"], SID, 0, image_bytes=cli,
                                parent_row=parent(SERVE_PID, SERVE_BIRTH, CLI_PATH)))
    broker = parent(BROKER_PID, BROKER_BIRTH, BROKER_PATH)
    rows += [process_row(BROKER_PID, controller, BROKER_BIRTH, BROKER_PATH, [BROKER_PATH, PIPE, str(controller), str(birth), SID, sha(RUNTIME_BYTES)],
                         ADMIN_SID, 1, image_bytes=BROKER_BYTES, parent_row=parent(controller, birth, CLI_PATH)),
             process_row(CONHOST_PID, BROKER_PID, CONHOST_BIRTH, CONHOST, ["\\??\\C:\\Windows\\system32\\conhost.exe", "0xffffffff", "-ForceV1"],
                         ADMIN_SID, 1, image_bytes=b"conhost", parent_row=broker),
             process_row(RUNTIME_PID, BROKER_PID, RUNTIME_BIRTH, RUNTIME_PATH, [RUNTIME_PATH, "run", "-c", "stdin"], ADMIN_SID, 1,
                         image_bytes=RUNTIME_BYTES, parent_row=broker)]
    return rows


def find(rows, pid):
    return next(row for row in rows if row["pid"] == pid)


class TunActorTests(unittest.TestCase):
    """windows_scenario_host_job.tun_actors: the controller, the approved broker and its runtime from one SYSTEM census."""

    def actors(self, rows, **changes):
        options = {"serve": {"pid": SERVE_PID, "creationFileTime": SERVE_BIRTH}, "worker": {"pid": WORKER_PID, "creationFileTime": WORKER_BIRTH},
                   "cli": {"path": CLI_PATH, "sha256": sha(b"exe:" + VERSION.encode())},
                   "broker": {"path": BROKER_PATH, "sha256": sha(BROKER_BYTES), "sizeBytes": len(BROKER_BYTES)},
                   "runtime_sha256": sha(RUNTIME_BYTES), "administrator_sid": ADMIN_SID, "sid": SID, "session": SESSION, **changes}
        return job.tun_actors(job.census_rows(rows), **options)

    def test_the_controller_broker_and_runtime_are_found_with_their_tokens(self):
        actors, facts = self.actors(tun_processes())
        self.assertEqual({"ownerActor": {"pid": JVM_PID, "creationFileTime": JVM_BIRTH, "image": CLI_PATH, "sha256": sha(b"exe:" + VERSION.encode()),
                                         "sid": SID, "sessionId": SESSION},
                          "helperActor": {"pid": BROKER_PID, "creationFileTime": BROKER_BIRTH, "image": BROKER_PATH, "sha256": sha(BROKER_BYTES),
                                          "sid": ADMIN_SID, "sessionId": SESSION},
                          "runtimeActor": {"pid": RUNTIME_PID, "creationFileTime": RUNTIME_BIRTH, "image": RUNTIME_PATH, "sha256": sha(RUNTIME_BYTES),
                                           "sid": ADMIN_SID, "sessionId": SESSION}}, actors)
        self.assertEqual({"pid": JVM_PID, "creationFileTime": JVM_BIRTH, "relaunched": True}, facts["controller"])
        self.assertEqual({"pid": JVM_PID, "alive": True, "matches": True}, facts["broker"]["parent"], "AppInfo's parent: the controller")
        self.assertEqual({"pid": BROKER_PID, "alive": True, "matches": True}, facts["runtime"]["parent"])
        self.assertEqual((1, 2, "vpn-control-vpn-5f5f5f5f-1111-4222-8333-944455556666"),
                         (facts["broker"]["elevated"], facts["broker"]["elevationType"], facts["runtime"]["stage"]))
        self.assertEqual((["conhost.exe"], 0), (facts["auxiliary"], facts["unreadChildren"]), "console plumbing is recorded, never the runtime")
        self.assertTrue(facts["broker"]["argv0MatchesImage"])

    def test_a_serve_that_is_its_own_jvm_is_the_controller_the_broker_names(self):
        actors, facts = self.actors(tun_processes(relaunched=False))
        self.assertEqual((SERVE_PID, SERVE_BIRTH), (actors["ownerActor"]["pid"], actors["ownerActor"]["creationFileTime"]))
        self.assertEqual({"pid": SERVE_PID, "creationFileTime": SERVE_BIRTH, "relaunched": False}, facts["controller"])

    def test_anything_else_is_refused_with_its_own_reason(self):
        def twin(pid):
            def change(rows):
                rows.append({**copy.deepcopy(find(rows, pid)), "pid": pid + 50})
            return change

        def remove(pid):
            return lambda rows: rows.remove(find(rows, pid))
        cases = (("collector_tun_serve", remove(SERVE_PID)),
                 ("collector_tun_serve", lambda rows: find(rows, SERVE_PID).update(parentPid=4, parent={**find(rows, SERVE_PID)["parent"], "pid": 4})),
                 ("collector_tun_serve", lambda rows: find(rows, SERVE_PID)["token"].update(elevated=1)),
                 ("collector_tun_serve", lambda rows: find(rows, SERVE_PID).update(creationFileTime=str(SERVE_BIRTH + 1))),
                 ("collector_tun_serve", lambda rows: find(rows, SERVE_PID).update(imageSha256="0" * 64)),
                 ("collector_tun_controller", twin(JVM_PID)),
                 ("collector_tun_controller", lambda rows: find(rows, JVM_PID).update(creationFileTime=str(SERVE_BIRTH - 1))),
                 ("collector_tun_controller", lambda rows: find(rows, JVM_PID)["token"].update(sid=ADMIN_SID)),
                 ("collector_tun_broker_count_0", remove(BROKER_PID)),
                 ("collector_tun_broker_count_0", lambda rows: find(rows, BROKER_PID).update(openError=5, alive=None)),
                 ("collector_tun_broker_count_2", twin(BROKER_PID)),
                 ("collector_tun_broker_identity", lambda rows: find(rows, BROKER_PID)["argv"].__setitem__(2, str(SERVE_PID))),
                 ("collector_tun_broker_identity", lambda rows: find(rows, BROKER_PID)["argv"].__setitem__(3, str(JVM_BIRTH + 1))),
                 ("collector_tun_broker_identity", lambda rows: find(rows, BROKER_PID)["argv"].__setitem__(4, ADMIN_SID)),
                 ("collector_tun_broker_identity", lambda rows: find(rows, BROKER_PID)["argv"].__setitem__(5, "0" * 64)),
                 ("collector_tun_broker_identity", lambda rows: find(rows, BROKER_PID)["argv"].__setitem__(1, "another-pipe")),
                 ("collector_tun_broker_identity", lambda rows: find(rows, BROKER_PID).update(imageSha256="0" * 64)),
                 ("collector_tun_broker_identity", lambda rows: find(rows, BROKER_PID).update(argv=find(rows, BROKER_PID)["argv"][:5])),
                 ("collector_tun_broker_token", lambda rows: find(rows, BROKER_PID)["token"].update(elevated=0)),
                 ("collector_tun_broker_token", lambda rows: find(rows, BROKER_PID)["token"].update(sid=SID)),
                 ("collector_tun_broker_token", lambda rows: find(rows, BROKER_PID)["token"].update(sessionId=1)),
                 ("collector_tun_broker_generation", lambda rows: find(rows, BROKER_PID).update(creationFileTime=str(JVM_BIRTH - 1))),
                 ("collector_tun_runtime_count_0", remove(RUNTIME_PID)),
                 ("collector_tun_runtime_count_0", lambda rows: find(rows, RUNTIME_PID).update(creationFileTime=str(BROKER_BIRTH - 1))),
                 ("collector_tun_runtime_count_0", lambda rows: find(rows, RUNTIME_PID).update(openError=5, alive=None)),
                 ("collector_tun_runtime_count_2", twin(RUNTIME_PID)),
                 ("collector_tun_runtime_identity", lambda rows: find(rows, RUNTIME_PID).update(image=PROFILE + "\\AppData\\Local\\w\\runtime\\tools\\sing-box.exe")),
                 ("collector_tun_runtime_identity", lambda rows: find(rows, RUNTIME_PID).update(image="C:\\ProgramData\\other\\sing-box.exe")),
                 ("collector_tun_runtime_identity", lambda rows: find(rows, RUNTIME_PID).update(imageSha256="0" * 64)),
                 ("collector_tun_runtime_identity", lambda rows: find(rows, RUNTIME_PID).update(argv=[RUNTIME_PATH, "run", "-c", "config.json"])),
                 ("collector_tun_runtime_token", lambda rows: find(rows, RUNTIME_PID)["token"].update(elevated=0)),
                 ("collector_tun_runtime_token", lambda rows: find(rows, RUNTIME_PID)["token"].update(sid=SID)))
        for reason, change in cases:
            with self.subTest(reason=reason, change=change):
                rows = tun_processes()
                change(rows)
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    self.actors(rows)

    def test_a_child_that_could_not_be_read_is_counted_and_never_taken_for_the_runtime(self):
        rows = tun_processes()
        find(rows, CONHOST_PID).update(openError=5, alive=None)
        actors, facts = self.actors(rows)
        self.assertEqual(RUNTIME_PID, actors["runtimeActor"]["pid"])
        self.assertEqual(([], 1), (facts["auxiliary"], facts["unreadChildren"]))


class VpnBrokerTests(unittest.TestCase):
    PIN = {"path": BROKER_PATH, "sha256": sha(BROKER_BYTES), "nativeIdentity": {"sizeBytes": len(BROKER_BYTES)}}

    def test_the_broker_is_the_one_the_installed_build_declares(self):
        raw = broker_manifest()
        self.assertEqual({"path": BROKER_PATH, "sha256": sha(BROKER_BYTES), "sizeBytes": len(BROKER_BYTES)}, job.vpn_broker(raw, sha(raw), self.PIN))
        self.assertEqual(sha(RUNTIME_BYTES), job.runtime_authority(raw, sha(raw)), "the same record names the runtime the broker stages")
        for change in ({"sha256": "0" * 64}, {"sizeBytes": 1}, {"operations": ["validate-only"]}, {"machine": "ARM64"}, {"clrHeader": True},
                       {"dependentLoadFlags": 0}):
            with self.subTest(change=change):
                raw = broker_manifest(**change)
                with self.assertRaisesRegex(ValueError, "^vpn_broker_manifest$"):
                    job.vpn_broker(raw, sha(raw), self.PIN)
        raw = broker_manifest()
        with self.assertRaisesRegex(ValueError, "^vpn_broker_manifest_bytes$"):
            job.vpn_broker(raw, "0" * 64, self.PIN)


class GrantRecords:
    """update_receipts as the driver's record handoff reads it: a record appears only once its collector published it,
    and folder and file read back with the security windows_tun_native_observer.publish_machine_record gives them."""
    FOLDER = {"ownerSid": "S-1-5-32-544", "sddl": "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"}
    FILE = {"ownerSid": "S-1-5-32-544", "sddl": "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)"}

    def __init__(self, calls):
        self.calls, self.records, self.misses, self.security = calls, {}, {}, {}
        outer = self

        class FileObservation:
            def __init__(self, owner, path, directory=False):
                outer.calls.append(("open-record", PureWindowsPath(path).name, directory))
                if not directory and (outer.misses.get(path, 0) > 0 or path not in outer.records):
                    outer.misses[path] = max(0, outer.misses.get(path, 0) - 1)
                    error = OSError(2, "absent")
                    error.winerror = 2
                    raise error
                self.path, self.directory = path, directory
                self.opening = {"path": path, "nativeIdentity": {"sizeBytes": 0 if directory else len(outer.records[path])},
                                "security": outer.security.get(path, outer.FOLDER if directory else outer.FILE)}

            def read(self, maximum):
                raw = outer.records[self.path]
                assert len(raw) <= maximum
                return raw

            def close(self):
                outer.calls.append(("close-record", PureWindowsPath(self.path).name))
        self.FileObservation = FileObservation
        self.canonical_path = update_receipts.canonical_path
        self.machine_security = update_receipts.machine_security


class DriverGrantTests(unittest.TestCase):
    """The dedicated driver's grant: its close hold armed before the request, its collector asked once the TUN came up,
    both records handed to the stages, the product's own off between them, and the hold released only by a pass.

    Until this route existed the driver refused every grant (dedicated-finite-proxy-variants-only)."""

    OPERATION = "2c731e91-c158-4e8a-b779-54076ce85229"
    EVIDENCE = "C:\\ProgramData\\tun-evidence-" + OPERATION

    def setUp(self):
        import tempfile
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        # The driver's own clock only, created where an unfixed driver has none: these tests then reach its run() and its refusal.
        clock = types.SimpleNamespace(sleep=lambda seconds: self.owner.calls.append(("sleep", seconds)))
        for patcher in (mock.patch.object(dedicated_driver, "__file__", str(DedicatedDispatchPeer.SOURCE_ROOT / "windows_ordinary_dedicated_driver.py")),
                        mock.patch.object(dedicated_driver, "time", clock, create=True)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.owner = DedicatedDispatchPeer(self.root)
        self.grant()

    def grant(self, *, variant="restart-grant", stages=None, hold=None):
        owner = self.owner
        self.state, _ = owner.lifecycle("find-best-success")
        self.state["serve"].pid, self.state["serve"].birth = SERVE_PID, str(SERVE_BIRTH)
        owner.inputs["variant"] = variant
        runtime = owner.inputs["runtime"]
        runtime.update(workspace=str(self.root / "workspace"), ordinaryContextArtifactId="peer-context")
        path = owner.source("windows_tun_stages.py", "agent_tools/windows_tun_stages.py")
        owner.inputs["modules"]["tun"] = path
        owner.inputs["tun"] = {"schemaVersion": 1, "variant": variant, "installedAdmissionArtifactId": runtime["installedAdmissionArtifactId"],
                               "ordinaryContextArtifactId": "peer-context", "runtimeConfigPath": str(PureWindowsPath(runtime["workspace"]) / "runtime-config.json"),
                               "collectorSourceSha256": contract.COLLECTORS["tun"],
                               "samplerPath": owner.source("windows_tun_direct_sampler.py", "agent_tools/windows_tun_direct_sampler.py")}
        self.records = GrantRecords(owner.calls)
        self.hold_inputs = owner.tun_grant(self.records)
        owner.modules[path] = stages or self.stages()
        owner.harness({"LIFECYCLE_INPUTS": owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": self.hold_inputs if hold is None else hold})

    def stages(self, **failures):
        """windows_tun_stages as the driver sees it, the stage bodies declared; settled and closing are the real ones."""
        test, calls = self, self.owner.calls

        def begin(owner, state, inputs, runtime, cases, observer):
            calls.append(("tun-begin", inputs["variant"]))
            if failures.get("begin"):
                raise AssertionError(failures["begin"])
            owner.tun_operation_requested = True
            lease = {"inputs": dict(inputs, programData="C:\\ProgramData"), "state": state, "finished": False,
                     "accepted": {"operationId": PRODUCT_OPERATION, "requestId": REQUEST_ID},
                     "baseline": {"brokers": [], "runtimes": [], "stages": [], "routes": []}}
            owner.tun_operation_leases = [lease]
            return lease

        def finish(owner, lease, runtime, cases, observer, handoff=None, receipts=None):
            calls.append(("tun-finish", lease.get("sourceSha")))
            if failures.get("cancelled"):
                lease.update(finished=True, knownEnd="CANCELLED")
                return {"terminal": {"code": "CANCELLED"}, "status": {}, "nativeRecord": None, "cancelled": True}
            test.records.records[test.EVIDENCE + "\\ready.json"] = b'{"stage":"ready"}'
            record = handoff(lease, "ready")
            calls.append(("ready-handed", record["sha256"]))
            lease.update(finished=True, nativeReady={"stage": "ready"})
            return {"terminal": {"code": "OK"}, "status": {}, "nativeRecord": lease["nativeReady"]}

        def traffic(owner, lease):
            calls.append("tun-traffic")
            if failures.get("traffic"):
                raise AssertionError(failures["traffic"])

        def begin_off(owner, lease, runtime):
            calls.append("tun-off")
            lease["offRequested"] = True
            test.records.records[test.EVIDENCE + "\\off.json"] = b'{"stage":"off"}'  # The collector writes it once both ended.

        def finish_off(owner, lease, record, receipts):
            calls.append(("tun-off-record", record["sha256"]))
            lease["offFinished"] = True

        def closing(owner, lease, observer):
            calls.append("tun-closing")
            with mock.patch.object(tun_stages, "census", lambda inputs, observer, exclude=(): {"brokers": [], "runtimes": [], "stages": [], "routes": []}):
                return tun_stages.closing(owner, lease, observer)
        return types.SimpleNamespace(begin=begin, finish=finish, traffic=traffic, begin_off=begin_off, finish_off=finish_off,
                                     closing=closing, settled=tun_stages.settled)

    def events(self, kind):
        return [call[1] for call in self.owner.calls if isinstance(call, tuple) and call[0] == kind]

    def test_a_grant_hands_both_records_over_and_ends_only_with_its_collectors_release(self):
        self.records.misses[self.EVIDENCE + "\\ready.json"] = 2  # The host job serves the need between two polls of the run.
        self.assertEqual(0, dedicated_driver.run(self.owner, "windows-proxy-lifecycle"))
        calls = self.owner.calls
        order = ["arm", ("tun-begin", "restart-grant"), ("tun-finish", "a" * 40), ("ready-handed", sha(b'{"stage":"ready"}')), "tun-traffic", "tun-off",
                 ("tun-off-record", sha(b'{"stage":"off"}')), "tun-closing", "stop-fixture", ("public", "quit"), ("wait", "serve", 0),
                 ("driver-completed", 0), "wait-release"]
        self.assertEqual(order, [call for call in calls if call in order], "the hold is armed first and released last")
        self.assertFalse([call for call in calls if isinstance(call, tuple) and call[0] == "off-actors"],
                         "proxy A is gone: the grant's own off already ran, so the proxy off never does")
        need = self.events(dedicated_driver.NATIVE_NEED)
        self.assertEqual([{"stage": "tun", "jobId": None, "productOperationId": PRODUCT_OPERATION, "originRequestId": REQUEST_ID,
                           "controllerId": "peer-controller", "serve": {"pid": SERVE_PID, "birthFileTimeUtc": str(SERVE_BIRTH)},
                           "ordinaryTaskOperationId": self.OPERATION, "evidenceFile": self.EVIDENCE + "\\ready.json",
                           "collectorSourceSha256": contract.COLLECTORS["tun"], "resubmitAllowed": False}], need, "asked once")
        self.assertLess(calls.index((dedicated_driver.NATIVE_NEED, need[0])), calls.index(("ready-handed", sha(b'{"stage":"ready"}'))))
        self.assertEqual(2, calls.count(("sleep", 0.2)), "a record not there yet is pending, never a failure")
        handed = self.events("scoped-tun-native-record-handed")
        self.assertEqual([("ready", sha(b'{"stage":"ready"}'), 17), ("off", sha(b'{"stage":"off"}'), 15)],
                         [(value["stage"], value["sha256"], value["sizeBytes"]) for value in handed])
        self.assertEqual("released", self.owner.caller_collection_hold.state)

    def test_a_failure_once_its_collector_was_asked_parks_with_the_hold_kept(self):
        # The collector waits on this owner's hold, which only a passed driver releases: once the TUN's off is proven a
        # known failure would still exit 1 and leave the collector waiting, so the owner parks with everything kept.
        self.owner.modules[self.owner.inputs["modules"]["runtime"]].stop_fixture = lambda *args: (_ for _ in ()).throw(
            AssertionError("original-owned-fixture-terminal"))
        with self.assertRaisesRegex(DedicatedParked, "^dedicated-tun-failure-with-original-collector-hold$"):
            dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
        self.assertIn("tun-closing", self.owner.calls)
        self.assertNotIn("wait-release", self.owner.calls)
        self.assertFalse(self.events("dedicated-proxy-lifecycle-known-failure-closing"), "never closed as a known failure")
        self.assertIs(self.owner.caller_collection_hold, self.owner.parked["originalHold"])

    def test_a_failure_before_its_off_is_proven_leaves_everything_to_the_park(self):
        self.grant(stages=self.stages(traffic="scoped-tun-direct-traffic"))
        with self.assertRaisesRegex(AssertionError, "^scoped-tun-direct-traffic$"):
            dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
        for step in ("tun-off", "tun-closing", "stop-fixture", "wait-release"):
            self.assertNotIn(step, self.owner.calls)
        self.assertEqual("armed", self.owner.caller_collection_hold.state)

    def test_a_cancelled_grant_retires_its_unused_hold(self):
        # The prompt expired: the product's own CANCELLED with A intact, no TUN and no collector asked. The row closes
        # like a known end, proxy A's own off included, and its armed hold retires unused.
        self.owner = DedicatedDispatchPeer(self.root)
        self.grant(stages=self.stages(cancelled=True))
        self.assertEqual(1, dedicated_driver.run(self.owner, "windows-proxy-lifecycle"))
        self.assertFalse(self.events(dedicated_driver.NATIVE_NEED), "no TUN came up: no collector was asked")
        self.assertNotIn("wait-release", self.owner.calls)
        self.assertIsNone(self.owner.caller_collection_hold, "Owner.finish does not park on a hold no collector was asked to use")
        self.assertEqual("armed", self.owner.retired_collection_hold.state)
        self.assertTrue([call for call in self.owner.calls if isinstance(call, tuple) and call[0] == "off-actors"], "proxy A is still up")
        self.assertEqual([{"result": 1, "collectorRequested": False, "replayAllowed": False}], self.events("dedicated-tun-grant-hold-retired"))

    def test_a_record_that_is_not_machine_written_is_never_handed_over(self):
        ready = self.EVIDENCE + "\\ready.json"
        for name, security in (("ordinary-owner", {"ownerSid": SID, "sddl": "O:" + SID + "D:P(A;;FA;;;" + SID + ")"}),
                               ("users-write", {"ownerSid": "S-1-5-32-544", "sddl": "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)"}),
                               ("unprotected", {"ownerSid": "S-1-5-32-544", "sddl": "O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)"})):
            for target in (ready, self.EVIDENCE):
                with self.subTest(case=name, target=PureWindowsPath(target).name):
                    self.owner = DedicatedDispatchPeer(self.root)
                    self.grant()
                    self.records.security[target] = security
                    with self.assertRaises(update_receipts.Refused):
                        dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
                    self.assertNotIn("tun-traffic", self.owner.calls)
                    self.assertNotIn("wait-release", self.owner.calls)

    def test_the_ready_record_is_asked_for_once_and_the_off_record_only_after_it(self):
        lease = {"inputs": {"variant": "restart-grant", "programData": "C:\\ProgramData", "collectorSourceSha256": contract.COLLECTORS["tun"]},
                 "state": {"identity": "peer-controller", "serve": types.SimpleNamespace(pid=SERVE_PID, birth=str(SERVE_BIRTH))},
                 "accepted": {"operationId": PRODUCT_OPERATION, "requestId": REQUEST_ID}}
        self.owner.operation = self.OPERATION
        with self.assertRaisesRegex(ValueError, "^dedicated-tun-off-before-its-collector$"):
            dedicated_driver.tun_record(self.owner, lease, self.records, "off")
        self.records.records[self.EVIDENCE + "\\ready.json"] = b"{}"
        dedicated_driver.tun_record(self.owner, lease, self.records, "ready")
        with self.assertRaisesRegex(ValueError, "^dedicated-tun-collector-once$"):
            dedicated_driver.tun_record(self.owner, lease, self.records, "ready")
        for stage, variant in (("ready", "restart-deny"), ("tun", "restart-grant")):
            with self.subTest(stage=stage, variant=variant), self.assertRaisesRegex(ValueError, "^dedicated-tun-record-stage$"):
                dedicated_driver.tun_record(self.owner, {**lease, "inputs": {**lease["inputs"], "variant": variant}}, self.records, stage)
        self.assertEqual(1, len(self.events(dedicated_driver.NATIVE_NEED)))

    def test_a_hold_not_bound_to_this_grants_collector_starts_nothing(self):
        receipts = self.hold_inputs["receiptsPath"]
        cases = (("dedicated-exact-final-tun-collector-binding", {"receiptsPath": receipts.replace("windows_public_updater", "elsewhere")}),
                 ("dedicated-exact-final-tun-collector-binding", {"sourceSha": "b" * 40}),
                 ("dedicated-exact-final-tun-collector-binding", {"systemWorkerSourceSha256": "0" * 64}),
                 ("dedicated-exact-final-tun-collector-binding", {"scope": "update", "stage": "terminal-actors",
                                                                   "collectorSourceSha256": dedicated_driver.UPDATE_MODULES["collector"]}),
                 ("hold-fixed-collector-source", {"collectorSourceSha256": dedicated_driver.UPDATE_MODULES["collector"]}),
                 ("hold-finite-scope-stage", {"stage": "ready"}))
        for reason, change in cases:
            with self.subTest(reason=reason, change=change):
                self.owner = DedicatedDispatchPeer(self.root)
                self.grant()
                self.grant(hold={**self.hold_inputs, **change})
                with self.assertRaisesRegex(ValueError, "^" + reason + "$"):
                    dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
                self.assertNotIn("start-runtime", self.owner.calls)
                self.assertNotIn("arm", self.owner.calls)
        # The stages' own collector input must name the same TUN collector.
        self.owner = DedicatedDispatchPeer(self.root)
        self.grant()
        self.owner.inputs["tun"]["collectorSourceSha256"] = "c" * 64
        self.owner.harness({"LIFECYCLE_INPUTS": self.owner.inputs, "SYSTEM_COLLECTOR_CLOSE_HOLD": self.hold_inputs})
        with self.assertRaisesRegex(ValueError, "^dedicated-exact-final-tun-collector-binding$"):
            dedicated_driver.run(self.owner, "windows-proxy-lifecycle")
        self.assertNotIn("start-runtime", self.owner.calls)

    def test_only_the_restart_grant_reaches_the_collector_route(self):
        self.assertEqual(frozenset({"restart-grant"}), dedicated_driver.TUN_GRANT_VARIANTS)
        self.assertEqual(frozenset({"restart-deny", "restart-grant"}), dedicated_driver.TUN_VARIANTS)
        self.assertEqual(contract.COLLECTORS["tun"], getattr(dedicated_driver, "TUN_COLLECTOR_SHA", None))
        self.assertEqual(sha((ROOT / "agent_tools/windows_tun_native_observer.py").read_bytes()), contract.COLLECTORS["tun"])
        self.owner = DedicatedDispatchPeer(self.root)
        self.grant(variant="find-best-grant")
        with self.assertRaisesRegex(ValueError, "^dedicated-finite-proxy-variants-only$"):
            dedicated_driver.run(self.owner, "windows-proxy-lifecycle")


class TunGrantQga(UpdateQga):
    """The update rows' wire peer with a TUN grant's guest: the installed broker and its record, the owner's one native
    need once its TUN is up, a census of the controller, broker and runtime, and a TUN collector that publishes its
    ready and off records before its caller hold. The publisher template's TUN observation is followed from the rendered
    template's own text, as the update peer follows its backup reader: a template without it refuses as that one would.
    Following text proves no behaviour: WindowsCollectorObservationTests runs those template functions on Windows."""

    TUN_MARKERS = {"need": "|event-[0-9]{6}-update-native-observation-needed'", "broker": "-install-helper|-vpn-broker)?\\.exe",
                   "children": "[VpnScenarioObserver]::Census($image,$children)", "config": "\\workspace\\runtime-config.json')"}

    def __init__(self):
        super().__init__()
        self.needs = ["tun"]
        files, directories = self.installed_tree
        self.installed_tree = (sorted({*files, BROKER_RELATIVE, MANIFEST_RELATIVE, "app/desktopApp.jar", "app/skiko-awt.jar"}),
                               sorted({*directories, "app/native", "app/native/windows-amd64"}))
        self.guest_data.update({BROKER_PATH: BROKER_BYTES, INSTALLED_ROOT + "\\" + MANIFEST_RELATIVE.replace("/", "\\"): broker_manifest()})
        self.processes = tun_processes()
        self.need = {"stage": "tun", "jobId": None, "productOperationId": PRODUCT_OPERATION, "originRequestId": REQUEST_ID,
                     "controllerId": CONTROLLER, "serve": {"pid": SERVE_PID, "birthFileTimeUtc": str(SERVE_BIRTH)},
                     "resubmitAllowed": False}
        self.config = CONFIG

    def _guest_file_open(self, arguments):
        if arguments["path"].endswith("\\scenario-status.json") and arguments["mode"] == "rb":
            self.files[arguments["path"]] = json.dumps({
                "schemaVersion": 1, "poll": len(self.calls), "pendingKinds": [], "parkedFiles": list(self.parked_files),
                "uacEvents": ["scoped-tun-awaiting-current-input"],
                "nativeNeeds": [{"name": "event-000040-" + job.UPDATE_NEED + ".json", "ordinal": 40, "stage": stage, "jobId": None,
                                 "productOperationId": PRODUCT_OPERATION} for stage in self.needs]}).encode()
            return super(UpdateQga, self)._guest_file_open(arguments)
        return super()._guest_file_open(arguments)

    def _publisher(self, m, pid):
        if m["action"] != "collector-observe" or not m.get("tunNeed"):
            return super()._publisher(m, pid)

        def refused(code):
            return {"exited": True, "exitcode": 1, "err-data": base64.b64encode(("Exception: " + code).encode()).decode()}
        present = {name: marker in self.source for name, marker in self.TUN_MARKERS.items()}
        specs = m["census"] if type(m["census"]) is list else [m["census"]]
        for spec in specs:
            leaf = spec["image"].rsplit("\\", 1)[-1]
            if not (re.fullmatch(r"vpn-control(?:-cli|-install-helper)?\.exe", leaf) or present["broker"] and leaf == "vpn-control-vpn-broker.exe"):
                return refused("PUB_CENSUS_IMAGE")
        if any(path.endswith("\\workspace\\runtime-config.json") for path in m["productPins"]) and not present["config"]:
            return refused("PUB_PRODUCT_PIN_PATH")
        reply = {"schemaVersion": 1, "operationId": m["operationId"], "kernelBootIdentifier": m["kernelBootIdentifier"], "systemToken": m["systemToken"],
                 "allHeldAndNamedPinsClosing": True, "productOperation": False, "taskOperation": False, "bootstrapOpening": self._actor(pid),
                 "bootstrapClosing": self._actor(pid), "guestBootClosing": True, "bootstrapActorClosing": True}

        def event(ordinal, kind, value, task=False):
            body = {"schemaVersion": 1, "operationId": m["operationId"], "ordinal": ordinal, "kind": kind, "value": value}
            if task:
                body.update(ownerPid=901, ownerBirthFileTimeUtc="134368653065000002")
            return base64.b64encode(json.dumps(body).encode()).decode()
        files = {"task-event-000000-submission-intent.json": event(0, "submission-intent", {"mode": "python-worker"}, True),
                 "task-event-000001-submitted.json": event(1, "submitted", {"pid": WORKER_PID, "birthFileTimeUtc": str(WORKER_BIRTH),
                                                                            "originalHandleRetained": True}, True)}
        if present["need"]:
            files["event-000040-" + job.UPDATE_NEED + ".json"] = event(40, job.UPDATE_NEED, dict(self.need))
        census = []
        for spec in specs:
            leaf = spec["image"].rsplit("\\", 1)[-1].casefold()  # Census matches the snapshot's image leaf, as the C# does.
            matched = [row for row in self.processes if row["image"].rsplit("\\", 1)[-1].casefold() == leaf]
            if spec.get("children") and present["children"]:
                pids = {row["pid"] for row in matched}
                matched += [row for row in self.processes if row["parentPid"] in pids and row["pid"] not in pids]
            census += [copy.deepcopy(row) for row in matched]
        pins = [self._pin(path, raw=self.config, security={"ownerSid": SID, "sddl": "O:" + SID + "D:P(A;;FA;;;" + SID + ")"}) for path in m["productPins"]]
        reply.update(state="ordinary-collector-observation", observation={"files": files, "dispositions": [], "census": census, "productPins": pins})
        return {"exited": True, "exitcode": 0, "out-data": out_data(reply)}

    def _collector(self, source, pid):
        pin, request = self._request(source, r"\$RequestPinBase64='([A-Za-z0-9+/=]+)'")
        if request["scope"] != "tun":
            return super()._collector(source, pid)
        self.collectors.append(request)
        self.request_pins.append(pin)
        worker = {"pid": 6000 + len(self.collectors), "birthFileTimeUtc": "134368653065000010", "image": request["pythonRuntime"]["interpreterPath"]}
        hold, ordinary = request["closeHold"], request["ordinaryTask"]["workerActor"]
        ready = {"schemaVersion": 1, "kind": "caller-collector-close-ready", "ordinaryTaskOperationId": request["ordinaryTaskOperationId"],
                 "collectorOperationId": request["operationId"], "sourceSha": hold["sourceSha"], "scope": "tun", "stage": hold["stage"],
                 "bootIdentifier": request["context"]["bootIdentifier"],
                 "ordinaryWorker": {"pid": ordinary["pid"], "birthFileTimeUtc": str(ordinary["creationFileTime"]),
                                    **{key: ordinary[key] for key in ("image", "sha256", "sid", "sessionId")}},
                 "callerSourcePin": hold["callerSourcePin"], "collectorRequestSha256": pin["sha256"],
                 "systemActor": {"pid": pid, "birthFileTimeUtc": "134368653065000001"},
                 "collectorChild": {"pid": worker["pid"], "birthFileTimeUtc": worker["birthFileTimeUtc"]},
                 "driverKnownResult": 0, "allOriginalChildrenTerminalAndEof": True}
        raw = encoded(ready)
        caller = {"ready": ready, "sha256": sha(raw), "originalHandleRetained": True,
                  "nativeFile": {"path": hold["holdReadyPath"], "nativeIdentity": self._pin(hold["holdReadyPath"], raw=raw)["nativeIdentity"],
                                 "security": {"ownerSid": SID, "sddl": "O:" + SID + "D:P(A;;FA;;;" + SID + ")"}}}
        result = {"schemaVersion": 1, "state": "collector-completed", "operationId": request["operationId"],
                  "ordinaryTaskOperationId": request["ordinaryTaskOperationId"], "scope": "tun", "collectorSourceSha256": request["modules"]["collector"]["sha256"],
                  "workerActor": {"pid": worker["pid"], "birthFileTimeUtc": worker["birthFileTimeUtc"], "image": worker["image"],
                                  "bootIdentifier": request["context"]["bootIdentifier"], "token": {"sid": "S-1-5-18", "sessionId": 0, "elevation": 1}},
                  "publications": [{"path": "C:\\ProgramData\\tun-evidence-" + request["ordinaryTaskOperationId"] + "\\" + stage + ".json",
                                    "createOnly": True, "readOnlyProductObservation": True} for stage in ("ready", "off")],
                  "closing": {"sourceClosing": True, "files": len(request["filePins"]) + 1, "completeFileDigestSha256": "a" * 64}, "callerHold": caller}
        stdout = json.dumps(result).encode()

        def capture(name, raw):
            return {"name": name, "sizeBytes": len(raw), "sha256": sha(raw), "base64": base64.b64encode(raw).decode(), "eof": True,
                    "nativeIdentity": {"sizeBytes": len(raw)}}
        proof = {"schemaVersion": 1, "state": "collector-closed", "operationId": request["operationId"],
                 "ordinaryTaskOperationId": request["ordinaryTaskOperationId"], "scope": "tun",
                 "collectorSourceSha256": request["modules"]["collector"]["sha256"], "requestSha256": pin["sha256"], "requestNativeIdentity": pin["nativeIdentity"],
                 "worker": {"pid": worker["pid"], "birthFileTimeUtc": worker["birthFileTimeUtc"], "image": worker["image"], "sessionId": 0,
                            "exitCode": 0, "bothEof": True, "originalHandleRetained": True},
                 "captures": [capture("stdout", stdout), capture("stderr", b"")], "sourceClosing": True, "productMutation": False,
                 "bootstrapOpening": self._actor(pid), "bootstrapClosing": self._actor(pid), "guestBootClosing": True, "bootstrapActorClosing": True}
        return {"exited": True, "exitcode": 0, "out-data": out_data(proof)}


def owner_journal(m, events):
    """The evidence copy as the publisher zips it: the owner's own event files, one per event, with its operation."""
    import io
    import zipfile
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w") as archive:
        for ordinal, (kind, value) in enumerate(events):
            archive.writestr("event-%06d-%s.json" % (ordinal, kind), json.dumps(
                {"schemaVersion": 1, "operationId": m["operationId"], "ordinal": ordinal, "kind": kind, "value": value}, sort_keys=True))
        archive.writestr("child-0000.stdout.raw", b"")
    return memory.getvalue()


def closed(**known):
    """The dedicated driver's last lifecycle event: a pass, or a known end it closed by the same steps (knownFailure)."""
    return ("dedicated-proxy-lifecycle-known-closed", {"variant": "restart-grant", "controllerId": CONTROLLER, "sourceSha": "a" * 40,
                                                       "nativeAcceptanceComplete": False, **known})


AWAITING = ("scoped-tun-awaiting-current-input", {"variant": "restart-grant", "inputNotPerformedByThisAdapter": True, "replayAllowed": False})
GRANT_PASSED = (AWAITING, ("scoped-tun-public-outcome", {"variant": "restart-grant", "terminal": {"code": "OK"}}),
                ("scoped-tun-exact-off-observed", {"exitedAfterOffRequest": True}), closed())
GRANT_CANCELLED = (AWAITING, ("scoped-tun-grant-cancelled-known", {"variant": "restart-grant", "terminal": {"code": "CANCELLED", "final": True},
                                                                   "knownFailure": True, "replayAllowed": False}),
                   ("scoped-tun-closing-census", {"replayAllowed": False}), closed(knownFailure="cancelled"),
                   ("dedicated-tun-grant-hold-retired", {"result": 1, "collectorRequested": False, "replayAllowed": False}))


class TunGrantFamilyTests(FamilyBase):
    """windows-scoped-tun.restart-grant on the fake VM: the proxy family's job, the TUN stages, and its one collector stage
    served inside the run when the owner asks for the ready record."""

    def setUp(self):
        super().setUp()
        self.qga = TunGrantQga()
        self.qga.evidence_factory = lambda m: owner_journal(m, GRANT_PASSED)
        self.rt = FakeRuntime(self.vm, self.qga)
        loaded = job.Job._load

        def load(instance, name):
            module = loaded(instance, name)
            if name == "windows_scenario_proxy":
                from agent_tools.tests.test_windows_scenario_host_job import proxy_tls
                module.material = lambda randbits, now: proxy_tls()
            return module
        patcher = mock.patch.object(job.Job, "_load", load)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_grant(self, install, **changes):
        plan = self.family_plan("windows-scoped-tun.restart-grant", prior=install)
        plan.update(administrator="recoveryadmin", **changes)
        self.addCleanup(self.forget_modules, plan["operationId"])
        start = len(self.qga.programs)
        code = job.run_job(self.rt, plan, self.files)
        return plan, code, self.receipt(plan), [kind for kind, _ in self.qga.programs[start:]]

    def harness(self, plan):
        import ast
        raw = self.qga.files[job.WORKSPACE_PREFIX + plan["operationId"] + "\\proxy-harness.py"]
        tree = ast.parse(raw.decode("ascii"))
        return {node.targets[0].id: ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)}

    def test_the_grant_serves_its_one_collector_inside_the_run_and_releases_the_hold(self):
        self.granted()

    def granted(self):
        install, _ = self.install_base()
        plan, code, receipt, kinds = self.run_grant(install)
        self.assertEqual((0, None, "passed"), (code, receipt["failure"], receipt["result"]))
        self.assertEqual({"installedPackage": True, "packageSha256": self.packages["targetPackage"]["sha256"]}, receipt["windows"],
                         "a passed grant claims the installed package like any product row")
        run = kinds.index("system-run")
        self.assertEqual(["collector-observe", "endpoints", "verify", "collector", "collector-release"], kinds[run + 1:run + 6],
                         "one stage, served between two polls of the SYSTEM run, behind its caller hold")
        source = [source for kind, source in self.qga.programs if kind == "system-run"][-1]
        from agent_tools.tests.test_windows_scenario_host_job import program_input
        self.assertEqual((True, ["scoped-tun-awaiting-current-input"]), (program_input(source)["nativeNeeds"], program_input(source)["uacKinds"]))
        [request] = self.qga.collectors
        operation, workspace = plan["operationId"], job.WORKSPACE_PREFIX + plan["operationId"]
        product = PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + operation + "\\workspace"
        collector = job.collector_operation(operation, "tun")
        self.assertEqual(("tun", collector, workspace + "\\system-collector-" + collector), (request["scope"], request["operationId"], request["operationRoot"]))
        self.assertEqual({"schemaVersion": 1, "callerSourcePin": request["closeHold"]["callerSourcePin"], "scope": "tun", "stage": "off",
                          "sourceSha": "a" * 40, "holdReadyPath": PROFILE + "\\AppData\\Local\\VpnControlOrdinary-" + operation + "\\collector-hold-" + collector + ".ready.json",
                          "releasePath": request["operationRoot"] + "\\close-release.json"}, request["closeHold"])
        body = request["collectorRequest"]
        self.assertEqual({"pid": JVM_PID, "creationFileTime": JVM_BIRTH, "image": CLI_PATH, "sha256": sha(b"exe:" + VERSION.encode()), "sid": SID,
                          "sessionId": SESSION}, body["ownerActor"])
        self.assertEqual((BROKER_PID, ADMIN_SID, BROKER_PATH, sha(BROKER_BYTES)), (body["helperActor"]["pid"], body["helperActor"]["sid"],
                                                                                 body["helperImagePath"], body["helperImageSha256"]))
        self.assertEqual((RUNTIME_PID, ADMIN_SID, RUNTIME_PATH, sha(RUNTIME_BYTES)), (body["runtimeActor"]["pid"], body["runtimeActor"]["sid"],
                                                                                    body["runtimeImagePath"], body["runtimeImageSha256"]))
        self.assertIsNone(body["guiActor"])
        self.assertEqual((PRODUCT_OPERATION, REQUEST_ID, CONTROLLER, "a" * 40, contract.COLLECTORS["tun"]),
                         (body["productOperationId"], body["originRequestId"], body["controllerId"], body["sourceSha"], body["collectorSourceSha256"]))
        self.assertEqual({"ordinarySid": SID, "ordinarySessionId": SESSION, "approvingAdminSid": ADMIN_SID, "bootIdentifier": request["context"]["bootIdentifier"],
                          "programData": "C:\\ProgramData", "workspace": product}, body["context"])
        self.assertEqual({"path": product + "\\runtime-config.json", "sha256": sha(CONFIG), "sizeBytes": len(CONFIG)}, body["configuration"])
        files = {pin["path"]: pin for pin in request["filePins"]}
        self.assertEqual(workspace + "\\windows_tun_native_observer.py", request["modules"]["collector"]["path"])
        self.assertEqual(workspace + "\\windows_broker_fixture_observer.py", request["modules"]["observer"]["path"], "the proxy rows' own observer role")
        self.assertIn(request["modules"]["receipts"]["path"], files)
        self.assertEqual([job.collector_operation(operation, "tun")], [release["collectorOperationId"] for release in self.qga.releases])
        tun = receipt["tun"]
        self.assertEqual(("restart-grant", {"tun": {"requestSha256": self.qga.request_pins[0]["sha256"], "released": True}}),
                         (tun["variant"], tun["collectors"]))
        self.assertIsNone(tun.get("knownEnd", "absent"), "a pass closed with no known end")
        self.assertEqual({"pid": JVM_PID, "creationFileTime": JVM_BIRTH, "relaunched": True}, tun["broker"]["controller"])
        self.assertEqual(({"pid": JVM_PID, "alive": True, "matches": True}, ["conhost.exe"]), (tun["broker"]["broker"]["parent"], tun["broker"]["auxiliary"]))
        self.assertTrue((Path(plan["dataDirectory"]) / "collectors" / "tun" / "census.json").exists())
        self.assertLessEqual(len((Path(plan["dataDirectory"]) / "scenario-receipt.json").read_bytes()), job.RECEIPT_BYTES)
        harness = self.harness(plan)
        hold = harness["SYSTEM_COLLECTOR_CLOSE_HOLD"]
        self.assertIs(hold, hold_protocol.validate_inputs(hold, ordinary_task_operation_id=operation, program_data="C:\\ProgramData"))
        self.assertEqual(("tun", "off", request["operationRoot"], contract.COLLECTORS["tun"], workspace + "\\windows_public_updater\\update_receipts.py"),
                         (hold["scope"], hold["stage"], hold["collectorRoot"], hold["collectorSourceSha256"], hold["receiptsPath"]))
        self.assertEqual(contract.COLLECTORS["tun"], harness["LIFECYCLE_INPUTS"]["tun"]["collectorSourceSha256"])
        self.assertEqual([], self.classify()["unresolved"])
        return plan, request

    def test_the_real_observer_and_stages_take_what_this_job_builds(self):
        """windows_tun_native_observer, the pinned TUN collector's own code, over the request this job built, with the
        guest's processes as the census reported them; its ready and off values, as windows_tun_stages reads them back,
        join the owner's lease and its worker request as the planner builds it."""
        plan, request = self.granted()
        spec = importlib.util.spec_from_file_location("_tun_grant_observer", ROOT / "scripts/windows_broker_fixture_observer.py")
        observer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(observer)
        rows = {row["pid"]: row for row in tun_processes()}
        signaled = set()

        class Process:
            def __init__(self, row):
                self.row, self.closed = row, False

            def describe(self):
                return {"image": self.row["image"], "creationFileTime": int(self.row["creationFileTime"]), "exitFileTime": 0,
                        "token": dict(self.row["token"]), "sha256": self.row["imageSha256"], "sizeBytes": self.row["imageSizeBytes"]}

            def wait(self):
                return 0 if self.row["pid"] in signaled else 258

            def times(self):
                # GetProcessTimes: a live process has no exit time; one the product's own off ended exited after it was asked.
                return {"creationFileTime": int(self.row["creationFileTime"]), "exitFileTime": OFF_EXITED if self.row["pid"] in signaled else 0,
                        "kernelTime100ns": 1, "userTime100ns": 1}

            def modules(self):
                return [{"base": 1, "path": "C:\\Windows\\System32\\ntdll.dll"}]

            def __exit__(self, *_):
                self.closed = True

        class Native:
            def open_process(self, pid, access):
                return Process(rows[pid])

            def processes(self):
                return [{"pid": row["pid"], "parentPid": row["parentPid"], "name": row["image"].rsplit("\\", 1)[-1]} for row in rows.values()]

            @staticmethod
            def file_identity(path):
                return {"sha256": "1" * 64, "sizeBytes": 1}
        observing = types.SimpleNamespace(WindowsNative=Native, require_identity=observer.require_identity)
        body = request["collectorRequest"]

        class Config:
            def __init__(self, owner, path):
                self.opening = {"path": path, "nativeIdentity": {"sizeBytes": len(CONFIG)}, "security": {"ownerSid": SID, "sddl": "O:" + SID + "D:P(A;;FA;;;" + SID + ")"}}

            def read(self, maximum):
                return CONFIG

            def close(self):
                pass
        owner = types.SimpleNamespace(native=types.SimpleNamespace(token=lambda: {"sid": "S-1-5-18", "elevation": 1},
                                                                   boot_identifier=lambda: body["context"]["bootIdentifier"]),
                                      guard=lambda: None,
                                      by_path={str(Path(tun_observer.__file__)).casefold(): types.SimpleNamespace(record={"sha256": body["collectorSourceSha256"]})})
        with mock.patch.object(update_receipts, "FileObservation", Config):
            custody = tun_observer.collect_ready(body, owner, update_receipts, observing)
        self.assertEqual([JVM_PID, BROKER_PID, RUNTIME_PID], [expected["pid"] for _, expected, _ in custody.handles])
        self.assertEqual({"sha256": sha(CONFIG), "sizeBytes": len(CONFIG)}, {key: custody.ready["observations"]["configuration"][key] for key in ("sha256", "sizeBytes")})
        signaled.update({BROKER_PID, RUNTIME_PID})  # The product's own off ended exactly these two.
        off = custody.after_off()
        self.assertEqual({"helperActor", "runtimeActor"}, {row["role"] for row in off["originalProcesses"]})
        # The stages read both values back as the owner of this very job: its worker request and its lease.
        worker = self.qga.requests_seen[-1]["worker"]
        self.assertNotIn("sourceSha", worker, "the worker request names no source: the lease carries the row's own")
        harness = self.harness(plan)
        lease = {"inputs": dict(harness["LIFECYCLE_INPUTS"]["tun"]), "accepted": {"operationId": PRODUCT_OPERATION, "requestId": REQUEST_ID},
                 "state": {"identity": CONTROLLER, "workspace": PureWindowsPath(worker["workspace"])}, "sourceSha": harness["LIFECYCLE_INPUTS"]["sourceSha"]}
        reader = types.SimpleNamespace(request=worker, operation=worker["operationId"])
        for value in (custody.ready, off):
            raw = update_receipts.encoded(value)
            path = "C:\\ProgramData\\tun-evidence-" + worker["operationId"] + "\\" + value["stage"] + ".json"

            class Record:
                def __init__(self, owner, actual):
                    self.opening = {"security": {"ownerSid": "S-1-5-32-544", "sddl": "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)"}}

                def read(self, maximum, raw=raw):
                    return raw

                def close(self):
                    pass
            receipts = types.SimpleNamespace(canonical_path=update_receipts.canonical_path, FileObservation=Record,
                                             machine_security=update_receipts.machine_security)
            with self.subTest(stage=value["stage"]):
                read = tun_stages.read_native_record(reader, lease, {"path": path, "sha256": sha(raw), "sizeBytes": len(raw)}, receipts, value["stage"])
                self.assertEqual(json.loads(raw), read)
        lease.update(offRequested=True, offRequestedFileTime=OFF_ASKED, offTerminal={"code": "OK"})
        reader.tun_operation_leases, reader.event = [lease], lambda kind, value: None
        raw = update_receipts.encoded(off)

        class OffRecord:
            def __init__(self, owner, actual):
                self.opening = {"security": {"ownerSid": "S-1-5-32-544", "sddl": "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)"}}

            def read(self, maximum):
                return raw

            def close(self):
                pass
        receipts = types.SimpleNamespace(canonical_path=update_receipts.canonical_path, FileObservation=OffRecord, machine_security=update_receipts.machine_security)
        tun_stages.finish_off(reader, lease, {"path": "C:\\ProgramData\\tun-evidence-" + worker["operationId"] + "\\off.json", "sha256": sha(raw),
                                              "sizeBytes": len(raw)}, receipts)
        self.assertTrue(lease["offFinished"])

    def test_a_publisher_without_the_tun_observation_leaves_the_owner_unknown(self):
        """The 1d9d239b template's census takes only the CLI and the installer helper: the broker's census refuses while
        the owner waits on the ready record, so the job ends UNKNOWN with no collector and the fence open."""
        install, _ = self.install_base()
        template = self.files["agent_tools/windows_scenario_publisher.ps1.template"]
        self.assertEqual(1, template.count(b"-install-helper|-vpn-broker)?"))
        self.files["agent_tools/windows_scenario_publisher.ps1.template"] = template.replace(b"-install-helper|-vpn-broker)?", b"-install-helper)?")
        plan, code, receipt, kinds = self.run_grant(install, files={path: {"sha256": sha(raw), "sizeBytes": len(raw)} for path, raw in self.files.items()})
        self.assertEqual((3, "collector_stage_failed:tun:publisher_refused:collector-observe-tun:PUB_CENSUS_IMAGE"), (code, receipt["failure"]))
        self.assertNotIn("collector", kinds)
        self.assertFalse(self.fence(plan, ".terminal.json").exists())

    def test_a_census_the_grant_cannot_take_leaves_the_owner_unknown_with_no_collector(self):
        install, _ = self.install_base()
        for reason, change in (("collector_tun_broker_token", lambda rows: find(rows, BROKER_PID)["token"].update(elevated=0)),
                               ("collector_tun_runtime_count_0", lambda rows: rows.remove(find(rows, RUNTIME_PID))),
                               ("collector_tun_serve", lambda rows: find(rows, SERVE_PID).update(parentPid=4, parent={**find(rows, SERVE_PID)["parent"], "pid": 4}))):
            with self.subTest(reason=reason):
                self.qga.processes = tun_processes()
                change(self.qga.processes)
                plan, code, receipt, kinds = self.run_grant(install)
                self.assertEqual((3, "collector_stage_failed:tun:" + reason), (code, receipt["failure"]))
                self.assertNotIn("collector", kinds)
                self.assertFalse(self.fence(plan, ".terminal.json").exists())
                self.forget(plan)

    def test_a_need_naming_another_operation_or_no_serve_starts_no_collector(self):
        install, _ = self.install_base()
        for reason, change in (("collector_tun_need", lambda need: need.update(productOperationId="88888888-aaaa-4bbb-8ccc-dddddddddddd")),
                               ("collector_tun_need", lambda need: need.update(stage="ready")),
                               ("collector_tun_need", lambda need: need.pop("serve")),
                               ("collector_tun_need", lambda need: need.update(controllerId="controller-1"))):
            with self.subTest(change=change):
                self.qga.need = {"stage": "tun", "jobId": None, "productOperationId": PRODUCT_OPERATION, "originRequestId": REQUEST_ID,
                                 "controllerId": CONTROLLER, "serve": {"pid": SERVE_PID, "birthFileTimeUtc": str(SERVE_BIRTH)}}
                change(self.qga.need)
                plan, code, receipt, kinds = self.run_grant(install)
                self.assertEqual((3, "collector_stage_failed:tun:" + reason), (code, receipt["failure"]))
                self.assertNotIn("collector", kinds)
                self.forget(plan)

    def test_without_its_broker_or_with_another_runtime_the_grant_ends_before_its_task(self):
        """Its owner waits on the collector with no deadline, so what the collector will need is read before any task.
        The install records the tree each manifest leaves, so the row reaches the read and refuses there."""
        manifest = INSTALLED_ROOT + "\\" + MANIFEST_RELATIVE.replace("/", "\\")
        for reason, raw in (("installed_runtime_authority", broker_manifest(runtime=b"another runtime")),
                            ("installed_vpn_broker", broker_manifest(operations=["validate-only"]))):
            with self.subTest(reason=reason):
                self.qga = TunGrantQga()  # A fresh guest: the install row never upgrades over a registered product.
                self.rt = FakeRuntime(self.vm, self.qga)
                self.qga.guest_data[manifest] = raw
                install, _ = self.install_base()
                plan, code, receipt, kinds = self.run_grant(install)
                self.assertEqual((1, reason, "publish"), (code, receipt["failure"], receipt["stage"]))
                self.assertNotIn("system-run", kinds)

    def forget(self, plan):
        import shutil
        shutil.rmtree(plan["dataDirectory"])
        for path in self.vm.glob("direct-guest-*.intent.json"):
            if not path.with_name(path.name[:-len(".intent.json")] + ".terminal.json").exists():
                path.unlink()
        self.qga.collectors.clear()
        self.qga.releases.clear()

    def test_a_failed_grant_receipt_names_the_known_end_its_owner_closed_with(self):
        """A grant whose prompt expired, because the decision never typed, fails by the product's own CANCELLED like one
        the product cancelled after a typed approval: the planner tells them apart by the decision's terminal, and only for
        the known end the owner's own journal names (_decision_joined). The job reads that name from the evidence copy."""
        install, _ = self.install_base()
        oracle = (AWAITING, ("dedicated-proxy-lifecycle-known-failure-closing", {"variant": "restart-grant", "reason": "x"}),
                  ("dedicated-proxy-lifecycle-known-failure", {"variant": "restart-grant", "reason": "x", "closed": True}))
        unexpected = (AWAITING, ("scoped-tun-unexpected-terminal-known", {"variant": "restart-grant", "terminal": {"code": "RUNTIME_FAILED"}}),
                      closed(knownFailure="RUNTIME_FAILED"))
        for name, journal, expected in (("cancelled", GRANT_CANCELLED, "cancelled"), ("unexpected-terminal", unexpected, "RUNTIME_FAILED"),
                                        ("oracle-failure", oracle, None), ("twice", (*GRANT_CANCELLED, closed()), "unread"),
                                        ("other-name", (closed(knownFailure="cancelled; drop"),), "unread"), ("no-zip", None, "unread")):
            with self.subTest(case=name):
                self.qga.needs, self.qga.task_exit = [], 1  # No TUN came up, so no collector is asked; the owner exits 1.
                self.qga.evidence_factory = (lambda m: b"PK not a zip") if journal is None else (lambda m, journal=journal: owner_journal(m, journal))
                plan, code, receipt, kinds = self.run_grant(install)
                self.assertEqual((1, "task_exit_code", "failed", "evidence-zip"), (code, receipt["failure"], receipt["result"], kinds[-1]))
                self.assertEqual(expected, receipt["tun"].get("knownEnd", "absent"))
                self.assertNotIn("collector", kinds)
                self.forget(plan)

    def test_the_deny_row_keeps_no_collector_hold_or_folder(self):
        row = windows.RECIPES["windows-scoped-tun.restart-deny"]
        self.assertEqual({"variant": "restart-deny"}, row["tun"])
        self.assertEqual([], job.update_subfolders("0d5e5c56-7a39-4f43-9d4b-2a1c3d4e5f60", row))
        grant = windows.RECIPES["windows-scoped-tun.restart-grant"]
        operation = "0d5e5c56-7a39-4f43-9d4b-2a1c3d4e5f60"
        self.assertEqual([("windows_public_updater", "0x1200a9"), ("windows_system_collector", "0x1200a9"),
                          ("system-collector-" + job.collector_operation(operation, "tun"), "0x1200a9")], job.update_subfolders(operation, grant))


@unittest.skipUnless(__import__("os").name == "nt", "Windows itself: the publisher's census, compiled and run by Windows PowerShell")
class WindowsCensusTests(unittest.TestCase):
    """The template's own C# census where Windows runs the tests: asked for children, it also names a process the matched
    image started, whatever its image; asked for none, only that image's processes, as the update rows' census was."""

    def test_a_census_with_children_also_names_what_the_image_started(self):
        import os
        import subprocess
        import sys
        from agent_tools.tests.test_windows_update_grant_collectors import observer_function
        shell = Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"
        child = subprocess.Popen([str(shell), "/d", "/c", "ping -n 30 127.0.0.1 >NUL"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        script = observer_function() + "\n" + "\n".join((
            "$ErrorActionPreference='Stop'", "Add-ObserverType",
            "[ordered]@{children=@([VpnScenarioObserver]::Census($env:VPN_TEST_IMAGE,$true));"
            "plain=@([VpnScenarioObserver]::Census($env:VPN_TEST_IMAGE))}|ConvertTo-Json -Depth 8 -Compress"))
        powershell = Path(os.environ["SystemRoot"]) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                                 "$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))"], input=script.encode("utf-8"),
                                capture_output=True, timeout=120, check=False, env={**os.environ, "VPN_TEST_IMAGE": sys.executable})
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        value = json.loads(result.stdout)
        with_children, plain = job.census_rows(value["children"]), job.census_rows(value["plain"])
        started = [row for row in with_children if row["pid"] == child.pid]
        self.assertEqual(1, len(started), "the image's own child is named with it")
        self.assertEqual((os.getpid(), True, "cmd.exe"), (started[0]["parentPid"], started[0]["live"], Path(started[0]["image"]).name.lower()))
        self.assertEqual([], [row for row in plain if row["pid"] == child.pid], "without children only the image's own processes")


def publisher_function(name):
    """One function of the publisher template exactly as it carries it, up to the next function or its main body."""
    template = (ROOT / "agent_tools" / "windows_scenario_publisher.ps1.template").read_text(encoding="utf-8")
    found = re.search(r"^function " + re.escape(name) + r"[ (]", template, re.M)
    if found is None:
        raise AssertionError("the publisher template has no function " + name)
    ends = [at for at in (template.find("\nfunction ", found.start()), template.find("\n$r=$null", found.start())) if at != -1]
    return template[found.start():min(ends)]


@unittest.skipUnless(__import__("os").name == "nt", "Windows itself: the publisher's TUN observation, run by Windows PowerShell")
class WindowsCollectorObservationTests(unittest.TestCase):
    """The template's own collector-observe functions where Windows runs the tests, not the wire peer that follows their text:
    a TUN need reads the owner's need event in place of its child events, the census of the installed broker names the
    process it started, only that broker may ask for children, and the product workspace's runtime config is a product pin."""

    def test_a_tun_observation_reads_its_need_the_brokers_child_and_its_config_pin(self):
        import os
        import shutil
        import subprocess
        import tempfile
        from agent_tools.tests.test_windows_update_grant_collectors import observer_function
        system = Path(os.environ["SystemRoot"]) / "System32"
        local = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, local, True)
        operation = local / "operation"
        operation.mkdir()
        events = {"task-event-000000-submission-intent.json": b'{"kind":"submission-intent"}',
                  "task-event-000001-submitted.json": b'{"kind":"submitted"}',
                  "event-000040-" + job.UPDATE_NEED + ".json": b'{"kind":"need","value":{"stage":"tun"}}',
                  "event-000041-child-intent.json": b'{"kind":"child-intent","value":{"label":"lifecycle-serve","child":1}}'}
        for name, raw in events.items():
            (operation / name).write_bytes(raw)
        # The installed broker's image name, which starts one child: a copy of cmd.exe that runs ping.
        broker = local / "vpn-control" / "vpn-control-vpn-broker.exe"
        broker.parent.mkdir()
        shutil.copyfile(system / "cmd.exe", broker)
        child = subprocess.Popen([str(broker), "/d", "/c", "ping -n 30 127.0.0.1 >NUL"], stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        m = {"operationRoot": str(operation), "localAppData": str(local), "tunNeed": True, "returnedActors": False,
             "readDisposition": False, "census": [{"image": str(broker), "children": True}], "productPins": []}
        script = "\n".join((observer_function(), *(publisher_function(name) for name in (
            "Read-Bounded", "Get-ProcessCensus", "Assert-ProductPin", "Get-CollectorObservation")),
            "$ErrorActionPreference='Stop'", "$m=$env:VPN_TEST_INPUT|ConvertFrom-Json", "$r=[ordered]@{}",
            "$r.observation=Get-CollectorObservation",
            "$r.configPin=$(try{Assert-ProductPin ($m.operationRoot+'\\workspace\\runtime-config.json');'accepted'}catch{[string]$_.Exception.Message})",
            "$r.otherConfigPin=$(try{Assert-ProductPin ($m.localAppData+'\\workspace\\runtime-config.json');'accepted'}catch{[string]$_.Exception.Message})",
            "$r.childrenOfAnother=$(try{[void](Get-ProcessCensus @([pscustomobject]@{image=($m.localAppData+'\\vpn-control\\vpn-control.exe');"
            "children=$true}));'accepted'}catch{[string]$_.Exception.Message})",
            "$r|ConvertTo-Json -Depth 8 -Compress"))
        powershell = system / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                                 "$s=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($s))"], input=script.encode("utf-8"),
                                capture_output=True, timeout=120, check=False, env={**os.environ, "VPN_TEST_INPUT": json.dumps(m)})
        self.assertEqual(0, result.returncode, result.stderr.decode(errors="replace"))
        value = json.loads(result.stdout)
        files = value["observation"]["files"]
        self.assertEqual(sorted(name for name in events if "child-intent" not in name), sorted(files),
                         "a TUN need reads its need event and the task's two, never a child event")
        self.assertEqual({name: events[name] for name in files}, {name: base64.b64decode(raw) for name, raw in files.items()})
        census = job.census_rows(value["observation"]["census"])
        self.assertEqual([True], [row["live"] for row in census if row["pid"] == child.pid], "the broker itself")
        # Its console, if it got one, is named as well; the ping is the child this test asked for.
        started = [row for row in census if row["parentPid"] == child.pid and row["live"]
                   and PureWindowsPath(row["image"]).name.lower() == "ping.exe"]
        self.assertEqual(1, len(started), "the process the broker started")
        self.assertEqual(("accepted", "PUB_PRODUCT_PIN_PATH", "PUB_CENSUS_CHILDREN"),
                         (value["configPin"], value["otherConfigPin"], value["childrenOfAnother"]))


if __name__ == "__main__":
    unittest.main()
