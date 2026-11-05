"""Persisted-start decisions and the actual unchanged Linux supervisor closure.

Native ownership, real AVD boot and PackageInstaller acceptance remain external.
Fixture bindings are inert; retained reader and supervisor code is authentic.
"""
import base64
import ast
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
import uuid
from unittest import mock

from agent_tools import android_persisted_start as start
from agent_tools import durable_remote_job as durable
from agent_tools import ssh_transport as ssh
from agent_tools import ssh_automatic_program as automatic

# These tests execute whole POSIX controllers or descriptor/socket fixtures.
POSIX_FDS = os.name == "posix" and all(hasattr(os, name) for name in
    ("getuid", "geteuid", "O_NOFOLLOW", "O_DIRECTORY", "fstatvfs"))

# Only coordinator-local authority names follow the coordinator path syntax.
# These names are inert; original remote Linux paths stay verbatim in capsule().
LOCAL_AUTHORITY_ROOT = PureWindowsPath("C:/vpn-control-owned-inert") if os.name == "nt" else Path("/owned")

FIXTURES = Path(__file__).parent / "fixtures/android_persisted_start"
PRODUCER = Path(__file__).parent / "fixtures/android_existing_readonly/coldboot_producer.source"
PRODUCER_SHA = "7d90c06070ffad1439e613c9ad5d63f979d43b738944f0630b2b15187f09fec6"
READERS_SHA = "106193c91deb9ba1b54c6cb1dee6b3821e47165f61c317ae6d8e553536d20b8c"
UNIT_HOST_SOURCE = b"def installer_host_preflight():return {'state':'admitted','stableBinding':{'owned-inert-installer-precondition':True},'evidence':{'unitOnly':True}}\n"


def host_guard(original_sha):
    return {"source": UNIT_HOST_SOURCE, "sha256": hashlib.sha256(UNIT_HOST_SOURCE).hexdigest(),
            "originalSourceSha256": original_sha, "sourcePins": {"owned-inert-test-capsule": original_sha}}


def authority(rows=None):
    raw = start._canonical({"version": 1, "reservations": rows or []})
    return {"hostAlias": "archlinux", "capturedAtNs": 1, "records": [{
        "path": str(LOCAL_AUTHORITY_ROOT / "reservations.json"), "pin": {"generation": [1, 2, 0o100600, 503, 20, 1, len(raw), 3, 4],
          "parents": {LOCAL_AUTHORITY_ROOT.anchor: [1, 2, 0o40755, 0, 0]}, "sha256": hashlib.sha256(raw).hexdigest()},
        "rawBase64": base64.b64encode(raw).decode()}]}


def capsule():
    boot = "25515f23-b966-4c3a-ae63-d38452375578"
    source = {"agent_tools/android_avd_coldboot.py": PRODUCER_SHA}
    generation = {"child": {"pid": 1001, "startTicks": 1}, "guest": {"pid": 1002, "startTicks": 2}, "device": {}}
    fact = {"present": True, "kind": "regular", "generation": [1, 2, 8, 3, 4, 0o100600, 1000, 1000, 1],
            "bytesRead": 8, "sha256": "b" * 64, "hashScope": "full"}
    launch = {"device": "api35", "avd": "owned-inert-avd", "port": 5682,
        "argv": ["/owned/emulator", "-avd", "owned-inert-avd", "-port", "5682", "-memory", "2048", "-no-snapshot-load", "-no-snapshot-save"],
        "environment": {"PATH": "/usr/bin:/bin"}, "qemuPath": "/owned/qemu", "adbPath": "/owned/adb",
        "correlationId": "e3e97a65-b14a-4c32-8954-a441ac28ec47",
        "intent": {"source": source, "reservation": {"nonsecretFixture": True}},
        "observation": {"bootId": boot, "avds": {"api35": {
            "directory": {"path": "/owned/fixture.avd"}, "ini": fact, "config": fact,
            "sdkFiles": {"/owned/adb": {}, "/owned/emulator": {}}}}}}
    readers = (FIXTURES / "original-readers.source").read_bytes()
    if hashlib.sha256(readers).hexdigest() != READERS_SHA: raise ValueError("authentic-reader-fixture-changed")
    raw = ("ROOT=pathlib.Path('/owned/shared-root')\nCFG=" + repr({"source": source}) + "\nLAUNCH=" + repr(launch)
        + "\nGETTER=" + repr({"generation": generation}) + "\n" + readers.decode()).encode()
    return raw, hashlib.sha256(raw).hexdigest(), launch


def admission(operation, digest, auth, launch):
    fact = {"present": True, "kind": "regular", "generation": [1, 2, 8, 3, 4, 0o100600, 1000, 1000, 1],
            "bytesRead": 8, "sha256": "b" * 64, "hashScope": "full"}
    now = time.time_ns() // 1000000
    samples = [{"observedAtUnixMs": stamp, "availableMemoryBytes": 64 * 1024 ** 3,
                "psi": "normal", "vmstat": {"pswpin": 0, "pswpout": 0, "oomKill": 0}}
               for stamp in (now - 10, now - 1)]
    measurement = {"platform": "linux", "physicalMemoryBytes": 128 * 1024 ** 3,
                   "availableMemoryBytes": 64 * 1024 ** 3, "runningConfiguredMemoryBytes": 0,
                   "swapUsedBytes": 0, "pressure": "normal", "samples": samples}
    row = {"host": {"bootId": launch["observation"]["bootId"], "machineSha256": "a" * 64, "uid": 0, "gid": 0},
        "installerHost": {"state": "admitted", "stableBinding": {"owned-inert-installer-precondition": True}, "evidence": {"unitOnly": True}},
        "avd": {"directory": "/owned/fixture.avd", "tree": {".": {"kind": "directory"}}, "ini": fact, "config": fact},
        "sdkFiles": {name: fact for name in launch["observation"]["avds"]["api35"]["sdkFiles"]},
        "emulatorFact": fact, "qemuFact": fact, "locks": {"coldboot": fact, "device": fact},
        "originalAbsence": [{"role": role, "originalPid": pid, "originalStartTicks": ticks, "currentStartTicks": None, "originalAbsent": True}
                            for role, pid, ticks in [("child", 1001, 1), ("guest", 1002, 2)]],
        "holderCensus": {"complete": True, "holders": [], "unreadableProcessCount": 0}, "protectedEmulators": [],
        "targetActors": [], "targetPorts": [], "resources": {"availableMemoryBytes": 64 * 1024 ** 3,
            "pendingReservationBytes": start.reservation_bytes(auth), "requestedMemoryBytes": start.MEMORY_BYTES,
            "headroomBytes": start.HEADROOM_BYTES, "freeDiskBytes": 64 * 1024 ** 3, "minDiskBytes": start.MIN_DISK_BYTES,
            "nativeObservation": {"state": "OBSERVED", "measurementAvailability": "complete", "measurement": measurement},
            "canonicalPlan": start.capacity_plan(measurement, start.reservation_bytes(auth)),
            "capacitySourcePins": start._capacity_sources()[1]}}
    return {"schema": 1, "kind": "android-persisted-start-native-admission", "operationId": operation,
        "originalSourceSha256": digest, "originalColdbootOperationId": launch["correlationId"],
        "observations": [copy.deepcopy(row), copy.deepcopy(row)],
        "reservationAuthoritySha256": hashlib.sha256(start._canonical(auth)).hexdigest(),
        "installerGuardSha256": hashlib.sha256(UNIT_HOST_SOURCE).hexdigest(),
        "installerGuardSourcePins": host_guard(digest)["sourcePins"],
        "stopCause": "off_unknown", "startPerformed": False, "originalOutcomesChanged": False, "replayAllowed": False}


def allocation_control():
    """Inert qualification chain and bridge; no native provider is invoked."""
    boot = "25515f23-b966-4c3a-ae63-d38452375578"
    gib = 1024 ** 3
    claims = [{"reservationId": "env-owned-" + str(index), "environment": "windows-owned-" + str(index),
               "fixtureId": "owned-fixture-" + str(index), "host": "archlinux", "hostBootId": boot,
               "machine": "owned-" + str(index), "operator": "windows-vm-deploy", "provider": provider,
               "root": "/owned/windows-" + str(index), "configuredMemoryBytes": 6 * gib}
              for index, provider in enumerate(("raw-qemu-windows", "libvirt-windows"), 1)]
    auth = authority([{"id": claim["reservationId"], "hostAlias": "archlinux", "environment": claim["environment"],
                       "operator": claim["operator"], "allocationState": "running", "requestedMemoryBytes": 6 * gib}
                      for claim in claims] + [{"hostAlias": "archlinux", "requestedMemoryBytes": 30 * gib,
                                              "allocationState": "unknown", "id": "env-owned-preserved-unknown"}])
    pins = {"/owned/source.py": "9" * 64}
    getter = ("_COVERAGE_SOURCE_PINS=" + repr(pins) + "\n").encode()
    getter_sha = hashlib.sha256(getter).hexdigest()
    rows = [{"schemaVersion": 1, "state": "qualified", "reservationId": claim["reservationId"],
             "machine": claim["machine"], "provider": claim["provider"], "root": claim["root"], "hostBootId": boot,
             "pid": 100 + index, "startTicks": 200 + index, "sessionId": 100 + index, "uid": 1000,
             "commandSha256": str(index) * 64, "executableGeneration": [1, 2, 0o100755, 0, 0, 1, 8, 3, 4],
             "configuredMemoryBytes": 6 * gib, "controlConnection": "owned-control-" + str(index),
             "observedAtUnixMs": 1, "guestRpc": False, "vmMutation": False, "claimMutation": False}
            for index, claim in enumerate(claims, 1)]
    coverage = {"schemaVersion": 1, "state": "qualified", "hostBootId": boot, "rows": rows,
                "sourcePins": pins, "observedAtUnixMs": 1, "guestRpc": False, "vmMutation": False, "claimMutation": False}
    source = ("import base64,copy,hashlib,json,time\nGETTER_SOURCE=" + repr(getter) + "\nGETTER_SHA=" + repr(getter_sha)
          + "\nPYTHON_SHA=" + repr("8" * 64) + "\nEXPECTED_BOOT=" + repr(boot) + "\nBRIDGE_RECORDS=[]\nCONTROL=" + repr(coverage) + r'''
def get_windows_allocation_coverage():
 value=copy.deepcopy(CONTROL);value['observedAtUnixMs']=time.time_ns()//1000000
 for row in value['rows']:row['observedAtUnixMs']=value['observedAtUnixMs']
 output=json.dumps({'principal':[1000,1000,1000,1000,[1000]],'coverage':value},sort_keys=True,separators=(',',':')).encode()
 BRIDGE_RECORDS.append({'kind':'ordinary-windows-coverage-child','complete':True,'returncode':0,'sourceSha256':GETTER_SHA,'pythonSha256':PYTHON_SHA,'stdoutBase64':base64.b64encode(output).decode(),'stderrBase64':'','stdoutSha256':hashlib.sha256(output).hexdigest(),'stderrSha256':hashlib.sha256(b'').hexdigest(),'parentPrincipal':[0,0,0,0,[0]],'parentClosingPrincipal':[0,0,0,0,[0]],'childPrincipal':[1000,1000,1000,1000,[1000]],'observedAtNs':time.time_ns(),'vmMutation':False,'claimMutation':False})
 return value
''').encode()
    qual = {"state": "qualified", "sourceClosing": True, "guestRpc": False, "vmMutation": False,
            "claimMutation": False, "ledgerTokenPrinted": False, "publicChain": claims,
            "getterSha256": getter_sha, "getterBytes": len(getter), "sourcePins": pins,
            "localInputPins": {auth["records"][0]["path"]: {key: auth["records"][0]["pin"][key] for key in ("generation", "sha256")}}}
    source_sha = hashlib.sha256(source).hexdigest()
    proof = {"schema": 1, "kind": "native-source-closed-ordinary-windows-coverage-bridge-proof",
             "bridgeSha256": source_sha, "getterSha256": getter_sha, "pythonSha256": "8" * 64,
             "childPrincipal": [1000, 1000, 1000, 1000, [1000]], "parentPrincipal": [0, 0, 0, 0, [0]],
             "parentPrincipalUnchanged": True, "coverageFullRowsAndSourcesMatchOrdinaryProof": True,
             "ignoredOnlyObservationTimestamp": True, "sourceClosing": True,
             "completeChildStderrSha256": hashlib.sha256(b"").hexdigest(), "vmMutation": False, "claimMutation": False}
    qual_raw, proof_raw = start._canonical(qual), start._canonical(proof)
    cap = {"source": source, "sha256": source_sha, "sourcePins": pins,
           "qualificationRaw": qual_raw, "qualificationSha256": hashlib.sha256(qual_raw).hexdigest(),
           "bridgeProofRaw": proof_raw, "bridgeProofSha256": hashlib.sha256(proof_raw).hexdigest()}
    now = time.time_ns() // 1000000
    available = 418 * gib // 10
    probe = {"state": "observed", "physicalMemoryBytes": 61820 * 1024 ** 2, "swapUsedBytes": 0,
             "samples": [{"observedAtUnixMs": stamp, "availableMemoryBytes": available,
                         "psi": "normal", "psiSomeAvg10": 0.0, "psiFullAvg10": 0.0,
                         "vmstat": {"pswpin": 0, "pswpout": 0, "oomKill": 0}}
                        for stamp in (now - 10, now - 1)], "inventoryComplete": True,
             "vms": [{"pid": row["pid"], "startTicks": row["startTicks"],
                       "qemuExecutable": "qemu-system-x86_64", "configuredMemoryBytes": row["configuredMemoryBytes"]}
                      for row in rows]}
    return auth, cap, coverage, probe


def allocation_runtime(auth, cap, probe, *, before=False):
    selected = start
    if before:
        path = FIXTURES / "allocation-coverage.before.source"
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != "4c703f4b2bc654ec9e882789529a9913b73e00df702c7aedea0aa6c9d4bf4e62":
            raise ValueError("allocation-whole-beforeimage-changed")
        selected = types.ModuleType("allocation_before_source")
        # The three canonical policy files are unchanged consumed dependencies;
        # retain their real root while executing the exact whole beforeimage.
        selected.__file__ = str(Path(start.__file__).resolve())
        exec(compile(raw, str(path), "exec"), selected.__dict__)
    source, _ = selected._capacity_sources()
    runtime = {"json": json, "time": time, "re": __import__("re"), "sys": sys,
               "hashlib": hashlib, "PENDING_BYTES": start.reservation_bytes(auth),
               "MEMORY_BYTES": start.MEMORY_BYTES, "HEADROOM_BYTES": start.HEADROOM_BYTES}
    exec(compile(start._allocation_runtime(cap, auth, "25515f23-b966-4c3a-ae63-d38452375578") + source + selected._CAPACITY,
                 "actual-source-closed-allocation-capacity", "exec"), runtime)
    runtime["boot"] = lambda: "25515f23-b966-4c3a-ae63-d38452375578"
    runtime["NATIVE_RESOURCE_PROGRAM"] = "import json;print(json.dumps(" + repr(probe) + "))"
    return runtime


class AllocationCoverageTests(unittest.TestCase):
    def test_qualified_same_generation_capacity_keeps_every_held_claim(self):
        auth, cap, _, probe = allocation_control()
        runtime = allocation_runtime(auth, cap, probe, before=os.environ.get("VPN_CONTROL_PERSISTED_START_ALLOCATION_BEFORE") == "1")
        observed, plan = runtime["native_capacity"]()
        self.assertEqual(start.reservation_bytes(auth), 42 * 1024 ** 3)
        self.assertEqual(observed["measurement"]["runningConfiguredMemoryBytes"], 12 * 1024 ** 3)
        self.assertEqual(plan["runningConfiguredMemoryBytes"], 42 * 1024 ** 3)
        self.assertEqual(plan["requiredMemoryBytes"], 52 * 1024 ** 3)
        evidence = runtime["LAST_ALLOCATION_EVIDENCE"]
        self.assertEqual(evidence["coveredNativeBytes"], 12 * 1024 ** 3)
        self.assertEqual(len(evidence["bridgeRecords"]), 2)
        self.assertNotEqual(evidence["bridgeRecords"][0]["observedAtNs"], evidence["bridgeRecords"][1]["observedAtNs"])

    def test_unrepresented_native_allocation_is_charged_in_full(self):
        auth, cap, _, probe = allocation_control()
        probe["vms"].append({"pid": 999, "startTicks": 777, "qemuExecutable": "qemu-system-x86_64", "configuredMemoryBytes": 2 * 1024 ** 3})
        runtime = allocation_runtime(auth, cap, probe)
        _, plan = runtime["native_capacity"]()
        self.assertEqual(plan["runningConfiguredMemoryBytes"], 44 * 1024 ** 3)

    def test_wrong_claim_or_local_chain_never_mints_coverage(self):
        auth, cap, _, _ = allocation_control()
        for mode in ("claim_id", "environment", "operator", "pending", "bytes", "ledger_pin", "uid_proof", "bool_parent", "source_pin"):
            changed = copy.deepcopy(cap)
            qualification = json.loads(changed["qualificationRaw"])
            proof = json.loads(changed["bridgeProofRaw"])
            if mode == "claim_id": qualification["publicChain"][0]["reservationId"] = "env-foreign"
            if mode == "environment": qualification["publicChain"][0]["environment"] = "windows-foreign"
            if mode == "operator": qualification["publicChain"][0]["operator"] = "foreign"
            if mode == "bytes": qualification["publicChain"][0]["configuredMemoryBytes"] += 1
            if mode == "ledger_pin": next(iter(qualification["localInputPins"].values()))["generation"][1] += 1
            if mode == "uid_proof": proof["childPrincipal"][0] = 0
            if mode == "bool_parent": proof["parentPrincipal"][0] = False
            if mode == "source_pin": changed["sourcePins"]["/owned/source.py"] = "0" * 64
            changed["qualificationRaw"] = start._canonical(qualification); changed["qualificationSha256"] = hashlib.sha256(changed["qualificationRaw"]).hexdigest()
            changed["bridgeProofRaw"] = start._canonical(proof); changed["bridgeProofSha256"] = hashlib.sha256(changed["bridgeProofRaw"]).hexdigest()
            changed_auth = copy.deepcopy(auth)
            if mode == "pending":
                ledger = json.loads(base64.b64decode(changed_auth["records"][0]["rawBase64"]))
                ledger["reservations"][0]["allocationState"] = "pending"
                changed_auth = authority(ledger["reservations"])
                # Preserve the exact current ledger pin in qualification so this
                # negative reaches the running-allocation guard, not pin drift.
                qualification["localInputPins"][changed_auth["records"][0]["path"]] = {key: changed_auth["records"][0]["pin"][key] for key in ("generation", "sha256")}
                changed["qualificationRaw"] = start._canonical(qualification); changed["qualificationSha256"] = hashlib.sha256(changed["qualificationRaw"]).hexdigest()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                start._allocation_contract(changed, changed_auth, "25515f23-b966-4c3a-ae63-d38452375578")

    def test_changed_or_ambiguous_bracket_and_catalog_refuse(self):
        auth, cap, before, probe = allocation_control()
        contract = start._allocation_contract(cap, auth, before["hostBootId"])
        runtime = allocation_runtime(auth, cap, probe)
        observed, _ = runtime["native_capacity"]()
        for mode in ("birth", "bytes", "uid", "control", "duplicate", "extra", "unknown", "host", "source", "bool_pid", "catalog_birth", "catalog_bytes", "catalog_duplicate", "catalog_unknown"):
            first, second, native = copy.deepcopy(before), copy.deepcopy(before), copy.deepcopy(observed)
            if mode == "birth": second["rows"][0]["startTicks"] += 1
            if mode == "bytes": second["rows"][0]["configuredMemoryBytes"] += 1
            if mode == "uid": first["rows"][0]["uid"] = second["rows"][0]["uid"] = 0
            if mode == "control": second["rows"][0]["controlConnection"] = "different-original-channel"
            if mode == "duplicate": second["rows"][1] = copy.deepcopy(second["rows"][0])
            if mode == "extra": second["rows"].append(copy.deepcopy(second["rows"][0]))
            if mode == "unknown": second["state"] = "unknown"
            if mode == "host": second["hostBootId"] = "foreign"
            if mode == "source": second["sourcePins"]["/owned/source.py"] = "0" * 64
            if mode == "bool_pid": first["rows"][0]["pid"] = second["rows"][0]["pid"] = True
            if mode == "catalog_birth": native["vms"][0]["startTicks"] += 1
            if mode == "catalog_bytes": native["vms"][0]["configuredMemoryBytes"] += 1; native["measurement"]["runningConfiguredMemoryBytes"] += 1
            if mode == "catalog_duplicate": native["vms"].append(copy.deepcopy(native["vms"][0]))
            if mode == "catalog_unknown": native["measurementAvailability"] = "unknown"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                start._allocation_namespace()["allocation_overlap"](native, first, second, contract)
        second = copy.deepcopy(before); second["observedAtUnixMs"] += 9
        for row in second["rows"]: row["observedAtUnixMs"] += 8
        self.assertEqual(start._allocation_namespace()["allocation_overlap"](observed, before, second, contract), 12 * 1024 ** 3)

    def test_complete_bridge_streams_remain_required(self):
        auth, cap, _, probe = allocation_control()
        runtime = allocation_runtime(auth, cap, probe)
        runtime["native_capacity"]()
        evidence = runtime["LAST_ALLOCATION_EVIDENCE"]
        for mode in ("missing", "partial", "uid", "parent", "stream", "reply"):
            value = copy.deepcopy(evidence["bridgeRecords"])
            if mode == "missing": value.pop()
            if mode == "partial": value[0]["complete"] = False
            if mode == "uid": value[0]["childPrincipal"][0] = 0
            if mode == "parent": value[0]["parentClosingPrincipal"][0] = 1000
            if mode == "stream": value[0]["stdoutSha256"] = "0" * 64
            if mode == "reply":
                reply = json.loads(base64.b64decode(value[0]["stdoutBase64"])); reply["coverage"]["rows"][0]["pid"] += 1
                raw = start._canonical(reply); value[0]["stdoutBase64"] = base64.b64encode(raw).decode(); value[0]["stdoutSha256"] = hashlib.sha256(raw).hexdigest()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                start._allocation_namespace()["allocation_records"](value, evidence["before"], evidence["after"], evidence["contract"])

    def test_coverage_is_optional_and_conservative_without_a_capsule(self):
        auth, _, _, probe = allocation_control()
        source, _ = start._capacity_sources()
        namespace = {"json": json, "time": time, "re": __import__("re"), "PENDING_BYTES": start.reservation_bytes(auth), "MEMORY_BYTES": start.MEMORY_BYTES, "HEADROOM_BYTES": start.HEADROOM_BYTES}
        exec(compile(source + start._CAPACITY, "actual-default-conservative-runtime", "exec"), namespace)
        namespace["NATIVE_RESOURCE_PROGRAM"] = "import json;print(json.dumps(" + repr(probe) + "))"
        with self.assertRaisesRegex(ValueError, "persisted_start_native_capacity_refused"):
            namespace["native_capacity"]()

    def test_failed_probe_keeps_both_complete_bridge_streams(self):
        auth, cap, _, probe = allocation_control()
        runtime = allocation_runtime(auth, cap, probe)
        runtime["NATIVE_RESOURCE_PROGRAM"] = "raise SystemExit(65)"
        with self.assertRaisesRegex(ValueError, "persisted_start_native_capacity_probe_exit"):
            runtime["native_capacity"]()
        evidence = runtime["LAST_ALLOCATION_EVIDENCE"]
        self.assertEqual(evidence["state"], "unknown")
        self.assertEqual(len(evidence["bridgeRecords"]), 2)
        runtime = allocation_runtime(auth, cap, probe)
        original = runtime["_ALLOCATION_HOST"].get_windows_allocation_coverage
        def fail_after_recording():
            original()
            raise ValueError("owned-getter-refusal-after-private-capture")
        runtime["_ALLOCATION_HOST"].get_windows_allocation_coverage = fail_after_recording
        with self.assertRaisesRegex(ValueError, "owned-getter-refusal"):
            runtime["native_capacity"]()
        self.assertEqual(len(runtime["LAST_ALLOCATION_EVIDENCE"]["bridgeRecords"]), 1)

    @unittest.skipUnless(POSIX_FDS, "Actual remote Linux owner rendering uses POSIX journal paths")
    def test_real_renderer_seals_qualified_coverage_and_validates_receipts(self):
        raw, digest, launch = capsule()
        auth, cap, _, probe = allocation_control()
        operation = str(uuid.uuid4())
        value = admission(operation, digest, auth, launch)
        runtime = allocation_runtime(auth, cap, probe)
        native, plan = runtime["native_capacity"]()
        evidence = copy.deepcopy(runtime["LAST_ALLOCATION_EVIDENCE"])
        value["allocationCoverageContract"] = evidence["contract"]
        for row in value["observations"]:
            row["resources"].update(nativeObservation=native, canonicalPlan=plan,
                  availableMemoryBytes=native["measurement"]["availableMemoryBytes"], allocationCoverage=evidence)
        observed = start._canonical(value)
        sealed = start.start_plan(raw, digest, operation, auth, observed, hashlib.sha256(observed).hexdigest(),
                job_root="/owned/external-persisted-owner", host_binding={"target": "owned-fixture", "machine": "a" * 64,
                "boot": launch["observation"]["bootId"], "account": "0"}, root_generation=[1, 2],
                coldboot_source=PRODUCER.read_bytes(), durable_source=durable.owner_source(),
                installer_guard=host_guard(digest), allocation_coverage=cap)
        self.assertEqual(sealed["allocationCoverageContract"], evidence["contract"])
        self.assertEqual(sealed["launch"]["intent"]["allocationCoverageContract"], evidence["contract"])
        compile(sealed["program"], "owned-real-allocation-renderer", "exec")
        _, literals = start._source(raw, digest)
        for mode in ("join", "stream", "missing", "top_contract"):
            changed = copy.deepcopy(value)
            if mode == "join": changed["observations"][0]["resources"]["allocationCoverage"]["after"]["rows"][0]["startTicks"] += 1
            if mode == "stream": changed["observations"][0]["resources"]["allocationCoverage"]["bridgeRecords"][0]["stdoutSha256"] = "0" * 64
            if mode == "missing": changed["observations"][0]["resources"].pop("allocationCoverage")
            if mode == "top_contract": changed["allocationCoverageContract"]["bridgeSha256"] = "0" * 64
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                start.validate_admission(changed, operation, digest, auth, literals, allocation_coverage=cap)


class NativeAdvisoryHarnessTests(unittest.TestCase):
    def test_actual_advisory_call_uses_supported_route_timeout(self):
        """Execute the actual authenticated caller expression, with inert config.

        The complete retained harness stays inert: no original main/imports,
        SSH admission, secret read, native request or target-side programme.
        Only its exact builder call and literal bootstrap string are selected;
        load_config is the sole declared seam supplying the owned inert config.
        The real current builder performs validation and command quoting.
        """
        before = os.environ.get("VPN_CONTROL_PERSISTED_ADVISORY_BEFORE") == "1"
        name = "advisory-timeout.before.source" if before else "advisory-timeout.fixed.source"
        wanted = "f294f0abe6945d2cd6a37f92a27eddc7258044570164dd1ed7ff74f170b69238" if before else "316ecbfa63bdda696035b545e09777cff33ee67da0c03da8ab8befa19c835ad1"
        path = FIXTURES / name
        raw = path.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), wanted)
        tree = ast.parse(raw)
        main = next(node for node in tree.body if type(node) is ast.FunctionDef and node.name == "main")
        calls = [node for node in ast.walk(main) if type(node) is ast.Call
                 and type(node.func) is ast.Attribute and node.func.attr == "build_ssh_argv"]
        bootstrap = [node for node in ast.walk(main) if type(node) is ast.Assign
                     and any(type(target) is ast.Name and target.id == "bootstrap_source" for target in node.targets)]
        self.assertEqual((len(calls), len(bootstrap)), (1, 1))
        receiver = ast.literal_eval(bootstrap[0].value)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            config = ssh.SshConfig(root=root, hosts={"archlinux": ssh.SshHost("archlinux", "inert.invalid", 22,
                    "owned-fixture", root / "inert-key", root / "inert-known-hosts")})
            def load_owned_config(actual_root):
                self.assertEqual(actual_root, root)
                return config
            facade = types.SimpleNamespace(load_config=load_owned_config, build_ssh_argv=ssh.build_ssh_argv)
            expression = compile(ast.Expression(body=copy.deepcopy(calls[0])), str(path), "eval", dont_inherit=True)
            argv = eval(expression, {"t": facade, "ROOT": root, "bootstrap_source": receiver})
            self.assertIn("ConnectTimeout=45", argv)
            self.assertIn("source-held-readonly-android-advisory", argv[-1])
            self.assertEqual(list(root.iterdir()), [])


@unittest.skipUnless(POSIX_FDS, "Actual POSIX locks, descriptors or socket fixtures are required")
class AdmissionSamplingTests(unittest.TestCase):
    def run_owner(self, replies, *, before=False, drift=False, malformed_raw=False):
        """Whole actual owner boundary; only local context/transport are owned seams.

        A positive final candidate must pass the real current start_plan. The
        distinct start-authority barrier is never granted and every submit/GO
        request is forbidden. All generated native programme bytes stay inert.
        """
        filename = "controller-composition.source" if before else "controller-sampling.final.source"
        digest = "f71178076d5df505a19ad9775133665e54b3f0f656b19471659a54b8c271a4ac" if before else "b2cec75b415152f88c629a56aad01a9db601b54183fa0a786a3e6a4e1fa043c6"
        path = FIXTURES / filename; source = path.read_bytes()
        self.assertEqual(hashlib.sha256(source).hexdigest(), digest)
        blocked_raw = (FIXTURES / "admission-blocked.native.json").read_bytes()
        self.assertEqual(hashlib.sha256(blocked_raw).hexdigest(), "88c0c699d367a9bb62b87f6e2e0abdca0dabdee897cfb17820216fba760e4072")
        original, original_sha, launch = capsule()
        auth, coverage, _, probe = allocation_control()
        operation = str(uuid.uuid4())
        blocked = json.loads(blocked_raw)
        # Explicit unit context projection only. The authentic native raw blob
        # and its original UNKNOWN operation remain immutable fixture evidence.
        blocked["operationId"] = operation
        good = admission(operation, original_sha, auth, launch)
        runtime = allocation_runtime(auth, coverage, probe)
        native, capacity = runtime["native_capacity"]()
        evidence = copy.deepcopy(runtime["LAST_ALLOCATION_EVIDENCE"])
        good["allocationCoverageContract"] = evidence["contract"]
        for row in good["observations"]:
            row["resources"].update(nativeObservation=native, canonicalPlan=capacity,
                  availableMemoryBytes=native["measurement"]["availableMemoryBytes"], allocationCoverage=evidence)
        seal = {"configSha256": "a" * 64, "sourceManifestSha256": "b" * 64, "receiverSha256": "c" * 64}
        namespace = {"__name__": "owned_whole_controller_sampling", "__CONTROLLER_SEAL__": seal}
        exec(compile(source, str(path), "exec", dont_inherit=True), namespace)
        temporary = tempfile.TemporaryDirectory(prefix="vc-as-", dir="/tmp")
        self.addCleanup(temporary.cleanup)
        out = Path(temporary.name).resolve(); out.chmod(0o700)
        namespace["OUT"] = out
        (out / "remote_receiver.py").write_bytes(b"owned-inert-receiver-source\n")
        holder = types.SimpleNamespace(config={"operationId": operation, "localBinding": {
                    "target": "owned-local", "machine": "owned-machine", "boot": "owned-boot", "account": str(os.geteuid())},
                    "lockFiles": [], "coverageBridgeQualified": True, "originalSourceSha256": original_sha,
                    "remoteRoot": "/owned/external-persisted-start", "binding": {"target": "owned-native",
                    "machine": "a" * 64, "boot": launch["observation"]["bootId"], "account": "0"}},
                    programme={"controllerSha256": "d" * 64, "ownerProgramSha256": "e" * 64},
                    sent=False, labels=[], raws=[], admitted=0, validationAttempts=0,
                    validatedPlans=[], locked=False, lockAcquires=0, closed=False, replies=list(replies))
        def acquire(rows):
            holder.locked = True; holder.lockAcquires += 1
        holder.inputs = types.SimpleNamespace(acquire=acquire)
        holder.durable = types.SimpleNamespace(MachineBinding=durable.MachineBinding, _binding_live=lambda value: None)
        holder.review = lambda name, expected: None
        holder.authority = lambda: auth
        holder.original = lambda: original
        holder.capsule = lambda prefix: host_guard(original_sha) if prefix == "installer" else coverage
        inputs = {"coverageBridgeQualification": b"owned qualification", "durableSource": durable.owner_source(), "coldbootSource": PRODUCER.read_bytes()}
        holder.input = lambda name: inputs[name]
        def guard(*, preeffect):
            self.assertTrue(holder.locked)
            self.assertTrue(preeffect)
            if drift and holder.admitted:
                raise ValueError("owned_authority_drift")
            if (out / "expected-start-authority.json").exists():
                raise ValueError("owned_distinct_start_authority_not_granted")
        holder.guard = guard
        def close():
            holder.closed = True; holder.locked = False
        holder.close = close
        def transaction(label, payload, prepared=None, **options):
            holder.labels.append(label)
            self.assertTrue(holder.locked)
            if label == "prepare":
                value = {"state": "prepared-not-submitted", "preparation": {
                         "operationId": operation, "rootGeneration": [1, 2]}}
                return value, start._canonical(value), out
            self.assertEqual(label, "admit", "Source-only owner attempted submit/observe/GO")
            holder.admitted += 1
            self.assertTrue(holder.replies, "Owner exceeded explicit queued read-only observations")
            instruction = holder.replies.pop(0)
            directory = out / ("owned-capture-" + str(holder.admitted)); directory.mkdir(mode=0o700)
            if instruction == "partial":
                (directory / "stdout.raw").write_bytes(b"{")
                holder.raws.append(b"{")
                raise ValueError("owned_transport_partial")
            if instruction == "blocked":
                value = copy.deepcopy(blocked)
            elif instruction == "admitted":
                value = copy.deepcopy(good)
            elif instruction == "bad_admitted":
                value = copy.deepcopy(good); value["reservationAuthoritySha256"] = "0" * 64
            else:
                value = copy.deepcopy(blocked)
                value.update(instruction)
            raw = b"{" if malformed_raw else start._canonical(value)
            (directory / "stdout.raw").write_bytes(raw)
            holder.raws.append(raw)
            return value, raw, directory
        holder.transaction = transaction
        def validated_plan(*args, **kwargs):
            holder.validationAttempts += 1
            plan = start.start_plan(*args, **kwargs)
            holder.validatedPlans.append({"admissionRaw": args[4], "plan": copy.deepcopy(plan)})
            return plan
        holder.renderer = types.SimpleNamespace(observation_program=start.observation_program,
                 start_plan=validated_plan, _source=start._source, _launchers=start._launchers)
        namespace["Context"] = lambda: holder
        namespace["machine"] = lambda: "owned-machine"
        with self.assertRaises(SystemExit):
            namespace["owner_main"]()
        self.assertTrue(holder.closed)
        self.assertFalse(holder.locked)
        self.assertEqual(holder.lockAcquires, 1)
        self.assertEqual(holder.labels.count("prepare"), 1)
        self.assertNotIn("submit-once", holder.labels)
        self.assertFalse((out / "remote-submission.once.json").exists())
        self.assertFalse((out / "start-authority.json").exists())
        holder.output = out
        return holder

    def test_actual_one_shot_then_sampled_owner_reaches_real_final_validation(self):
        value = self.run_owner(["blocked", "admitted"],
                     before=os.environ.get("VPN_CONTROL_PERSISTED_SAMPLING_BEFORE") == "1")
        self.assertEqual(value.admitted, 2)
        self.assertEqual(len(value.validatedPlans), 1)
        self.assertEqual(value.validatedPlans[0]["admissionRaw"], value.raws[-1])
        self.assertTrue((value.output / "ready-for-review.json").exists())
        self.assertTrue((value.output / "admission-sampling-accepted.json").exists())
        retained = value.output / "owned-capture-1/stdout.raw"
        self.assertEqual(retained.read_bytes(), value.raws[0])
        self.assertEqual(json.loads(retained.read_bytes())["state"], "blocked")

    def test_five_unknown_replies_exhaust_without_plan_or_submit(self):
        value = self.run_owner(["blocked"] * 6)
        self.assertEqual(value.admitted, 5)
        self.assertEqual(value.validationAttempts, 0)
        self.assertEqual(len(list(value.output.glob("admission-sample-*.json"))), 5)
        self.assertFalse((value.output / "ready-for-review.json").exists())
        self.assertEqual(len(value.raws), 5)

    def test_fifth_fresh_admission_uses_only_last_fully_validated_receipt(self):
        value = self.run_owner(["blocked"] * 4 + ["admitted"])
        self.assertEqual(value.admitted, 5)
        self.assertEqual(len(value.validatedPlans), 1)
        self.assertEqual(value.validatedPlans[0]["admissionRaw"], value.raws[-1])
        for index, raw in enumerate(value.raws, 1):
            self.assertEqual((value.output / ("owned-capture-" + str(index)) / "stdout.raw").read_bytes(), raw)
        self.assertTrue((value.output / "admission-sampling-accepted.json").exists())

    def test_other_block_or_untyped_context_never_samples_again(self):
        for update in ({"reason": "persisted_start_native_capacity_refused"}, {"schema": True}, {"schema": 1.0},
                       {"kind": "foreign"}, {"operationId": str(uuid.uuid4())},
                       {"state": "unknown"}, {"startPerformed": True}, {"startPerformed": 0}, {"originalOutcomesChanged": True},
                       {"replayAllowed": True}, {"failureType": "TimeoutError"},
                       {"capacityReason": "foreign"}, {"allocationCoverageEvidence": []},
                       {"capacityObservation": []}, {"unexpected": True}):
            with self.subTest(update=update):
                value = self.run_owner([update, "admitted"])
                self.assertEqual(value.admitted, 1)
                self.assertEqual(value.validationAttempts, 0)

    def test_partial_drift_and_malformed_raw_stop_without_plan_or_submit(self):
        for args in ((["partial", "admitted"], {}), (["blocked", "admitted"], {"drift": True}),
                     (["blocked", "admitted"], {"malformed_raw": True})):
            with self.subTest(options=args[1]):
                value = self.run_owner(args[0], **args[1])
                self.assertEqual(value.admitted, 1)
                self.assertEqual(value.validationAttempts, 0)
                self.assertTrue((value.output / "owned-capture-1/stdout.raw").exists())

    def test_final_candidate_still_requires_actual_renderer_validation(self):
        value = self.run_owner(["blocked", "bad_admitted", "admitted"])
        self.assertEqual(value.admitted, 2)
        self.assertEqual(value.validationAttempts, 1)
        self.assertFalse(value.validatedPlans)
        self.assertFalse((value.output / "ready-for-review.json").exists())

    def transaction_with_typed_readiness_change(self, action, *, before=False):
        """Actual whole Context.transaction; genuine typed returned-result error."""
        name = "controller-sampling.fixed.source" if before else "controller-sampling.final.source"
        digest = "33477e449a4151f9543fb722dc1fb36b640ea14a28caf2054d6fa0f59608d699" if before else "b2cec75b415152f88c629a56aad01a9db601b54183fa0a786a3e6a4e1fa043c6"
        source = (FIXTURES / name).read_bytes(); self.assertEqual(hashlib.sha256(source).hexdigest(), digest)
        operation = str(uuid.uuid4())
        seal = {"configSha256": "a" * 64, "receiverPin": {}}
        namespace = {"__name__": "owned_transaction_readiness_boundary", "__CONTROLLER_SEAL__": seal}
        exec(compile(source, str(FIXTURES / name), "exec", dont_inherit=True), namespace)
        temporary = tempfile.TemporaryDirectory(prefix="vc-ar-", dir="/tmp"); self.addCleanup(temporary.cleanup)
        out = Path(temporary.name).resolve(); out.chmod(0o700); namespace["OUT"] = out
        value = {"state": "owned-original-result", "operationId": operation, "replayAllowed": False}
        raw = start._canonical(value)
        typed_error = ssh.SubmittedResultReadinessChanged(
            ssh._readiness.ReadinessBlocked("connection_generation_changed", operation),
            subprocess.CompletedProcess(["owned-no-executable"], 0, stdout=raw, stderr=b""))
        @contextmanager
        def admitted(*args, **kwargs):
            yield types.SimpleNamespace(revalidate=lambda: None)
        def run_ssh(*args, **kwargs):
            raise typed_error
        transport = types.SimpleNamespace(admitted_transport=admitted, load_config=lambda root: None,
                    build_ssh_argv=lambda *a, **k: ["owned-never-executed"], run_ssh=run_ssh,
                    SubmittedResultReadinessChanged=ssh.SubmittedResultReadinessChanged)
        class Credential:
            pin = tuple(range(9)); text = "PUBLIC-inert-credential-marker"
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def guard(self): pass
        context = namespace["Context"].__new__(namespace["Context"])
        context.recordings = 0; context.recording_bytes = 0; context.sent = False
        context.config = {"operationId": operation, "credentialPath": "/owned/not-read"}
        context.credential_descriptor = {"credential": {"generation": list(range(9))}}
        context.snapshot = types.SimpleNamespace(add=lambda *a, **k: b"owned-inert-receiver\n")
        context.transport = transport; context.readiness = ssh._readiness
        context.credentials = types.SimpleNamespace(SecretFile=lambda path: Credential())
        context.guard = lambda **kwargs: None; context.sync_sources = lambda: None
        context.session = types.SimpleNamespace(guard=lambda: None)
        payload = {"context": {"programSha256": "e" * 64}}
        result = None; error = None
        try:
            result = context.transaction(action, payload, {"rootGeneration": [1, 2]}, once=action == "submit-once")
        except ValueError as caught:
            error = caught
        captures = sorted(out.glob("capture-*/capture.json")); self.assertEqual(len(captures), 1)
        directory = captures[0].parent
        self.assertEqual((directory / "stdout.raw").read_bytes(), raw)
        self.assertEqual((directory / "stderr.raw").read_bytes(), b"")
        self.assertEqual(json.loads((directory / "result.json").read_bytes()), value)
        self.assertIsNone(typed_error._submitted_result, "Original result was not consumed exactly once")
        return result, error, json.loads(captures[0].read_bytes())

    def test_admit_typed_readiness_change_retains_original_but_refuses_retry_data(self):
        result, error, capture = self.transaction_with_typed_readiness_change("admit",
                     before=os.environ.get("VPN_CONTROL_PERSISTED_ADMIT_READINESS_BEFORE") == "1")
        self.assertIsNone(result)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(str(error), "controller_admit_transport_readiness_changed")
        self.assertTrue(capture["streamsComplete"])
        self.assertTrue(capture["transportReadinessChanged"])

    def test_other_typed_readiness_results_keep_original_collection_behavior(self):
        for action in ("submit-once", "observe", "recover-prepare"):
            with self.subTest(action=action):
                result, error, capture = self.transaction_with_typed_readiness_change(action)
                self.assertIsNone(error)
                self.assertEqual(result[0]["state"], "owned-original-result")
                self.assertTrue(capture["streamsComplete"])
                self.assertTrue(capture["transportReadinessChanged"])


@unittest.skipUnless(POSIX_FDS, "Actual POSIX locks, descriptors or socket fixtures are required")
class PrivilegedCompositionTests(unittest.TestCase):
    def setup_call(self, *, before=False):
        name = "composition-setup.before.source" if before else "composition-setup.fixed.source"
        digest = "be791c61ab945026307de0855340902bcb2ad2f873b8be87ab06ad50850a098c" if before else "54bb2624170dc101ed645918bae863d3047d2193fc81ad9dfc001a585b031183"
        path = FIXTURES / name
        raw = path.read_bytes(); self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        calls = [node for node in ast.walk(ast.parse(raw)) if type(node) is ast.Call
                 and type(node.func) is ast.Attribute and node.func.attr == "TemporaryDirectory"]
        self.assertEqual(len(calls), 1)
        return compile(ast.Expression(copy.deepcopy(calls[0])), str(path), "eval", dont_inherit=True)

    def test_actual_owned_fixture_setup_avoids_unix_socket_path_overflow(self):
        """Actual failed/fixed setup call and real kernel bind; no SSH endpoint."""
        from agent_tools.tests.test_ssh_privileged_program import SocketGuest
        before = os.environ.get("VPN_CONTROL_PERSISTED_COMPOSITION_SETUP_BEFORE") == "1"
        with tempfile.TemporaryDirectory(prefix="vc-ps-", dir="/tmp") as owner:
            parent = Path(owner).resolve() / ("P" * 80)
            parent.mkdir(mode=0o700)
            with mock.patch.object(tempfile, "tempdir", str(parent)):
                temporary = eval(self.setup_call(before=before), {"tempfile": tempfile})
            peer = SocketGuest.__new__(SocketGuest)
            try:
                root = Path(temporary.name).resolve(); root.chmod(0o700)
                # The original verbose default-temp call raises the same real
                # AF_UNIX path error. Only the actual fixed call escapes the
                # deliberately long owned TMPDIR through its explicit /tmp.
                peer.__init__(root)
                self.assertLess(len(os.fsencode(peer.socket)), 104)
                self.assertTrue(peer.socket.exists())
            finally:
                if hasattr(peer, "stop"):
                    peer.close()
                elif hasattr(peer, "listener"):
                    peer.listener.close()
                temporary.cleanup()

    def test_actual_final_caller_keeps_header_body_through_privileged_modes(self):
        """Mandatory current wrapper delivers bytes before whole receiver main.

        The final caller expression is exact authenticated f711 source. Only
        the SSH executable and native target-root/observation business seams use
        existing owned fixture projections. No direct-to-receiver password path
        is substituted for the mandatory PlannedArgv/root-loader composition.
        """
        from agent_tools.tests.test_ssh_privileged_program import SocketGuest
        caller_path = FIXTURES / "controller-composition.source"
        receiver_path = FIXTURES / "receiver-composition.source"
        caller, template = caller_path.read_bytes(), receiver_path.read_bytes()
        self.assertEqual(hashlib.sha256(caller).hexdigest(), "f71178076d5df505a19ad9775133665e54b3f0f656b19471659a54b8c271a4ac")
        self.assertEqual(hashlib.sha256(template).hexdigest(), "3d291375895a9e84bf31516fbe43aa5476a90ef8f605b8e70b9ce8381823cafb")
        owner = next(node for node in ast.parse(caller).body if type(node) is ast.ClassDef and node.name == "Context")
        method = next(node for node in owner.body if type(node) is ast.FunctionDef and node.name == "transaction")
        calls = [node for node in ast.walk(method) if type(node) is ast.Call
                 and type(node.func) is ast.Attribute and node.func.attr == "build_ssh_argv"]
        self.assertEqual(len(calls), 1)
        expression = compile(ast.Expression(copy.deepcopy(calls[0])), str(caller_path), "eval", dont_inherit=True)
        operation = str(uuid.uuid4()); config_sha = "c" * 64
        config = {"operationId": operation, "root": "/var/tmp/vc-android-persisted-" + operation,
                  "controllerConfigSha256": config_sha, "durableSha256": "d" * 64,
                  "binding": {"target": "owned-fixture", "machine": "a" * 64,
                              "boot": "11111111-1111-1111-1111-111111111111", "account": "0"}}
        receiver = template.replace(b"__REMOTE_CONFIG__", repr(config).encode())
        body = start._canonical({"ownedFixture": True})
        header = {"schema": 1, "action": "observe", "operationId": operation,
                  "controllerConfigSha256": config_sha, "receiverSha256": hashlib.sha256(receiver).hexdigest(),
                  "payloadSha256": hashlib.sha256(body).hexdigest(), "rootGeneration": [1, 2]}
        payload = start._canonical(header) + body
        projected = ("import base64,hashlib,json,sys,types\nreceiver=" + repr(receiver) + "\n"
            "m=types.ModuleType('owned_whole_receiver');m.__name__='owned_whole_receiver'\n"
            "exec(compile(receiver,'exact-whole-final-receiver','exec'),m.__dict__)\n"
            "class Recorder:\n"
            " def __init__(self,stream):self.stream=stream;self.raw=bytearray()\n"
            " def readline(self,n):raw=self.stream.readline(n);self.raw.extend(raw);return raw\n"
            " def read(self,n):raw=self.stream.read(n);self.raw.extend(raw);return raw\n"
            "record=Recorder(sys.stdin.buffer)\n"
            "m.sys=types.SimpleNamespace(stdin=types.SimpleNamespace(buffer=record))\n"
            "m.open_root=lambda **kw:None\n"
            "m.original_observation=lambda:{'state':'owned-fixture-observed','receivedBase64':base64.b64encode(bytes(record.raw)).decode(),'receivedSha256':hashlib.sha256(record.raw).hexdigest()}\n"
            "m.main()\n").encode()
        temporary = eval(self.setup_call(), {"tempfile": tempfile})
        root = Path(temporary.name).resolve(); root.chmod(0o700)
        peer = SocketGuest(root)
        try:
            peer.base.hosts = {"archlinux": peer.base.hosts["explicit-peer"]}; peer.base.write_config()
            shutil.copyfile(peer.base.binary, root / "ssh"); (root / "ssh").chmod(0o700)
            with peer.environment():
                exact = eval(expression, {"t": ssh, "ROOT": root, "receiver": receiver})
                self.assertIsInstance(exact, automatic.PlannedArgv)
                self.assertTrue(automatic.password_carrier(exact.command))
                self.assertEqual(exact.command[-1], 'exec(compile(' + repr(receiver) + ',"sealed-native-receiver","exec"))')
                exact.close()
                for mode in ("consumed", "cached", "echo"):
                    with self.subTest(mode=mode):
                        peer.mode.write_text(mode)
                        argv = eval(expression, {"t": ssh, "ROOT": root, "receiver": projected})
                        self.assertIsInstance(argv, automatic.PlannedArgv)
                        self.assertTrue(automatic.password_carrier(argv.command))
                        secret = b"PRIVATE-fixture-password-42"
                        result = ssh.run_ssh(argv, input=secret + b"\n" + payload, capture_output=True, timeout=15)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertNotIn(secret, result.stdout + result.stderr)
                        value = json.loads(result.stdout.replace(b"[REDACTED]\n", b""))
                        self.assertEqual(base64.b64decode(value["receivedBase64"], validate=True), payload)
                        self.assertEqual(value["receivedSha256"], hashlib.sha256(payload).hexdigest())
                        self.assertEqual(value["state"], "owned-fixture-observed")
                        self.assertFalse(peer.failures)
                        for path in (root / ".rag_index").rglob("*"):
                            if path.is_file(): self.assertNotIn(secret, path.read_bytes())
                self.assertTrue(all(row["commandBytes"] <= 60000 for row in peer.events))
        finally:
            peer.close(); temporary.cleanup()


class PersistedStartTests(unittest.TestCase):
    def sdk_runtime(self, root, *, optional_present=False):
        """Actual emitted readers over real files; declared OS-only seams.

        Linux/root and controlled-file UID1000 metadata are projected on this
        coordinator. Unowned ancestor timestamps/size/link counts are frozen;
        their inode/mode identity and every owned fixture field remain real.
        Empty owned /proc, machine identity and admitted capacity are isolated
        fixtures. SDK bytes, absence, full reads and all assembly execute
        unchanged. No VM, password, arbitrary source or native claim.
        """
        selected = start
        mode = os.environ.get("VPN_CONTROL_PERSISTED_START_BEFORE")
        if mode in ("1", "native"):
            selected = types.ModuleType("persisted_start_before_fixture")
            before_name = "native-observer.before.source" if mode == "native" else "adapter.before.source"
            before_path = FIXTURES / before_name
            before_raw = before_path.read_bytes()
            self.assertEqual(hashlib.sha256(before_raw).hexdigest(),
                "8a2d81e09f1c22d1668aa300618a398651e4f74fa40c21b4895d8ef1ec3a4da1" if mode == "native" else
                "a7056498c100b5d3fe831fbd4d45aa962fcead5a6d11fd912b7a62fbcf9817e4")
            selected.__file__ = str(before_path)
            exec(compile(before_raw, selected.__file__, "exec"), selected.__dict__)
        for folder in ("fixture.avd", "sdk", "shared", "proc/sys/kernel/random", "proc/net"):
            (root / folder).mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in ("fixture.avd/config.ini", "fixture.avd/userdata-qemu.img", "owned-inert-avd.ini",
                     "shared/android-avd-coldboot-api35.lock", "shared/android-native-device-api35.lock"):
            (root / name).write_bytes(b"owned-inert-file\n"); (root / name).chmod(0o600)
        for name in ("emulator", "qemu", "adb"):
            (root / "sdk" / name).write_bytes(b"owned-inert-executable\n"); (root / "sdk" / name).chmod(0o700)
        optional = root / "sdk/userdata.img"
        if optional_present: optional.write_bytes(b"optional-image"); optional.chmod(0o600)
        raw, _, launch = capsule()
        launch["argv"][0] = str(root / "sdk/emulator")
        launch["qemuPath"] = str(root / "sdk/qemu"); launch["adbPath"] = str(root / "sdk/adb")
        chosen = launch["observation"]["avds"]["api35"]
        chosen["directory"]["path"] = str(root / "fixture.avd")
        sdk_paths = [str(root / "sdk" / name) for name in ("emulator", "qemu", "adb", "userdata.img")]
        chosen["sdkFiles"] = {name: {} for name in sdk_paths}
        (root / "proc/sys/kernel/random/boot_id").write_text(launch["observation"]["bootId"])
        (root / "proc/meminfo").write_text("MemAvailable: 67108864 kB\n")
        for name in ("tcp", "tcp6"): (root / "proc/net" / name).write_text("owned-empty-proc-port-table\n")
        real_os = os
        outside = {}
        for ancestor in root.parents:
            info = ancestor.lstat()
            outside[(info.st_dev, info.st_ino)] = {name: getattr(info, name) for name in
                ("st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")}
        def projected(info):
            values = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
            values.update(outside.get((info.st_dev, info.st_ino), {}))
            values.update(st_uid=1000, st_gid=1000)
            return types.SimpleNamespace(**values)
        proxy = types.SimpleNamespace(**vars(os))
        for name in ("getuid", "geteuid", "getgid", "getegid"): setattr(proxy, name, lambda: 0)
        proxy.fstat = lambda fd: projected(real_os.fstat(fd))
        proxy.stat = lambda *args, **kwargs: projected(real_os.stat(*args, **kwargs))
        def render():
            tree = ast.parse(raw)
            getter = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == "GETTER"))
            source = ("ROOT=pathlib.Path(" + repr(str(root / "shared")) + ")\nCFG=" + repr({"source": launch["intent"]["source"]})
                + "\nLAUNCH=" + repr(launch) + "\nGETTER=" + repr(getter) + "\n"
                + (FIXTURES / "original-readers.source").read_text()).encode()
            generated = selected.observation_program(source, hashlib.sha256(source).hexdigest(), str(uuid.uuid4()), authority())
            syntax = ast.parse(generated)
            # Execute the complete assembled namespace before its final entry.
            nodes = [node for node in syntax.body if isinstance(node, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef, ast.ClassDef))]
            namespace = {"__name__": "owned_emitted_sdk_control"}
            exec(compile(ast.Module(body=nodes, type_ignores=[]), "emitted-sdk-control", "exec"), namespace)
            namespace.update(os=proxy, sys=types.SimpleNamespace(platform="linux"), PROC=root / "proc", MIN_DISK_BYTES=0)
            namespace["machine"] = lambda: hashlib.sha256(b"owned-native-machine-control").hexdigest()
            measurement = admission(str(uuid.uuid4()), "a" * 64, authority(), launch)["observations"][0]["resources"]["nativeObservation"]["measurement"]
            namespace["native_capacity"] = lambda: ({"measurement": measurement}, start.capacity_plan(measurement, 0))
            return namespace
        namespace = render()
        chosen["sdkFiles"] = {name: namespace["facts"](Path(name), 16777216, name.endswith("/package.xml")) for name in sdk_paths}
        return render(), optional, chosen

    @unittest.skipUnless(POSIX_FDS, "Actual POSIX emitted-reader descriptors are required")
    def test_original_absent_sdk_template_is_preserved_by_actual_emitted_observer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            runtime, absent, _ = self.sdk_runtime(root)
            result = runtime["measured"]()
            self.assertEqual(result["sdkFiles"][str(absent)], {"present": False})

    @unittest.skipUnless(POSIX_FDS, "Actual POSIX emitted-reader descriptors are required")
    def test_newly_absent_sdk_file_still_blocks_actual_emitted_observer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            runtime, optional, _ = self.sdk_runtime(root, optional_present=True)
            optional.unlink()
            with self.assertRaisesRegex(ValueError, "persisted_start_sdk_changed"):
                runtime["measured"]()

    @unittest.skipUnless(POSIX_FDS, "Actual POSIX emitted-reader descriptors are required")
    def test_supervisor_preflight_reopens_names_after_inherited_fds_close(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            runtime, _, _ = self.sdk_runtime(root, optional_present=True)
            baseline = runtime["measured"]()
            owner = 54321; birth = 77; actor = 54322
            (root / "proc" / str(owner)).mkdir()
            tail = ["S"] + ["0"] * 18 + [str(birth)]
            (root / "proc" / str(owner) / "stat").write_text(str(owner) + " (owned-parent) " + " ".join(tail))
            path = root / "shared/android-native-device-api35.lock"
            chain, leaf = runtime["parent_fds"](path)
            fd = os.open(path, os.O_RDONLY); os.close(fd)
            selected = start._START
            if os.environ.get("VPN_CONTROL_PERSISTED_START_BEFORE") == "1":
                tree = ast.parse((FIXTURES / "adapter.before.source").read_bytes())
                selected = ast.literal_eval(next(node.value for node in tree.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "_START" for target in node.targets)))
            runtime.update(ADMISSION={"observations": [baseline, baseline]}, HELD_LOCKS=[("device", fd, chain, leaf)],
                           LOCK_OWNER_PID=owner, LOCK_OWNER_BIRTH=birth)
            runtime["os"].getpid = lambda: actor
            runtime["os"].getppid = lambda: owner
            runtime["os"].getsid = lambda pid: actor
            exec(compile(selected, "actual-supervisor-preflight-closure", "exec"), runtime)
            try:
                result = runtime["selected_preflight"]()
                self.assertEqual(result["pendingReservationBytes"], baseline["resources"]["pendingReservationBytes"])
                self.assertGreaterEqual(result["freeDiskBytes"], result["minDiskBytes"])
                (root / "proc" / str(owner) / "stat").write_text(str(owner) + " (foreign-parent) " + " ".join(tail[:-1] + [str(birth + 1)]))
                with self.assertRaisesRegex(ValueError, "persisted_start_supervisor_parent_changed"):
                    runtime["selected_preflight"]()
            finally:
                runtime["close_parents"](chain)

    def test_canonical_capacity_retains_claims_and_avoids_available_double_count(self):
        now = time.time_ns() // 1000000
        available = 418 * 1024 ** 3 // 10
        measurement = {"platform": "linux", "physicalMemoryBytes": 64 * 1024 ** 3,
            "availableMemoryBytes": available, "runningConfiguredMemoryBytes": 0,
            "swapUsedBytes": 0, "pressure": "normal", "samples": [
                {"observedAtUnixMs": stamp, "availableMemoryBytes": available, "psi": "normal",
                 "vmstat": {"pswpin": 0, "pswpout": 0, "oomKill": 0}} for stamp in (now - 10, now - 1)]}
        held = 42 * 1024 ** 3
        if os.environ.get("VPN_CONTROL_PERSISTED_START_BEFORE") == "1":
            before = ast.parse((FIXTURES / "adapter.before.source").read_bytes())
            expression = ast.literal_eval(next(node.value for node in before.body if isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "_OBSERVE" for target in node.targets)))
            measured = next(node for node in ast.parse(expression).body if isinstance(node, ast.FunctionDef) and node.name == "measured")
            guard = next(node for node in measured.body if isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                         and isinstance(node.test.left, ast.Name) and node.test.left.id == "available")
            namespace = {"available": available, "PENDING_BYTES": held,
                         "MEMORY_BYTES": start.MEMORY_BYTES, "HEADROOM_BYTES": start.HEADROOM_BYTES}
            exec(compile(ast.Module(body=[guard], type_ignores=[]), "authentic-before-capacity-decision", "exec"), namespace)
            return
        result = start.capacity_plan(measurement, held)
        self.assertEqual(result["runningConfiguredMemoryBytes"], held)
        self.assertEqual(result["requiredMemoryBytes"], held + start.MEMORY_BYTES + start.HEADROOM_BYTES)
        self.assertEqual(result["observedAvailableMemoryBytes"], available)

    def test_canonical_capacity_refuses_unknown_pressure_and_swap_out(self):
        _, digest, launch = capsule(); auth = authority()
        measurement = admission(str(uuid.uuid4()), digest, auth, launch)["observations"][0]["resources"]["nativeObservation"]["measurement"]
        for mode in ("low_available", "physical_total", "psi", "swap_out"):
            value = copy.deepcopy(measurement)
            if mode == "low_available":
                for sample in value["samples"]: sample["availableMemoryBytes"] = 1
                value["availableMemoryBytes"] = 1
            if mode == "physical_total": value["physicalMemoryBytes"] = 1
            if mode == "psi": value["samples"][0]["psi"] = "warning"
            if mode == "swap_out": value["samples"][1]["vmstat"]["pswpout"] = 1
            with self.subTest(mode=mode), self.assertRaises(ValueError): start.capacity_plan(value, 0)

    def test_native_probe_clean_unknown_exit_is_retained_and_blocks(self):
        source, _ = start._capacity_sources()
        namespace = {"json": json, "time": time, "re": __import__("re"), "PENDING_BYTES": 0,
                     "MEMORY_BYTES": start.MEMORY_BYTES, "HEADROOM_BYTES": start.HEADROOM_BYTES}
        exec(compile(source + start._CAPACITY, "actual-capacity-runtime", "exec"), namespace)
        namespace["NATIVE_RESOURCE_PROGRAM"] = "import json;print(json.dumps({'state':'unknown'}));raise SystemExit(0)"
        with self.assertRaisesRegex(ValueError, "persisted_start_native_capacity_visibility"):
            namespace["native_capacity"]()
        self.assertEqual(namespace["LAST_CAPACITY_OBSERVATION"]["state"], "UNKNOWN")

    def test_all_matching_claims_are_counted_without_guessing_retirement(self):
        auth = authority([{"hostAlias": "archlinux", "requestedMemoryBytes": 2, "allocationState": "unknown"},
            {"hostAlias": "archlinux", "requestedMemoryBytes": 3, "allocationState": "inactive"},
            {"hostAlias": "other", "requestedMemoryBytes": 100}])
        second = copy.deepcopy(auth["records"][0]); second["path"] = str(LOCAL_AUTHORITY_ROOT.parent / "other-coordinator/reservations.json")
        auth["records"].append(second)
        self.assertEqual(start.reservation_bytes(auth), 10)

    def test_tampered_reservation_bytes_refuse(self):
        auth = authority(); auth["records"][0]["rawBase64"] = base64.b64encode(b"{}").decode()
        with self.assertRaisesRegex(ValueError, "persisted_start_reservation_record_changed"):
            start.reservation_bytes(auth)

    def test_unknown_or_incomplete_visibility_never_produces_start_plan(self):
        raw, digest, launch = capsule(); operation = str(uuid.uuid4()); auth = authority()
        _, literals = start._source(raw, digest)
        for field, replacement in [("holderCensus", {"complete": False, "holders": [], "unreadableProcessCount": 1}),
                                   ("targetActors", [{"pid": 123}]), ("targetPorts", [{"port": 5682}])]:
            value = admission(operation, digest, auth, launch)
            for row in value["observations"]: row[field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "persisted_start_positive_visibility_required"):
                start.validate_admission(value, operation, digest, auth, literals)

    def test_native_capacity_refusal_is_preserved(self):
        raw, digest, launch = capsule(); operation = str(uuid.uuid4()); auth = authority()
        _, literals = start._source(raw, digest); value = admission(operation, digest, auth, launch)
        value["observations"][0]["resources"]["availableMemoryBytes"] = 1
        with self.assertRaisesRegex(ValueError, "persisted_start_native_capacity_required"):
            start.validate_admission(value, operation, digest, auth, literals)

    def test_native_original_actor_absence_is_not_inferred_from_new_uuid(self):
        raw, digest, launch = capsule(); operation = str(uuid.uuid4()); auth = authority()
        _, literals = start._source(raw, digest); value = admission(operation, digest, auth, launch)
        for row in value["observations"]: row["originalAbsence"][0]["currentStartTicks"] = 1
        with self.assertRaisesRegex(ValueError, "persisted_start_original_absence_required"):
            start.validate_admission(value, operation, digest, auth, literals)

    def test_same_path_does_not_qualify_different_avd_configuration(self):
        raw, digest, launch = capsule(); operation = str(uuid.uuid4()); auth = authority()
        _, literals = start._source(raw, digest); value = admission(operation, digest, auth, launch)
        for row in value["observations"]:
            row["avd"]["config"] = dict(row["avd"]["config"], sha256="c" * 64)
        with self.assertRaisesRegex(ValueError, "persisted_start_original_config_bytes_changed"):
            start.validate_admission(value, operation, digest, auth, literals)

    @unittest.skipUnless(POSIX_FDS, "Actual remote Linux owner rendering uses POSIX journal paths")
    def test_plan_preserves_exact_argv_originals_and_external_journal(self):
        raw, digest, launch = capsule(); operation = str(uuid.uuid4()); auth = authority()
        observation = start._canonical(admission(operation, digest, auth, launch))
        plan = start.start_plan(raw, digest, operation, auth, observation, hashlib.sha256(observation).hexdigest(),
            job_root="/var/tmp/owned-start", host_binding={"target": "owned-target", "machine": "a" * 64,
                "boot": launch["observation"]["bootId"], "account": "0"}, root_generation=[1, 2],
            coldboot_source=PRODUCER.read_bytes(), durable_source=durable.owner_source(), installer_guard=host_guard(digest))
        self.assertEqual(plan["launch"]["argv"], launch["argv"])
        self.assertEqual(plan["launch"]["environment"], launch["environment"])
        self.assertEqual(launch["correlationId"], "e3e97a65-b14a-4c32-8954-a441ac28ec47")
        self.assertEqual(plan["launch"]["intent"]["originalColdbootOperationId"], launch["correlationId"])
        self.assertEqual(plan["journalDirectory"], "/var/tmp/owned-start/" + operation + "/coldboot")
        self.assertFalse(plan["submitted"])
        self.assertFalse(plan["originalOutcomesChanged"])
        status = start.status_program(raw, digest, plan, PRODUCER.read_bytes())
        compile(status, "fixed-original-status", "exec")

    def test_missing_installer_capsule_cannot_create_a_start_plan(self):
        raw, digest, launch = capsule(); operation = str(uuid.uuid4()); auth = authority()
        observation = start._canonical(admission(operation, digest, auth, launch))
        with self.assertRaisesRegex(ValueError, "persisted_start_installer_host_guard_required"):
            start.start_plan(raw, digest, operation, auth, observation, hashlib.sha256(observation).hexdigest(),
                job_root="/var/tmp/owned-start", host_binding={"target": "owned-target", "machine": "a" * 64,
                    "boot": launch["observation"]["bootId"], "account": "0"}, root_generation=[1, 2],
                coldboot_source=PRODUCER.read_bytes(), durable_source=durable.owner_source())

    @unittest.skipUnless(POSIX_FDS, "Actual POSIX emitted-reader descriptors are required")
    def test_start_runtime_refuses_unqualified_installer_before_avd_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            runtime, _, _ = self.sdk_runtime(root)
            runtime["REQUIRE_INSTALLER_HOST_GUARD"] = True
            def forbidden_avd_read(path): raise AssertionError("target disk read before installer host qualification")
            runtime["tree_facts"] = forbidden_avd_read
            with self.assertRaisesRegex(ValueError, "persisted_start_installer_host_guard_required"):
                runtime["measured"]()

    @unittest.skipUnless(POSIX_FDS, "Actual POSIX emitted-reader descriptors are required")
    def test_observer_executes_complete_namespace_and_refuses_coordinator(self):
        if sys.platform.startswith("linux") and os.geteuid() == 0:
            self.skipTest("This guard control targets a non-root or non-Linux coordinator")
        raw, digest, _ = capsule()
        source = start.observation_program(raw, digest, str(uuid.uuid4()), authority())
        result = subprocess.run([sys.executable, "-I", "-B", "-c", source], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value["reason"], "persisted_start_linux_root_required")
        self.assertIs(value["startPerformed"], False)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Actual Linux PR_SET_CHILD_SUBREAPER is required")
    def test_unchanged_supervisor_waits_for_forked_launcher_descendant(self):
        legacy = start._launchers(PRODUCER.read_bytes(), PRODUCER_SHA)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); root.chmod(0o700)
            source = "import os,ctypes,pathlib,json,time,signal\nROOT=pathlib.Path(" + repr(str(root)) + ")\n"
            source += "LAUNCH={'correlationId':'owned-unit','intentSha256':'fixed'}\nCFG={'source':{}}\n"
            source += legacy["close_supervisor_inherited"] + "\n" + legacy["child_exec"] + r'''
def child_identity(pid):return {'pid':pid,'startTicks':int(pathlib.Path('/proc/'+str(pid)+'/stat').read_text().rsplit(')',1)[1].split()[19])}
def selected_preflight():return {'fixture':'inert-VM-exec-adapter'}
def qemu_fact():return {'fixture':'inert-executable'}
def journal_read(directory,name):return {'qemuFact':qemu_fact()}
def journal_write(directory,name,value):
 fd=os.open(directory/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w')as f:json.dump(value,f);f.flush();os.fsync(f.fileno())
def emulator_exec(go,executable,log):
 if os.read(go,1)!=b'G':os._exit(125)
 os.close(go)
 descendant=os.fork()
 if descendant==0:
  time.sleep(.3);(ROOT/'descendant-complete').write_text('one-original-descendant');os._exit(0)
 os._exit(0)
read_go,write_go=os.pipe();executable=os.open('/dev/null',os.O_RDONLY);log=os.open(ROOT/'private.log',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
pid=os.fork()
if pid==0:
 os.close(write_go);child_exec(read_go,executable,log,ROOT);os._exit(126)
os.close(read_go);os.write(write_go,b'G');os.close(write_go);os.close(executable);os.close(log)
end=time.monotonic()+5;result=None
while time.monotonic()<end:
 observed,status=os.waitpid(pid,os.WNOHANG)
 if observed:result=status;break
 time.sleep(.01)
if result is None:
 if os.getsid(pid)==pid:os.killpg(pid,signal.SIGTERM)
 os.waitpid(pid,0);raise RuntimeError('owned-supervisor-timeout')
assert os.waitstatus_to_exitcode(result)==0,result
assert(ROOT/'descendant-complete').read_text()=='one-original-descendant'
print(json.dumps({'supervisorReaped':True,'oneDescendant':True}))
'''
            result = subprocess.run([sys.executable, "-I", "-B", "-c", source], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {"supervisorReaped": True, "oneDescendant": True})


if __name__ == "__main__":
    unittest.main()
