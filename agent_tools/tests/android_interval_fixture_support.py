"""Finite owned fixtures and truthful whole-beforeimage helper materialization."""
import ast,atexit,base64,copy,hashlib,json,os,sys,tempfile,time,types,uuid
from pathlib import Path
from agent_tools import android_persisted_start as start
ROOT=Path(__file__).resolve().parents[2]
RESOURCES=Path(__file__).parent/'fixtures/android_persisted_interval_reports'
FIXTURES=Path(__file__).parent/'fixtures/android_persisted_start'
PRODUCER=Path(__file__).parent/'fixtures/android_existing_readonly/coldboot_producer.source'
PRODUCER_SHA='7d90c06070ffad1439e613c9ad5d63f979d43b738944f0630b2b15187f09fec6'
READERS_SHA='106193c91deb9ba1b54c6cb1dee6b3821e47165f61c317ae6d8e553536d20b8c'
UNIT_HOST_SOURCE=b"def installer_host_preflight():return {'state':'admitted','stableBinding':{'owned-inert-installer-precondition':True},'evidence':{'unitOnly':True}}\n"
def load_path(path,name,expected=None):
 raw=Path(path).read_bytes()
 if expected is not None and hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('owned_beforeimage_sha_changed')
 module=types.ModuleType(name);module.__file__=str(Path(path));sys.modules[name]=module
 exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
 return module
def before_helper(resource,expected):
 raw=(RESOURCES/resource).read_bytes()
 if hashlib.sha256(raw).hexdigest()!=expected:raise ValueError('owned_beforeimage_sha_changed')
 owned=tempfile.TemporaryDirectory(prefix='vc-before-')
 root=Path(owned.name).resolve();(root/'agent_tools').mkdir();(root/'scripts').mkdir()
 for relative in ('agent_tools/vm_workflow.py','agent_tools/native_host_observation.py','scripts/fixture_environment.py'):
  body=(ROOT/relative).read_bytes();target=root/relative;target.write_bytes(body)
  if target.read_bytes()!=body or (ROOT/relative).read_bytes()!=body:raise ValueError('owned_policy_copy_changed')
 path=root/'agent_tools/android_persisted_start.py';path.write_bytes(raw)
 module=load_path(path,'owned_whole_before_'+uuid.uuid4().hex,expected)
 module._owned_fixture_root=owned;atexit.register(owned.cleanup)
 return module
def host_guard(original_sha):
    return {"source": UNIT_HOST_SOURCE, "sha256": hashlib.sha256(UNIT_HOST_SOURCE).hexdigest(),
            "originalSourceSha256": original_sha, "sourcePins": {"owned-inert-test-capsule": original_sha}}

def authority(rows=None):
    raw = start._canonical({"version": 1, "reservations": rows or []})
    return {"hostAlias": "archlinux", "capturedAtNs": 1, "records": [{
        "path": str(ROOT/'owned-fixture-reservations.json'), "pin": {"generation": [1, 2, 0o100600, 503, 20, 1, len(raw), 3, 4],
          "parents": {"/": [1, 2, 0o40755, 0, 0]}, "sha256": hashlib.sha256(raw).hexdigest()},
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
