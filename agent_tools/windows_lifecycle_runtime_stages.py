"""Concrete finite runtime/fixture/Find Best stages inside retained Windows Owner.

No import-time effects. Actual package, source, material, ordinary context and
native artifact references are required; nulls refuse before mutation. Sources and
TLS material are immutable pins; generated files stay under the one operation.
"""
from __future__ import annotations
import ctypes
import hashlib
import json
import ntpath
import os
from pathlib import Path
import subprocess
import time
import uuid


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


class OwnedData:
    """Original native custody for generated immutable fixture inputs/parents."""
    def __init__(self, owner, path, expected=None, directory=False):
        self.owner, self.path, self.expected, self.directory = owner, path, expected, directory
        self.handle = None
        if not hasattr(owner, "fixture_data_leases"):
            owner.fixture_data_leases = []
        owner.fixture_data_leases.append(self)
        self.handle = owner.native.k.CreateFileW(str(path), 0x20080 if directory else 0x80020000,
            3 if directory else 1, None, 3, 0x02200000, None)
        require(self.handle != ctypes.c_void_p(-1).value, "owned-data-native-open")
        self.identity = owner.native.identity(self.handle, directory)
        self.security = owner.native.security(self.handle)
        require(self.security["ownerSid"] == owner.request["context"]["ordinarySid"], "owned-data-native-owner")
        self.current()

    def current(self):
        require(self.handle is not None, "owned-data-native-closed")
        native = self.owner.native
        require(native.identity(self.handle, self.directory) == self.identity
                and native.security(self.handle) == self.security, "owned-data-original-generation")
        if not self.directory:
            digest, total = hashlib.sha256(), 0
            for block in native.read_blocks(self.handle):
                total += len(block)
                require(total <= 32768, "owned-data-read-bound")
                digest.update(block)
            require(total == self.identity["sizeBytes"] and digest.hexdigest() == self.expected,
                    "owned-data-original-content")
        named = native.k.CreateFileW(str(self.path), 0x20080, 3, None, 3, 0x02200000, None)
        require(named != ctypes.c_void_p(-1).value, "owned-data-named-open")
        try:
            require(native.identity(named, self.directory) == self.identity
                    and native.security(named) == self.security, "owned-data-named-generation")
        finally:
            require(bool(native.k.CloseHandle(named)), "owned-data-named-close")

    def close(self):
        self.current()
        require(bool(self.owner.native.k.CloseHandle(self.handle)), "owned-data-original-close")
        self.handle = None


def data_guard(owner):
    owner.guard()
    for lease in getattr(owner, "fixture_data_leases", []):
        if lease.handle is not None:
            lease.current()


def publish(owner, path, value):
    """Windows rename cannot replace an existing destination. No retry on error."""
    require(os.name == "nt" and path.parent in {owner.root, owner.root / "fixture"}
            and not path.exists(), "owned-create-only-data-publication")
    data_guard(owner)
    temporary = path.parent / ("publish-" + uuid.uuid4().hex + ".tmp")
    data = value if type(value) is bytes else wire(value)
    require(len(data) <= 32768, "owned-data-publication-bound")
    with temporary.open("xb", buffering=0) as output:
        offset = 0
        while offset < len(data):
            count = output.write(data[offset:])
            require(count is not None and count > 0, "owned-data-publication-write")
            offset += count
        os.fsync(output.fileno())
    owner.event("owned-data-publication-intent", {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
                 "sizeBytes": len(data), "replayAllowed": False})
    os.rename(temporary, path)
    require(path.read_bytes() == data, "owned-data-publication-closing")
    OwnedData(owner, path, hashlib.sha256(data).hexdigest())
    data_guard(owner)
    return path


def result(owner, workspace, identity, *arguments, final=True, codes=("OK",), exits=(0,)):
    data_guard(owner)
    value = owner.invoke(workspace, "--json", "--controller-id", identity, *arguments)
    require(value.returncode in exits and value.stderr == "", "runtime-public-cli-exit-stderr")
    body = json.loads(value.stdout)
    require(type(body) is dict and body.get("schemaVersion") == 1 and body.get("controllerId") == identity
            and body.get("final") is final and body.get("code") in codes
            and body.get("ok") is (value.returncode == 0), "runtime-public-cli-envelope")
    data_guard(owner)
    return body


def validate_inputs(owner, inputs):
    fields = {"schemaVersion", "workspace", "fixtureRoot", "operationId", "fixtureWorkerPath",
        "socksSourcePath", "httpsSourcePath", "certificatePath", "privateKeyPath", "trustStorePath",
        "runtimeImagePath", "runtimeSha256", "installedAdmissionArtifactId", "materialAdmissionArtifactId",
        "ordinaryContextArtifactId", "fixtureBody", "maxFixtureSeconds"}
    require(type(inputs) is dict and set(inputs) == fields and inputs["schemaVersion"] == 1
            and all(inputs[name] is not None for name in fields), "runtime-native-inputs-pending")
    require(inputs["workspace"] == owner.request["workspace"] and Path(inputs["workspace"]).parent == owner.root
            and Path(inputs["fixtureRoot"]) == owner.root / "fixture"
            and str(uuid.UUID(inputs["operationId"])) == inputs["operationId"], "runtime-owned-operation-scope")
    require(type(inputs["maxFixtureSeconds"]) is int and 360 <= inputs["maxFixtureSeconds"] <= 1800
            and type(inputs["fixtureBody"]) is str and 0 < len(inputs["fixtureBody"].encode()) <= 4096,
            "runtime-finite-fixture-policy")
    for name in ("fixtureWorkerPath", "socksSourcePath", "httpsSourcePath", "certificatePath", "privateKeyPath", "trustStorePath"):
        require(str(Path(inputs[name])).casefold() in owner.by_path, "runtime-held-source-material-role")
    require(len(inputs["runtimeSha256"]) == 64 and Path(inputs["runtimeImagePath"]) == Path(inputs["workspace"]) / "runtime" / "tools" / "sing-box.exe",
            "runtime-image-role-under-owned-workspace")
    return inputs


def scoped_trust_options(path):
    require(type(path) is str and path and not any(char in path for char in '\r\n\x00"'), "scoped-jvm-trust-path")
    return '"-Djavax.net.ssl.trustStore=' + path + '" -Djavax.net.ssl.trustStorePassword=changeit'


def read_ready(owner, child, path, operation):
    until = time.monotonic() + 30
    while not path.exists():
        require(child.process.poll() is None, "original-runtime-fixture-ended-before-ready")
        if time.monotonic() >= until:
            owner.park("runtime-fixture-readiness-unknown-no-replay")
        time.sleep(0.1)
    raw = path.read_bytes()
    require(len(raw) <= 16384 and child.process.poll() is None, "runtime-fixture-ready-bound")
    ready = json.loads(raw)
    require(ready["operationId"] == operation and ready["httpsHost"] == "localhost"
            and ready["advertisedSocksHost"] == "127.0.0.1"
            and all(type(ready[key]) is int and 1 <= ready[key] <= 65535
                    for key in ("httpsPort", "advertisedSocksPort")), "actual-runtime-fixture-endpoints")
    OwnedData(owner, path, hashlib.sha256(raw).hexdigest())
    data_guard(owner)
    owner.event("runtime-fixture-ready-observed", {"child": child.ordinal, "pid": child.pid,
        "birthFileTimeUtc": child.birth, "ready": ready, "readySha256": hashlib.sha256(raw).hexdigest()})
    return ready


def start_runtime(owner, inputs, observer):
    """Create one fixture, fresh persistent serve, two local profiles, proxy A ON."""
    validate_inputs(owner, inputs)
    workspace, fixture_root = Path(inputs["workspace"]), Path(inputs["fixtureRoot"])
    require(not workspace.exists() and not fixture_root.exists()
            and not any(child.label == "serve" for child in owner.children), "fresh-runtime-owned-workspace")
    fixture_root.mkdir()
    OwnedData(owner, fixture_root, directory=True)
    config = {"schemaVersion": 1, **{name: inputs[name] for name in
        ("socksSourcePath", "httpsSourcePath", "certificatePath", "privateKeyPath", "operationId")},
        "readyFile": str(fixture_root / "ready.json"), "ledgerFile": str(fixture_root / "ledger.jsonl"),
        "controlFile": str(fixture_root / "stop.json"), "maxServeSeconds": inputs["maxFixtureSeconds"],
        "token": inputs["fixtureBody"]}
    config_path = publish(owner, owner.root / "runtime-fixture-input.json", config)
    fixture = owner.child("owned-runtime-fixture", [owner.request["pythonRuntime"]["interpreterPath"],
        "-I", "-B", inputs["fixtureWorkerPath"], "--input", str(config_path)])
    ready = read_ready(owner, fixture, Path(config["readyFile"]), inputs["operationId"])
    require("JAVA_TOOL_OPTIONS" not in owner.environment, "clean-retained-owner-environment")
    owner.environment["JAVA_TOOL_OPTIONS"] = scoped_trust_options(inputs["trustStorePath"])
    try:
        serve = owner.child("serve", [owner.request["cliPath"], "--state-dir", str(workspace), "serve"])
    finally:
        owner.environment.pop("JAVA_TOOL_OPTIONS", None)
    identity, until = None, time.monotonic() + 30
    while identity is None:
        require(serve.process.poll() is None, "original-serve-ended-during-readiness")
        value = owner.invoke(workspace, "--json", "status")
        body = json.loads(value.stdout)
        if value.returncode == 0:
            require(value.stderr == "" and body["code"] == "OK" and body["final"] is True
                    and body["data"]["runtimeRunning"] is False, "fresh-runtime-owner-readiness")
            identity = body["controllerId"]
        else:
            require(value.returncode == 2 and body["code"] == "UNAVAILABLE", "runtime-readiness-read-failure")
            if time.monotonic() >= until:
                owner.park("runtime-owner-readiness-unknown-no-replay")
            time.sleep(0.1)
    def guarded(*tail):
        before = result(owner, workspace, identity, "status")
        return result(owner, workspace, identity, "--if-revision", str(before["configurationRevision"]), *tail)
    # A fresh workspace reads its locations from a subscription, where adding one is READ_ONLY_SOURCE.
    guarded("source", "set", "current-locations")
    require(result(owner, workspace, identity, "locations", "list")["data"]["locations"] == [], "empty-runtime-location-population")
    for name in ("Owned A", "Owned B"):
        link = f"socks5://127.0.0.1:{ready['advertisedSocksPort']}#{name.replace(' ', '%20')}\n".encode()
        path = publish(owner, owner.root / (name.replace(" ", "-") + ".txt"), link)
        guarded("locations", "add", "--input", str(path))
    guarded("locations", "select", "Owned A")
    guarded("routing", "set", "ignore-rules", "true")
    for key, value in (("mode", "proxy-only"), ("validation.test-url", ready["trafficUrl"]),
                       ("validation.retry-count", "0"), ("validation.batch-size", "1"),
                       ("validation.active-verification-window-size", "1")):
        guarded("settings", "set", key, value)
    result(owner, workspace, identity, "on")
    status = result(owner, workspace, identity, "status")
    require(status["data"]["runtimeRunning"] is True and status["data"]["activeMode"] == "proxy-only",
            "actual-runtime-on-result")
    native = observer.WindowsNative()
    actors = capture_proxy_actors(owner, serve, native, inputs["runtimeImagePath"], inputs["runtimeSha256"])
    state = {"workspace": workspace, "identity": identity, "inputs": inputs, "fixture": fixture,
        "ready": ready, "serve": serve, "modeOrdinal": 0, "actors": actors, "openingStatus": status,
        "runtimeArtifact": {key: inputs[key] for key in ("installedAdmissionArtifactId", "runtimeImagePath", "runtimeSha256")}}
    if not hasattr(owner, "runtime_fixture_states"):
        owner.runtime_fixture_states = []
    owner.runtime_fixture_states.append(state)
    owner.event("actual-proxy-fixture-started", {"controllerId": identity, "status": status,
        "actors": actors, "fixtureReady": ready, "fixtureChild": fixture.ordinal,
        "tlsTrustScope": "original-persistent-owner-only", "acceptanceComplete": False})
    return state


def capture_proxy_actors(owner, serve, native, runtime_path, runtime_sha):
    """The serve launcher, the JVM that owns the runtime, and that one exact runtime.

    A jpackage launcher whose PATH lacks its app folder starts itself again and waits for
    that second process of the same image, which runs the JVM and so starts the runtime.
    A launcher that did not relaunch is its own JVM.
    """
    require(serve in owner.children and serve.label == "serve" and serve.process.poll() is None,
            "original-runtime-serve-handle")
    context = owner.request["context"]
    def describe(pid):
        with native.open_process(pid, 0x101000) as process:
            value = process.describe()
            require(process.wait() == 258 and value["token"]["sid"] == context["ordinarySid"]
                    and value["token"]["sessionId"] == context["ordinarySessionId"]
                    and value["token"]["elevated"] == 0, "ordinary-runtime-actor-token")
            return value
    parent = {"pid": serve.pid, **describe(serve.pid)}
    require(parent["creationFileTime"] == int(serve.birth), "original-runtime-serve-generation")
    table = native.processes()
    def children(actor):
        # A parent PID outlives its process: only a child born after this actor is its child.
        found = [{"pid": entry["pid"], **describe(entry["pid"])} for entry in table if entry["parentPid"] == actor["pid"]]
        return [row for row in found if row["creationFileTime"] >= actor["creationFileTime"]]
    launched = children(parent)
    relaunched = [row for row in launched if ntpath.normcase(row["image"]) == ntpath.normcase(parent["image"])
                  and row["sha256"] == parent["sha256"]]
    require(len(relaunched) <= 1, "one-relaunched-owner-jvm")
    jvm = relaunched[0] if relaunched else parent
    owned = children(jvm) if relaunched else launched
    candidates = [row for row in owned if ntpath.normcase(row["image"]) == ntpath.normcase(runtime_path)
                  and row["sha256"] == runtime_sha]
    auxiliary = [row for row in launched + (owned if relaunched else []) if row is not jvm and row not in candidates]
    require(len(candidates) == 1, "one-exact-owned-proxy-runtime")
    project = lambda value: {"pid": value["pid"], "creationFileTime": value["creationFileTime"],
        "image": value["image"], "sha256": value["sha256"], "sid": value["token"]["sid"],
        "sessionId": value["token"]["sessionId"]}
    return {"owner": project(parent), "jvm": project(jvm), "runtime": project(candidates[0]),
            "auxiliary": auxiliary}


def fixture_mode(owner, state, mode):
    require(mode in {"ok", "reject", "slow"} and state["fixture"].process.poll() is None
            and state["modeOrdinal"] < 8, "finite-owned-fixture-mode")
    ordinal = state["modeOrdinal"] + 1
    path = Path(state["inputs"]["fixtureRoot"]) / f"mode-{ordinal:04d}.json"
    publish(owner, path, {"operationId": state["inputs"]["operationId"], "ordinal": ordinal, "mode": mode})
    state["modeOrdinal"] = ordinal
    owner.event("owned-fixture-mode-published", {"ordinal": ordinal, "mode": mode,
        "operationId": state["inputs"]["operationId"], "replayAllowed": False})


def finish_operation(owner, state, accepted, expected_codes, seconds=120):
    identity, workspace = state["identity"], state["workspace"]
    operation = accepted["operationId"]
    require(type(operation) is str and accepted["controllerId"] == identity
            and accepted["code"] == "ACCEPTED" and accepted["final"] is False, "original-accepted-operation")
    until = time.monotonic() + seconds
    samples = []
    while True:
        listed = result(owner, workspace, identity, "operations", "list")
        original = [row for row in listed["data"]["operations"] if row["id"] == operation]
        require(len(original) == 1 and original[0]["controllerId"] == identity
                and original[0]["requestId"] == accepted["requestId"], "original-operation-ledger-join")
        value = owner.invoke(workspace, "--json", "--controller-id", identity,
                             "operations", "status", operation)
        body = json.loads(value.stdout)
        # InspectResult intentionally uses the NEW inspection request ID. The
        # retained ledger row above joins the original submitted request.
        require(value.stderr == "" and body["schemaVersion"] == 1
                and body["controllerId"] == identity and body["operationId"] == operation
                and type(body["requestId"]) is str and str(uuid.UUID(body["requestId"])) == body["requestId"],
                "original-operation-status-join")
        samples.append({"code": body["code"], "final": body["final"], "exitCode": value.returncode,
                        "inspectionRequestId": body["requestId"], "originalRequestId": accepted["requestId"]})
        if body["final"] is True:
            expected_exit = {"OK": 0, "RUNTIME_FAILED": 1, "CANCELLED": 130, "PERMISSION_DENIED": 1}
            require(body["code"] in expected_codes and body["code"] in expected_exit
                    and value.returncode == expected_exit[body["code"]]
                    and body["ok"] is (value.returncode == 0), "original-operation-unexpected-terminal")
            owner.event("original-operation-finished", {"accepted": accepted, "terminal": body,
                "samples": samples, "replayAllowed": False})
            return body
        require(body["code"] == "ACCEPTED" and value.returncode == 0, "original-operation-pending-result")
        if time.monotonic() >= until:
            owner.park("original-find-best-pending-no-replay")
        time.sleep(0.2)


def wait_https_work(owner, state, requested_at):
    path = Path(state["inputs"]["fixtureRoot"]) / "ledger.jsonl"
    deadline = time.monotonic() + 30
    while True:
        data_guard(owner)
        require(state["fixture"].process.poll() is None, "original-fixture-ended-before-https-work")
        with path.open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "owned-https-work-ledger-bound")
        # Only complete rows are observations; a worker may still be writing.
        rows = [json.loads(line) for line in raw.split(b"\n")[:-1]]
        matching = [row for row in rows if row["timestamp"] >= requested_at and row["path"] == "/traffic"
                    and row["modeOrdinal"] == state["modeOrdinal"] and row["mode"] == "slow"
                    and row["userAgent"] == "VPNControlDesktop/1.0"]
        if matching:
            owner.event("actual-delayed-https-work-observed", {"row": matching[0],
                "ledgerSha256AtObservation": hashlib.sha256(raw).hexdigest()})
            return matching[0]
        if time.monotonic() >= deadline:
            owner.park("original-find-best-real-https-work-not-observed-no-cancel-replay")
        time.sleep(.05)


def find_best(owner, state, variant):
    require(variant in {"success", "verification-failure", "cancel"}, "finite-find-best-variant")
    before = result(owner, state["workspace"], state["identity"], "status")
    require(before["data"]["runtimeRunning"] is True, "find-best-active-a-required")
    fixture_mode(owner, state, "reject" if variant == "verification-failure" else "slow" if variant == "cancel" else "ok")
    requested_at = time.time()
    accepted = result(owner, state["workspace"], state["identity"], "--async", "find-best",
                      final=False, codes=("ACCEPTED",))
    owner.event("find-best-original-accepted", {"variant": variant, "accepted": accepted,
                                              "before": before, "replayAllowed": False})
    if variant == "cancel":
        # Wait for this mode generation's actual delayed HTTPS GET, so this
        # tests cancellation during real owner work rather than before start.
        wait_https_work(owner, state, requested_at)
        result(owner, state["workspace"], state["identity"], "operations", "cancel", accepted["operationId"])
    terminal = finish_operation(owner, state, accepted,
        {"RUNTIME_FAILED"} if variant == "verification-failure" else {"CANCELLED"} if variant == "cancel" else {"OK"})
    after = result(owner, state["workspace"], state["identity"], "status")
    require(after["data"]["runtimeRunning"] is True and after["data"]["activeMode"] == before["data"]["activeMode"],
            "find-best-stranded-original-connection")
    if variant == "success":
        require(after["data"]["activeLocationId"] == after["data"]["selectedLocationId"]
                and after["restartRequired"] is False, "find-best-not-verified-and-committed")
    else:
        require(after["data"]["activeLocationId"] == before["data"]["activeLocationId"],
                "find-best-failure-or-cancel-lost-active-a")
    fixture_mode(owner, state, "ok")
    owner.event("find-best-observed", {"variant": variant, "before": before, "terminal": terminal,
        "after": after, "rollbackAfterPrivilegedCommitProven": False})
    return {"before": before, "accepted": accepted, "terminal": terminal, "after": after}


def stop_fixture(owner, state):
    status = result(owner, state["workspace"], state["identity"], "status")
    require(status["data"]["runtimeRunning"] is False, "explicit-product-off-before-fixture-stop")
    path = Path(state["inputs"]["fixtureRoot"]) / "stop.json"
    publish(owner, path, {"schemaVersion": 1, "operationId": state["inputs"]["operationId"], "action": "stop-owned-fixture"})
    terminal = state["fixture"].wait()
    require(terminal["exitCode"] == 0 and all(terminal["eof"].values()), "original-owned-fixture-terminal")
    owner.event("owned-runtime-fixture-closed", {"terminal": terminal, "productOwnerStillOwned": True,
        "serveGuiEndpointCleanupStillRequired": True})
    data_guard(owner)
    for lease in reversed(owner.fixture_data_leases):
        if lease.handle is not None:
            lease.close()
    return terminal


def scheduled_setup_and_observe(owner,state,inputs,cases,observer,original_gui_child):
    """Configure a real five-minute no-GUI refresh, then use the read-only collector."""
    fields={'schemaVersion','collectorPath','curlPath','fixtureAdmissionArtifactId'}
    require(type(inputs) is dict and set(inputs)==fields and inputs['schemaVersion']==1
            and all(value is not None for value in inputs.values()), 'scheduled-setup-native-inputs-pending')
    require(all(str(Path(inputs[key])).casefold() in owner.by_path for key in ('collectorPath','curlPath')),
            'scheduled-setup-held-programs')
    require(all(child.terminal is not None and all(child.terminal['eof'].values())
                for child in owner.children if child.label=='lifecycle-gui'), 'scheduled-setup-original-gui-still-live')
    workspace,identity=state['workspace'],state['identity']
    before=result(owner,workspace,identity,'status')
    require(before['data']['runtimeRunning'] is True and before['data']['activeMode']=='proxy-only'
            and state['fixture'].process.poll() is None, 'scheduled-active-original-proxy-fixture')
    def guarded(*tail):
        status=result(owner,workspace,identity,'status')
        return result(owner,workspace,identity,'--if-revision',str(status['configurationRevision']),*tail)
    guarded('settings','set','refresh.policy','off')
    require(result(owner,workspace,identity,'subscriptions','list')['data']['subscriptions']==[],
            'scheduled-owned-empty-subscription-population')
    added=guarded('subscriptions','add','--source',state['ready']['source'],'--name','Owned scheduled')
    rows=result(owner,workspace,identity,'subscriptions','list')['data']['subscriptions']
    require(len(rows)==1 and type(rows[0]['id']) is str,'scheduled-one-actual-subscription')
    subscription=rows[0]['id']
    guarded('source','set','subscription',subscription)
    guarded('subscriptions','refresh',subscription)
    require(len(result(owner,workspace,identity,'locations','list')['data']['locations'])==1,
            'scheduled-owned-source-readback')
    guarded('locations','select','1')
    guarded('settings','set','refresh.find-best-after-refresh','false')
    guarded('settings','set','refresh.custom-hours','0.08333333333333333')
    guarded('settings','set','refresh.policy','custom')
    armed=result(owner,workspace,identity,'status')
    require(all(armed['data'][key]==before['data'][key] for key in
        ('runtimeRunning','runtimeId','runtimeStartedAt','activeLocationId','activeMode')),
        'scheduled-arming-mutated-original-runtime')
    import argparse
    arguments=argparse.Namespace(launcher=owner.request['cliPath'],state_dir=str(workspace),
        curl=inputs['curlPath'],ready_file=str(Path(state['inputs']['fixtureRoot'])/'ready.json'),
        ledger=str(Path(state['inputs']['fixtureRoot'])/'ledger.jsonl'),ca_file=state['inputs']['certificatePath'],
        evidence_dir=str(owner.root/'scheduled-observation'),command_timeout=30,curl_timeout=3,
        max_duration=660,poll_interval=1)
    collector=owner.module(inputs['collectorPath'],'_owned_windows_scheduled_collector')
    owner.event('scheduled-owned-five-minute-armed',{'subscriptionId':subscription,'armed':armed,
        'fixtureSource':state['ready']['source'],'configuredHours':'0.08333333333333333',
        'guiChild':original_gui_child.ordinal,'noGuiAcceptedWindowStillRequired':True})
    observed=cases.scheduled_refresh(owner,workspace,identity,arguments,collector,
        inputs['fixtureAdmissionArtifactId'],original_gui_child,observer)
    data_guard(owner)
    guarded('settings','set','refresh.policy','off')
    return observed
