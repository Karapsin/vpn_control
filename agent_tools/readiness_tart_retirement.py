"""Append-only retirement of fully collected legacy Tart guest owners.

This never resolves UNKNOWN. A collected owner may leave the active projection
only after the same machine booted again and its exact old root is absent.
"""
import base64
import hashlib
import json
import re
import time
from pathlib import Path
from uuid import UUID

from . import durable_remote_job as jobs
from . import readiness_fixture_registry as registry
from . import ssh_program_execution_remote as protocol


def _need(value):
    if not value:
        raise registry.FixtureRegistryError("tart_guest_retirement_invalid")


def _json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            _need(key not in result)
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    _need(type(value) is dict)
    return value


def _collected(admission, collection, result):
    """Authenticate actual original terminal and complete retained bytes."""
    packet = admission["packet"]
    program = protocol.validate(admission["program"])
    _need(hashlib.sha256(protocol._canonical(program)).hexdigest() == packet["requestSha256"])
    payload = "import sys\nsys.argv=" + repr(["-c", *program["args"]]) + "\n" + protocol.command(program)[4]
    digest = jobs.Program("generated-python-program", payload.encode(), jobs.MAX_STREAM_BYTES).digest
    _need(set(collection) == {"exitCode", "stdout", "stderr"}
          and type(collection["exitCode"]) is int and collection["exitCode"] == 0
          and collection["stderr"] == "" and type(collection["stdout"]) is str)
    reply = _json(collection["stdout"])
    _need(set(reply) == {"schemaVersion", "operationId", "status", "stdout", "stderr"}
          and type(reply["schemaVersion"]) is int and reply["schemaVersion"] == 1
          and reply["operationId"] == packet["operationId"])
    status = reply["status"]
    _need(type(status) is dict and set(status) == {"binding", "operationId", "owner", "reason", "replayAllowed", "schemaVersion", "state", "terminal"}
          and status["binding"] == packet["binding"] and status["operationId"] == packet["operationId"]
          and type(status["schemaVersion"]) is int and status["schemaVersion"] == 1
          and status["reason"] == "correlated_terminal" and status["replayAllowed"] is False and status["state"] == "terminal")
    terminal = status["terminal"]
    _need(type(terminal) is dict and set(terminal) == {"binding", "exitCode", "generation", "operationId", "owner", "programSha256", "stderr", "stdout", "streamsClosed"}
          and terminal["binding"] == packet["binding"] and terminal["operationId"] == packet["operationId"]
          and terminal["programSha256"] == digest and type(terminal["exitCode"]) is int
          and terminal["streamsClosed"] is True and type(terminal["generation"]) is str
          and str(UUID(terminal["generation"])) == terminal["generation"])
    owner = terminal["owner"]
    _need(type(owner) is dict and set(owner) == {"pid", "birth"} and type(owner["pid"]) is int and owner["pid"] > 0
          and type(owner["birth"]) is str and re.fullmatch(r"linux:[1-9][0-9]*", owner["birth"]) is not None
          and owner == status["owner"])
    output = {}
    for name in ("stdout", "stderr"):
        meta = terminal[name]
        _need(type(reply[name]) is str)
        raw = base64.b64decode(reply[name], validate=True)
        _need(type(meta) is dict and set(meta) == {"overflow", "retainedBytes", "sha256", "totalBytes"}
              and meta["overflow"] is False and type(meta["retainedBytes"]) is int and type(meta["totalBytes"]) is int
              and len(raw) == meta["retainedBytes"] == meta["totalBytes"] <= jobs.MAX_STREAM_BYTES
              and meta["sha256"] == hashlib.sha256(raw).hexdigest())
        output[name] = raw
    _need(result.get("operationId") == packet["operationId"] and result.get("provider") == "tart-linux"
          and result.get("terminal") == status and type(result.get("sentinelOutput")) is str
          and result["sentinelOutput"].encode() == output["stdout"])
    return {"terminal": terminal, "stdoutSha256": hashlib.sha256(output["stdout"]).hexdigest(),
            "stderrSha256": hashlib.sha256(output["stderr"]).hexdigest()}


def _evidence(custody, record_path, record):
    admission_path = registry._under(record["admissionPath"], custody.root / ".runtime")
    admission, admission_pin = registry._json(admission_path)
    original_record, record_pin = registry._json(record_path)
    _need(original_record == record and set(admission) == {"operationId", "provider", "packet", "program", "counterPath"}
          and admission_pin == record["admissionPin"] and admission.get("packet") == record["packet"]
          and admission.get("provider") == "tart-linux" and admission.get("operationId") == record["packet"]["operationId"])
    program = protocol.validate(admission["program"])
    _need(program["targetContext"]["uid"] == custody.binding.expected_uid
          and program["targetContext"]["principal"] == custody.binding.expected_account
          and program["targetContext"]["bootId"] == record["packet"]["binding"]["boot"])
    pins = {str(record_path): record_pin, str(admission_path): admission_pin}
    values = []
    for name in ("original-reconciliation.json", "result.json"):
        path = admission_path.parent / name
        value, pin = registry._json(path)
        values.append(value); pins[str(path)] = pin
    summary = _collected(admission, *values)
    return pins, summary


def is_retired(custody, record_path, record):
    """Pure projection; changing original evidence invalidates retirement."""
    path = custody.lifecycle_root / "guest-program-retirements" / (record["packet"]["operationId"] + ".json")
    if not path.exists():
        _need(not path.is_symlink())
        return False
    proof, _ = registry._json(path)
    pins, summary = _evidence(custody, record_path, record)
    _need(set(proof) == {"schemaVersion", "packet", "pins", "collection", "absence", "observerSha256"}
          and type(proof["schemaVersion"]) is int and proof["schemaVersion"] == 1
          and proof["packet"] == record["packet"] and proof["pins"] == pins and proof["collection"] == summary
          and proof["observerSha256"] == hashlib.sha256(_observer(record["packet"]).encode()).hexdigest())
    _absence(proof["absence"], record["packet"])
    return True


def _absence(value, packet):
    _need(type(value) is dict and set(value) == {"machine", "boot", "account", "rootAbsent"}
          and value["machine"] == packet["binding"]["machine"] and value["account"] == packet["binding"]["account"]
          and type(value["boot"]) is str and str(UUID(value["boot"])) == value["boot"]
          and value["boot"] != packet["binding"]["boot"] and value["rootAbsent"] is True)


def _observer(packet):
    return """import json,os
from pathlib import Path
root=Path(%r)
try:
 root.lstat()
 absent=False
except FileNotFoundError:
 absent=True
print(json.dumps({'machine':Path('/etc/machine-id').read_text().strip(),'boot':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'account':str(os.geteuid()),'rootAbsent':absent},sort_keys=True))
""" % packet["remoteRoot"]


def collected_candidate(custody, record_path, record):
    """Return only locally authenticated complete original collections."""
    admission = registry._under(record["admissionPath"], custody.root / ".runtime")
    paths = [admission.parent / name for name in ("original-reconciliation.json", "result.json")]
    if any(not path.exists() for path in paths):
        _need(not any(path.is_symlink() for path in paths))
        return False
    _evidence(custody, record_path, record)
    return True


def _retire_custody(custody, operation_id, *, deadline=None, require_absence=True):
    """Normal admission hook; existing roots remain active for pure probing."""
    from . import readiness_tart, readiness_tart_registry as tart
    _need(type(operation_id) is str and str(UUID(operation_id)) == operation_id)
    _need(type(custody) is tart.TartCustody and custody.descriptor["provider"] == "tart-linux")
    deadline = time.monotonic() + 30 if deadline is None else deadline
    with custody.operator(deadline=deadline):
        custody.guard(deadline=deadline)
        path = custody.lifecycle_root / "guest-programs" / (operation_id + ".json")
        record, _ = registry._json(path)
        _need(set(record) == {"packet", "admissionPath", "admissionPin"})
        packet = tart._guest_packet(record["packet"], custody.binding)
        _need(packet["operationId"] == operation_id)
        if is_retired(custody, path, record):
            return packet
        pins, summary = _evidence(custody, path, record)
        source = _observer(packet).encode()
        gate = "import hashlib,sys;p=sys.stdin.buffer.read(262145);assert len(p)==int(sys.argv[1]) and hashlib.sha256(p).hexdigest()==sys.argv[2];exec(compile(p,'<collected-owner-absence>','exec'))"
        reply, _ = readiness_tart.TartBackend(custody.binding, custody)._guest(
            ["python3", "-I", "-B", "-c", gate, str(len(source)), hashlib.sha256(source).hexdigest()], deadline, payload=source)
        _need(reply.returncode == 0 and len(reply.stdout) <= 4096)
        absent = _json(reply.stdout)
        if not require_absence and (absent.get("rootAbsent") is not True or absent.get("boot") == packet["binding"]["boot"]):
            return None
        _absence(absent, packet)
        _need(_evidence(custody, path, record) == (pins, summary))
        custody.guard(deadline=deadline)
        directory = custody.lifecycle_root / "guest-program-retirements"
        directory.mkdir(mode=0o700, exist_ok=True); jobs._private(directory, directory=True)
        jobs._publish(directory / (operation_id + ".json"), {"schemaVersion": 1, "packet": packet,
            "pins": pins, "collection": summary, "absence": absent, "observerSha256": hashlib.sha256(source).hexdigest()})
        _need(is_retired(custody, path, record))
        return packet


def retire_collected_guest_program(root, fixture_id, operation_id):
    """Internal original-only collection retirement; no replay or power."""
    fixture = registry.registered_fixture(root, fixture_id)
    return _retire_custody(fixture.adapter.backend.custody, operation_id)
