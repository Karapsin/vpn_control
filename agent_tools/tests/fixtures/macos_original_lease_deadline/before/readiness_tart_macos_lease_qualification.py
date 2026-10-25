"""Read immutable native lease evidence; labels alone never admit a producer.

Only the reviewed native qualification programs below are recognized. These
programs are public fixture source, never credentials, VM images or user input.
Parsing performs no guest call, recovery, assertion or module execution.
"""
from __future__ import annotations

import ast
import base64
from dataclasses import asdict
import hashlib
import json
import time
import sys
from pathlib import Path

from . import readiness_tart_macos_registry as mac
from . import readiness_tart_macos as backend
from . import readiness_tart_macos_lease_bridge as bridge
from . import readiness_tart_macos_leases as leases

_EXECUTING_CODE = sys._getframe().f_code

_PRODUCERS = {
    "expiry": "c51a0f887725291b1f46eb18951503c637a337f9c51a4639220c9e86b43813fa",
    "cancel": "e0837869809c8a31f03d7db33028467581a37126227964dcd8fbfd343911ff19",
    "client-death": "14b3fca067979ba39c54b65aef7c9e335cbb750b182de2531aeffc5d1c48bc5a",
}
_GUEST_SOURCES = {
    "durable_remote_job.py": "f3b4707528c16f176b80781dd86208c324c1e10d6eb2c14451dcf4be08d0e734",
    "tart_macos_probe.py": "b144862272b3bbb5464bcdb3ed57403d76d4f5418c4388c859195f9afb3c38ab",
    "readiness_tart_macos_leases.py": "721c397ffa4fe4c25ef7fc9da2470f6d925a43410986d596b215b255b94877e7",
}
_BRIDGE = "f456cd5b4448fbe9f94b3b32c4802f2e8822d71213cab5ba7d47d0ff07c0ead6"


def _need(value):
    if not value:
        raise mac.MacBlocked("macos_native_lease_qualification_invalid")


def _canonical_request(source):
    # JSON archives sort mapping keys. Only CONFIG dictionary insertion order
    # may consequently differ; every executable body/package byte stays exact.
    lines = source.decode("utf-8").splitlines(keepends=True)
    indices = [index for index, line in enumerate(lines) if line.startswith("CONFIG=")]
    _need(len(indices) == 1)
    index = indices[0]
    lines[index] = "CONFIG=" + json.dumps(ast.literal_eval(lines[index][7:]), sort_keys=True, separators=(",", ":")) + "\n"
    return "".join(lines).encode()


def _expected_request(capsule, binding, namespace, action, operation, ttl):
    _need(action in {"acquire", "status", "cancel"})
    source = base64.b64decode(capsule["bridge"], validate=True)
    body = next(node.value.value for node in ast.parse(source).body if isinstance(node, ast.Assign)
                and any(isinstance(name, ast.Name) and name.id == "_GUEST" for name in node.targets))
    captured = {name: base64.b64decode(data, validate=True) for name, data in capsule["files"].items()}
    config = {"action": action, "binding": asdict(binding), "namespace": namespace, "operation": operation,
              "ttl": ttl if action == "acquire" else None, "root": namespace["root"], "sources": namespace["sources"]}
    # Exact f456 renderer, without later HOST-only status-wrapper additions.
    preamble = ('import sys,types\n'
                "package=types.ModuleType('_fixed_macos_lease');package.__path__=[];sys.modules[package.__name__]=package\n")
    for name in ("durable_remote_job.py", "tart_macos_probe.py", "readiness_tart_macos_leases.py"):
        short = name[:-3]
        preamble += (f"m=types.ModuleType('_fixed_macos_lease.{short}');m.__package__=package.__name__;"
                     f"m.__file__='<fixed-{name}>';sys.modules[m.__name__]=m;setattr(package,{short!r},m)\n")
        if name == "readiness_tart_macos_leases.py":
            preamble += "m.__dict__['__captured_probe_source__']=" + repr(captured["tart_macos_probe.py"]) + "\n"
        preamble += 'exec(compile(' + repr(captured[name]) + f",'<fixed-{name}>','exec'),m.__dict__)\n"
        if name == "durable_remote_job.py":
            preamble += "m.owner_source=lambda:" + repr(captured[name]) + "\n"
    return (preamble + "\nCONFIG=" + repr(config) + "\n" + body + "\nraise SystemExit(main())\n").encode()


class QualifiedProducer:
    """Opaque result constructed only after checking the original native cases."""
    __slots__ = ("raw", "digest", "binding", "namespace", "manifest")

    def __init__(self, *args, **kwargs):
        raise mac.MacBlocked("macos_native_lease_qualification_required")


def _program_digest(capsule, binding, namespace, operation, ttl):
    files = {name: base64.b64decode(body, validate=True) for name, body in capsule["files"].items()}
    constants = {node.targets[0].id: node.value.value for node in ast.parse(files["readiness_tart_macos_leases.py"]).body
                 if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                 and isinstance(node.value, ast.Constant) and type(node.value.value) is str}
    payload = {"root": namespace["root"] + "/jobs", "operationId": operation,
               "binding": asdict(binding), "ttlSeconds": ttl, "controlled": None}
    # Exact reviewed native program construction; no old module is imported.
    source = ("import sys,types\nDmod=types.ModuleType('macos_lease_job_snapshot')\n"
              "sys.modules[Dmod.__name__]=Dmod\nD=Dmod.__dict__\nexec(" + repr(files["durable_remote_job.py"]) + ",D)\n"
              "Pmod=types.ModuleType('macos_lease_probe_snapshot')\nsys.modules[Pmod.__name__]=Pmod\n"
              "P=Pmod.__dict__\nexec(" + repr(files["tart_macos_probe.py"]) + ",P)\n" +
              constants["_ASSERTIONS"] + constants["_CONTROLLED"] + constants["_OWNER"] +
              "\nmacos_lease_run(" + repr(payload) + ")\n").encode()
    return hashlib.sha256(source).hexdigest()


def _load(custody, reference):
    """Validate a private manifest anchored to this original RUN and namespace."""
    def read(ref, *, json_value=True):
        _need(type(ref) is dict and set(ref) == {"path", "pin"} and type(ref["path"]) is str)
        path, pin = Path(ref["path"]), ref["pin"]
        _need(type(pin) is dict and type(pin.get("generation")) is list
              and len(pin["generation"]) == 9 and type(pin["generation"][6]) is int
              and 0 <= pin["generation"][6] <= 262144)
        _need(path.is_absolute() and path == path.resolve(strict=True) and path.is_relative_to(custody.lifecycle_root)
              and path.suffix in {".json", ".py", ".txt"})
        if ref != reference:
            relative = path.relative_to(custody.lifecycle_root)
            _need(len(relative.parts) >= 2 and relative.parts[0].startswith("native-iopm-v2-qualification-"))
            mac._uuid(relative.parts[0][len("native-iopm-v2-qualification-"):])
        else:
            _need(path == custody.lifecycle_root / "lease-native-qualification.json")
        with mac.PublicProof(path, pin, allow_empty=not json_value) as held:
            _need(len(held.body) <= 262144)
            return held.value() if json_value else held.body

    manifest = read(reference)
    _need(type(manifest) is dict and set(manifest) == {"schemaVersion", "originalRunOperationId", "cases"}
          and type(manifest["schemaVersion"]) is int and manifest["schemaVersion"] == 1
          and manifest["originalRunOperationId"] == custody.run_intent["operationId"]
          and type(manifest["cases"]) is dict and set(manifest["cases"]) == set(_PRODUCERS))
    selected = None
    operations = set()
    for kind, case in manifest["cases"].items():
        _need(type(case) is dict and set(case) == {"producer", "admission", "capsule", "evidence", "requests", "active", "client"})
        _need(hashlib.sha256(read(case["producer"], json_value=False)).hexdigest() == _PRODUCERS[kind])
        admission, evidence = read(case["admission"]), read(case["evidence"])
        raw = read(case["capsule"], json_value=False)
        digest = hashlib.sha256(raw).hexdigest()
        capsule = json.loads(raw)
        binding = leases.MacLeaseBinding(**admission["binding"])
        namespace = admission["namespace"]
        operation, ttl = admission["operationId"], admission["ttlSeconds"]
        mac._uuid(operation); leases._ttl(ttl)
        _need(type(ttl) is int and ttl == {"expiry": 3, "cancel": 90, "client-death": 15}[kind])
        _need(operation not in operations); operations.add(operation)
        _need(admission["capsuleSha256"] == digest and capsule["binding"] == admission["binding"]
              and capsule["namespace"] == namespace and namespace == custody.load_lease_namespace("v2")
              and namespace["sources"] == _GUEST_SOURCES
              and (binding.target, binding.machine, binding.account, binding.principal, binding.home) ==
                  (custody.binding.target, custody.binding.machine, str(custody.binding.ordinary_uid),
                   custody.binding.ordinary_account, custody.binding.ordinary_home))
        _need(hashlib.sha256(base64.b64decode(capsule["bridge"], validate=True)).hexdigest() == _BRIDGE)
        _need({name: hashlib.sha256(base64.b64decode(body, validate=True)).hexdigest()
               for name, body in capsule["files"].items()} == _GUEST_SOURCES)
        # This also validates the captured schema and fixed v2 root.
        bridge.observer_source(raw, "inventory", expected_sha256=digest)
        original = evidence["originalEvidence"]
        acquired, terminal, status = original["acquired"], original["leaseTerminal"], original["terminalStatus"]
        backend._actor(acquired["leaseOwner"]); backend._actor(status["owner"])
        mac._uuid(acquired["generation"])
        expected_binding = asdict(binding.job_binding())
        program = _program_digest(capsule, binding, namespace, operation, ttl)
        state = "cancelled" if kind == "cancel" else "expired"
        _need(evidence["operationId"] == operation and evidence["status"]["operationId"] == operation
              and evidence["status"]["state"] == state and evidence["status"]["restored"] is True
              and acquired["backend"] == "native" and acquired["binding"] == expected_binding
              and acquired["operationId"] == operation and acquired["programSha256"] == program
              and acquired["session"] == binding.session and acquired["ttlSeconds"] == ttl
              and type(acquired["assertions"]) is list and len(acquired["assertions"]) == 2
              and all(type(number) is int and number > 0 for number in acquired["assertions"])
              and len(set(acquired["assertions"])) == 2
              and terminal["binding"] == expected_binding and terminal["operationId"] == operation
              and terminal["programSha256"] == program and terminal["generation"] == acquired["generation"]
              and terminal["leaseOwner"] == acquired["leaseOwner"] and terminal["assertions"] == acquired["assertions"]
              and terminal["state"] == state and terminal["restored"] is True
              and original["actualOwnerPresent"] is False and original["nativeOwnerAbsent"] is True
              and status["state"] == "terminal" and status["binding"] == expected_binding
              and status["operationId"] == operation and status["replayAllowed"] is False)
        receipt = status["terminal"]
        _need(receipt["binding"] == expected_binding and receipt["operationId"] == operation
              and receipt["generation"] == acquired["generation"] and receipt["programSha256"] == program
              and type(receipt["exitCode"]) is int and receipt["exitCode"] == 0
              and receipt["streamsClosed"] is True and receipt["owner"] == status["owner"])
        for stream in ("stdout", "stderr"):
            body = base64.b64decode(original[stream], validate=True)
            _need(type(receipt[stream]["retainedBytes"]) is int and type(receipt[stream]["totalBytes"]) is int
                  and receipt[stream]["overflow"] is False
                  and receipt[stream] == {"overflow": False, "retainedBytes": len(body), "totalBytes": len(body),
                                      "sha256": hashlib.sha256(body).hexdigest()})
        outcome = json.loads(base64.b64decode(original["stdout"]))
        _need(outcome["state"] == state and outcome["restored"] is True)
        _need(type(case["requests"]) is list and 1 <= len(case["requests"]) <= 32)
        acquisitions = 0; cancellations = 0
        for request in case["requests"]:
            _need(set(request) == {"source", "intent", "result", "stdout", "stderr"})
            source = read(request["source"], json_value=False)
            intent, result = read(request["intent"]), read(request["result"])
            stdout, stderr = read(request["stdout"], json_value=False), read(request["stderr"], json_value=False)
            _need(intent["operationId"] == operation and intent["originalRun"] == custody.run_intent["operationId"]
                  and hashlib.sha256(source).hexdigest() == intent["sourceSha256"]
                  and result["operationId"] == operation and result["action"] == intent["action"]
                  and result["returncode"] == 0 and result["stdoutBytes"] == len(stdout) and result["stderrBytes"] == len(stderr))
            reply = json.loads(stdout)
            _need(_canonical_request(source) == _canonical_request(
                _expected_request(capsule, binding, namespace, intent["action"], operation, ttl)))
            if intent["action"] == "acquire":
                acquisitions += 1
                _need(_canonical_request(source) == _canonical_request(
                    bridge.qualified_acquire_source(raw, expected_sha256=digest, operation=operation, ttl=ttl)))
            if intent["action"] == "cancel": cancellations += 1
            _need(reply.get("operationId") == operation and reply.get("replayAllowed") is False)
        _need(acquisitions == 1 and cancellations == (1 if kind == "cancel" else 0))
        if kind != "expiry":
            active = read(case["active"])
            proof = active["nativeActiveProof"]
            _need(active["acquired"] == acquired and active["actualOwnerPresent"] is True
                  and proof == {"active": True, "assertions": acquired["assertions"],
                                "nativeInventoryComplete": True, "owner": acquired["leaseOwner"]}
                  and active["status"]["state"] == "running")
        if kind == "client-death":
            client = read(case["client"])
            _need(client["sameOriginalOperationId"] == operation and client["originalControllerAbsent"] is True
                  and client["originalController"]["exitCode"] == 77
                  and client["nativeEvidence"]["acquired"] == acquired)
        if selected is None:
            selected = (raw, digest, binding, namespace)
        else:
            _need(selected == (raw, digest, binding, namespace))
    result = object.__new__(QualifiedProducer)
    result.raw, result.digest, result.binding, result.namespace = selected
    result.manifest = reference
    return result


def load(custody, reference):
    try:
        from .readiness_tart_macos_lease_executor import _OriginalMacCustody
        _need(type(custody) in {mac.MacCustody, _OriginalMacCustody})
        custody.guard(deadline=time.monotonic()+30)
        result = _load(custody, reference)
        custody.guard(deadline=time.monotonic()+30)
        return result
    except mac.MacBlocked:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OSError, UnicodeError, SyntaxError):
        raise mac.MacBlocked("macos_native_lease_qualification_invalid") from None


if _EXECUTING_CODE != compile(Path(__file__).read_bytes(), __file__, "exec", dont_inherit=True, optimize=sys.flags.optimize):
    raise mac.MacBlocked("macos_lease_qualification_executing_source_changed")
