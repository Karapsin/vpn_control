"""Finite registered-fixture counter sentinels over the shared durable owner.

Only count and interval are caller data. Historical inspection/collection is
local. Reconciliation restores transport only and observes the admitted owner;
it never starts a replacement job, wakes a guest or changes its account.
"""
import base64
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import subprocess
import time

from . import durable_remote_job as jobs
from . import readiness
from . import readiness_fixture_registry as registry
from . import readiness_qemu_jobs as protocol
from . import readiness_windows_jobs as windows_jobs


def _need(value, reason):
    if not value:
        raise ValueError(reason)


def _directory(root, fixture_id, *, create=False):
    _need(type(fixture_id) is str and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", fixture_id), "guest_fixture_id")
    root = Path(root).resolve(strict=True)
    path = root / ".runtime" / "readiness-guest-jobs" / fixture_id
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    jobs._private(path, directory=True)
    _need(path.resolve() == path, "guest_local_state_redirected")
    return path


def _operation(directory, operation, *, create=False):
    path = directory / jobs._uuid(operation)
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    jobs._private(path, directory=True)
    return path


def _save(path, value):
    if path.exists() or path.is_symlink():
        _need(jobs._record(path) == value, "guest_original_state_changed")
        return False
    else:
        try:
            jobs._publish(path, value)
            return True
        except FileExistsError:
            _need(jobs._record(path) == value, "guest_original_state_changed")
            return False


def _result(fixture_id, operation, state, reason, **fields):
    action = "collect_original" if state == "terminal" else "reconcile_original"
    return {"schemaVersion": 1, "fixtureId": fixture_id, "operationId": operation,
            "state": state, "reason": reason, "replayAllowed": False,
            "durableProtocol": 1, "qualificationScope": "fixed-counter", **fields,
            "nextAction": {"kind": action, "replayAllowed": False,
                           "action": {"tool": "vm_workflow",
                                      "action": "guest-program-collect" if state == "terminal" else "guest-program-reconcile",
                                      "args": {"inputs": {"fixtureId": fixture_id, "operationId": operation}}}}}


def status(root, fixture_id, operation):
    """Local observation only; no fixture lookup, transport or readiness work."""
    directory = _operation(_directory(root, fixture_id), operation)
    intent = jobs._record(directory / "intent.json")
    _need(intent["operationId"] == operation and intent["fixtureId"] == fixture_id, "guest_original_state_changed")
    terminal = directory / "terminal.json"
    if terminal.exists() or terminal.is_symlink():
        return jobs._record(terminal)
    observations = sorted(directory.glob("observation-*.json"))
    _need(len(observations) <= 10000, "guest_local_observation_bound")
    if observations:
        return jobs._record(observations[-1])
    return _result(fixture_id, operation, "unknown", "guest_submission_unresolved")


def collect(root, fixture_id, operation):
    result = status(root, fixture_id, operation)
    _need(result["state"] == "terminal", "guest_collection_not_terminal")
    return result


def _posix_original(root, fixture_id, operation):
    """Pure original discriminant; malformed or partial admission never falls through."""
    _need(type(fixture_id) is str and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", fixture_id), "guest_fixture_id")
    operation = jobs._uuid(operation)
    root = Path(root).resolve(strict=True)
    path = root / ".runtime" / "readiness-guest-jobs" / fixture_id / operation
    if not path.exists() and not path.is_symlink():
        return None
    directory = _operation(_directory(root, fixture_id), operation)
    intent = jobs._record(directory / "intent.json")
    _need(set(intent) == {"schemaVersion", "fixtureId", "operationId", "binding", "namespace", "spec"}
          and type(intent["schemaVersion"]) is int and intent["schemaVersion"] == 1
          and intent["operationId"] == operation and intent["fixtureId"] == fixture_id,
          "guest_original_state_changed")
    jobs.MachineBinding.from_dict(intent["binding"])
    _need(type(intent["spec"]) is dict and set(intent["spec"]) == {"count", "intervalSeconds"}
          and protocol._spec(intent["spec"]["count"], intent["spec"]["intervalSeconds"]) == intent["spec"],
          "guest_original_state_changed")
    return intent


def _original_provider(root, fixture_id, operation):
    # This ordering is intentional. No current registry metadata, provider
    # connection, or desktop observation may decide an admitted job's protocol.
    windows = windows_jobs.has_original(root, fixture_id, operation)
    posix = _posix_original(root, fixture_id, operation)
    _need(not (windows and posix is not None), "guest_original_provider_ambiguous")
    return "windows" if windows else "posix" if posix is not None else None


@contextmanager
def _executor(root, fixture_id, operation, deadline, *, start, original_binding=None):
    fixture = registry.registered_fixture(root, fixture_id)
    if original_binding is not None:
        original = jobs.MachineBinding.from_dict(original_binding)
        _need((fixture.target, fixture.machine) == (original.target, original.machine),
              "guest_original_target_changed")
        _need(getattr(fixture.adapter.backend, "provider", None) not in {"raw-qemu-windows", "libvirt-windows"}
              and getattr(getattr(fixture.adapter, "support", None), "lane", None) not in
              {"raw-qemu-windows", "libvirt-windows"}, "guest_original_provider_changed")
    required = frozenset({"guest_agent"}) if start else frozenset({"transport"})
    permitted = frozenset({"reconnect", "resume", "start", "reboot"}) if start else frozenset({"reconnect"})
    context = fixture.context(deadline=deadline)
    _need((context.target, context.machine) == (fixture.target, fixture.machine), "guest_executor_binding")
    ready = readiness.ensure_ready(context, readiness.Requirements(required, permitted), operation)
    factory = getattr(fixture.adapter.backend, "guest_job_executor", None)
    _need(callable(factory), "guest_program_provider_unavailable")
    options = {"deadline": time.monotonic() + readiness.NORMAL_BUDGET if deadline is None else deadline}
    if getattr(getattr(fixture.adapter, "support", None), "lane", "") == "raw-qemu-linux":
        options["operation_id"] = operation
    with factory(**options) as executor:
        readiness.revalidate(context, ready)
        _need(executor.target == fixture.target and executor.machine == fixture.machine
              and type(executor.uid) is int and executor.uid > 0, "guest_executor_binding")
        if original_binding is not None:
            _need(str(executor.uid) == original.account, "guest_original_account_changed")
        yield executor, fixture.adapter.backend


def _remote(executor, source):
    if callable(getattr(executor, "execute_source", None)):
        response = executor.execute_source(source)
    else:
        argv, payload = protocol.stdin_command(source)
        response = executor.execute(argv, payload=payload)
    _need(response.returncode == 0 and len(response.stdout) <= 262144 and len(response.stderr) <= 65536,
          "guest_original_observation_unavailable")
    value = json.loads(response.stdout)
    _need(type(value) is dict, "guest_original_response")
    return value


def _namespace_owner(backend):
    return getattr(backend, "custody", backend)


def _namespace(directory, executor, backend, *, enroll):
    path = directory / "namespace.json"
    owner = _namespace_owner(backend)
    load = getattr(owner, "load_guest_namespace", getattr(owner, "load_guest_job_namespace", None))
    provider_packet = load() if callable(load) else None
    # This identity comes from the admitted provider executor, never a public
    # selector or the coordinator's own operating system.
    guest_platform = {"raw-qemu-linux": "linux", "tart-linux": "linux", "tart-macos": "darwin"}.get(executor.provider)
    _need(guest_platform is not None, "guest_namespace_platform")
    if path.exists() or path.is_symlink():
        namespace = protocol._packet(jobs._record(path), guest_platform=guest_platform)
        if callable(load):
            _need(provider_packet == namespace, "guest_namespace_registry_changed")
    elif provider_packet is not None:
        namespace = protocol._packet(provider_packet, guest_platform=guest_platform)
        _save(path, namespace)
    else:
        _need(enroll, "guest_namespace_unresolved")
        value = _remote(executor, protocol.enroll_program(executor.target, executor.machine, executor.uid,
                       actual_machine_id=getattr(executor, "guest_machine_id", executor.machine)))
        _need(set(value) == {"namespace"}, "guest_namespace_response")
        namespace = protocol._packet(value["namespace"], guest_platform=guest_platform)
        # Registration is required before any async job can be submitted, so
        # provider idle proof cannot overlook the new namespace.
        admit = getattr(owner, "admit_guest_namespace", getattr(owner, "admit_guest_job_namespace", None))
        _need(callable(admit), "guest_namespace_registry_unavailable")
        admit(namespace)
        _save(path, namespace)
    _need((namespace["target"], namespace["machine"], namespace["account"]) ==
          (executor.target, executor.machine, str(executor.uid)), "guest_namespace_binding")
    _need(namespace["actualMachineId"].lower() == getattr(executor, "guest_machine_id", executor.machine).lower(),
          "guest_namespace_machine_changed")
    _remote(executor, protocol.observe_program(namespace))
    return namespace


def _record_observation(directory, intent, response):
    _need(type(response) is dict and type(response.get("status")) is dict, "guest_original_response")
    observed = response["status"]
    _need(observed.get("operationId") == intent["operationId"]
          and observed.get("state") in {"running", "terminal", "unknown", "unsubmitted"}, "guest_original_response")
    state = observed["state"]
    if response.get("admissionConsumed") is True:
        _save(directory / "remote-admission-consumed.json", {"operationId": intent["operationId"],
               "binding": intent["binding"], "namespace": intent["namespace"]})
    # Only reconcile's positively proven same-root absence path can prepare
    # another original admission. Unknown owner records never reach it.
    if state == "unsubmitted":
        state = "unknown"
    fields = {"binding": intent["binding"]}
    if "owner" in observed:
        fields["remoteOwner"] = observed["owner"]
    if state == "terminal":
        _need(observed.get("binding") == intent["binding"] and observed["terminal"]["exitCode"] == 0,
              "guest_sentinel_terminal_invalid")
        stdout, stderr, counter = (base64.b64decode(response[name], validate=True) for name in ("stdout", "stderr", "counter"))
        expected = [str(n).encode() for n in range(intent["spec"]["count"])]
        _need(len(stdout) <= 8192 and stdout.splitlines() == expected
              and stderr == b"guest sentinel retained stderr\n"
              and counter.splitlines() == [b"execution", *expected], "guest_sentinel_result_invalid")
        fields.update(stdout=stdout.decode("ascii"), stderr=stderr.decode("ascii"),
                      counterValues=len(expected), executions=1)
    result = _result(intent["fixtureId"], intent["operationId"], state, observed.get("reason", "guest_original_observed"), **fields)
    jobs._publish(directory / ("observation-" + str(time.time_ns()) + ".json"), result)
    if state == "terminal":
        _save(directory / "terminal.json", result)
    return result


def _effective_intent(directory, original):
    effective = dict(original)
    amendments = sorted(directory.glob("binding-amendment-*.json"))
    _need(len(amendments) <= 3, "guest_binding_amendments_exhausted")
    for index, path in enumerate(amendments, 1):
        value = jobs._record(path)
        _need(path.name == "binding-amendment-%08d.json" % index
              and set(value) == {"operationId", "namespace", "originalBinding", "previousBinding", "binding", "proof"}
              and value["operationId"] == original["operationId"] and value["namespace"] == original["namespace"]
              and value["originalBinding"] == original["binding"] and value["previousBinding"] == effective["binding"],
              "guest_binding_amendment_changed")
        previous = jobs.MachineBinding.from_dict(effective["binding"])
        renewed = jobs.MachineBinding.from_dict(value["binding"])
        _need((renewed.target, renewed.machine, renewed.account) == (previous.target, previous.machine, previous.account)
              and value["proof"] == {"operationId": original["operationId"], "root": original["namespace"]["root"],
                                      "generation": original["namespace"]["generation"],
                                      "admissionGeneration": original["namespace"]["admissionGeneration"],
                                      "binding": value["binding"]},
              "guest_binding_amendment_changed")
        effective["binding"] = value["binding"]
    return effective


def start(root, fixture_id, operation, *, count=10, interval_seconds=.1, deadline=None):
    operation = jobs._uuid(operation)
    spec = protocol._spec(count, interval_seconds)
    directory = _directory(root, fixture_id, create=True)
    original = directory / operation / "intent.json"
    if original.exists() or original.is_symlink():
        intent = jobs._record(original)
        _need(intent["spec"] == spec, "guest_original_spec_changed")
        return reconcile(root, fixture_id, operation, deadline=deadline)
    with _executor(root, fixture_id, operation, deadline, start=True) as (executor, backend):
        namespace = _namespace(directory, executor, backend, enroll=True)
        binding = jobs.asdict(jobs.MachineBinding(executor.target, executor.machine, executor.boot, str(executor.uid)))
        operation_directory = _operation(directory, operation, create=True)
        intent = {"schemaVersion": 1, "fixtureId": fixture_id, "operationId": operation,
                  "binding": binding, "namespace": namespace, "spec": spec}
        _save(operation_directory / "intent.json", intent)
        # A dispatch intent is durable before any submission. A lost ACK may
        # only reconcile this operation; no client/server retry starts again.
        dispatch = operation_directory / "dispatch.json"
        try:
            if dispatch.exists() or dispatch.is_symlink():
                response = _remote(executor, protocol.operation_program(namespace, operation, binding))
            else:
                admitted = _save(dispatch, {"operationId": operation, "submissionAttempted": True})
                response = _remote(executor, protocol.operation_program(namespace, operation, binding, submit=admitted,
                                    count=count, interval_seconds=interval_seconds))
        except (OSError, subprocess.SubprocessError):
            return _result(fixture_id, operation, "unknown", "guest_submission_unresolved", binding=binding)
        return _record_observation(operation_directory, intent, response)


def reconcile(root, fixture_id, operation, *, deadline=None):
    directory = _directory(root, fixture_id)
    operation_directory = _operation(directory, operation)
    current = status(root, fixture_id, operation)
    if current["state"] == "terminal":
        return current
    original = jobs._record(operation_directory / "intent.json")
    intent = _effective_intent(operation_directory, original)
    # A provider-created partial publication selects ORIGINAL observation only;
    # no readiness recovery or positive-absence resubmission enters this lane.
    from . import readiness_tart_macos_active_work_original
    response = readiness_tart_macos_active_work_original.guest_original_response(
        root, fixture_id, operation, deadline=deadline)
    if response is not None:
        return _record_observation(operation_directory, intent, response)
    with _executor(root, fixture_id, operation, deadline, start=False, original_binding=intent["binding"]) as (executor, backend):
        namespace = _namespace(directory, executor, backend, enroll=False)
        _need(namespace == intent["namespace"], "guest_namespace_changed")
        try:
            response = _remote(executor, protocol.operation_program(namespace, operation, intent["binding"]))
            if response.get("status", {}).get("state") == "unsubmitted":
                _need(response["status"].get("reason") == "admission_absent"
                      and response.get("admissionConsumed") is False
                      and not (operation_directory / "remote-admission-consumed.json").exists()
                      and not (operation_directory / "remote-admission-consumed.json").is_symlink(),
                      "guest_original_admission_lost")
                current_binding = jobs.asdict(jobs.MachineBinding(executor.target, executor.machine, executor.boot, str(executor.uid)))
                proof = {"operationId": operation, "root": namespace["root"], "generation": namespace["generation"],
                         "admissionGeneration": namespace["admissionGeneration"],
                         "binding": current_binding}
                _need(response.get("unsubmittedProof") == proof, "guest_unsubmitted_binding_changed")
                proofs = sorted(operation_directory.glob("unsubmitted-proof-*.json"))
                _need(len(proofs) < 3, "guest_unsubmitted_attempts_exhausted")
                jobs._publish(operation_directory / ("unsubmitted-proof-" + str(time.time_ns()) + ".json"),
                              {"operationId": operation, "namespace": namespace, "binding": intent["binding"],
                               "observation": response["status"]})
                if current_binding != intent["binding"]:
                    amendments = sorted(operation_directory.glob("binding-amendment-*.json"))
                    _need(len(amendments) < 3, "guest_binding_amendments_exhausted")
                    _save(operation_directory / ("binding-amendment-%08d.json" % (len(amendments)+1)),
                          {"operationId": operation, "namespace": namespace, "originalBinding": original["binding"],
                           "previousBinding": intent["binding"], "binding": current_binding, "proof": proof})
                    intent = _effective_intent(operation_directory, original)
                response = _remote(executor, protocol.operation_program(namespace, operation, intent["binding"],
                                   submit=True, count=intent["spec"]["count"],
                                   interval_seconds=intent["spec"]["intervalSeconds"]))
        except (OSError, subprocess.SubprocessError):
            return _result(fixture_id, operation, "unknown", "guest_original_observation_unavailable", binding=intent["binding"])
        return _record_observation(operation_directory, intent, response)


def workflow(root, action, inputs):
    """Validate the complete normal VM-tool schema before resolving a fixture."""
    actions = {"start": start, "status": status, "reconcile": reconcile, "collect": collect}
    _need(action in actions and type(inputs) is dict, "guest_program_action")
    fields = {"fixtureId", "operationId", "count", "intervalSeconds"} if action == "start" else {"fixtureId", "operationId"}
    _need(set(inputs) == fields, "guest_program_inputs")
    jobs._uuid(inputs["operationId"])
    if action == "start":
        _need(type(inputs["count"]) is int and 1 <= inputs["count"] <= 1000
              and type(inputs["intervalSeconds"]) in (int, float) and math.isfinite(inputs["intervalSeconds"])
              and .01 <= inputs["intervalSeconds"] <= 1, "guest_sentinel_spec")
    original = _original_provider(root, inputs["fixtureId"], inputs["operationId"])
    if original == "windows":
        return windows_jobs.workflow(root, action, inputs)
    if original is None:
        _need(action == "start", "guest_program_original_missing")
        fixture = registry.registered_fixture(root, inputs["fixtureId"])
        backend = fixture.adapter.backend
        if getattr(backend, "provider", None) in {"raw-qemu-windows", "libvirt-windows"}:
            # The Windows facade independently validates its real registered
            # factory and pins a snapshot before submission. No POSIX UID or
            # namespace is synthesized for a SYSTEM/session-zero owner.
            return windows_jobs.workflow(root, action, inputs)
    options = ({"count": inputs["count"], "interval_seconds": inputs["intervalSeconds"]}
               if action == "start" else {})
    return actions[action](root, inputs["fixtureId"], inputs["operationId"], **options)
