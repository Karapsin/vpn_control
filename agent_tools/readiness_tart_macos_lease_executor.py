"""Mac guest leases admitted by immutable native qualifications.

New acquisition requires current custody and a qualified retained producer.
Reconstructing an original snapshot never enters readiness, unlocks, powers,
reenrolls, or grants new-acquisition authority.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from uuid import uuid4

from . import durable_remote_job as jobs
from . import readiness_fixture_registry as registry
from . import readiness_tart_macos_registry as mac
from . import readiness_tart_macos_lease_bridge as bridge
from . import readiness_tart_macos_leases as leases
from . import readiness_qemu_jobs as protocol
from . import readiness_tart_macos_lease_qualification as qualification

_EXECUTING_CODE = sys._getframe().f_code
KIND = "qualified-tart-macos-guest-lease-v1"


def _need(value, reason):
    if not value:
        raise mac.MacBlocked(reason)


def source_pins():
    result = mac._source_pins()
    result[Path(__file__).name] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    result[Path(qualification.__file__).name] = hashlib.sha256(Path(qualification.__file__).read_bytes()).hexdigest()
    return result


def _original_source_roles(sources):
    """Two finite registration epochs; historical hashes never select code."""
    current = set(source_pins())
    historical = current - {"readiness_tart_macos_lease_executor.py", "readiness_tart_macos_lease_qualification.py"}
    return (type(sources) is dict and set(sources) in (current, historical, {'readiness_providers.py', 'tart_macos_probe.py', 'readiness_tart_vnc.py', 'readiness.py', 'readiness_tart_macos_lease_executor.py', 'durable_remote_job.py', 'readiness_tart_macos_lease_bridge.py', 'readiness_qemu_jobs.py', 'readiness_tart_macos_leases.py', 'readiness_tart_macos.py', 'readiness_tart_macos_lease_qualification.py', 'readiness_tart_macos_registry.py', 'readiness_fixture_registry.py', 'private_inventory_lock.py'}, {'readiness_providers.py', 'tart_macos_probe.py', 'readiness_tart_vnc.py', 'readiness.py', 'durable_remote_job.py', 'readiness_tart_macos_lease_bridge.py', 'readiness_qemu_jobs.py', 'readiness_tart_macos_leases.py', 'readiness_tart_macos.py', 'readiness_tart_macos_registry.py', 'readiness_fixture_registry.py', 'private_inventory_lock.py'})
            and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in sources.values()))


def normalize(value, operation):
    """Retain native outcomes within the finite normal lease response schema."""
    fields = {"schemaVersion", "operationId", "provider", "state", "jobState", "reason", "replayAllowed", "nextAction"}
    _need(type(value) is dict and set(value) in (fields, fields | {"restored"})
          and type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1
          and value.get("operationId") == operation and value.get("replayAllowed") is False
          and value.get("provider") == "tart-macos"
          and type(value.get("state")) is str and type(value.get("nextAction")) is str
          and type(value.get("jobState")) is str
          and value.get("jobState") in {"unsubmitted", "unknown", "pending", "running", "terminal"}
          and type(value.get("reason")) is str and re.fullmatch(r"[a-z][a-z0-9_]{0,95}", value["reason"])
          and ("restored" not in value or type(value["restored"]) is bool),
          "macos_original_lease_reply_invalid")
    state, next_action = value.get("state"), value.get("nextAction")
    allowed = {"unsubmitted", "unknown", "starting", "active", "expired", "cancelled", "failed", "restore_blocked"}
    result = dict(value)
    result["ok"] = False
    result["nativeState"] = state
    if state == "restore_pending":
        result.update(state="unknown", nativeState=state)
    elif state == "restored":
        # Assertion cleanup succeeded after its original job/owner failed.
        result.update(state="failed", nativeState=state)
    else:
        _need(state in allowed, "macos_original_lease_reply_invalid")
    cleanup = (
            type(value.get("schemaVersion")) is int and value["schemaVersion"] == 1
            and value.get("provider") == "tart-macos" and state == "restore_blocked"
            and value.get("jobState") == "terminal" and value.get("restored") is False
            and value.get("reason") == "macos_assertion_release_unverified")
    if next_action == "resolve_restoration_blocker":
        result["nextAction"] = "reconcile_original" if cleanup else "resolve_blocker"
    if result.get("nextAction") == "reconcile_original":
        _need(cleanup, "macos_original_lease_reply_invalid")
    _need(result.get("nextAction") in {"none", "observe_original", "resolve_blocker", "reconcile_original"},
          "macos_original_lease_reply_invalid")
    if result["state"] == "unsubmitted":
        _need(result.get("reason") == "original_admission_absent", "macos_lease_absence_proof_invalid")
    if (state == "active" and value["jobState"] == "running"
            and value["reason"] == "original_lease_owner_running" and next_action == "observe_original"
            and "restored" not in value):
        result["ok"] = True
    elif (state == "unknown" and value["jobState"] == "unknown"
            and value["reason"] == "record_unavailable" and next_action == "observe_original"
            and "restored" not in value):
        result.update(ok=True, reason="original_owner_ack_pending", nativeReason=value["reason"])
    elif (state == "unknown" and value["jobState"] == "running"
            and value["reason"] == "original_owner_running" and next_action == "observe_original"
            and "restored" not in value):
        result.update(ok=True, state="starting")
    elif (state in {"expired", "cancelled"} and value.get("restored") is True
            and value["reason"] == {"expired": "lease_deadline_reached", "cancelled": "original_lease_cancelled"}[state]
            and ((value["jobState"] == "terminal" and next_action == "none")
                 or (value["jobState"] == "running" and next_action == "observe_original"))):
        result["ok"] = True
    elif (state == "restore_pending" and value["jobState"] == "running"
            and type(value.get("restored")) is bool and next_action == "observe_original"
            and value["reason"] in {"lease_deadline_reached", "original_lease_cancelled", "macos_lease_failed",
                                    "macos_assertion_release_unverified"}):
        result["ok"] = True
    return result


class _OriginalMacCustody(mac.MacCustody):
    """Current trusted custody, restricted to an admitted original producer.

    Historical hashes describe original provenance; they never load executable
    modules. Actual host actors, artifacts and registration remain fenced by the
    current implementation. There is no stale-admission option for new work.
    """
    def __init__(self, root, fixture_id, descriptor, descriptor_pin):
        sources = descriptor.get("sources")
        _need(_original_source_roles(sources),
              "macos_original_source_admission_invalid")
        self._admitted_sources = dict(sources)
        super().__init__(root, fixture_id, descriptor, descriptor_pin)

    def _check_source_custody(self, descriptor):
        _need(mac._LOADED_SOURCE_PINS == mac._source_pins()
              and descriptor["sources"] == self._admitted_sources, "macos_original_observer_source_changed")

    def _guest_producer_source(self, intent, proof):
        command = intent.get("command", {})
        if (command.get("registrySha256"), command.get("sourceSha256")) == (
                "de315b7ffa415f88e2b8d15b0d221f8b5f00d7f7e882bfa60d648d7814aff12e",
                "04cb972f2e9e4e48c6c6bd5e8b231bd37c49ca89da936adf2d1c2d34df51a571"):
            # One reviewed historical source epoch, authenticated by the
            # original immutable registration/receipt. Retained bytes are data
            # for receipt comparison; no old host/guest module is executed.
            path = self.root / ".runtime/tool-recovery/direct-entrypoints/macos-initial-factory-probe/validator.py"
            _need(command.get("stdinFile") == str(path), "macos_original_guest_producer_changed")
            try:
                generation = list(mac.private._generation(path.lstat()))
                _need(0 < generation[6] <= 262144, "macos_original_guest_producer_changed")
                with mac.PublicProof(path, {"generation": generation, "sha256": command["sourceSha256"]}) as held:
                    return held.body.decode("utf-8", "strict")
            except (OSError, UnicodeError):
                raise mac.MacBlocked("macos_original_guest_producer_changed") from None
        return super()._guest_producer_source(intent, proof)

    def ordinary_guest_call(self, *args, **kwargs):
        raise mac.MacBlocked("macos_original_lease_only")

    def guest_probe(self, *args, **kwargs):
        raise mac.MacBlocked("macos_original_lease_only")

    def prepare_lease_namespace(self, *args, **kwargs):
        raise mac.MacBlocked("macos_original_lease_only")

    def admit_lease_namespace(self, *args, **kwargs):
        raise mac.MacBlocked("macos_original_lease_only")

    def admit_guest_namespace(self, *args, **kwargs):
        raise mac.MacBlocked("macos_original_lease_only")

    def lease_executor(self):
        raise mac.MacBlocked("macos_original_lease_only")

    def original_lease_call(self, raw, action, operation, *, expected_sha256, deadline):
        _need(action in {"status", "cancel", "reconcile"}, "macos_lease_action_invalid")
        source = bridge.observer_source(raw, action, expected_sha256=expected_sha256, operation=operation)
        argv, payload = protocol.stdin_command(source.decode("utf-8"))
        return mac.MacCustody.ordinary_guest_call(self, self.binding, argv, payload, deadline)


class OriginalMacLeaseExecutor:
    """A fixed original observer/cancellation request; never a new owner."""
    provider = "tart-macos"

    def __init__(self, root, snapshot):
        self.root = Path(root).resolve(strict=True)
        fields = {"schemaVersion", "provider", "kind", "fixtureId", "registration", "binding", "namespace", "capsule", "sources", "qualification"}
        _need(type(snapshot) is dict and set(snapshot) == fields
              and type(snapshot["schemaVersion"]) is int and snapshot["schemaVersion"] == 2
              and snapshot["provider"] == self.provider and snapshot["kind"] == KIND
              and _original_source_roles(snapshot["sources"]),
              "macos_lease_snapshot_invalid")
        _need(type(snapshot["binding"]) is dict and set(snapshot["binding"]) == {
                  "target", "machine", "boot", "account", "principal", "home", "session"}
              and type(snapshot["namespace"]) is dict
              and type(snapshot["namespace"].get("root")) is str
              and snapshot["namespace"].get("root") in {
                  "/private/var/tmp/vc-recovery-macos-leases", "/private/var/tmp/vc-recovery-macos-leases-v2"},
              "macos_lease_snapshot_invalid")
        try:
            original_binding = leases.MacLeaseBinding(**snapshot["binding"])
        except (ValueError, TypeError):
            raise mac.MacBlocked("macos_lease_snapshot_invalid") from None
        self._snapshot = json.loads(json.dumps(snapshot))
        fixture_id = registry._id(snapshot["fixtureId"])
        registration = snapshot["registration"]
        path = self.root / ".rag_index/readiness-fixtures" / (fixture_id + ".json")
        _need(type(registration) is dict and set(registration) == {"path", "pin"}
              and registration["path"] == str(path),
              "macos_lease_registration_changed")
        pin = registration["pin"]
        descriptor, actual_pin = registry._json(path)
        _need(type(descriptor) is dict and actual_pin == pin and descriptor.get("provider") == "tart-macos"
              and type(descriptor.get("schemaVersion")) is int and descriptor["schemaVersion"] == 3,
              "macos_lease_registration_changed")
        _need(snapshot["sources"] == descriptor["sources"],
              "macos_original_source_admission_invalid")
        self.custody = _OriginalMacCustody(self.root, fixture_id, descriptor, pin)
        try:
            self.binding = original_binding
            _need((self.binding.target, self.binding.machine, self.binding.account, self.binding.principal, self.binding.home) ==
                  (self.custody.binding.target, self.custody.binding.machine, str(self.custody.binding.ordinary_uid),
                   self.custody.binding.ordinary_account, self.custody.binding.ordinary_home), "macos_lease_original_target_changed")
            roots = {"/private/var/tmp/vc-recovery-macos-leases": "v1", "/private/var/tmp/vc-recovery-macos-leases-v2": "v2"}
            self._version = roots.get(snapshot["namespace"].get("root"))
            _need(self._version is not None and self.custody.load_lease_namespace(self._version) == snapshot["namespace"],
                  "macos_lease_namespace_changed")
            # Construction is local evidence validation only. The caller's
            # first observation supplies the absolute budget for live custody.
            self._capsule_metadata()
        except BaseException:
            self.custody.close(); raise

    @contextmanager
    def _capsule_input(self):
        path, pin = mac._reference(self._snapshot["capsule"], self.root)
        _need(path.is_relative_to(self.custody.lifecycle_root / "lease-executors"), "macos_lease_capsule_changed")
        with mac.PublicProof(path, pin) as held:
            value = held.value()
            _need(value.get("binding") == self._snapshot["binding"] and value.get("namespace") == self._snapshot["namespace"],
                  "macos_lease_capsule_changed")
            yield held.body, value, pin

    def _capsule_metadata(self):
        with self._capsule_input() as (raw, value, pin):
            proof = qualification.load_metadata(self.custody, self._snapshot["qualification"])
            return self._capsule_proof(raw, value, pin, proof)

    def _capsule(self, *, deadline=None):
        deadline = registry._lease_deadline(deadline, 30)
        with self._capsule_input() as (raw, value, pin):
            proof = qualification.load(self.custody, self._snapshot["qualification"], deadline=deadline)
            return self._capsule_proof(raw, value, pin, proof)

    def _capsule_proof(self, raw, value, pin, proof):
        original = json.loads(proof.raw)
        _need(set(value) == set(original) and value["namespace"] == proof.namespace
              and all(value[key] == original[key] for key in ("schemaVersion", "provider", "bridge", "files"))
              and all(value["binding"][key] == original["binding"][key]
                      for key in ("target", "machine", "account", "principal", "home")),
              "macos_lease_native_producer_changed")
        bridge.observer_source(raw, "inventory", expected_sha256=pin["sha256"])
        return raw

    def _guard(self, deadline):
        _need(_CURRENT_OBSERVER_SOURCES == source_pins(), "macos_lease_original_source_changed")
        self.custody.guard(deadline=deadline)
        _need(self.custody.load_lease_namespace(self._version) == self._snapshot["namespace"], "macos_lease_namespace_changed")
        self._capsule(deadline=deadline)

    def snapshot(self, *, deadline=None):
        self._guard(registry._lease_deadline(deadline, 30))
        return json.loads(json.dumps(self._snapshot))

    def _state(self, operation):
        jobs._uuid(operation)
        directory = self.custody.lifecycle_root / "lease-executors" / "operations" / operation
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        jobs._root(directory)
        return directory

    def _observe(self, action, operation, *, deadline=None):
        _need(action in {"status", "cancel", "reconcile"}, "macos_lease_action_invalid")
        deadline = registry._lease_deadline(deadline)
        self._guard(deadline)
        directory = self._state(operation)
        result = self.custody.original_lease_call(self._capsule(deadline=deadline), action, operation,
                    expected_sha256=self._snapshot["capsule"]["pin"]["sha256"], deadline=deadline)
        # Keep the complete fixed reply before interpreting or asserting it.
        jobs._publish(directory / (str(uuid4()) + ".reply.json"), {
            "operationId": operation, "action": action, "returncode": result.returncode,
            "stdout": base64.b64encode(result.stdout).decode(), "stderr": base64.b64encode(result.stderr).decode()})
        if result.returncode != 0:
            return {"schemaVersion": 1, "operationId": operation, "provider": self.provider,
                    "state": "unknown", "jobState": "unknown", "reason": "macos_original_lease_unresolved",
                    "replayAllowed": False, "nextAction": "resolve_blocker"}
        try: value = json.loads(result.stdout)
        except (ValueError, UnicodeError): raise mac.MacBlocked("macos_original_lease_reply_invalid") from None
        return normalize(value, operation)

    def observe(self, operation_id, *, deadline=None):
        return self._observe("status", operation_id, deadline=deadline)

    def cancel(self, operation_id, *, deadline=None):
        deadline = registry._lease_deadline(deadline)
        original = self.observe(operation_id, deadline=deadline)
        if original.get("jobState") == "terminal" and original.get("restored") is True:
            return original
        return self._observe("cancel", operation_id, deadline=deadline)

    def reconcile(self, operation_id, *, deadline=None):
        deadline = registry._lease_deadline(deadline)
        original = self.observe(operation_id, deadline=deadline)
        if original.get("jobState") == "terminal" and original.get("restored") is True:
            return original
        return self._observe("reconcile", operation_id, deadline=deadline)


class QualifiedMacLeaseExecutor(OriginalMacLeaseExecutor):
    """New work admitted by current custody and immutable native qualifications."""
    def __init__(self, custody, *, deadline=None):
        deadline = registry._lease_deadline(deadline, 30)
        _need(type(custody) is mac.MacCustody, "macos_current_custody_required")
        custody.guard(deadline=deadline)
        reference = custody.descriptor["qualifications"].get("leases")
        _need(reference is not None, "macos_lease_native_qualification_missing")
        proof = qualification.load(custody, reference, deadline=deadline)
        bound = custody._lease_binding(deadline)
        _need((bound.target, bound.machine, bound.account, bound.principal, bound.home) ==
              (proof.binding.target, proof.binding.machine, proof.binding.account, proof.binding.principal, proof.binding.home),
              "macos_lease_qualified_target_changed")
        # Only actual boot/session parameters may advance for a new operation.
        # Qualified executable bytes and the admitted namespace never change.
        value = json.loads(proof.raw); value["binding"] = asdict(bound)
        raw = json.dumps(value,sort_keys=True,separators=(",", ":")).encode()
        key = hashlib.sha256(raw+json.dumps(custody.descriptor_pin,sort_keys=True).encode()).hexdigest()
        directory = custody.lifecycle_root/"lease-executors"/key
        directory.mkdir(mode=0o700,parents=True,exist_ok=True); jobs._root(directory)
        path = directory/"capsule.json"
        try: jobs._create(path,raw)
        except FileExistsError:
            with mac.PublicProof(path, custody._registry._json(path)[1]) as held:
                _need(held.body == raw, "macos_lease_capsule_changed")
        _, pin = custody._registry._json(path)
        snapshot = {"schemaVersion":2,"provider":self.provider,"kind":KIND,"fixtureId":custody.fixture_id,
                    "registration":{"path":str(custody._descriptor_path),"pin":custody.descriptor_pin},
                    "binding":asdict(bound),"namespace":proof.namespace,"capsule":{"path":str(path),"pin":pin},
                    "qualification":reference,"sources":source_pins()}
        super().__init__(custody.root,snapshot)
        self._current = custody

    def submit(self, operation_id, ttl_seconds, *, deadline=None):
        jobs._uuid(operation_id); leases._ttl(ttl_seconds)
        deadline = registry._lease_deadline(deadline)
        with self._current.operator(deadline=deadline):
            original = self.observe(operation_id, deadline=deadline)
            if original.get("state") != "unsubmitted":
                return original
            _need(original.get("reason") == "original_admission_absent", "macos_lease_absence_proof_invalid")
            self._current.guard(deadline=deadline)
            _need(self._current._lease_binding(deadline) == self.binding
                  and self._current.load_lease_namespace("v2") == self._snapshot["namespace"],
                  "macos_lease_current_identity_changed")
            qualification.load(self._current,self._snapshot["qualification"],deadline=deadline)
            raw = self._capsule(deadline=deadline)
            request = {"operationId":operation_id,"ttlSeconds":ttl_seconds,"binding":asdict(self.binding),
                       "namespace":self._snapshot["namespace"],"capsule":self._snapshot["capsule"]}
            path = self._state(operation_id)/"intent.json"
            try: jobs._publish(path,request)
            except FileExistsError:
                _need(jobs._record(path) == request, "macos_original_lease_inputs_changed")
            source = bridge.qualified_acquire_source(raw,expected_sha256=self._snapshot["capsule"]["pin"]["sha256"],
                                                     operation=operation_id,ttl=ttl_seconds)
            argv,payload = protocol.stdin_command(source.decode())
            result = self._current.ordinary_guest_call(self._current.binding,argv,payload,deadline)
            jobs._publish(self._state(operation_id)/(str(uuid4())+".acquire-reply.json"),{
                "operationId":operation_id,"returncode":result.returncode,
                "stdout":base64.b64encode(result.stdout).decode(),"stderr":base64.b64encode(result.stderr).decode()})
            if result.returncode != 0:
                return {"schemaVersion":1,"operationId":operation_id,"provider":self.provider,"state":"unknown",
                        "jobState":"unknown","reason":"macos_original_lease_unresolved","replayAllowed":False,
                        "nextAction":"observe_original"}
            try: value=json.loads(result.stdout)
            except (ValueError,UnicodeError):raise mac.MacBlocked("macos_original_lease_reply_invalid")from None
            return normalize(value,operation_id)


_CURRENT_OBSERVER_SOURCES = source_pins()
if _EXECUTING_CODE != compile(Path(__file__).read_bytes(), __file__, "exec", dont_inherit=True, optimize=sys.flags.optimize):
    raise mac.MacBlocked("macos_lease_executor_executing_source_changed")
