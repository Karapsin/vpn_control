"""Finite VM-tool readiness routes derived from the actual native adapters.

This boundary does not replace native request, artifact, original-operation or
ownership validation. Call it after those pure gates and before generating the
remote packet. It restores transport for original observers without starting,
unlocking or rebooting their VM. Unknown target metadata never selects a default.
"""
from __future__ import annotations

from contextlib import contextmanager, ExitStack
from contextvars import ContextVar
from dataclasses import dataclass, replace
import json
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType
from uuid import UUID, uuid4

from . import committed_source
from . import private_inventory_lock as private
from . import readiness
from . import readiness_fixture_registry as fixtures
from . import readiness_gui_lease as gui_leases
from . import ssh_dispatch_admission
from . import ssh_transport
from . import tool_action_policy as policies
from .native_vm_spec import FreshWindowsVmSpec


_SOURCE = Path(__file__).absolute()
_EXECUTING = sys._getframe().f_code
_RAW, _GENERATION, _DIGEST = policies._capture(_SOURCE)
if _EXECUTING != compile(_RAW, __file__, "exec", dont_inherit=True, optimize=sys.flags.optimize):
    raise ValueError("vm_readiness_executing_source_mismatch")
_SOURCE_PIN = (_GENERATION, _DIGEST)
_MANIFEST = _SOURCE.with_suffix(".json")
_MANIFEST_RAW, _MANIFEST_GENERATION, _MANIFEST_DIGEST = policies._capture(_MANIFEST)
_MANIFEST_PIN = (_MANIFEST_GENERATION, _MANIFEST_DIGEST)
_MODULE = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_SYMBOL = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}(?:\.[A-Za-z_][A-Za-z0-9_]{0,127}){0,3}\Z")
_PROOFS = frozenset({"host-constant", "validated-host"})
_KINDS = frozenset({"fixed_host", "selected_host", "windows_deployment", "registered_tart",
                    "hosted_boundary", "provider_boundary", "facade", "phase"})
# A closure member: a repository path under agent_tools/ or scripts/ (dispatch_source_closure).
_CLOSURE_PATH = re.compile(r"(?:agent_tools|scripts)(?:/[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}){1,4}\Z")
# Requirement-free classes that still reach a guest or a native host: their source is checked too (TEST-005).
SOURCE_CHECKED_PHASES = frozenset({"intentional_phase"})
# Read-only observation of a job: it may run on a later local commit when the job's submit SHA was published.
OBSERVATIONS = frozenset({"remote_observation", "readiness_observation", "local_observation"})
_SUBMITS = (".rag_index", "dispatch-source")
_ACTIVE = ContextVar("vm_dispatch_admission", default=())
# Replaceable only by tests, whose checkouts need not be published. The
# committed-source rule itself is covered by test_committed_source.
_require_committed = committed_source.require_published_tree


class DispatchBlocked(readiness.ReadinessBlocked):
    pass


def _need(condition, operation, reason="vm_readiness_target_unavailable"):
    if not condition:
        raise DispatchBlocked(reason, operation)


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("vm_readiness_duplicate_field")
        value[key] = item
    return value


def _parse_manifest():
    value = json.loads(_MANIFEST_RAW, object_pairs_hook=_unique)
    # No source digests. The closure is CI-computed (dispatch_source_closure)
    # and admitted only when committed and published (committed_source); a
    # fixed-host proof names the symbol holding its host. Schema 3: a closure is
    # a list of repository paths, and equal closures are one shared list
    # (closures) that a row names by id.
    if (type(value) is not dict or set(value) != {"schemaVersion", "closures", "actions"} or value["schemaVersion"] != 3
            or type(value["closures"]) is not dict):
        raise ValueError("vm_readiness_manifest_invalid")
    shared = value.pop("closures")
    for action, row in value["actions"].items():
        if type(row) is dict and type(row.get("closure")) is str:
            if type(shared.get(row["closure"])) is not list:
                raise ValueError("vm_readiness_manifest_invalid")
            row["closure"] = list(shared[row["closure"]])
    for action, row in value["actions"].items():
        if type(action) is not str or type(row) is not dict or row.get("kind") not in _KINDS:
            raise ValueError("vm_readiness_manifest_invalid")
        fields = {"kind", "modules", "closure"} | ({"host", "proof"} if row["kind"] == "fixed_host" else set())
        if set(row) != fields or type(row["modules"]) is not list or type(row["closure"]) is not list:
            raise ValueError("vm_readiness_manifest_invalid")
        if any(type(m) is not str or not _MODULE.fullmatch(m) for m in row["modules"]):
            raise ValueError("vm_readiness_manifest_invalid")
        if any(type(m) is not str or not _CLOSURE_PATH.fullmatch(m) or ".." in m.split("/") for m in row["closure"]):
            raise ValueError("vm_readiness_manifest_invalid")
        if not {"agent_tools/" + m + ".py" for m in row["modules"]} <= set(row["closure"]):
            raise ValueError("vm_readiness_manifest_invalid")
        if row["kind"] == "fixed_host":
            proof = row["proof"]
            if (type(row["host"]) is not str or not _ALIAS.fullmatch(row["host"])
                    or type(proof) is not dict or set(proof) != {"module", "symbol", "kind"}
                    or proof["kind"] not in _PROOFS or "agent_tools/" + str(proof["module"]) + ".py" not in row["closure"]
                    or type(proof["symbol"]) is not str or not _SYMBOL.fullmatch(proof["symbol"])):
                raise ValueError("vm_readiness_manifest_invalid")
    return value


_DOCUMENT = _parse_manifest()
ROUTES = MappingProxyType({action: MappingProxyType({
    **row, "modules": tuple(row["modules"]), "closure": tuple(row["closure"]),
    **({"proof": MappingProxyType(dict(row["proof"]))} if "proof" in row else {})})
    for action, row in _DOCUMENT["actions"].items()})
del _DOCUMENT


def _guard():
    for path, pin in ((_SOURCE, _SOURCE_PIN), (_MANIFEST, _MANIFEST_PIN)):
        _, generation, digest = policies._capture(path)
        if (generation, digest) != pin:
            raise ValueError("vm_readiness_loaded_source_changed")


def audit_sources():
    """CI rejects unclassified actions and closure members without a source file.

    Closure equality and proof symbols are CI tests (dispatch_source_closure);
    review of the bytes is the committed-source rule at dispatch.
    """
    _guard()
    expected = {action for (surface, action), policy in policies.CATALOG.items()
                if surface == "vm_workflow" and (policy.requirements or policy.classification in SOURCE_CHECKED_PHASES)}
    if expected != set(ROUTES):
        raise ValueError("vm_readiness_action_unclassified")
    phases = {action for action, row in ROUTES.items() if row["kind"] == "phase"}
    if phases != {action for action in expected if not policies.action_policy("vm_workflow", action).requirements}:
        raise ValueError("vm_readiness_action_unclassified")
    nodes = {path for row in ROUTES.values() for path in row["closure"]}
    missing = sorted(path for path in nodes if not (_SOURCE.parent.parent / path).is_file())
    if missing:
        raise ValueError("vm_readiness_target_source_missing:" + ",".join(missing))
    return {"ok": True, "actions": len(ROUTES), "sourceNodes": len(nodes)}


def _operation(inputs):
    for name in ("operationId", "correlationId", "deploymentId", "recoveryCorrelationId"):
        value = inputs.get(name)
        try:
            if type(value) is str and str(UUID(value)) == value:
                return value
        except ValueError:
            pass
    # Recovery identity is separate from any opaque original job identifier.
    return str(uuid4())


def _host(value, operation):
    _need(type(value) is str and bool(_ALIAS.fullmatch(value)), operation, "vm_readiness_host_invalid")
    return value


def _original(root, parts, operation):
    """Read fixed private paths only, never an input-supplied evidence path."""
    path = root.joinpath(*parts)
    try:
        presented = private.PresentedPath(path.parent)
        with private.Directory(presented.canonical) as parent, private.Snapshot(parent, path.name) as held:
            value = json.loads(held.body, object_pairs_hook=_unique)
            _need(type(value) is dict, operation)
            held.guard(); presented.guard()
            return value
    except (OSError, ValueError, TypeError):
        raise DispatchBlocked("vm_readiness_original_metadata_unavailable", operation) from None


_ORIGINAL_HOSTS = MappingProxyType({
    "android_cli_stage": (".rag_index", "android-cli-stages", "{id}", "intent.json"),
    "android_vpn_permission_reset": (".rag_index", "android-vpn-permission-reset", "{id}.json"),
    "android_proxy_recovery": (".rag_index", "android-proxy-recovery", "{id}.json"),
    "windows_credential_probe_ssh": (".rag_index", "windows-credential-probe-ssh", "{id}.json"),
    "windows_credential_recovery_ssh": (".runtime", "native-credentials", "recovery", "{id}.json"),
    "native_scenario_execution": (".rag_index", "native-scenario-executions", "{id}.json"),
})


def _selected_host(root, inputs, row, operation):
    if "host" in inputs:
        return _host(inputs["host"], operation)
    identity = inputs.get("correlationId")
    try:
        _need(type(identity) is str and str(UUID(identity)) == identity, operation)
    except ValueError:
        raise DispatchBlocked("vm_readiness_target_unavailable", operation) from None
    candidates = []
    for module in row["modules"]:
        template = _ORIGINAL_HOSTS.get(module)
        if template is None:
            continue
        record = _original(root, tuple(part.format(id=identity) for part in template), operation)
        if module == "native_scenario_execution":
            record = record.get("plan")
        _need(type(record) is dict and record.get("correlationId") == identity, operation)
        candidates.append(_host(record.get("host"), operation))
    _need(bool(candidates) and len(set(candidates)) == 1, operation)
    return candidates[0]


def _deployment_host(root, inputs, operation):
    if "spec" in inputs:
        try:
            return FreshWindowsVmSpec.parse(inputs["spec"]).host
        except (ValueError, TypeError, KeyError):
            raise DispatchBlocked("vm_readiness_deployment_invalid", operation) from None
    identity = inputs.get("deploymentId")
    try:
        _need(type(identity) is str and str(UUID(identity)) == identity, operation)
    except ValueError:
        raise DispatchBlocked("vm_readiness_deployment_invalid", operation) from None
    record = _original(root, (".rag_index", "windows-vm-deploy-intents", identity + ".intent.json"), operation)
    _need(set(record) == {"spec", "setup", "context", "correlationId", "mode", "callerSha256"}
          and record["mode"] == "start", operation, "vm_readiness_deployment_invalid")
    try:
        spec = FreshWindowsVmSpec.parse(record["spec"])
    except (ValueError, TypeError, KeyError):
        raise DispatchBlocked("vm_readiness_deployment_invalid", operation) from None
    _need(spec.deployment_id == identity, operation, "vm_readiness_deployment_invalid")
    return spec.host


def _fixture_candidates(root, operation):
    """Only internally qualified registration IDs are discoverable here."""
    directory = root / ".rag_index" / "readiness-fixtures"
    try:
        presented = private.PresentedPath(directory)
        with private.Directory(presented.canonical) as held:
            names = os.listdir(held.fd)
            _need(len(names) <= 256, operation, "vm_readiness_fixture_inventory_unavailable")
            result = []
            for name in sorted(names):
                if name.endswith(".json"):
                    fixture_id = name[:-5]
                    fixtures._id(fixture_id)
                    try:
                        result.append((fixture_id, fixtures.registered_fixture(root, fixture_id)))
                    except (ValueError, OSError, TypeError, KeyError):
                        # Historical registrations/source generations are not
                        # current authority and cannot be repaired by lookup.
                        continue
            held.guard(); presented.guard()
            return result
    except (ValueError, OSError, TypeError):
        raise DispatchBlocked("vm_readiness_fixture_unqualified", operation) from None


def _guest_fixture(root, action, host, inputs, operation):
    device = inputs.get("device")
    _need(type(device) is str and bool(_ALIAS.fullmatch(device)), operation, "vm_readiness_device_invalid")
    config = ssh_transport.load_config(root)
    target = config.hosts.get(host)
    profile = None if target is None else target.android_devices.get(device)
    _need(profile is not None, operation, "vm_readiness_device_unconfigured")
    # The matcher compares actual private host/ADB/serial/AVD custody. The
    # current local fixture cannot impersonate an unconfigured SSH device.
    matches = []
    selector = {"host": host, "device": device, "profile": profile}
    for fixture_id, fixture in _fixture_candidates(root, operation):
        matcher = getattr(fixture.adapter.backend, "native_selector_matches", None)
        if callable(matcher):
            try:
                if matcher(action, selector) is True:
                    matches.append((fixture_id, fixture))
            except (ValueError, TypeError, KeyError, AttributeError, OSError):
                continue
    _need(len(matches) == 1, operation, "vm_readiness_device_unqualified")
    return matches[0]


def _tart_fixture(root, inputs, operation, *, action=None):
    context = inputs.get("environmentContext")
    contextual = context.get("vmName") if type(context) is dict else None
    explicit = inputs.get("vmName")
    if explicit is not None and contextual is not None:
        _need(explicit == contextual, operation, "vm_readiness_target_mismatch")
    name = explicit if explicit is not None else contextual
    if action == "macos-machine-server-stop-start":
        _need(type(explicit) is str and bool(explicit), operation, "vm_readiness_tart_context_unavailable")
    elif action in {"macos-machine-server-stop-status", "macos-machine-server-stop-collect"}:
        from . import macos_machine_server_stop
        try:
            original = macos_machine_server_stop.original_vm_name(root, inputs.get("correlationId"))
        except (ValueError, OSError, TypeError, KeyError):
            raise DispatchBlocked("vm_readiness_original_metadata_unavailable", operation) from None
        _need(name is None or name == original, operation, "vm_readiness_target_mismatch")
        name = original
    _need(type(name) is str and name, operation, "vm_readiness_tart_context_unavailable")
    matches = []
    for fixture_id, fixture in _fixture_candidates(root, operation):
        try:
            if fixtures.dispatch_binding(fixture, "tart") == {"vmName": name}:
                matches.append((fixture_id, fixture))
        except (ValueError, TypeError, AttributeError, KeyError, OSError):
            continue
    _need(len(matches) == 1, operation, "vm_readiness_fixture_unqualified")
    return matches[0]


@dataclass(frozen=True)
class DispatchPlan:
    root: Path
    action: str
    operation_identity: str
    host: str | None
    fixture_id: str | None = None
    fixture: object = None
    boundary: str | None = None
    source: object = None


def resolve(root, action, inputs):
    """Metadata/ownership selection with no VM connection or input effects; the committed-source check may ask origin
    for its ci/* tips (a bounded git ls-remote) when neither origin/dev nor the gate ledger publishes the source."""
    _guard()
    if type(inputs) is not dict:
        raise ValueError("vm_readiness_inputs_invalid")
    root = Path(root).resolve(strict=True)
    operation = _operation(inputs)
    policy = policies.action_policy("vm_workflow", action)
    if not policy.requirements:
        if policy.classification not in SOURCE_CHECKED_PHASES:
            return DispatchPlan(root, action, operation, None, boundary="observation_only")
        # A requirement-free phase (scenario-start, batch-start, baseline-restore, ...) still reaches a guest or a
        # native host, so its source is checked like every routed action's.
        row = ROUTES.get(action)
        _need(row is not None and row["kind"] == "phase", operation, "vm_readiness_action_unclassified")
        return DispatchPlan(root, action, operation, None, boundary="observation_only",
                            source=_committed(row, operation, root=root, policy=policy, inputs=inputs))
    row = ROUTES.get(action)
    _need(row is not None, operation, "vm_readiness_action_unclassified")
    kind = row["kind"]
    if kind in {"facade", "hosted_boundary", "provider_boundary"}:
        return DispatchPlan(root, action, operation, None, boundary=kind,
                            source=_committed(row, operation, root=root, policy=policy, inputs=inputs))
    if kind == "registered_tart":
        fixture_id, fixture = _tart_fixture(root, inputs, operation, action=action)
        plan = DispatchPlan(root, action, operation, None, fixture_id, fixture)
    else:
        if kind == "windows_deployment":
            host = _deployment_host(root, inputs, operation)
        elif kind == "fixed_host":
            host = _host(row["host"], operation)
            if "host" in inputs:
                _need(_host(inputs["host"], operation) == host, operation, "vm_readiness_target_mismatch")
        else:
            host = _selected_host(root, inputs, row, operation)
        config = ssh_transport.load_config(root)
        _need(host in config.hosts, operation, "vm_readiness_host_unconfigured")
        if policy.requirements - {"transport"}:
            fixture_id, fixture = _guest_fixture(root, action, host, inputs, operation)
            plan = DispatchPlan(root, action, operation, host, fixture_id, fixture)
        else:
            plan = DispatchPlan(root, action, operation, host)
    return replace(plan, source=_committed(row, operation, root=root, policy=policy, inputs=inputs))


def _input_identity(inputs):
    """The job identity a caller named (the one its later status, collect or reconcile names too), or None."""
    if type(inputs) is not dict:
        return None
    for name in ("operationId", "correlationId", "deploymentId", "recoveryCorrelationId"):
        value = inputs.get(name)
        try:
            if type(value) is str and str(UUID(value)) == value:
                return value
        except ValueError:
            pass
    return None


def _committed(row, operation, *, root=None, policy=None, inputs=None):
    """agent_tools/ (without tests/) and every closure file are clean and published (committed_source, TEST-005).

    A read-only observation of a job whose submit recorded a published SHA (record_submit) is not refused because
    that SHA's ci/* branch was deleted or a local commit followed: it checks the recorded submit SHA instead.
    """
    try:
        return _require_committed(_SOURCE.parent.parent, list(row["closure"]))
    except committed_source.SourceNotCommitted as error:
        identity = _input_identity(inputs)
        if (error.reason == committed_source.UNPUBLISHED and identity is not None and root is not None
                and policy is not None and policy.classification in OBSERVATIONS):
            record = _submit_record(root, identity)
            if record is not None and committed_source.commit_exists(_SOURCE.parent.parent, record["reference"]):
                return {"reference": record["reference"], "basis": "submit-record", "head": None,
                        "submitHead": record["head"], "submitBasis": record["basis"]}
        reason = ("vm_readiness_target_source_unpublished" if error.reason == committed_source.UNPUBLISHED
                  else "vm_readiness_target_source_uncommitted")
        raise DispatchBlocked(reason, operation) from None


_RECORD_FIELDS = frozenset({"schemaVersion", "identity", "action", "reference", "basis", "head"})
_SHA = re.compile(r"[0-9a-f]{40}\Z")


def _submits(root, create=False):
    directory = Path(root).joinpath(*_SUBMITS)
    if create:
        directory.parent.mkdir(mode=0o700, exist_ok=True)
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise OSError("dispatch_source_directory_unsafe")
    return directory


def _submit_record(root, identity):
    """The published source a submission of `identity` ran from, or None."""
    try:
        path = _submits(root) / (identity + ".json")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                return None
            raw = os.read(descriptor, 4097)
        finally:
            os.close(descriptor)
        value = json.loads(raw, object_pairs_hook=_unique)
    except (OSError, ValueError):
        return None
    if (type(value) is not dict or set(value) != _RECORD_FIELDS or value["schemaVersion"] != 1 or value["identity"] != identity
            or type(value["reference"]) is not str or not _SHA.fullmatch(value["reference"])
            or type(value["head"]) is not str or not _SHA.fullmatch(value["head"])
            or value["basis"] not in (committed_source.BASIS_DEV, committed_source.BASIS_LEDGER, committed_source.BASIS_REMOTE)):
        return None
    return value


def record_submit(root, action, inputs, source):
    """Record, create-only, the published SHA a submitting dispatch of a named job ran from (the job's submit SHA)."""
    identity = _input_identity(inputs)
    if (identity is None or type(source) is not dict or source.get("basis") not in
            (committed_source.BASIS_DEV, committed_source.BASIS_LEDGER, committed_source.BASIS_REMOTE)):
        return None
    record = {"schemaVersion": 1, "identity": identity, "action": action, "reference": source["reference"],
              "basis": source["basis"], "head": source["head"]}
    try:
        path = _submits(root, create=True) / (identity + ".json")
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return _submit_record(root, identity)  # The first submit of a job is the one that ran.
    except OSError:
        return None
    try:
        os.write(descriptor, (json.dumps(record, sort_keys=True) + "\n").encode())
    finally:
        os.close(descriptor)
    return record


def revalidate_current(root, *, family, expected_binding):
    """Pure final fence for non-SSH native carriers and GUI input."""
    wanted = Path(root).resolve(strict=True)
    for plan, guards in reversed(_ACTIVE.get()):
        if plan.root != wanted or plan.fixture is None:
            continue
        _need(fixtures.dispatch_binding(plan.fixture, family) == expected_binding,
              plan.operation_identity, "vm_readiness_target_mismatch")
        for guard in guards:
            guard()
        _guard()
        return
    raise DispatchBlocked("vm_dispatch_admission_missing", str(uuid4()))


class _AdmissionContext:
    """Source-owned capability; the loader guards entry and final cleanup."""

    def __init__(self, manager):
        self._manager = manager

    def __enter__(self):
        return self._manager.__enter__()

    def __exit__(self, *error):
        return self._manager.__exit__(*error)


def admitted_dispatch(root, action, inputs, *, deadline=None):
    return _AdmissionContext(_admitted_dispatch(root, action, inputs, deadline=deadline))


@contextmanager
def _admitted_dispatch(root, action, inputs, *, deadline=None):
    """Normal MCP/CLI native boundary, after existing pure admission gates."""
    plan = resolve(root, action, inputs)
    policy = policies.action_policy("vm_workflow", action)
    with ExitStack() as stack:
        guards = []
        transport_admission = None
        if plan.host is not None:
            transport_admission = stack.enter_context(ssh_transport.admitted_transport(plan.root, plan.host, plan.operation_identity, deadline=deadline))
        if plan.fixture is not None:
            context = plan.fixture.context(deadline=deadline)
            intentional = frozenset() if policy.expected_test_state == "default" else frozenset({policy.expected_test_state})
            requirements = readiness.Requirements(policy.requirements, policy.permitted_recoveries, intentional)
            ready = readiness.ensure_ready(context, requirements, plan.operation_identity)
            readiness.revalidate(context, ready)
            guards.append(lambda: readiness.revalidate(context, ready))
            if "interactive_desktop" in policy.requirements and policy.expected_test_state == "default":
                lease = gui_leases.acquire(plan.root, plan.fixture_id, plan.operation_identity, ready, deadline=deadline)
                stack.callback(lease.cancel, deadline=deadline)
                guards.append(lease.guard)
            if transport_admission is not None:
                for guard in guards:
                    ssh_dispatch_admission.add_dispatch_guard(transport_admission, guard)
        _guard()
        if policy.classification not in OBSERVATIONS:
            record_submit(plan.root, action, inputs, plan.source)
        token = _ACTIVE.set((*_ACTIVE.get(), (plan, tuple(guards))))
        try:
            yield plan
            _guard()
        finally:
            _ACTIVE.reset(token)
