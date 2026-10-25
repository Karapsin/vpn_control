"""Readiness admission for finite direct visual entrypoints.

Public selection is a private registered fixture ID. Endpoint values come from
the registered provider, never from an ownership assertion or an arbitrary
command. Admission precedes command generation; every dispatch rechecks both
the original registration and the actual boot/account/session identities.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import argparse
import json
import os
from pathlib import Path
import stat
import sys
from types import MappingProxyType
from typing import Callable, Mapping
from uuid import UUID, uuid4

from . import readiness
from . import private_inventory_lock as private
from . import readiness_fixture_registry as fixtures
from . import readiness_gui_lease as gui_leases
from . import tool_action_policy as policies


_EXECUTING_CODE = sys._getframe().f_code
_SOURCE_PATH = Path(__file__).absolute()
_SOURCE_BYTES, _SOURCE_GENERATION, _SOURCE_DIGEST = policies._capture(_SOURCE_PATH)
if _EXECUTING_CODE != compile(_SOURCE_BYTES, __file__, "exec", dont_inherit=True, optimize=sys.flags.optimize):
    raise ValueError("entrypoint_executing_source_mismatch")
_SOURCE_PIN = (_SOURCE_GENERATION, _SOURCE_DIGEST)


def _guard_self():
    _, generation, digest = policies._capture(_SOURCE_PATH)
    if (generation, digest) != _SOURCE_PIN:
        raise ValueError("entrypoint_source_changed")


_FAMILIES = MappingProxyType({
    "capture_visual_android": "android",
    "android_installer_lifecycle": "android",
    "capture_visual_macos_tart": "tart",
    "capture_visual_windows_qemu": "qmp",
})
_PLATFORMS = MappingProxyType({"android": "android", "macos": "tart", "windows": "qmp", "linux": "tart"})
_FIELDS = MappingProxyType({
    "android": frozenset({"adb", "serial", "avd", "serverPort"}),
    "tart": frozenset({"vmName"}),
    "qmp": frozenset({"qmpSocket"}),
    "libvirt": frozenset({"uri", "domain"}),
})


class EntrypointBlocked(readiness.ReadinessBlocked):
    """A finite blocker; private registration exceptions never escape."""


def _operation(value):
    if value is None:
        return str(uuid4())
    if type(value) is not str:
        raise ValueError("entrypoint_operation_invalid")
    try:
        valid = str(UUID(value)) == value
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("entrypoint_operation_invalid")
    return value


def _binding(fixture, family, operation):
    try:
        value = fixtures.dispatch_binding(fixture, family)
        if type(value) is not dict or set(value) != _FIELDS[family]:
            raise ValueError("invalid_binding")
        for key, item in value.items():
            if key == "serverPort":
                if type(item) is not int or not 1024 <= item <= 65535:
                    raise ValueError("invalid_binding")
            elif type(item) is not str or not item or "\x00" in item or "\n" in item:
                raise ValueError("invalid_binding")
        for key in {"adb", "qmpSocket"} & value.keys():
            if not Path(value[key]).is_absolute():
                raise ValueError("invalid_binding")
        return value
    except (ValueError, TypeError, KeyError, AttributeError, OSError):
        raise EntrypointBlocked("fixture_entrypoint_unqualified", operation) from None


def _registered(root, fixture_id, operation):
    try:
        return fixtures.registered_fixture(root, fixture_id)
    except (ValueError, TypeError, KeyError, OSError):
        raise EntrypointBlocked("fixture_entrypoint_unqualified", operation) from None


def _registration_pin(root, fixture_id, operation):
    try:
        # Only a validated registry ID forms a filename.
        fixtures._id(fixture_id)
        return fixtures._json(root / ".rag_index" / "readiness-fixtures" / (fixture_id + ".json"))[1]
    except (ValueError, TypeError, KeyError, OSError):
        raise EntrypointBlocked("fixture_entrypoint_unqualified", operation) from None


def _target(value, family, operation):
    prefix = {"android": "android:", "tart": "tart:", "qmp": "qemu:", "libvirt": "libvirt:"}.get(family)
    if (type(value) is not str or not prefix or not value.startswith(prefix) or len(value) > 4096
            or not value[len(prefix):] or any(ord(char) < 32 for char in value)):
        raise EntrypointBlocked("entrypoint_target_required", operation)
    if family == "qmp" and not Path(value[len(prefix):]).is_absolute():
        raise EntrypointBlocked("entrypoint_target_invalid", operation)
    return value


def _target_matches(fixture, family, expected, operation):
    _target(expected, family, operation)
    try:
        actual = fixtures.explicit_target(fixture, family)
    except Exception:
        raise EntrypointBlocked("fixture_target_authority_unavailable", operation) from None
    if actual != expected:
        raise EntrypointBlocked("fixture_entrypoint_target_mismatch", operation)


def bound_target(root, surface, target, *, fixture_id=None, platform=None):
    """Pure target/ownership inspection for direct observers; no recovery."""
    _guard_self()
    operation = _operation(None)
    family = _FAMILIES.get(surface) or (_PLATFORMS.get(platform) if surface == "visual_platform" else None)
    _target(target, family, operation)
    fixture = _registered(Path(root).resolve(strict=True), fixture_id, operation)
    binding = _binding(fixture, family, operation)
    _target_matches(fixture, family, target, operation)
    return binding


@dataclass(frozen=True)
class Admission:
    root: Path
    surface: str
    action: str
    operation_identity: str
    fixture_id: str | None
    family: str | None
    binding: Mapping[str, object]
    registration_pin: object = None
    context: readiness.Context | None = None
    ready: readiness.ReadyContext | None = None
    gui_lease: object = None
    expected_target: str | None = None
    _state: dict = field(default_factory=lambda: {"closed": False}, compare=False, repr=False)

    def revalidate(self):
        """Pure observation immediately before each command or GUI packet."""
        _guard_self()
        if self._state["closed"]:
            raise EntrypointBlocked("prepared_context_closed", self.operation_identity)
        policy = policies.action_policy(self.surface, self.action)
        if self.context is None:
            if policy.requirements:
                raise EntrypointBlocked("entrypoint_policy_changed", self.operation_identity)
            return
        fixture = _registered(self.root, self.fixture_id, self.operation_identity)
        if _registration_pin(self.root, self.fixture_id, self.operation_identity) != self.registration_pin:
            raise EntrypointBlocked("fixture_entrypoint_changed", self.operation_identity)
        if _binding(fixture, self.family, self.operation_identity) != dict(self.binding):
            raise EntrypointBlocked("fixture_entrypoint_changed", self.operation_identity)
        if self.expected_target is not None:
            _target_matches(fixture, self.family, self.expected_target, self.operation_identity)
        elif self.family == "qmp":
            raise EntrypointBlocked("fixture_target_authority_unavailable", self.operation_identity)
        readiness.revalidate(self.context, self.ready)
        if self.gui_lease is not None:
            self.gui_lease.guard()

    def close(self):
        """Cancel only this original temporary lease, even after stale input."""
        try:
            if self.gui_lease is not None:
                self.gui_lease.cancel(deadline=self.context.deadline if self.context else None)
        finally:
            self._state["closed"] = True

    def dispatch(self, operation: Callable, *args, **kwargs):
        """Submit once; an exception never causes this layer to replay input."""
        self.revalidate()
        try:
            return operation(*args, **kwargs)
        except Exception:
            self._state["closed"] = True
            raise EntrypointBlocked("direct_dispatch_outcome_unknown", self.operation_identity) from None

    def run(self, build: Callable, dispatch: Callable):
        """Build only after admission, then revalidate the generated packet."""
        packet = build(self.binding)
        return self.dispatch(dispatch, packet)

    def vnc_action(self, commands, *, timeout=120):
        """One input submission through the qualified private guest executor.

        That executor owns authentication and its protected credential FD. A
        lost reply is an unknown original input outcome, never a retry signal.
        """
        if self.family != "tart" or type(commands) not in (tuple, list) or not commands or len(commands) > 128:
            raise ValueError("entrypoint_vnc_action_invalid")
        if any(type(item) is not str or len(item) > 8192 or "\x00" in item for item in commands):
            raise ValueError("entrypoint_vnc_action_invalid")
        if type(timeout) is not int or not 1 <= timeout <= 600:
            raise ValueError("entrypoint_vnc_action_invalid")
        self.revalidate()
        fixture = _registered(self.root, self.fixture_id, self.operation_identity)
        executor = getattr(fixture.adapter.backend, "vnc_action", None)
        if not callable(executor):
            raise EntrypointBlocked("qualified_vnc_executor_unavailable", self.operation_identity)
        try:
            executor(tuple(commands), self.operation_identity, self.ready, timeout)
        except readiness.ReadinessBlocked:
            self._state["closed"] = True
            raise
        except Exception:
            self._state["closed"] = True
            raise EntrypointBlocked("direct_input_outcome_unknown", self.operation_identity) from None

    def ordinary_account_name(self):
        self.revalidate()
        fixture = _registered(self.root, self.fixture_id, self.operation_identity)
        observer = getattr(fixture.adapter.backend, "ordinary_account_name", None)
        if not callable(observer):
            raise EntrypointBlocked("qualified_account_observer_unavailable", self.operation_identity)
        try:
            account = observer(self.ready)
            if type(account) is not str or not account or len(account) > 128 or any(not (c.isalnum() or c in "_.-") for c in account):
                raise ValueError("invalid_account")
            return account
        except readiness.ReadinessBlocked:
            raise
        except Exception:
            raise EntrypointBlocked("qualified_account_observer_unavailable", self.operation_identity) from None

    def reboot_guest(self):
        self.revalidate()
        if self.gui_lease is not None:
            self.gui_lease.cancel(deadline=self.context.deadline)
            # Cancellation changes only the lease. Reclose the actual guest
            # before the provider's full positive-idle/power admission.
            readiness.revalidate(self.context, self.ready)
        fixture = _registered(self.root, self.fixture_id, self.operation_identity)
        executor = getattr(fixture.adapter.backend, "idle_reboot", None)
        if not callable(executor):
            raise EntrypointBlocked("qualified_reboot_executor_unavailable", self.operation_identity)
        renewed = None
        try:
            # The qualified provider owns positive idle proof and durable
            # once-only power admission; this layer never submits shutdown.
            recovery_id = executor(self.operation_identity, self.ready)
            if type(recovery_id) is not str:
                raise EntrypointBlocked("direct_power_outcome_unknown", self.operation_identity)
            recovery_id = _operation(recovery_id)
            # The fixed observer reopens the original private provider receipt;
            # callers cannot supply a terminal DTO or assert a successful boot.
            observed_fixture = _registered(self.root, self.fixture_id, self.operation_identity)
            if _registration_pin(self.root, self.fixture_id, self.operation_identity) != self.registration_pin:
                raise EntrypointBlocked("fixture_entrypoint_changed", self.operation_identity)
            observer = getattr(observed_fixture.adapter.backend, "reboot_receipt", None)
            if not callable(observer):
                raise EntrypointBlocked("qualified_reboot_receipt_unavailable", self.operation_identity)
            receipt = observer(recovery_id)
            fields = {"operationId", "recoveryId", "target", "machine", "oldBoot", "newBoot", "state", "result"}
            if (type(receipt) is not dict or set(receipt) != fields or receipt["state"] != "terminal"
                    or receipt["result"] != "rebooted" or receipt["operationId"] != self.operation_identity
                    or receipt["recoveryId"] != recovery_id or receipt["target"] != self.ready.target
                    or receipt["machine"] != self.ready.machine or receipt["oldBoot"] != self.ready.boot
                    or type(receipt["newBoot"]) is not str or not receipt["newBoot"] or receipt["newBoot"] == self.ready.boot):
                raise EntrypointBlocked("direct_power_outcome_unknown", self.operation_identity)
            self._state["closed"] = True
            renewed = admit(self.root, self.surface, self.action, fixture_id=self.fixture_id,
                            operation_identity=self.operation_identity, expected_binding=dict(self.binding),
                            expected_registration_pin=self.registration_pin,
                            expected_identity=(self.ready.target, self.ready.machine),
                            expected_target=self.expected_target,
                            lease_ttl_seconds=self.gui_lease.ttl_seconds if self.gui_lease else gui_leases.DEFAULT_TTL_SECONDS)
            if (renewed.registration_pin != self.registration_pin or renewed.ready.boot != receipt["newBoot"]
                    or observer(recovery_id) != receipt):
                raise EntrypointBlocked("direct_power_outcome_unknown", self.operation_identity)
            renewed.revalidate()
            return renewed
        except readiness.ReadinessBlocked:
            if renewed is not None:
                renewed.close()
            self._state["closed"] = True
            raise
        except Exception:
            if renewed is not None:
                renewed.close()
            self._state["closed"] = True
            raise EntrypointBlocked("direct_power_outcome_unknown", self.operation_identity) from None


def admit(root, surface, action, *, fixture_id=None, operation_identity=None, platform=None,
          expected_binding=None, expected_registration_pin=None, expected_identity=None,
          expected_target=None,
          lease_ttl_seconds=gui_leases.DEFAULT_TTL_SECONDS):
    """Admit a classified entrypoint; local and intentional phases stay inert.

    ``expected_binding`` is an optional equality fence for existing direct
    targets. Omitting it means the caller must use the returned private binding.
    It never grants ownership or supplies a replacement endpoint.
    """
    operation = _operation(operation_identity)
    _guard_self()
    policy = policies.action_policy(surface, action)
    root = Path(root).resolve(strict=True)
    if not policy.requirements:
        return Admission(root, surface, action, operation, None, None, MappingProxyType({}))
    family = _FAMILIES.get(surface)
    if surface == "visual_platform" and action == "capture-local":
        family = _PLATFORMS.get(platform)
    if family is None or type(fixture_id) is not str or not fixture_id:
        raise EntrypointBlocked("fixture_entrypoint_unqualified", operation)
    if expected_target is not None:
        _target(expected_target, family, operation)
    registration_pin = _registration_pin(root, fixture_id, operation)
    if expected_registration_pin is not None and registration_pin != expected_registration_pin:
        raise EntrypointBlocked("fixture_entrypoint_changed", operation)
    fixture = _registered(root, fixture_id, operation)
    binding = _binding(fixture, family, operation)
    if family == "qmp" and expected_target is None:
        try:
            expected_target = _target(fixtures.explicit_target(fixture, family), family, operation)
        except Exception:
            raise EntrypointBlocked("fixture_target_authority_unavailable", operation) from None
    if expected_target is not None:
        _target_matches(fixture, family, expected_target, operation)
    if expected_binding is not None and (type(expected_binding) is not dict or expected_binding != binding):
        raise EntrypointBlocked("fixture_entrypoint_mismatch", operation)
    intentional = frozenset() if policy.expected_test_state == "default" else frozenset({policy.expected_test_state})
    requirements = readiness.Requirements(policy.requirements, policy.permitted_recoveries, intentional)
    context = fixture.context()
    if expected_identity is not None and (context.target, context.machine) != expected_identity:
        raise EntrypointBlocked("fixture_entrypoint_changed", operation)
    ready = readiness.ensure_ready(context, requirements, operation)
    admission = Admission(root, surface, action, operation, fixture_id, family, MappingProxyType(binding),
                          registration_pin, context, ready)
    admission = replace(admission, expected_target=expected_target)
    admission.revalidate()
    if "interactive_desktop" in policy.requirements and policy.expected_test_state == "default":
        lease = gui_leases.acquire(root, fixture_id, operation, ready, ttl_seconds=lease_ttl_seconds,
                                   deadline=context.deadline)
        admission = replace(admission, gui_lease=lease)
        try:
            admission.revalidate()
        except Exception:
            admission.close()
            raise
    return admission


def from_environment(root, surface, action, *, platform=None, expected_binding=None,
                     expected_target=None,
                     lease_ttl_seconds=gui_leases.DEFAULT_TTL_SECONDS):
    """Normal direct CLI selection; values are identifiers, never credentials."""
    return admit(root, surface, action,
                 fixture_id=os.environ.get("VPN_CONTROL_READINESS_FIXTURE_ID"),
                 operation_identity=os.environ.get("VPN_CONTROL_READINESS_OPERATION_ID"),
                 platform=platform, expected_binding=expected_binding, expected_target=expected_target,
                 lease_ttl_seconds=lease_ttl_seconds)


def _source_pins():
    _guard_self()
    paths = (Path(__file__), Path(fixtures.__file__), Path(readiness.__file__), Path(policies.__file__), policies.MANIFEST_PATH,
             Path(gui_leases.__file__), Path(gui_leases.workflow.__file__),
             Path(__file__).with_name("readiness_adb_dispatch.py"))
    return {path.name: fixtures._body(path, private_file=False)[1] for path in paths}


def _receipt_directory(root):
    """Create only fixed private children, relative to guarded directory FDs."""
    current = Path(root).resolve(strict=True)
    for name in (".rag_index", "readiness-entrypoints"):
        presented = private.PresentedPath(current)
        with private.Directory(presented.canonical) as held:
            try:
                os.mkdir(name, 0o700, dir_fd=held.fd)
            except FileExistsError:
                pass
            info = os.stat(name, dir_fd=held.fd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError("entrypoint_receipt_directory_unsafe")
            presented.guard(); held.guard()
        current = current / name
    return current


def persist(admission):
    """Create an immutable guard receipt, never a replay or job authorization."""
    if admission.context is None:
        raise ValueError("entrypoint_receipt_not_required")
    admission.revalidate()
    value = {"schemaVersion": 2, "surface": admission.surface, "action": admission.action,
             "operationId": admission.operation_identity, "fixtureId": admission.fixture_id,
             "family": admission.family, "binding": dict(admission.binding),
             "registrationPin": admission.registration_pin, "identities": list(admission.ready.identities()),
             "sourcePins": _source_pins(), "guiLease": admission.gui_lease.record() if admission.gui_lease else None,
             "expectedTarget": admission.expected_target}
    directory = _receipt_directory(admission.root)
    with private.Directory(directory) as held:
        # Repeated/lost acknowledgement must check the existing admission. It
        # cannot replace it with a newly unlocked/rebooted context.
        descriptor = os.open(admission.operation_identity + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=held.fd)
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.fsync(held.fd); held.guard()
    return {"operationId": admission.operation_identity, "binding": dict(admission.binding)}


def check_persisted(root, operation_identity):
    """Reopen the original admission; never recover or replace stale packets."""
    operation = _operation(operation_identity)
    try:
        root = Path(root).resolve(strict=True)
        directory = root / ".rag_index" / "readiness-entrypoints"
        presented = private.PresentedPath(directory)
        with private.Directory(presented.canonical) as held, private.Snapshot(held, operation + ".json") as snapshot:
            value = json.loads(snapshot.body)
            fields = {"schemaVersion", "surface", "action", "operationId", "fixtureId", "family", "binding",
                      "registrationPin", "identities", "sourcePins", "guiLease", "expectedTarget"}
            if type(value) is not dict or set(value) != fields or value["schemaVersion"] != 2 or value["operationId"] != operation:
                raise ValueError("invalid_receipt")
            if value["sourcePins"] != _source_pins():
                raise EntrypointBlocked("entrypoint_source_changed", operation)
            policy = policies.action_policy(value["surface"], value["action"])
            if not policy.requirements or value["family"] not in _FIELDS or len(value["identities"]) != 6:
                raise ValueError("invalid_receipt")
            fixture = _registered(root, value["fixtureId"], operation)
            context = fixture.context()
            requirements = readiness.Requirements(policy.requirements, policy.permitted_recoveries)
            ready = readiness.ReadyContext(operation, *value["identities"], requirements)
            admission = Admission(root, value["surface"], value["action"], operation, value["fixtureId"], value["family"],
                                  MappingProxyType(value["binding"]), value["registrationPin"], context, ready)
            admission = replace(admission, expected_target=value["expectedTarget"])
            if value["guiLease"] is not None:
                lease = gui_leases.from_record(root, value["guiLease"])
                if (lease.parent_operation != operation or lease.fixture_id != value["fixtureId"]
                        or lease.identities != tuple(value["identities"])):
                    raise ValueError("invalid_gui_lease")
                admission = replace(admission, gui_lease=lease)
            elif "interactive_desktop" in policy.requirements and policy.expected_test_state == "default":
                raise ValueError("missing_gui_lease")
            admission.revalidate()
            snapshot.guard(); presented.guard()
            return {"operationId": operation, "binding": dict(admission.binding)}
    except readiness.ReadinessBlocked:
        raise
    except (ValueError, TypeError, KeyError, OSError):
        raise EntrypointBlocked("entrypoint_receipt_invalid", operation) from None


def finish_persisted(root, operation_identity):
    """Cancel original keep-awake ownership without probing/recovering a guest."""
    operation = _operation(operation_identity)
    root = Path(root).resolve(strict=True)
    path = root / ".rag_index" / "readiness-entrypoints" / (operation + ".json")
    try:
        value, _ = fixtures._json(path)
        if value.get("operationId") != operation or type(value.get("fixtureId")) is not str:
            raise ValueError("invalid_original_admission")
        lease = gui_leases.from_record(root, value["guiLease"])
        if lease.parent_operation != operation or lease.fixture_id != value["fixtureId"]:
            raise ValueError("invalid_original_admission")
        result = lease.cancel()
        return {"operationId": operation, "leaseOperationId": lease.operation_identity,
                "state": result["state"], "jobState": result["jobState"], "restored": result.get("restored", True)}
    except readiness.ReadinessBlocked:
        raise
    except (ValueError, TypeError, KeyError, OSError):
        raise EntrypointBlocked("entrypoint_original_lease_unavailable", operation) from None


def main(argv=None, *, root=None):
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    admission = actions.add_parser("admit")
    admission.add_argument("--surface", choices=tuple(_FAMILIES) + ("visual_platform",), required=True)
    admission.add_argument("--entry-action", choices=("run", "input", "capture-local"), required=True)
    admission.add_argument("--platform", choices=tuple(_PLATFORMS))
    admission.add_argument("--lease-ttl-seconds", type=float, default=gui_leases.DEFAULT_TTL_SECONDS)
    admission.add_argument("--target", required=True)
    check = actions.add_parser("check")
    check.add_argument("--operation-id", required=True)
    finish = actions.add_parser("finish")
    finish.add_argument("--operation-id", required=True)
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1] if root is None else Path(root).resolve(strict=True)
    try:
        policies.action_policy("readiness_entrypoints", args.action)
        if args.action == "finish":
            result = finish_persisted(root, args.operation_id)
        elif args.action == "check":
            result = check_persisted(root, args.operation_id)
        else:
            # A lost admission reply cannot start a fresh readiness attempt for
            # an existing original receipt selected by the same operation ID.
            operation = _operation(os.environ.get("VPN_CONTROL_READINESS_OPERATION_ID"))
            existing = root / ".rag_index" / "readiness-entrypoints" / (operation + ".json")
            if existing.exists() or existing.is_symlink():
                # Check the original, but a fresh direct invocation has no
                # durable owner proving that its earlier input was unsubmitted.
                check_persisted(root, operation)
                raise EntrypointBlocked("entrypoint_admission_already_exists", operation)
            else:
                result = persist(admit(root, args.surface, args.entry_action, fixture_id=os.environ.get("VPN_CONTROL_READINESS_FIXTURE_ID"),
                                       operation_identity=operation, platform=args.platform, expected_target=args.target,
                                       lease_ttl_seconds=args.lease_ttl_seconds))
        print(json.dumps({"ok": True, **result}, sort_keys=True))
        return 0
    except readiness.ReadinessBlocked as error:
        print(json.dumps(error.as_dict(), sort_keys=True))
        return 2
    except (ValueError, TypeError, OSError):
        print(json.dumps({"ok": False, "state": "blocked", "reason": "entrypoint_admission_invalid", "replayAllowed": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
