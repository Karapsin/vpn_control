"""Private registration of the original owned Android instance, no VM effects.

Public clients select only a fixture ID. Registration is an internal custody
step after direct native proof, deriving current kernel/process, AVD and source
identities itself. It cannot turn an unknown launch into permission to replace it.
"""
from dataclasses import dataclass
from contextlib import nullcontext
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from . import durable_remote_job as jobs
from . import private_inventory_lock as private
from . import readiness
from . import readiness_providers as providers

_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,95}\Z")


class FixtureRegistryError(ValueError):
    pass


def _need(condition, reason):
    if not condition:
        raise FixtureRegistryError(reason)


def _lease_deadline(deadline=None, budget=180):
    if deadline is not None:
        _need(type(deadline) in (int, float) and math.isfinite(deadline), "lease_deadline_invalid")
        _need(time.monotonic() < deadline, "lease_deadline")
    return min(time.monotonic() + budget, deadline if deadline is not None else float("inf"))

def _id(value):
    _need(type(value) is str and bool(_ID.fullmatch(value)), "fixture_id_invalid")
    return value


def _body(path, *, private_file=True):
    path = Path(path)
    presented = private.PresentedPath(path.parent)
    with private.Directory(presented.canonical) as directory:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory.fd)
        try:
            info = os.fstat(descriptor)
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1 and
                  not info.st_mode & 0o022 and 0 < info.st_size <= 262144 and
                  (not private_file or stat.S_IMODE(info.st_mode) == 0o600), "fixture_file_unsafe")
            raw = os.read(descriptor, 262145)
            _need(len(raw) == info.st_size and private._generation(os.fstat(descriptor)) == private._generation(info) ==
                  private._generation(os.stat(path.name, dir_fd=directory.fd, follow_symlinks=False)), "fixture_file_changed")
            presented.guard(); directory.guard()
            return raw, {"generation": list(private._generation(info)), "sha256": hashlib.sha256(raw).hexdigest()}
        finally:
            os.close(descriptor)


def _json(path):
    raw, pin = _body(path)
    def pairs(values):
        result = {}
        for key, value in values:
            _need(key not in result, "fixture_duplicate_field")
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    _need(type(value) is dict, "fixture_record_invalid")
    return value, pin


def _run(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=10, check=False)
    _need(result.returncode == 0 and 0 < len(result.stdout) <= 65536, "fixture_process_observation_unavailable")
    return result.stdout.decode("utf-8", errors="strict").strip()


def process_identity(pid):
    """Kernel birth closes PID reuse; command and UID are reclosed around ps."""
    _need(type(pid) is int and pid > 0, "fixture_process_identity_invalid")
    birth = jobs._birth(pid)
    _need(birth is not None, "fixture_process_absent")
    uid = _run(["ps", "-p", str(pid), "-o", "uid="])
    command = _run(["ps", "-ww", "-p", str(pid), "-o", "command="])
    _need(uid.isdigit() and int(uid) == os.geteuid() and jobs._birth(pid) == birth,
          "fixture_process_identity_changed")
    return {"pid": pid, "birth": birth, "uid": int(uid),
            "commandSha256": hashlib.sha256(command.encode()).hexdigest()}


def adb_server_identity(port):
    _need(type(port) is int and 1024 <= port <= 65535, "fixture_adb_port_invalid")
    output = _run(["lsof", "-nP", "-iTCP:" + str(port), "-sTCP:LISTEN", "-Fp"])
    pids = {int(line[1:]) for line in output.splitlines() if line.startswith("p") and line[1:].isdigit()}
    _need(len(pids) == 1, "fixture_adb_server_ambiguous")
    pid = pids.pop()
    executable = _run(["ps", "-p", str(pid), "-o", "comm="])
    _need(Path(executable).name == "adb", "fixture_adb_server_foreign")
    value = process_identity(pid)
    _need(process_identity(pid) == value, "fixture_adb_server_changed")
    return value


def _sources():
    paths = [Path(providers.__file__), Path(__file__), Path(jobs.__file__)]
    return {path.name: _body(path, private_file=False)[1]["sha256"] for path in paths}


def _under(path, parent):
    candidate = Path(path).absolute()
    try:
        candidate.relative_to(parent)
    except ValueError:
        raise FixtureRegistryError("fixture_path_not_owned") from None
    _need(candidate == candidate.resolve(strict=True), "fixture_path_not_owned")
    return candidate


def _binding(value):
    _need(type(value) is dict and set(value) == {"target", "machine", "adb", "avdName", "serial", "serverPort"},
          "fixture_binding_invalid")
    return providers.AndroidBinding(value["target"], value["machine"], Path(value["adb"]),
                                    value["avdName"], value["serial"], value["serverPort"])


def _owner(root, fixture_id, descriptor, descriptor_pin):
    def guard():
        current, pin = _json(root / ".rag_index" / "readiness-fixtures" / (fixture_id + ".json"))
        _need(current == descriptor and pin == descriptor_pin, "fixture_registration_changed")
        _need(_sources() == descriptor["sources"], "fixture_source_changed")
        _need(_body(Path(descriptor["avdConfig"]), private_file=False)[1] == descriptor["avdConfigPin"],
              "fixture_avd_config_changed")
        _need(process_identity(descriptor["emulator"]["pid"]) == descriptor["emulator"], "fixture_emulator_changed")
        observed_server = adb_server_identity(descriptor["binding"]["serverPort"])
        _need(observed_server == descriptor["adbServer"], "fixture_adb_server_changed")
        return "adb:" + str(observed_server["pid"]) + ":" + observed_server["birth"]
    return guard


@dataclass(frozen=True)
class RegisteredFixture:
    target: str
    machine: str
    adapter: providers.ProviderAdapter
    journal_directory: Path
    required_readiness: frozenset[str] = frozenset({"interactive_desktop"})

    def lease_executor(self, *, deadline=None):
        method = getattr(self.adapter.backend, "lease_executor", None)
        _need(callable(method), "fixture_lease_executor_unavailable")
        if deadline is None:
            return method()
        _lease_deadline(deadline)
        return method(deadline=deadline)

    def context(self, *, deadline=None):
        self.journal_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.journal_directory.lstat()
        _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and
              stat.S_IMODE(info.st_mode) == 0o700, "fixture_journal_unsafe")
        return readiness.Context(self.target, self.machine, self.adapter,
                                 readiness.RecoveryJournal(self.journal_directory), deadline=deadline)


def registered_fixture(root, fixture_id, *, deadline=None):
    """Observe the registered original instance; never starts or repairs it."""
    if deadline is not None:
        _lease_deadline(deadline)
    root = Path(root).resolve(strict=True); fixture_id = _id(fixture_id)
    descriptor, pin = _json(root / ".rag_index" / "readiness-fixtures" / (fixture_id + ".json"))
    # Each provider derives custody from its own original native receipts.
    # The public selector never supplies a host, path, account or ownership flag.
    provider = descriptor.get("provider")
    if provider == "android-emulator" and descriptor.get("schemaVersion") == 2:
        from . import readiness_android
        return readiness_android.load_registered_fixture(root, fixture_id, descriptor, pin)
    if provider in {"raw-qemu-linux"}:
        from . import readiness_qemu
        return readiness_qemu.load_registered_fixture(root, fixture_id, descriptor, pin)
    if provider in {"raw-qemu-windows", "libvirt-windows"}:
        from . import readiness_windows
        return readiness_windows.load_registered_fixture(root, fixture_id, descriptor, pin)
    if provider == "tart-macos" and type(descriptor.get("schemaVersion")) is int and descriptor["schemaVersion"] == 3:
        from . import readiness_tart_macos_registry
        return readiness_tart_macos_registry.load_registered_fixture(root, fixture_id, descriptor, pin, deadline=deadline)
    if provider in {"tart-linux", "tart-macos"}:
        from . import readiness_tart
        return readiness_tart.load_registered_fixture(root, fixture_id, descriptor, pin)
    fields = {"schemaVersion", "fixtureId", "provider", "binding", "emulator", "adbServer", "avdConfig",
              "avdConfigPin", "sources", "qualification"}
    _need(set(descriptor) == fields and type(descriptor["schemaVersion"]) is int and descriptor["schemaVersion"] == 1
          and descriptor["fixtureId"] == fixture_id and descriptor["provider"] == "android-emulator", "fixture_descriptor_invalid")
    binding = _binding(descriptor["binding"])
    _under(descriptor["avdConfig"], root / ".runtime")
    guard = _owner(root, fixture_id, descriptor, pin)
    guard()
    qualification = descriptor["qualification"]
    _need(type(qualification) is dict and set(qualification) == {"wakeDisplayProof", "proofPin"}, "fixture_qualification_invalid")
    proof = _under(qualification["wakeDisplayProof"], root / ".runtime")
    _need(_body(proof)[1] == qualification["proofPin"], "fixture_qualification_changed")
    adapter = providers.android_adapter(binding, guard, wake_qualified=True)
    # The actual selected AVD is freshly checked by the ordinary backend.
    adapter.observe(readiness.Requirements(frozenset({"guest_agent"})), time.monotonic() + 30)
    digest = hashlib.sha256(json.dumps([binding.target, binding.machine], separators=(",", ":")).encode()).hexdigest()
    journal = root / ".rag_index" / "readiness-targets" / digest
    return RegisteredFixture(binding.target, binding.machine, adapter, journal)


class _OriginalObservationBackend:
    """An original job can restore transport and observe, never power or input."""
    def __init__(self, backend):
        self._backend=backend
        self.binding,self.adb=backend.binding,backend.adb
        self.capabilities=frozenset({"reconnect"}) & backend.capabilities

    def observe(self,requirements,deadline):
        _need(requirements.required <= {"transport","guest","guest_agent"},"original_fixture_observation_only")
        return self._backend.observe(requirements,deadline)

    def operation_scope(self,*,deadline=None,cancelled=lambda:False):
        method=getattr(self._backend,"operation_scope",None)
        return method(deadline=deadline,cancelled=cancelled) if callable(method) else nullcontext()

    def recover(self,action,recovery_identity,observed,deadline):
        _need(action=="reconnect" and action in self.capabilities,"original_fixture_observation_only")
        return self._backend.recover(action,recovery_identity,observed,deadline)

    def recover_attempt(self,action,recovery_identity,observed,deadline,attempt,dispatch_digest):
        _need(action=="reconnect" and action in self.capabilities,"original_fixture_observation_only")
        method=getattr(self._backend,"recover_attempt",None)
        if callable(method):
            return method(action,recovery_identity,observed,deadline,attempt,dispatch_digest)
        return self.recover(action,recovery_identity,observed,deadline)


def _original_observer(fixture,target,machine):
    _need((fixture.target,fixture.machine)==(target,machine)
          and fixture.adapter.support.lane=="android-emulator","original_fixture_identity_changed")
    backend=_OriginalObservationBackend(fixture.adapter.backend)
    adapter=providers.ProviderAdapter("android-emulator",target,machine,backend)
    return RegisteredFixture(target,machine,adapter,fixture.journal_directory,frozenset({"guest_agent"}))


def registered_fixture_for_original(root,fixture_id,target,machine):
    """Resolve reviewed source custody without changing an original admission.

    Only an exact source-version mismatch may select a newly registered alias.
    Every other descriptor field (including config, endpoints, host and original
    durable generations) must be identical, and the new alias's full live
    custody must pass. The result can only reconnect and observe background work.
    """
    root=Path(root).resolve(strict=True);fixture_id=_id(fixture_id)
    try:
        return _original_observer(registered_fixture(root,fixture_id),target,machine)
    except providers.ProviderError as error:
        if str(error)!="android_lifecycle_spec_changed":
            raise
    from . import readiness_android
    directory=root/".rag_index/readiness-fixtures"
    original,pin=_json(directory/(fixture_id+".json"))
    _need(original.get("schemaVersion")==2 and original.get("provider")=="android-emulator"
          and original.get("fixtureId")==fixture_id
          and (original.get("binding",{}).get("target"),original.get("binding",{}).get("machine"))==(target,machine),
          "original_fixture_identity_changed")
    sources=readiness_android._source_pins()
    _need(original.get("sources")!=sources,"original_fixture_integrity_mismatch")
    identity={key:value for key,value in original.items() if key not in {"sources","fixtureId"}}
    candidates=sorted(directory.glob("*.json"));_need(len(candidates)<=1000,"original_fixture_registry_overflow")
    for path in candidates:
        candidate_id=_id(path.stem)
        if candidate_id==fixture_id:
            continue
        candidate,_=_json(path)
        if (candidate.get("sources")!=sources or candidate.get("fixtureId")!=candidate_id
                or {key:value for key,value in candidate.items() if key not in {"sources","fixtureId"}}!=identity):
            continue
        fixture=registered_fixture(root,candidate_id)  # never suppress a current custody failure
        _need(_json(directory/(fixture_id+".json"))==(original,pin),"original_fixture_integrity_mismatch")
        return _original_observer(fixture,target,machine)
    raise FixtureRegistryError("original_fixture_current_registration_missing")


def register_android_fixture(root, fixture_id, fixture_directory, *, server_port, wake_proof_name, source_proof_name):
    """Internal, observation-only registration from original direct launch receipts.

    There is no MCP/CLI registration endpoint accepting paths or ownership flags.
    A source change needs a fresh native proof and explicit new fixture ID; an
    existing descriptor is immutable and cannot hide an unresolved old operation.
    """
    root = Path(root).resolve(strict=True); fixture_id = _id(fixture_id)
    fixture = _under(fixture_directory, root / ".runtime")
    _need(all(type(name) is str and Path(name).name == name for name in (wake_proof_name, source_proof_name)),
          "fixture_proof_name_invalid")
    actor, _ = _json(fixture / "retry-launch-actor.json")
    intent, _ = _json(fixture / "retry-launch-intent.json")
    identity, _ = _json(fixture / "avd-identity.json")
    _need(set(actor) == {"pid", "startTime", "submitted"} and actor["submitted"] is True,
          "fixture_original_launch_unresolved")
    _need(intent.get("identity") == identity and type(intent.get("argv")) is list and
          identity["name"] in intent["argv"] and "-no-snapshot-load" in intent["argv"] and
          "-no-snapshot-save" in intent["argv"], "fixture_original_intent_mismatch")
    _need(_run(["ps", "-p", str(actor["pid"]), "-o", "lstart="]) == actor["startTime"], "fixture_original_actor_changed")
    emulator = process_identity(actor["pid"])
    avd_home = _under(identity["avdHome"], fixture)
    avd_config = _under(avd_home / (identity["name"] + ".avd") / "config.ini", avd_home)
    sdk = Path(identity["sdk"])
    # Registry aliases/source refreshes must not discard an original recovery's
    # journal. The actual persisted AVD root, not its fixture ID, selects target.
    target = "local-android-" + hashlib.sha256(str(avd_config.parent).encode()).hexdigest()[:24]
    binding_data = {"target": target, "machine": identity["name"],
                    "adb": str(sdk / "platform-tools" / "adb"), "avdName": identity["name"],
                    "serial": identity["serial"], "serverPort": server_port}
    binding = _binding(binding_data)
    server = adb_server_identity(binding.server_port)
    def initial_owner():
        _need(process_identity(actor["pid"]) == emulator and adb_server_identity(binding.server_port) == server,
              "fixture_original_actor_changed")
        return "adb:" + str(server["pid"]) + ":" + server["birth"]
    backend = providers.AndroidAdbBackend(binding, initial_owner)
    observed = backend.observe(readiness.Requirements(frozenset({"interactive_desktop"})), time.monotonic() + 30)
    path, _ = backend._command(["emu", "avd", "path"], time.monotonic() + 15)
    _need(path.strip().splitlines() == [str(avd_config.parent), "OK"], "fixture_actual_avd_path_mismatch")
    proof_path = fixture / wake_proof_name
    proof, proof_pin = _json(proof_path)
    source_proof, _ = _json(fixture / source_proof_name)
    _need(proof.get("display") == "ready" and type(proof.get("recoveryRecords")) is int and proof["recoveryRecords"] >= 1
          and type(proof.get("identities")) is list and len(proof["identities"]) == 6 and
          proof["identities"][3:6] == [observed.boot, observed.account, observed.session], "fixture_native_wake_proof_invalid")
    source_hash = _sources()["readiness_providers.py"]
    _need(source_proof.get("agent_tools/readiness_providers.py") == source_hash, "fixture_native_source_changed")
    descriptor = {"schemaVersion": 1, "fixtureId": fixture_id, "provider": "android-emulator", "binding": binding_data,
                  "emulator": emulator, "adbServer": server, "avdConfig": str(avd_config),
                  "avdConfigPin": _body(avd_config, private_file=False)[1], "sources": _sources(),
                  "qualification": {"wakeDisplayProof": str(proof_path), "proofPin": proof_pin}}
    directory = root / ".rag_index" / "readiness-fixtures"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with private.Directory(directory) as held:
        _need(stat.S_IMODE(os.fstat(held.fd).st_mode) == 0o700, "fixture_registry_not_private")
        descriptor_fd = os.open(fixture_id + ".json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=held.fd)
        with os.fdopen(descriptor_fd, "w") as stream:
            json.dump(descriptor, stream, sort_keys=True); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.fsync(held.fd)
    return registered_fixture(root, fixture_id)


def dispatch_binding(fixture, family):
    """Derive finite native endpoints only from an admitted private backend."""
    _need(family in {"android", "tart", "qmp", "libvirt"}, "fixture_dispatch_family_invalid")
    backend = fixture.adapter.backend
    if family == "android" and isinstance(getattr(backend, "binding", None), providers.AndroidBinding):
        binding = backend.binding
        value = {"adb": str(binding.adb), "serial": binding.serial,
                 "avd": binding.avd_name, "serverPort": binding.server_port}
    else:
        method = getattr(backend, "dispatch_binding", None)
        _need(callable(method), "fixture_dispatch_binding_unavailable")
        value = method(family)
    fields = {"android": {"adb", "serial", "avd", "serverPort"}, "tart": {"vmName"},
              "qmp": {"qmpSocket"}, "libvirt": {"uri", "domain"}}[family]
    _need(type(value) is dict and set(value) == fields, "fixture_dispatch_binding_invalid")
    for key, text in value.items():
        if key == "serverPort":
            _need(type(text) is int and 1024 <= text <= 65535, "fixture_dispatch_binding_invalid")
        else:
            _need(type(text) is str and 0 < len(text) <= 4096 and not any(ord(char) < 32 for char in text),
                  "fixture_dispatch_binding_invalid")
            if key in {"adb", "qmpSocket"}:
                _need(Path(text).is_absolute() and ".." not in Path(text).parts, "fixture_dispatch_binding_invalid")
    return dict(value)


def explicit_target(fixture, family):
    """Compare caller intent to private custody before any readiness recovery.

    A remote QMP pathname or local relay supplies no local disk authority. Its
    backend must separately prove the selected local peer/disk relationship.
    """
    value = dispatch_binding(fixture, family)
    if family == "android": return "android:" + value["avd"]
    if family == "tart": return "tart:" + value["vmName"]
    if family == "libvirt": return "libvirt:" + value["domain"]
    method = getattr(fixture.adapter.backend, "local_visual_target", None)
    _need(callable(method), "fixture_local_disk_authority_unavailable")
    selected = method()
    _need(type(selected) is str and selected.startswith("qemu:/")
          and ".." not in Path(selected[5:]).parts
          and not any(ord(char) < 32 for char in selected), "fixture_dispatch_binding_invalid")
    return selected


def lease_executor_from_snapshot(root, snapshot):
    """Resolve only an original private executor snapshot; no live admission.

    Status/cancel must preserve the original operation and may restore its
    transport for observation. This function never registers a fixture, probes
    a desktop, unlocks a session, starts a VM or substitutes a replacement owner.
    """
    _need(type(snapshot) is dict and type(snapshot.get("provider")) is str,
          "fixture_lease_snapshot_invalid")
    provider = snapshot["provider"]
    if provider in {"raw-qemu-windows", "libvirt-windows"}:
        from . import readiness_windows
        factory = getattr(readiness_windows, "lease_executor_from_snapshot", None)
    elif provider == "tart-macos":
        if snapshot.get("kind") == "qualified-tart-macos-guest-lease-v1":
            from . import readiness_tart_macos_lease_executor
            from . import readiness_tart_macos_active_work_original
            selected = readiness_tart_macos_active_work_original.executor_for_original(root, snapshot)
            if selected is not None:
                return selected
            factory = readiness_tart_macos_lease_executor.OriginalMacLeaseExecutor
        else:
            from . import readiness_tart
            factory = getattr(readiness_tart, "lease_executor_from_snapshot", None)
    else:
        raise FixtureRegistryError("fixture_lease_executor_unavailable")
    _need(callable(factory), "fixture_lease_executor_unavailable")
    return factory(Path(root).resolve(strict=True), snapshot)
