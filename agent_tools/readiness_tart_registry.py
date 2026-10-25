"""Private native-proof custody for owned Tart fixtures; no public ownership flags."""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time
from uuid import UUID, uuid4

from . import durable_remote_job as jobs
from . import readiness
from . import local_fixture_admission
from . import readiness_fixture_registry as registry
from . import readiness_providers as providers
from scripts import native_fixture_storage as storage
from scripts import visual_platform as visual


def _need(condition, reason):
    if not condition:
        raise registry.FixtureRegistryError(reason)


def _disk_pin(path):
    path = Path(path)
    _need(path == path.resolve(strict=True), "tart_disk_redirected")
    value = path.lstat()
    _need(stat.S_ISREG(value.st_mode) and value.st_uid == os.geteuid() and value.st_nlink == 1
          and not value.st_mode & 0o022, "tart_disk_unsafe")
    return {"device": value.st_dev, "inode": value.st_ino, "size": value.st_size,
            "uid": value.st_uid, "mode": stat.S_IMODE(value.st_mode)}


def _binary_pin(path):
    path = Path(path)
    value = path.lstat()
    _need(path == path.resolve(strict=True) and stat.S_ISREG(value.st_mode) and not value.st_mode & 0o022
          and os.access(path, os.X_OK), "tart_binary_unsafe")
    return list(registry.private._generation(value))


def _tart_binary(path):
    candidate = Path(path).resolve(strict=True)
    _binary_pin(candidate)
    with candidate.open("rb") as stream:
        header = stream.read(4097)
    if header.startswith(b"#!"):
        actual = candidate.parent.parent / "libexec/tart.app/Contents/MacOS/tart"
        expected = b'#!/bin/bash\nexec "' + str(actual).encode() + b'" "$@"\n'
        _need(candidate.name == "tart" and candidate.parent.name == "bin" and header == expected,
              "tart_launcher_unrecognized")
        _binary_pin(actual)
        return actual
    _need(header[:4] in {b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf", b"\x7fELF"},
          "tart_launcher_unrecognized")
    return candidate


def _sources():
    from . import readiness_tart
    from . import ssh_program_execution_remote
    from . import readiness_qemu_jobs
    from . import readiness_tart_retirement
    from scripts import fixture_environment
    from . import tart_linux_probe
    modules = (readiness_tart, tart_linux_probe, registry, providers, jobs, visual, storage, fixture_environment,
               local_fixture_admission, local_fixture_admission.vm_workflow, ssh_program_execution_remote, readiness_qemu_jobs,
               readiness_tart_retirement)
    paths = [Path(__file__), *(Path(module.__file__) for module in modules)]
    return {str(path): registry._body(path, private_file=False)[1] for path in paths}


def _guest_packet(packet, binding):
    _need(type(packet) is dict and set(packet) == {"remoteRoot", "generation", "binding", "operationId",
                                                 "requestSha256", "ownerSourceSha256"}, "tart_guest_packet_invalid")
    try:
        operation = str(UUID(packet["operationId"]))
        guest = jobs.MachineBinding.from_dict(packet["binding"])
        UUID(guest.boot)
    except (ValueError, KeyError, TypeError):
        raise registry.FixtureRegistryError("tart_guest_packet_invalid") from None
    _need(operation == packet["operationId"] and guest.machine == binding.machine
          and guest.account == str(binding.expected_uid)
          and packet["remoteRoot"] == "/tmp/vpn-control-program-" + guest.account + "-" + operation
          and type(packet["generation"]) is list and len(packet["generation"]) == 2
          and all(type(item) is int and item > 0 for item in packet["generation"])
          and type(packet["requestSha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", packet["requestSha256"])
          and packet["ownerSourceSha256"] == hashlib.sha256(jobs.owner_source()).hexdigest(),
          "tart_guest_packet_invalid")
    return packet


def admit_guest_program_packet(root, fixture_id, original_admission):
    """Internal create-only adoption of an original source-owned guest packet.

    No terminal flag is accepted here. The fixed guest probe observes the
    original retained owner and separately inventories unregistered job roots.
    """
    from . import ssh_program_execution_remote as program_protocol
    root = Path(root).resolve(strict=True)
    fixture = registry.registered_fixture(root, fixture_id)
    custody = fixture.adapter.backend.custody
    _need(type(custody) is TartCustody and custody.descriptor["provider"] == "tart-linux", "tart_guest_packet_invalid")
    path = registry._under(original_admission, root / ".runtime")
    admission, pin = registry._json(path)
    _need(set(admission) == {"operationId", "provider", "packet", "program", "counterPath"}
          and admission["provider"] == "tart-linux", "tart_guest_packet_invalid")
    packet = _guest_packet(admission["packet"], custody.binding)
    program = program_protocol.validate(admission["program"])
    _need(admission["operationId"] == packet["operationId"]
          and hashlib.sha256(program_protocol._canonical(program)).hexdigest() == packet["requestSha256"]
          and program["targetContext"]["uid"] == custody.binding.expected_uid
          and program["targetContext"]["principal"] == custody.binding.expected_account
          and program["targetContext"]["bootId"] == packet["binding"]["boot"], "tart_guest_packet_invalid")
    value = {"packet": packet, "admissionPath": str(path), "admissionPin": pin}
    with custody.operator(deadline=time.monotonic()+30):
        custody.guard(deadline=time.monotonic()+30)
        directory = custody.lifecycle_root / "guest-programs"
        directory.mkdir(mode=0o700, exist_ok=True); jobs._private(directory, directory=True)
        destination = directory / (packet["operationId"] + ".json")
        if destination.exists() or destination.is_symlink():
            _need(jobs._record(destination) == value, "tart_guest_packet_changed")
        else:
            jobs._publish(destination, value)
        _need(packet in custody.guest_jobs, "tart_guest_packet_changed")
    return packet


class TartCustody:
    def __init__(self, root, fixture_id, descriptor, pin):
        from . import readiness_tart
        self.root, self.fixture_id, self.descriptor, self.pin = Path(root), fixture_id, descriptor, pin
        b = descriptor["binding"]
        self.binding = readiness_tart.TartBinding(b["target"], b["machine"], b["vmName"], Path(b["tartBinary"]),
            Path(b["fixtureRoot"]), b["expectedAccount"], b["expectedUid"], b["memoryMiB"], b["storageFixtureId"])
        self.lifecycle_root = Path(descriptor["lifecycleRoot"])
        self.host_binding = jobs.MachineBinding.from_dict(descriptor["hostBinding"])
        self.job_root_generation = tuple(descriptor["jobRootGeneration"])
        self._operator_held = False
        self.guest_baseline = descriptor["guestBaseline"]
        self.reservation_digest=hashlib.sha256(json.dumps([self.binding.target,self.binding.machine],separators=(",",":")).encode()).hexdigest()
        self.reservation_key=visual._qualified_reservation_key(descriptor["provider"],self.reservation_digest)

    def _guest_namespace(self, packet):
        from . import readiness_qemu_jobs
        value=readiness_qemu_jobs._packet(packet, guest_platform="linux")
        _need((value["target"],value["machine"],value["account"]) ==
              (self.binding.target,self.binding.machine,str(self.binding.expected_uid))
              and value["actualMachineId"]==self.binding.machine,"tart_guest_namespace_changed")
        return value

    def load_guest_namespace(self):
        """Pure original namespace lookup; absence is never an idle proof."""
        self._pins()
        path=self.lifecycle_root/"guest-jobs.json"
        if not path.exists():
            _need(not path.is_symlink(),"tart_guest_namespace_changed")
            return None
        return self._guest_namespace(jobs._record(path))

    def admit_guest_namespace(self, packet, *, deadline=None):
        """Pin only an actually observed original guest namespace, once."""
        from . import readiness_qemu_jobs, readiness_tart
        packet=self._guest_namespace(packet)
        limit=time.monotonic()+30 if deadline is None else deadline
        with self.operator(deadline=limit):
            current=self.load_guest_namespace()
            if current is not None:
                _need(current==packet,"tart_guest_namespace_changed")
                return current
            source=readiness_qemu_jobs.observe_program(packet).encode()
            gate=("import hashlib,sys;p=sys.stdin.buffer.read(262145);"
                  "assert len(p)==int(sys.argv[1]) and hashlib.sha256(p).hexdigest()==sys.argv[2];"
                  "exec(compile(p,'<owned-guest-namespace-observe>','exec'))")
            result,_=readiness_tart.TartBackend(self.binding,self)._guest(
                ["python3","-I","-B","-c",gate,str(len(source)),hashlib.sha256(source).hexdigest()],limit,payload=source)
            _need(result.returncode==0,"tart_guest_namespace_unavailable")
            observed=json.loads(result.stdout)
            _need(type(observed) is dict and set(observed)=={"visibilityComplete","jobs","idle"}
                  and observed["visibilityComplete"] is True and type(observed["jobs"]) is list
                  and type(observed["idle"]) is bool,"tart_guest_namespace_unavailable")
            proof={"packet":packet,"observed":observed,"observerSha256":hashlib.sha256(source).hexdigest()}
            jobs._publish(self.lifecycle_root/("guest-namespace-admission-"+str(uuid4())+".json"),proof)
            jobs._publish(self.lifecycle_root/"guest-jobs.json",packet)
            return self.load_guest_namespace()

    @property
    def guest_collected_jobs(self):
        """Pure complete collections; the probe must prove current absence."""
        from . import readiness_tart_retirement
        result = []
        for path, record, packet in self._guest_program_records():
            readiness_tart_retirement.is_retired(self, path, record)
            if readiness_tart_retirement.collected_candidate(self, path, record):
                result.append(packet)
        return result

    def reconcile_collected_guest_programs(self, *, deadline=None):
        """Normal admission only; append proofs without changing originals."""
        from . import readiness_tart_retirement
        _need(self._operator_held, "tart_operator_required")
        if self.guard(deadline=deadline)["state"] != "running":
            return
        for packet in self.guest_collected_jobs:
            readiness_tart_retirement._retire_custody(self, packet["operationId"], deadline=deadline, require_absence=False)

    @property
    def guest_jobs(self):
        """Original private packets only; guest status is derived by the probe.

        Missing local records cannot hide foreign guest roots because the fixed
        probe independently enumerates the guest namespace before idle proof.
        """
        from . import readiness_tart_retirement
        return [packet for path, record, packet in self._guest_program_records()
                if not readiness_tart_retirement.is_retired(self, path, record)]

    def _guest_program_records(self):
        self._pins()
        directory = self.lifecycle_root / "guest-programs"
        if not directory.exists():
            _need(not directory.is_symlink(), "tart_guest_packet_invalid")
            return []
        jobs._private(directory, directory=True)
        result = []
        for path in sorted(directory.iterdir()):
            _need(len(result) < 1000 and path.name.endswith(".json"), "tart_guest_packet_invalid")
            value = jobs._record(path)
            _need(set(value) == {"packet", "admissionPath", "admissionPin"}, "tart_guest_packet_invalid")
            original_path = registry._under(value["admissionPath"], self.root / ".runtime")
            original, pin = registry._json(original_path)
            packet = _guest_packet(value["packet"], self.binding)
            _need(path.name == packet["operationId"] + ".json" and pin == value["admissionPin"]
                  and original.get("packet") == packet and original.get("operationId") == packet["operationId"]
                  and original.get("provider") == self.descriptor["provider"], "tart_guest_packet_changed")
            result.append((path, value, packet))
        return result

    def _pins(self, *, check_sources=True):
        d = self.descriptor
        current, pin = registry._json(self.root / ".rag_index/readiness-fixtures" / (self.fixture_id + ".json"))
        _need(current == d and pin == self.pin, "tart_custody_source_changed")
        if check_sources:
            _need(d["sources"] == _sources(), "tart_custody_source_changed")
        _need(registry._body(self.binding.fixture_root / "config.json", private_file=False)[1] == d["configPin"]
              and _disk_pin(self.binding.fixture_root / "disk.img") == d["diskPin"]
              and _binary_pin(self.binding.tart_binary) == d["binaryPin"], "tart_custody_instance_changed")
        for path, original in d["qualification"].items():
            value = registry._under(path, self.root / ".runtime")
            _need(registry._body(value)[1] == original, "tart_qualification_changed")
        jobs._root(self.lifecycle_root / "jobs", self.job_root_generation)
        jobs._binding_live(self.host_binding)

    def guard(self, *, deadline=None):
        from . import readiness_tart
        self._pins()
        current = readiness_tart.current_instance(self.binding, self.lifecycle_root,
                    self.descriptor["seedActor"], self.host_binding, self.job_root_generation, deadline=deadline)
        _need(type(current) is dict and current.get("state") in {"running", "starting", "booting", "stopped", "suspended"},
              "tart_original_owner_unresolved")
        if not (self.lifecycle_root / "active.json").exists() and current.get("jobState") == "running":
            seed = self.descriptor["seedActor"]
            _need(jobs._birth(seed["operatorPid"]) == seed["operatorBirth"], "tart_original_owner_unresolved")
        self._pins()
        return current

    @contextmanager
    def operator(self, *, deadline=None, cancelled=lambda: False):
        if self._operator_held:
            yield
            return
        import fcntl
        self._pins()
        path = self.lifecycle_root / "operator.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
                  and stat.S_IMODE(info.st_mode) == 0o600, "tart_operator_lock_unsafe")
            limit = time.monotonic() + 600 if deadline is None else deadline
            while True:
                _need(not cancelled() and time.monotonic() < limit, "tart_readiness_deadline")
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(min(.05, max(0, limit - time.monotonic())))
            _need(not self._operator_held, "tart_operator_lock_conflict")
            self._operator_held = True
            yield
        finally:
            self._operator_held = False
            os.close(descriptor)

    def _job_facts(self, current):
        blockers = set()
        for path in (self.lifecycle_root / "jobs").iterdir():
            _need(path.is_dir() and not path.is_symlink() and str(UUID(path.name)) == path.name,
                  "tart_job_visibility_incomplete")
            result = jobs.observe(path.parent, path.name, self.host_binding, generation=self.job_root_generation)
            if path.name == current.get("operationId") and result["state"] == "running":
                continue  # Original VM owner is intentionally the current VM.
            if result["state"] == "running":
                blockers.add("running_jobs")
            elif result["state"] != "terminal":
                blockers.add("unknown_jobs")
        return blockers

    def idle_facts(self, guest_facts):
        """Only actual, complete category observations can authorize a reboot."""
        current = self.guard(); visibility = set(); blockers = set()
        if current["state"] != "running":
            return frozenset(), frozenset({"guest_not_running"})
        actor = current.get("actor")
        reservations = visual._read_reservations()
        platform = "macos" if self.descriptor["provider"] == "tart-macos" else "linux"
        own_key=getattr(self,"reservation_key",None)
        own=reservations.get(own_key) if own_key in reservations else reservations.get(platform)
        if type(actor) is dict and own == {"memory_mib":self.binding.memory_mib,"pid":actor["pid"]}:
            visibility.add("reservations")
        if self._operator_held:
            visibility.add("operators")
        if type(guest_facts) is not dict:
            return frozenset(visibility), frozenset({"guest_visibility"})
        host_blockers = self._job_facts(current)
        if (guest_facts.get("jobVisibilityComplete") is True and type(guest_facts.get("runningJobs")) is list
                and type(guest_facts.get("unknownJobs")) is list):
            visibility.update({"running_jobs", "unknown_jobs"})
            if guest_facts["runningJobs"]:
                blockers.add("running_jobs")
            if guest_facts["unknownJobs"]:
                blockers.add("unknown_jobs")
        blockers.update(host_blockers)
        if guest_facts.get("processVisibilityComplete") is True and type(guest_facts.get("protectedProcesses")) is list:
            visibility.add("protected_processes")
            if guest_facts["protectedProcesses"]:
                blockers.add("protected_processes")
        if (guest_facts.get("processVisibilityComplete") is True and
                all(type(guest_facts.get(key)) is list for key in ("installerRoles", "installerLocks", "installerUpdates"))):
            roles = guest_facts["installerRoles"]
            recognized = all(type(role) is dict and set(role) == {"pid", "role"}
                             and type(role["pid"]) is int and role["pid"] > 0
                             and role["role"] in {"shutdown_waiter", "packagekit_idle", "fwupd_idle_no_devices", "blocked"} for role in roles)
            if recognized:
                visibility.add("installers")
                if guest_facts["installerLocks"] or guest_facts["installerUpdates"] or any(role["role"] == "blocked" for role in roles):
                    blockers.add("installers")
        # Pending lifecycle effects are never assumed terminal from file age.
        lifecycle_complete = current.get("jobState") in {"running", "terminal"}
        for path in self.lifecycle_root.glob("effect-*.json"):
            effect = jobs._record(path)
            action = effect.get("action")
            if action == "reboot":
                lifecycle_complete &= (type(guest_facts.get("boot")) is str and guest_facts["boot"] != effect.get("bootBefore"))
            elif action in {"start", "resume"}:
                lifecycle_complete &= current["state"] == "running"
            else:
                lifecycle_complete = False
        if type(guest_facts.get("systemdJobs")) is not str:
            lifecycle_complete = False
        elif guest_facts["systemdJobs"]:
            blockers.add("lifecycle_phases")
        if guest_facts.get("interactiveSessions") != "":
            blockers.add("operators")
        if lifecycle_complete:
            visibility.add("lifecycle_phases")
        return frozenset(visibility), frozenset(blockers)

    def admit_start(self, deadline):
        current = self.guard()
        _need(current["state"] == "stopped" and current.get("jobState") == "terminal", "tart_original_owner_unresolved")
        platform = "macos" if self.descriptor["provider"] == "tart-macos" else "linux"
        reservations = visual._read_reservations()
        original = current.get("actor") or self.descriptor["seedActor"]
        own_key=self.reservation_key
        old = reservations.get(own_key)
        if old is None and reservations.get(platform)=={"memory_mib":self.binding.memory_mib,"pid":original["pid"]}:
            own_key=platform;old=reservations[platform]
        if old is not None:
            allowed = {"memory_mib": self.binding.memory_mib, "pid": original["pid"]}
            pending = {"memory_mib": self.binding.memory_mib, "pid": 0}
            _need(old == allowed or old == pending and (self.lifecycle_root / "pending-admission.json").is_file(),
                  "tart_reservation_ownership_unproven")
            _need(jobs._birth(original["pid"]) is None, "tart_original_owner_unresolved")
            visual._release_visual_reservation(own_key)
        plans = storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
        plans.settle(self.binding.storage_fixture_id)
        capacity = plans.check(platform, "start", self.binding.fixture_root, current_fixture_id=self.binding.storage_fixture_id)
        memory = local_fixture_admission.memory_plan(self.binding.memory_mib, deadline)
        self.guard()
        admission = visual._admit_recovery_fixture_start(self.descriptor["provider"],self.reservation_digest,
            self.binding.memory_mib,storage_fixture_id=self.binding.storage_fixture_id)
        identity = str(uuid4())
        value = {"admissionId": identity, "capacity": capacity, "memoryMeasurement": memory,
                 "admission": admission, "originalOperation": current.get("operationId")}
        jobs._publish(self.lifecycle_root / ("admission-" + identity + ".json"), value)
        # This mutable pointer carries only a capacity claim; immutable original
        # admission/actor/jobs remain the evidence for any later reconciliation.
        temporary = self.lifecycle_root / ("pending-" + identity + ".json")
        jobs._publish(temporary, value)
        os.replace(temporary, self.lifecycle_root / "pending-admission.json")
        jobs._sync_directory(self.lifecycle_root)
        return value

    def bind_start(self, pid):
        current = self.guard()
        _need(type(pid) is int and pid > 0 and current["state"] == "running"
              and current.get("actor", {}).get("pid") == pid, "tart_start_owner_unproven")
        platform = "macos" if self.descriptor["provider"] == "tart-macos" else "linux"
        reservation = visual._read_reservations().get(self.reservation_key)
        _need(reservation in ({"memory_mib": self.binding.memory_mib, "pid": 0},
                             {"memory_mib": self.binding.memory_mib, "pid": pid}), "tart_reservation_ownership_unproven")
        visual._bind_visual_reservation(self.reservation_key, pid)
        storage.StoragePlans(visual.STORAGE_PLANS_ROOT).bind_writer(self.binding.storage_fixture_id, pid)

    def reconcile_ready(self,ready,deadline):
        """Recover only bookkeeping for an admitted original durable VM actor."""
        from . import readiness_tart
        _need(self._operator_held,"tart_reservation_ownership_unproven")
        current=self.guard(deadline=deadline)
        _need(current["state"]=="running" and current.get("jobState")=="running","tart_original_owner_unresolved")
        if not (self.lifecycle_root/"active.json").exists():
            return  # a legacy native process is never adopted as a new owner
        observed=readiness_tart.TartBackend(self.binding,self).observe(ready.requirements,deadline)
        _need((observed.target,observed.machine,observed.connection,observed.boot,observed.account,observed.session)==ready.identities(),
              "tart_power_identity_changed")
        actor=current["actor"]
        reservation=visual._read_reservations().get(self.reservation_key)
        _need(reservation in ({"memory_mib":self.binding.memory_mib,"pid":0},
                              {"memory_mib":self.binding.memory_mib,"pid":actor["pid"]}),"tart_reservation_ownership_unproven")
        plans=storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
        with plans._locked():
            plan=plans._read()["plans"].get(self.binding.storage_fixture_id)
        _need(type(plan) is dict and plan.get("directory")==str(self.binding.fixture_root)
              and plan.get("state") in {"retained","pending"},"tart_storage_custody_missing")
        if reservation["pid"]==actor["pid"] and plan.get("writerPid")==actor["pid"]:
            return
        self.bind_start(actor["pid"])
        _need(self.guard(deadline=deadline)==current,"tart_original_owner_unresolved")


def load_registered_fixture(root, fixture_id, descriptor, descriptor_pin):
    from . import readiness_tart
    root = Path(root).resolve(strict=True)
    fields = {"schemaVersion", "fixtureId", "provider", "binding", "seedActor", "configPin", "diskPin", "binaryPin",
              "sources", "qualification", "lifecycleRoot", "hostBinding", "jobRootGeneration", "guestBaseline", "qualifiedRecoveries"}
    _need(type(descriptor) is dict and set(descriptor) == fields and descriptor["schemaVersion"] == 1
          and descriptor["fixtureId"] == fixture_id and descriptor["provider"] in {"tart-linux", "tart-macos"}, "tart_descriptor_invalid")
    b = descriptor["binding"]
    _need(type(b) is dict and set(b) == {"target", "machine", "vmName", "tartBinary", "fixtureRoot", "expectedAccount", "expectedUid", "memoryMiB", "storageFixtureId"}, "tart_descriptor_invalid")
    expected_root = Path.home() / ".tart/vms" / b["vmName"]
    _need(Path(b["fixtureRoot"]) == expected_root and expected_root.resolve(strict=True) == expected_root
          and b["vmName"].startswith("vpn-tool-recovery-tart-") and b["expectedAccount"] == "admin"
          and b["expectedUid"] == 1000 and type(b["memoryMiB"]) is int, "tart_descriptor_invalid")
    target = "local-tart-" + hashlib.sha256(str(expected_root).encode()).hexdigest()[:24]
    _need(b["target"] == target and type(b["machine"]) is str and bool(b["machine"]), "tart_descriptor_invalid")
    digest = hashlib.sha256(json.dumps([target, b["machine"]], separators=(",", ":")).encode()).hexdigest()
    _need(Path(descriptor["lifecycleRoot"]) == root / ".rag_index/readiness-tart" / digest, "tart_descriptor_invalid")
    custody = TartCustody(root, fixture_id, descriptor, descriptor_pin)
    custody.guard()
    _need(type(descriptor["qualifiedRecoveries"]) is list and descriptor["qualifiedRecoveries"] in (["start"], ["reboot", "start"]),
          "tart_descriptor_invalid")
    backend = readiness_tart.TartBackend(custody.binding, custody, start_qualified=True,
                                         reboot_qualified="reboot" in descriptor["qualifiedRecoveries"])
    # Headless Linux deliberately has no GUI session requirement.
    requirements = frozenset({"guest_agent"}) if descriptor["provider"] == "tart-linux" else frozenset({"interactive_desktop"})
    return registry.RegisteredFixture(target, b["machine"], providers.ProviderAdapter(descriptor["provider"], target, b["machine"], backend),
                                      root / ".rag_index/readiness-targets" / digest, requirements)


def register_tart_linux(root, fixture_id, evidence_directory):
    """Internal custody handoff; native procedures precede public registration."""
    root = Path(root).resolve(strict=True); fixture_id = registry._id(fixture_id)
    evidence = registry._under(evidence_directory, root / ".runtime")
    metadata, _ = registry._json(evidence / "linux-fixture.json")
    active, _ = registry._json(evidence / "linux-active-run.json")
    restart, _ = registry._json(evidence / "linux-persisted-restart-proof.json")
    first, _ = registry._json(evidence / "linux-first-ready.json")
    restarted, _ = registry._json(evidence / "linux-restarted-ready.json")
    fixture_root = Path(metadata["fixtureRoot"])
    name = metadata["name"]
    _need(fixture_root == Path.home() / ".tart/vms" / name and fixture_root.resolve(strict=True) == fixture_root
          and name.startswith("vpn-tool-recovery-tart-linux-") and restart["fixtureRoot"] == str(fixture_root), "tart_fixture_not_owned")
    config = fixture_root / "config.json"; disk = fixture_root / "disk.img"
    _need(config.stat().st_ino == restart["configInode"] and disk.stat().st_ino == restart["diskInode"]
          and hashlib.sha256(config.read_bytes()).hexdigest() == restart["configSha256"] == metadata["configSha256"], "tart_fixture_generation_changed")
    observations = [first["observation"], restarted["observation"]]
    _need(all(o["machine"] == restart["machine"] and o["account"] == "admin" and o["uid"] == 1000 for o in observations)
          and observations[0]["boot"] == restart["firstBoot"] and observations[1]["boot"] == restart["restartBoot"]
          and restart["firstBoot"] != restart["restartBoot"], "tart_native_qualification_invalid")
    operation = active["operationIdentity"]
    native_actor, _ = registry._json(evidence / ("run-" + operation) / "actor.json")
    native_intent, _ = registry._json(evidence / ("run-" + operation) / "intent.json")
    _need(active["actor"] == native_actor and native_actor["fixture"] == name and native_actor["submitted"] is True
          and native_intent["operationIdentity"] == operation and native_intent["fixture"] == name
          and registry._run(["ps", "-p", str(native_actor["childPid"]), "-o", "lstart="]) == native_actor["childStartTime"], "tart_native_actor_unresolved")
    actor = registry.process_identity(native_actor["childPid"]); operator = registry.process_identity(active["ownerPid"])
    binary = _tart_binary(shutil.which("tart") or "missing")
    _need(Path(registry._run(["ps", "-p", str(actor["pid"]), "-o", "comm="])).resolve(strict=True) == binary,
          "tart_native_actor_unresolved")
    target = "local-tart-" + hashlib.sha256(str(fixture_root).encode()).hexdigest()[:24]
    machine = restart["machine"]
    digest = hashlib.sha256(json.dumps([target, machine], separators=(",", ":")).encode()).hexdigest()
    lifecycle = root / ".rag_index/readiness-tart" / digest; lifecycle.mkdir(mode=0o700, parents=True, exist_ok=True)
    jobs._private(lifecycle, directory=True)
    job_root = lifecycle / "jobs"; job_root.mkdir(mode=0o700, exist_ok=True)
    plans = storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
    with plans._locked():
        candidates = [(key, p) for key, p in plans._read()["plans"].items() if p["directory"] == str(fixture_root) and p["state"] != "retired"]
    _need(len(candidates) == 1, "tart_storage_custody_missing")
    proofs = [evidence / n for n in ("linux-fixture.json", "linux-active-run.json", "linux-persisted-restart-proof.json", "linux-first-ready.json", "linux-restarted-ready.json")]
    proofs += [evidence / ("run-" + operation) / name for name in ("actor.json", "intent.json")]
    proofs += list(evidence.glob("reboot-*.json")) + list(evidence.glob("poweroff-*.json"))
    _need(9 <= len(proofs) <= 32, "tart_native_qualification_invalid")
    qualification = {str(path): registry._json(path)[1] for path in proofs}
    baseline_path = evidence / "linux-service-unit-baseline.json"
    guest_baseline = {}
    if baseline_path.exists():
        baseline, baseline_pin = registry._json(baseline_path)
        from . import tart_linux_probe
        _need(set(baseline) == {"schemaVersion", "machine", "boot", "sourceOciDigest", "probeSha256", "units"}
              and baseline["schemaVersion"] == 1 and baseline["machine"] == machine
              and baseline["sourceOciDigest"] == "sha256:51b493a05e4bc6f21c5c5052cffc1b26b5cea1d76847f5db10b97da90c16e58c"
              and baseline["probeSha256"] == hashlib.sha256(Path(tart_linux_probe.__file__).read_bytes()).hexdigest()
              and type(baseline["units"]) is dict, "tart_guest_baseline_invalid")
        for unit_name, unit in baseline["units"].items():
            _need(type(unit_name) is str and type(unit) is dict and set(unit) == {"fragment", "sha256", "generation"}
                  and type(unit["fragment"]) is str and (unit["fragment"].startswith(("/usr/lib/systemd/system/", "/lib/systemd/system/")) or unit["fragment"] == "/etc/systemd/system/tart-guest-agent.service")
                  and type(unit["sha256"]) is str and len(unit["sha256"]) == 64
                  and type(unit["generation"]) is list and len(unit["generation"]) == 9 and all(type(value) is int for value in unit["generation"]),
                  "tart_guest_baseline_invalid")
        guest_baseline = baseline["units"]
        qualification[str(baseline_path)] = baseline_pin
    descriptor = {"schemaVersion": 1, "fixtureId": fixture_id, "provider": "tart-linux",
        "binding": {"target": target, "machine": machine, "vmName": name, "tartBinary": str(binary), "fixtureRoot": str(fixture_root),
                    "expectedAccount": "admin", "expectedUid": 1000, "memoryMiB": 4096, "storageFixtureId": candidates[0][0]},
        "seedActor": {"pid": actor["pid"], "birth": actor["birth"], "operatorPid": operator["pid"], "operatorBirth": operator["birth"],
                      "operationId": operation, "terminalPath": str(evidence / ("run-" + operation) / "terminal.json")},
        "configPin": registry._body(config, private_file=False)[1], "diskPin": _disk_pin(disk), "binaryPin": _binary_pin(binary),
        "sources": _sources(), "qualification": qualification, "lifecycleRoot": str(lifecycle), "guestBaseline": guest_baseline, "qualifiedRecoveries": ["start"],
        "hostBinding": asdict(jobs.current_binding(target, os.uname().nodename)), "jobRootGeneration": list(jobs.root_generation(job_root))}
    descriptor["qualification"] = _snapshot_qualification(root, target, descriptor["qualification"])
    directory = root / ".rag_index/readiness-fixtures"; directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    jobs._private(directory, directory=True)
    jobs._publish(directory / (fixture_id + ".json"), descriptor)
    current, pin = registry._json(directory / (fixture_id + ".json"))
    return load_registered_fixture(root, fixture_id, current, pin)


def _qualification_root(root, target):
    directory = Path(root) / ".runtime/tool-recovery/registry-evidence/tart" / target
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    jobs._private(directory, directory=True)
    return directory


def _snapshot_qualification(root, target, proofs):
    directory = _qualification_root(root, target) / str(uuid4())
    directory.mkdir(mode=0o700)
    result = {}
    for index, (original, pin) in enumerate(proofs.items()):
        raw, current = registry._body(Path(original))
        _need(current == pin, "tart_qualification_changed")
        path = directory / (f"{index:02d}-" + Path(original).name)
        jobs._create(path, raw)
        result[str(path)] = registry._body(path)[1]
    return result


def record_direct_reboot_qualification(root, fixture_id, recovery_identity):
    """Retain actual changed-boot proof after a directly qualified native reboot."""
    from . import readiness_tart
    _need(type(recovery_identity) is str and len(recovery_identity) == 64
          and all(char in "0123456789abcdef" for char in recovery_identity), "tart_recovery_invalid")
    fixture = registry.registered_fixture(root, fixture_id)
    custody = fixture.adapter.backend.custody
    effect = jobs._record(custody.lifecycle_root / ("effect-" + recovery_identity + ".json"))
    _need(effect.get("action") == "reboot" and effect.get("recoveryIdentity") == recovery_identity
          and effect.get("target") == fixture.target and effect.get("machine") == fixture.machine, "tart_qualification_invalid")
    with custody.operator(deadline=time.monotonic()+30):
        current = readiness_tart.TartBackend(custody.binding, custody).observe(
            readiness.Requirements(frozenset({"guest_agent"})), time.monotonic()+30)
        _need(current.guest == "running" and current.boot is not None and current.boot != effect.get("bootBefore")
              and current.idle_visibility == readiness.IDLE_VISIBILITY and not current.idle_blockers,
              "tart_qualification_invalid")
        actor = custody.guard()["actor"]
        actor_connection = "tart:" + str(actor["pid"]) + ":" + actor["birth"]
        _need(type(effect.get("connectionBefore")) is str and type(current.connection) is str
              and effect["connectionBefore"].split(":agent:",1)[0] == actor_connection
              and current.connection.split(":agent:",1)[0] == actor_connection,
              "tart_qualification_invalid")
    proof = {"schemaVersion": 1, "target": fixture.target, "machine": fixture.machine,
             "recoveryIdentity": recovery_identity, "bootBefore": effect["bootBefore"], "bootAfter": current.boot,
             "actor": actor, "sources": _sources(), "idleVisibility": sorted(current.idle_visibility)}
    path = _qualification_root(root, fixture.target) / ("reboot-" + recovery_identity + ".json")
    jobs._publish(path, proof)
    return path


_BASELINE_REFRESH_GATE = r"""import hashlib,json,sys
source=sys.stdin.buffer.read(262145)
n,h,original=sys.argv[1:]
assert len(source)==int(n) and hashlib.sha256(source).hexdigest()==h,'guest_source_mismatch'
namespace={'__name__':'owned_baseline_refresh'}
exec(compile(source,'<owned-tart-baseline-refresh>','exec'),namespace)
old=json.loads(original)
for unit,expected in old.items():
    fields,path,generation=namespace['_unit'](unit)
    assert str(path)==expected['fragment'] and generation==expected['generation'],'original_public_artifact_changed'
units=namespace['baseline_units']()
assert all(units.get(unit)==expected for unit,expected in old.items()),'original_public_artifact_changed'
print(json.dumps(units,sort_keys=True))
"""


def _refresh_baseline(custody, backend, deadline):
    from . import tart_linux_probe
    source = Path(tart_linux_probe.__file__).read_bytes()
    response, _ = backend._guest(["python3", "-c", _BASELINE_REFRESH_GATE, str(len(source)),
                                  hashlib.sha256(source).hexdigest(),
                                  json.dumps(custody.guest_baseline, sort_keys=True, separators=(",", ":"))],
                                 deadline, payload=source)
    _need(response.returncode == 0, "tart_baseline_refresh_failed")
    value = json.loads(response.stdout)
    _need(type(value) is dict and all(value.get(key) == original for key, original in custody.guest_baseline.items()),
          "tart_original_public_artifact_changed")
    custody.guest_baseline = value
    return value


def refresh_tart_linux(root, old_fixture_id, new_fixture_id, *, reboot_recovery_id=None):
    """Source-only internal refresh preserving every original lifecycle identity.

    A fresh direct read-only probe closes current guest, account, boot and actor.
    Neither this path nor its probe admits a lifecycle effect. Unresolved original
    jobs, missing actors, changed disks/configs or credential state remain blocked.
    """
    from . import readiness_tart
    root = Path(root).resolve(strict=True)
    old_fixture_id = registry._id(old_fixture_id); new_fixture_id = registry._id(new_fixture_id)
    original, original_pin = registry._json(root / ".rag_index/readiness-fixtures" / (old_fixture_id + ".json"))
    _need(original.get("provider") == "tart-linux" and original.get("schemaVersion") == 1,
          "tart_descriptor_invalid")

    class SourceRefreshCustody(TartCustody):
        def _pins(self, *, check_sources=True):
            # Only source is expected to change; every original identity and
            # native qualification stays closed against its original descriptor.
            return super()._pins(check_sources=False)

    custody = SourceRefreshCustody(root, old_fixture_id, original, original_pin)
    with custody.operator(deadline=time.monotonic()+30):
        before = custody.guard(deadline=time.monotonic()+30)
        _need(before["state"] == "running" and before["jobState"] == "running", "tart_original_owner_unresolved")
        backend = readiness_tart.TartBackend(custody.binding, custody)
        first = backend.observe(readiness.Requirements(frozenset({"guest_agent"})), time.monotonic()+30)
        baseline = _refresh_baseline(custody, backend, time.monotonic()+30)
        observation = backend.observe(readiness.Requirements(frozenset({"guest_agent"})), time.monotonic()+30)
        after = custody.guard(deadline=time.monotonic()+30)
        _need((first.boot, first.account, first.connection) == (observation.boot, observation.account, observation.connection),
              "tart_direct_refresh_probe_failed")
        _need(before == after and observation.guest == "running" and observation.guest_agent
              and observation.machine == custody.binding.machine, "tart_direct_refresh_probe_failed")
        sources = _sources()
        proof = {"schemaVersion": 1, "previousFixtureId": old_fixture_id, "fixtureId": new_fixture_id,
                 "target": observation.target, "machine": observation.machine, "boot": observation.boot,
                 "account": observation.account, "connection": observation.connection,
                 "actor": after["actor"], "operationId": after["operationId"], "sources": sources, "guestBaseline": baseline}
    path = _qualification_root(root, observation.target) / ("source-refresh-" + str(uuid4()) + ".json")
    jobs._publish(path, proof)
    descriptor = json.loads(json.dumps(original))
    descriptor.update(fixtureId=new_fixture_id, sources=sources, qualifiedRecoveries=["start"], guestBaseline=baseline)
    descriptor["qualification"][str(path)] = registry._body(path)[1]
    if reboot_recovery_id is not None:
        _need(type(reboot_recovery_id) is str and len(reboot_recovery_id) == 64
              and all(char in "0123456789abcdef" for char in reboot_recovery_id), "tart_recovery_invalid")
        reboot_path = _qualification_root(root, observation.target) / ("reboot-" + reboot_recovery_id + ".json")
        reboot, reboot_pin = registry._json(reboot_path)
        _need(reboot.get("sources") == sources and reboot.get("target") == observation.target
              and reboot.get("machine") == observation.machine and reboot.get("bootAfter") == observation.boot
              and reboot.get("actor") == after["actor"] and reboot.get("idleVisibility") == sorted(readiness.IDLE_VISIBILITY),
              "tart_qualification_invalid")
        descriptor["qualification"][str(reboot_path)] = reboot_pin
        descriptor["qualifiedRecoveries"] = ["reboot", "start"]
    directory = root / ".rag_index/readiness-fixtures"
    jobs._private(directory, directory=True)
    jobs._publish(directory / (new_fixture_id + ".json"), descriptor)
    value, pin = registry._json(directory / (new_fixture_id + ".json"))
    return load_registered_fixture(root, new_fixture_id, value, pin)


def refresh_stopped_tart_linux(root, old_fixture_id, new_fixture_id):
    """Refresh source custody of one proven stopped persisted fixture.

    No guest command, start, wake or reboot occurs. All original instance/job
    generations survive. Only already qualified start survives; guest identity
    must be observed anew after any later caller-admitted start.
    """
    root=Path(root).resolve(strict=True)
    old_fixture_id=registry._id(old_fixture_id);new_fixture_id=registry._id(new_fixture_id)
    original,pin=registry._json(root/".rag_index/readiness-fixtures"/(old_fixture_id+".json"))
    _need(original.get("provider")=="tart-linux" and original.get("schemaVersion")==1
          and "start" in original.get("qualifiedRecoveries",[]),"tart_descriptor_invalid")
    class StoppedSourceCustody(TartCustody):
        def _pins(self,*,check_sources=True):
            return super()._pins(check_sources=False)
    custody=StoppedSourceCustody(root,old_fixture_id,original,pin)
    with custody.operator(deadline=time.monotonic()+30):
        before=custody.guard(deadline=time.monotonic()+30)
        _need(before["state"]=="stopped" and before.get("jobState")=="terminal"
              and before.get("actor") is not None and jobs._birth(before["actor"]["pid"]) is None
              and not custody._job_facts(before),"tart_original_owner_unresolved")
        packets=custody.guest_jobs
        plans=storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
        with plans._locked():
            plan=plans._read()["plans"].get(custody.binding.storage_fixture_id)
            _need(type(plan) is dict and plan.get("state")=="retained"
                  and plan.get("directory")==str(custody.binding.fixture_root)
                  and type(plan.get("writerPid")) is int and plan["writerPid"]>0
                  and jobs._birth(plan["writerPid"]) is None,"tart_storage_custody_missing")
            after=custody.guard(deadline=time.monotonic()+30)
            _need(before==after,"tart_original_owner_unresolved")
            sources=_sources()
            proof={"schemaVersion":1,"kind":"stopped_source_refresh","previousFixtureId":old_fixture_id,
                   "fixtureId":new_fixture_id,"target":custody.binding.target,"machine":custody.binding.machine,
                   "originalInstance":after,"storagePlan":plan,"guestPackets":packets,"sources":sources}
    path=_qualification_root(root,custody.binding.target)/("stopped-source-refresh-"+str(uuid4())+".json")
    jobs._publish(path,proof)
    descriptor=json.loads(json.dumps(original))
    descriptor.update(fixtureId=new_fixture_id,sources=sources,qualifiedRecoveries=["start"])
    descriptor["qualification"][str(path)]=registry._body(path)[1]
    directory=root/".rag_index/readiness-fixtures";jobs._private(directory,directory=True)
    jobs._publish(directory/(new_fixture_id+".json"),descriptor)
    value,pin=registry._json(directory/(new_fixture_id+".json"))
    return load_registered_fixture(root,new_fixture_id,value,pin)
