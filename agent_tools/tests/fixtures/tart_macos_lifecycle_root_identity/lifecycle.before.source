"""Source-owned Mac lifecycle admission and original-operation observation.

This module performs no VM power action on import.  A trusted registered
custody owns the resource/operator locks and supplies actual observations.
Native qualification must precede adding any capability to the provider.

Tart 2.32.1 Stop.swift falls back to SIGKILL and deletes saved state, so it is
deliberately excluded.  Graceful shutdown/reboot require a separately installed
fixed guest helper.  Run.swift restores a saved state through ``tart run``;
Suspend.swift signals only the already-running original process.

https://github.com/cirruslabs/tart/blob/2.32.1/Sources/tart/Commands/Stop.swift
https://github.com/cirruslabs/tart/blob/2.32.1/Sources/tart/Commands/Run.swift
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

from . import durable_remote_job as jobs
from . import private_inventory_lock as private
from . import readiness

NATIVE_QUALIFIED = False
_EXECUTING_CODE = sys._getframe().f_code
_ACTIONS = frozenset({"start", "resume", "suspend", "reboot", "shutdown"})


class LifecycleBlocked(ValueError):
    """Only finite public reasons cross the lifecycle boundary."""


def _need(condition, reason):
    if not condition:
        raise LifecycleBlocked(reason)


def _rid(value):
    _need(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value),
          "macos_lifecycle_recovery_invalid")
    return value


def _uuid(value):
    try:
        _need(type(value) is str and str(uuid.UUID(value)) == value,
              "macos_lifecycle_operation_invalid")
    except (ValueError, TypeError, AttributeError):
        raise LifecycleBlocked("macos_lifecycle_operation_invalid") from None
    return value


def operation_id(recovery_id):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "vpn-control:tart-macos:" + _rid(recovery_id)))


@dataclass(frozen=True)
class Actor:
    pid: int
    birth: str

    def __post_init__(self):
        _need(type(self.pid) is int and self.pid > 0 and type(self.birth) is str
              and re.fullmatch(r"darwin:[1-9][0-9]*:[0-9]{1,6}", self.birth),
              "macos_lifecycle_actor_invalid")

    def present(self):
        return jobs._birth(self.pid) == self.birth


def require_idle(observed):
    """Missing categories and uncertain work always block a power mutation."""
    _need(type(observed) is readiness.Observation and observed.trusted and observed.owned
          and observed.integrity and not observed.coordinator_host
          and observed.guest == "running" and observed.guest_agent,
          "macos_lifecycle_guest_not_ready")
    _need(observed.idle_visibility == readiness.IDLE_VISIBILITY
          and not observed.idle_blockers, "macos_lifecycle_idle_incomplete")


def require_same(observed, ready):
    _need(type(observed) is readiness.Observation and type(ready) is readiness.Observation
          and all(getattr(observed, key) == getattr(ready, key) for key in
                  ("target", "machine", "connection", "boot", "account", "session")),
          "macos_lifecycle_identity_changed")


def saved_state(path):
    """Metadata only; VM memory never enters a digest or retained stream."""
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
          and info.st_nlink == 1 and not info.st_mode & 0o077 and info.st_size > 0,
          "macos_saved_state_unsafe")
    return {"device": info.st_dev, "inode": info.st_ino, "size": info.st_size,
            "uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode),
            "mtimeNs": info.st_mtime_ns, "ctimeNs": info.st_ctime_ns}


class Journal:
    """Create-only operation admissions under the original stable lifecycle root.

    The caller must hold the source-owned custody operator throughout admit,
    final observation, and dispatch.  The journal never starts a VM itself.
    An effect receipt means submission may have occurred, not success.
    """
    def __init__(self, root, target, machine):
        self.root = Path(root)
        self.target, self.machine = jobs._token(target), jobs._token(machine)
        self.directory = private.Directory(self.root)

    def close(self):
        self.directory.close()

    def _name(self, recovery_id, suffix):
        return "macos-lifecycle-" + _rid(recovery_id) + "-" + suffix + ".json"

    def _read(self, name):
        self.directory.guard()
        try:
            with private.Snapshot(self.directory, name) as snapshot:
                return json.loads(snapshot.body)
        except FileNotFoundError:
            return None
        except (ValueError, OSError, UnicodeError):
            # A concurrent publication may still have its private stage link.
            # Never read through unsafe custody or treat it as absence.
            raise LifecycleBlocked("macos_lifecycle_original_record_unavailable") from None

    def admit(self, action, recovery_id, observed, *, original_owner):
        _need(type(action) is str and action in _ACTIONS, "macos_lifecycle_action_invalid")
        _need(type(observed) is readiness.Observation
              and (observed.target, observed.machine) == (self.target, self.machine),
              "macos_lifecycle_target_changed")
        _need(type(original_owner) is dict and set(original_owner) == {"operationId", "actor"},
              "macos_lifecycle_original_owner_invalid")
        _uuid(original_owner["operationId"]); Actor(**original_owner["actor"])
        if action in {"reboot", "shutdown", "suspend"}:
            require_idle(observed)
        elif action == "start":
            _need(observed.guest == "stopped", "macos_lifecycle_state_changed")
        else:
            _need(observed.guest == "suspended", "macos_lifecycle_state_changed")
        value = {"schemaVersion": 1, "action": action, "recoveryId": _rid(recovery_id),
                 "operationId": operation_id(recovery_id), "target": self.target,
                 "machine": self.machine, "connectionBefore": observed.connection,
                 "bootBefore": observed.boot, "accountBefore": observed.account,
                 "sessionBefore": observed.session, "originalOwner": original_owner}
        name = self._name(recovery_id, "intent")
        before = self._read(name)
        if before is not None:
            _need(before == value, "macos_lifecycle_original_changed")
            return before
        self.directory.guard()
        self._publish(name, value)
        self.directory.guard()
        return value

    def consume(self, recovery_id, observed):
        """Publish before the first power/start effect.  Never consumes twice."""
        intent = self._read(self._name(recovery_id, "intent"))
        _need(intent is not None, "macos_lifecycle_admission_missing")
        _need(all(getattr(observed, key) == intent[field] for key, field in
                  (("target", "target"), ("machine", "machine"),
                   ("connection", "connectionBefore"), ("boot", "bootBefore"),
                   ("account", "accountBefore"), ("session", "sessionBefore"))),
              "macos_lifecycle_identity_changed")
        if intent["action"] in {"reboot", "shutdown", "suspend"}:
            require_idle(observed)
        elif intent["action"] == "start":
            _need(observed.guest == "stopped", "macos_lifecycle_state_changed")
        else:
            _need(observed.guest == "suspended", "macos_lifecycle_state_changed")
        value = {"schemaVersion": 1, "operationId": intent["operationId"],
                 "recoveryId": recovery_id, "intentSha256": _digest(intent),
                 "state": "unknown", "replacementForbidden": True}
        name = self._name(recovery_id, "effect")
        if self._read(name) is not None:
            raise LifecycleBlocked("macos_lifecycle_original_effect_pending")
        self._publish(name, value)
        self.directory.guard()
        return value

    def _publish(self, name, value):
        """Publish through the held directory FD, never a replaced parent path."""
        self.directory.guard()
        stage = ".lifecycle-stage-" + str(uuid.uuid4())
        descriptor = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.directory.fd)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())
                stream.flush(); os.fsync(stream.fileno())
            self.directory.guard()
            os.link(stage, name, src_dir_fd=self.directory.fd,
                    dst_dir_fd=self.directory.fd, follow_symlinks=False)
            os.fsync(self.directory.fd)
            self.directory.guard()
        finally:
            os.unlink(stage, dir_fd=self.directory.fd)

    def status(self, recovery_id):
        """Pure original observation; never creates a journal, starts, or wakes."""
        intent = self._read(self._name(recovery_id, "intent"))
        if intent is None:
            return {"state": "unsubmitted", "recoveryId": _rid(recovery_id)}
        effect = self._read(self._name(recovery_id, "effect"))
        terminal = self._read(self._name(recovery_id, "terminal"))
        if effect is not None:
            _need(effect == {"schemaVersion": 1, "operationId": intent["operationId"],
                  "recoveryId": recovery_id, "intentSha256": _digest(intent),
                  "state": "unknown", "replacementForbidden": True},
                  "macos_lifecycle_original_changed")
        if terminal is not None:
            _need(effect is not None and terminal.get("intentSha256") == _digest(intent)
                  and terminal.get("operationId") == intent["operationId"]
                  and terminal.get("recoveryId") == recovery_id,
                  "macos_lifecycle_original_changed")
            return terminal
        return {"state": "unknown" if effect else "unsubmitted",
                "operationId": intent["operationId"], "recoveryId": recovery_id}


def _digest(value):
    # Lifecycle records contain public identities only, never credential data.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class DelegateOutcomes:
    """Discard raw Tart output; retain only exact reviewed delegate outcomes.

    VZ reports guestDidStop and didStopWithError through the same semaphore.
    Exit zero therefore proves neither a graceful stop nor a successful save.
    No unrecognized line, error detail, VNC URL or derived hash is retained.
    """
    def __init__(self):
        self._line = bytearray()
        self._overflow = False
        self.outcome = None

    def feed(self, stream, data):
        if stream != "stdout": return
        for byte in data:
            if byte == 10:
                if not self._overflow:
                    line = bytes(self._line).removesuffix(b"\r")
                    kind = None
                    if line == b"guest has stopped the virtual machine":
                        kind = "guest_did_stop"
                    elif line.startswith(b"guest has stopped the virtual machine due to error: "):
                        kind = "guest_stop_error"
                    elif line == b"snapshot created successfully! shutting down the VM...":
                        kind = "save_complete"
                    if kind is not None:
                        self.outcome = kind if self.outcome is None else "ambiguous"
                self._line.clear(); self._overflow = False
            elif not self._overflow:
                if len(self._line) >= 1024:
                    self._line.clear(); self._overflow = True
                else:
                    self._line.append(byte)


def terminal_state(exit_code, delegate_outcome, saved):
    """Keep physically OFF with unknown cause separate from clean closure."""
    if exit_code == 0 and delegate_outcome == "guest_did_stop" and saved is None:
        return "stopped"
    if exit_code == 0 and delegate_outcome == "save_complete" and saved is not None:
        return "suspended"
    return "off_unknown"


@dataclass(frozen=True, init=False)
class KnownOffAdmission:
    """Source-produced permission to recover OFF without relabeling its cause.

    This distinct type must never be accepted as a clean-stop receipt. The
    future custody producer must authenticate the original full terminal
    streams, absent original actors/holders, persisted artifacts and the seven
    prestop idle categories before constructing it. No public Boolean factory
    or constructor is available.
    """
    target: str
    machine: str
    predecessor: str
    power_recovery_id: str
    proof_sha256: str


@dataclass(frozen=True)
class LaunchOwner:
    """Reference derived only from an authenticated original RUN admission.

    A later reference must retain its exact predecessor.  No ``running`` flag,
    current PID guess, or connection alias is accepted as an owner receipt.
    """
    root: Path
    operation_id: str
    host_binding: jobs.MachineBinding
    job_generation: tuple[int, int]
    program_sha256: str
    argv: tuple[str, ...]
    predecessor: str | None = None

    def __post_init__(self):
        _uuid(self.operation_id)
        if self.predecessor is not None: _uuid(self.predecessor)
        _need(type(self.host_binding) is jobs.MachineBinding
              and type(self.job_generation) is tuple and len(self.job_generation) == 2
              and all(type(value) is int and value > 0 for value in self.job_generation)
              and type(self.program_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", self.program_sha256)
              and type(self.argv) is tuple and self.argv and all(type(item) is str for item in self.argv),
              "macos_launch_owner_invalid")

    def observe(self, *, saved_path, deadline):
        """Original process/receipt reconciliation.  This never starts a VM."""
        from .readiness_tart_macos_registry import PublicActor
        with private.Directory(Path(self.root)) as held:
            status = jobs.observe(Path(self.root) / "jobs", self.operation_id,
                                  self.host_binding, generation=self.job_generation)
            if status["state"] not in {"running", "terminal"}:
                return {"state": "unknown", "operationId": self.operation_id}
            intent = jobs._intent(Path(self.root) / "jobs" / self.operation_id,
                                  self.operation_id, self.host_binding)
            _need(intent["programSha256"] == self.program_sha256,
                  "macos_launch_original_program_changed")
            def read(name):
                try:
                    with private.Snapshot(held, name) as snapshot: return json.loads(snapshot.body)
                except FileNotFoundError: return None
            endpoint = read("endpoint.json")
            child_record = read("child.json")
            child = None
            if endpoint is not None:
                _need(type(endpoint) is dict and endpoint.get("operationId") == self.operation_id
                      and type(endpoint.get("port")) is int and 1 <= endpoint["port"] <= 65535,
                      "macos_launch_original_endpoint_changed")
                child = Actor(**endpoint["child"])
            elif child_record is not None:
                _need(child_record.get("operationId") == self.operation_id,
                      "macos_launch_original_endpoint_changed")
                child = Actor(**child_record["child"])
            if child is not None and child.present():
                _need(status["state"] == "running", "macos_launch_terminal_actor_present")
                PublicActor(child.pid, child.birth, self.argv[0], self.argv).guard(deadline=deadline)
                if endpoint is None:
                    return {"state": "starting", "operationId": self.operation_id,
                            "actor": {"pid": child.pid, "birth": child.birth}}
                return {"state": "running", "operationId": self.operation_id,
                        "actor": {"pid": child.pid, "birth": child.birth},
                        "endpoint": endpoint, "root": str(self.root),
                        "connection": "tart:" + str(child.pid) + ":" + child.birth}
            if status["state"] == "running":
                # The original wrapper may still be draining retained output.
                return {"state": "starting" if child is None else "unknown",
                        "operationId": self.operation_id}
            # A terminal wrapper alone cannot prove that no child escaped.
            terminal = read("child-terminal.json")
            if child is None or terminal is None:
                return {"state": "unknown", "operationId": self.operation_id}
            _need(terminal.get("operationId") == self.operation_id
                  and terminal.get("child") == {"pid": child.pid, "birth": child.birth}
                  and type(terminal.get("exitCode")) is int,
                  "macos_launch_original_terminal_changed")
            jobs.collect(Path(self.root) / "jobs", self.operation_id,
                         self.host_binding, generation=self.job_generation)
            state = saved_state(saved_path)
            outcome = terminal.get("delegateOutcome")
            _need(outcome in {None, "guest_did_stop", "guest_stop_error", "save_complete", "ambiguous"},
                  "macos_launch_original_terminal_changed")
            return {"state": terminal_state(terminal["exitCode"], outcome, state),
                    "stopOutcome": outcome or "unobserved", "operationId": self.operation_id,
                    "originalActor": {"pid": child.pid, "birth": child.birth},
                    "connection": "tart:" + str(child.pid) + ":" + child.birth,
                    "savedState": state}


def current_instance(owners, *, saved_path, deadline):
    """Follow an authenticated contiguous launch chain without selecting a VM.

    Custody loads these refs from create-only predecessor receipts.  Every
    previous owner must be terminal/collected and its exact actor absent before
    a successor can represent the same persisted fixture.
    """
    _need(type(owners) is tuple and owners and all(type(item) is LaunchOwner for item in owners),
          "macos_launch_chain_invalid")
    seen = set()
    for index, owner in enumerate(owners):
        _need(owner.operation_id not in seen and
              (owner.predecessor is None if index == 0 else owner.predecessor == owners[index-1].operation_id),
              "macos_launch_chain_invalid")
        seen.add(owner.operation_id)
        value = owner.observe(saved_path=saved_path, deadline=deadline)
        if index < len(owners)-1:
            _need(value["state"] in {"stopped", "suspended"}, "macos_launch_predecessor_unresolved")
    return value


def start_program(binding, custody, recovery_id, launch_root, *, deadline):
    """Build the qualified private-output owner for the SAME persisted fixture.

    This is preparation only.  Custody admits resources and publishes authority
    for the actual durable wrapper before it may spawn Tart.  The original
    native manager's PTY redaction is preserved; raw VNC output cannot reach
    retained streams.  A lost manager acknowledgement never submits a successor.
    """
    from . import readiness_tart_macos as mac, readiness_tart_output as output
    _need(type(binding) is mac.MacBinding and custody.binding == binding,
          "macos_lifecycle_target_changed")
    _need(_EXECUTING_CODE == compile(Path(__file__).read_bytes(), __file__, "exec",
                                    dont_inherit=True, optimize=sys.flags.optimize),
          "macos_lifecycle_source_changed")
    current = custody.guard(deadline=deadline)
    _need(current["state"] in {"stopped", "suspended"}, "macos_lifecycle_state_changed")
    original = custody.run_intent["plan"]
    operation = operation_id(recovery_id)
    launch_root = Path(launch_root)
    _need(launch_root == custody.lifecycle_root / "macos-launches" / operation,
          "macos_lifecycle_owner_root_invalid")
    with private.Directory(launch_root) as held:
        generation = list(private._directory_identity(os.fstat(held.fd)))
    target = Path(binding.fixture_root)
    config = target / "config.json"
    before = private._generation(config.lstat()); raw = config.read_bytes()
    _need(private._generation(config.lstat()) == before
          and hashlib.sha256(raw).hexdigest() == original["configSha256"],
          "macos_lifecycle_config_changed")
    disk = target / "disk.img"; disk_info = disk.lstat()
    _need(stat.S_ISREG(disk_info.st_mode) and disk_info.st_nlink == 1
          and disk_info.st_uid == os.geteuid() and not disk_info.st_mode & 0o077
          and list(private._generation(disk_info)[:6]) == original["diskGeneration"][:6],
          "macos_lifecycle_disk_changed")
    nvram = target / "nvram.bin"; nvram_info = nvram.lstat()
    _need(stat.S_ISREG(nvram_info.st_mode) and nvram_info.st_nlink == 1
          and nvram_info.st_uid == os.geteuid() and not nvram_info.st_mode & 0o077
          and nvram_info.st_size > 0, "macos_lifecycle_nvram_unsafe")
    state = target / "state.vzvmsave"
    saved = saved_state(state)
    _need((saved is None) == (current["state"] == "stopped"), "macos_lifecycle_saved_state_changed")
    custody._public_share.guard()
    values = {"root": str(launch_root), "rootGeneration": generation, "operationId": operation,
              "fixtureName": binding.vm_name, "fixtureDirectory": binding.fixture_root,
              "tart": binding.tart_binary, "binaryGeneration": original["binaryGeneration"],
              "binarySha256": original["binarySha256"], "diskGeneration": list(private._generation(disk_info)),
              "diskCapacityBytes": disk_info.st_size, "memoryMiB": binding.memory_mib,
              "configGeneration": list(before), "configSha256": original["configSha256"],
              "nvramGeneration": list(private._generation(nvram_info)),
              "bootstrapShare": original["bootstrapShare"],
              "publicSharePins": list(custody._public_share.rows.values()),
              "storageLedger": original["storageLedger"], "memoryLedger": original["memoryLedger"],
              "storageFixtureId": binding.storage_fixture_id, "reservationKey": original["reservationKey"],
              "hostBoot": custody.host_binding.boot, "expectedState": current["state"],
              "savedStateGeneration": list(private._generation(state.lstat())) if saved else None}
    source = output.standalone_source() + inspect.getsource(jobs._birth) + "\n" + inspect.getsource(DelegateOutcomes) + "\n" + _START_BODY
    source += ("\nwith _output_private.Directory(Path(" + repr(str(launch_root)) + ")) as root_guard, "
               "_output_private.Directory(Path(" + repr(binding.fixture_root) + ")) as fixture_guard:\n"
               " run(" + repr(values) + ")\n")
    return jobs.Program("tart-macos-existing-instance-v1", source.encode(), stream_limit=262144)


# Ported from the actual qualified initial manager; no private plan or input.
# Original run() public SHA256: b78ee703c51e2e62ea8689a7e2bb51e09c56048ac90a3f57577130ec8bd2a3b2
_START_BODY = r'''import errno,hashlib,json,os,pty,resource,selectors,stat,subprocess,sys,time
from pathlib import Path
def require(value,reason):
 if not value:raise RuntimeError(reason)
def generation(s):
 return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def publish(path,value):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:json.dump(value,f,sort_keys=True);f.flush();os.fsync(f.fileno())
def read_record(path,*,private=True):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  before=os.fstat(f.fileno());require(stat.S_ISREG(before.st_mode)and before.st_uid==os.geteuid()and (stat.S_IMODE(before.st_mode)==0o600 if private else not before.st_mode&0o022) and before.st_nlink==1 and before.st_size<=1048576,'run_private_record_unsafe')
  raw=f.read(1048577);after=os.fstat(f.fileno())
 require(generation(before)==generation(after)==generation(path.lstat()),'run_private_record_changed')
 return json.loads(raw)
def run(plan):
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 os.umask(0o077);root=Path(plan['root']);info=root.lstat();require(stat.S_ISDIR(info.st_mode)and stat.S_IMODE(info.st_mode)==0o700 and info.st_uid==os.geteuid()and[info.st_dev,info.st_ino]==plan['rootGeneration'],'run_owner_root_changed')
 actor={'operationId':plan['operationId'],'pid':os.getpid(),'birth':_birth(os.getpid())};require(actor['birth']is not None,'run_owner_unavailable');publish(root/'actor.json',actor)
 until=time.monotonic()+180
 while not(root/'authority.json').exists():
  require(time.monotonic()<until,'run_unsubmitted_authority_expired');time.sleep(.05)
 expected={'operationId':plan['operationId'],'actor':actor,'storageFixtureId':plan['storageFixtureId'],'reservationKey':plan['reservationKey'],'hostBoot':plan['hostBoot']}
 require(read_record(root/'authority.json')==expected and _birth(actor['pid'])==actor['birth'],'run_authority_changed')
 binary=Path(plan['tart']);target=Path(plan['fixtureDirectory']);disk=target/'disk.img';config=target/'config.json';nvram=target/'nvram.bin'
 require(generation(binary.lstat())==tuple(plan['binaryGeneration'])and hashlib.sha256(binary.read_bytes()).hexdigest()==plan['binarySha256'],'run_binary_changed')
 require(generation(disk.lstat())==tuple(plan['diskGeneration'])and generation(config.lstat())==tuple(plan['configGeneration'])and hashlib.sha256(config.read_bytes()).hexdigest()==plan['configSha256'],'run_fixture_changed')
 require(generation(nvram.lstat())==tuple(plan['nvramGeneration']),'run_nvram_changed')
 claim=read_record(Path(plan['storageLedger']))['plans'][plan['storageFixtureId']]
 require(claim['state']=='pending'and claim['writerPid']==actor['pid']and claim['directory']==str(target)and claim['disks']==[{'path':str(disk),'capacityBytes':plan['diskCapacityBytes']}],'run_storage_writer_changed')
 memory=read_record(Path(plan['memoryLedger']),private=False)
 require(memory.get('schema_version')==1 and memory.get('reservations',{}).get(plan['reservationKey'])=={'memory_mib':plan['memoryMiB'],'pid':0},'run_pending_memory_claim_changed')
 boot=subprocess.run(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],stdin=subprocess.DEVNULL,capture_output=True,timeout=3,check=True)
 require(boot.stdout.decode('ascii').strip()==plan['hostBoot'],'run_host_boot_changed')
 environment={k:v for k,v in os.environ.items()if k in{'HOME','USER','LOGNAME','PATH','LANG','LC_ALL','TMPDIR'}}
 environment.update(TART_HOME=str(Path.home()/'.tart'),TART_NO_AUTO_PRUNE='1')
 listing=subprocess.run([str(binary),'list','--format','json'],stdin=subprocess.DEVNULL,capture_output=True,timeout=5,check=True,env=environment)
 rows=json.loads(listing.stdout);matches=[row for row in rows if row.get('Name')==plan['fixtureName']];require(len(matches)==1 and matches[0].get('State')==plan['expectedState'],'run_original_instance_not_stopped')
 require(read_record(root/'authority.json')==expected and _birth(actor['pid'])==actor['birth'],'run_authority_changed')
 share=Path(plan['bootstrapShare'])
 actual_paths=sorted(str(p.relative_to(share))for p in share.rglob('*'))
 require(actual_paths==sorted(row['path']for row in plan['publicSharePins']),'run_public_share_changed')
 for row in plan['publicSharePins']:
  item=share/row['path'];require(generation(item.lstat())==tuple(row['generation']),'run_public_share_changed')
  if row['kind']=='file':require(hashlib.sha256(item.read_bytes()).hexdigest()==row['sha256'],'run_public_share_integrity_changed')
  elif row['kind']=='symlink':require(os.readlink(item)==row['target']and item.resolve().is_relative_to(share),'run_public_share_link_changed')
  else:require(item.is_dir(),'run_public_share_changed')
 state_path=target/'state.vzvmsave'
 if plan['expectedState']=='stopped':require(not state_path.exists()and not state_path.is_symlink(),'run_unexpected_saved_state')
 else:
  state=state_path.lstat();require(generation(state)==tuple(plan['savedStateGeneration'])and stat.S_ISREG(state.st_mode)and not state.st_mode&0o077 and state.st_nlink==1,'run_saved_state_changed')
 root_guard.guard();fixture_guard.guard()
 require(generation(nvram.lstat())==tuple(plan['nvramGeneration']),'run_nvram_changed')
 with _tart_output.ProtectedRunOutput(root) as protected:
  master,slave=pty.openpty()
  try:
   command=[str(binary),'run',plan['fixtureName'],'--no-graphics','--vnc-experimental','--suspendable','--dir','bootstrap:'+plan['bootstrapShare']+':ro']
   require(generation(nvram.lstat())==tuple(plan['nvramGeneration']),'run_nvram_changed')
   # The ONLY raw-output descriptors are this private PTY and private pipe.
   # Neither is inherited by the durable owner's retained stdout/stderr.
   child=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=slave,stderr=subprocess.PIPE,env=environment,close_fds=True)
  finally:os.close(slave)
  birth=_birth(child.pid);require(birth is not None,'run_original_child_generation_unavailable')
  child_actor={'pid':child.pid,'birth':birth};publish(root/'child.json',{'operationId':plan['operationId'],'actor':actor,'child':child_actor,'fixtureName':plan['fixtureName']})
  endpoint_published=False;privacy_blocked=False;started=time.monotonic();outcomes=DelegateOutcomes()
  with selectors.DefaultSelector()as selector:
   selector.register(master,selectors.EVENT_READ,'stdout');selector.register(child.stderr,selectors.EVENT_READ,'stderr')
   while selector.get_map():
    for key,_ in selector.select(.25):
     try:data=os.read(key.fd,4096)
     except OSError as error:
      if key.data=='stdout'and error.errno==errno.EIO:data=b''
      else:raise RuntimeError('run_private_stream_unavailable')from None
     if not data:selector.unregister(key.fileobj);continue
     outcomes.feed(key.data,data)
     if privacy_blocked:continue
     try:
      protected.feed(key.data,data);endpoint=protected.endpoint()
      if endpoint is not None and not endpoint_published:
       require(_birth(child.pid)==birth,'run_original_child_changed')
       publish(root/'endpoint.json',{'operationId':plan['operationId'],'actor':actor,'child':child_actor,'port':endpoint['port'],'credentialMetadata':protected.credential_metadata()})
       endpoint_published=True
     except _tart_output.OutputBlocked as error:
      privacy_blocked=True
      publish(root/'privacy-blocked.json',{'operationId':plan['operationId'],'reason':str(error),'originalChild':child_actor,'rawOutputRetained':False})
    if not endpoint_published and time.monotonic()-started>180 and not(root/'endpoint-unresolved.json').exists():
     publish(root/'endpoint-unresolved.json',{'operationId':plan['operationId'],'reason':'original_run_endpoint_not_ready','originalChild':child_actor,'replacementForbidden':True})
  os.close(master);code=child.wait()
  publish(root/'child-terminal.json',{'operationId':plan['operationId'],'child':child_actor,'exitCode':code,'endpointPublished':endpoint_published,'privacyBlocked':privacy_blocked,'delegateOutcome':outcomes.outcome,'rawOutputRetained':False})
  # Only fixed public closure reaches the durable owner; never raw stream bytes.
  print(json.dumps({'operationId':plan['operationId'],'originalChildExitCode':code,'rawOutputRetained':False}),flush=True)
  raise SystemExit(code)
'''
