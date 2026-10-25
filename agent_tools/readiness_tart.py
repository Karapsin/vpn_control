"""Qualified Tart guest readiness, separate from transport and durable job identity.

Only an internally registered owned fixture can construct the custody object.
Linux GUI/session recovery is deliberately absent. Power dispatch is never local.
"""
from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import uuid
import inspect

from . import durable_remote_job as jobs
from . import private_inventory_lock as private
from . import readiness
from . import readiness_providers as providers
from . import readiness_qemu_jobs as guest_protocol


class TartError(providers.ProviderError):
    """Only fixed reason identifiers cross this boundary."""


def _need(value, reason):
    if not value:
        raise TartError(reason)


@dataclass(frozen=True)
class TartBinding:
    target: str
    machine: str
    vm_name: str
    tart_binary: Path
    fixture_root: Path
    expected_account: str = "admin"
    expected_uid: int = 1000
    memory_mib: int = 4096
    storage_fixture_id: str = ""

    def __post_init__(self):
        _need(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,95}", self.vm_name) and
              self.vm_name.startswith("vpn-tool-recovery-tart-"), "tart_fixture_name_invalid")
        _need(self.tart_binary.is_absolute() and self.fixture_root.is_absolute() and
              self.fixture_root.name == self.vm_name, "tart_fixture_path_invalid")
        _need(type(self.expected_uid) is int and self.expected_uid > 0 and
              type(self.memory_mib) is int and self.memory_mib >= 4096 and
              re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", self.expected_account), "tart_account_invalid")
        _need(bool(self.target) and bool(re.fullmatch(r"[0-9a-f]{32}", self.machine)), "tart_machine_invalid")


@dataclass(frozen=True)
class TartGuestExecutor:
    """Private fixed-protocol dispatcher bound to actual current guest identity."""
    provider: str
    target: str
    machine: str
    boot: str
    uid: int
    principal: str
    home: str
    _backend: object
    _observation: object
    _deadline: float

    def execute(self, argv, *, payload=None):
        current = self._backend.observe(readiness.Requirements(frozenset({"guest_agent"})), self._deadline)
        fields = ("target", "machine", "connection", "boot", "account", "session")
        _need(current.guest_agent and all(getattr(current, key) == getattr(self._observation, key) for key in fields),
              "tart_guest_executor_stale")
        result, _ = self._backend._guest(tuple(argv), self._deadline, payload=payload)
        return result


def canonical_job_facts(value):
    """Project only a complete source-bound original namespace observation."""
    _need(type(value) is dict and set(value) == {"visibilityComplete", "jobs", "idle"}
          and value["visibilityComplete"] is True and type(value["jobs"]) is list
          and len(value["jobs"]) <= 1024 and type(value["idle"]) is bool,
          "tart_guest_job_projection_invalid")
    running, unknown = [], []
    operations = set()
    for row in value["jobs"]:
        _need(type(row) is dict and type(row.get("operationId")) is str
              and row.get("state") in {"running", "terminal", "unknown", "unsubmitted"},
              "tart_guest_job_projection_invalid")
        operation = str(uuid.UUID(row["operationId"]))
        _need(operation == row["operationId"] and operation not in operations,
              "tart_guest_job_projection_invalid")
        operations.add(operation)
        projected = {"operationId": operation, "role": "durable_" + row["state"]}
        if row["state"] == "running":
            running.append(projected)
        elif row["state"] != "terminal":
            unknown.append(projected)
    _need(value["idle"] == (not running and not unknown), "tart_guest_job_projection_invalid")
    return running, unknown


def _record(path):
    path = Path(path)
    presented = private.PresentedPath(path.parent)
    with private.Directory(presented.canonical) as directory:
        with private.Snapshot(directory, path.name) as value:
            result = json.loads(value.body)
            _need(type(result) is dict, "tart_record_invalid")
            value.guard(); presented.guard()
            return result


def _run(argv, deadline, *, payload=None):
    remaining = deadline - time.monotonic()
    _need(math.isfinite(remaining) and remaining > 0, "tart_readiness_deadline")
    try:
        value = subprocess.run(argv, input=payload, stdin=subprocess.DEVNULL if payload is None else None,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(10, remaining), check=False)
    except subprocess.TimeoutExpired:
        raise TartError("tart_observation_timeout") from None
    _need(len(value.stdout) <= 262144 and len(value.stderr) <= 262144, "tart_observation_overflow")
    return value


def _process(actor, deadline=None):
    _need(type(actor) is dict and set(actor) == {"pid", "birth"} and type(actor["pid"]) is int
          and actor["pid"] > 0 and type(actor["birth"]) is str, "tart_actor_invalid")
    observed = jobs._birth(actor["pid"])
    if observed is None:
        return None
    _need(observed == actor["birth"], "tart_actor_generation_changed")
    value = _run(["ps", "-ww", "-p", str(actor["pid"]), "-o", "uid=", "-o", "command="],
                 time.monotonic() + 10 if deadline is None else deadline)
    _need(value.returncode == 0, "tart_actor_unavailable")
    fields = value.stdout.decode("utf-8", errors="strict").strip().split(None, 1)
    _need(len(fields) == 2 and fields[0].isdigit() and int(fields[0]) == os.geteuid()
          and jobs._birth(actor["pid"]) == actor["birth"], "tart_actor_generation_changed")
    return shlex.split(fields[1])


def current_instance(binding, lifecycle_root, seed_actor, host_binding, job_root_generation, *, deadline=None):
    """Observe one original launch; missing ownership never authorizes a new VM."""
    lifecycle_root = Path(lifecycle_root)
    active_path = lifecycle_root / "active.json"
    if active_path.exists() or active_path.is_symlink():
        active = _record(active_path)
        _need(set(active) == {"version", "operationId", "recoveryIdentity", "actor"} and
              active["version"] == 1 and type(active["recoveryIdentity"]) is str and
              re.fullmatch(r"[0-9a-f]{64}", active["recoveryIdentity"]), "tart_active_record_invalid")
        operation = str(uuid.UUID(active["operationId"]))
        _need(operation == active["operationId"], "tart_operation_invalid")
        actor = active["actor"]
        original = jobs.observe(lifecycle_root / "jobs", operation, host_binding, generation=job_root_generation)
        _need(original["state"] != "unknown", "tart_original_launch_unknown")
        _need(original["state"] in {"running", "terminal"}, "tart_original_launch_unsubmitted")
        job_state = original["state"]
        operator = actor
    else:
        _need(set(seed_actor) == {"pid", "birth", "operatorPid", "operatorBirth", "operationId", "terminalPath"},
              "tart_seed_actor_invalid")
        actor = {"pid": seed_actor["pid"], "birth": seed_actor["birth"]}
        operation = seed_actor["operationId"]
        operator = {"pid": seed_actor["operatorPid"], "birth": seed_actor["operatorBirth"]}
        terminal = Path(seed_actor["terminalPath"])
        job_state = "terminal" if terminal.exists() else "running"
        if job_state == "terminal":
            receipt = _record(terminal)
            _need(receipt.get("operationIdentity") == operation and receipt.get("fixture") == binding.vm_name
                  and type(receipt.get("exitCode")) is int, "tart_native_terminal_invalid")
    command = _process(actor, deadline)
    value = _run([str(binding.tart_binary), "get", binding.vm_name, "--format", "json"],
                 time.monotonic() + 10 if deadline is None else deadline)
    _need(value.returncode == 0, "tart_instance_unavailable")
    state = json.loads(value.stdout)
    _need(type(state) is dict and state.get("OS") == "linux" and state.get("Memory") == binding.memory_mib
          and state.get("State") in {"running", "stopped", "suspended"}
          and type(state.get("Running")) is bool, "tart_instance_state_invalid")
    running = state["State"] == "running" and state["Running"]
    if command is None:
        _need(not running and job_state == "terminal", "tart_original_actor_missing")
    else:
        expected = [str(binding.tart_binary), "run", "--no-graphics", "--no-audio", "--no-clipboard", binding.vm_name]
        if command != expected:
            _need(active_path.exists() and job_state == "running" and not running,
                  "tart_actor_command_changed")
            return {"state": "starting", "connection": "tart-job:" + operation, "actor": actor,
                    "operator": operator, "operationId": operation, "jobState": job_state}
        _need(job_state == "running", "tart_terminal_actor_still_running")
    return {"state": state["State"], "connection": "tart:" + str(actor["pid"]) + ":" + actor["birth"],
            "actor": actor, "operator": operator, "operationId": operation, "jobState": job_state}


_PROBE_GATE = ("import hashlib,json,sys; p=sys.stdin.buffer.read(262145); n,h,b,j,c,m,g=sys.argv[1:]; "
               "n=int(n); s,o=p[:n],p[n:]; "
               "assert len(s)==n and hashlib.sha256(s).hexdigest()==h and len(o)==int(m) and hashlib.sha256(o).hexdigest()==g, 'guest_source_mismatch'; "
               "exec(compile(s,'<owned-tart-readonly-probe>','exec'),{'__name__':'__main__','__baseline__':json.loads(b),'__guest_jobs__':json.loads(j),'__collected_guest_jobs__':json.loads(c),'__owner_source__':o})")


class TartBackend:
    def __init__(self, binding, custody, *, start_qualified=False, reboot_qualified=False):
        self.binding, self.custody = binding, custody
        self.capabilities = frozenset(({"start"} if start_qualified else set()) |
                                      ({"reboot"} if reboot_qualified else set()))

    def dispatch_binding(self, family):
        _need(family == "tart", "tart_dispatch_family_invalid")
        self.custody.guard()
        return {"vmName": self.binding.vm_name}

    def reconcile_ready(self, ready, deadline):
        return self.custody.reconcile_ready(ready, deadline)

    @contextmanager
    def operation_scope(self, *, deadline=None, cancelled=lambda: False):
        with self.custody.operator(deadline=deadline, cancelled=cancelled):
            self.custody.reconcile_collected_guest_programs(deadline=deadline)
            yield

    @contextmanager
    def guest_job_executor(self, *, deadline):
        # Readiness is established by the public facade before this private
        # scope. This scope only revalidates and never powers or unlocks a VM.
        with self.custody.operator(deadline=deadline):
            observed = self.observe(readiness.Requirements(frozenset({"guest_agent"})), deadline)
            _need(observed.guest == "running" and observed.guest_agent and observed.boot,
                  "tart_guest_executor_not_ready")
            identity_source = "import json,os,pwd;p=pwd.getpwuid(os.geteuid());print(json.dumps({'uid':os.geteuid(),'principal':p.pw_name,'home':p.pw_dir}))"
            result, _ = self._guest(["python3", "-I", "-B", "-c", identity_source], deadline)
            _need(result.returncode == 0, "tart_guest_executor_identity_unavailable")
            actual = json.loads(result.stdout)
            _need(type(actual) is dict and set(actual) == {"uid", "principal", "home"}
                  and actual["uid"] == self.binding.expected_uid and actual["principal"] == self.binding.expected_account
                  and type(actual["home"]) is str and actual["home"].startswith("/")
                  and not any(char in actual["home"] for char in ("\0", "\n", "\r")),
                  "tart_guest_executor_identity_changed")
            yield TartGuestExecutor("tart-linux", observed.target, observed.machine, observed.boot,
                                    actual["uid"], actual["principal"], actual["home"], self, observed, deadline)

    def _guest(self, argv, deadline, *, payload=None):
        before = self.custody.guard(deadline=deadline)
        _need(before["state"] == "running", "tart_guest_not_running")
        result = _run([str(self.binding.tart_binary), "exec", *(["-i"] if payload is not None else []),
                       self.binding.vm_name, *argv], deadline, payload=payload)
        after = self.custody.guard(deadline=deadline)
        _need(before == after, "tart_connection_generation_changed")
        return result, before

    def _canonical_jobs(self, value, deadline):
        namespace = self.custody.load_guest_namespace()
        if namespace is None:
            # The fixed probe already blocks any unadmitted namespace path.
            return value
        try:
            argv, payload = guest_protocol.stdin_command(guest_protocol.observe_program(namespace))
            reply, _ = self._guest(argv, deadline, payload=payload)
            _need(reply.returncode == 0, "tart_guest_job_observation_unavailable")
            running, unknown = canonical_job_facts(json.loads(reply.stdout))
            value["jobVisibilityComplete"] = value.get("legacyJobVisibilityComplete") is True
            value["runningJobs"].extend(running)
            value["unknownJobs"].extend(unknown)
        except (TartError, ValueError, TypeError, KeyError):
            value["jobVisibilityComplete"] = False
            value["unknownJobs"].append({"role": "canonical_owner_unresolved"})
        return value

    def observe(self, requirements, deadline):
        current = self.custody.guard(deadline=deadline)
        fields = dict(target=self.binding.target, machine=self.binding.machine,
                      connection=current["connection"], transport="ready", trusted=True, owned=True,
                      integrity=True, coordinator_host=False)
        if current["state"] != "running":
            return readiness.Observation(**fields, guest="booting" if current["state"] == "starting" else current["state"])
        source = Path(__file__).with_name("tart_linux_probe.py").read_bytes()
        owner_source = jobs.owner_source()
        guest_jobs = getattr(self.custody, "guest_jobs", [])
        collected_jobs = getattr(self.custody, "guest_collected_jobs", [])
        try:
            result, _ = self._guest(["python3", "-c", _PROBE_GATE, str(len(source)), hashlib.sha256(source).hexdigest(),
                                    json.dumps(self.custody.guest_baseline, sort_keys=True, separators=(",", ":")),
                                    json.dumps(guest_jobs, sort_keys=True, separators=(",", ":")),
                                    json.dumps(collected_jobs, sort_keys=True, separators=(",", ":")),
                                    str(len(owner_source)), hashlib.sha256(owner_source).hexdigest()],
                                    deadline, payload=source + owner_source)
        except TartError as error:
            if str(error) == "tart_observation_timeout":
                return readiness.Observation(**fields, guest="booting")
            raise
        if result.returncode:
            return readiness.Observation(**fields, guest="booting")
        value = json.loads(result.stdout)
        _need(value.get("machine") == self.binding.machine, "tart_machine_identity_changed")
        _need(value.get("account") == self.binding.expected_account and value.get("uid") == self.binding.expected_uid,
              "tart_wrong_account")
        boot = str(uuid.UUID(value["boot"]))
        _need(boot == value["boot"], "tart_boot_identity_invalid")
        _need(type(value.get("agentIdentity")) is str and re.fullmatch(r"linux:[1-9][0-9]*:[0-9]+", value["agentIdentity"]),
              "tart_guest_agent_identity_invalid")
        fields["connection"] += ":agent:" + value["agentIdentity"]
        value = self._canonical_jobs(value, deadline)
        visibility, blockers = self.custody.idle_facts(value)
        return readiness.Observation(**fields, boot=boot, account=self.binding.expected_account,
                                     session=boot + ":uid:" + str(self.binding.expected_uid), guest="running",
                                     guest_agent=True, ordinary_session="ready", display="unknown",
                                     idle_visibility=visibility, idle_blockers=blockers)

    def recover(self, action, recovery_identity, observed, deadline):
        _need(action in self.capabilities and re.fullmatch(r"[0-9a-f]{64}", recovery_identity), "tart_recovery_unqualified")
        if action == "start":
            return self._start(recovery_identity, observed, deadline)
        if action == "reboot":
            with self.custody.operator(deadline=deadline):
                current = self.observe(readiness.Requirements(frozenset({"guest_agent"})), deadline)
                fields = ("target", "machine", "connection", "boot", "account", "session")
                _need(all(getattr(current, key) == getattr(observed, key) for key in fields),
                      "tart_power_identity_changed")
                _need(current.idle_visibility == readiness.IDLE_VISIBILITY and not current.idle_blockers,
                      "tart_idle_proof_incomplete")
                return self._reboot(recovery_identity, current, deadline)
        raise TartError("tart_recovery_unqualified")

    def _start(self, recovery_identity, observed, deadline):
        current = self.custody.guard(deadline=deadline)
        _need(current["state"] == "stopped" and observed.guest == "stopped"
              and current["connection"] == observed.connection, "tart_power_identity_changed")
        operation = str(uuid.uuid5(uuid.NAMESPACE_URL, "vpn-control-tart-start:" + recovery_identity))
        root = self.custody.lifecycle_root
        original = jobs.observe(root / "jobs", operation, self.custody.host_binding,
                                generation=self.custody.job_root_generation)
        _need(original["state"] == "unsubmitted", "tart_original_launch_already_admitted")
        self.custody.admit_start(deadline)
        effect = {"action": "start", "operationId": operation, "recoveryIdentity": recovery_identity,
                  "target": self.binding.target, "machine": self.binding.machine, "bootBefore": observed.boot}
        jobs._publish(root / ("effect-" + recovery_identity + ".json"), effect)
        program = start_program(self.binding, self.custody, operation, recovery_identity)
        submitted = jobs.submit(root / "jobs", operation, self.custody.host_binding, program,
                                generation=self.custody.job_root_generation)
        _need(submitted["state"] != "unsubmitted", "tart_original_launch_unknown")
        while time.monotonic() < deadline:
            original = jobs.observe(root / "jobs", operation, self.custody.host_binding,
                                    generation=self.custody.job_root_generation)
            current = self.custody.guard(deadline=deadline)
            if current["operationId"] == operation and current["state"] == "running":
                self.custody.bind_start(current["actor"]["pid"])
                return
            _need(original["state"] != "terminal", "tart_original_launch_failed")
            time.sleep(min(.1, max(0, deadline-time.monotonic())))
        raise TartError("tart_original_launch_pending")

    def _reboot(self, recovery_identity, observed, deadline):
        root = self.custody.lifecycle_root
        jobs._publish(root / ("effect-" + recovery_identity + ".json"),
                      {"action": "reboot", "recoveryIdentity": recovery_identity,
                       "target": self.binding.target, "machine": self.binding.machine,
                       "bootBefore": observed.boot, "connectionBefore": observed.connection,
                       "account": observed.account, "session": observed.session})
        try:
            self._guest(["sudo", "-n", "systemctl", "reboot"], deadline)
        except TartError as error:
            if str(error) not in {"tart_observation_timeout", "tart_connection_generation_changed"}:
                raise
        # Any lost acknowledgement is reconciled only by observing a new boot.


def start_program(binding, custody, operation, recovery_identity):
    """Self-contained durable child; no repository import or secret in argv."""
    root = Path(custody.lifecycle_root)
    with private.Directory(root) as held:
        root_identity = list(private._directory_identity(os.fstat(held.fd)))
        try:
            with private.Snapshot(held, "active.json") as snapshot:
                previous = snapshot.digest
        except FileNotFoundError:
            previous = None
    private_source = Path(private.__file__).read_text()
    birth_source = inspect.getsource(jobs._birth)
    values = {"root": str(root), "rootIdentity": root_identity, "operationId": operation,
              "recoveryIdentity": recovery_identity, "previous": previous,
              "fixtureRoot": str(binding.fixture_root), "name": binding.vm_name,
              "binary": str(binding.tart_binary), "configPin": custody.descriptor["configPin"],
              "diskPin": custody.descriptor["diskPin"], "binaryPin": custody.descriptor["binaryPin"]}
    source = "import sys,os,json,hashlib,stat,types,subprocess\nfrom pathlib import Path\n"
    source += "p=types.ModuleType('fixed_tart_private')\nexec(compile(" + repr(private_source) + ",'<fixed-private-custody>','exec'),p.__dict__)\n"
    source += birth_source + "\nv=" + repr(values) + "\n"
    source += '''
def need(value):
    if not value: raise RuntimeError('tart_start_admission_changed')
with p.Directory(Path(v['root'])) as root, p.Directory(Path(v['fixtureRoot'])) as vm:
    need(list(p._directory_identity(os.fstat(root.fd)))==v['rootIdentity'])
    try:
        with p.Snapshot(root,'active.json') as previous: need(previous.digest==v['previous'])
    except FileNotFoundError: need(v['previous'] is None)
    fd=os.open('config.json',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=vm.fd)
    try:
        before=os.fstat(fd); raw=os.read(fd,262145)
        need(list(p._generation(before))==v['configPin']['generation'])
        need(hashlib.sha256(raw).hexdigest()==v['configPin']['sha256'])
        need(p._generation(before)==p._generation(os.fstat(fd))==p._generation(os.stat('config.json',dir_fd=vm.fd,follow_symlinks=False)))
    finally: os.close(fd)
    disk=os.stat('disk.img',dir_fd=vm.fd,follow_symlinks=False)
    need({'device':disk.st_dev,'inode':disk.st_ino,'size':disk.st_size,'uid':disk.st_uid,'mode':stat.S_IMODE(disk.st_mode)}==v['diskPin'])
    need(list(p._generation(os.stat(v['binary'],follow_symlinks=False)))==v['binaryPin'])
    observed=subprocess.run([v['binary'],'get',v['name'],'--format','json'],capture_output=True,timeout=10,check=True)
    state=json.loads(observed.stdout)
    need(state['State']=='stopped' and state['Running'] is False)
    actor={'pid':os.getpid(),'birth':_birth(os.getpid())}
    need(actor['birth'] is not None)
    active={'version':1,'operationId':v['operationId'],'recoveryIdentity':v['recoveryIdentity'],'actor':actor}
    name='actor-'+v['operationId']+'.json'
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=root.fd)
    with os.fdopen(fd,'w') as stream:
        json.dump(active,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    temporary='active-'+v['operationId']+'.json'
    fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=root.fd)
    with os.fdopen(fd,'w') as stream:
        json.dump(active,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
    root.guard();vm.guard()
    os.replace(temporary,'active.json',src_dir_fd=root.fd,dst_dir_fd=root.fd);os.fsync(root.fd)
    argv=[v['binary'],'run','--no-graphics','--no-audio','--no-clipboard',v['name']]
    os.execv(argv[0],argv)
'''
    return jobs.Program("tart-existing-instance-start", source.encode("utf-8"), stream_limit=262144)


def load_registered_fixture(root, fixture_id, descriptor, descriptor_pin):
    from . import readiness_tart_registry
    return readiness_tart_registry.load_registered_fixture(root, fixture_id, descriptor, descriptor_pin)
