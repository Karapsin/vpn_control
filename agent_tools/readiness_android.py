"""Owned existing-instance Android lifecycle, distinct from a live ADB channel.

Only private registration admits a persisted AVD and original process lineage.
New emulator processes belong to durable execution owners. A launch admission
without an actor receipt remains uncertain and can never authorize a replacement.
The only generated program execs the admitted SDK emulator with fixed arguments;
credentials and arbitrary public command inputs are not accepted.
"""
from dataclasses import asdict, replace
from contextlib import contextmanager
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from uuid import UUID, uuid5, NAMESPACE_URL

from . import durable_remote_job as jobs
from . import readiness
from . import local_fixture_admission
from . import readiness_providers as providers
from . import readiness_adb_transport
from scripts import native_fixture_storage as storage
from scripts import visual_platform as visual


def _need(condition, reason):
    if not condition:
        raise providers.ProviderError(reason)


def _process_names(raw):
    _need(type(raw) is str, "android_idle_visibility_incomplete")
    names = [line.strip() for line in raw.strip().splitlines()]
    _need(names and names[0] == "NAME" and len(names) <= 4096
          and all(names), "android_idle_visibility_incomplete")
    return names


def launch_program(job_root, operation, binding, argv, environment):
    """Snapshot all execution dependencies; no import of a changing checkout."""
    environment = dict(sorted(environment.items()))
    source = ("import sys,types,os,json\nfrom pathlib import Path\n"
              "M=types.ModuleType('android_owner_snapshot');sys.modules[M.__name__]=M\n"
              "exec(compile(" + repr(jobs.owner_source()) + ",'durable-owner-snapshot','exec'),M.__dict__)\n"
              "D=M.__dict__\n"
              "job=Path(" + repr(str(job_root / operation)) + ")\n"
              "binding=D['MachineBinding'].from_dict(" + repr(asdict(binding)) + ")\n"
              "D['_binding_live'](binding)\n"
              "intent=D['_intent'](job," + repr(operation) + ",binding)\n"
              "actor={'pid':os.getpid(),'birth':D['_birth'](os.getpid())}\n"
              "D['_need'](actor['birth'] is not None,'android_owner_generation_unavailable')\n"
              "D['_publish'](job/'emulator.json',{'actor':actor,'operationId':intent['operationId'],"
              "'generation':intent['generation'],'programSha256':intent['programSha256']})\n"
              "argv=" + repr(argv) + "\n"
              "os.execve(argv[0],argv," + repr(environment) + ")\n")
    return jobs.Program("android-existing-instance", source.encode(), stream_limit=1024 * 1024)


def _seed_owner(root, descriptor):
    """Observe the original native durable owner; a vanished PID is insufficient."""
    from . import readiness_fixture_registry as registry
    value=descriptor["initialOwner"]
    _need(type(value) is dict and set(value)=={"jobRoot","operationId","hostBinding","rootGeneration","programSha256","programPin"},
          "android_lifecycle_history_invalid")
    operation=value["operationId"]
    _need(type(operation) is str and str(UUID(operation))==operation
          and value["hostBinding"]==descriptor["hostBinding"],"android_lifecycle_history_invalid")
    host=jobs.MachineBinding.from_dict(value["hostBinding"])
    generation=value["rootGeneration"]
    _need(type(generation) is list and len(generation)==2 and all(type(n) is int and n>0 for n in generation),
          "android_lifecycle_history_invalid")
    job_root=registry._under(value["jobRoot"],Path(root)/".runtime")
    jobs._root(job_root,tuple(generation))
    intent=jobs._intent(job_root/operation,operation,host)
    _need(value["programSha256"]==intent["programSha256"]
          and intent["purpose"]=="android-existing-instance" and intent["streamLimit"]==1024*1024
          and registry._body(job_root/operation/"program.py")[1]==value["programPin"]
          and value["programPin"]["sha256"]==value["programSha256"],
          "android_lifecycle_history_invalid")
    actor=descriptor["initialActor"]
    receipt=jobs._record(job_root/operation/"emulator.json")
    _need(receipt=={"actor":actor,"operationId":operation,"generation":intent["generation"],"programSha256":value["programSha256"]},
          "android_lifecycle_history_invalid")
    result=jobs.observe(job_root,operation,host,generation=tuple(generation))
    _need(result["state"] in {"running","terminal"},"android_lifecycle_outcome_unknown")
    birth=jobs._birth(actor["pid"])
    _need(birth in (None,actor["birth"]),"android_owner_unavailable")
    _need((birth is not None and result["state"]=="running") or (birth is None and result["state"]=="terminal"),
          "android_lifecycle_outcome_unknown")
    return actor,"live" if birth is not None else "stopped",None


class AndroidInstanceBackend:
    """A registered, qualified AVD with immutable source and original lineage."""
    def __init__(self, root, descriptor, custody_guard, state_root, *, clock=time.monotonic):
        self.root, self.descriptor = Path(root), descriptor
        self.custody_guard, self.state_root, self.clock = custody_guard, Path(state_root), clock
        b = descriptor["binding"]
        self.binding = providers.AndroidBinding(b["target"], b["machine"], Path(b["adb"]),
                                                b["avdName"], b["serial"], b["serverPort"])
        self.capabilities = frozenset({"reconnect", "start", "resume", "reboot", "wake_display"})
        self.job_root = self.state_root / "jobs"
        self.host_binding = jobs.MachineBinding.from_dict(descriptor["hostBinding"])
        self.job_generation = tuple(descriptor["jobRootGeneration"])
        self.storage_plan = descriptor["storagePlan"]
        self.reservation_key=descriptor.get("memoryReservation","android")
        self.reservation_digest=hashlib.sha256(json.dumps([self.binding.target,self.binding.machine],separators=(",",":")).encode()).hexdigest()
        self._operator_held = False
        self._retry_start = False
        self._dispatch_attempt = 1
        self.avd_root = Path(descriptor["avdConfig"]).parent
        self.transport = readiness_adb_transport.OwnedAdbTransport(
            self.binding, descriptor.get("adbServer", {}), self.state_root, self.host_binding, self.custody_guard, clock=clock)
        self.adb = providers.AndroidAdbBackend(self.binding, self._live_guard, wake_qualified=True,
                                               clock=clock, deadline_guard=self._live_guard)

    def _launches(self):
        records = []
        names = sorted(self.state_root.glob("launch-*.json"))
        _need(len(names) <= 1000, "android_lifecycle_history_overflow")
        for index, path in enumerate(names):
            _need(path.name == f"launch-{index:06d}.json", "android_lifecycle_history_invalid")
            value = jobs._record(path)
            _need(set(value) == {"index", "operationId", "recoveryId", "programSha256"}
                  and value["index"] == index and re.fullmatch(r"[0-9a-f]{64}", value["recoveryId"])
                  and str(UUID(value["operationId"])) == value["operationId"], "android_lifecycle_history_invalid")
            records.append(value)
        return records

    def _current(self):
        self.custody_guard()
        records = self._launches()
        if not records:
            if "initialOwner" in self.descriptor:
                return _seed_owner(self.root,self.descriptor)
            actor = self.descriptor["initialActor"]
            actual = jobs._birth(actor["pid"])
            _need(actual in (None, actor["birth"]), "android_owner_unavailable")
            return (actor, "live" if actual else "stopped", None)
        record = records[-1]
        result = jobs.observe(self.job_root, record["operationId"], self.host_binding, generation=self.job_generation)
        if result["state"] == "unsubmitted":
            proof = self._prove_start_unsubmitted(record["recoveryId"])
            return None, "stopped" if proof is not None else "pending", record
        _need(result["state"] in {"running", "terminal", "unknown"}, "android_lifecycle_history_invalid")
        path = self.job_root / record["operationId"] / "emulator.json"
        try:
            receipt = jobs._record(path)
        except jobs.DurableJobError:
            _need(result["state"] == "running", "android_lifecycle_outcome_unknown")
            return None, "pending", record
        intent = jobs._intent(path.parent, record["operationId"], self.host_binding)
        _need(receipt == {"actor": receipt.get("actor"), "operationId": intent["operationId"],
                          "generation": intent["generation"], "programSha256": intent["programSha256"]}
              and record["programSha256"] == intent["programSha256"], "android_lifecycle_history_invalid")
        actor = receipt["actor"]
        _need(type(actor) is dict and set(actor) == {"pid", "birth"} and type(actor["pid"]) is int
              and actor["pid"] > 0 and type(actor["birth"]) is str, "android_owner_unavailable")
        actual = jobs._birth(actor["pid"])
        _need(actual in (None, actor["birth"]), "android_owner_unavailable")
        if actual:
            _need(result["state"] == "running", "android_lifecycle_outcome_unknown")
            return actor, "live", record
        if result["state"] == "terminal":
            return actor, "stopped", record
        return actor, "pending", record

    def _prove_start_unsubmitted(self, recovery_identity):
        """Pure original-owner absence proof; no missing ACK or PID is enough."""
        try:
            self.custody_guard()
            operation = str(uuid5(NAMESPACE_URL, "android-existing-instance:" + recovery_identity))
            job = self.job_root / operation
            if job.exists() or job.is_symlink():
                return None
            if jobs._birth(self.descriptor["initialActor"]["pid"]) is not None:
                return None
            program = launch_program(self.job_root, operation, self.host_binding,
                                     self.descriptor["argv"], self.descriptor["environment"])
            effect = self.state_root / ("effect-" + recovery_identity + ".json")
            if effect.exists() or effect.is_symlink():
                if jobs._record(effect) != {"action": "start", "recoveryId": recovery_identity, "operationId": operation}:
                    return None
            for record in self._launches():
                status = jobs.observe(self.job_root, record["operationId"], self.host_binding, generation=self.job_generation)
                if record["recoveryId"] == recovery_identity:
                    if (record["operationId"] != operation or record["programSha256"] != program.digest
                            or status["state"] != "unsubmitted"):
                        return None
                elif status["state"] != "terminal":
                    return None
            self._stopped_disk_guard()
            status = jobs.observe(self.job_root, operation, self.host_binding, generation=self.job_generation)
            if status["state"] != "unsubmitted" or job.exists() or job.is_symlink():
                return None
            self.custody_guard()
            return {"version": 1, "kind": "android_original_admission_absent", "recoveryId": recovery_identity,
                    "operationId": operation, "programSha256": program.digest,
                    "rootGeneration": list(self.job_generation), "target": self.binding.target, "machine": self.binding.machine}
        except Exception:
            return None

    def observe_recovery(self, action, recovery_identity, observed, deadline, attempt, dispatch_digest):
        if action != "start" or not self._operator_held or self.clock() >= deadline:
            return None
        proof = self._prove_start_unsubmitted(recovery_identity)
        if proof is None:
            return None
        proof.update(attempt=attempt, dispatchDigest=dispatch_digest)
        digest = hashlib.sha256(json.dumps(proof, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return readiness.RecoveryUnsubmitted(recovery_identity, attempt, dispatch_digest, digest)

    def recover_attempt(self, action, recovery_identity, observed, deadline, attempt, dispatch_digest):
        with self._operator(deadline=deadline):
            self._retry_start = action == "start" and attempt > 1 and self._prove_start_unsubmitted(recovery_identity) is not None
            self._dispatch_attempt = attempt
            try:
                return self._recover(action, recovery_identity, observed, deadline)
            finally:
                self._retry_start = False
                self._dispatch_attempt = 1

    def _connection(self):
        return self.transport.connection()

    def _live_guard(self, deadline=None):
        actor, state, _ = self._current()
        _need(state == "live" and actor is not None, "android_owner_unavailable")
        return self.transport.connection(deadline)

    def _stopped_disk_guard(self):
        # Foreign ownership or an unknown original launch blocks replacement.
        for disk in self.descriptor["writableDisks"]:
            result = subprocess.run(["lsof", "-t", "--", disk["path"]], stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=5, check=False)
            _need(result.returncode in (0, 1) and not result.stdout and not result.stderr,
                  "android_owner_unavailable")

    def observe(self, requirements, deadline):
        actor, state, _ = self._current()
        transport, connection = self.transport.observe(deadline)
        common = dict(target=self.binding.target, machine=self.binding.machine, connection=connection,
                      transport=transport, trusted=True, owned=True, integrity=True)
        if transport != "ready":
            return readiness.Observation(**common, guest="stopped" if state == "stopped" else "unknown")
        if state == "stopped":
            self._stopped_disk_guard()
            return readiness.Observation(**common, guest="stopped")
        if state == "pending":
            return readiness.Observation(**common, guest="booting")
        try:
            status, _ = self.adb._command(["emu", "avd", "status"], deadline)
        except providers.ProviderError as error:
            if str(error) == "android_transport_unavailable":
                return readiness.Observation(**common, guest="booting")
            raise
        if status.strip().splitlines() == ["virtual device is stopped", "OK"]:
            return readiness.Observation(**common, guest="paused")
        _need(status.strip().splitlines() == ["virtual device is running", "OK"], "android_guest_state_unrecognized")
        try:
            observed = self.adb.observe(requirements, deadline)
        except providers.ProviderError as error:
            if str(error) == "android_transport_unavailable":
                # A live, owned emulator with no responsive Android agent is
                # booting; it does not authorize another emulator or reboot.
                return readiness.Observation(**common, guest="booting")
            raise
        if (self._operator_held and observed.guest == "running" and observed.guest_agent
                and "reboot" in requirements.permitted_recoveries):
            try:
                return self._idle(observed, deadline)
            except providers.ProviderError as error:
                if str(error) not in {"android_idle_work_active", "android_idle_visibility_incomplete"}:
                    raise
                # Healthy background readiness does not require an idle guest.
                # The coordinator refuses power while these facts are blocked.
                return replace(observed, idle_blockers=frozenset({str(error)}))
        return observed

    def operation_scope(self, *, deadline=None, cancelled=lambda: False):
        return self._operator(deadline=deadline, cancelled=cancelled)

    @contextmanager
    def _operator(self, *, deadline=None, cancelled=lambda: False):
        if self._operator_held:
            yield
            return
        import fcntl
        path = self.state_root / "operator.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            _need(info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_mode & 0o777 == 0o600,
                  "android_idle_visibility_incomplete")
            limit = self.clock() + 600 if deadline is None else deadline
            while True:
                _need(not cancelled() and self.clock() < limit, "provider_deadline")
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    time.sleep(min(.05, max(0, limit - self.clock())))
            self._operator_held = True
            yield
        finally:
            self._operator_held = False
            os.close(descriptor)

    def _idle(self, observed, deadline):
        actor, state, current = self._current()
        _need(state == "live" and self._operator_held, "android_owner_unavailable")
        self._native_seed_idle(deadline)
        from . import readiness_adb_jobs
        guest_jobs = readiness_adb_jobs.active_operations(self.root, self.binding.target, self.binding.machine)
        _need(type(guest_jobs) is dict and set(guest_jobs) == {"visibility", "reservations", "runningJobs", "unknownJobs"}
              and guest_jobs["visibility"] is True and all(type(guest_jobs[key]) is list
                    for key in ("reservations", "runningJobs", "unknownJobs")), "android_idle_visibility_incomplete")
        _need(not any(guest_jobs[key] for key in ("reservations", "runningJobs", "unknownJobs")), "android_idle_work_active")
        reservations = visual._read_reservations()
        _need(reservations.get(self.reservation_key) == {"memory_mib": self.descriptor["memoryMiB"], "pid": actor["pid"]},
              "android_idle_visibility_incomplete")
        for disk in self.descriptor["writableDisks"]:
            users = subprocess.run(["lsof", "-t", "--", disk["path"]], stdin=subprocess.DEVNULL,
                                   capture_output=True, timeout=5, check=False)
            _need(users.returncode == 0 and not users.stderr and users.stdout.decode().split() == [str(actor["pid"])],
                  "android_idle_visibility_incomplete")
        for path in self.state_root.glob("effect-*.json"):
            effect = jobs._record(path)
            _need(effect.get("action") in {"start", "resume", "reboot"}, "android_idle_visibility_incomplete")
            if effect["action"] == "reboot":
                _need(effect.get("bootBefore") != observed.boot, "android_idle_work_active")
            elif effect["action"] == "resume":
                _need(observed.guest == "running", "android_idle_work_active")
            elif current is None or effect.get("operationId") != current["operationId"]:
                result = jobs.observe(self.job_root, effect["operationId"], self.host_binding, generation=self.job_generation)
                _need(result["state"] == "terminal", "android_idle_work_active")
        names, _ = self.adb._command(["shell", "ps", "-A", "-o", "NAME"], deadline)
        installers, _ = self.adb._command(["shell", "dumpsys", "package", "installs"], deadline)
        baseline = self.descriptor.get("jobBaseline")
        _need(type(baseline) is list and bool(baseline) and all(type(name) is str for name in baseline),
              "android_idle_visibility_incomplete")
        from . import readiness_android_processes
        projected = _process_names(readiness_android_processes.idle_names(names,baseline,self.adb._command,deadline))
        _need(not (set(projected[1:]) - set(baseline) - {"ps"}), "android_idle_work_active")
        visibility, blockers = providers.android_guest_idle_facts(names, installers)
        _need(not blockers and visibility == frozenset({"installers", "protected_processes"}), "android_idle_work_active")
        # Every durable launch except the current VM owner must be terminal.
        for record in self._launches():
            if current is not None and record == current:
                continue
            result = jobs.observe(self.job_root, record["operationId"], self.host_binding, generation=self.job_generation)
            _need(result["state"] == "terminal", "android_idle_work_active")
        from . import readiness_lease_workflow as leases
        admissions = self.root / ".rag_index" / "readiness-leases" / "admissions"
        if admissions.exists():
            for fixture in admissions.iterdir():
                _need(fixture.is_dir() and not fixture.is_symlink(), "android_idle_visibility_incomplete")
                for path in fixture.glob("*.json"):
                    if path.stem.endswith(".cancelled"):
                        original_path = path.with_name(path.stem[:-10] + ".json")
                        _need(original_path.is_file() and not original_path.is_symlink(),
                              "android_idle_visibility_incomplete")
                        continue
                    _need(re.fullmatch(r"[0-9a-f-]{36}", path.stem) is not None,
                          "android_idle_visibility_incomplete")
                    # Scope only after validating the complete retained local
                    # admission. A corrupt or unclassified namespace still
                    # blocks visibility; foreign target work needs no probe.
                    try:
                        leases._inputs("status", {"fixtureId": fixture.name, "operationId": path.stem})
                        state, roots = leases._paths(self.root, fixture.name, create=False)
                        original = jobs._record(path)
                        if original.get("schemaVersion") == 1:
                            original = leases._admission(state, roots, fixture.name, path.stem)[0]
                        else:
                            original = leases._external_admission(original, fixture.name, path.stem)
                    except (ValueError, OSError):
                        raise providers.ProviderError("android_idle_visibility_incomplete") from None
                    if original["readyIdentities"][:2] != [self.binding.target, self.binding.machine]:
                        continue
                    value = leases.workflow(self.root, "status", {"fixtureId": fixture.name, "operationId": path.stem})
                    _need(value.get("state") in {"expired", "cancelled", "restored"} and value.get("restored") is True
                          and value.get("jobState") == "terminal"
                          and (value.get("state")!="restored" or value.get("restorationState")=="terminal"),
                          "android_idle_work_active")
        installed, _ = self.adb._command(["shell", "pm", "list", "packages", "com.kardinal.vpncontrol"], deadline)
        _need(not installed.strip(), "android_idle_work_active")
        return replace(observed, idle_visibility=readiness.IDLE_VISIBILITY, idle_blockers=frozenset())

    def _native_seed_idle(self, deadline):
        """Close every original native bootstrap owner, including UNKNOWN roots."""
        if "initialOwner" not in self.descriptor:
            return
        from . import readiness_fixture_registry as registry
        owner=self.descriptor["initialOwner"]
        native=registry._under(owner["jobRoot"],self.root/".runtime")
        jobs._root(native,tuple(owner["rootGeneration"]))
        proofs=[Path(path) for path in self.descriptor["qualification"] if Path(path).name=="existing-start-intent.json"]
        _need(len(proofs)==1 and native.parent==proofs[0].parent,"android_idle_visibility_incomplete")
        directory=proofs[0].parent
        values={};pins={}
        for name in ("private-adb-intent.json","private-adb-ready.json","retry-launch-intent.json","existing-start-intent.json","existing-stop-before-terminal.json"):
            path=registry._under(directory/name,self.root/".runtime")
            values[name],pins[path]=registry._json(path)
        adb=values["private-adb-intent.json"];prior=values["retry-launch-intent.json"]
        seed=values["existing-start-intent.json"]["durableOwner"]
        expected={adb["operationId"],prior["operationId"],seed["operationId"]}
        _need(len(expected)==3 and all(type(op) is str and str(UUID(op))==op for op in expected)
              and {path.name for path in native.iterdir()}==expected,"android_idle_visibility_incomplete")
        _need(seed=={key:value for key,value in owner.items() if key!="programPin"}
              and adb["hostBinding"]==prior["hostBinding"]==seed["hostBinding"]==self.descriptor["hostBinding"]
              and adb["rootGeneration"]==prior["rootGeneration"]==seed["rootGeneration"]==owner["rootGeneration"]
              and prior["argv"]==self.descriptor["argv"] and prior["environment"]==self.descriptor["environment"],
              "android_idle_visibility_incomplete")
        ready=values["private-adb-ready.json"]
        _need(ready["operationId"]==adb["operationId"] and ready["server"]==self.descriptor["adbServer"]
              and ready["root"]==str(native) and ready["hostBinding"]==seed["hostBinding"]
              and ready["generation"]==owner["rootGeneration"],"android_idle_visibility_incomplete")
        host=jobs.MachineBinding.from_dict(owner["hostBinding"])
        for role,record in (("adb",adb),("prior",prior),("seed",seed)):
            _need(self.clock()<deadline,"provider_deadline")
            operation=record["operationId"];job=native/operation
            intent=jobs._intent(job,operation,host)
            source,pin=registry._body(job/"program.py");pins[job/"program.py"]=pin
            _need(intent["programSha256"]==record["programSha256"]==pin["sha256"],"android_idle_visibility_incomplete")
            if role=="adb":
                program=readiness_adb_transport.daemon_program(native,operation,host,self.binding)
                _need(source==program.source and intent["purpose"]==program.purpose,"android_idle_visibility_incomplete")
                receipt=jobs._record(job/"adb.json")
                expected_actor={key:self.descriptor["adbServer"][key] for key in ("pid","birth")}
            else:
                program=launch_program(native,operation,host,self.descriptor["argv"],self.descriptor["environment"])
                # Legacy environment dictionaries differed only in insertion
                # order. Compare fixed Python syntax without executing it.
                def normalized(raw):
                    class Ordered(ast.NodeTransformer):
                        def visit_Dict(self,node):
                            self.generic_visit(node)
                            if all(isinstance(key,ast.Constant) and type(key.value) is str for key in node.keys):
                                keys=[key.value for key in node.keys]
                                _need(len(set(keys))==len(keys),"android_idle_visibility_incomplete")
                                ordered=sorted(zip(node.keys,node.values),key=lambda pair:pair[0].value)
                                node.keys=[pair[0] for pair in ordered];node.values=[pair[1] for pair in ordered]
                            return node
                    return ast.dump(Ordered().visit(ast.parse(raw)),include_attributes=False)
                _need(normalized(source)==normalized(program.source) and intent["purpose"]==program.purpose,
                      "android_idle_visibility_incomplete")
                receipt=jobs._record(job/"emulator.json");expected_actor=receipt.get("actor")
                if role=="seed":_need(expected_actor==self.descriptor["initialActor"],"android_idle_visibility_incomplete")
            _need(receipt=={"actor":expected_actor,"operationId":operation,"generation":intent["generation"],"programSha256":intent["programSha256"]},
                  "android_idle_visibility_incomplete")
            status=jobs.observe(native,operation,host,generation=tuple(owner["rootGeneration"]))
            _need(status["state"] in {"running","terminal"},"android_idle_work_active")
            if role=="prior":
                _need(status["state"]=="terminal","android_idle_work_active")
                collected,out,err=jobs.collect(native,operation,host,generation=tuple(owner["rootGeneration"]))
                witness=values["existing-stop-before-terminal.json"]
                _need(witness["originalVmOperationId"]==operation and witness["status"]==collected
                      and base64.b64decode(witness["stdout"],validate=True)==out
                      and base64.b64decode(witness["stderr"],validate=True)==err,"android_idle_visibility_incomplete")
            elif status["state"]=="running":
                _need(type(expected_actor) is dict and jobs._birth(expected_actor["pid"])==expected_actor["birth"],
                      "android_idle_work_active")
        for path,pin in pins.items():
            _need(registry._body(path)[1]==pin,"android_idle_visibility_incomplete")

    def _bind_actor(self, actor):
        reservations = visual._read_reservations()
        expected = reservations.get(self.reservation_key)
        _need(expected in ({"memory_mib": self.descriptor["memoryMiB"], "pid": 0},
                           {"memory_mib": self.descriptor["memoryMiB"], "pid": actor["pid"]}), "android_idle_visibility_incomplete")
        visual._bind_visual_reservation(self.reservation_key, actor["pid"])
        plans = storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
        with plans._locked():
            existing = plans._read()["plans"].get(self.storage_plan)
        _need(existing is not None, "android_idle_visibility_incomplete")
        if existing["writerPid"] != actor["pid"] and existing["state"] != "retained":
            plans.settle(self.storage_plan)
        plans.bind_writer(self.storage_plan, actor["pid"])

    def reconcile_ready(self,ready,deadline):
        """Bind only the existing original VM owner after a lost client ACK."""
        _need(self._operator_held,"android_owner_unavailable")
        actor,state,record=self._current()
        _need(state=="live" and actor is not None,"android_owner_unavailable")
        if record is None and "initialOwner" not in self.descriptor:
            return  # legacy direct processes gain no durable ownership here
        observed=self.observe(ready.requirements,deadline)
        _need((observed.target,observed.machine,observed.connection,observed.boot,observed.account,observed.session)==ready.identities(),
              "android_input_identity_changed")
        reservation=visual._read_reservations().get(self.reservation_key)
        _need(reservation in ({"memory_mib":self.descriptor["memoryMiB"],"pid":0},
                              {"memory_mib":self.descriptor["memoryMiB"],"pid":actor["pid"]}),"android_idle_visibility_incomplete")
        plans=storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
        with plans._locked():
            plan=plans._read()["plans"].get(self.storage_plan)
        _need(type(plan) is dict and plan.get("directory")==str(self.avd_root)
              and plan.get("state") in {"retained","pending"},"android_idle_visibility_incomplete")
        if reservation["pid"]==actor["pid"] and plan.get("writerPid")==actor["pid"]:
            return
        self._bind_actor(actor)
        _need(self._current()==(actor,state,record),"android_owner_unavailable")

    def recover(self, action, recovery_identity, observed, deadline):
        with self._operator(deadline=deadline):
            return self._recover(action, recovery_identity, observed, deadline)

    def _recover(self, action, recovery_identity, observed, deadline):
        _need(action in self.capabilities and re.fullmatch(r"[0-9a-f]{64}", recovery_identity), "provider_recovery_unqualified")
        if action == "reconnect":
            _need(observed.target == self.binding.target and observed.machine == self.binding.machine,
                  "android_input_identity_changed")
            return self.transport.recover(recovery_identity, observed.connection, deadline)
        needed = "guest_agent" if action == "reboot" else "interactive_desktop"
        current = self.observe(readiness.Requirements(frozenset({needed})), deadline)
        _need(all(getattr(current, key) == getattr(observed, key)
                  for key in ("target", "machine", "connection", "boot", "account", "session")),
              "android_input_identity_changed")
        if action == "wake_display":
            return self.adb.recover(action, recovery_identity, observed, deadline)
        effect = self.state_root / ("effect-" + recovery_identity + ".json")
        if effect.exists() and not (action == "start" and self._retry_start):
            return  # lost ACK observes the original, never sends power again
        if action == "start":
            _need(current.guest == "stopped", "android_input_state_changed")
            self._stopped_disk_guard()
            plans = storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
            plans.settle(self.storage_plan)
            plans.check("android", "start", self.avd_root, current_fixture_id=self.storage_plan)
            # A zero-PID reservation can only be released when its signed prior
            # generation is proven terminal and every original VM actor is gone.
            reservation = visual._read_reservations().get(self.reservation_key)
            if reservation == {"memory_mib": self.descriptor["memoryMiB"], "pid": 0}:
                _need(self._current()[1] == "stopped" and bool(self._launches()), "android_idle_visibility_incomplete")
                visual._release_visual_reservation(self.reservation_key)
            memory = local_fixture_admission.memory_plan(self.descriptor["memoryMiB"], deadline)
            jobs._publish(self.state_root / ("admission-" + recovery_identity + "-attempt-" + str(self._dispatch_attempt) + ".json"), memory)
            if self.reservation_key=="android":
                visual._admit_visual_start("android", self.descriptor["memoryMiB"], storage_fixture_id=self.storage_plan)
            else:
                visual._admit_recovery_fixture_start("android-emulator",self.reservation_digest,
                    self.descriptor["memoryMiB"],storage_fixture_id=self.storage_plan)
            operation = str(uuid5(NAMESPACE_URL, "android-existing-instance:" + recovery_identity))
            program = launch_program(self.job_root, operation, self.host_binding,
                                     self.descriptor["argv"], self.descriptor["environment"])
            launches = self._launches()
            originals = [record for record in launches if record["recoveryId"] == recovery_identity]
            _need(len(originals) <= 1, "android_lifecycle_history_invalid")
            index = originals[0]["index"] if originals else len(launches)
            record = {"index": index, "operationId": operation,
                      "recoveryId": recovery_identity, "programSha256": program.digest}
            if originals:
                _need(originals[0] == record and self._retry_start, "android_lifecycle_history_invalid")
            expected_effect = {"action": action, "recoveryId": recovery_identity, "operationId": operation}
            if effect.exists():
                _need(jobs._record(effect) == expected_effect and self._retry_start, "android_lifecycle_history_invalid")
            else:
                jobs._publish(effect, expected_effect)
            if not originals:
                jobs._publish(self.state_root / f"launch-{index:06d}.json", record)
            jobs.submit(self.job_root, operation, self.host_binding, program, generation=self.job_generation)
            end = min(deadline, self.clock() + 5)
            while self.clock() < end:
                try:
                    actor, state, _ = self._current()
                except providers.ProviderError as error:
                    if str(error) != "android_lifecycle_outcome_unknown":
                        raise
                    time.sleep(min(.02, max(0, end-self.clock())))
                    continue
                if actor is not None and state == "live":
                    self._bind_actor(actor)
                    return
                time.sleep(.02)
            return
        actor, state, _ = self._current()
        _need(state == "live", "android_owner_unavailable")
        if action == "resume":
            _need(current.guest in {"paused", "suspended"}, "android_input_state_changed")
            tail = ["emu", "avd", "resume"]
        elif action == "reboot":
            self._bind_actor(actor)
            self._idle(current, deadline)
            # The full census can outlive a guest boot. Re-admit the actual
            # guest identity immediately before creating the power intent.
            fresh = self.adb.observe(readiness.Requirements(frozenset({"guest_agent"})), deadline)
            _need(all(getattr(fresh, key) == getattr(current, key)
                      for key in ("target", "machine", "connection", "boot", "account", "session")),
                  "android_input_identity_changed")
            _need(current.guest == "running", "android_input_state_changed")
            tail = ["reboot"]
        else:
            raise providers.ProviderError("provider_recovery_unqualified")
        jobs._publish(effect, {"action": action, "recoveryId": recovery_identity, "bootBefore": current.boot, "actor": actor})
        self.adb._command(tail, deadline)


def _source_pins():
    from . import readiness_fixture_registry as registry
    from . import readiness_adb_jobs
    from . import readiness_android_processes
    from scripts import fixture_environment
    modules = (registry, providers, jobs, visual, storage, fixture_environment, local_fixture_admission,
               local_fixture_admission.vm_workflow, readiness_adb_transport, readiness_adb_jobs, readiness_android_processes)
    paths = [Path(__file__), *(Path(module.__file__) for module in modules)]
    return {str(path): registry._body(path, private_file=False)[1] for path in paths}


def _argv(identity, argv):
    """Accept only the native-proven fixed emulator invocation, never commands."""
    expected = [str(Path(identity["sdk"]) / "emulator" / "emulator"), "-avd", identity["name"],
                "-port", identity["serial"].split("-", 1)[1], "-memory", str(identity["memoryMiB"]),
                "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot-load", "-no-snapshot-save",
                "-no-metrics", "-gpu", "swiftshader_indirect"]
    _need(argv == expected and Path(argv[0]).is_file() and os.access(argv[0], os.X_OK), "android_lifecycle_spec_invalid")
    return expected


def _original_server(fixture,native_start,server_port):
    """Source refresh preserves the first connection owner and its history."""
    from . import readiness_fixture_registry as registry
    if "durableOwner" not in native_start:
        return registry.adb_server_identity(server_port)
    original,_=registry._json(Path(fixture)/"private-adb-ready.json")
    owner=native_start["durableOwner"]
    _need(original.get("root")==owner["jobRoot"] and original.get("generation")==owner["rootGeneration"]
          and original.get("hostBinding")==owner["hostBinding"],"android_lifecycle_qualification_invalid")
    server=original["server"]
    _need(type(server) is dict and set(server)=={"pid","birth","uid","commandSha256"}
          and type(server["pid"]) is int and server["pid"]>0 and server["uid"]==os.geteuid()
          and type(server["birth"]) is str and type(server["commandSha256"]) is str
          and re.fullmatch(r"[0-9a-f]{64}",server["commandSha256"]),"android_lifecycle_qualification_invalid")
    return server


def load_registered_fixture(root, fixture_id, descriptor, descriptor_pin):
    from . import readiness_fixture_registry as registry
    root = Path(root).resolve(strict=True)
    fields = {"schemaVersion", "fixtureId", "provider", "lifecycle", "binding", "avdConfig", "avdConfigPin",
              "sources", "qualification", "initialActor", "adbServer", "hostBinding", "jobRootGeneration", "jobBaseline",
              "stateRoot", "storagePlan", "writableDisks", "memoryMiB", "argv", "environment"}
    _need(type(descriptor) is dict and set(descriptor) in (fields,fields|{"memoryReservation"},fields|{"initialOwner"},fields|{"memoryReservation","initialOwner"}) and descriptor["schemaVersion"] == 2
          and descriptor["fixtureId"] == fixture_id and descriptor["provider"] == "android-emulator"
          and descriptor["lifecycle"] == "owned-existing-instance", "android_lifecycle_spec_invalid")
    binding = registry._binding(descriptor["binding"])
    avd_config = registry._under(descriptor["avdConfig"], root / ".runtime")
    target = "local-android-" + hashlib.sha256(str(avd_config.parent).encode()).hexdigest()[:24]
    _need(binding.target == target and binding.machine == avd_config.parent.name.removesuffix(".avd"), "android_machine_mismatch")
    digest = hashlib.sha256(json.dumps([binding.target, binding.machine], separators=(",", ":")).encode()).hexdigest()
    if "memoryReservation" in descriptor:
        expected_key=visual._qualified_reservation_key("android-emulator",digest)
        _need(descriptor["memoryReservation"]==expected_key,"android_lifecycle_spec_invalid")
        proofs=[path for path in descriptor["qualification"] if Path(path).name=="existing-start-intent.json"]
        _need(len(proofs)==1,"android_lifecycle_qualification_invalid")
        start,_=registry._json(registry._under(proofs[0],root/".runtime"))
        _need(start.get("admission",{}).get("profile")=="infrastructure-recovery-tests"
              and start["admission"].get("reservationKey")==expected_key,"android_lifecycle_qualification_invalid")
    state_root = root / ".rag_index" / "readiness-android" / digest
    _need(Path(descriptor["stateRoot"]) == state_root and state_root.resolve(strict=True) == state_root,
          "android_lifecycle_spec_invalid")
    jobs._root(state_root / "jobs", tuple(descriptor["jobRootGeneration"]))
    jobs._binding_live(jobs.MachineBinding.from_dict(descriptor["hostBinding"]))
    expected_env = {"PATH": os.defpath, "HOME": str(Path.home()),
                    "ANDROID_AVD_HOME": str(avd_config.parent.parent),
                    "ANDROID_SDK_ROOT": str(Path(descriptor["argv"][0]).parents[1]),
                    "ANDROID_ADB_SERVER_PORT": str(binding.server_port)}
    identity = {"sdk": expected_env["ANDROID_SDK_ROOT"], "name": binding.avd_name,
                "serial": binding.serial, "memoryMiB": descriptor["memoryMiB"]}
    _argv(identity, descriptor["argv"])
    _need(descriptor["environment"] == expected_env and type(descriptor["memoryMiB"]) is int
          and 512 <= descriptor["memoryMiB"] <= 8192, "android_lifecycle_spec_invalid")

    def custody():
        current, pin = registry._json(root / ".rag_index" / "readiness-fixtures" / (fixture_id + ".json"))
        _need(current == descriptor and pin == descriptor_pin and descriptor["sources"] == _source_pins(),
              "android_lifecycle_spec_changed")
        _need(registry._body(avd_config, private_file=False)[1] == descriptor["avdConfigPin"], "android_lifecycle_spec_changed")
        for path, original in descriptor["qualification"].items():
            value = registry._under(path, root / ".runtime")
            _need(registry._body(value)[1] == original, "android_lifecycle_qualification_changed")
        jobs._binding_live(jobs.MachineBinding.from_dict(descriptor["hostBinding"]))
        return "android-fixture:" + binding.target

    custody()
    if "initialOwner" in descriptor:
        proofs=[path for path in descriptor["qualification"] if Path(path).name=="existing-start-intent.json"]
        _need(len(proofs)==1,"android_lifecycle_qualification_invalid")
        start,_=registry._json(registry._under(proofs[0],root/".runtime"))
        _need(start.get("durableOwner")=={key:value for key,value in descriptor["initialOwner"].items() if key!="programPin"},
              "android_lifecycle_qualification_invalid")
        _seed_owner(root,descriptor)
    backend = AndroidInstanceBackend(root, descriptor, custody, state_root)
    adapter = providers.ProviderAdapter("android-emulator", binding.target, binding.machine, backend)
    return registry.RegisteredFixture(binding.target, binding.machine, adapter,
                                      root / ".rag_index" / "readiness-targets" / digest)


def register_existing_instance(root, fixture_id, fixture_directory, *, server_port=5038):
    """Internal observation-only custody handoff after native direct procedures.

    No registration route is exposed through MCP/CLI. Original start/reboot/
    pause/resume/wake receipts are immutable; actual disk/config and current host
    process facts close ownership. Registration cannot replay any old operation.
    """
    from . import readiness_fixture_registry as registry
    root = Path(root).resolve(strict=True); fixture_id = registry._id(fixture_id)
    fixture = registry._under(fixture_directory, root / ".runtime")
    identity, _ = registry._json(fixture / "avd-identity.json")
    intent, _ = registry._json(fixture / "retry-launch-intent.json")
    argv = _argv(identity, intent["argv"])
    _need(intent["identity"] == identity, "android_lifecycle_spec_invalid")
    avd = registry._under(Path(identity["avdHome"]) / (identity["name"] + ".avd"), fixture)
    config = avd / "config.ini"
    native_start, _ = registry._json(fixture / "existing-start-intent.json")
    start, _ = registry._json(fixture / "existing-start-result.json")
    actor_record, _ = registry._json(fixture / "existing-start-actor.json")
    initial = actor_record["process"]
    _need(type(initial) is dict and set(initial) == {"pid", "birth", "uid", "commandSha256"}
          and initial["uid"] == os.geteuid() and jobs._birth(initial["pid"]) in (None, initial["birth"])
          and start["operationId"] == actor_record["operationId"] == native_start["operationId"]
          and start["bootBefore"] != start["bootAfter"] and start["user"] == "0"
          and start["actualAvdPath"] == [str(avd), "OK"] and native_start["originalRoot"] == str(avd)
          and native_start["configSha256"] == hashlib.sha256(config.read_bytes()).hexdigest(),
          "android_lifecycle_qualification_invalid")
    for path, generation in native_start["disks"].items():
        disk = registry._under(path, avd)
        _need([disk.stat().st_dev, disk.stat().st_ino] == generation, "android_lifecycle_qualification_invalid")
    names = ("existing-start-intent.json", "existing-start-result.json", "existing-start-actor.json",
             "direct-reboot-result.json", "direct-pause-result.json", "direct-resume-result.json", "v4-direct-core-wake.json")
    proofs = {str(fixture / name): registry._json(fixture / name) for name in names}
    reboot = proofs[str(fixture / "direct-reboot-result.json")][0]
    pause = proofs[str(fixture / "direct-pause-result.json")][0]
    resume = proofs[str(fixture / "direct-resume-result.json")][0]
    wake = proofs[str(fixture / "v4-direct-core-wake.json")][0]
    _need(reboot["bootBefore"] != reboot["bootAfter"] and reboot["user"] == "0"
          and pause["status"].strip().splitlines() == ["virtual device is stopped", "OK"]
          and resume["status"].strip().splitlines() == ["virtual device is running", "OK"]
          and wake["display"] == "ready" and wake["recoveryRecords"] >= 1,
          "android_lifecycle_qualification_invalid")
    baseline_proofs = ("direct-reboot-idle.json", "existing-stop-before-idle.json", "existing-stop-final-idle.json")
    baseline_names = set()
    for name in baseline_proofs:
        proof, pin = registry._json(fixture / name)
        projected = _process_names(proof.get("protected_processes", ""))
        baseline_names.update(projected[1:])
        proofs[str(fixture / name)] = (proof, pin)
    baseline_names.difference_update({"ps", "sh", "sleep", "toybox", "python", "python3"})
    target = "local-android-" + hashlib.sha256(str(avd).encode()).hexdigest()[:24]
    machine = identity["name"]
    digest = hashlib.sha256(json.dumps([target, machine], separators=(",", ":")).encode()).hexdigest()
    state_root = root / ".rag_index" / "readiness-android" / digest
    state_root.mkdir(mode=0o700, parents=True, exist_ok=True); jobs._private(state_root, directory=True)
    job_root = state_root / "jobs"; job_root.mkdir(mode=0o700, exist_ok=True)
    plans = storage.StoragePlans(visual.STORAGE_PLANS_ROOT)
    with plans._locked():
        candidates = [(key, value) for key, value in plans._read()["plans"].items()
                      if value["directory"] == str(avd) and value["state"] != "retired"]
    _need(len(candidates) == 1, "android_lifecycle_storage_unavailable")
    plan_id, plan = candidates[0]
    server=_original_server(fixture,native_start,server_port)
    descriptor = {"schemaVersion": 2, "fixtureId": fixture_id, "provider": "android-emulator",
                  "lifecycle": "owned-existing-instance",
                  "binding": {"target": target, "machine": machine, "adb": str(Path(identity["sdk"]) / "platform-tools/adb"),
                              "avdName": machine, "serial": identity["serial"], "serverPort": server_port},
                  "avdConfig": str(config), "avdConfigPin": registry._body(config, private_file=False)[1],
                  "sources": _source_pins(), "qualification": {path: pin for path, (_, pin) in proofs.items()}, "jobBaseline": sorted(baseline_names),
                  "initialActor": {key: initial[key] for key in ("pid", "birth")}, "adbServer": server,
                  "hostBinding": asdict(jobs.current_binding(target, os.uname().nodename)),
                  "jobRootGeneration": list(jobs.root_generation(job_root)), "stateRoot": str(state_root),
                  "storagePlan": plan_id, "writableDisks": plan["disks"], "memoryMiB": identity["memoryMiB"],
                  "argv": argv, "environment": {"PATH": os.defpath, "HOME": str(Path.home()),
                      "ANDROID_AVD_HOME": str(avd.parent), "ANDROID_SDK_ROOT": identity["sdk"],
                      "ANDROID_ADB_SERVER_PORT": str(server_port)}}
    profile=native_start.get("admission",{}).get("profile")
    _need(profile in (None,"infrastructure-recovery-tests"),"android_lifecycle_qualification_invalid")
    if profile is not None:
        key=visual._qualified_reservation_key("android-emulator",digest)
        _need(native_start["admission"].get("reservationKey")==key,"android_lifecycle_qualification_invalid")
        descriptor["memoryReservation"]=key
    if "durableOwner" in native_start:
        owner=native_start["durableOwner"]
        _need(type(owner) is dict and set(owner)=={"jobRoot","operationId","hostBinding","rootGeneration","programSha256"},
              "android_lifecycle_qualification_invalid")
        native_root=registry._under(owner["jobRoot"],fixture)
        native_host=jobs.MachineBinding.from_dict(owner["hostBinding"])
        program=launch_program(native_root,owner["operationId"],native_host,argv,descriptor["environment"])
        _need(program.digest==owner["programSha256"]
              and jobs._read(native_root/owner["operationId"]/"program.py",jobs.MAX_PROGRAM_BYTES)==program.source,
              "android_lifecycle_qualification_invalid")
        descriptor["initialOwner"]={**owner,"programPin":registry._body(native_root/owner["operationId"]/"program.py")[1]}
        _seed_owner(root,descriptor)
    directory = root / ".rag_index" / "readiness-fixtures"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True); jobs._private(directory, directory=True)
    jobs._publish(directory / (fixture_id + ".json"), descriptor)
    value, pin = registry._json(directory / (fixture_id + ".json"))
    return load_registered_fixture(root, fixture_id, value, pin)
