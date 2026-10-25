"""An owned private ADB listener, with durable daemon generations.

Observation never invokes an ADB client (which could otherwise start a server).
Only reconnect creates an admitted foreground daemon under a retained job owner.
"""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from uuid import NAMESPACE_URL, uuid5

from . import durable_remote_job as jobs
from . import readiness_providers as providers


def _need(value, reason="android_adb_lineage_unknown"):
    if not value:
        raise providers.ProviderError(reason)


def _executable(pid):
    """Kernel executable identity remains valid when ADB rewrites argv[0]."""
    if sys.platform == "darwin":
        import ctypes
        library = ctypes.CDLL("/usr/lib/libproc.dylib")
        call = library.proc_pidpath
        call.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        call.restype = ctypes.c_int
        output = ctypes.create_string_buffer(4096)
        _need(call(pid, output, len(output)) > 0, "android_adb_listener_unrecognized")
        return Path(os.fsdecode(output.value)).resolve(strict=True)
    if sys.platform.startswith("linux"):
        return Path(os.readlink("/proc/" + str(pid) + "/exe")).resolve(strict=True)
    raise providers.ProviderError("android_adb_listener_unrecognized")


def daemon_program(job_root, operation, host_binding, binding):
    argv = [str(binding.adb), "-L", "tcp:localhost:" + str(binding.server_port),
            "--one-device", binding.serial, "server", "nodaemon"]
    # Only the task's emulator range is searched; USB is restricted to its
    # emulator serial (which cannot match an attached physical USB device).
    environment = {"PATH": os.defpath, "HOME": str(Path.home()), "ADB_MDNS_AUTO_CONNECT": "",
                   "ADB_LOCAL_TRANSPORT_MAX_PORT": str(int(binding.serial.split("-")[1]) + 1)}
    source = ("import sys,types,os\nfrom pathlib import Path\n"
              "M=types.ModuleType('adb_owner_snapshot');sys.modules[M.__name__]=M\n"
              "exec(compile(" + repr(jobs.owner_source()) + ",'durable-owner-snapshot','exec'),M.__dict__)\n"
              "D=M.__dict__;job=Path(" + repr(str(job_root / operation)) + ")\n"
              "binding=D['MachineBinding'].from_dict(" + repr(asdict(host_binding)) + ")\n"
              "D['_binding_live'](binding);intent=D['_intent'](job," + repr(operation) + ",binding)\n"
              "actor={'pid':os.getpid(),'birth':D['_birth'](os.getpid())}\n"
              "D['_need'](actor['birth'] is not None,'android_adb_actor_unavailable')\n"
              "D['_publish'](job/'adb.json',{'actor':actor,'operationId':intent['operationId'],"
              "'generation':intent['generation'],'programSha256':intent['programSha256']})\n"
              "argv=" + repr(argv) + "\nos.execve(argv[0],argv," + repr(environment) + ")\n")
    return jobs.Program("android-private-adb-daemon", source.encode(), stream_limit=1024 * 1024)


class OwnedAdbTransport:
    def __init__(self, binding, original, state_root, host_binding, guard, *, clock=time.monotonic):
        self.binding, self.original = binding, original
        self.state_root, self.host_binding, self.guard, self.clock = Path(state_root), host_binding, guard, clock
        self.job_root = self.state_root / "adb-jobs"

    def _records(self):
        records = []
        for index, path in enumerate(sorted(self.state_root.glob("adb-generation-*.json"))):
            _need(index < 100 and path.name == f"adb-generation-{index:06d}.json")
            value = jobs._record(path)
            _need(set(value) == {"index", "operationId", "recoveryId", "programSha256", "jobRootGeneration"}
                  and value["index"] == index and re.fullmatch(r"[0-9a-f]{64}", value["recoveryId"]))
            program = daemon_program(self.job_root, value["operationId"], self.host_binding, self.binding)
            _need(value["operationId"] == str(uuid5(NAMESPACE_URL, "android-private-adb:" + value["recoveryId"]))
                  and value["programSha256"] == program.digest)
            records.append(value)
        return records

    def _listener(self, deadline):
        _need(self.clock() < deadline, "provider_deadline")
        reply = subprocess.run(["lsof", "-nP", "-iTCP:" + str(self.binding.server_port),
                                "-sTCP:LISTEN", "-Fp"], stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=min(5, deadline-self.clock()), check=False)
        if reply.returncode == 1 and not reply.stdout and not reply.stderr:
            return None
        _need(reply.returncode == 0 and not reply.stderr and 0 < len(reply.stdout) < 65536,
              "android_adb_listener_unrecognized")
        pids = {int(line[1:]) for line in reply.stdout.decode("ascii", "strict").splitlines()
                if line.startswith("p") and line[1:].isdigit()}
        _need(len(pids) == 1, "android_adb_listener_unrecognized")
        pid = pids.pop(); birth = jobs._birth(pid)
        _need(birth is not None, "android_adb_listener_unrecognized")
        def ps(field):
            _need(self.clock() < deadline, "provider_deadline")
            result = subprocess.run(["ps", "-ww", "-p", str(pid), "-o", field+"="], stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=min(5, deadline-self.clock()), check=False)
            _need(result.returncode == 0 and not result.stderr and 0 < len(result.stdout) < 65536,
                  "android_adb_listener_unrecognized")
            return result.stdout.decode("utf-8", "strict").strip()
        # Reject foreign executable ownership before inspecting/hashing argv.
        _need(_executable(pid) == self.binding.adb.resolve(), "android_adb_listener_unrecognized")
        uid = ps("uid")
        _need(uid.isdigit() and int(uid) == os.geteuid(), "android_adb_listener_unrecognized")
        command = ps("command")
        _need(jobs._birth(pid) == birth, "android_connection_changed")
        return {"pid":pid,"birth":birth,"uid":int(uid),"commandSha256":hashlib.sha256(command.encode()).hexdigest()}

    def observe(self, deadline):
        self.guard()
        listener = self._listener(deadline)
        records = self._records()
        if not records:
            actual = jobs._birth(self.original["pid"])
            _need(actual in (None, self.original["birth"]), "android_connection_changed")
            if actual is not None:
                _need(listener == self.original, "android_connection_changed")
                return "ready", "adb:" + str(listener["pid"]) + ":" + listener["birth"]
            _need(listener is None, "android_adb_listener_unrecognized")
            return "dead", "adb:" + str(self.original["pid"]) + ":" + self.original["birth"]
        record = records[-1]
        result = jobs.observe(self.job_root, record["operationId"], self.host_binding,
                              generation=tuple(record["jobRootGeneration"]))
        _need(result["state"] in {"running", "terminal"}, "android_adb_lineage_unknown")
        path = self.job_root / record["operationId"] / "adb.json"
        try:
            receipt = jobs._record(path)
        except jobs.DurableJobError:
            _need(result["state"] == "running" and listener is None)
            return "unavailable", "adb-job:" + record["operationId"]
        intent = jobs._intent(path.parent, record["operationId"], self.host_binding)
        actor = receipt.get("actor")
        _need(type(actor) is dict and set(actor) == {"pid", "birth"}
              and type(actor["pid"]) is int and actor["pid"] > 0 and type(actor["birth"]) is str
              and receipt == {"actor": actor, "operationId": intent["operationId"],
                              "generation": intent["generation"], "programSha256": intent["programSha256"]}
              and intent["programSha256"] == record["programSha256"])
        birth = jobs._birth(actor["pid"])
        _need(birth in (None, actor["birth"]), "android_connection_changed")
        connection = "adb:" + str(actor["pid"]) + ":" + actor["birth"]
        if birth is None:
            _need(listener is None, "android_adb_listener_unrecognized")
            _need(result["state"] == "terminal", "android_adb_lineage_unknown")
            return "dead", connection
        _need(result["state"] == "running")
        if listener is None:
            return "unavailable", connection
        _need(listener["pid"] == actor["pid"] and listener["birth"] == actor["birth"]
              and listener["uid"] == os.geteuid(), "android_adb_listener_unrecognized")
        # Pin the executable and fixed public argv, not just a reused port/PID.
        expected = " ".join([str(self.binding.adb), "-L", "tcp:localhost:" + str(self.binding.server_port),
                             "--one-device", self.binding.serial, "server", "nodaemon"])
        _need(listener["commandSha256"] == hashlib.sha256(expected.encode()).hexdigest(),
              "android_adb_listener_unrecognized")
        self.guard()
        return "ready", connection

    def connection(self, deadline=None):
        state, identity = self.observe(self.clock()+10 if deadline is None else deadline)
        _need(state == "ready", "android_transport_unavailable")
        return identity

    def recover(self, recovery_id, observed_connection, deadline):
        _need(re.fullmatch(r"[0-9a-f]{64}", recovery_id) is not None)
        state, identity = self.observe(deadline)
        _need(identity == observed_connection, "android_connection_changed")
        if state == "ready":
            return
        records = self._records()
        if records and records[-1]["recoveryId"] == recovery_id:
            return  # lost acknowledgement observes this exact durable owner
        if state == "unavailable" and records:
            return  # an admitted live owner may still be opening its listener
        _need(state == "dead", "android_adb_lineage_unknown")
        # Every prior daemon is terminal, so no delayed owner can compete.
        for record in records:
            _need(jobs.observe(self.job_root, record["operationId"], self.host_binding,
                              generation=tuple(record["jobRootGeneration"]))["state"] == "terminal")
        self.job_root.mkdir(mode=0o700, exist_ok=True)
        generation = jobs.root_generation(self.job_root)
        operation = str(uuid5(NAMESPACE_URL, "android-private-adb:" + recovery_id))
        program = daemon_program(self.job_root, operation, self.host_binding, self.binding)
        record = {"index": len(records), "operationId": operation, "recoveryId": recovery_id,
                  "programSha256": program.digest, "jobRootGeneration": list(generation)}
        # Intent precedes submission. Missing/unknown admission never grants a
        # replacement daemon; subsequent calls preserve that original identity.
        jobs._publish(self.state_root / f"adb-generation-{len(records):06d}.json", record)
        self.guard()
        _need(self._listener(deadline) is None, "android_adb_listener_unrecognized")
        jobs.submit(self.job_root, operation, self.host_binding, program, generation=generation)
        end = min(deadline, self.clock()+5)
        while self.clock() < end:
            try:
                if self.observe(deadline)[0] == "ready":
                    return
            except providers.ProviderError as error:
                # The durable owner can be publishing its first receipt after
                # submit returns. Wait on this original job only; never admit
                # a second daemon or turn uncertainty into an absence proof.
                if str(error) != "android_adb_lineage_unknown":
                    raise
            time.sleep(min(.05, max(0, end-self.clock())))
