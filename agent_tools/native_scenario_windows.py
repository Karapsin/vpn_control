"""Closed Windows scenario table and the one driver behind ScenarioExecutor.

A scenario is one detached durable job on the VM host (windows_scenario_host_job),
carried by ssh_program_execution_remote over the existing SSH owner. The VM is named
by ``host`` and ``environment``. No request supplies a path, argv, source or bytes:
every byte comes from this checkout and a differing bundle refuses before any journal.
``discover``, ``observe`` and ``collect`` only read; a lost submit reply is resolved
by correlation and the job is never submitted twice.
"""
from __future__ import annotations

import ast
import base64
from contextlib import contextmanager
import gzip
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
import uuid
from typing import Any, Callable, Mapping

try:
    from . import durable_remote_job, native_scenario_bundle, native_scenario_execution
    from . import ssh_program_execution_remote as carrier
    from . import ssh_transport
    from . import windows_scenario_host_job as host_job
except ImportError:  # pragma: no cover - MCP CLI fallback executes mcp_server.py as a script.
    import durable_remote_job  # type: ignore[no-redef]
    import native_scenario_bundle  # type: ignore[no-redef]
    import native_scenario_execution  # type: ignore[no-redef]
    import ssh_program_execution_remote as carrier  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]
    import windows_scenario_host_job as host_job  # type: ignore[no-redef]


BUNDLE_SCENARIO_ID = "windows-scenario-driver"
_HOST_JOB_PATH = "agent_tools/windows_scenario_host_job.py"
_DATA_PARENT = ".cache/vpn-control-windows-scenarios"
_LOCAL_STATE = (".rag_index", "native-scenario-windows")
_EVIDENCE_PARENT = (".runtime", "windows-scenarios")
_MAX_REPLY = 2 * 1024 * 1024  # Above native_scenario_ssh's 8,192: terminal replies carry base64 streams.
_EVIDENCE_CHUNK = 1024 * 1024
# One admission covers the whole pull and every chunk is a new SSH connection, so this is what
# 60 s can carry. A row with more evidence needs a deadline scaled to its bytes and a pull that resumes.
_MAX_EVIDENCE = 8 * 1024 * 1024
_SUBMIT_SECONDS = 180
_OBSERVE_SECONDS = 60
_EVIDENCE_NAME = re.compile(r"evidence-[0-9]{1,6}\.zip\Z")
_BIRTH = re.compile(r"(?:linux:([1-9][0-9]*)|darwin:([0-9]+):([0-9]+))\Z")

# One row per closed name. A later name is a row here plus its stages in the host job.
RECIPES: dict[str, dict[str, Any]] = {
    "windows-ordinary-qualification": {
        "evidenceClass": "component",
        "bootstrapMode": "qualification",
        "workerAction": None,
        "artifactKeys": ("bundleManifest",),
        "guestFiles": (("agent_tools/windows_ordinary_task_owner.ps1", "owner", "powershell"),
                       ("agent_tools/windows_scenario_qualification_child.ps1", "child", "powershell")),
        "readPins": (host_job.POWERSHELL_PATH,),
        "subfolders": (),
        "qualificationArguments": ("-Value", "scenario-ok"),
        "expectedExit": 7,
        "expectedStreams": {"stdout": "stdout|scenario-ok", "stderr": "stderr|scenario-ok"},
        "rawStreamLimitBytes": 1024 * 1024,
        "deadlineSeconds": 300,
        "stages": host_job.STAGE_ORDER,
    },
}
SETUP_OR_COMPONENT = frozenset({"setup", "component"})


class NativeScenarioWindowsError(ValueError):
    """A finite refusal; no private path or stream crosses it."""


def _need(condition: Any, reason: str) -> None:
    if not condition:
        raise NativeScenarioWindowsError(reason)


def _canonical_uuid(value: Any, reason: str) -> str:
    try:
        _need(type(value) is str and str(uuid.UUID(value)) == value, reason)
    except (ValueError, AttributeError, TypeError):
        raise NativeScenarioWindowsError(reason) from None
    return value


def _row(scenario_id: Any) -> dict[str, Any]:
    row = RECIPES.get(scenario_id) if isinstance(scenario_id, str) else None
    _need(row is not None, "windows_scenario_not_allowlisted")
    return row


def _binding(root: Path | str, plan: native_scenario_execution.ScenarioPlan) -> dict[str, Any]:
    """The original start intent names the VM; nothing here is caller supplied."""
    from . import readiness_windows_registration as registration
    from . import readiness_windows_remote as packets
    try:
        binding, _, _ = registration.original_binding(root, plan.environment)
        provider, spec, _, _ = packets.validate_binding(binding)
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise NativeScenarioWindowsError("windows_scenario_environment_unavailable") from error
    _need(provider == "raw-qemu-windows" and spec.deployment_id == plan.environment and spec.host == plan.host,
          "windows_scenario_environment_mismatch")
    return binding


def verified_bundle(root: Path | str, plan: native_scenario_execution.ScenarioPlan,
                    bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str]) -> tuple[Path, dict[str, Any]]:
    """The frozen inventory, byte for byte this checkout: no caller supplies case bytes."""
    try:
        bundle = Path(bundle_resolver(plan)).resolve(strict=True)
        verified = native_scenario_bundle.verify_bundle(root, bundle, plan.bundle_hash)
    except (OSError, ValueError) as error:
        raise NativeScenarioWindowsError("windows_scenario_bundle_unavailable") from error
    _need(verified.get("scenarioId") == BUNDLE_SCENARIO_ID, "windows_scenario_bundle_foreign")
    for entry in verified["files"]:
        source = Path(root) / entry["path"]
        try:
            matches = source.is_file() and not source.is_symlink() and native_scenario_bundle._hash(source) == entry["sha256"]
        except OSError:
            matches = False
        _need(matches, "windows_scenario_bundle_differs_from_checkout")
    return bundle, verified


def admit_start(root: Path | str, request: Mapping[str, Any],
                bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str]) -> dict[str, Any]:
    """Pure gates before any journal: no connection, no guest and no intent exists yet.

    A later row that takes a package artifact adds its platform, kind, source and
    frozen-set checks here; today the exact key set refuses every package ID.
    """
    if not isinstance(request, Mapping):
        raise NativeScenarioWindowsError("windows_scenario_request_invalid")
    row = _row(request.get("scenarioId"))
    plan = native_scenario_execution.ScenarioPlan.from_mapping(request)
    _canonical_uuid(plan.correlation_id, "windows_scenario_correlation_invalid")
    _canonical_uuid(plan.environment, "windows_scenario_environment_invalid")
    _need(set(plan.artifact_ids) == set(row["artifactKeys"]), "windows_scenario_artifacts_invalid")
    _need(plan.artifact_ids["bundleManifest"] == "sha256-" + plan.bundle_hash, "windows_scenario_bundle_artifact_invalid")
    _binding(root, plan)
    verified_bundle(root, plan, bundle_resolver)
    return row


def public_evidence(result: Mapping[str, Any]) -> dict[str, Any]:
    """A setup or component row never claims installed-package, whatever its receipt says."""
    row = _row(result.get("scenarioId"))
    if row["evidenceClass"] in SETUP_OR_COMPONENT:
        return {"evidenceClass": row["evidenceClass"], "productAction": False}
    windows = (result.get("scenarioEvidence") or {}).get("windows") if isinstance(result.get("scenarioEvidence"), Mapping) else None
    proven = (result.get("state") == "terminal" and result.get("collectionState") == "complete" and isinstance(windows, Mapping)
              and windows.get("installedPackage") is True and isinstance(windows.get("packageSha256"), str)
              and windows["packageSha256"] == row.get("packageSha256"))
    return {"evidenceClass": "installed-package" if proven else "installed-package-unproven", "productAction": True}


def _instance_definitions() -> str:
    """The same canonical definitions readiness packets embed, so the guards cannot drift."""
    from . import windows_vm_instance as instance
    source = inspect.getsource(instance._vm_main)
    node = next(item for item in ast.parse(source).body if isinstance(item, ast.FunctionDef))
    nodes = [item for item in node.body if isinstance(item, (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef))
             and not (isinstance(item, ast.FunctionDef) and item.name == "launch")]
    return "\n".join(ast.get_source_segment(source, item) for item in nodes)


def render_program(plan: native_scenario_execution.ScenarioPlan, binding: Mapping[str, Any], bundle: Path,
                   verified: Mapping[str, Any], target: Mapping[str, Any], *, stop_after: str | None = None) -> tuple[str, str]:
    """One fixed job source: host module, canonical guards, closed plan and the frozen files."""
    from . import windows_vm_deploy_remote as deployment
    row = _row(plan.scenario_id)
    data = str(PurePosixPath(target["home"]) / _DATA_PARENT / plan.environment / plan.correlation_id)
    entries = {entry["path"]: {"sha256": entry["sha256"], "sizeBytes": entry["sizeBytes"]} for entry in verified["files"]}
    raw_files = {path: (bundle / path).read_bytes() for path in entries}
    _need(all(hashlib.sha256(raw_files[path]).hexdigest() == entry["sha256"] for path, entry in entries.items()),
          "windows_scenario_bundle_changed")
    job_plan = {"schemaVersion": 1, "operationId": plan.correlation_id, "scenarioId": plan.scenario_id, "machine": plan.environment,
                "bundleHash": plan.bundle_hash, "user": binding["setup"]["user"], "dataDirectory": data,
                "row": row, "files": entries, "stopAfter": stop_after}
    payload = gzip.compress(json.dumps({path: base64.b64encode(raw).decode("ascii") for path, raw in raw_files.items()},
                                       sort_keys=True).encode("ascii"), mtime=0)
    text = raw_files[_HOST_JOB_PATH].decode("utf-8")
    marker = "    _CANONICAL_INSTANCE_DEFINITIONS()\n"
    _need(text.count(marker) == 1, "windows_scenario_host_source")
    text = text.replace(marker, "".join("    " + line + "\n" for line in _instance_definitions().splitlines()))
    bindings = {"SPEC": binding["spec"], "SETUP": binding["setup"], "CONTEXT": binding["context"], "PLAN": _plain(job_plan),
                "FILES_GZ": base64.b64encode(payload).decode("ascii")}
    source = (text + "\n" + "\n".join(key + "=" + repr(value) for key, value in bindings.items()) + "\n"
              + deployment.guest_rpc_definitions() + "\nwire=partial_wire=-1\nQGA_PEER_PID=QGA_GUARD=None\n"
              + "raise SystemExit(_host_main())\n")
    compile(source, "windows scenario job", "exec")
    return source, data


def _plain(value: Any) -> Any:
    return json.loads(json.dumps(value))


def _py(program: str, *arguments: str) -> tuple[str, ...]:
    return ("python3", "-I", "-B", "-c", "exec(" + repr(program) + ")", *arguments)


# Fixed read-only programs for the host. They take token arguments and no source.
_TARGET = r'''import json,os,pwd,subprocess,sys
e=pwd.getpwuid(os.geteuid())
if sys.platform.startswith('linux'):
 b=open('/proc/sys/kernel/random/boot_id').read(128).strip()
else:b=subprocess.run(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=3,check=True).stdout.decode('ascii').strip().lower()
print(json.dumps({'kind':'ssh','uid':os.geteuid(),'principal':e.pw_name,'home':e.pw_dir,'bootId':b},sort_keys=True))'''

_COLLECT = r'''import base64,json,os,stat,sys
job=sys.argv[1]
def read(name,limit):
 fd=os.open(os.path.join(job,name),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>limit: raise ValueError()
  raw=os.read(fd,limit+1)
  if len(raw)!=info.st_size: raise ValueError()
  return raw
 finally: os.close(fd)
try:
 print(json.dumps({"state":"collected","receipt":base64.b64encode(read("scenario-receipt.json",8192)).decode(),"jobExit":json.loads(read("job-exit.json",1024))},separators=(",",":")))
except Exception: print(json.dumps({"state":"unknown"},separators=(",",":")))'''

_PULL = r'''import base64,json,os,stat,sys
job,name,offset,length=sys.argv[1:]
fd=os.open(os.path.join(job,name),os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600: raise ValueError()
 print(json.dumps({"size":info.st_size,"data":base64.b64encode(os.pread(fd,int(length),int(offset))).decode()},separators=(",",":")))
finally: os.close(fd)'''


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(path)
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077,
          "windows_scenario_private_state_unsafe")
    return path


def _create_private(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _read_private(path: Path) -> Any:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o077,
              "windows_scenario_private_state_unsafe")
        return json.loads(stream.read())


def _start_ticks(birth: Any) -> int | None:
    match = _BIRTH.fullmatch(birth) if isinstance(birth, str) else None
    if match is None:
        return None
    return int(match[1]) if match[1] else int(match[2]) * 1_000_000 + int(match[3]) + 1


def _exit_marker(stdout: bytes, operation: str) -> dict[str, Any] | None:
    """Job exit 1 is also what an uncaught Python error exits with; only the job's own line counts."""
    lines = stdout.decode("utf-8", "replace").strip().splitlines()
    try:
        value = json.loads(lines[-1]) if lines else None
    except ValueError:
        return None
    if (isinstance(value, dict) and value.get("operationId") == operation and type(value.get("scenarioExit")) is int
            and (value.get("failure") is None or isinstance(value.get("failure"), str))):
        return value
    return None


class NativeScenarioWindowsDriver:
    """Private adapter. ``stop_after`` is constructor wiring for the direct script, never request data."""

    def __init__(self, repository_root: Path | str, bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str],
                 timeout_seconds: int = 30, ssh_binary: str = "ssh", configuration_root: Path | str | None = None,
                 *, stop_after: str | None = None):
        _need(stop_after is None or stop_after in host_job.STOP_AFTER, "windows_scenario_stop_after_invalid")
        self.root = Path(repository_root).resolve()
        self.configuration_root = Path(configuration_root).resolve() if configuration_root is not None else self.root
        self.bundle_resolver = bundle_resolver
        self.timeout_seconds = timeout_seconds
        self.ssh_binary = ssh_binary
        self.stop_after = stop_after

    def _local(self, plan: native_scenario_execution.ScenarioPlan) -> Path:
        return self.configuration_root.joinpath(*_LOCAL_STATE, plan.correlation_id)

    @contextmanager
    def _admitted(self, config: Any, plan: native_scenario_execution.ScenarioPlan, seconds: int):
        """Send pattern of readiness_windows: an explicit transport admission around the SSH child."""
        if ssh_transport._dispatch_binding(config, plan.host) is not None:
            yield  # The public dispatch boundary already admitted this host.
            return
        with ssh_transport.admitted_transport(self.configuration_root, plan.host, plan.correlation_id, deadline=time.monotonic() + seconds):
            yield

    def _send(self, config: Any, host: str, command: tuple[str, ...], *, seconds: int, keep: Path | None = None) -> dict[str, Any] | None:
        argv = ssh_transport.build_ssh_argv(config, host, self.timeout_seconds, command=command, ssh_binary=self.ssh_binary)
        connection = ssh_transport.connection_host(config, host)

        def run(environment=None):
            return ssh_transport.run_ssh(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         timeout=seconds, env=environment, check=False)
        try:
            if connection.password is not None:
                with tempfile.TemporaryDirectory(prefix="vpn-control-askpass-") as directory:
                    _, environment = ssh_transport._askpass_environment(connection.password, Path(directory))
                    done = run(environment)
            else:
                done = run()
        except (OSError, subprocess.TimeoutExpired):
            return None
        if keep is not None:  # A first contact's only record of what the host said.
            _create_private(keep.with_name(keep.name + ".stdout.private"), done.stdout)
            _create_private(keep.with_name(keep.name + ".stderr.private"), done.stderr)
            _create_private(keep.with_name(keep.name + ".returncode"), str(done.returncode).encode())
        if done.returncode != 0 or len(done.stdout) > _MAX_REPLY:
            return None
        try:
            value = json.loads(done.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    def _retained(self, plan: native_scenario_execution.ScenarioPlan) -> dict[str, Any] | None:
        directory = self._local(plan)
        try:
            return {"program": _read_private(directory / "program.json"), "packet": _read_private(directory / "admission.json")}
        except FileNotFoundError:
            return None

    def _identity(self, plan: native_scenario_execution.ScenarioPlan, program: Mapping[str, Any], owner: Any) -> native_scenario_execution.JobIdentity:
        receipt = str(PurePosixPath(program["dataDirectory"]) / "scenario-receipt.json")
        ticks = _start_ticks(owner.get("birth")) if isinstance(owner, Mapping) else None
        pid = owner.get("pid") if isinstance(owner, Mapping) and ticks is not None else None
        return native_scenario_execution.JobIdentity("windows-" + plan.correlation_id, pid if type(pid) is int else None,
                                                     ticks if type(pid) is int else None, receipt)

    def submit(self, plan: native_scenario_execution.ScenarioPlan) -> native_scenario_execution.JobIdentity:
        admit_start(self.root, plan.as_dict(), self.bundle_resolver)
        bundle, verified = verified_bundle(self.root, plan, self.bundle_resolver)
        binding = _binding(self.root, plan)
        directory = self._local(plan)
        _private_directory(directory.parent)
        try:
            os.mkdir(directory, 0o700)  # Create-only: a second submit of this correlation stops here.
        except FileExistsError:
            raise NativeScenarioWindowsError("windows_scenario_job_already_exists") from None
        config = ssh_transport.load_config(self.configuration_root)
        with self._admitted(config, plan, _SUBMIT_SECONDS):
            target = self._send(config, plan.host, _py(_TARGET), seconds=self.timeout_seconds, keep=directory / "target")
            _need(target is not None, "windows_scenario_target_unavailable")
            source, data = render_program(plan, binding, bundle, verified, target, stop_after=self.stop_after)
            program = {"language": "python3", "source": source, "args": [], "cwd": target["home"], "targetContext": target}
            _create_private(directory / "program.json", json.dumps({"program": program, "dataDirectory": data}, sort_keys=True).encode())
            packet = self._send(config, plan.host, carrier.prepare_command(plan.correlation_id, program, durable_remote_job.owner_source()),
                                seconds=_SUBMIT_SECONDS, keep=directory / "prepare")
            _need(packet is not None, "windows_scenario_preparation_unavailable")
            carrier.durable_command(plan.correlation_id, program, packet, mode="observe")  # Validate with an inert render.
            _create_private(directory / "admission.json", json.dumps(packet, sort_keys=True).encode())
            reply = self._send(config, plan.host, carrier.durable_command(plan.correlation_id, program, packet, mode="submit", wait_seconds=2),
                               seconds=_SUBMIT_SECONDS, keep=directory / "submit")
        _need(reply is not None, "windows_scenario_submit_unavailable")
        status = reply.get("status")
        _need(isinstance(status, Mapping) and status.get("operationId") == plan.correlation_id, "windows_scenario_submit_unavailable")
        return self._identity(plan, {"dataDirectory": data}, status.get("owner"))

    def _status(self, plan: native_scenario_execution.ScenarioPlan) -> tuple[dict[str, Any], dict[str, Any]] | None:
        retained = self._retained(plan)
        if retained is None:
            return None
        program = retained["program"]["program"]
        try:
            config = ssh_transport.load_config(self.configuration_root)
            with self._admitted(config, plan, _OBSERVE_SECONDS):
                reply = self._send(config, plan.host, carrier.durable_command(plan.correlation_id, program, retained["packet"], mode="observe", wait_seconds=0),
                                   seconds=_OBSERVE_SECONDS)
        except (OSError, ValueError, ssh_transport.SshConfigError):
            return None
        if (reply is None or reply.get("schemaVersion") != 1 or reply.get("operationId") != plan.correlation_id
                or not isinstance(reply.get("status"), Mapping) or reply["status"].get("operationId") != plan.correlation_id):
            return None
        return reply, retained["program"]

    def discover(self, plan: native_scenario_execution.ScenarioPlan) -> native_scenario_execution.JobIdentity | None:
        found = self._status(plan)
        if found is None:
            return None
        reply, program = found
        identity = self._identity(plan, program, reply["status"].get("owner"))
        return identity if identity.pid is not None else None

    def observe(self, plan: native_scenario_execution.ScenarioPlan, identity: native_scenario_execution.JobIdentity) -> native_scenario_execution.DriverObservation:
        unknown = native_scenario_execution.ObservationStatus.UNKNOWN
        found = self._status(plan)
        if found is None:
            return native_scenario_execution.DriverObservation(unknown, "observer_unavailable")
        reply, program = found
        status = reply["status"]
        observed = self._identity(plan, program, status.get("owner"))
        observed = observed if observed.pid is not None else None
        paths = (observed.receipt_path,) if observed is not None else ()
        state = status.get("state")
        if state == "running":
            return native_scenario_execution.DriverObservation(native_scenario_execution.ObservationStatus.RUNNING,
                                                               "original_owner_running", observed, evidence_paths=paths)
        if state != "terminal":
            return native_scenario_execution.DriverObservation(unknown, str(status.get("reason", "remote_unknown")), observed, evidence_paths=paths)
        terminal = status.get("terminal")
        code = terminal.get("exitCode") if isinstance(terminal, Mapping) else None
        try:
            marker = _exit_marker(base64.b64decode(reply.get("stdout", ""), validate=True), plan.correlation_id)
        except (ValueError, TypeError):
            marker = None
        if (type(code) is not int or code not in host_job.KNOWN_EXITS or marker is None or marker["scenarioExit"] != code
                or observed is None):
            failure = host_job.token(marker.get("failure")) if marker and marker.get("failure") else "unverified"
            return native_scenario_execution.DriverObservation(unknown, "job_exit_unknown:" + failure, observed, evidence_paths=paths)
        receipt = {**plan.as_dict(), "jobId": observed.job_id, "pid": observed.pid, "startTicks": observed.start_ticks, "exitCode": code}
        # A job refused before it started leaves no receipt: its own line is the only cause there is.
        excerpt = host_job.token(marker["failure"]) if marker.get("failure") else None
        return native_scenario_execution.DriverObservation(native_scenario_execution.ObservationStatus.TERMINAL, "remote_receipt",
                                                           observed, receipt, paths, excerpt)

    def collect(self, plan: native_scenario_execution.ScenarioPlan, identity: native_scenario_execution.JobIdentity) -> Mapping[str, Any] | None:
        retained = self._retained(plan)
        if retained is None or identity.pid is None:
            return None
        data = retained["program"]["dataDirectory"]
        try:
            config = ssh_transport.load_config(self.configuration_root)
            with self._admitted(config, plan, _OBSERVE_SECONDS):
                reply = self._send(config, plan.host, _py(_COLLECT, data), seconds=_OBSERVE_SECONDS)
                if reply is None or reply.get("state") != "collected":
                    return None
                raw = base64.b64decode(reply["receipt"], validate=True)
                summary = self._summary(plan, raw, reply.get("jobExit"))
                if summary is not None:
                    self._pull_evidence(config, plan, data, json.loads(raw).get("evidence"))
        except (OSError, ValueError, KeyError, TypeError, ssh_transport.SshConfigError):
            return None
        return summary

    def _summary(self, plan: native_scenario_execution.ScenarioPlan, raw: bytes, job_exit: Any) -> dict[str, Any] | None:
        receipt = json.loads(raw)
        if (not isinstance(receipt, dict) or not isinstance(job_exit, Mapping) or job_exit.get("operationId") != plan.correlation_id
                or type(job_exit.get("exitCode")) is not int or receipt.get("exitCode") != job_exit["exitCode"]):
            return None
        task = receipt.get("task") if isinstance(receipt.get("task"), Mapping) else {}
        windows = receipt.get("windows") if isinstance(receipt.get("windows"), Mapping) else {}
        return {"state": "collected", "scenarioId": plan.scenario_id, "correlationId": plan.correlation_id,
                "result": receipt.get("result"), "exitCode": job_exit["exitCode"],
                "windows": {"evidenceClass": _row(plan.scenario_id)["evidenceClass"], "installedPackage": windows.get("installedPackage") is True,
                            "packageSha256": windows.get("packageSha256"), "taskDeleted": task.get("taskDeleted"),
                            "taskExitCode": task.get("ownerExitCode"), "taskEvents": task.get("events"),
                            "parked": task.get("parked"), "stoppedAfter": receipt.get("stoppedAfter"),
                            "failure": receipt.get("failure")},
                "actualReceiptRaw": raw.decode("utf-8"), "actualReceiptSha256": hashlib.sha256(raw).hexdigest()}

    def _pull_evidence(self, config: Any, plan: native_scenario_execution.ScenarioPlan, data: str, evidence: Any) -> None:
        """Raw evidence stays on the host until here; a collection is complete only with its bytes."""
        if evidence is None:
            return
        _need(isinstance(evidence, Mapping) and isinstance(evidence.get("name"), str) and _EVIDENCE_NAME.fullmatch(evidence["name"])
              and type(evidence.get("bytes")) is int and 0 <= evidence["bytes"] <= _MAX_EVIDENCE and isinstance(evidence.get("sha256"), str),
              "windows_scenario_evidence_invalid")
        directory = _private_directory(self.configuration_root.joinpath(*_EVIDENCE_PARENT, plan.correlation_id))
        target = directory / evidence["name"]
        if target.exists():
            _need(native_scenario_bundle._hash(target) == evidence["sha256"], "windows_scenario_evidence_changed")
            return
        digest = hashlib.sha256()
        parts = []
        offset = 0
        while offset < evidence["bytes"]:
            reply = self._send(config, plan.host, _py(_PULL, data, evidence["name"], str(offset), str(_EVIDENCE_CHUNK)), seconds=_OBSERVE_SECONDS)
            _need(reply is not None and reply.get("size") == evidence["bytes"], "windows_scenario_evidence_unavailable")
            part = base64.b64decode(reply["data"], validate=True)
            _need(0 < len(part) <= _EVIDENCE_CHUNK, "windows_scenario_evidence_unavailable")
            digest.update(part)
            parts.append(part)
            offset += len(part)
        _need(offset == evidence["bytes"] and digest.hexdigest() == evidence["sha256"], "windows_scenario_evidence_changed")
        _create_private(target, b"".join(parts))
