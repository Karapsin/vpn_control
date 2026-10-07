"""Fixed optional tmux driver for Linux fixture packaging (transport only).

Public input is the coordinator's exact four-field build request or correlation.
The coordinator owns clean-source admission and its sole Arch claim. This driver
never accepts a remote path, shell command, overlay, or transport fallback.
Private journal authority assumes the repository's single authorized operator;
full generation checks detect cooperating-tool drift, not hostile same-UID CAS.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
try:
    import resource
except ImportError:  # Import remains portable; the managed coordinator is POSIX.
    resource = None
import stat
import subprocess
import tarfile
import tempfile
import ctypes
import sys
from uuid import uuid4

from . import linux_package_fixture_build as build
from . import ssh_tmux_session as session
from . import ssh_transport

TOOL_SHA = "0b865df3b9c5221229f4bd3c6f49a63c569a609d6258a269ab92c61b013a41fb"
BUILD_SHA = session.REVIEWED_BUILD_SHA256
REMOTE_ROOT = "/home/kardinal/.vpn-control-linux-package-fixture"
MAX_RESPONSE = 2 * 1024**2


class AdapterError(ValueError):
    pass


def need(value, reason):
    if not value:
        raise AdapterError(reason)


def blob(path, maximum=256 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and
             0 < info.st_size <= maximum, "unsafe_source_record")
        raw = os.read(fd, maximum + 1)
        need(len(raw) == info.st_size and session.generation(info) == session.generation(os.fstat(fd)) ==
             session.generation(path.lstat()), "source_record_changed")
        return raw, {"generation": session.generation(info), "sha256": hashlib.sha256(raw).hexdigest()}
    finally:
        os.close(fd)



def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def rename_complete(source, target):
    """Exclusive atomic promotion; partial attempts remain immutable history."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        function = libc.renameatx_np; flags = 4  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        function = libc.renameat2; flags = 1  # RENAME_NOREPLACE
    else:
        raise AdapterError("exclusive_promotion_unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(-100 if sys.platform.startswith("linux") else -2, os.fsencode(source),
                -100 if sys.platform.startswith("linux") else -2, os.fsencode(target), flags) != 0:
        raise AdapterError("exclusive_promotion_failed")
    sync_directory(target.parent)


def result_record(job):
    directory = job / "result-authority"; session.private_dir(directory)
    raw, pin = session.read(directory / "record.json")
    authority = json.loads(session.read(directory / "seal.json")[0])
    need(authority == {"recordPin": pin}, "result_authority_changed")
    value = json.loads(raw)
    need(session._valid_pin(value), "result_authority_changed")
    return value



def file_pin(path, maximum):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and 0 < info.st_size <= maximum,
             "unsafe_artifact_file")
        digest = hashlib.sha256(); total = 0
        while block := os.read(fd, 1024**2):
            total += len(block); need(total <= maximum, "artifact_oversized"); digest.update(block)
        need(total == info.st_size and session.generation(info) == session.generation(os.fstat(fd)) ==
             session.generation(path.lstat()), "artifact_changed")
        return {"generation": session.generation(info), "sha256": digest.hexdigest()}
    finally: os.close(fd)

def output_record(job, request, result_pin):
    output = job / "output"; session.private_dir(output)
    raw, marker_pin = session.read(output / "tmux-extraction-complete.json")
    marker = json.loads(raw)
    need(type(marker) is dict and set(marker) == {"request", "resultPin", "files"} and
         marker["request"] == request and marker["resultPin"] == result_pin and
         type(marker["files"]) is list and 0 < len(marker["files"]) <= 32, "extraction_authority_changed")
    names = set()
    for record in marker["files"]:
        need(type(record) is dict and set(record) == {"path", "pin"} and type(record["path"]) is str and
             session._valid_pin(record["pin"]), "extraction_authority_changed")
        parts = Path(record["path"]).parts
        need(parts and parts[0] in ("default", "arch", ".rag_index") and ".." not in parts and
             not record["path"].startswith("/") and record["path"] not in names, "extraction_authority_changed")
        names.add(record["path"])
        parent = output
        for part in parts[:-1]: parent = parent / part; session.private_dir(parent)
        need(file_pin(output / record["path"], 1024**3) == record["pin"], "extracted_file_changed")
    need(session.read(output / "tmux-extraction-complete.json")[1] == marker_pin, "extraction_authority_changed")
    return {"request": request, "artifactVerification": "complete", "outputIdentity": session.private_dir(output),
            "extractionMarkerPin": marker_pin}

def purpose(request):
    return session.request({**build._request(request), "purpose": session.PURPOSE,
                            "host": "archlinux", "environment": "owned-linux-package-build"})


# Read-only dependency check has no job, launch fence, claim, or installation.
_AVAILABILITY = """import json,subprocess
try:
 p=subprocess.run(['tmux','-V'],stdin=subprocess.DEVNULL,capture_output=True,timeout=5,check=False)
 available=p.returncode==0 and len(p.stdout)<128 and p.stdout.startswith(b'tmux ')
except (OSError,subprocess.TimeoutExpired):available=False
print(json.dumps({'available':available,'reason':'available' if available else 'tmux_unavailable','nativeActionAllowed':False},separators=(',',':')))
"""

# Deliberately stops before any package build. Only fixed Git and two reviewed
# tool files are staged; the existing bootstrap's immediate --remote-run is gone.
_STAGE = r'''
import base64,hashlib,json,os,pathlib,stat,subprocess,sys
payload=json.loads(sys.stdin.buffer.read(131073))
if set(payload)!={'request','build','tool'}:raise SystemExit(31)
request=payload['request'];corr=request['correlationId']
from uuid import UUID
if str(UUID(corr))!=corr:raise SystemExit(31)
raw_build=base64.b64decode(payload['build'],validate=True);raw_tool=base64.b64decode(payload['tool'],validate=True)
if hashlib.sha256(raw_build).hexdigest()!='BUILD_DIGEST' or hashlib.sha256(raw_tool).hexdigest()!='TOOL_DIGEST':raise SystemExit(32)
root=pathlib.Path('FIXED_ROOT');root.mkdir(mode=0o700,exist_ok=True)
if root.is_symlink() or not stat.S_ISDIR(root.lstat().st_mode) or root.stat().st_uid!=os.getuid() or stat.S_IMODE(root.stat().st_mode)!=0o700:raise SystemExit(33)
job=root/corr;job.mkdir(mode=0o700)
def create(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
create(job/'stage-intent.json',json.dumps(request,sort_keys=True,separators=(',',':')).encode())
source=job/'source'
subprocess.run(['git','clone','--no-checkout','https://github.com/Karapsin/vpn_control.git',str(source)],check=True,stdout=sys.stderr,timeout=60)
subprocess.run(['git','-C',str(source),'checkout','--detach',request['sourceSha']],check=True,stdout=sys.stderr,timeout=20)
head=subprocess.run(['git','-C',str(source),'rev-parse','HEAD'],check=True,capture_output=True,timeout=10).stdout.strip().decode()
if head!=request['sourceSha']:raise SystemExit(34)
# Only overwrite a file in this freshly owned exact-source clone. Parent links
# are refused; the baseline HEAD is separately preserved and never relabelled.
parent=source/'agent_tools'
if parent.is_symlink() or not parent.is_dir():raise SystemExit(35)
helper=parent/'linux_package_fixture_build.py'
if helper.is_symlink():raise SystemExit(35)
fd=os.open(helper,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
with os.fdopen(fd,'wb') as f:f.write(raw_build);f.flush();os.fsync(f.fileno())
create(job/'tmux-tool.py',raw_tool)
sys.path.insert(0,str(source));namespace={'__name__':'reviewed_tmux_tool'}
exec(compile(raw_tool,str(job/'tmux-tool.py'),'exec'),namespace)
proof=namespace['preflight'](job,source,request)
value={'request':request,'proof':proof,'toolPin':namespace['read'](job/'tmux-tool.py',131072)[1]}
pin=namespace['write_once'](job/'stage-ready.json',namespace['canonical'](value))
print(json.dumps({'state':'staged','correlationId':corr,'stagePin':pin},separators=(',',':')))
'''.replace("BUILD_DIGEST", BUILD_SHA).replace("TOOL_DIGEST", TOOL_SHA).replace("FIXED_ROOT", REMOTE_ROOT)

_ACTION = r'''
import hashlib,json,os,pathlib,stat,sys
payload=json.loads(sys.stdin.buffer.read(16385));action=payload['action'];request=payload['request']
if action not in ('prepare','release','status','collect'):raise SystemExit(31)
from uuid import UUID
corr=request['correlationId']
if str(UUID(corr))!=corr:raise SystemExit(31)
job=pathlib.Path('FIXED_ROOT')/corr;source=job/'source';path=job/'tmux-tool.py'
fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 info=os.fstat(fd);raw=os.read(fd,131073)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=len(raw) or len(raw)>131072 or hashlib.sha256(raw).hexdigest()!='TOOL_DIGEST':raise SystemExit(32)
finally:os.close(fd)
sys.path.insert(0,str(source));ns={'__name__':'reviewed_tmux_tool'};exec(compile(raw,str(path),'exec'),ns)
ns['private_dir'](job.parent);ns['private_dir'](job)
ready_raw,ready_pin=ns['read'](job/'stage-ready.json');ready=json.loads(ready_raw)
if ready_pin!=payload['stagePin'] or ready['request']!=request or ns['read'](path,131072)[1]!=ready['toolPin'] or ns['source_pin'](source,request)!=ready['proof']['source'] or ns['private_dir'](job.parent)!=ready['proof']['parent'] or ns['private_dir'](job)!=ready['proof']['job']:raise SystemExit(33)
if action=='prepare':result=ns['start'](job,source,request)
elif action=='release':result=ns['release'](job,source,payload['anchorPin'])
elif action=='status':result=ns['status'](job,source,payload['anchorPin'])
else:result=ns['collect'](job,source,payload['anchorPin'],payload['terminalPin'],payload['offset'],payload['limit'],payload['resultPin'])
if ns['read'](job/'stage-ready.json')[1]!=ready_pin or ns['read'](path,131072)[1]!=ready['toolPin'] or ns['private_dir'](job.parent)!=ready['proof']['parent'] or ns['private_dir'](job)!=ready['proof']['job'] or ns['source_pin'](source,request)!=ready['proof']['source']:raise SystemExit(33)
print(json.dumps(result,sort_keys=True,separators=(',',':')))
'''.replace("FIXED_ROOT", REMOTE_ROOT).replace("TOOL_DIGEST", TOOL_SHA)


def command(program):
    """Flatten only our fixed reviewed programs; no caller-supplied source."""
    need(program in (_AVAILABILITY, _STAGE, _ACTION), "unsupported_program")
    return ["python3", "-I", "-B", "-c", "exec(" + repr(program) + ")"]


class TmuxArchDriver:
    def __init__(self, root, *, source_root=None):
        need(os.name == "posix" and resource is not None, "unsupported_coordinator_platform")
        self.root = Path(root).resolve(strict=True)
        self.source_root = build._source_root(self.root, source_root)

    def _tools(self):
        values = {}
        for name, sha in (("ssh_tmux_session.py", TOOL_SHA), ("linux_package_fixture_build.py", BUILD_SHA)):
            raw, pin = blob(self.root / "agent_tools" / name)
            need(pin["sha256"] == sha, "unreviewed_tool_source")
            values[name] = {"pin": pin, "raw": raw}
        return values

    def _transport(self):
        config = ssh_transport.load_config(self.root)
        need("archlinux" in config.hosts, "host_not_configured")
        config_path = self.root / ".vm-hosts.local.json"
        unused, pin = session.read(config_path, 131072)
        connection = ssh_transport.connection_host(config, "archlinux")
        files = {str(config_path): pin}
        for path in (connection.identity_file, connection.known_hosts_file):
            need(isinstance(path, Path), "outer_file_not_local")
            files[str(path)] = blob(path)[1]
        return config, files

    def _records(self, request):
        directory = build._directory(self.root, False)
        need(directory is not None, "coordinator_journal_missing")
        paths = {"intent": directory / (request["correlationId"] + ".json"),
                 "claim": directory / "archlinux.claim"}
        records = {}
        for key, path in paths.items():
            raw, pin = session.read(path)
            expected = request if key == "intent" else {"correlationId": request["correlationId"], "host": "archlinux"}
            need(json.loads(raw) == expected, "coordinator_owner_changed")
            records[key] = pin
        return {"directory": session.private_dir(directory), "index": session.private_dir(directory.parent),
                "records": records}

    def _job(self, request):
        directory = build._directory(self.root, False)
        need(directory is not None, "coordinator_journal_missing")
        return directory / request["correlationId"]

    def _snapshot(self, request):
        tools = self._tools(); unused, transport = self._transport()
        return {"request": request, "coordinator": self._records(request), "transport": transport,
                "tools": {key: value["pin"] for key, value in tools.items()},
                "adapterSource": blob(Path(__file__).resolve())[1],
                "transportSource": blob(Path(ssh_transport.__file__).resolve())[1]}

    def _guard(self, request, original):
        need(self._snapshot(request) == original, "admission_changed")

    def _saved(self, request):
        job = self._job(request); session.private_dir(job)
        raw, unused = session.read(job / "tmux-adapter-intent.json")
        value = json.loads(raw)
        need(value.get("request") == request, "adapter_intent_changed")
        self._guard(request, value)
        return job, value

    def _query(self, program, payload, *, job=None, guard=None):
        """Bounded private subprocess capsule; no raw output in exceptions."""
        config, original_transport = self._transport()
        argv = ssh_transport.build_ssh_argv(config, "archlinux", 10, command=command(program))
        if guard: guard()
        # Diagnostic capsules are local only, with a fresh identity per query.
        base = job if job is not None else self.root / ".rag_index"
        if job is None and not os.path.lexists(base): base.mkdir(mode=0o700)
        session.private_dir(base)
        capsule = base / ("tmux-query-" + str(uuid4())); capsule.mkdir(mode=0o700)
        stdout = capsule / "stdout"; stderr = capsule / "stderr"
        input_bytes = session.canonical(payload)
        need(len(input_bytes) <= 131072, "payload_oversized")
        def limits(): resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_RESPONSE, MAX_RESPONSE))
        connection = ssh_transport.connection_host(config, "archlinux")
        process = None; timed_out = False
        try:
            with tempfile.TemporaryDirectory(prefix="vpn-tmux-askpass-") as askpass, \
                 stdout.open("xb") as out, stderr.open("xb") as err:
                os.chmod(stdout, 0o600); os.chmod(stderr, 0o600)
                env = None
                if connection.password:
                    unused, env = ssh_transport._askpass_environment(connection.password, Path(askpass))
                need(self._transport()[1] == original_transport, "transport_changed")
                if guard: guard()
                process = subprocess.Popen(argv, cwd=self.root, stdin=subprocess.PIPE, stdout=out, stderr=err,
                                           env=env, preexec_fn=limits)
                try:
                    process.communicate(input=input_bytes, timeout=95)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    process.kill()
                    try: process.wait(timeout=2)
                    except subprocess.TimeoutExpired: pass
                    raise AdapterError("transport_timeout") from None
                finally:
                    out.flush(); os.fsync(out.fileno()); err.flush(); os.fsync(err.fileno())
            need(self._transport()[1] == original_transport, "transport_changed")
            if guard: guard()
            raw, unused = session.read(stdout, MAX_RESPONSE)
            need(process.returncode == 0, "transport_unknown")
            value = json.loads(raw)
            need(type(value) is dict, "invalid_remote_reply")
            return value
        except (OSError, ValueError, subprocess.SubprocessError):
            raise AdapterError("transport_unknown") from None
        finally:
            # Retain original bounded streams/exit before success or loss returns. This capsule cannot admit, release, or retry a job.
            try:
                out_pin = session.read(stdout, MAX_RESPONSE)[1]
                err_pin = session.read(stderr, MAX_RESPONSE)[1]
                session.write_once(capsule / "receipt.json", session.canonical({
                    "schemaVersion": 1, "requestSha256": hashlib.sha256(input_bytes).hexdigest(),
                    "argvSha256": hashlib.sha256(session.canonical(argv)).hexdigest(),
                    "exitCode": None if process is None else process.returncode,
                    "timedOut": timed_out, "stdoutPin": out_pin, "stderrPin": err_pin,
                    "replayAllowed": False}))
            except (OSError, ValueError):
                pass  # Raw private streams survive; no missing capsule promotes authority.

    def availability(self):
        value = self._query(_AVAILABILITY, {})
        need(type(value.get("available")) is bool and value == {"available": value["available"],
             "reason": "available" if value["available"] else "tmux_unavailable", "nativeActionAllowed": False}
             and value.get("nativeActionAllowed") is False, "invalid_preflight_reply")
        return value

    def preflight(self, raw):
        request = build._request(raw)
        admitted = build.preflight(self.root, request, source_root=self.source_root)
        dependency = self.availability()
        return {**admitted, "state": "ready" if dependency["available"] else "blocked",
                "reason": dependency["reason"], "nativeActionAllowed": False}

    def submit(self, raw):
        request = build._request(raw)
        # Reuse mandatory clean exact origin/dev version admission, including the
        # existing same-Git managed worktree constraint; no dirty-source bypass.
        build._source_preflight(self.source_root, request)
        original = self._snapshot(request); job = self._job(request)
        job.mkdir(mode=0o700)  # Any existing/partial attempt is consumed.
        intent_pin = session.write_once(job / "tmux-adapter-intent.json", session.canonical(original))
        job_pin = session.private_dir(job)
        tools = self._tools()
        payload = {"request": purpose(request), "build": base64.b64encode(tools["linux_package_fixture_build.py"]["raw"]).decode(),
                   "tool": base64.b64encode(tools["ssh_tmux_session.py"]["raw"]).decode()}
        def guard():
            self._guard(request, original)
            need(session.private_dir(job) == job_pin and
                 session.read(job / "tmux-adapter-intent.json")[1] == intent_pin, "local_authority_changed")
        stage = self._query(_STAGE, payload, job=job, guard=guard)
        need(set(stage) == {"state", "correlationId", "stagePin"} and stage["state"] == "staged" and
             stage["correlationId"] == request["correlationId"] and session._valid_pin(stage["stagePin"]), "invalid_stage_reply")
        session.write_once(job / "tmux-stage.json", session.canonical(stage))
        value = self._action(request, "prepare")
        need(set(value) == {"state", "correlationId", "anchorPin", "replayAllowed", "artifactVerification"} and
             value["state"] == "prepared" and value["correlationId"] == request["correlationId"] and
             session._valid_pin(value["anchorPin"]) and value["replayAllowed"] is False and
             value["artifactVerification"] == "required", "invalid_prepare_reply")
        # Original authority is retained locally BEFORE release can start a build.
        session.write_once(job / "tmux-anchor.json", session.canonical(value))
        self.release(request)
        return {"state": "submitted", "correlationId": request["correlationId"]}

    def _action(self, request, action, **fields):
        job, original = self._saved(request)
        job_pin = session.private_dir(job)
        intent_pin = session.read(job / "tmux-adapter-intent.json")[1]
        stage_raw, stage_pin = session.read(job / "tmux-stage.json")
        stage = json.loads(stage_raw)
        payload = {"action": action, "request": purpose(request), "stagePin": stage["stagePin"]}
        pins = {"stage": stage_pin}
        if action != "prepare":
            anchor_raw, anchor_pin = session.read(job / "tmux-anchor.json")
            payload["anchorPin"] = json.loads(anchor_raw)["anchorPin"]; pins["anchor"] = anchor_pin
        payload.update(fields)
        def guard():
            self._guard(request, original)
            need(session.private_dir(job) == job_pin and
                 session.read(job / "tmux-adapter-intent.json")[1] == intent_pin, "local_authority_changed")
            need(session.read(job / "tmux-stage.json")[1] == pins["stage"] and
                 ("anchor" not in pins or session.read(job / "tmux-anchor.json")[1] == pins["anchor"]), "external_authority_changed")
        return self._query(_ACTION, payload, job=job, guard=guard)

    def release(self, raw):
        request = build._request(raw); job, unused = self._saved(request)
        # Lost replies never call release again; status remains available.
        session.write_once(job / "tmux-release-intent.json", session.canonical({"request": request}))
        value = self._action(request, "release")
        need(value == {"state": "released", "correlationId": request["correlationId"],
                       "replayAllowed": False, "artifactVerification": "required"} and
             value.get("replayAllowed") is False, "invalid_release_reply")
        return value

    @staticmethod
    def _status_reply(value, request):
        need(type(value) is dict and value.get("correlationId") == request["correlationId"] and
             value.get("replayAllowed") is False and value.get("artifactVerification") == "required", "invalid_status_reply")
        if value.get("state") in ("prepared", "running"):
            need(set(value) == {"state", "correlationId", "replayAllowed", "artifactVerification"}, "invalid_status_reply")
        else:
            need(set(value) == {"state", "correlationId", "exitCode", "terminalPin", "artifactVerification", "replayAllowed"} and
                 value["state"] in ("terminal", "unknown") and session._valid_pin(value["terminalPin"]) and
                 ((value["state"] == "terminal" and type(value["exitCode"]) is int) or
                  (value["state"] == "unknown" and value["exitCode"] is None)), "invalid_status_reply")
        return value

    def status(self, raw):
        request = build._request(raw)
        try:
            job, unused = self._saved(request)
            if os.path.lexists(job / "tmux-output-ready.json"):
                saved = json.loads(session.read(job / "tmux-output-ready.json")[0])
                need(saved == output_record(job, request, result_record(job)), "collection_changed")
                build._verify_built(job / "output", request)
                build._timing_inventory(job / "output/.rag_index/build-timings", request)
                return {"state": "ready", "correlationId": request["correlationId"], "sourceSha": request["sourceSha"]}
            value = self._status_reply(self._action(request, "status"), request)
            if value.get("state") in ("running", "prepared"):
                state = "running" if value["state"] == "running" else "unknown"
                return {"state": state, "correlationId": request["correlationId"], "sourceSha": request["sourceSha"],
                        "reason": "running" if state == "running" else "prepared-not-released"}
            need(value.get("state") in ("terminal", "unknown") and session._valid_pin(value.get("terminalPin")), "invalid_status_reply")
            return {"state": "unknown", "correlationId": request["correlationId"], "sourceSha": request["sourceSha"],
                    "reason": "explicit-collection-required", "remoteTerminal": value}
        except (OSError, ValueError, RuntimeError):
            return {"state": "unknown", "correlationId": request["correlationId"], "sourceSha": request["sourceSha"],
                    "reason": "tmux-status-unavailable"}

    def collect_existing(self, raw):
        """Explicit transfer; resumable reads, never package/release replay."""
        request = build._request(raw); job, original = self._saved(request)
        fence_path = job / "tmux-collection.json"
        if not os.path.lexists(fence_path):
            value = self._status_reply(self._action(request, "status"), request)
            need(value.get("state") == "terminal" and type(value.get("exitCode")) is int and value["exitCode"] == 0 and
                 value.get("correlationId") == request["correlationId"] and value.get("replayAllowed") is False and
                 session._valid_pin(value.get("terminalPin")), "remote_build_not_successful")
            session.write_once(fence_path, session.canonical({"request": request, "terminalPin": value["terminalPin"]}))
        fence_raw, fence_pin = session.read(fence_path); fence = json.loads(fence_raw)
        need(fence.get("request") == request and session._valid_pin(fence.get("terminalPin")), "collection_changed")
        chunks = job / "chunks"
        if not chunks.exists(): chunks.mkdir(mode=0o700)
        session.private_dir(chunks)
        result_record_path = job / "result-authority"
        result_pin = result_record(job) if os.path.lexists(result_record_path) else None
        offset = 0; total = None
        while total is None or offset < total:
            self._guard(request, original)
            need(session.read(fence_path)[1] == fence_pin, "collection_changed")
            path = chunks / f"{offset:012d}.bin"
            value = self._action(request, "collect", terminalPin=fence["terminalPin"], offset=offset,
                                 limit=1024**2, resultPin=result_pin)
            need(set(value) == {"offset", "totalBytes", "chunkBase64", "resultSha256", "resultPin", "artifactVerification", "replayAllowed"} and
                 type(value["offset"]) is int and value["offset"] == offset and type(value["totalBytes"]) is int and
                 0 < value["totalBytes"] <= session.MAX_RESULT and session._valid_pin(value["resultPin"]) and
                 value["totalBytes"] == value["resultPin"]["generation"][5] and
                 type(value["chunkBase64"]) is str and len(value["chunkBase64"]) <= 1398104 and
                 value["resultSha256"] == value["resultPin"]["sha256"] and value["artifactVerification"] == "required" and
                 value["replayAllowed"] is False, "invalid_chunk_reply")
            if result_pin is None:
                authority_attempt = job / ("result-authority-attempt-" + str(uuid4())); authority_attempt.mkdir(mode=0o700)
                record_pin = session.write_once(authority_attempt / "record.json", session.canonical(value["resultPin"]))
                session.write_once(authority_attempt / "seal.json", session.canonical({"recordPin": record_pin}))
                sync_directory(authority_attempt)
                self._guard(request, original)
                need(session.read(fence_path)[1] == fence_pin, "collection_changed")
                rename_complete(authority_attempt, result_record_path)
                result_pin = value["resultPin"]
            need(result_record(job) == result_pin and value["resultPin"] == result_pin and
                 (total is None or total == value["totalBytes"]), "result_changed")
            total = value["totalBytes"]
            chunk = base64.b64decode(value["chunkBase64"], validate=True)
            need(len(chunk) == min(1024**2, total - offset), "invalid_chunk_reply")
            if path.exists(): need(session.read(path, 1024**2)[0] == chunk, "local_chunk_changed")
            else:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream: stream.write(chunk); stream.flush(); os.fsync(stream.fileno())
                sync_directory(chunks)
                need(session.read(path, 1024**2)[0] == chunk, "local_chunk_changed")
            offset += len(chunk)
        expected_names = [f"{position:012d}.bin" for position in range(0, total, 1024**2)]
        actual_names = set()
        for entry in chunks.iterdir():
            need(len(actual_names) < len(expected_names), "foreign_chunk")
            actual_names.add(entry.name)
        need(actual_names == set(expected_names), "foreign_chunk")
        archive = job / "result.tar"
        if not archive.exists():
            temporary_archive = job / ("archive-attempt-" + str(uuid4()) + ".tar")
            fd = os.open(temporary_archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as sink:
                for name in expected_names: sink.write(session.read(chunks / name, 1024**2)[0])
                sink.flush(); os.fsync(sink.fileno())
            self._guard(request, original)
            need(build._digest(temporary_archive, session.MAX_RESULT) == (total, result_pin["sha256"]), "local_archive_changed")
            rename_complete(temporary_archive, archive)
        size, digest = build._digest(archive, session.MAX_RESULT)
        need(size == total and digest == result_pin["sha256"], "local_archive_changed")
        self._guard(request, original)
        need(session.read(fence_path)[1] == fence_pin, "collection_changed")
        output = job / "output"
        if not output.exists():
            extraction = job / ("output-attempt-" + str(uuid4())); extraction.mkdir(mode=0o700)
            files = []
            fd = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            archive_before = os.fstat(fd)
            with os.fdopen(fd, "rb") as archive_stream, tarfile.open(fileobj=archive_stream, mode="r:") as stream:
                names = set(); count = 0
                for member in stream:
                    parts = Path(member.name).parts
                    need(member.isfile() and parts and parts[0] in ("default", "arch", ".rag_index") and
                         ".." not in parts and not member.name.startswith("/") and member.name not in names and
                         len(names) < 32 and 0 < member.size <= 1024**3, "unsafe_archive")
                    names.add(member.name); count += member.size; need(count <= 3 * 1024**3, "unsafe_archive")
                    target = extraction / member.name
                    parent = extraction
                    for part in parts[:-1]:
                        parent = parent / part
                        if not os.path.lexists(parent): parent.mkdir(mode=0o700)
                        session.private_dir(parent)
                    source = stream.extractfile(member); need(source is not None, "unsafe_archive")
                    out_fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(out_fd, "wb") as sink:
                        while block := source.read(1024**2): sink.write(block)
                        sink.flush(); os.fsync(sink.fileno())
                    sync_directory(target.parent)
                    files.append({"path": member.name, "pin": file_pin(target, 1024**3)})
                need(session.generation(archive_before) == session.generation(os.fstat(archive_stream.fileno())) ==
                     session.generation(archive.lstat()), "local_archive_changed")
            build._verify_built(extraction, request)
            build._timing_inventory(extraction / ".rag_index/build-timings", request)
            session.write_once(extraction / "tmux-extraction-complete.json",
                               session.canonical({"request": request, "resultPin": result_pin, "files": files}))
            for directory in sorted({extraction / Path(item["path"]).parent for item in files}, key=lambda path: -len(path.parts)):
                while directory != extraction:
                    sync_directory(directory); directory = directory.parent
            sync_directory(extraction)
            self._guard(request, original)
            need(session.read(fence_path)[1] == fence_pin and result_record(job) == result_pin, "collection_changed")
            rename_complete(extraction, output)
        output_proof = output_record(job, request, result_pin)
        build._verify_built(output, request)
        build._timing_inventory(output / ".rag_index/build-timings", request)
        self._guard(request, original)
        need(session.read(fence_path)[1] == fence_pin, "collection_changed")
        if not (job / "tmux-output-ready.json").exists():
            session.write_once(job / "tmux-output-ready.json", session.canonical(output_proof))
        else:
            need(json.loads(session.read(job / "tmux-output-ready.json")[0]) == output_proof, "collection_changed")
        return build.FixedArchDriver(self.root).collect(request, {"state": "ready"})

    def collect(self, request, observed):
        # Coordinator calls this ONLY after verified local readiness. Native
        # transfer is explicit through collect_existing, never hidden in status.
        need(observed.get("state") == "ready", "collection_not_ready")
        return build.FixedArchDriver(self.root).collect(request, observed)


def operate(root, action, raw, *, source_root=None):
    """Fixed public adapter surface for root-owned MCP/CLI integration.

    availability takes {}; preflight/start take the coordinator's four fields;
    status/release/collect take only its canonical correlationId. source_root is
    trusted managed-worktree wiring, never a request field. No script CLI here.
    """
    need(type(action) is str and action in {"availability", "preflight", "start", "status", "release", "collect"},
         "unsupported_action")
    driver = TmuxArchDriver(root, source_root=source_root)
    if action == "availability":
        need(type(raw) is dict and not raw, "invalid_availability_request")
        return driver.availability()
    if action == "preflight": return driver.preflight(raw)
    if action == "start":
        return build.start(root, raw, driver=driver, source_root=source_root,
                           admission=lambda unused, request: driver.preflight(request))
    need(type(raw) is dict and set(raw) == {"correlationId"} and build._correlation(raw["correlationId"]),
         "invalid_correlation_request")
    if action == "status": return build.status(root, raw, driver=driver)
    directory = build._directory(Path(root).resolve(strict=True), False)
    need(directory is not None, "coordinator_journal_missing")
    record = build._read(directory / (raw["correlationId"] + ".json"))
    need(record is not None, "coordinator_intent_missing")
    request = build._request(record)
    driver._saved(request)  # Exact original claim/source/transport must still hold.
    return driver.release(request) if action == "release" else driver.collect_existing(request)
