"""Fixed SSH adapter for the non-mutating Linux bundle import preflight.

It only stages the allowlisted ``linux-public-update-driver`` bundle and imports
its fixed entrypoint in an isolated interpreter.  It does not install, update,
start a VPN, or claim an installation result.  Product-changing public-update
execution needs a separate owned-guest/PTy adapter.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
from typing import Any, Callable, Mapping

try:
    from . import native_scenario_bundle, native_scenario_execution, ssh_transport
except ImportError:  # pragma: no cover
    import native_scenario_bundle, native_scenario_execution, ssh_transport


SCENARIO_ID = "linux-public-update-preflight"
BUNDLE_SCENARIO_ID = "linux-public-update-driver"
_MAX_OUTPUT = 8192


class NativeScenarioSshError(ValueError):
    pass


def _py(program: str, *arguments: str) -> tuple[str, ...]:
    return ("python3", "-c", "exec(" + repr(program) + ")", *arguments)


# The receiver has a fixed inventory, creates one private remote job directory,
# verifies every streamed byte and only then starts its fixed import preflight.
_SUBMIT = r'''import hashlib,json,os,stat,subprocess,sys,time
root,host,env,scenario,corr,bundle_hash,artifact_json=sys.argv[1:]
os.umask(0o077)
names=("scripts/test_linux_public_install.py","scripts/arch_public_update.py","scripts/rpm_public_update.py","scripts/prepare_desktop_update_fixture.py","scripts/fixture_environment.py","scripts/macos_packaging_jdk_preflight.py","scripts/native_fixture_run.sh","native-scenario-manifest.json")
def bad(reason): print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(64)
if scenario!="linux-public-update-preflight": bad("scenario_not_allowed")
try: artifacts=json.loads(artifact_json)
except Exception: bad("invalid_artifacts")
if not isinstance(artifacts,dict): bad("invalid_artifacts")
try:
 h=json.loads(sys.stdin.buffer.readline(16385).decode())
 if set(h)!={"files"} or not isinstance(h["files"],list): bad("invalid_header")
 files=h["files"]
 if [x.get("path") if isinstance(x,dict) else None for x in files] != list(names): bad("unexpected_inventory")
except Exception: bad("invalid_header")
def private(path):
 st=os.stat(path,follow_symlinks=False)
 return stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and stat.S_IMODE(st.st_mode)==0o700
if not root.startswith("/") or ".." in root.split("/"): bad("unsafe_root")
if not os.path.isdir(root) or not private(root): bad("unsafe_root")
base=os.path.join(root,"native-scenario-jobs",env,scenario); os.makedirs(base,mode=0o700,exist_ok=True)
for p in (os.path.join(root,"native-scenario-jobs"),os.path.join(root,"native-scenario-jobs",env),base):
 if not private(p): bad("unsafe_root")
job=os.path.join(base,corr)
try: os.mkdir(job,0o700)
except FileExistsError: bad("job_already_exists")
if not private(job): bad("unsafe_job")
stage=os.path.join(job,"bundle"); os.mkdir(stage,0o700)
for item in files:
 path,size,digest=item.get("path"),item.get("sizeBytes"),item.get("sha256")
 if not isinstance(size,int) or size<0 or size>8*1024*1024 or not isinstance(digest,str) or len(digest)!=64: bad("invalid_file_metadata")
 target=os.path.join(stage,path)
 os.makedirs(os.path.dirname(target),mode=0o700,exist_ok=True)
 out=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 left=size; hasher=hashlib.sha256()
 with os.fdopen(out,"wb") as f:
  while left:
   chunk=sys.stdin.buffer.read(min(left,65536))
   if not chunk: bad("interrupted_transfer")
   f.write(chunk); hasher.update(chunk); left-=len(chunk)
  f.flush(); os.fsync(f.fileno())
 if hasher.hexdigest()!=digest: bad("bundle_hash_mismatch")
manifest=open(os.path.join(stage,"native-scenario-manifest.json"),"rb").read()
if hashlib.sha256(manifest).hexdigest()!=bundle_hash: bad("manifest_hash_mismatch")
try:
 m=json.loads(manifest)
 if json.dumps(m,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()+b"\n" != manifest: bad("manifest_not_canonical")
 if m.get("schemaVersion")!=1 or m.get("scenarioId")!="linux-public-update-driver": bad("bundle_not_allowed")
 if m.get("files") != [{k:x[k] for k in ("path","sha256","sizeBytes")} for x in files[:-1]]: bad("manifest_inventory_mismatch")
except Exception: bad("invalid_manifest")
intent={"scenarioId":scenario,"host":host,"environment":env,"bundleHash":bundle_hash,"artifactIds":artifacts,"correlationId":corr,"jobId":"preflight-"+corr}
intent_path=os.path.join(job,"intent.json")
def durable(path,value):
 tmp=path+".tmp"; f=open(tmp,"w",encoding="utf-8"); f.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n"); f.flush(); os.fsync(f.fileno()); f.close(); os.replace(tmp,path); d=os.open(job,os.O_RDONLY); os.fsync(d); os.close(d)
durable(intent_path,intent)
launcher=os.path.join(job,"launch.py")
code=''' + repr(r'''import json,os,subprocess,sys,time
job,stage=sys.argv[1:]
while not os.path.exists(os.path.join(job,"release")): time.sleep(.01)
intent=json.load(open(os.path.join(job,"intent.json"),encoding="utf-8"))
pid=os.path.join(job,"child.pid"); exit_file=os.path.join(job,"child.exit")
entry=os.path.join(stage,"scripts","test_linux_public_install.py")
command="import importlib.util,pathlib,sys;p=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(p.parent));s=importlib.util.spec_from_file_location('native_preflight',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)"
def durable(name,value):
 path=os.path.join(job,name); tmp=path+".tmp"; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,"w",encoding="utf-8") as f: f.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n"); f.flush(); os.fsync(f.fileno())
 os.replace(tmp,path); d=os.open(job,os.O_RDONLY); os.fsync(d); os.close(d)
err=os.path.join(job,"failure.stderr"); efd=os.open(err,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(efd,"wb") as out:
 rc=subprocess.call(["/bin/sh",os.path.join(stage,"scripts","native_fixture_run.sh"),"--pid-file",pid,"--exit-file",exit_file,"--",sys.executable,"-I","-B","-c",command,entry],stdout=subprocess.DEVNULL,stderr=out)
 out.flush(); os.fsync(out.fileno())
identity=intent["identity"]
receipt={key:intent[key] for key in ("scenarioId","host","environment","bundleHash","artifactIds","correlationId","jobId")}
receipt.update({"pid":identity["pid"],"startTicks":identity["startTicks"],"exitCode":rc})
durable("evidence.json",{"evidenceClass":"component","action":"no_product_action","exitCode":rc,"failurePath":err})
durable("receipt.json",receipt)
''') + r'''
open(launcher,"w",encoding="utf-8").write(code)
os.chmod(launcher,0o600)
proc=subprocess.Popen([sys.executable,"-I","-B",launcher,job,stage],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
try: ticks=int(open("/proc/%d/stat"%proc.pid,encoding="ascii").read().rsplit(")",1)[1].split()[19])
except Exception: proc.kill(); bad("proc_generation_unavailable")
identity={"jobId":intent["jobId"],"pid":proc.pid,"startTicks":ticks,"receiptPath":os.path.join(job,"receipt.json")}
intent["identity"]=identity; durable(intent_path,intent)
open(os.path.join(job,"release"),"x").close()
print(json.dumps({"state":"submitted","identity":identity},separators=(",",":")))'''

_STATUS = r'''import json,os,stat,sys
root,host,env,scenario,corr,bundle_hash,artifact_json=sys.argv[1:]
job=os.path.join(root,"native-scenario-jobs",env,scenario,corr)
def unknown(reason): print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(0)
try:
 if not os.path.isdir(job) or stat.S_IMODE(os.stat(job,follow_symlinks=False).st_mode)!=0o700: unknown("missing_job")
 def read(name):
  path=os.path.join(job,name); fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600: os.close(fd); unknown("unsafe_"+name)
  raw=os.read(fd,16385); os.close(fd)
  if len(raw)>16384: unknown("oversized_"+name)
  return json.loads(raw)
 intent=read("intent.json")
 artifacts=json.loads(artifact_json)
 expected={"scenarioId":scenario,"host":host,"environment":env,"bundleHash":bundle_hash,"artifactIds":artifacts,"correlationId":corr}
 if any(intent.get(k)!=v for k,v in expected.items()): unknown("intent_mismatch")
 identity=intent.get("identity")
 if not isinstance(identity,dict): unknown("identity_unavailable")
 try:
  receipt=read("receipt.json")
  print(json.dumps({"state":"terminal","identity":identity,"receipt":receipt,"evidencePaths":[os.path.join(job,"evidence.json")]},separators=(",",":"))); raise SystemExit(0)
 except FileNotFoundError: pass
 try:
  tail=open("/proc/%d/stat"%identity["pid"],encoding="ascii").read().rsplit(")",1)[1].split()
  if tail[0]=="Z" or int(tail[19])!=identity["startTicks"]: unknown("pid_generation_mismatch")
 except Exception: unknown("process_missing")
 print(json.dumps({"state":"running","reason":"live_supervisor","identity":identity,"evidencePaths":[os.path.join(job,"evidence.json")]},separators=(",",":")))
except Exception: unknown("status_unavailable")'''


class NativeScenarioSshDriver:
    """Private adapter; bundle resolution is constructor wiring, never request data."""
    def __init__(self, repository_root: Path | str, bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str],
                 timeout_seconds: int = 30, ssh_binary: str = "ssh", configuration_root: Path | str | None = None):
        self.root = Path(repository_root).resolve()
        self.configuration_root = Path(configuration_root).resolve() if configuration_root is not None else self.root
        self.bundle_resolver = bundle_resolver
        self.timeout_seconds = timeout_seconds
        self.ssh_binary = ssh_binary

    def submit(self, plan: native_scenario_execution.ScenarioPlan) -> native_scenario_execution.JobIdentity:
        bundle, config, remote_root = self._admit(plan)
        payload = self._payload(bundle)
        result = self._run(config, plan.host, _py(_SUBMIT, str(remote_root), plan.host, plan.environment, plan.scenario_id,
                           plan.correlation_id, plan.bundle_hash, json.dumps(dict(plan.artifact_ids), sort_keys=True, separators=(",", ":"))), payload)
        if result is None or result.get("state") != "submitted":
            raise NativeScenarioSshError("preflight_submit_unavailable")
        return self._identity(result.get("identity"), pending=True)

    def discover(self, plan: native_scenario_execution.ScenarioPlan) -> native_scenario_execution.JobIdentity | None:
        result = self._status(plan)
        return self._identity(result.get("identity"), pending=True) if result and isinstance(result.get("identity"), Mapping) else None

    def observe(self, plan: native_scenario_execution.ScenarioPlan, identity: native_scenario_execution.JobIdentity) -> native_scenario_execution.DriverObservation:
        result = self._status(plan)
        if result is None:
            return native_scenario_execution.DriverObservation(native_scenario_execution.ObservationStatus.UNKNOWN, "observer_unavailable")
        observed = self._identity(result.get("identity"), pending=True) if isinstance(result.get("identity"), Mapping) else None
        paths = tuple(value for value in result.get("evidencePaths", []) if isinstance(value, str))
        if result.get("state") == "terminal":
            return native_scenario_execution.DriverObservation(native_scenario_execution.ObservationStatus.TERMINAL, "remote_receipt", observed, result.get("receipt"), paths)
        if result.get("state") == "running":
            return native_scenario_execution.DriverObservation(native_scenario_execution.ObservationStatus.RUNNING, str(result.get("reason", "live_pid")), observed, evidence_paths=paths)
        return native_scenario_execution.DriverObservation(native_scenario_execution.ObservationStatus.UNKNOWN, str(result.get("reason", "remote_unknown")), observed, evidence_paths=paths)

    def _admit(self, plan):
        if plan.scenario_id != SCENARIO_ID:
            raise NativeScenarioSshError("Scenario is unsupported by the preflight adapter.")
        bundle = Path(self.bundle_resolver(plan)).resolve(strict=True)
        verified = native_scenario_bundle.verify_bundle(self.root, bundle, plan.bundle_hash)
        if verified.get("scenarioId") != BUNDLE_SCENARIO_ID:
            raise NativeScenarioSshError("Bundle does not belong to the fixed preflight scenario.")
        config = ssh_transport.load_config(self.configuration_root)
        target = config.hosts.get(plan.host)
        remote_root = getattr(target, "fixture_transfer_root", None) if target else None
        if not isinstance(remote_root, PurePosixPath) or not remote_root.is_absolute():
            raise NativeScenarioSshError("Configured host has no approved fixture transfer root.")
        return bundle, config, remote_root

    def _status(self, plan):
        try:
            config = ssh_transport.load_config(self.configuration_root)
            target = config.hosts.get(plan.host)
            remote_root = getattr(target, "fixture_transfer_root", None) if target else None
            if not isinstance(remote_root, PurePosixPath) or not remote_root.is_absolute():
                return None
            return self._run(config, plan.host, _py(_STATUS, str(remote_root), plan.host, plan.environment, plan.scenario_id,
                             plan.correlation_id, plan.bundle_hash, json.dumps(dict(plan.artifact_ids), sort_keys=True, separators=(",", ":"))), None)
        except (OSError, ValueError, ssh_transport.SshConfigError):
            return None

    def _payload(self, bundle: Path) -> bytes:
        manifest = (bundle / native_scenario_bundle.MANIFEST_NAME).read_bytes()
        try:
            paths = [entry["path"] for entry in json.loads(manifest)["files"]]
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise NativeScenarioSshError("Frozen bundle manifest is invalid.") from error
        entries = []
        contents = []
        for relative in paths:
            raw = (bundle / relative).read_bytes(); entries.append({"path": relative, "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}); contents.append(raw)
        entries.append({"path": native_scenario_bundle.MANIFEST_NAME, "sizeBytes": len(manifest), "sha256": hashlib.sha256(manifest).hexdigest()}); contents.append(manifest)
        return json.dumps({"files": entries}, sort_keys=True, separators=(",", ":")).encode() + b"\n" + b"".join(contents)

    def _run(self, config, host, command, payload):
        argv = ssh_transport.build_ssh_argv(config, host, self.timeout_seconds, command=command, ssh_binary=self.ssh_binary)
        try:
            done = subprocess.run(argv, input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=self.timeout_seconds + 2, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if done.returncode != 0 or len(done.stdout) > _MAX_OUTPUT:
            return None
        try:
            value = json.loads(done.stdout.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _identity(value: Any, pending: bool) -> native_scenario_execution.JobIdentity:
        return native_scenario_execution.JobIdentity.from_mapping(value, allow_pending=pending)
