"""Fixed SSH driver for the owned Linux scheduled-refresh native scenario.

The registered bundle and typed input are transferred by exact digest into one
private correlation directory.  A durable remote intent precedes one detached
fixed runner invocation; status only observes that exact job generation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import uuid
from typing import Any, Callable, Mapping

try:
    from . import native_scenario_bundle, native_scenario_execution, native_scenario_ssh, ssh_transport
except ImportError:  # MCP CLI fallback executes mcp_server.py as a script.
    import native_scenario_bundle  # type: ignore[no-redef]
    import native_scenario_execution  # type: ignore[no-redef]
    import native_scenario_ssh  # type: ignore[no-redef]
    import ssh_transport  # type: ignore[no-redef]


SCENARIO_ID = "linux-scheduled-refresh"
BUNDLE_SCENARIO_ID = "linux-scheduled-refresh-driver"
_FILES = ("scripts/integration/linux_scheduled_refresh_scenario.py",
          "scripts/integration/socks_http_fixture.py", "scripts/native_fixture_preflight.py",
          "scripts/native_fixture_run.sh")
_INPUT_SCHEMA = "vpn-control.linux-scheduled-refresh.input"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_INPUT = 65536


class NativeScheduledRefreshSshError(ValueError):
    pass


_LAUNCHER = r'''import json,os,stat,subprocess,sys,time
job,stage=sys.argv[1:]
while not os.path.exists(os.path.join(job,"release")): time.sleep(.01)
intent=json.load(open(os.path.join(job,"intent.json"),encoding="utf-8"))
pid=os.path.join(job,"child.pid"); exit_file=os.path.join(job,"child.exit")
entry=os.path.join(stage,"scripts","integration","linux_scheduled_refresh_scenario.py")
input_path=os.path.join(stage,"scenario-input.json")
scenario_receipt=os.path.join(job,"scenario-receipt.json")
runner="import pathlib,runpy,sys;p=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(p.parent.parent));sys.path.insert(0,str(p.parent));sys.argv=[str(p),'--input',sys.argv[2],'--receipt',sys.argv[3]];runpy.run_path(str(p),run_name='__main__')"
def durable(name,value):
 path=os.path.join(job,name); tmp=path+".tmp"; fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,"w",encoding="utf-8") as f: f.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n"); f.flush(); os.fsync(f.fileno())
 os.replace(tmp,path); d=os.open(job,os.O_RDONLY); os.fsync(d); os.close(d)
err=os.path.join(job,"failure.stderr"); efd=os.open(err,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(efd,"wb") as out:
 rc=subprocess.call(["/bin/sh",os.path.join(stage,"scripts","native_fixture_run.sh"),"--pid-file",pid,"--exit-file",exit_file,"--",sys.executable,"-I","-B","-c",runner,entry,input_path,scenario_receipt],stdout=subprocess.DEVNULL,stderr=out)
 out.flush(); os.fsync(out.fileno())
evidence={"evidenceClass":"native-scheduled-refresh","scenarioReceiptAvailable":False,"runnerExitCode":rc,"cleanupState":"unknown"}
try:
 fd=os.open(scenario_receipt,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)); info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)&0o077 or info.st_size>4*1024*1024: raise ValueError()
 raw=os.read(fd,4*1024*1024+1); os.close(fd); item=json.loads(raw)
 if not isinstance(item,dict) or item.get("schema")!="vpn-control.linux-scheduled-refresh.receipt" or item.get("scenarioId")!=intent["scenarioId"] or item.get("correlationId")!=intent["correlationId"]: raise ValueError()
 cleanup=item.get("cleanup")
 if not isinstance(cleanup,dict): raise ValueError()
 evidence["scenarioReceiptAvailable"]=True
 evidence["cleanupState"]=str(cleanup.get("state","unknown"))[:32]
 evidence["scenarioReceiptPath"]=scenario_receipt
 if rc==0 and (item.get("result")!="passed" or cleanup.get("state")!="complete" or cleanup.get("ownerStopped") is not True or cleanup.get("workspaceRemoved") is not True or cleanup.get("protectedPreserved") is not True): rc=1
except Exception:
 if rc==0: rc=1
if rc!=0: evidence["failurePath"]=err
durable("evidence.json",evidence)
identity=intent["identity"]
receipt={key:intent[key] for key in ("scenarioId","host","environment","bundleHash","artifactIds","correlationId","jobId")}
receipt.update({"pid":identity["pid"],"startTicks":identity["startTicks"],"exitCode":rc})
durable("receipt.json",receipt)
'''


_SUBMIT = r'''import hashlib,json,os,stat,subprocess,sys
root,host,env,scenario,corr,bundle_hash,artifact_json=sys.argv[1:8]
os.umask(0o077)
names=("scripts/integration/linux_scheduled_refresh_scenario.py","scripts/integration/socks_http_fixture.py","scripts/native_fixture_preflight.py","scripts/native_fixture_run.sh","native-scenario-manifest.json","scenario-input.json")
def bad(reason): print(json.dumps({"state":"unknown","reason":reason},separators=(",",":"))); raise SystemExit(64)
if scenario!="linux-scheduled-refresh": bad("scenario_not_allowed")
try: artifacts=json.loads(artifact_json)
except Exception: bad("invalid_artifacts")
if not isinstance(artifacts,dict) or set(artifacts)!={"bundleManifest","scenarioInput"}: bad("invalid_artifacts")
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
 if hasher.hexdigest()!=digest: bad("input_hash_mismatch")
manifest=open(os.path.join(stage,"native-scenario-manifest.json"),"rb").read()
if hashlib.sha256(manifest).hexdigest()!=bundle_hash or artifacts["bundleManifest"]!="sha256-"+bundle_hash: bad("manifest_hash_mismatch")
if hashlib.sha256(open(os.path.join(stage,"scenario-input.json"),"rb").read()).hexdigest()!=artifacts["scenarioInput"].removeprefix("sha256-"): bad("scenario_input_hash_mismatch")
try:
 m=json.loads(manifest)
 if json.dumps(m,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()+b"\n" != manifest: bad("manifest_not_canonical")
 if m.get("schemaVersion")!=1 or m.get("scenarioId")!="linux-scheduled-refresh-driver": bad("bundle_not_allowed")
 if m.get("files") != [{k:x[k] for k in ("path","sha256","sizeBytes")} for x in files[:-2]]: bad("manifest_inventory_mismatch")
 typed=json.load(open(os.path.join(stage,"scenario-input.json"),encoding="utf-8"))
 if typed.get("schema")!="vpn-control.linux-scheduled-refresh.input" or typed.get("schemaVersion")!=1 or typed.get("scenarioId")!=scenario or typed.get("correlationId")!=corr: bad("scenario_input_mismatch")
except Exception: bad("invalid_manifest_or_input")
intent={"scenarioId":scenario,"host":host,"environment":env,"bundleHash":bundle_hash,"artifactIds":artifacts,"correlationId":corr,"jobId":"scheduled-"+corr}
def durable(path,value):
 tmp=path+".tmp"; f=open(tmp,"w",encoding="utf-8"); f.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n"); f.flush(); os.fsync(f.fileno()); f.close(); os.replace(tmp,path); d=os.open(job,os.O_RDONLY); os.fsync(d); os.close(d)
durable(os.path.join(job,"intent.json"),intent)
launcher=os.path.join(job,"launch.py")
code=''' + repr(_LAUNCHER) + r'''
open(launcher,"w",encoding="utf-8").write(code)
os.chmod(launcher,0o600)
proc=subprocess.Popen([sys.executable,"-I","-B",launcher,job,stage],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)
try: ticks=int(open("/proc/%d/stat"%proc.pid,encoding="ascii").read().rsplit(")",1)[1].split()[19])
except Exception: proc.kill(); bad("proc_generation_unavailable")
identity={"jobId":intent["jobId"],"pid":proc.pid,"startTicks":ticks,"receiptPath":os.path.join(job,"receipt.json")}
intent["identity"]=identity; durable(os.path.join(job,"intent.json"),intent)
open(os.path.join(job,"release"),"x").close()
print(json.dumps({"state":"submitted","identity":identity},separators=(",",":")))'''


_COLLECT = r'''import json,os,stat,sys
root,host,env,scenario,corr,bundle_hash,artifact_json,pid,ticks=sys.argv[1:]
job=os.path.join(root,"native-scenario-jobs",env,scenario,corr)
def unknown(): print(json.dumps({"state":"unknown","correlationId":corr},separators=(",",":"))); raise SystemExit(0)
def read(name):
 path=os.path.join(job,name); fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size>4*1024*1024: unknown()
  raw=os.read(fd,4*1024*1024+1)
  if len(raw)!=info.st_size: unknown()
  value=json.loads(raw)
  if not isinstance(value,dict): unknown()
  return value
 finally: os.close(fd)
try:
 st=os.stat(job,follow_symlinks=False)
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700: unknown()
 intent=read("intent.json"); wrapper=read("receipt.json"); receipt=read("scenario-receipt.json")
 expected={"scenarioId":scenario,"host":host,"environment":env,"bundleHash":bundle_hash,"artifactIds":json.loads(artifact_json),"correlationId":corr}
 if any(intent.get(k)!=v or wrapper.get(k)!=v for k,v in expected.items()): unknown()
 identity=intent.get("identity")
 if not isinstance(identity,dict) or identity.get("pid")!=int(pid) or identity.get("startTicks")!=int(ticks): unknown()
 if wrapper.get("pid")!=int(pid) or wrapper.get("startTicks")!=int(ticks): unknown()
 if receipt.get("schema")!="vpn-control.linux-scheduled-refresh.receipt" or receipt.get("scenarioId")!=scenario or receipt.get("correlationId")!=corr: unknown()
 cleanup=receipt.get("cleanup"); preflight=receipt.get("preflight")
 if not isinstance(cleanup,dict): unknown()
 def flag(row,key): return row.get(key) if isinstance(row.get(key),bool) else None
 summary={"state":"collected","scenarioId":scenario,"correlationId":corr,"result":receipt.get("result") if receipt.get("result") in ("passed","failed") else "unknown",
  "exitCode":wrapper.get("exitCode") if type(wrapper.get("exitCode")) is int else None,
  "mode":receipt.get("mode") if receipt.get("mode") in ("refresh-only","refresh-find-best") else None,
  "cleanup":{"state":cleanup.get("state") if cleanup.get("state") in ("complete","incomplete","preserved-for-recovery","not-started") else "unknown",
   "ownerStopped":flag(cleanup,"ownerStopped"),"protectedPreserved":flag(cleanup,"protectedPreserved"),"workspaceRemoved":flag(cleanup,"workspaceRemoved")},
  "preflightReady":flag(preflight,"ready") if isinstance(preflight,dict) else None}
 scheduled=receipt.get("scheduled")
 if isinstance(scheduled,dict):
  operation=scheduled.get("operation")
  if isinstance(operation,dict):
   opid=operation.get("id")
   if isinstance(opid,str) and len(opid)<=128 and all(c.isalnum() or c in "_.:-" for c in opid): summary["scheduledOperationId"]=opid
  code=scheduled.get("code")
  if isinstance(code,str) and len(code)<=64 and all(c.isalnum() or c in "_.:-" for c in code): summary["scheduledCode"]=code
 explicit=receipt.get("explicit")
 if isinstance(explicit,dict) and isinstance(explicit.get("benchmark"),dict):
  measured=explicit["benchmark"].get("secondaryTotalMs")
  if type(measured) in (int,float) and 0<=measured<=3600000: summary["secondaryTotalMs"]=measured
 traffic=receipt.get("traffic")
 if isinstance(traffic,dict):
  summary["traffic"]={key:flag(traffic,key) for key in ("oldPortContinuity","portMigrated","postTransitionTraffic")}
 print(json.dumps(summary,separators=(",",":")))
except Exception: unknown()'''


class NativeScheduledRefreshSshDriver(native_scenario_ssh.NativeScenarioSshDriver):
    def __init__(self, repository_root: Path | str,
                 bundle_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str],
                 input_resolver: Callable[[native_scenario_execution.ScenarioPlan], Path | str],
                 timeout_seconds: int = 30, ssh_binary: str = "ssh",
                 configuration_root: Path | str | None = None):
        super().__init__(repository_root, bundle_resolver, timeout_seconds, ssh_binary, configuration_root)
        self.input_resolver = input_resolver

    def submit(self, plan: native_scenario_execution.ScenarioPlan) -> native_scenario_execution.JobIdentity:
        if plan.scenario_id != SCENARIO_ID or set(plan.artifact_ids) != {"bundleManifest", "scenarioInput"}:
            raise NativeScheduledRefreshSshError("Scheduled refresh artifact binding is invalid.")
        bundle = Path(self.bundle_resolver(plan)).resolve(strict=True)
        verified = native_scenario_bundle.verify_bundle(self.root, bundle, plan.bundle_hash)
        if verified.get("scenarioId") != BUNDLE_SCENARIO_ID:
            raise NativeScheduledRefreshSshError("Bundle is not the scheduled refresh driver.")
        input_path = Path(self.input_resolver(plan))
        input_bytes = self._input_bytes(input_path, plan)
        config = ssh_transport.load_config(self.configuration_root)
        target = config.hosts.get(plan.host)
        remote_root = getattr(target, "fixture_transfer_root", None) if target else None
        if not isinstance(remote_root, PurePosixPath) or not remote_root.is_absolute():
            raise NativeScheduledRefreshSshError("Configured host has no fixture transfer root.")
        payload = self._payload_scheduled(bundle, input_bytes)
        result = self._run(config, plan.host, native_scenario_ssh._py(_SUBMIT, str(remote_root), plan.host,
            plan.environment, plan.scenario_id, plan.correlation_id, plan.bundle_hash,
            json.dumps(dict(plan.artifact_ids), sort_keys=True, separators=(",", ":"))), payload)
        if result is None or result.get("state") != "submitted":
            raise NativeScheduledRefreshSshError("Scheduled refresh submission is unavailable; observe correlation.")
        return self._identity(result.get("identity"), pending=True)

    def collect(self, plan: native_scenario_execution.ScenarioPlan,
                identity: native_scenario_execution.JobIdentity) -> Mapping[str, Any] | None:
        if (plan.scenario_id != SCENARIO_ID or identity.pid is None or identity.start_ticks is None
                or set(plan.artifact_ids) != {"bundleManifest", "scenarioInput"}):
            return None
        try:
            config = ssh_transport.load_config(self.configuration_root)
            target = config.hosts.get(plan.host)
            remote_root = getattr(target, "fixture_transfer_root", None) if target else None
            if not isinstance(remote_root, PurePosixPath) or not remote_root.is_absolute():
                return None
            result = self._run(config, plan.host, native_scenario_ssh._py(_COLLECT, str(remote_root),
                plan.host, plan.environment, plan.scenario_id, plan.correlation_id, plan.bundle_hash,
                json.dumps(dict(plan.artifact_ids), sort_keys=True, separators=(",", ":")),
                str(identity.pid), str(identity.start_ticks)), None)
            return result if result and result.get("state") == "collected" and result.get("correlationId") == plan.correlation_id else None
        except (OSError, ValueError, ssh_transport.SshConfigError):
            return None

    @staticmethod
    def _input_bytes(path: Path, plan: native_scenario_execution.ScenarioPlan) -> bytes:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > _MAX_INPUT:
                raise NativeScheduledRefreshSshError("Frozen scheduled refresh input is unsafe.")
            raw = os.read(descriptor, _MAX_INPUT + 1)
            after = os.fstat(descriptor)
            if (len(raw) != info.st_size or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                raise NativeScheduledRefreshSshError("Frozen scheduled refresh input changed during admission.")
        finally:
            os.close(descriptor)
        if "sha256-" + hashlib.sha256(raw).hexdigest() != plan.artifact_ids["scenarioInput"]:
            raise NativeScheduledRefreshSshError("Frozen scheduled refresh input bytes changed.")
        try:
            value = json.loads(raw)
        except (UnicodeError, ValueError) as error:
            raise NativeScheduledRefreshSshError("Frozen scheduled refresh input is invalid JSON.") from error
        required = {"schema", "schemaVersion", "scenarioId", "correlationId", "ownedWorkspaceRoot",
                    "protectedStateDir", "protectedControllerId", "expectedPackageNevra", "expectedDesktopJarSha256",
                    "mode", "scheduleHours", "maxObservationSeconds"}
        if (not isinstance(value, dict) or set(value) != required or value.get("schema") != _INPUT_SCHEMA
                or value.get("schemaVersion") != 1 or value.get("scenarioId") != plan.scenario_id
                or value.get("correlationId") != plan.correlation_id
                or not isinstance(value.get("expectedDesktopJarSha256"), str)
                or not _HEX.fullmatch(value["expectedDesktopJarSha256"])
                or value.get("mode") not in {"refresh-only", "refresh-find-best"}):
            raise NativeScheduledRefreshSshError("Frozen scheduled refresh input does not match the plan.")
        for field in ("ownedWorkspaceRoot", "protectedStateDir"):
            selected = value[field]
            if (not isinstance(selected, str) or not PurePosixPath(selected).is_absolute()
                    or ".." in PurePosixPath(selected).parts or any(ord(char) < 32 for char in selected)):
                raise NativeScheduledRefreshSshError("Frozen scheduled refresh path is invalid.")
        try:
            if str(uuid.UUID(value["protectedControllerId"])) != value["protectedControllerId"]:
                raise ValueError()
        except (ValueError, TypeError, AttributeError) as error:
            raise NativeScheduledRefreshSshError("Frozen controller identity is invalid.") from error
        package = value["expectedPackageNevra"]
        hours = value["scheduleHours"]
        duration = value["maxObservationSeconds"]
        if (not isinstance(package, str) or not package or len(package) > 200
                or any(ord(char) < 32 for char in package)
                or type(hours) not in (int, float) or not 0.084 <= hours <= 0.98
                or type(duration) not in (int, float) or not hours * 3600 + 30 <= duration <= 3600):
            raise NativeScheduledRefreshSshError("Frozen scheduled refresh timing or package identity is invalid.")
        return raw

    @staticmethod
    def _payload_scheduled(bundle: Path, input_bytes: bytes) -> bytes:
        paths = (*_FILES, native_scenario_bundle.MANIFEST_NAME)
        entries = []
        contents = []
        for relative in paths:
            raw = (bundle / relative).read_bytes()
            entries.append({"path": relative, "sizeBytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            contents.append(raw)
        entries.append({"path": "scenario-input.json", "sizeBytes": len(input_bytes),
                        "sha256": hashlib.sha256(input_bytes).hexdigest()})
        contents.append(input_bytes)
        return json.dumps({"files": entries}, sort_keys=True, separators=(",", ":")).encode() + b"\n" + b"".join(contents)
