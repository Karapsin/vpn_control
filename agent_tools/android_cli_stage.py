"""Stage a verified current-source Linux CLI from its exact x86_64 RPM.

This fixed transfer never installs the RPM or starts an app.  It preserves one
private correlation and exact package/tree hashes before and after transport.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Any

try:
    from . import native_artifact_registry, ssh_transfer, ssh_transport
except ImportError:  # pragma: no cover
    import native_artifact_registry, ssh_transfer, ssh_transport


_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_PREFIX = "opt/vpn-control/"
_LAUNCHER = "opt/vpn-control/bin/vpn-control"
_JAR = re.compile(r"opt/vpn-control/lib/app/desktopApp-[0-9a-f]{16,64}\.jar\Z")
_SAFE = re.compile(r"[A-Za-z0-9._+/-]+\Z")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(65536): digest.update(chunk)
    return digest.hexdigest()


def _state(root: Path | str, correlation: str) -> Path:
    return Path(root).resolve() / ".rag_index" / "android-cli-stages" / correlation


def _private_json(path: Path, value: dict[str, Any]) -> None:
    data = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data); output.flush(); os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)


def _read_intent(root: Path | str, correlation: str) -> dict[str, Any] | None:
    path = _state(root, correlation) / "intent.json"
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                return None
            raw = source.read(65537)
        if len(raw) > 65536: return None
        value = json.loads(raw)
        return value if isinstance(value, dict) and value.get("correlationId") == correlation else None
    except (OSError, ValueError):
        return None


def _validate_entries(names: list[str], details: list[str]) -> list[tuple[str, str]]:
    if len(names) != len(details) or not 20 <= len(names) <= 1000:
        raise ValueError("Android CLI RPM entry inventory is invalid")
    result: list[tuple[str, str]] = []
    seen: set[str] = set()
    for name, detail in zip(names, details):
        normalized = name.removeprefix("./")
        if (not _SAFE.fullmatch(normalized) or normalized.startswith("/") or
                normalized in seen or any(part in {"", ".", ".."} for part in normalized.split("/")) or
                (normalized != "opt" and normalized != "opt/vpn-control" and not normalized.startswith(_PREFIX))):
            raise ValueError("Android CLI RPM has unsafe entries")
        kind = detail[:1]
        if kind not in {"-", "d"}:
            raise ValueError("Android CLI RPM contains a nonregular entry")
        seen.add(normalized); result.append((normalized, kind))
    if _LAUNCHER not in seen or len([name for name in seen if _JAR.fullmatch(name)]) != 1:
        raise ValueError("Android CLI RPM lacks a unique launcher/JAR")
    return result


def _list_rpm(rpm: Path) -> list[tuple[str, str]]:
    """Reject links/traversal before bsdtar may extract any archive entry."""
    names = subprocess.run(["bsdtar", "-tf", str(rpm)], capture_output=True, timeout=30, check=True).stdout.decode("utf-8", "strict").splitlines()
    details = subprocess.run(["bsdtar", "-tvf", str(rpm)], capture_output=True, timeout=30, check=True).stdout.decode("utf-8", "strict").splitlines()
    return _validate_entries(names, details)


def _manifest(snapshot: Path, output_root: Path) -> dict[str, Any]:
    inventory = _list_rpm(snapshot)
    tree = output_root / "tree"
    tree.mkdir(mode=0o700)
    subprocess.run(["bsdtar", "-xf", str(snapshot), "-C", str(tree)], capture_output=True, timeout=90, check=True)
    entries: list[dict[str, Any]] = []
    directories: list[dict[str, Any]] = []
    for name, kind in inventory:
        path = tree / name
        info = path.lstat()
        if kind == "d":
            if not stat.S_ISDIR(info.st_mode): raise ValueError("Android CLI RPM directory changed")
            directories.append({"path": name, "mode": stat.S_IMODE(info.st_mode)})
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 100_000_000:
                raise ValueError("Android CLI RPM file is unsafe")
            entries.append({"path": name, "size": info.st_size, "sha256": _sha(path), "mode": stat.S_IMODE(info.st_mode)})
    discovered = {str(path.relative_to(tree)) for path in tree.rglob("*")}
    if discovered != {name for name, _ in inventory}:
        raise ValueError("Android CLI RPM extracted unexpected entries")
    entries.sort(key=lambda value: value["path"])
    directories.sort(key=lambda value: value["path"])
    launcher = next(entry for entry in entries if entry["path"] == _LAUNCHER)
    jar = next(entry for entry in entries if _JAR.fullmatch(entry["path"]))
    if not launcher["mode"] & 0o111:
        raise ValueError("Android CLI launcher is not executable")
    manifest = {"schema": 1, "files": entries, "directories": directories,
                "launcherSha256": launcher["sha256"],
                "desktopJarSha256": jar["sha256"], "desktopJarPath": jar["path"]}
    return manifest


_RECEIVE = r'''import hashlib,json,os,pathlib,re,stat,subprocess,sys
root,correlation,header_json=sys.argv[1:]
def fail(reason): print(json.dumps({"state":"unknown","reason":reason,"correlationId":correlation},separators=(",",":"))); raise SystemExit(0)
try: header=json.loads(header_json)
except ValueError: fail("invalid_header")
if not isinstance(header,dict) or header.get("correlationId")!=correlation or not re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}",correlation): fail("invalid_identity")
parent=pathlib.Path(root); info=parent.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: fail("unsafe_root")
job=parent/("android-cli-stage-"+correlation)
try: job.mkdir(mode=0o700)
except FileExistsError: fail("existing_stage_no_replay")
def durable(name,value):
 path=job/name; data=json.dumps(value,sort_keys=True,separators=(",",":")).encode()+b"\n"
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 with os.fdopen(fd,"wb") as out: out.write(data); out.flush(); os.fsync(out.fileno())
 directory=os.open(job,os.O_RDONLY); os.fsync(directory); os.close(directory)
durable("intent.json",header)
expected=header.get("rpmSha256"); size=header.get("rpmSize"); manifest=header.get("manifest"); manifest_hash=header.get("manifestSha256")
if not isinstance(expected,str) or not re.fullmatch(r"[0-9a-f]{64}",expected) or type(size) is not int or not 0<size<=300000000 or not isinstance(manifest,dict) or not isinstance(manifest_hash,str): fail("invalid_inputs")
canonical=json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()
if hashlib.sha256(canonical).hexdigest()!=manifest_hash: fail("manifest_hash_invalid")
rpm=job/"package.rpm"; fd=os.open(rpm,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
digest=hashlib.sha256(); remaining=size
with os.fdopen(fd,"wb") as out:
 while remaining:
  chunk=sys.stdin.buffer.read(min(65536,remaining))
  if not chunk: fail("truncated_package")
  out.write(chunk); digest.update(chunk); remaining-=len(chunk)
 out.flush(); os.fsync(out.fileno())
if sys.stdin.buffer.read(1) or digest.hexdigest()!=expected: fail("package_hash_mismatch")
tree=job/"tree"; tree.mkdir(mode=0o700)
done=subprocess.run(["bsdtar","-xf",str(rpm),"-C",str(tree)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=120,check=False)
if done.returncode: fail("extract_failed")
files=manifest.get("files")
directory_manifest=manifest.get("directories")
if not isinstance(files,list) or not 20<=len(files)<=1000 or not isinstance(directory_manifest,list) or not 2<=len(directory_manifest)<=1000: fail("manifest_entries_invalid")
seen=set()
for entry in files:
 if not isinstance(entry,dict): fail("manifest_entry_invalid")
 name=entry.get("path"); size=entry.get("size"); expected=entry.get("sha256"); mode=entry.get("mode")
 if not isinstance(name,str) or not name.startswith("opt/vpn-control/") or any(part in ("",".","..") for part in name.split("/")) or name in seen or type(size) is not int or not 0<=size<=100000000 or not isinstance(expected,str) or re.fullmatch(r"[0-9a-f]{64}",expected) is None or type(mode) is not int: fail("manifest_entry_invalid")
 seen.add(name); path=tree/name; info=path.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_size!=size or stat.S_IMODE(info.st_mode)!=mode: fail("tree_file_invalid")
 h=hashlib.sha256()
 with path.open("rb") as source:
  while block:=source.read(65536): h.update(block)
 if h.hexdigest()!=expected: fail("tree_hash_mismatch")
discovered=set(); directories=set()
for path in tree.rglob("*"):
 info=path.lstat(); name=str(path.relative_to(tree))
 if stat.S_ISREG(info.st_mode): discovered.add(name)
 elif stat.S_ISDIR(info.st_mode): directories.add(name)
 else: fail("tree_nonregular")
expected_directories=set()
for entry in directory_manifest:
 if not isinstance(entry,dict) or not isinstance(entry.get("path"),str) or type(entry.get("mode")) is not int: fail("manifest_directory_invalid")
 name=entry["path"]; path=tree/name; info=path.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=entry["mode"]: fail("tree_directory_invalid")
 expected_directories.add(name)
if discovered!=seen or directories!=expected_directories: fail("tree_extra_or_missing")
launcher=tree/"opt/vpn-control/bin/vpn-control"; jars=[e for e in files if re.fullmatch(r"opt/vpn-control/lib/app/desktopApp-[0-9a-f]{16,64}\.jar",e["path"])]
if len(jars)!=1 or not os.access(launcher,os.X_OK): fail("launcher_invalid")
if manifest.get("launcherSha256")!=next(e["sha256"] for e in files if e["path"]=="opt/vpn-control/bin/vpn-control") or manifest.get("desktopJarSha256")!=jars[0]["sha256"] or manifest.get("desktopJarPath")!=jars[0]["path"]: fail("key_hash_invalid")
receipt={"state":"published","correlationId":correlation,"rpmSha256":header["rpmSha256"],"manifestSha256":manifest_hash,"launcherSha256":manifest["launcherSha256"],"desktopJarSha256":manifest["desktopJarSha256"],"cliPath":str(launcher)}
durable("receipt.json",receipt)
print(json.dumps(receipt,separators=(",",":")))'''


_STATUS = r'''import hashlib,json,os,pathlib,re,stat,sys
root,correlation,expected_hash=sys.argv[1:]
def emit(state,reason=None,**extra): print(json.dumps({"state":state,"reason":reason,"correlationId":correlation,**extra},separators=(",",":"))); raise SystemExit(0)
job=pathlib.Path(root)/("android-cli-stage-"+correlation)
try:
 info=job.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700: emit("unknown","unsafe_job")
 def read(name):
  fd=os.open(job/name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  with os.fdopen(fd,"rb") as source:
   info=os.fstat(source.fileno())
   if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600: emit("unknown","unsafe_"+name)
   raw=source.read(65537)
  if len(raw)>65536: emit("unknown","oversized_"+name)
  return json.loads(raw)
 intent=read("intent.json")
 if intent.get("manifestSha256")!=expected_hash or intent.get("correlationId")!=correlation: emit("unknown","intent_mismatch")
 try: receipt=read("receipt.json")
 except FileNotFoundError: emit("unknown","stage_incomplete")
 if receipt.get("state")!="published" or receipt.get("manifestSha256")!=expected_hash or receipt.get("rpmSha256")!=intent.get("rpmSha256"): emit("unknown","receipt_mismatch")
 manifest=intent.get("manifest"); files=manifest.get("files") if isinstance(manifest,dict) else None
 if not isinstance(files,list): emit("unknown","manifest_invalid")
 if hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(",",":")).encode()).hexdigest()!=expected_hash: emit("unknown","manifest_changed")
 tree=job/"tree"; names=set()
 for entry in files:
  name=entry.get("path"); names.add(name)
  path=tree/name; info=path.lstat()
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or info.st_size!=entry.get("size") or stat.S_IMODE(info.st_mode)!=entry.get("mode"): emit("unknown","tree_file_invalid")
  digest=hashlib.sha256()
  fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
  with os.fdopen(fd,"rb") as source:
   if os.fstat(source.fileno()).st_ino!=info.st_ino: emit("unknown","tree_changed")
   while chunk:=source.read(65536): digest.update(chunk)
  if digest.hexdigest()!=entry.get("sha256"): emit("unknown","tree_hash_mismatch")
 discovered=set(); directories=set()
 for path in tree.rglob("*"):
  info=path.lstat(); name=str(path.relative_to(tree))
  if stat.S_ISREG(info.st_mode): discovered.add(name)
  elif stat.S_ISDIR(info.st_mode): directories.add(name)
  else: emit("unknown","tree_nonregular")
 expected_directories=set()
 for entry in manifest.get("directories",[]):
  if not isinstance(entry,dict) or not isinstance(entry.get("path"),str) or type(entry.get("mode")) is not int: emit("unknown","manifest_directory_invalid")
  name=entry["path"]; path=tree/name; info=path.lstat()
  if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=entry["mode"]: emit("unknown","tree_directory_invalid")
  expected_directories.add(name)
 if discovered!=names or directories!=expected_directories: emit("unknown","tree_extra_or_missing")
 rpm=job/"package.rpm"; info=rpm.lstat()
 if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or info.st_size!=intent.get("rpmSize"): emit("unknown","rpm_size_changed")
 digest=hashlib.sha256()
 fd=os.open(rpm,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
 with os.fdopen(fd,"rb") as source:
  if os.fstat(source.fileno()).st_ino!=info.st_ino: emit("unknown","rpm_changed")
  while chunk:=source.read(65536): digest.update(chunk)
 if digest.hexdigest()!=intent.get("rpmSha256"): emit("unknown","rpm_hash_changed")
 emit("published",None,receipt=receipt)
except FileNotFoundError: emit("unknown","stage_missing")
except (OSError,ValueError,TypeError,KeyError): emit("unknown","stage_unavailable")'''


def start(root: Path | str, host: str, correlation_id: str, artifact_id: str) -> dict[str, Any]:
    if host != "archlinux" or not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android CLI stage requires owned Arch host and UUID")
    verified = native_artifact_registry.verify_artifact(root, artifact_id)
    if (verified.get("verification") != "verified" or verified["artifact"].get("platform") != "linux" or
            verified["artifact"].get("artifactKind") not in {"package", "desktop-package-target"}):
        raise ValueError("Android CLI stage requires a verified Linux RPM")
    source_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=10, check=True).stdout.strip()
    if verified["artifact"].get("sourceSha") != source_sha:
        raise ValueError("Android CLI package source differs from checkout")
    rpm_path = Path(verified["location"]["localPath"])
    if rpm_path.suffix != ".rpm" or not rpm_path.name.startswith("vpn-control-") or not rpm_path.name.endswith(".x86_64.rpm"):
        raise ValueError("Android CLI stage requires x86_64 VPN Control RPM")
    config = ssh_transport.load_config(root)
    if host not in config.hosts or config.hosts[host].fixture_transfer_root is None or ssh_transport.connection_host(config, host).password is not None:
        raise ValueError("Android CLI stage route is unavailable")
    state = _state(root, correlation_id)
    state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = state.parent.lstat()
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
        raise ValueError("Android CLI stage journal parent is not private")
    state.mkdir(mode=0o700, exist_ok=False)
    state_info = state.lstat()
    if not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != os.getuid() or stat.S_IMODE(state_info.st_mode) != 0o700:
        raise ValueError("Android CLI stage journal is not private")
    snapshot = state / "package.rpm"
    digest = hashlib.sha256(); total = 0
    fd = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output, rpm_path.open("rb") as source:
        while chunk := source.read(65536):
            output.write(chunk); digest.update(chunk); total += len(chunk)
        output.flush(); os.fsync(output.fileno())
    if digest.hexdigest() != verified["artifact"]["sha256"] or total != verified["artifact"]["size"]:
        raise ValueError("Android CLI RPM changed during snapshot")
    manifest = _manifest(snapshot, state)
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest_hash = hashlib.sha256(canonical).hexdigest()
    intent = {"correlationId": correlation_id, "host": host, "artifactId": artifact_id, "sourceSha": source_sha,
              "rpmSha256": digest.hexdigest(), "rpmSize": total, "manifest": manifest,
              "manifestSha256": manifest_hash, "fixtureRoot": str(config.hosts[host].fixture_transfer_root)}
    _private_json(state / "intent.json", intent)
    header = json.dumps(intent, sort_keys=True, separators=(",", ":")).encode()
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c", "exec(" + repr(_RECEIVE) + ")",
        intent["fixtureRoot"], correlation_id, header.decode()))
    try:
        code, output = ssh_transfer._bounded_run(argv, ssh_transfer.StreamPayload(b"", snapshot), 60)
        observed = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(observed, dict) and observed.get("state") == "published" and observed.get("correlationId") == correlation_id and observed.get("manifestSha256") == manifest_hash:
            return {"ok": True, "state": "published", "correlationId": correlation_id, "identity": observed, "replayAllowed": False}
    except (OSError, ValueError, UnicodeError, ssh_transfer.SshTransferError):
        pass
    return {"ok": False, "state": "unknown", "correlationId": correlation_id, "replayAllowed": False}


def status(root: Path | str, correlation_id: str) -> dict[str, Any]:
    if not isinstance(correlation_id, str) or not _UUID.fullmatch(correlation_id):
        raise ValueError("Android CLI stage requires UUID")
    intent = _read_intent(root, correlation_id)
    if intent is None: return {"ok": False, "state": "unknown", "reason": "missing_intent", "correlationId": correlation_id, "replayAllowed": False}
    config = ssh_transport.load_config(root); host = intent["host"]
    if host not in config.hosts or str(config.hosts[host].fixture_transfer_root) != intent.get("fixtureRoot"):
        return {"ok": False, "state": "unknown", "reason": "route_changed", "correlationId": correlation_id, "replayAllowed": False}
    argv = ssh_transport.build_ssh_argv(config, host, 60, command=("python3", "-I", "-B", "-c", "exec(" + repr(_STATUS) + ")",
        intent["fixtureRoot"], correlation_id, intent["manifestSha256"]))
    try:
        code, output = ssh_transfer._bounded_run(argv, None, 60)
        observed = json.loads(output.decode("utf-8", "strict")) if code == 0 else None
        if isinstance(observed, dict) and observed.get("state") == "published" and observed.get("correlationId") == correlation_id:
            receipt = observed.get("receipt")
            expected_path = intent["fixtureRoot"] + "/android-cli-stage-" + correlation_id + "/tree/" + _LAUNCHER
            if isinstance(receipt, dict) and receipt.get("cliPath") == expected_path and receipt.get("rpmSha256") == intent["rpmSha256"] and receipt.get("manifestSha256") == intent["manifestSha256"]:
                return {"ok": True, "state": "published", "correlationId": correlation_id, "receipt": receipt,
                        "sourceSha": intent["sourceSha"], "artifactId": intent["artifactId"], "replayAllowed": False}
    except (OSError, ValueError, UnicodeError, ssh_transfer.SshTransferError):
        pass
    return {"ok": False, "state": "unknown", "reason": "stage_or_transport_unknown", "correlationId": correlation_id, "replayAllowed": False}


def collect(root: Path | str, correlation_id: str) -> dict[str, Any]:
    return status(root, correlation_id)
