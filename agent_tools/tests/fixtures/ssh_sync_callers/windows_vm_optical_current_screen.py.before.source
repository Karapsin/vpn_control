"""One-shot read-only QMP current-screen observation for the sealed third boot attempt."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
from typing import Any, Mapping

try:
    from . import windows_vm_optical_boot as boot
    from . import windows_vm_optical_boot_attempt3 as third
    from . import windows_vm_optical_post_collect as post
except ImportError:
    import windows_vm_optical_boot as boot  # type: ignore[no-redef]
    import windows_vm_optical_boot_attempt3 as third  # type: ignore[no-redef]
    import windows_vm_optical_post_collect as post  # type: ignore[no-redef]


ATTEMPT_CORRELATION = "e80d5b29-d44f-4b22-a821-5612304564b5"
CLOSURE_CORRELATION = "7cbc014c-3890-422a-891a-a114d7cb779e"

_OBSERVE = r'''
ACTION=__ACTION__;OBS=__OBS__;EXPECTED_OWNER=__EXPECTED_OWNER__
CURRENT_INTENT=GUEST+'/optical-boot-attempt3-current-intent.json'
CURRENT_RECEIPT=GUEST+'/optical-boot-attempt3-current-receipt.json'
CURRENT_FRAME=GUEST+'/optical-boot-attempt3-current-'+OBS+'.ppm'
def current_source():
 owner=claim();media=source()
 if EXPECTED_OWNER is not None and owner!=EXPECTED_OWNER:raise ValueError('owner-changed')
 old=read(INTENT);disk=old.get('blankDisk')
 if not isinstance(disk,dict) or disk!={'device':owner['diskDevice'],'inode':owner['diskInode'],'virtualSizeBytes':96*1024**3,'allocatedGuestClusters':0}:raise ValueError('old-intent')
 historical_closures(owner,media,disk)
 state=validate_receipts(owner,media,disk)
 if state.get('state')!='post-screen-observed':raise ValueError('old-frame-not-sealed')
 after=frame(POST_FRAME,False)
 if state.get('frameHashes',{}).get('after')!=after['sha256']:raise ValueError('old-frame-hash')
 if claim()!=owner or not same_media(media):raise ValueError('source-changed')
 return owner,media,disk,after
def current_expected(owner,media,disk,after):
 return {'schemaVersion':1,'observationCorrelationId':OBS,'attemptCorrelationId':CORR,
         'closureCorrelationId':EXPECTED_CLOSURE,'owner':owner,'media':media,
         'blankDisk':disk,'previousPostSha256':after['sha256']}
def current_status(owner,media,disk,after):
 if not os.path.lexists(CURRENT_INTENT):
  if os.path.lexists(CURRENT_RECEIPT) or os.path.lexists(CURRENT_FRAME):raise ValueError('orphan-current-evidence')
  return {'state':'absent'}
 if read(CURRENT_INTENT)!=current_expected(owner,media,disk,after):raise ValueError('current-intent-changed')
 if not os.path.lexists(CURRENT_RECEIPT):
  if os.path.lexists(CURRENT_FRAME):return {'state':'frame-uncertain'}
  return {'state':'intent-only'}
 current=frame(CURRENT_FRAME,False)
 if read(CURRENT_RECEIPT)!={'schemaVersion':1,'observationCorrelationId':OBS,
                           'attemptCorrelationId':CORR,'owner':owner,'frame':current}:raise ValueError('current-receipt-changed')
 return {'state':'observed','frame':current}
try:
 owner,media,disk,after=current_source()
 if ACTION=='preflight':
  if current_status(owner,media,disk,after)['state']!='absent':raise ValueError('observation-already-started')
  print(json.dumps({'schemaVersion':1,'observationCorrelationId':OBS,'state':'ready','owner':owner,
                    'previousPostSha256':after['sha256'],'nativeActionAllowed':False}))
 elif ACTION=='start':
  if current_status(owner,media,disk,after)['state']!='absent':raise ValueError('observation-already-started')
  record(CURRENT_INTENT,current_expected(owner,media,disk,after))
  sock,command=qmp_open(owner)
  try:
   if claim()!=owner or not same_media(media):raise ValueError('owner-changed-before-frame')
   observed=frame(CURRENT_FRAME,True,command)
   if claim()!=owner or not same_media(media):raise ValueError('owner-changed-after-frame')
   record(CURRENT_RECEIPT,{'schemaVersion':1,'observationCorrelationId':OBS,
                           'attemptCorrelationId':CORR,'owner':owner,'frame':observed})
  finally:sock.close()
  print(json.dumps({'schemaVersion':1,'observationCorrelationId':OBS,'state':'observed','owner':owner,
                    'frame':observed,'nativeActionAllowed':False}))
 elif ACTION=='status':
  state=current_status(owner,media,disk,after)
  if claim()!=owner:raise ValueError('owner-changed')
  print(json.dumps({'schemaVersion':1,'observationCorrelationId':OBS,**state,'owner':owner,'nativeActionAllowed':False}))
 elif ACTION=='collect':
  state=current_status(owner,media,disk,after)
  if state['state']!='observed':raise ValueError('current-not-sealed')
  sealed=state['frame']
  fd=os.open(CURRENT_FRAME,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  try:
   before=os.fstat(fd);raw=os.read(fd,8388609);later=os.fstat(fd);named=os.stat(CURRENT_FRAME,follow_symlinks=False)
   keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
   if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or
       len(raw)!=sealed['sizeBytes'] or hashlib.sha256(raw).hexdigest()!=sealed['sha256'] or
       any(getattr(before,k)!=getattr(later,k) or getattr(before,k)!=getattr(named,k) for k in keys)):
    raise ValueError('current-frame-changed')
  finally:os.close(fd)
  if claim()!=owner or not same_media(media):raise ValueError('owner-changed')
  write_all(1,raw)
 else:raise ValueError('invalid-action')
except Exception:
 if ACTION=='collect':raise SystemExit(3)
 print(json.dumps({'schemaVersion':1,'observationCorrelationId':OBS,'state':'unknown','nativeActionAllowed':False}))
'''


def _program(action: str, observation_correlation_id: str,
             expected_owner: Mapping[str, int] | None = None) -> str:
    if action not in ("preflight", "start", "status", "collect"):
        raise ValueError("Windows current-screen action is not fixed")
    base = boot._program(ATTEMPT_CORRELATION, "status", attempt=3,
                         expected_closure=CLOSURE_CORRELATION)
    prefix = base.split("\ntry:\n owner=claim()", 1)[0]
    if prefix == base:
        raise ValueError("Windows optical source has no fixed observation boundary")
    tail = _OBSERVE
    for key, value in {"ACTION": action, "OBS": observation_correlation_id,
                       "EXPECTED_OWNER": dict(expected_owner) if expected_owner is not None else None}.items():
        tail = tail.replace("__" + key + "__", repr(value))
    return prefix + tail


def _check(root: str | Path, host: str, observation_correlation_id: str,
           timeout_seconds: int) -> dict[str, Any]:
    boot._check(host, observation_correlation_id, timeout_seconds)
    if observation_correlation_id in (boot.FIRST_CORRELATION, boot.FIRST_CLOSURE,
                                      boot.SECOND_CORRELATION, ATTEMPT_CORRELATION,
                                      CLOSURE_CORRELATION):
        raise ValueError("Windows current-screen observation needs a new correlation")
    third_status = third.status(root, host=host, correlation_id=ATTEMPT_CORRELATION,
                                closure_correlation_id=CLOSURE_CORRELATION,
                                timeout_seconds=timeout_seconds)
    if (third_status.get("state") != "post-screen-observed"
            or not isinstance(third_status.get("owner"), Mapping)
            or not isinstance(third_status.get("frameHashes"), Mapping)
            or not boot.SHA.fullmatch(third_status["frameHashes"].get("after", ""))):
        raise ValueError("Windows third optical post-frame is not sealed")
    return third_status


def _intent(root: str | Path, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-optical-current-screen"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Windows current-screen journal is unsafe")
    return directory / "intent.json"


def _payload(observation_correlation_id: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "host": boot.HOST,
            "observationCorrelationId": observation_correlation_id,
            "attemptCorrelationId": ATTEMPT_CORRELATION,
            "closureCorrelationId": CLOSURE_CORRELATION,
            "guest": boot.setup.GUEST, "windowsSha256": boot.setup.WINDOWS_SHA256}


def _remote_json(root: str | Path, action: str, observation_correlation_id: str,
                 expected_owner: Mapping[str, int], timeout_seconds: int,
                 previous_post_sha256: str) -> dict[str, Any]:
    config = boot.ssh_transport.load_config(root)
    if (boot.HOST not in config.hosts
            or boot.ssh_transport.connection_host(config, boot.HOST).password is not None):
        raise ValueError("Configured Arch transport is unavailable")
    program = _program(action, observation_correlation_id, expected_owner)
    argv = boot.ssh_transport.build_ssh_argv(
        config, boot.HOST, min(timeout_seconds, 30),
        command=("python3", "-c", "exec(" + repr(program) + ")"))
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout_seconds, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("Windows current-screen transport is unknown")
    value = json.loads(result.stdout)
    if (not isinstance(value, dict) or value.get("schemaVersion") != 1
            or value.get("observationCorrelationId") != observation_correlation_id
            or value.get("nativeActionAllowed") is not False
            or value.get("state") not in ("ready", "absent", "intent-only", "frame-uncertain", "observed", "unknown")):
        raise ValueError("Windows current-screen response is invalid")
    if value["state"] != "unknown" and value.get("owner") != dict(expected_owner):
        raise ValueError("Windows current-screen owner changed")
    allowed = {"preflight": {"ready"}, "start": {"observed", "unknown"},
               "status": {"absent", "intent-only", "frame-uncertain", "observed", "unknown"}}
    if value["state"] not in allowed[action]:
        raise ValueError("Windows current-screen state is invalid for action")
    if value["state"] == "ready" and value.get("previousPostSha256") != previous_post_sha256:
        raise ValueError("Windows current-screen previous frame changed")
    if value["state"] == "observed":
        frame = value.get("frame")
        if (not isinstance(frame, dict) or set(frame) != {"sha256", "width", "height", "sizeBytes"}
                or not isinstance(frame.get("sha256"), str) or not boot.SHA.fullmatch(frame["sha256"])
                or type(frame.get("width")) is not int or not 320 <= frame["width"] <= 3840
                or type(frame.get("height")) is not int or not 240 <= frame["height"] <= 2160
                or type(frame.get("sizeBytes")) is not int or not 64 <= frame["sizeBytes"] <= post.MAX_PPM):
            raise ValueError("Windows current-screen frame is invalid")
    return value


def preflight(root: str | Path, *, host: str, observation_correlation_id: str,
              timeout_seconds: int = 90) -> dict[str, Any]:
    prior = _check(root, host, observation_correlation_id, timeout_seconds)
    result = _remote_json(root, "preflight", observation_correlation_id,
                          prior["owner"], timeout_seconds, prior["frameHashes"]["after"])
    return {"observationCorrelationId": observation_correlation_id,
            "state": result["state"], "owner": result.get("owner"),
            "previousPostSha256": result.get("previousPostSha256"),
            "nativeActionAllowed": False, "replayAllowed": False}


def start(root: str | Path, *, host: str, observation_correlation_id: str,
          timeout_seconds: int = 90) -> dict[str, Any]:
    prior = _check(root, host, observation_correlation_id, timeout_seconds)
    path = _intent(root, create=True)
    try:
        boot._save(path, observation_correlation_id, _payload(observation_correlation_id))
    except FileExistsError as error:
        raise ValueError("Windows current-screen intent exists; use status") from error
    try:
        result = _remote_json(root, "start", observation_correlation_id,
                              prior["owner"], timeout_seconds, prior["frameHashes"]["after"])
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"observationCorrelationId": observation_correlation_id,
            "state": result["state"], "owner": result.get("owner"),
            "frame": result.get("frame"), "nativeActionAllowed": False,
            "replayAllowed": False}


def status(root: str | Path, *, host: str, observation_correlation_id: str,
           timeout_seconds: int = 60) -> dict[str, Any]:
    boot._check(host, observation_correlation_id, timeout_seconds)
    boot._read(_intent(root, create=False), observation_correlation_id,
               _payload(observation_correlation_id))
    prior = _check(root, host, observation_correlation_id, timeout_seconds)
    try:
        result = _remote_json(root, "status", observation_correlation_id,
                              prior["owner"], timeout_seconds, prior["frameHashes"]["after"])
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"observationCorrelationId": observation_correlation_id,
            "state": result["state"], "owner": result.get("owner"),
            "frame": result.get("frame"), "nativeActionAllowed": False,
            "replayAllowed": False}


def collect(root: str | Path, *, host: str, observation_correlation_id: str,
            timeout_seconds: int = 90) -> dict[str, Any]:
    boot._check(host, observation_correlation_id, timeout_seconds)
    observed = status(root, host=host, observation_correlation_id=observation_correlation_id,
                      timeout_seconds=timeout_seconds)
    if observed.get("state") != "observed" or not isinstance(observed.get("frame"), Mapping):
        raise ValueError("Windows current-screen frame is not sealed")
    with post._anchor(root, "attempt3-current-frame") as (directory, chain):
        leaf = "current-" + observation_correlation_id + ".png"
        try:
            os.stat(leaf, dir_fd=chain[-1][1], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("Windows current-screen local image already exists")
        try:
            raw = post._bounded_ssh(root, _program("collect", observation_correlation_id,
                                                   observed["owner"]), timeout_seconds)
            width, height, rgb = post._ppm(raw, observed["frame"]["sha256"])
            if (len(raw) != observed["frame"]["sizeBytes"] or width != observed["frame"]["width"]
                    or height != observed["frame"]["height"]):
                raise ValueError("Windows current-screen frame metadata changed")
            png = post._png(width, height, rgb)
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            return {"observationCorrelationId": observation_correlation_id,
                    "state": "unknown", "nativeActionAllowed": False, "replayAllowed": False}
        path = post._publish(directory, chain, observation_correlation_id, png, "current")
    return {"observationCorrelationId": observation_correlation_id,
            "state": "collected", "imagePath": str(path),
            "ppmSha256": hashlib.sha256(raw).hexdigest(),
            "pngSha256": hashlib.sha256(png).hexdigest(), "width": width,
            "height": height, "nativeActionAllowed": False, "replayAllowed": False}
