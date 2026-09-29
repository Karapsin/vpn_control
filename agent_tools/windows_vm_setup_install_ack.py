"""One-shot deletion acknowledgment on the disposable Windows installer.

The checkbox is visibly focused in the pinned prior frame. This sends exactly
one Space after fresh disk provenance and two exact pre-key captures.
"""
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
    from . import windows_vm_optical_current_screen as current
    from . import windows_vm_optical_post_collect as post
    from . import windows_vm_setup_install_focus as focus
except ImportError:
    import windows_vm_optical_boot as boot  # type: ignore[no-redef]
    import windows_vm_optical_current_screen as current  # type: ignore[no-redef]
    import windows_vm_optical_post_collect as post  # type: ignore[no-redef]
    import windows_vm_setup_install_focus as focus  # type: ignore[no-redef]


CURRENT_CORRELATION = "5af04161-b7ac-4788-8a75-090a3443a194"
SETUP_FRAME_SHA256 = "17fe2d580af8e429253c514fe1097dbdeb8298b879d02593ba0d2006468604ba"
HOLD_MS = 100
AFTER_DELAY_MS = 3000

_REMOTE = r'''
ACK_CORR=__ACK_CORR__;ACK_ACTION=__ACK_ACTION__;PREVIOUS_NEXT_CORR=__PREVIOUS_NEXT_CORR__
SETUP_FRAME_SHA=__SETUP_FRAME_SHA__;ACK_HOLD_MS=__ACK_HOLD_MS__;AFTER_DELAY_MS=__AFTER_DELAY_MS__
ACK_PHASE='source'
ACK_INTENT=GUEST+'/setup-install-ack-intent.json'
ACK_BEFORE=GUEST+'/setup-install-ack-before.json';ACK_KEY_INTENT=GUEST+'/setup-install-ack-key-intent.json'
ACK_KEY_ACK=GUEST+'/setup-install-ack-key-ack.json';ACK_AFTER=GUEST+'/setup-install-ack-after.json'
ACK_BEFORE_FRAME=GUEST+'/setup-install-ack-before-'+ACK_CORR+'.ppm'
ACK_CONFIRM_FRAME=GUEST+'/setup-install-ack-confirm-'+ACK_CORR+'.ppm'
ACK_AFTER_FRAME=GUEST+'/setup-install-ack-after-'+ACK_CORR+'.ppm'
def ack_source():
 global ACK_PHASE
 ACK_PHASE='prior'
 owner,media,disk,old=focus_source()
 previous=focus_status(owner,media,disk)
 if previous.get('state')!='after-observed' or previous.get('frame',{}).get('sha256')!=SETUP_FRAME_SHA:
  raise ValueError('install-focus-frame-not-sealed')
 ACK_PHASE='disk-proof'
 proof=install_disk_proof()
 if proof.get('state')!='ready' or proof.get('owner')!=owner or proof.get('historicalBlankDisk')!=disk:
  raise ValueError('install-disk-proof-unavailable')
 ACK_PHASE='owner'
 if claim()!=owner or not same_media(media):raise ValueError('setup-owner-changed')
 return owner,media,disk,proof
def ack_expected(owner,media,disk):
 return {'schemaVersion':1,'nextCorrelationId':ACK_CORR,'previousNextCorrelationId':PREVIOUS_NEXT_CORR,
         'attemptCorrelationId':CORR,'closureCorrelationId':EXPECTED_CLOSURE,
         'owner':owner,'media':media,'blankDisk':disk,'setupFrameSha256':SETUP_FRAME_SHA,
         'keyQcode':'spc','holdMs':ACK_HOLD_MS,'afterDelayMs':AFTER_DELAY_MS}
def ack_status(owner,media,disk):
 paths=(ACK_BEFORE,ACK_KEY_INTENT,ACK_KEY_ACK,ACK_AFTER)
 if not os.path.lexists(ACK_INTENT):
  if any(os.path.lexists(path) for path in paths+(ACK_BEFORE_FRAME,ACK_CONFIRM_FRAME,ACK_AFTER_FRAME)):
   raise ValueError('orphan-setup-evidence')
  return {'state':'absent'}
 if read(ACK_INTENT)!=ack_expected(owner,media,disk):raise ValueError('setup-intent-changed')
 present=[os.path.lexists(path) for path in paths]
 if any(present[i] and not all(present[:i]) for i in range(len(present))):raise ValueError('setup-receipt-order')
 hashes={}
 if present[0]:
  before=frame(ACK_BEFORE_FRAME,False)
  if before['sha256']!=SETUP_FRAME_SHA or read(ACK_BEFORE)!={'schemaVersion':1,'nextCorrelationId':ACK_CORR,
       'owner':owner,'frame':before}:raise ValueError('setup-before-changed')
  hashes['before']=before['sha256']
 elif os.path.lexists(ACK_BEFORE_FRAME):return {'state':'pre-frame-uncertain'}
 if present[1] and read(ACK_KEY_INTENT)!={'schemaVersion':1,'nextCorrelationId':ACK_CORR,'owner':owner,'phase':'key-intent'}:raise ValueError('setup-key-intent-changed')
 if not present[1] and os.path.lexists(ACK_CONFIRM_FRAME):raise ValueError('orphan-confirm-frame')
 if present[2]:
  confirm=frame(ACK_CONFIRM_FRAME,False)
  if confirm['sha256']!=SETUP_FRAME_SHA:raise ValueError('setup-confirm-frame-changed')
 if present[2] and read(ACK_KEY_ACK)!={'schemaVersion':1,'nextCorrelationId':ACK_CORR,'owner':owner,'phase':'key-ack'}:raise ValueError('setup-key-ack-changed')
 if present[3]:
  after=frame(ACK_AFTER_FRAME,False)
  if read(ACK_AFTER)!={'schemaVersion':1,'nextCorrelationId':ACK_CORR,'owner':owner,'frame':after}:raise ValueError('setup-after-changed')
  hashes['after']=after['sha256']
 elif os.path.lexists(ACK_AFTER_FRAME):return {'state':'post-frame-uncertain','frameHashes':hashes}
 return {'state':('intent-only','before-observed','key-uncertain','key-acknowledged','after-observed')[sum(present)],
         'frameHashes':hashes,'frame':after if present[3] else None}
try:
 owner,media,disk,old=ack_source()
 if ACK_ACTION=='preflight':
  ACK_PHASE='status'
  if ack_status(owner,media,disk)['state']!='absent':raise ValueError('setup-next-already-started')
  print(json.dumps({'schemaVersion':1,'nextCorrelationId':ACK_CORR,'state':'ready','owner':owner,
                    'setupFrameSha256':SETUP_FRAME_SHA,'nativeActionAllowed':False}))
 elif ACK_ACTION=='start':
  if ack_status(owner,media,disk)['state']!='absent':raise ValueError('setup-next-already-started')
  record(ACK_INTENT,ack_expected(owner,media,disk))
  sock,command=qmp_open(owner)
  try:
   if claim()!=owner or not same_media(media):raise ValueError('setup-owner-changed')
   before=frame(ACK_BEFORE_FRAME,True,command)
   if before['sha256']!=SETUP_FRAME_SHA:raise ValueError('setup-visible-frame-changed')
   record(ACK_BEFORE,{'schemaVersion':1,'nextCorrelationId':ACK_CORR,'owner':owner,'frame':before})
   if claim()!=owner or not same_media(media):raise ValueError('setup-owner-changed')
   record(ACK_KEY_INTENT,{'schemaVersion':1,'nextCorrelationId':ACK_CORR,'owner':owner,'phase':'key-intent'})
   confirm=frame(ACK_CONFIRM_FRAME,True,command)
   if confirm['sha256']!=SETUP_FRAME_SHA:raise ValueError('setup-visible-frame-changed-before-key')
   command('send-key',{'keys':[{'type':'qcode','data':'spc'}],'hold-time':ACK_HOLD_MS})
   record(ACK_KEY_ACK,{'schemaVersion':1,'nextCorrelationId':ACK_CORR,'owner':owner,'phase':'key-ack'})
   until=time.monotonic()+AFTER_DELAY_MS/1000
   while time.monotonic()<until:time.sleep(min(.1,until-time.monotonic()))
   if claim()!=owner or not same_media(media):raise ValueError('setup-owner-changed')
   after=frame(ACK_AFTER_FRAME,True,command)
   record(ACK_AFTER,{'schemaVersion':1,'nextCorrelationId':ACK_CORR,'owner':owner,'frame':after})
  finally:sock.close()
  print(json.dumps({'schemaVersion':1,'nextCorrelationId':ACK_CORR,'state':'after-observed','owner':owner,
                    'frameHashes':{'before':before['sha256'],'after':after['sha256']},
                    'frame':after,'nativeActionAllowed':False}))
 elif ACK_ACTION=='status':
  state=ack_status(owner,media,disk)
  if claim()!=owner:raise ValueError('setup-owner-changed')
  print(json.dumps({'schemaVersion':1,'nextCorrelationId':ACK_CORR,**state,'owner':owner,'nativeActionAllowed':False}))
 elif ACK_ACTION=='collect':
  state=ack_status(owner,media,disk)
  if state['state']!='after-observed':raise ValueError('setup-after-not-sealed')
  sealed=state['frame'];fd=os.open(ACK_AFTER_FRAME,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
  try:
   before=os.fstat(fd);raw=os.read(fd,8388609);later=os.fstat(fd);named=os.stat(ACK_AFTER_FRAME,follow_symlinks=False)
   keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
   if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or
       len(raw)!=sealed['sizeBytes'] or hashlib.sha256(raw).hexdigest()!=sealed['sha256'] or
       any(getattr(before,k)!=getattr(later,k) or getattr(before,k)!=getattr(named,k) for k in keys)):
    raise ValueError('setup-after-frame-changed')
  finally:os.close(fd)
  if claim()!=owner or not same_media(media):raise ValueError('setup-owner-changed')
  write_all(1,raw)
 else:raise ValueError('invalid-next-action')
except Exception as error:
 if ACK_ACTION=='collect':raise SystemExit(3)
 allowed={'install-focus-frame-not-sealed','install-disk-proof-unavailable','setup-owner-changed',
          'setup-next-already-started','setup-intent-changed','orphan-setup-evidence'}
 reason=str(error) if isinstance(error,ValueError) and str(error) in allowed else type(error).__name__
 print(json.dumps({'schemaVersion':1,'nextCorrelationId':ACK_CORR,'state':'unknown',
                   'phase':ACK_PHASE,'reason':reason,'nativeActionAllowed':False}))
'''


def _program(action: str, next_correlation_id: str,
             expected_owner: Mapping[str, int] | None = None) -> str:
    if action not in ("preflight", "start", "status", "collect"):
        raise ValueError("Windows install acknowledgment action is not fixed")
    base = focus._program("status", CURRENT_CORRELATION, expected_owner)
    prefix = base.split("\ntry:\n owner,media,disk,old=focus_source()", 1)[0]
    if prefix == base:
        raise ValueError("Windows install focus has no fixed boundary")
    # The prior focus receipt keeps its own predecessor and screen pin.
    prefix = prefix.replace("PREVIOUS_NEXT_CORR", "FOCUS_PREVIOUS_NEXT_CORR")
    prefix = prefix.replace("SETUP_FRAME_SHA", "FOCUS_SETUP_FRAME_SHA")
    tail = _REMOTE
    for key, value in {"ACK_CORR": next_correlation_id, "ACK_ACTION": action,
                       "PREVIOUS_NEXT_CORR": CURRENT_CORRELATION,
                       "SETUP_FRAME_SHA": SETUP_FRAME_SHA256,
                       "ACK_HOLD_MS": HOLD_MS, "AFTER_DELAY_MS": AFTER_DELAY_MS}.items():
        tail = tail.replace("__" + key + "__", repr(value))
    return prefix + tail


def _check(root: str | Path, host: str, next_correlation_id: str,
           timeout_seconds: int) -> dict[str, Any]:
    boot._check(host, next_correlation_id, timeout_seconds)
    if next_correlation_id in (boot.FIRST_CORRELATION, boot.FIRST_CLOSURE,
                                  boot.SECOND_CORRELATION, current.ATTEMPT_CORRELATION,
                                  current.CLOSURE_CORRELATION, CURRENT_CORRELATION):
        raise ValueError("Windows Setup Next needs a new correlation")
    observed = focus.status(root, host=host, next_correlation_id=CURRENT_CORRELATION,
                            timeout_seconds=timeout_seconds)
    if (observed.get("state") != "after-observed" or not isinstance(observed.get("owner"), Mapping)
            or not isinstance(observed.get("frame"), Mapping)
            or observed["frame"].get("sha256") != SETUP_FRAME_SHA256):
        raise ValueError("Windows install checkbox focus is not sealed")
    return observed


def _intent(root: str | Path, create: bool) -> Path:
    base = Path(root).resolve() / ".rag_index"
    directory = base / "windows-vm-setup-install-ack"
    if create:
        base.mkdir(mode=0o700, exist_ok=True)
        directory.mkdir(mode=0o700, exist_ok=True)
    for path in (base, directory):
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError("Windows install acknowledgment journal is unsafe")
    return directory / "intent.json"


def _payload(next_correlation_id: str) -> dict[str, Any]:
    return {"schemaVersion": 1, "host": boot.HOST,
            "nextCorrelationId": next_correlation_id,
            "previousNextCorrelationId": CURRENT_CORRELATION,
            "focusedCheckboxFrameSha256": SETUP_FRAME_SHA256,
            "attemptCorrelationId": current.ATTEMPT_CORRELATION,
            "closureCorrelationId": current.CLOSURE_CORRELATION,
            "guest": boot.setup.GUEST, "windowsSha256": boot.setup.WINDOWS_SHA256,
            "keyQcode": "spc", "holdMs": HOLD_MS, "afterDelayMs": AFTER_DELAY_MS}


def _remote_json(root: str | Path, action: str, next_correlation_id: str,
                 expected_owner: Mapping[str, int], timeout_seconds: int) -> dict[str, Any]:
    config = boot.ssh_transport.load_config(root)
    if (boot.HOST not in config.hosts
            or boot.ssh_transport.connection_host(config, boot.HOST).password is not None):
        raise ValueError("Configured Arch transport is unavailable")
    program = _program(action, next_correlation_id, expected_owner)
    argv = boot.ssh_transport.build_ssh_argv(config, boot.HOST, min(timeout_seconds, 30),
                                              command=("python3", "-c", "exec(" + repr(program) + ")"))
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout_seconds, check=False)
    if result.returncode != 0 or len(result.stdout) > 4096:
        raise ValueError("Windows Setup Next transport is unknown")
    value = json.loads(result.stdout)
    allowed = {"preflight": {"ready", "unknown"}, "start": {"after-observed", "unknown"},
               "status": {"absent", "intent-only", "pre-frame-uncertain", "before-observed",
                          "key-uncertain", "key-acknowledged", "post-frame-uncertain", "after-observed", "unknown"}}
    if (not isinstance(value, dict) or value.get("schemaVersion") != 1
            or value.get("nextCorrelationId") != next_correlation_id
            or value.get("nativeActionAllowed") is not False
            or value.get("state") not in allowed[action]):
        raise ValueError("Windows Setup Next response is invalid")
    if value["state"] == "unknown" and (value.get("phase") not in
            ("source", "prior", "disk-proof", "owner", "status")
            or not isinstance(value.get("reason"), str) or not 1 <= len(value["reason"]) <= 64):
        raise ValueError("Windows install focus diagnostic is invalid")
    if value["state"] != "unknown" and value.get("owner") != dict(expected_owner):
        raise ValueError("Windows Setup Next owner changed")
    if value["state"] == "ready" and value.get("setupFrameSha256") != SETUP_FRAME_SHA256:
        raise ValueError("Windows Setup Next input frame changed")
    if value["state"] == "after-observed":
        frame = value.get("frame")
        if (not isinstance(frame, dict) or set(frame) != {"sha256", "width", "height", "sizeBytes"}
                or not isinstance(frame.get("sha256"), str) or not boot.SHA.fullmatch(frame["sha256"])
                or type(frame.get("width")) is not int or not 320 <= frame["width"] <= 3840
                or type(frame.get("height")) is not int or not 240 <= frame["height"] <= 2160
                or type(frame.get("sizeBytes")) is not int or not 64 <= frame["sizeBytes"] <= post.MAX_PPM):
            raise ValueError("Windows Setup Next output frame is invalid")
    return value


def preflight(root: str | Path, *, host: str, next_correlation_id: str,
              timeout_seconds: int = 90) -> dict[str, Any]:
    prior = _check(root, host, next_correlation_id, timeout_seconds)
    result = _remote_json(root, "preflight", next_correlation_id,
                          prior["owner"], timeout_seconds)
    return {"nextCorrelationId": next_correlation_id, "state": result["state"],
            "owner": result.get("owner"), "setupFrameSha256": result.get("setupFrameSha256"),
            "phase": result.get("phase"), "reason": result.get("reason"),
            "nativeActionAllowed": False, "replayAllowed": False}


def start(root: str | Path, *, host: str, next_correlation_id: str,
          timeout_seconds: int = 90) -> dict[str, Any]:
    prior = _check(root, host, next_correlation_id, timeout_seconds)
    path = _intent(root, create=True)
    try:
        boot._save(path, next_correlation_id, _payload(next_correlation_id))
    except FileExistsError as error:
        raise ValueError("Windows Setup Next intent exists; use status") from error
    try:
        result = _remote_json(root, "start", next_correlation_id,
                              prior["owner"], timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"nextCorrelationId": next_correlation_id, "state": result["state"],
            "owner": result.get("owner"), "frame": result.get("frame"),
            "frameHashes": result.get("frameHashes"),
            "nativeActionAllowed": False, "replayAllowed": False}


def status(root: str | Path, *, host: str, next_correlation_id: str,
           timeout_seconds: int = 60) -> dict[str, Any]:
    boot._check(host, next_correlation_id, timeout_seconds)
    boot._read(_intent(root, create=False), next_correlation_id,
               _payload(next_correlation_id))
    prior = _check(root, host, next_correlation_id, timeout_seconds)
    try:
        result = _remote_json(root, "status", next_correlation_id,
                              prior["owner"], timeout_seconds)
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError):
        result = {"state": "unknown"}
    return {"nextCorrelationId": next_correlation_id, "state": result["state"],
            "owner": result.get("owner"), "frame": result.get("frame"),
            "frameHashes": result.get("frameHashes"),
            "nativeActionAllowed": False, "replayAllowed": False}


def collect(root: str | Path, *, host: str, next_correlation_id: str,
            timeout_seconds: int = 90) -> dict[str, Any]:
    boot._check(host, next_correlation_id, timeout_seconds)
    observed = status(root, host=host, next_correlation_id=next_correlation_id,
                      timeout_seconds=timeout_seconds)
    if observed.get("state") != "after-observed" or not isinstance(observed.get("frame"), Mapping):
        raise ValueError("Windows Setup Next output frame is not sealed")
    with post._anchor(root, "attempt3-current-frame") as (directory, chain):
        leaf = "current-" + next_correlation_id + ".png"
        try:
            os.stat(leaf, dir_fd=chain[-1][1], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("Windows Setup Next local image already exists")
        try:
            raw = post._bounded_ssh(root, _program("collect", next_correlation_id,
                                                   observed["owner"]), timeout_seconds)
            width, height, rgb = post._ppm(raw, observed["frame"]["sha256"])
            if (len(raw) != observed["frame"]["sizeBytes"] or width != observed["frame"]["width"]
                    or height != observed["frame"]["height"]):
                raise ValueError("Windows Setup Next output metadata changed")
            png = post._png(width, height, rgb)
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            return {"nextCorrelationId": next_correlation_id,
                    "state": "unknown", "nativeActionAllowed": False, "replayAllowed": False}
        path = post._publish(directory, chain, next_correlation_id, png, "current")
    return {"nextCorrelationId": next_correlation_id, "state": "collected", "imagePath": str(path),
            "ppmSha256": hashlib.sha256(raw).hexdigest(), "pngSha256": hashlib.sha256(png).hexdigest(),
            "width": width, "height": height, "nativeActionAllowed": False, "replayAllowed": False}
