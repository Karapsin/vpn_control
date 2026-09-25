"""Bounded, read-only Linux host memory and QEMU identity observation.

The observer sends one fixed Python program through the reviewed SSH transport.
It never accepts a remote command from a caller and reports only small, typed
facts; command lines, environment values, network addresses, and credentials
are intentionally absent from its receipt.
"""
from __future__ import annotations

import json
import math
import os
from pathlib import Path
import re
import select
import subprocess
import time
from typing import Any, Mapping

try:
    from . import ssh_transport
except ImportError:  # pragma: no cover - standalone MCP fallback
    import ssh_transport  # type: ignore[no-redef]


_MAX_TIMEOUT_SECONDS = 30
_MAX_OUTPUT_BYTES = 32_768
_IDENTITY_FIELDS = {"pid", "startTicks"}

# This is deliberately a closed program: only its fixed source and a bounded
# sample delay are passed to the remote Python interpreter.  ``/proc`` is read
# directly, avoiding shell, ps, and arbitrary command execution.  It emits no
# command line, only QEMU's executable basename and typed process facts.
_REMOTE_PROGRAM = r'''import json,os,sys,time
def stat(pid):
 try:
  raw=open("/proc/%d/stat"%pid,"r",encoding="ascii").read()
  tail=raw.rsplit(")",1)[1].split()
  return int(tail[19])
 except (OSError,ValueError,IndexError,UnicodeError): return None
def memory():
 data={}
 try:
  for line in open("/proc/meminfo","r",encoding="ascii"):
   key,value=line.split(":",1); data[key]=int(value.split()[0])*1024
  vm={}
  for line in open("/proc/vmstat","r",encoding="ascii"):
   key,value=line.split();
   if key in ("pswpin","pswpout","oom_kill"): vm[key]=int(value)
  psi={}
  for line in open("/proc/pressure/memory","r",encoding="ascii"):
   fields=line.split(); kind=fields[0]
   if kind in ("some","full"):
    avg10=[field[6:] for field in fields[1:] if field.startswith("avg10=")]
    if len(avg10)!=1: raise ValueError("missing PSI average")
    psi[kind]=float(avg10[0])
  if set(psi)!={"some","full"}: raise ValueError("incomplete PSI")
  pressure="normal" if psi["full"]==0.0 and psi["some"]<=1.0 else "warning"
  return {"observedAtUnixMs":time.time_ns()//1000000,"availableMemoryBytes":data["MemAvailable"],"psi":pressure,"psiSomeAvg10":psi["some"],"psiFullAvg10":psi["full"],"vmstat":{"pswpin":vm["pswpin"],"pswpout":vm["pswpout"],"oomKill":vm["oom_kill"]}},data["MemTotal"],data.get("SwapTotal",0)-data.get("SwapFree",0)
 except (OSError,ValueError,KeyError,UnicodeError): return None,None,None
def parse_memory(argv):
 values=[]
 for index,item in enumerate(argv):
  if item==b"-m":
   if index+1>=len(argv): return None
   values.append((b"qemu",argv[index+1]))
  elif item.startswith(b"-m="): values.append((b"qemu",item[3:]))
  elif item.startswith(b"-m") and len(item)>2 and item[2:3].isdigit(): values.append((b"qemu",item[2:]))
  elif item==b"-memory":
   if index+1>=len(argv): return None
   values.append((b"android",argv[index+1]))
  elif item.startswith(b"-memory="): return None
 if len(values)!=1: return None
 kind,value=values[0]
 try:
  text=value.decode("ascii").upper()
  if kind==b"android":
   if not text.isdigit() or int(text)<=0: return None
   return int(text)*1048576
  suffix=text[-1:] if text[-1:] in ("K","M","G","T") else ""
  number=text[:-1] if suffix else text
  if not number.isdigit() or int(number)<=0: return None
  return int(number)*{"":1048576,"K":1024,"M":1048576,"G":1073741824,"T":1099511627776}[suffix]
 except (UnicodeError,ValueError): return None
if not sys.platform.startswith("linux") or not os.path.isdir("/proc"):
 print(json.dumps({"state":"unsupported_linux"},separators=(",",":"))); raise SystemExit(0)
first,physical,swap=memory(); time.sleep(.05); last,physical_last,swap_last=memory()
if first is None or last is None or physical!=physical_last:
 print(json.dumps({"state":"unknown"},separators=(",",":"))); raise SystemExit(0)
vms=[]
inventory_complete=True
try: entries=os.listdir("/proc")
except OSError: entries=[]; inventory_complete=False
for entry in entries:
 if not entry.isdigit(): continue
 pid=int(entry); ticks=stat(pid)
 if ticks is None: continue
 try:
  comm=open("/proc/%d/comm"%pid,"r",encoding="ascii").read().strip()
 except (OSError,UnicodeError):
  if stat(pid) is not None: inventory_complete=False
  continue
 if not comm.startswith("qemu-system-"): continue
 executable=None; configured=None
 try:
  candidate=os.path.basename(os.readlink("/proc/%d/exe"%pid))
  if candidate.startswith("qemu-system-"): executable=candidate
  else: inventory_complete=False
 except (OSError,UnicodeError): inventory_complete=False
 try:
  raw=open("/proc/%d/cmdline"%pid,"rb").read(16385)
  if raw and len(raw)<=16384: configured=parse_memory(raw.rstrip(b"\0").split(b"\0"))
  else: inventory_complete=False
 except OSError: inventory_complete=False
 try:
  # Re-read the generation after cmdline so a PID reuse never receives the
  # executable or allocation observed for a different process generation.
  if ticks is not None and stat(pid)==ticks: vms.append({"pid":pid,"startTicks":ticks,"qemuExecutable":executable,"configuredMemoryBytes":configured})
  elif stat(pid) is not None: inventory_complete=False
 except OSError: inventory_complete=False
result={"state":"observed","physicalMemoryBytes":physical,"swapUsedBytes":swap_last,"samples":[first,last],"vms":vms,"inventoryComplete":inventory_complete}
print(json.dumps(result,separators=(",",":")))'''
_REMOTE_ARGUMENT = "exec(" + repr(_REMOTE_PROGRAM) + ")"


class NativeHostObservationError(ValueError):
    """The caller supplied an unsafe host observation request."""


def _identity(value: Mapping[str, Any] | None) -> dict[str, int] | None:
    if value is None:
        return None
    if not isinstance(value, Mapping) or set(value) != _IDENTITY_FIELDS:
        raise NativeHostObservationError("VM identity must contain only pid and startTicks")
    result: dict[str, int] = {}
    for key in _IDENTITY_FIELDS:
        item = value[key]
        if isinstance(item, bool) or not isinstance(item, int) or item < 1:
            raise NativeHostObservationError("VM identity fields must be positive integers")
        result[key] = item
    return result


def _unknown(timestamp: int, reason: str, *, timeout: int) -> dict[str, Any]:
    return {"state": "UNKNOWN", "ready": False, "nativeActionAllowed": False,
            "source": "live-linux-host", "observedAtUnixMs": timestamp,
            "timeoutSeconds": timeout, "reason": reason, "measurement": None}


def _measurement(payload: Mapping[str, Any], timestamp: int, identity: dict[str, int] | None, timeout: int) -> dict[str, Any]:
    if payload.get("state") == "unsupported_linux":
        return _unknown(timestamp, "unsupported_linux", timeout=timeout)
    if payload.get("state") != "observed":
        return _unknown(timestamp, "observer_failed", timeout=timeout)
    physical, swap, samples, vms, inventory_complete = (payload.get("physicalMemoryBytes"), payload.get("swapUsedBytes"),
                                                         payload.get("samples"), payload.get("vms"), payload.get("inventoryComplete"))
    if (isinstance(physical, bool) or not isinstance(physical, int) or physical <= 0 or
            isinstance(swap, bool) or not isinstance(swap, int) or swap < 0 or
            not isinstance(samples, list) or len(samples) != 2 or not isinstance(vms, list) or not isinstance(inventory_complete, bool)):
        return _unknown(timestamp, "malformed_probe_output", timeout=timeout)
    parsed_samples: list[dict[str, Any]] = []
    for item in samples:
        if not isinstance(item, Mapping): return _unknown(timestamp, "malformed_probe_output", timeout=timeout)
        observed, available, psi, vmstat = item.get("observedAtUnixMs"), item.get("availableMemoryBytes"), item.get("psi"), item.get("vmstat")
        some, full = item.get("psiSomeAvg10"), item.get("psiFullAvg10")
        if (isinstance(observed, bool) or not isinstance(observed, int) or observed <= 0 or
                isinstance(available, bool) or not isinstance(available, int) or available < 0 or
                psi not in {"normal", "warning"} or not isinstance(vmstat, Mapping) or
                isinstance(some, bool) or not isinstance(some, (int, float)) or not math.isfinite(some) or some < 0 or
                isinstance(full, bool) or not isinstance(full, (int, float)) or not math.isfinite(full) or full < 0 or
                psi != ("normal" if full == 0 and some <= 1 else "warning")):
            return _unknown(timestamp, "malformed_probe_output", timeout=timeout)
        counters = {"pswpin": vmstat.get("pswpin"), "pswpout": vmstat.get("pswpout"), "oomKill": vmstat.get("oomKill")}
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counters.values()):
            return _unknown(timestamp, "malformed_probe_output", timeout=timeout)
        parsed_samples.append({"observedAtUnixMs": observed, "availableMemoryBytes": available, "psi": psi,
                               "psiSomeAvg10": some, "psiFullAvg10": full, "vmstat": counters})
    parsed_vms: list[dict[str, Any]] = []
    complete = True
    for item in vms:
        if not isinstance(item, Mapping): return _unknown(timestamp, "malformed_probe_output", timeout=timeout)
        pid, ticks, executable, configured = item.get("pid"), item.get("startTicks"), item.get("qemuExecutable"), item.get("configuredMemoryBytes")
        if (isinstance(pid, bool) or not isinstance(pid, int) or pid < 1 or isinstance(ticks, bool) or not isinstance(ticks, int) or ticks < 1 or
                (executable is not None and (not isinstance(executable, str) or not re.fullmatch(r"qemu-system-[A-Za-z0-9_.-]+", executable)))):
            return _unknown(timestamp, "malformed_probe_output", timeout=timeout)
        if isinstance(configured, bool) or (configured is not None and (not isinstance(configured, int) or configured <= 0)):
            return _unknown(timestamp, "malformed_probe_output", timeout=timeout)
        complete = complete and configured is not None and executable is not None
        parsed_vms.append({"pid": pid, "startTicks": ticks, "qemuExecutable": executable, "configuredMemoryBytes": configured})
    complete = complete and inventory_complete
    matched = None
    if identity is not None:
        matched = next((item for item in parsed_vms if item["pid"] == identity["pid"] and item["startTicks"] == identity["startTicks"] and item["qemuExecutable"] is not None), None)
    pressure = "normal" if all(item["psi"] == "normal" for item in parsed_samples) else "warning"
    # Keep raw memory facts visible even when a QEMU allocation cannot be
    # determined.  ``measurement`` is withheld in that case so callers cannot
    # accidentally feed an incomplete value to ``vm_workflow.admit_plan``.
    memory = {"platform": "linux", "physicalMemoryBytes": physical,
              "availableMemoryBytes": parsed_samples[-1]["availableMemoryBytes"], "swapUsedBytes": swap,
              "pressure": pressure, "samples": parsed_samples}
    measurement = dict(memory)
    if complete:
        measurement["runningConfiguredMemoryBytes"] = sum(item["configuredMemoryBytes"] for item in parsed_vms)
    return {"state": "OBSERVED" if complete else "UNKNOWN", "ready": False,
            "nativeActionAllowed": False, "source": "live-linux-host", "observedAtUnixMs": parsed_samples[-1]["observedAtUnixMs"],
            "timeoutSeconds": timeout, "reason": "complete_measurement" if complete else "unknown_qemu_memory",
            "measurementAvailability": "complete" if complete else "unknown", "memory": memory,
            "measurement": measurement if complete else None, "vms": parsed_vms,
            "vmIdentity": {"state": "matched" if matched else "unknown", "vm": matched} if identity else None}


def _run(argv: list[str], timeout_seconds: int) -> bytes:
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as error:
        raise RuntimeError("ssh_unavailable") from error
    assert process.stdout is not None
    chunks: list[bytes] = []; received = 0; deadline = time.monotonic() + timeout_seconds + 1
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise RuntimeError("timeout")
            ready, _, _ = select.select([process.stdout], [], [], remaining)
            if ready:
                chunk = os.read(process.stdout.fileno(), min(4096, _MAX_OUTPUT_BYTES + 1 - received))
                if chunk:
                    chunks.append(chunk); received += len(chunk)
                    if received > _MAX_OUTPUT_BYTES: raise RuntimeError("oversized_probe_output")
                    continue
                if process.poll() is not None:
                    if process.returncode != 0: raise RuntimeError("observer_failed")
                    return b"".join(chunks)
    finally:
        if process.poll() is None:
            process.kill(); process.wait()
        process.stdout.close()


def observe_host(root: Path | str, host_alias: str, timeout_seconds: int, vm_identity: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Return a fresh two-sample Linux receipt; this performs no admission or action."""
    identity = _identity(vm_identity)
    timestamp = time.time_ns() // 1_000_000
    if os.name != "posix":
        return _unknown(timestamp, "unsupported_platform", timeout=timeout_seconds if isinstance(timeout_seconds, int) else 0)
    if not isinstance(host_alias, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", host_alias):
        raise NativeHostObservationError("host alias is invalid")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= _MAX_TIMEOUT_SECONDS:
        raise NativeHostObservationError("timeoutSeconds must be between 1 and 30")
    try:
        config = ssh_transport.load_config(root)
        target = config.hosts.get(host_alias)
        if target is None or ssh_transport.connection_host(config, host_alias).password is not None:
            return _unknown(timestamp, "transport_unavailable", timeout=timeout_seconds)
        argv = ssh_transport.build_ssh_argv(config, host_alias, timeout_seconds, command=("python3", "-c", _REMOTE_ARGUMENT))
        output = _run(argv, timeout_seconds)
        return _measurement(json.loads(output.decode("utf-8")), timestamp, identity, timeout_seconds)
    except (ssh_transport.SshConfigError, OSError, RuntimeError, UnicodeError, ValueError, json.JSONDecodeError):
        return _unknown(timestamp, "observer_failed", timeout=timeout_seconds)
