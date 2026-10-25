"""Read-only, fixed Arch sudo eligibility probe for the virt-firmware dependency."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

from . import ssh_transport


HOST = "archlinux"
_UNKNOWN = {"state": "unknown", "nativeActionAllowed": False}

_REMOTE = r'''import json,os,re,stat,subprocess
def emit(state):
 print(json.dumps({'schemaVersion':1,'host':'archlinux','state':state},separators=(',',':'),sort_keys=True))
def executable(path):
 try:
  info=os.lstat(path)
  return stat.S_ISREG(info.st_mode) and os.access(path,os.X_OK)
 except OSError:return False
try:
 if not executable('/usr/bin/pacman') or not executable('/usr/bin/sudo'):
  emit('command-unavailable')
 else:
  result=subprocess.run(['/usr/bin/sudo','-n','-l'],
   stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
   env={**os.environ,'LC_ALL':'C','LANG':'C','SUDO_ASKPASS':'/bin/false'},
   timeout=5,check=False)
  if len(result.stdout)>8192 or len(result.stderr)>8192:
   emit('unknown')
  elif result.returncode==0:
   output=result.stdout.decode('utf-8','strict')
   # An unfiltered sudo listing shows rule tags. A command-filtered listing
   # normally prints only the path, so it cannot prove NOPASSWD semantics.
   # Require one exact root rule with unrestricted pacman arguments.
   specs=[line for line in output.splitlines() if re.search(r'\([^)]*\)\s+',line)]
   canonical=re.fullmatch(r'\s*\(root\)\s+NOPASSWD:\s+/usr/bin/pacman\s*',specs[0]) if len(specs)==1 else None
   pacman_lines=[line for line in output.splitlines() if '/usr/bin/pacman' in line]
   emit('sudo-nopasswd-pacman' if canonical and len(pacman_lines)==1 else 'sudo-listing-inconclusive')
  elif result.returncode==1:emit('sudo-unavailable-or-auth-required')
  else:emit('unknown')
except Exception:emit('unknown')
'''


def _request(value: Mapping[str, Any]) -> int:
    if (not isinstance(value, Mapping) or set(value) != {"host", "timeoutSeconds"}
            or value.get("host") != HOST or type(value.get("timeoutSeconds")) is not int
            or not 10 <= value["timeoutSeconds"] <= 30):
        raise ValueError("Arch dependency admission requires exact host and bounded timeout.")
    return value["timeoutSeconds"]


def classify(value: Mapping[str, Any]) -> dict[str, Any]:
    states = {"command-unavailable", "sudo-nopasswd-pacman", "sudo-listing-inconclusive",
              "sudo-unavailable-or-auth-required", "unknown"}
    if (not isinstance(value, Mapping) or set(value) != {"schemaVersion", "host", "state"}
            or type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1
            or value.get("host") != HOST or value.get("state") not in states):
        return dict(_UNKNOWN)
    return {"state": value["state"], "host": HOST,
            "noninteractivePacmanEligible": value["state"] == "sudo-nopasswd-pacman",
            "nativeActionAllowed": False}


def observe(root: str | Path, value: Mapping[str, Any]) -> dict[str, Any]:
    timeout = _request(value)
    config = ssh_transport.load_config(Path(root).resolve(strict=True))
    if HOST not in config.hosts or ssh_transport.connection_host(config, HOST).password is not None:
        raise ValueError("Configured Arch transport is unavailable.")
    command = ("python3", "-c", "exec(" + repr(_REMOTE) + ")")
    argv = ssh_transport.build_ssh_argv(config, HOST, min(timeout, 20), command=command)
    try:
        completed = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return dict(_UNKNOWN)
    if completed.returncode != 0 or not 0 < len(completed.stdout) <= 1024:
        return dict(_UNKNOWN)
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, ValueError):
        return dict(_UNKNOWN)
    return classify(payload)
