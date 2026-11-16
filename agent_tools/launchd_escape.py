#!/usr/bin/env python3
"""Run an opted-in local check under launchd instead of the caller's background-priority tree.

On macOS a process started from the agent-session tmux tree inherits Darwin
background priority (ps pri 4). CPU-bound agent tests then run 5-7x slower and
sleeps overshoot, and no per-process option (taskpolicy, nice, launchctl asuser,
setpriority) lifts it. A job bootstrapped into the user's `gui/<uid>` domain is a
child of launchd and runs at the normal priority, with no sudo and no system change.

`managed_agent_check.background_escape(command)` returns
`[python, this_file, "relay", "--bound", N, "--", *command]` for the opted-in
commands on macOS and the unchanged command otherwise (this file stays
import-free so it is only ever run, never imported). The relay keeps the Popen
contract of the original command:

- one run: the job is a plist with RunAtLoad and KeepAlive=false, so launchd never
  restarts it; `job.sh` also claims a no-clobber `started` marker, and the relay's
  direct fallback after a failed bootstrap must claim the same marker first, so
  the command can never run both as the job and directly;
- the caller's exact environment (`env -i` plus every caller variable) and soft
  resource limits (nofile, nproc, core, stack via SoftResourceLimits), its cwd,
  stdout/stderr relayed, exit status returned, SIGTERM forwarded;
- a job that ends without writing its exit status returns 137 within seconds;
- no leftover label: the relay boots the job out, the job boots itself out when it
  finishes (also after the relay was SIGKILLed: its watchdog stops the command),
  and every relay start sweeps `vpncontrol.check.*` labels whose relay is gone or
  whose bound has passed.

VPN_CONTROL_LAUNCHD_ESCAPE=0 disables it.
"""
from __future__ import annotations

import os
import plistlib
import re
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

INSIDE_VARIABLE = "VPN_CONTROL_LAUNCHD_ESCAPED"
LABEL_PREFIX = "vpncontrol.check."
# vpncontrol.check.<deadline epoch>.<relay pid>.<random>; the bound travels in the label for the sweep.
LABEL_RE = re.compile(r"vpncontrol\.check\.(\d+)\.(\d+)\.[0-9a-f]{8}")
# Labels of the earlier `launchctl submit` relay: vpncontrol.check.<relay pid>.<random>.
LEGACY_LABEL_RE = re.compile(r"vpncontrol\.check\.(\d+)\.[0-9a-f]{8}")
TERM_GRACE_SECONDS = 40
DEFAULT_BOUND_SECONDS = 3 * 60 * 60
STARTUP_SECONDS = 30.0
POLL_SECONDS = 0.2
STATE_SECONDS = 1.0
LOST_STATUS = 137
LIMITS = (("NumberOfFiles", "RLIMIT_NOFILE"), ("NumberOfProcesses", "RLIMIT_NPROC"),
          ("Core", "RLIMIT_CORE"), ("Stack", "RLIMIT_STACK"))


def _launchctl() -> str:
    return shutil.which("launchctl") or "/bin/launchctl"


def _domain() -> str:
    return f"gui/{os.getuid()}"


def _soft_limits() -> dict[str, int]:
    limits = {}
    for key, name in LIMITS:
        soft = resource.getrlimit(getattr(resource, name))[0]
        limits[key] = min(int(soft), 0x7FFFFFFFFFFFFFFF)
    return limits


def _script(argv, cwd, env, directory: Path, label: str, relay_pid: int, launchctl: str = "/bin/launchctl") -> str:
    q = shlex.quote
    target = q(f"{_domain()}/{label}")
    started, rc, rc_tmp = (q(str(directory / name)) for name in ("started", "rc", "rc.tmp"))
    # `env -i` plus every caller variable: launchd's own SSH_AUTH_SOCK, XPC_* and PATH never reach the command.
    assignments = " ".join(q(f"{k}={v}") for k, v in env.items() if k and "=" not in k and "\0" not in k + v)
    marker = q(f"{INSIDE_VARIABLE}=1")
    return f"""#!/bin/bash
remove() {{ {q(launchctl)} bootout {target} >/dev/null 2>&1; }}
write_rc() {{ echo "$1" > {rc_tmp} && /bin/mv -f {rc_tmp} {rc}; }}
# Only the first start runs the command. A later start, or one after the relay claimed the marker for its
# direct fallback, never reruns it nor touches its outputs; a run that left no exit status reports 137.
if ! ( set -C; : > {started} ) 2>/dev/null; then
  [ -e {rc} ] || write_rc {LOST_STATUS}
  remove
  exit 0
fi
cd {q(cwd)} || {{ write_rc 126; remove; exit 126; }}
exec >{q(str(directory / 'out'))} 2>{q(str(directory / 'err'))} </dev/null
/usr/bin/env -i {assignments} {marker} {shlex.join(argv)} &
child=$!
trap 'kill -TERM $child 2>/dev/null' TERM INT HUP
# The relay is gone (even SIGKILLed): stop the command, then the job removes itself below.
( while kill -0 {relay_pid} 2>/dev/null; do /bin/sleep 1; done
  kill -TERM $child 2>/dev/null; /bin/sleep {TERM_GRACE_SECONDS}; kill -KILL $child 2>/dev/null ) &
watchdog=$!
wait $child; rc=$?
while kill -0 $child 2>/dev/null; do wait $child; rc=$?; done
kill $watchdog 2>/dev/null
write_rc $rc
trap - TERM INT HUP
remove
exit 0
"""


def _plist(label: str, script: Path) -> bytes:
    return plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/env", "-i", "/bin/bash", "--noprofile", "--norc", str(script)],
        "WorkingDirectory": "/",
        "RunAtLoad": True,
        "KeepAlive": False,
        "ExitTimeOut": TERM_GRACE_SECONDS,
        "SoftResourceLimits": _soft_limits(),
        "ProcessType": "Standard",
    })


def _pump(path: Path, offset: int, sink) -> int:
    try:
        with open(path, "rb") as handle:
            handle.seek(offset)
            data = handle.read()
    except FileNotFoundError:
        return offset
    if data:
        sink.write(data)
        sink.flush()
    return offset + len(data)


def _claim(directory: Path) -> bool:
    """Take the single-run marker for the relay; False once the job has it."""
    try:
        os.close(os.open(directory / "started", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
    except FileExistsError:
        return False
    return True


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _detached(argv: list[str]) -> None:
    # The removal must not delay this relay (bootout waits for ExitTimeOut) nor leave it a child.
    subprocess.run(["/bin/sh", "-c", '"$@" >/dev/null 2>&1 </dev/null &', "sh", *argv],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def sweep(launchctl: str, now: float | None = None) -> list[str]:
    """Remove relay labels whose relay is gone or whose bound passed; return them."""
    now = time.time() if now is None else now
    listed = subprocess.run([launchctl, "list"], stdin=subprocess.DEVNULL, capture_output=True, text=True)
    removed = []
    for line in listed.stdout.splitlines() if listed.returncode == 0 else ():
        label = line.split()[-1] if line.split() else ""
        current, legacy = LABEL_RE.fullmatch(label), LEGACY_LABEL_RE.fullmatch(label)
        if current and (int(current.group(1)) < now or not _alive(int(current.group(2)))):
            _detached([launchctl, "bootout", f"{_domain()}/{label}"])
        elif legacy and not _alive(int(legacy.group(1))):
            _detached([launchctl, "remove", label])
        else:
            continue
        removed.append(label)
    return removed


def _state(launchctl: str, target: str) -> str:
    printed = subprocess.run([launchctl, "print", target], stdin=subprocess.DEVNULL, capture_output=True, text=True)
    if printed.returncode != 0:
        return "gone"
    match = re.search(r"^\s*state = (.+?)\s*$", printed.stdout, flags=re.MULTILINE)
    return match.group(1) if match else "unknown"


def relay(argv: list[str], bound: int = DEFAULT_BOUND_SECONDS) -> int:
    launchctl = _launchctl()
    sweep(launchctl)
    directory = Path(tempfile.mkdtemp(prefix="vpncontrol-launchd-"))
    os.chmod(directory, 0o700)
    deadline = int(time.time()) + max(1, int(bound)) + 2 * TERM_GRACE_SECONDS
    label = f"{LABEL_PREFIX}{deadline}.{os.getpid()}.{uuid.uuid4().hex[:8]}"
    target = f"{_domain()}/{label}"
    script, plist = directory / "job.sh", directory / "job.plist"
    script.write_text(_script(argv, os.getcwd(), dict(os.environ), directory, label, os.getpid(), launchctl))
    os.chmod(script, 0o700)
    plist.write_bytes(_plist(label, script))
    loaded = subprocess.run([launchctl, "bootstrap", _domain(), str(plist)],
                            stdin=subprocess.DEVNULL, capture_output=True)
    if loaded.returncode != 0 and _claim(directory):
        # The job had not started and now never can: run the command directly instead.
        subprocess.run([launchctl, "bootout", target], stdin=subprocess.DEVNULL, capture_output=True)
        shutil.rmtree(directory, ignore_errors=True)
        os.execvpe(argv[0], argv, dict(os.environ, **{INSIDE_VARIABLE: "1"}))
    # A failed bootstrap whose job already holds the marker is that job's only run: relay it as usual.
    terminated: list[float] = []

    def stop(*_):
        if not terminated:
            terminated.append(time.monotonic())
            subprocess.run([launchctl, "kill", "SIGTERM", target], stdin=subprocess.DEVNULL, capture_output=True)

    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, stop)
    offsets = {"out": 0, "err": 0}
    began = last_state = time.monotonic()
    status = None
    finished = False
    try:
        while True:
            for name, sink in (("out", sys.stdout.buffer), ("err", sys.stderr.buffer)):
                offsets[name] = _pump(directory / name, offsets[name], sink)
            if (directory / "rc").exists():
                for name, sink in (("out", sys.stdout.buffer), ("err", sys.stderr.buffer)):
                    offsets[name] = _pump(directory / name, offsets[name], sink)
                status = int((directory / "rc").read_text().strip() or 125)
                finished = True
                break
            now = time.monotonic()
            if terminated and now - terminated[0] > TERM_GRACE_SECONDS:
                status = 143
                break
            if now - last_state >= STATE_SECONDS:
                last_state = now
                state = _state(launchctl, target)
                started = (directory / "started").exists()
                if not started and (state == "gone" or now - began > STARTUP_SECONDS) and _claim(directory):
                    print(f"launchd_escape: job {label} never started ({state})", file=sys.stderr, flush=True)
                    status = LOST_STATUS
                    break
                if started and state != "running" and not (directory / "rc").exists():
                    print(f"launchd_escape: job {label} ended without an exit status ({state})",
                          file=sys.stderr, flush=True)
                    status = 143 if terminated else LOST_STATUS
                    break
            time.sleep(POLL_SECONDS)
    finally:
        if not finished:
            subprocess.run([launchctl, "kill", "SIGKILL", target], stdin=subprocess.DEVNULL, capture_output=True)
        subprocess.run([launchctl, "bootout", target], stdin=subprocess.DEVNULL, capture_output=True)
        shutil.rmtree(directory, ignore_errors=True)
    return status


def main(args: list[str]) -> int:
    bound = DEFAULT_BOUND_SECONDS
    if len(args) >= 4 and args[0] == "relay" and args[1] == "--bound" and args[2].isdigit():
        bound, args = int(args[2]), ["relay", *args[3:]]
    if len(args) >= 3 and args[0] == "relay" and args[1] == "--" and "=" not in args[2]:
        return relay(args[2:], bound)
    print("usage: launchd_escape.py relay [--bound SECONDS] -- COMMAND [ARG...]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
