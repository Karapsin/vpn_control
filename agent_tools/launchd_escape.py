#!/usr/bin/env python3
"""Run a heavy check under launchd instead of the caller's background-priority tree.

On macOS a process started from the agent-session tmux tree inherits Darwin
background priority (ps pri 4). CPU-bound agent tests then run 5-7x slower and
sleeps overshoot, and no per-process option (taskpolicy, nice, launchctl asuser,
setpriority) lifts it. A job submitted with `launchctl submit` is a child of
launchd and runs at the normal priority, with no sudo and no system change.

`managed_agent_check.background_escape(command)` returns
`[python, this_file, "relay", "--", *command]` on macOS and the unchanged command
elsewhere (this file stays import-free so it is only ever run, never imported). The relay keeps the Popen contract of the
original command: same cwd and environment, stdout/stderr relayed, exit status
returned, SIGTERM forwarded, and the job stopped if the relay itself dies.
VPN_CONTROL_LAUNCHD_ESCAPE=0 disables it. If submission fails the relay runs
the command directly.
"""
from __future__ import annotations

import os
import re
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
NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TERM_GRACE_SECONDS = 40.0


def _script(argv, cwd, env, directory: Path, label: str, relay_pid: int) -> str:
    exports = "".join(f"export {k}={shlex.quote(v)}\n" for k, v in env.items()
                      if NAME_RE.match(k) and "\0" not in v)
    return f"""#!/bin/bash
{exports}export {INSIDE_VARIABLE}=1
cd {shlex.quote(cwd)} || {{ echo 126 > {shlex.quote(str(directory / 'rc.tmp'))}; mv {shlex.quote(str(directory / 'rc.tmp'))} {shlex.quote(str(directory / 'rc'))}; exit 126; }}
exec >{shlex.quote(str(directory / 'out'))} 2>{shlex.quote(str(directory / 'err'))} </dev/null
{shlex.join(argv)} &
child=$!
trap 'kill -TERM $child 2>/dev/null' TERM INT HUP
( while kill -0 {relay_pid} 2>/dev/null; do sleep 2; done; kill -TERM $child 2>/dev/null ) &
watchdog=$!
wait $child; rc=$?
while kill -0 $child 2>/dev/null; do wait $child; rc=$?; done
kill $watchdog 2>/dev/null
echo $rc > {shlex.quote(str(directory / 'rc.tmp'))}
mv {shlex.quote(str(directory / 'rc.tmp'))} {shlex.quote(str(directory / 'rc'))}
"""


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


def relay(argv: list[str]) -> int:
    directory = Path(tempfile.mkdtemp(prefix="vpncontrol-launchd-"))
    os.chmod(directory, 0o700)
    label = f"vpncontrol.check.{os.getpid()}.{uuid.uuid4().hex[:8]}"
    script = directory / "job.sh"
    script.write_text(_script(argv, os.getcwd(), dict(os.environ), directory, label, os.getpid()))
    os.chmod(script, 0o700)
    submitted = subprocess.run(["launchctl", "submit", "-l", label, "--", str(script)],
                               stdin=subprocess.DEVNULL, capture_output=True)
    if submitted.returncode != 0:
        shutil.rmtree(directory, ignore_errors=True)
        env = dict(os.environ, **{INSIDE_VARIABLE: "1"})
        os.execvpe(argv[0], argv, env)
    terminated = []

    def remove(*_):
        if not terminated:
            terminated.append(time.monotonic())
            subprocess.run(["launchctl", "remove", label], capture_output=True)

    for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(number, remove)
    offsets = {"out": 0, "err": 0}
    last_check = time.monotonic()
    status = None
    try:
        while True:
            offsets["out"] = _pump(directory / "out", offsets["out"], sys.stdout.buffer)
            offsets["err"] = _pump(directory / "err", offsets["err"], sys.stderr.buffer)
            if (directory / "rc").exists():
                offsets["out"] = _pump(directory / "out", offsets["out"], sys.stdout.buffer)
                offsets["err"] = _pump(directory / "err", offsets["err"], sys.stderr.buffer)
                status = int((directory / "rc").read_text().strip() or 125)
                break
            now = time.monotonic()
            if terminated and now - terminated[0] > TERM_GRACE_SECONDS:
                status = 143
                break
            if now - last_check > 5:
                last_check = now
                listed = subprocess.run(["launchctl", "list", label], capture_output=True)
                if listed.returncode != 0 and not (directory / "rc").exists():
                    status = 143 if terminated else 125
                    break
            time.sleep(0.2)
    finally:
        subprocess.run(["launchctl", "remove", label], capture_output=True)
        shutil.rmtree(directory, ignore_errors=True)
    return status


def main(args: list[str]) -> int:
    if len(args) >= 3 and args[0] == "relay" and args[1] == "--":
        return relay(args[2:])
    print("usage: launchd_escape.py relay -- COMMAND [ARG...]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
