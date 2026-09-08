#!/usr/bin/env python3
"""Close one explicitly identified macOS fixture frontend through guest Aqua."""
import argparse
import shlex
import subprocess
import sys


def positive_pid(value: str) -> int:
    try:
        pid = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("PID must be an integer") from error
    if pid <= 0:
        raise argparse.ArgumentTypeError("PID must be positive")
    return pid


def close_script() -> str:
    return """on run argv
set targetPid to (item 1 of argv) as integer
tell application \"System Events\"
    tell (first application process whose unix id is targetPid)
        tell window 1
            click (first button whose description is \"close button\")
        end tell
    end tell
end tell
end run"""


def close_command(guest: str, uid: str, user: str, pid: int) -> list[str]:
    if (not guest or guest.startswith("-") or not uid.isascii() or not uid.isdecimal()
            or int(uid) <= 0 or not user or pid <= 0):
        raise ValueError("guest, positive numeric UID, user, and positive PID are required")
    remote = shlex.join([
        "sudo", "-n", "launchctl", "asuser", uid, "sudo", "-n", "-u", user,
        "/usr/bin/osascript", "-e", close_script(), "--", str(pid),
    ])
    return [
        "ssh", "-o", "BatchMode=yes", "--", guest, remote,
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guest", required=True)
    parser.add_argument("--uid", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--pid", required=True, type=positive_pid)
    args = parser.parse_args()
    try:
        return subprocess.run(
            close_command(args.guest, args.uid, args.user, args.pid), check=False, timeout=30,
        ).returncode
    except subprocess.TimeoutExpired:
        print("outcome unknown; inspect guest before retry", file=sys.stderr)
        return 124


if __name__ == "__main__":
    raise SystemExit(main())
