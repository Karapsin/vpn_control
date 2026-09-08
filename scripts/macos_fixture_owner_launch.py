#!/usr/bin/env python3
"""Launch one task-owned macOS fixture owner through its active Aqua session."""
import argparse
import json
import shlex
import subprocess
from pathlib import PurePosixPath


def positive_uid(value: str) -> int:
    if not value.isascii() or not value.isdecimal() or int(value) <= 0:
        raise ValueError("positive numeric UID is required")
    return int(value)


def require_aqua_session(user: str, uid: str, console_user: str, console_uid: str, launchctl_exit: int) -> int:
    parsed = positive_uid(uid)
    if not user or user.startswith("-") or console_user.strip() != user or console_uid.strip() != str(parsed):
        raise ValueError("active console user does not match requested fixture owner")
    if launchctl_exit != 0:
        raise ValueError("requested GUI launchctl session is unavailable")
    return parsed


def owner_command(guest: str, uid: str, user: str, launcher: str, workspace: str, environment: dict[str, str]) -> list[str]:
    parsed = positive_uid(uid)
    if not guest or guest.startswith("-") or not user or user.startswith("-"):
        raise ValueError("non-option guest and user are required")
    executable, state = PurePosixPath(launcher), PurePosixPath(workspace)
    if not executable.is_absolute() or not state.is_absolute() or "\x00" in str(executable) + str(state):
        raise ValueError("absolute launcher and workspace paths are required")
    if set(environment) - {"JAVA_TOOL_OPTIONS"} or any("\x00" in value for value in environment.values()):
        raise ValueError("unsupported fixture environment")
    remote = shlex.join([
        "sudo", "-n", "launchctl", "asuser", str(parsed), "sudo", "-n", "-u", user,
        "/usr/bin/env", *(f"{key}={value}" for key, value in sorted(environment.items())),
        str(executable), "--state-dir", str(state), "serve",
    ])
    return ["ssh", "-o", "BatchMode=yes", "--", guest, remote]


def admission_paths(launcher: str) -> tuple[PurePosixPath, PurePosixPath, PurePosixPath, PurePosixPath]:
    executable = PurePosixPath(launcher)
    if (not executable.is_absolute() or ".." in executable.parts or executable.name != "vpn-control" or
            executable.parent.name != "MacOS" or executable.parent.parent.name != "Contents" or
            not executable.parent.parent.parent.name.endswith(".app")):
        raise ValueError("exact packaged macOS launcher path is required")
    macos = executable.parent
    contents = macos.parent
    bundle = contents.parent
    return bundle, contents, macos, executable


def admission_owner_command(guest: str, uid: str, launcher: str) -> list[str]:
    positive_uid(uid)
    if not guest or guest.startswith("-"):
        raise ValueError("non-option guest is required")
    paths = admission_paths(launcher)
    remote = "set -e; " + " ".join(
        f"/usr/bin/stat -f '%u' {shlex.quote(str(path))};" for path in paths)
    return ["ssh", "-o", "BatchMode=yes", "--", guest, remote]


def require_admission_owners(uid: str, owners: list[str]) -> None:
    requested = positive_uid(uid)
    if len(owners) != 4:
        raise ValueError("admission preflight did not return every packaged path owner")
    for owner in owners:
        if not owner.isascii() or not owner.isdecimal() or int(owner) not in {0, requested}:
            raise ValueError("packaged launcher path owner is not admitted")


def run_admission_preflight(guest: str, uid: str, launcher: str) -> None:
    completed = subprocess.run(admission_owner_command(guest, uid, launcher), check=False, text=True,
                               capture_output=True, timeout=20)
    if completed.returncode != 0:
        raise ValueError("admission path owner preflight failed")
    require_admission_owners(uid, completed.stdout.splitlines())


def preflight_command(guest: str, uid: str) -> list[str]:
    parsed = positive_uid(uid)
    if not guest or guest.startswith("-"):
        raise ValueError("non-option guest is required")
    remote = " ".join([
        "set -e; /usr/bin/stat -f '%Su' /dev/console; /usr/bin/stat -f '%u' /dev/console;",
        f"sudo -n launchctl print gui/{parsed} >/dev/null",
    ])
    return ["ssh", "-o", "BatchMode=yes", "--", guest, remote]


def run_preflight(guest: str, uid: str, user: str) -> int:
    completed = subprocess.run(preflight_command(guest, uid), check=False, text=True, capture_output=True, timeout=20)
    lines = completed.stdout.splitlines()
    if len(lines) != 2:
        raise ValueError("Aqua preflight did not return one console identity")
    return require_aqua_session(user, uid, lines[0], lines[1], completed.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "launch"))
    parser.add_argument("--guest", required=True)
    parser.add_argument("--uid", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--launcher")
    parser.add_argument("--workspace")
    parser.add_argument("--java-tool-options", default="")
    args = parser.parse_args()
    if args.action == "preflight":
        print(json.dumps({"uid": run_preflight(args.guest, args.uid, args.user), "aqua": True}, sort_keys=True))
        return 0
    if not args.launcher or not args.workspace:
        parser.error("launch requires --launcher and --workspace")
    run_preflight(args.guest, args.uid, args.user)
    run_admission_preflight(args.guest, args.uid, args.launcher)
    environment = {"JAVA_TOOL_OPTIONS": args.java_tool_options} if args.java_tool_options else {}
    return subprocess.run(owner_command(args.guest, args.uid, args.user, args.launcher, args.workspace, environment), check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
