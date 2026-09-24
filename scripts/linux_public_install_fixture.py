#!/usr/bin/env python3
"""Prepare target-owned Linux public-install fixture directories and keytool execution."""

from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from typing import Callable, Mapping, Sequence

PUBLIC_STORE_ENV = "FIXTURE_PUBLIC_STORE_PASSWORD"

class FixtureSetupError(RuntimeError): pass
def require(value, message):
    if not value: raise FixtureSetupError(message)

def normalized(path: Path) -> Path:
    require(path.is_absolute() and ".." not in path.parts, "Fixture path must be absolute and lexical")
    return Path(os.path.abspath(path))

def target_command(user: str, home: Path, command: Sequence[str], environment: Mapping[str, str]):
    require(bool(user) and "/" not in user, "Invalid target user")
    allowed = {PUBLIC_STORE_ENV}
    require(set(environment).issubset(allowed), "Unsupported fixture environment")
    require(all(isinstance(v, str) and v and "\n" not in v and "\r" not in v for v in environment.values()), "Invalid public-store environment")
    child = {"PATH": os.defpath}; child.update(environment)
    names = ",".join(sorted(environment))
    prefix = ["sudo", "-n"] + ([f"--preserve-env={names}"] if names else [])
    return prefix + ["-u", user, "env", f"HOME={home}", *command], child

def _lstat(path, stat_reader):
    try: return stat_reader(path)
    except FileNotFoundError: return None

def _verify_existing_ancestors(home, path, uid, gid, stat_reader):
    current = path
    while True:
        info = _lstat(current, stat_reader)
        if info is not None:
            require(not stat.S_ISLNK(info.st_mode), f"Fixture ancestor is a symlink: {current}")
            require(stat.S_ISDIR(info.st_mode), f"Fixture ancestor is not a directory: {current}")
            require(info.st_uid == uid and info.st_gid == gid and info.st_mode & 0o022 == 0,
                    f"Fixture ancestor is not target-owned/private: {current}")
        if current == home: break
        current = current.parent

def prepare_target_paths(user, home, fixture_root, *, uid, gid, runner=subprocess.run, stat_reader=os.lstat):
    home, fixture_root = normalized(home), normalized(fixture_root)
    require(fixture_root != home and home in fixture_root.parents, "Fixture root must be inside target home")
    paths = [home / ".local", home / ".local" / "state", fixture_root, fixture_root / "public"]
    for path in paths:
        _verify_existing_ancestors(home, path, uid, gid, stat_reader)
        command, environment = target_command(user, home, ["mkdir", "-p", "-m", "0700", "--", str(path)], {})
        runner(command, env=environment, check=True)
        info = _lstat(path, stat_reader)
        require(info is not None and not stat.S_ISLNK(info.st_mode) and stat.S_ISDIR(info.st_mode)
                and info.st_uid == uid and info.st_gid == gid and info.st_mode & 0o022 == 0,
                f"Fixture path was not created target-owned/private: {path}")
    return paths

def run_keytool_as_target(user, home, keytool_arguments, *, runner=subprocess.run):
    password = os.environ.get(PUBLIC_STORE_ENV)
    require(password is not None, f"Missing {PUBLIC_STORE_ENV} for public CA store")
    require(keytool_arguments and Path(keytool_arguments[0]).name == "keytool", "Keytool command must start with keytool")
    # Public certificate stores only: password literals and unrelated key operations
    # must never enter command receipts. Values travel through the named environment.
    flags = {"-list", "-importcert", "-noprompt", "-trustcacerts", "-v"}
    valued = {"-alias", "-file", "-keystore", "-storetype", "-storepass:env"}
    arguments = list(keytool_arguments[1:])
    password_flags = 0
    while arguments:
        option = arguments.pop(0)
        require(option in flags | valued, "Unsupported public-store keytool option")
        if option in valued:
            require(bool(arguments), "Missing public-store keytool option value")
            value = arguments.pop(0)
            if option == "-storepass:env":
                require(value == PUBLIC_STORE_ENV, "Unexpected public-store environment")
                password_flags += 1
    require(password_flags == 1, "Exactly one public-store environment is required")
    command, environment = target_command(user, normalized(home), keytool_arguments, {PUBLIC_STORE_ENV: password})
    return runner(command, env=environment, check=True)

def read_target_metadata(user, home, path, *, expected_uid, expected_gid, expected_mode, runner=subprocess.run):
    command, environment = target_command(user, normalized(home), ["stat", "-c", "%u:%g:%a", "--", str(normalized(path))], {})
    completed = runner(command, env=environment, check=True, capture_output=True, text=True)
    actual = completed.stdout.strip()
    require(actual == f"{expected_uid}:{expected_gid}:{expected_mode:o}", "Target metadata differs from expected ownership")
    return actual

def main():
    require(sys.platform.startswith("linux"), "Linux fixture setup requires Linux")
    parser=argparse.ArgumentParser(description=__doc__); sub=parser.add_subparsers(dest="action", required=True)
    setup=sub.add_parser("setup"); setup.add_argument("--target-user", required=True); setup.add_argument("--target-home", type=Path, required=True); setup.add_argument("--fixture-root",type=Path,required=True)
    keytool=sub.add_parser("keytool"); keytool.add_argument("--target-user",required=True); keytool.add_argument("--target-home",type=Path,required=True); keytool.add_argument("command",nargs=argparse.REMAINDER)
    args=parser.parse_args()
    import pwd
    account=pwd.getpwnam(args.target_user)
    require(normalized(args.target_home) == normalized(Path(account.pw_dir)), "Target home differs from account home")
    if args.action=="setup":
        paths=prepare_target_paths(args.target_user,args.target_home,args.fixture_root,uid=account.pw_uid,gid=account.pw_gid)
        print(json.dumps({"targetUser":args.target_user,"paths":[p.name for p in paths]},sort_keys=True))
    else:
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        run_keytool_as_target(args.target_user,args.target_home,command)
if __name__=="__main__": main()
