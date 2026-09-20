#!/usr/bin/env python3
"""Exercise one Android self-update installer interaction on an admitted AVD."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import android_no_update_tls_preflight as tls
from scripts.integration import android_update_fixture as fixture

EXIT = {"OK": 0, "ACCEPTED": 0, "INTERACTION_REQUIRED": 1,
        "PERMISSION_DENIED": 1, "CANCELLED": 130, "TIMEOUT": 2,
        "OUTCOME_UNKNOWN": 2}


def invoke(cli, serial, *words, interactive=False, asynchronous=False, environment=None):
    argv = [str(cli), "--json", "--android", "--serial", serial]
    if asynchronous:
        argv.append("--async")
    if interactive:
        argv.append("--interactive")
    argv.extend(words)
    done = subprocess.run(argv, text=True, capture_output=True, env=environment)
    try:
        body = json.loads(done.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("CLI did not return JSON") from error
    return {"argv": argv, "exit": done.returncode, "response": body, "stderr": done.stderr}


def final(record, expected):
    if (record["exit"] != EXIT[expected] or record["response"].get("code") != expected
            or record["response"].get("final") is not True):
        raise RuntimeError(f"expected final {expected}: {record}")


def focused_dialog_state(adb):
    windows = adb.shell("dumpsys", "window", "windows")
    return tuple(line.strip() for line in windows.splitlines()
                 if "AndroidControlInteractionActivity" in line or "packageinstaller" in line.lower())


def checkpoint(args, receipt):
    path = args.probe_output
    if path.exists():
        raise RuntimeError("action checkpoint path already exists")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump({"callbackReceipt": receipt}, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise RuntimeError("action checkpoint was not private/persisted")


def require_private_callback_parent(parent):
    info = parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError("continue callback parent must be private owned mode 0700")


def prepare_continue_file(path, parent):
    require_private_callback_parent(parent)
    if path.parent != parent or path.exists() or path.is_symlink():
        raise RuntimeError("continue callback path must be a new direct private file")


def wait_for_continue_file(path, parent):
    require_private_callback_parent(parent)
    while not path.exists():
        time.sleep(0.1)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as callback:
        info = os.fstat(callback.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise RuntimeError("continue callback must be a private regular file")
        if callback.read() != "continue\n":
            raise RuntimeError("continue callback content must be literal continue")


def await_callback(args):
    callback = getattr(args, "continue_file", None)
    if callback is None:
        print("Handle the requested OS-dialog case, then press Enter. Do not invoke install again.", flush=True)
        input()
        return
    print("Handle the requested OS-dialog case, then create the private continue callback. Do not invoke install again.", flush=True)
    wait_for_continue_file(callback, args.fixture_parent)


def action(args, adb, receipt):
    if adb.shell_id() != "uid=2000":
        raise RuntimeError("product action requires public UID 2000")
    environment = getattr(args, "cli_environment", None)
    check = invoke(args.cli, args.serial, "updates", "check", environment=environment)
    final(check, "OK")
    download = invoke(args.cli, args.serial, "updates", "download", environment=environment)
    final(download, "OK")
    before_windows = focused_dialog_state(adb)
    rejected = invoke(args.cli, args.serial, "updates", "install", environment=environment)
    final(rejected, "INTERACTION_REQUIRED")
    if focused_dialog_state(adb) != before_windows:
        raise RuntimeError("noninteractive install opened a focused OS dialog")
    accepted = invoke(args.cli, args.serial, "updates", "install", interactive=True,
                      asynchronous=True, environment=environment)
    operation = accepted["response"].get("operationId")
    if (accepted["exit"] != 0 or accepted["response"].get("code") != "ACCEPTED"
            or accepted["response"].get("final") is not False
            or not isinstance(operation, str) or not operation):
        raise RuntimeError(f"interactive install was not accepted once: {accepted}")
    receipt["installerLifecycle"] = {"check": check, "download": download,
        "noninteractiveRejected": rejected, "interactiveAccepted": accepted,
        "operationId": operation}
    checkpoint(args, receipt)
    await_callback(args)
    status = invoke(args.cli, args.serial, "operations", "status", operation, environment=environment)
    waited = invoke(args.cli, args.serial, "--timeout-seconds", "0", "operations", "wait", operation,
                    environment=environment)
    receipt["installerLifecycle"].update({"statusAfterUi": status, "waitOriginalOperation": waited,
                                            "targetSha256": args.target_sha256})
    return receipt["installerLifecycle"]


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("adb", "serial", "api", "avd", "device-port"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--ca-certificate", type=Path, required=True)
    parser.add_argument("--leaf-certificate", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--continue-file", type=Path)
    for prefix in ("base", "target"):
        parser.add_argument(f"--{prefix}-apk", type=Path, required=True)
        parser.add_argument(f"--{prefix}-sha256", required=True)
        parser.add_argument(f"--{prefix}-version", required=True)
        parser.add_argument(f"--{prefix}-code", required=True)
    return parser.parse_args()


def main():
    args = parse_args()
    args.device_port = int(args.device_port)
    if args.api not in ("29", "35") or args.output.exists():
        raise SystemExit("API must be 29/35 and output must be new")
    args.cli_environment = tls.public_cli_environment(args.adb, args.cli)
    args.output.mkdir(mode=0o700, parents=True)
    if args.continue_file is None:
        tls.require_interactive_stdin()
    else:
        prepare_continue_file(args.continue_file, args.output)
    tls.require_artifact_hash(args.base_apk, args.base_sha256)
    tls.require_artifact_hash(args.target_apk, args.target_sha256)
    ready, log, served = args.output / "ready.json", args.output / "fixture.log", args.output / "fixture-receipt.json"
    process = fixture.launch_supervised_fixture(args.target_apk, args.target_version, int(args.target_code),
                                                args.leaf_certificate, args.private_key, ready, log, served)
    try:
        args.host_port = fixture.read_ready_file(
            ready, fixture.make_manifest(args.target_apk, args.target_version, int(args.target_code)))
        lifecycle = argparse.Namespace(
            adb=args.adb, serial=args.serial, cli=args.cli, certificate=args.ca_certificate,
            leaf_certificate=args.leaf_certificate, fixture_parent=args.output, server_log=log,
            probe_output=args.output / "probe.json", device_port=args.device_port, host_port=args.host_port,
            staging=f"/data/local/tmp/vpn-control-installer-api{args.api}", receipt=args.output / "lifecycle-receipt.json",
            expected_avd=args.avd, expected_api=args.api, expected_version=args.base_version,
            expected_code=args.base_code, base_apk=args.base_apk, base_sha256=args.base_sha256,
            target_sha256=args.target_sha256, continue_file=args.continue_file,
            cli_environment=args.cli_environment)
        target = "/apex/com.android.conscrypt/cacerts" if args.api == "35" else "/system/etc/security/cacerts"
        tls.run_fixture_lifecycle(lifecycle, action, target_install=True, ca_store_target=target,
                                  expected_proxy="null")
    finally:
        fixture._stop_fixture(process)


if __name__ == "__main__":
    main()
