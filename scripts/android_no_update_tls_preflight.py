#!/usr/bin/env python3
"""Reviewed-only disposable Android no-update TLS preflight; never installs a target APK."""
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from android_fixture_transport import cleanup_fixture_transport, establish_fixture_transport, parse_reverse_inventory
from android_fixture_trust import (
    android_ca_store_filename,
    require_android_certificate_store_layout,
    require_device_time_within_certificates,
    secure_private_fixture_files,
    zygote_bind_mount_argv,
)


def bounded_text(value: str, limit: int = 1024) -> str:
    return value[:limit] + ("…" if len(value) > limit else "")


class Adb:
    def __init__(self, adb: str, serial: str):
        self.command = [adb, "-s", serial]
        self.records = []

    def run(self, *args: str) -> str:
        result = subprocess.run([*self.command, *args], check=False, text=True, capture_output=True)
        self.records.append({"args": list(args), "exit": result.returncode,
                             "stdout": bounded_text(result.stdout), "stderr": bounded_text(result.stderr),
                             "stdoutTruncated": len(result.stdout) > 1024,
                             "stderrTruncated": len(result.stderr) > 1024})
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, [*self.command, *args], result.stdout, result.stderr)
        return result.stdout.strip()

    def shell(self, *args: str) -> str:
        return self.run("shell", *args)

    def exec_out_bytes(self, *args: str) -> bytes:
        result = subprocess.run([*self.command, "exec-out", *args], check=False, capture_output=True)
        stderr = result.stderr.decode("utf-8", "replace")
        self.records.append({"args": ["exec-out", *args], "exit": result.returncode,
                             "stdoutBytes": len(result.stdout), "stderr": bounded_text(stderr),
                             "stderrTruncated": len(stderr) > 1024})
        if result.returncode:
            raise subprocess.CalledProcessError(result.returncode, [*self.command, "exec-out", *args],
                                                result.stdout, result.stderr)
        return result.stdout

    def shell_id(self) -> str:
        return f"uid={self.shell('id', '-u')}"

    def reverse_inventory(self) -> dict[int, int]:
        return parse_reverse_inventory(self.run("reverse", "--list"))

    def reverse_mapping(self, port: int):
        return self.reverse_inventory().get(port)

    def reverse(self, device_port: int, host_port: int) -> None:
        self.run("reverse", f"tcp:{device_port}", f"tcp:{host_port}")

    def remove_reverse(self, device_port: int) -> None:
        self.run("reverse", "--remove", f"tcp:{device_port}")

    def global_proxy(self) -> str:
        return self.shell("settings", "get", "global", "http_proxy")

    def set_global_proxy(self, value: str) -> None:
        self.shell("settings", "put", "global", "http_proxy", value)

    def unroot(self) -> None:
        self.run("unroot")

    def wait_for_device(self) -> None:
        self.run("wait-for-device")


def device_mode(adb: Adb, path: str) -> int:
    return int(adb.shell("stat", "-c", "%a", path), 8)


def device_label(adb: Adb, path: str) -> str:
    return adb.shell("ls", "-Zd", path).split(maxsplit=1)[0]


class ProbeFailure(RuntimeError):
    def __init__(self, message: str, evidence: dict):
        super().__init__(message)
        self.evidence = evidence


def public_no_update_probe(cli: Path, serial: str, server_log: Path, output_path: Path) -> dict:
    result = subprocess.run(
        [sys.executable, str(cli), "--json", "--android", "--serial", serial,
         "--timeout-seconds", "180", "updates", "check"],
        check=False, text=True, capture_output=True,
    )
    output_path.write_text(result.stdout + ("\n--- stderr ---\n" + result.stderr if result.stderr else ""))
    os.chmod(output_path, 0o600)
    evidence = {"output": str(output_path), "command": {"exit": result.returncode, "stdoutBytes": len(result.stdout),
                            "stderr": bounded_text(result.stderr),
                            "stderrTruncated": len(result.stderr) > 1024}}
    if result.returncode != 0:
        raise ProbeFailure("Public no-update probe command failed", evidence)
    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ProbeFailure("Public no-update probe returned invalid JSON", evidence) from error
    data = response.get("data") or {}
    manifests = sum('"served": "manifest"' in line for line in server_log.read_text().splitlines())
    evidence.update({"operationId": response.get("operationId"), "controllerId": response.get("controllerId"),
                     "manifestCount": manifests, "ok": response.get("ok"), "code": response.get("code")})
    if not (response.get("ok") and response.get("code") == "OK" and data.get("checked")
            and data.get("available") is False and manifests == 1):
        raise ProbeFailure("Public no-update probe did not prove TLS visibility", evidence)
    return evidence


def require_task_staging(staging: str) -> None:
    if not re.fullmatch(r"/data/local/tmp/vpn-control-[A-Za-z0-9][A-Za-z0-9._-]*", staging):
        raise ValueError("Fixture staging must be one shell-safe task-owned leaf under /data/local/tmp")


SELINUX_CONTEXT = re.compile(r"u:object_r:[A-Za-z0-9_.-]+:s0(?::c[0-9]+(?:,c[0-9]+)*)?")
STAGED_CHILD_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def staged_regular_file_paths(adb: Adb, staging: str) -> list[str]:
    """Return only direct, regular staging children after rejecting unsafe shapes."""
    require_task_staging(staging)
    for kind in ("l", "d"):
        found = adb.shell("find", staging, "-mindepth", "1", "-type", kind, "-print")
        if found:
            raise RuntimeError("Staged Android CA store contains a forbidden child shape")
    direct = [line for line in adb.shell(
        "find", staging, "-mindepth", "1", "-maxdepth", "1", "-print"
    ).splitlines() if line]
    raw = adb.shell("find", staging, "-mindepth", "1", "-maxdepth", "1", "-type", "f", "-print")
    files = [line for line in raw.splitlines() if line]
    if not files:
        raise RuntimeError("Staged Android CA store contains no regular certificates")
    if len(direct) != len(set(direct)) or set(direct) != set(files):
        raise RuntimeError("Staged Android CA store contains a nonregular direct entry")
    prefix = staging + "/"
    if any(not path.startswith(prefix) or "/" in path[len(prefix):]
           or not STAGED_CHILD_NAME.fullmatch(path[len(prefix):]) for path in files):
        raise RuntimeError("Staged Android CA store returned an unsafe child path")
    return files


def relabel_staged_ca_store(adb: Adb, staging: str, expected_label: str) -> list[str]:
    """Relabel only validated task-owned staging entries to the captured CA-store context."""
    if not SELINUX_CONTEXT.fullmatch(expected_label):
        raise ValueError("Captured Android CA-store SELinux context is unsafe")
    files = staged_regular_file_paths(adb, staging)
    for path in [staging, *files]:
        adb.shell("chcon", expected_label, path)
    for path in [staging, *files]:
        if device_label(adb, path) != expected_label:
            raise RuntimeError("Staged Android CA store relabel did not take effect")
    return files


def require_artifact_hash(artifact: Path, expected_sha256: str) -> str:
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if digest != expected_sha256:
        raise RuntimeError("Fixture base APK hash does not match frozen artifact")
    return digest


def require_installed_base_hash(adb: Adb, package_dump: str, expected_sha256: str) -> str:
    paths = [line.removeprefix("package:") for line in package_dump.splitlines()
             if line.startswith("package:") and line.endswith("/base.apk")]
    if len(paths) != 1:
        raise RuntimeError("Fixture package base APK path is not unambiguous")
    digest = hashlib.sha256(adb.exec_out_bytes("cat", paths[0])).hexdigest()
    if digest != expected_sha256:
        raise RuntimeError("Installed base APK bytes do not match frozen artifact")
    return digest


def establish_owned_transport(adb: Adb, device_port: int, host_port: int, previous_proxy: str) -> None:
    if adb.reverse_mapping(device_port) is not None:
        raise RuntimeError("Fixture target reverse route already exists")
    adb.reverse(device_port, host_port)
    fixture_proxy = f"127.0.0.1:{device_port}"
    try:
        adb.set_global_proxy(fixture_proxy)
    except Exception as error:
        rollback_error = None
        try:
            if adb.reverse_mapping(device_port) == host_port:
                current_proxy = adb.global_proxy()
                if current_proxy == fixture_proxy:
                    adb.set_global_proxy(previous_proxy)
                if adb.global_proxy() == previous_proxy:
                    adb.remove_reverse(device_port)
        except Exception as failed_rollback:
            rollback_error = failed_rollback
        try:
            error.fixture_reverse_owned = adb.reverse_mapping(device_port) == host_port
            error.fixture_proxy_owned = adb.global_proxy() == fixture_proxy
        except Exception:
            error.fixture_reverse_owned = False
            error.fixture_proxy_owned = False
        if rollback_error is not None:
            raise error from rollback_error
        raise


def verify_public_baseline(adb: Adb, cli: Path, serial: str, expected_avd: str, expected_api: str,
                           expected_version: str, expected_code: str, expected_sha256: str) -> dict:
    avd = adb.shell("getprop", "ro.kernel.qemu.avd_name")
    api = adb.shell("getprop", "ro.build.version.sdk")
    package = adb.shell("dumpsys", "package", "com.kardinal.vpncontrol")
    status = subprocess.run(
        [sys.executable, str(cli), "--json", "--android", "--serial", serial, "status"],
        check=True, text=True, capture_output=True,
    )
    response = json.loads(status.stdout)
    data = response.get("data") or {}
    if (avd != expected_avd or api != expected_api
            or f"versionName={expected_version}" not in package
            or f"versionCode={expected_code}" not in package
            or "DEBUGGABLE" in package
            or not response.get("ok") or data.get("runtimeRunning") is not False):
        raise RuntimeError("Fixture public baseline does not match approved OFF base")
    installed_hash = require_installed_base_hash(adb, adb.shell("pm", "path", "com.kardinal.vpncontrol"), expected_sha256)
    return {"avd": avd, "api": api, "controllerId": response.get("controllerId"),
            "runtimeRunning": data.get("runtimeRunning"), "installedBaseSha256": installed_hash}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--certificate", type=Path, required=True)
    parser.add_argument("--leaf-certificate", type=Path, required=True)
    parser.add_argument("--fixture-parent", type=Path, required=True)
    parser.add_argument("--server-log", type=Path, required=True)
    parser.add_argument("--probe-output", type=Path, required=True)
    parser.add_argument("--device-port", type=int, required=True)
    parser.add_argument("--host-port", type=int, required=True)
    parser.add_argument("--staging", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--expected-avd", required=True)
    parser.add_argument("--expected-api", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-code", required=True)
    parser.add_argument("--base-apk", type=Path, required=True)
    parser.add_argument("--base-sha256", required=True)
    return parser.parse_args()

def run_fixture_lifecycle(args: argparse.Namespace, action, *, target_install: bool = False) -> dict:
    if not isinstance(target_install, bool):
        raise ValueError("Fixture target-install metadata must be boolean")
    args.target = "/system/etc/security/cacerts"
    require_task_staging(args.staging)
    frozen_hash = require_artifact_hash(args.base_apk, args.base_sha256)
    adb = Adb(args.adb, args.serial)
    receipt = {"serial": args.serial, "target": args.target, "targetInstall": target_install, "cleanupFailures": []}
    previous_proxy = adb.global_proxy()
    if adb.shell_id() != "uid=2000" or adb.reverse_inventory() or previous_proxy != "null":
        raise RuntimeError("Public no-update preflight requires an unowned public transport baseline")
    receipt["baseline"] = verify_public_baseline(
        adb, args.cli, args.serial, args.expected_avd, args.expected_api,
        args.expected_version, args.expected_code, args.base_sha256,
    )
    receipt["frozenBaseSha256"] = frozen_hash
    secure_private_fixture_files([args.certificate])
    private_mode = stat.S_IMODE(args.fixture_parent.stat().st_mode)
    target_mode, target_label = device_mode(adb, args.target), device_label(adb, args.target)
    device_epoch = int(adb.shell("date", "+%s"))
    require_device_time_within_certificates(device_epoch, args.certificate, args.leaf_certificate)
    receipt.update({"deviceEpoch": device_epoch, "expectedLabel": target_label, "targetMode": oct(target_mode)})
    mounted = False
    unmounted = False
    transport = False
    reverse_created = False
    proxy_attempted = False
    primary_failure = False
    rooted = False
    staging_created = False
    try:
        adb.run("root")
        rooted = True
        adb.wait_for_device()
        zygote = adb.shell("pidof", "zygote64")
        adb.shell("mkdir", "-m", "0755", args.staging)
        staging_created = True
        adb.shell("cp", "-a", args.target + "/.", args.staging + "/")
        staged_certificate = args.staging + "/" + android_ca_store_filename(args.certificate)
        adb.run("push", str(args.certificate), staged_certificate)
        adb.shell("chmod", "0755", args.staging)
        adb.shell("chmod", "0644", staged_certificate)
        staged_files = relabel_staged_ca_store(adb, args.staging, target_label)
        if staged_certificate not in staged_files:
            raise RuntimeError("Staged Android CA certificate is not a validated regular file")
        require_android_certificate_store_layout(
            private_mode, device_mode(adb, args.staging), device_mode(adb, staged_certificate),
            device_label(adb, args.staging), target_label,
        )
        if device_label(adb, staged_certificate) != target_label:
            raise RuntimeError("Staged Android CA certificate has an unexpected SELinux label")
        argv = zygote_bind_mount_argv(zygote, args.staging, args.target)
        adb.shell(*argv)
        mounted = True
        adb.unroot()
        rooted = False
        adb.wait_for_device()
        if adb.shell_id() != "uid=2000":
            raise RuntimeError("Fixture setup did not restore public adbd")
        proxy_attempted = True
        try:
            establish_owned_transport(adb, args.device_port, args.host_port, previous_proxy)
        except Exception as error:
            reverse_created = bool(getattr(error, "fixture_reverse_owned", False))
            raise
        reverse_created = True
        transport = True
        adb.shell("am", "force-stop", "com.kardinal.vpncontrol")
        receipt["probe"] = action(args, adb, receipt)
    except Exception as error:
        primary_failure = True
        receipt["failure"] = {"type": type(error).__name__, "commandsRecorded": len(adb.records)}
        if isinstance(error, ProbeFailure):
            receipt["failure"]["probe"] = error.evidence
        raise
    finally:
        def cleanup_attempt(name, action):
            try:
                action()
            except Exception as error:
                receipt["cleanupFailures"].append({"step": name, "type": type(error).__name__})

        if transport:
            cleanup_attempt(
                "transport", lambda: cleanup_fixture_transport(
                    adb, args.device_port, args.host_port, previous_proxy
                ),
            )
        elif reverse_created:
            def remove_partial_reverse():
                if adb.reverse_mapping(args.device_port) != args.host_port:
                    raise RuntimeError("Partial fixture reverse ownership changed")
                fixture_proxy = f"127.0.0.1:{args.device_port}"
                current_proxy = adb.global_proxy()
                if proxy_attempted and current_proxy == fixture_proxy:
                    adb.set_global_proxy(previous_proxy)
                elif current_proxy != previous_proxy:
                    raise RuntimeError("Partial fixture proxy ownership changed")
                adb.remove_reverse(args.device_port)
            cleanup_attempt("partialReverse", remove_partial_reverse)
        if mounted or staging_created:
            if not rooted:
                def become_root():
                    nonlocal rooted
                    adb.run("root")
                    rooted = True
                    adb.wait_for_device()
                cleanup_attempt("rootForCleanup", become_root)
        if mounted:
            def unmount_original_zygote():
                nonlocal unmounted
                if adb.shell("pidof", "zygote64") != zygote:
                    raise RuntimeError("Zygote changed; preserving mount for explicit recovery")
                adb.shell("nsenter", "-t", zygote, "-m", "--", "umount", args.target)
                unmounted = True
            cleanup_attempt("unmount", unmount_original_zygote)
        if staging_created and (not mounted or unmounted):
            cleanup_attempt("staging", lambda: adb.shell("rm", "-r", args.staging))
        elif staging_created:
            receipt["retainedStaging"] = args.staging
        if rooted:
            def restore_public_adbd():
                nonlocal rooted
                adb.unroot()
                rooted = False
                adb.wait_for_device()
                if adb.shell_id() != "uid=2000":
                    raise RuntimeError("Cleanup did not restore public adbd")
            cleanup_attempt("unroot", restore_public_adbd)
        try:
            receipt["commands"] = adb.records
            args.receipt.write_text(json.dumps(receipt, sort_keys=True) + "\n")
            os.chmod(args.receipt, 0o600)
        except Exception as error:
            raise RuntimeError("Could not persist fixture receipt") from error
        if receipt["cleanupFailures"] and not primary_failure:
            raise RuntimeError("Fixture cleanup did not reach authoritative terminal state")
    return receipt



def main() -> None:
    args = parse_args()
    run_fixture_lifecycle(
        args,
        lambda current_args, _adb, _receipt: public_no_update_probe(
            current_args.cli, current_args.serial, current_args.server_log, current_args.probe_output
        ),
    )


if __name__ == "__main__":
    main()
