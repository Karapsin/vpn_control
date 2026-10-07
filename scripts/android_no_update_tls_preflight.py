#!/usr/bin/env python3
"""Reviewed-only disposable Android no-update TLS preflight; never installs a target APK."""
import argparse
import hashlib
import json
import os
import re
import shutil
import shlex
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from android_fixture_preflight import read_effective_proxy, require_disconnected_effective_proxy
from android_fixture_transport import cleanup_fixture_transport, establish_fixture_transport, parse_reverse_inventory
from android_fixture_trust import (
    android_ca_store_filename,
    require_android_ca_store_entry,
    require_android_certificate_store_layout,
    require_device_time_within_certificates,
    secure_private_fixture_files,
    zygote_bind_mount_argv,
)


def bounded_text(value: str, limit: int = 1024) -> str:
    return value[:limit] + ("…" if len(value) > limit else "")


def public_cli_argv(cli: Path) -> list[str]:
    """Run retained Python fixture adapters through Python, but packaged CLIs directly."""
    return [sys.executable, str(cli)] if cli.suffix.lower() == ".py" else [str(cli)]


def public_cli_environment(adb: str, cli: Path, environment=None) -> dict | None:
    """Pin packaged Android CLI children to this lifecycle's approved ADB binary.

    Python fixture adapters do not execute the packaged Desktop Android client, so
    they keep their existing inherited execution behavior. Packaged clients resolve
    a bare ``adb`` at runtime; validate the selected binary before device or fixture
    work, then put only its resolved parent ahead of the child's inherited PATH.
    """
    if cli.suffix.lower() == ".py":
        return None
    selected = Path(adb)
    if not selected.is_absolute():
        raise ValueError("Fixture packaged CLI requires an absolute ADB binary")
    try:
        selected = selected.resolve(strict=True)
    except OSError as error:
        raise ValueError("Fixture ADB binary is unavailable") from error
    if not selected.is_file() or not os.access(selected, os.X_OK):
        raise ValueError("Fixture ADB binary is not executable")
    result = dict(os.environ if environment is None else environment)
    result.pop("DYLD_INSERT_LIBRARIES", None)
    result["PATH"] = str(selected.parent) + os.pathsep + result.get("PATH", os.defpath)
    discovered = shutil.which("adb", path=result["PATH"])
    try:
        approved = discovered is not None and os.path.samefile(discovered, selected)
    except OSError:
        approved = False
    if not approved:
        raise RuntimeError("Fixture packaged CLI ADB path does not select the approved binary")
    return result


def require_interactive_stdin(stream=None) -> None:
    """Reject an interactive lifecycle driver before it can create fixture state."""
    candidate = sys.stdin if stream is None else stream
    if not callable(getattr(candidate, "isatty", None)) or not candidate.isatty():
        raise RuntimeError("INTERACTIVE_STDIN_REQUIRED")


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


def public_no_update_probe(cli: Path, serial: str, server_log: Path, output_path: Path,
                           cli_environment=None) -> dict:
    result = subprocess.run(
        [*public_cli_argv(cli), "--json", "--android", "--serial", serial,
         "--timeout-seconds", "180", "updates", "check"],
        check=False, text=True, capture_output=True, env=cli_environment,
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
CA_STORE_TARGETS = frozenset({
    "/system/etc/security/cacerts",
    "/apex/com.android.conscrypt/cacerts",
})
DISCONNECTED_PROXY_BASELINES = frozenset({"null", ":0"})


def require_ca_store_target(target: str) -> str:
    if target not in CA_STORE_TARGETS:
        raise ValueError("Fixture CA-store target is not approved")
    return target


def require_disconnected_proxy_baseline(proxy: str) -> str:
    if proxy not in DISCONNECTED_PROXY_BASELINES:
        raise ValueError("Fixture proxy baseline is not approved")
    return proxy


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


def require_emulator_avd_name(adb: Adb) -> str:
    """Read both emulator AVD identity properties on every lifecycle admission."""
    kernel = adb.shell("getprop", "ro.kernel.qemu.avd_name")
    boot = adb.shell("getprop", "ro.boot.qemu.avd_name")
    identities = {value for value in (kernel, boot) if value}
    if len(identities) != 1:
        raise RuntimeError("Fixture emulator AVD identity is missing or conflicting")
    return identities.pop()


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



def private_proxy_record(path: Path, value: dict) -> dict:
    """Create a durable private fence; an existing fence is never replayed."""
    payload = (json.dumps(value, sort_keys=True) + "\n").encode()
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parent_info = os.fstat(parent)
        if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) & 0o077:
            raise RuntimeError("Fixture proxy evidence parent must be private")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
            info = os.fstat(stream.fileno())
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (info.st_dev, info.st_ino, info.st_nlink) != (named.st_dev, named.st_ino, 1):
                raise RuntimeError("Fixture proxy evidence generation changed")
        os.fsync(parent)
        named_parent = path.parent.stat(follow_symlinks=False)
        if (named_parent.st_dev, named_parent.st_ino) != (parent_info.st_dev, parent_info.st_ino):
            raise RuntimeError("Fixture proxy evidence parent changed")
        return {"parent": (parent_info.st_dev, parent_info.st_ino),
                "generation": proxy_file_generation(info), "sha256": hashlib.sha256(payload).hexdigest()}
    finally:
        os.close(parent)



def proxy_file_generation(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
            info.st_mode, info.st_uid, info.st_nlink)


def guard_proxy_record(path: Path, pin: dict) -> None:
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(parent)
        if (info.st_dev, info.st_ino) != pin["parent"]:
            raise RuntimeError("Fixture proxy fence parent changed")
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            raw = stream.read(1048577)
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (proxy_file_generation(before) != pin["generation"] or proxy_file_generation(named) != pin["generation"]
                    or proxy_file_generation(os.fstat(stream.fileno())) != pin["generation"]
                    or hashlib.sha256(raw).hexdigest() != pin["sha256"]):
                raise RuntimeError("Fixture proxy fence generation changed")
        named_parent = path.parent.stat(follow_symlinks=False)
        if (named_parent.st_dev, named_parent.st_ino) != pin["parent"]:
            raise RuntimeError("Fixture proxy fence named parent changed")
    finally:
        os.close(parent)


def proxy_source_authority(args) -> dict:
    values = {name: getattr(args, name, None) for name in ("serial", "device_port", "host_port", "base_sha256",
        "expected_avd", "expected_api", "expected_version", "expected_code", "adb", "cli", "target", "staging", "intent")}
    return json.loads(json.dumps(values, sort_keys=True, default=str))


def guard_proxy_evidence(args) -> None:
    if proxy_source_authority(args) != args.proxy_source_authority:
        raise RuntimeError("Fixture proxy source authority changed")
    guard_proxy_record(args.receipt.with_name(args.receipt.name + ".proxy-baseline.json"), args.proxy_baseline_pin)
    if args.proxy_owned_pin is not None:
        guard_proxy_record(args.receipt.with_name(args.receipt.name + ".proxy-owned.json"), args.proxy_owned_pin)

def fixture_proxy_snapshot(adb: Adb) -> dict:
    values = read_effective_proxy(lambda field: adb.shell("settings", "get", "global", field))
    if any(not isinstance(value, str) for value in values.values()):
        raise RuntimeError("Fixture proxy snapshots require exact text")
    return values



def fixture_proxy_presence(adb: Adb, expected: dict) -> dict:
    # `get` renders an absent row as "null". Retain presence separately so
    # restoring an absent host never creates a literal network host "null".
    rows = {}
    for line in adb.shell("settings", "list", "global").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in expected:
            if key in rows:
                raise RuntimeError("Duplicate fixture proxy setting row")
            rows[key] = value
    if any(rows.get(key, "null") != value for key, value in expected.items()):
        raise RuntimeError("Fixture proxy settings presence/readback changed")
    return {key: key in rows for key in expected}

def capture_fixture_proxy(adb: Adb, baseline: dict, baseline_presence: dict, device_port: int, host_port: int) -> tuple[dict, dict]:
    """Capture only the bounded settings derivation of this owned route."""
    if adb.shell_id() != "uid=2000" or adb.reverse_mapping(device_port) != host_port:
        raise RuntimeError("Fixture proxy route ownership changed")
    current = fixture_proxy_snapshot(adb)
    presence = fixture_proxy_presence(adb, current)
    if any(presence[key] != baseline_presence[key] for key in ("global_http_proxy_pac", "global_http_proxy_exclusion_list")):
        raise RuntimeError("Fixture proxy companion presence changed")
    if fixture_proxy_snapshot(adb) != current or fixture_proxy_presence(adb, current) != presence:
        raise RuntimeError("Fixture owned proxy snapshot changed between reads")
    if current == baseline:
        if presence != baseline_presence:
            raise RuntimeError("Fixture proxy baseline presence changed")
        return current, presence
    if (current["http_proxy"] != f"127.0.0.1:{device_port}"
            or current["global_http_proxy_host"] not in (baseline["global_http_proxy_host"], "127.0.0.1")
            or current["global_http_proxy_port"] not in (baseline["global_http_proxy_port"], str(device_port))
            or any(current[key] != baseline[key] for key in ("global_http_proxy_pac", "global_http_proxy_exclusion_list"))):
        raise RuntimeError("Fixture proxy derivation changed")
    return current, presence


def restore_owned_proxy_transport(adb: Adb, args, baseline: dict, owned: dict | None, receipt: dict) -> None:
    if adb.shell_id() != "uid=2000" or adb.reverse_mapping(args.device_port) != args.host_port:
        raise RuntimeError("Fixture proxy cleanup route ownership changed")
    guard_proxy_evidence(args)
    current = fixture_proxy_snapshot(adb)
    if current != baseline and (owned is None or current != owned):
        raise RuntimeError("Fixture proxy cleanup settings ownership changed")
    presence = args.proxy_baseline_presence
    if set(presence) != set(baseline) or any(type(value) is not bool for value in presence.values()):
        raise RuntimeError("Fixture proxy presence baseline missing")
    current_presence = fixture_proxy_presence(adb, current)
    expected_presence = presence if current == baseline else args.proxy_owned_presence
    if current_presence != expected_presence:
        raise RuntimeError("Fixture proxy cleanup row ownership changed")
    binding = {"serial": args.serial, "devicePort": args.device_port, "hostPort": args.host_port,
               "baseSha256": args.base_sha256, "baseline": baseline, "owned": owned,
               "before": current, "sourceAuthority": args.proxy_source_authority, "baselinePresence": presence, "currentPresence": current_presence, "installerIntent": getattr(args, "intent", None)}
    fence = args.receipt.with_name(args.receipt.name + ".proxy-restore-intent.json")
    fence_pin = private_proxy_record(fence, binding)
    guard_proxy_record(fence, fence_pin)
    guard_proxy_evidence(args)
    if adb.reverse_mapping(args.device_port) != args.host_port or fixture_proxy_snapshot(adb) != current or fixture_proxy_presence(adb, current) != current_presence:
        raise RuntimeError("Fixture proxy changed after restoration fence")
    if current != baseline:
        # ADB flattens shell arguments. Quote the complete command so an exact
        # empty-string baseline survives the device shell unchanged.
        progress = current
        progress_presence = current_presence
        for field, value in baseline.items():
            guard_proxy_record(fence, fence_pin)
            guard_proxy_evidence(args)
            if adb.shell_id() != "uid=2000" or adb.reverse_mapping(args.device_port) != args.host_port:
                raise RuntimeError("Fixture proxy route changed during restoration")
            if fixture_proxy_snapshot(adb) != progress or fixture_proxy_presence(adb, progress) != progress_presence:
                raise RuntimeError("Fixture proxy changed during restoration")
            command = ("settings", "put", "global", field, value) if presence[field] else ("settings", "delete", "global", field)
            adb.shell(shlex.join(command))
            updated = fixture_proxy_snapshot(adb)
            if updated[field] != value or any(updated[key] not in (progress[key], baseline[key]) for key in baseline if key != field):
                raise RuntimeError("Fixture proxy write had unexpected settings effects")
            updated_presence = fixture_proxy_presence(adb, updated)
            expected_updated_presence = {**progress_presence, field: presence[field]}
            if updated_presence != expected_updated_presence:
                raise RuntimeError("Fixture proxy write had unexpected row presence effects")
            progress = updated
            progress_presence = updated_presence
    guard_proxy_evidence(args)
    after = fixture_proxy_snapshot(adb)
    receipt["effectiveProxyRestored"] = after
    if after != baseline or fixture_proxy_presence(adb, after) != presence:
        raise RuntimeError("Fixture effective proxy restoration did not match baseline")
    if adb.reverse_mapping(args.device_port) != args.host_port:
        raise RuntimeError("Fixture reverse route changed after proxy restoration")
    guard_proxy_record(fence, fence_pin)
    guard_proxy_evidence(args)
    adb.remove_reverse(args.device_port)
    guard_proxy_evidence(args)

def verify_public_baseline(adb: Adb, cli: Path, serial: str, expected_avd: str, expected_api: str,
                           expected_version: str, expected_code: str, expected_sha256: str,
                           cli_environment=None) -> dict:
    avd = require_emulator_avd_name(adb)
    api = adb.shell("getprop", "ro.build.version.sdk")
    package = adb.shell("dumpsys", "package", "com.kardinal.vpncontrol")
    status = subprocess.run(
        [*public_cli_argv(cli), "--json", "--android", "--serial", serial, "status"],
        check=True, text=True, capture_output=True, env=cli_environment,
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

def run_fixture_lifecycle(args: argparse.Namespace, action, *, target_install: bool = False,
                          ca_store_target: str = "/system/etc/security/cacerts",
                          expected_proxy: str = "null", transport_mode: str = "http-proxy") -> dict:
    if not isinstance(target_install, bool):
        raise ValueError("Fixture target-install metadata must be boolean")
    args.target = require_ca_store_target(ca_store_target)
    expected_proxy = require_disconnected_proxy_baseline(expected_proxy)
    if transport_mode not in ("http-proxy", "reverse-only"):
        raise ValueError("Fixture transport mode is not approved")
    require_task_staging(args.staging)
    cli_environment = getattr(args, "cli_environment", None)
    if cli_environment is None:
        cli_environment = public_cli_environment(args.adb, args.cli)
    args.cli_environment = cli_environment
    frozen_hash = require_artifact_hash(args.base_apk, args.base_sha256)
    adb = Adb(args.adb, args.serial)
    receipt = {"serial": args.serial, "target": args.target, "expectedProxy": expected_proxy,
               "targetInstall": target_install, "cleanupFailures": []}
    previous_proxy = adb.global_proxy()
    effective_proxy = require_disconnected_effective_proxy(
        read_effective_proxy(lambda field: adb.shell("settings", "get", "global", field))
    )
    if (adb.shell_id() != "uid=2000" or adb.reverse_inventory() or previous_proxy != expected_proxy
            or effective_proxy["http_proxy"] != previous_proxy):
        raise RuntimeError("Public no-update preflight requires an unowned public transport baseline")
    receipt["effectiveProxyBaseline"] = effective_proxy
    args.proxy_baseline_presence = fixture_proxy_presence(adb, effective_proxy)
    receipt["effectiveProxyBaselinePresence"] = args.proxy_baseline_presence
    receipt["baseline"] = verify_public_baseline(
        adb, args.cli, args.serial, args.expected_avd, args.expected_api,
        args.expected_version, args.expected_code, args.base_sha256, cli_environment,
    )
    receipt["frozenBaseSha256"] = frozen_hash
    if transport_mode == "http-proxy":
        args.proxy_source_authority = proxy_source_authority(args)
        args.proxy_owned_pin = None
        args.proxy_baseline_pin = private_proxy_record(args.receipt.with_name(args.receipt.name + ".proxy-baseline.json"),
            {"serial": args.serial, "devicePort": args.device_port, "hostPort": args.host_port,
             "baseSha256": frozen_hash, "sourceAuthority": args.proxy_source_authority, "baseline": effective_proxy, "baselinePresence": args.proxy_baseline_presence, "publicBaseline": receipt["baseline"], "installerIntent": getattr(args, "intent", None)})
    secure_private_fixture_files([args.certificate])
    private_mode = stat.S_IMODE(args.fixture_parent.stat().st_mode)
    target_mode, target_label = device_mode(adb, args.target), device_label(adb, args.target)
    device_epoch = int(adb.shell("date", "+%s"))
    require_device_time_within_certificates(device_epoch, args.certificate, args.leaf_certificate)
    receipt.update({"deviceEpoch": device_epoch, "expectedLabel": target_label, "targetMode": oct(target_mode)})
    mounted = False
    mount_attempted = False
    unmounted = False
    transport = False
    reverse_created = False
    proxy_attempted = False
    owned_proxy = None
    primary_failure = False
    rooted = False
    staging_created = False
    try:
        if transport_mode == "http-proxy":
            guard_proxy_evidence(args)
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
        require_android_ca_store_entry(args.certificate, args.staging, staged_certificate)
        if staged_certificate not in staged_files:
            raise RuntimeError("Staged Android CA certificate is not a validated regular file")
        require_android_certificate_store_layout(
            private_mode, device_mode(adb, args.staging), device_mode(adb, staged_certificate),
            device_label(adb, args.staging), target_label,
        )
        if device_label(adb, staged_certificate) != target_label:
            raise RuntimeError("Staged Android CA certificate has an unexpected SELinux label")
        argv = zygote_bind_mount_argv(zygote, args.staging, args.target)
        # An ADB response can be lost after the guest executed this mount.  Do not
        # delete the source staging tree unless we know no bind was attempted.
        mount_attempted = True
        adb.shell(*argv)
        mounted = True
        adb.unroot()
        rooted = False
        adb.wait_for_device()
        if adb.shell_id() != "uid=2000":
            raise RuntimeError("Fixture setup did not restore public adbd")
        if transport_mode == "http-proxy":
            guard_proxy_evidence(args)
            if fixture_proxy_snapshot(adb) != effective_proxy or fixture_proxy_presence(adb, effective_proxy) != args.proxy_baseline_presence or adb.reverse_mapping(args.device_port) is not None:
                raise RuntimeError("Fixture proxy baseline changed before setup")
            adb.reverse(args.device_port, args.host_port)
            reverse_created = True
            proxy_attempted = True
            try:
                adb.set_global_proxy(f"127.0.0.1:{args.device_port}")
            finally:
                owned_proxy, args.proxy_owned_presence = capture_fixture_proxy(adb, effective_proxy, args.proxy_baseline_presence, args.device_port, args.host_port)
                receipt["effectiveProxyOwned"] = owned_proxy
                receipt["effectiveProxyOwnedPresence"] = args.proxy_owned_presence
                args.proxy_owned_pin = private_proxy_record(args.receipt.with_name(args.receipt.name + ".proxy-owned.json"),
                    {"serial": args.serial, "devicePort": args.device_port, "hostPort": args.host_port,
                     "baseSha256": frozen_hash, "sourceAuthority": args.proxy_source_authority, "baseline": effective_proxy, "baselinePresence": args.proxy_baseline_presence, "owned": owned_proxy, "ownedPresence": args.proxy_owned_presence, "installerIntent": getattr(args, "intent", None)})
            guard_proxy_evidence(args)
            transport = True
        else:
            if adb.reverse_mapping(args.device_port) is not None:
                raise RuntimeError("Fixture target reverse route already exists")
            adb.reverse(args.device_port, args.host_port)
            reverse_created = True
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

        if reverse_created and transport_mode == "http-proxy":
            cleanup_attempt("transport" if transport else "partialReverse",
                lambda: restore_owned_proxy_transport(adb, args, effective_proxy, owned_proxy, receipt))
        elif reverse_created:
            def remove_partial_reverse():
                if adb.reverse_mapping(args.device_port) != args.host_port:
                    raise RuntimeError("Partial fixture reverse ownership changed")
                if fixture_proxy_snapshot(adb) != effective_proxy:
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
        if staging_created and (not mount_attempted or unmounted):
            cleanup_attempt("staging", lambda: adb.shell("rm", "-r", args.staging))
        elif staging_created:
            receipt["retainedStaging"] = args.staging
            if mount_attempted and not mounted:
                receipt["unknownMount"] = True
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
            current_args.cli, current_args.serial, current_args.server_log, current_args.probe_output,
            current_args.cli_environment,
        ),
    )


if __name__ == "__main__":
    main()
