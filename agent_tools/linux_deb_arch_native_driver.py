"""Fixed guest package actions for one-shot DEB/Arch acceptance.

This is staged into a root-owned disposable guest only after source, package,
server and owner admission. It accepts no path or executable from its caller.
The host-side MCP route must journal before invoking it and never replay an
unknown native outcome.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Mapping
import uuid


_ROLES = {"ubuntu-fresh": ("fresh-deb-dependencies", "ubuntu"),
          "ubuntu-update": ("package-update", "ubuntu"),
          "arch-update": ("package-update", "arch"),
          "arch-rollback": ("arch-rollback", "arch")}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_VERSION = re.compile(r"[1-9][0-9]*\.[0-9]+\.[0-9]+\Z")
_STAGE_ROOT = Path("/var/lib/vpn-control-parity")
_PROTECTED_JOBS = Path("/var/lib/vpn-control-install-jobs")


class NativeGuestError(ValueError):
    pass


def _sha_staged_file(path: Path, *, max_bytes: int) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or not 0 < info.st_size <= max_bytes):
            raise NativeGuestError("DEB/Arch staged file is unsafe")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(fd, 1024 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise NativeGuestError("DEB/Arch staged file grew")
            digest.update(chunk)
        after = os.fstat(fd)
        if size != info.st_size or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise NativeGuestError("DEB/Arch staged file changed")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _read_small_owned(path: Path, *, max_bytes: int = 65536) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_mode & 0o022 or not 0 < info.st_size <= max_bytes):
            raise NativeGuestError("DEB/Arch staged metadata is unsafe")
        data = os.read(fd, max_bytes + 1)
        after = os.fstat(fd)
        if len(data) != info.st_size or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise NativeGuestError("DEB/Arch staged metadata changed")
        return data
    finally:
        os.close(fd)


def _stage(role: str) -> Path:
    if role not in _ROLES:
        raise NativeGuestError("DEB/Arch guest role is unknown")
    path = _STAGE_ROOT / role
    for candidate in (Path("/var"), Path("/var/lib"), _STAGE_ROOT, path):
        info = candidate.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise NativeGuestError("DEB/Arch guest stage ancestry is unsafe")
    return path


def _guest_quiet(proc: Path = Path("/proc")) -> bool:
    """Fail closed on a live owner, runtime, package manager, or unreadable PID."""
    ancestors: set[int] = set()
    current = os.getpid()
    while current > 1 and current not in ancestors:
        ancestors.add(current)
        try:
            fields = (proc / str(current) / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()
            current = int(fields[1])
        except (OSError, IndexError, ValueError):
            return False
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) in ancestors:
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            if not raw:  # Kernel thread with no executable argv.
                continue
            if len(raw) > 8192:
                return False
            executable = os.readlink(entry / "exe")
        except OSError:
            if entry.exists():
                return False
            continue
        parts = raw.rstrip(b"\0").split(b"\0")
        first = os.path.basename(parts[0]).decode("ascii", "replace")
        if (executable.startswith("/opt/vpn-control/") or os.path.basename(executable) == "sing-box"
                or first in {"sing-box", "apt", "apt-get", "dpkg", "pacman", "packagekitd"}
                or any(part.startswith(b"/opt/vpn-control/") and b"\n" not in part
                       for part in parts)):
            return False
    jobs = _PROTECTED_JOBS
    try:
        try:
            info = jobs.lstat()
        except FileNotFoundError:
            info = None
        if info is not None:
            if not stat.S_ISDIR(info.st_mode) or any(jobs.iterdir()):
                return False
    except OSError:
        return False
    return True


def _claim(role: str, correlation: str) -> None:
    root = Path.home() / ".vpn-control-parity-jobs"
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise NativeGuestError("DEB/Arch guest journal is unsafe")
    raw = (json.dumps({"guestRole": role, "correlationId": correlation}, sort_keys=True) + "\n").encode()
    fd = os.open(root / (role + ".claim"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _request(raw: Mapping[str, Any]) -> dict[str, Any]:
    required = {"profile", "distribution", "guestRole", "correlationId", "sourceSha",
                "sourceFingerprint", "targetVersion", "targetSha256",
                "fixtureReceiptArtifactId", "trustStoreSha256", "harnessSha256"}
    if not isinstance(raw, Mapping) or set(raw) != required:
        raise NativeGuestError("DEB/Arch guest intent is invalid")
    role = raw["guestRole"]
    try:
        canonical = isinstance(raw["correlationId"], str) and str(uuid.UUID(raw["correlationId"])) == raw["correlationId"]
    except ValueError:
        canonical = False
    if (not isinstance(role, str) or role not in _ROLES
            or (raw["profile"], raw["distribution"]) != _ROLES[role]
            or not canonical
            or not isinstance(raw["sourceSha"], str) or not re.fullmatch(r"[0-9a-f]{40}", raw["sourceSha"])
            or not isinstance(raw["sourceFingerprint"], str) or not _HASH.fullmatch(raw["sourceFingerprint"])
            or not isinstance(raw["targetSha256"], str) or not _HASH.fullmatch(raw["targetSha256"])
            or not isinstance(raw["fixtureReceiptArtifactId"], str)
            or raw["fixtureReceiptArtifactId"][:7] != "sha256-"
            or not _HASH.fullmatch(raw["fixtureReceiptArtifactId"][7:])
            or (raw["trustStoreSha256"] is not None
                and (not isinstance(raw["trustStoreSha256"], str)
                     or not _HASH.fullmatch(raw["trustStoreSha256"])))
            or (raw["harnessSha256"] is not None
                and (not isinstance(raw["harnessSha256"], str)
                     or not _HASH.fullmatch(raw["harnessSha256"])))
            or not isinstance(raw["targetVersion"], str) or not _VERSION.fullmatch(raw["targetVersion"])):
        raise NativeGuestError("DEB/Arch guest intent identity is invalid")
    if (raw["profile"] == "fresh-deb-dependencies") != (raw["trustStoreSha256"] is None):
        raise NativeGuestError("DEB/Arch guest trust identity differs")
    if (raw["profile"] == "fresh-deb-dependencies") != (raw["harnessSha256"] is None):
        raise NativeGuestError("DEB/Arch guest harness identity differs")
    return dict(raw)


def _packages(runner: Any) -> dict[str, str]:
    result = runner(["dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Abbrev}\t${Version}\n"],
                    capture_output=True, text=True, timeout=30, check=False)
    if result.returncode != 0:
        raise NativeGuestError("DEB package inventory is unavailable")
    packages = {}
    for line in result.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 3:
            raise NativeGuestError("DEB package inventory is malformed")
        if fields[1].startswith("ii"):
            packages[fields[0]] = fields[2]
    return packages


def _fresh_deb(intent: Mapping[str, Any], stage: Path, runner: Any) -> dict[str, Any]:
    target = stage / "target.deb"
    if _sha_staged_file(target, max_bytes=1_000_000_000) != intent["targetSha256"]:
        raise NativeGuestError("Fresh DEB package bytes differ")
    before = _packages(runner)
    absent = "xdg-utils" not in before
    directory_absent = not Path("/usr/share/desktop-directories").exists()
    audit = runner(["dpkg", "--audit"], capture_output=True, text=True, timeout=30, check=False)
    if (not absent or not directory_absent or audit.returncode != 0 or audit.stdout.strip()
            or "vpn-control" in before):
        raise NativeGuestError("Fresh DEB prerequisite baseline differs")
    installed = runner(["sudo", "-n", "apt-get", "install", "-y", "--", str(target)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900, check=False)
    after = _packages(runner)
    audit_after = runner(["dpkg", "--audit"], capture_output=True, text=True, timeout=30, check=False)
    added = set(after) - set(before)
    only_added = added <= {"vpn-control", "xdg-utils"} and {"vpn-control", "xdg-utils"} <= added
    unchanged = all(after.get(name) == version for name, version in before.items())
    version = runner(["/opt/vpn-control/bin/vpn-control", "--version"],
                     capture_output=True, text=True, timeout=30, check=False)
    return {"exitCode": installed.returncode, "packageTransaction": {
        "manager": "apt", "exitCode": installed.returncode, "beforeXdgUtilsAbsent": absent,
        "beforeDesktopDirectoryAbsent": directory_absent, "afterXdgUtilsInstalled": "xdg-utils" in after,
        "afterDesktopDirectoryPresent": Path("/usr/share/desktop-directories").is_dir(),
        "dpkgAuditClean": audit_after.returncode == 0 and not audit_after.stdout.strip(),
        "onlyExpectedPackagesAdded": only_added and unchanged},
        "launcherVersionMatched": version.returncode == 0 and version.stdout.strip() == intent["targetVersion"]}


def _json_objects(raw: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    values = []
    offset = 0
    while offset < len(raw):
        while offset < len(raw) and raw[offset].isspace():
            offset += 1
        if offset >= len(raw):
            break
        value, offset = decoder.raw_decode(raw, offset)
        if not isinstance(value, dict):
            raise NativeGuestError("DEB/Arch harness output is not an object")
        values.append(value)
        if len(values) > 2:
            raise NativeGuestError("DEB/Arch harness output is ambiguous")
    return values


def _update_setup(intent: Mapping[str, Any], stage: Path) -> tuple[list[str], dict[str, str]]:
    package = stage / ("target.deb" if intent["distribution"] == "ubuntu" else "target.tar.gz")
    if _sha_staged_file(package, max_bytes=1_000_000_000) != intent["targetSha256"]:
        raise NativeGuestError("DEB/Arch update package bytes differ")
    receipt = json.loads(_read_small_owned(stage / "fixture-receipt.json", max_bytes=262144))
    ready = json.loads(_read_small_owned(stage / "public-fixture.json"))
    if (receipt.get("sourceFingerprint") != intent["sourceFingerprint"]
            or receipt.get("derivedFrom", {}).get("derivedFromArtifactId") != intent["fixtureReceiptArtifactId"]
            or ready.get("sourceFingerprint") != intent["sourceFingerprint"]
            or type(ready.get("port")) is not int or not 1 <= ready["port"] <= 65535):
        raise NativeGuestError("DEB/Arch fixture server identity differs")
    if _sha_staged_file(stage / "trust.jks", max_bytes=65536) != intent.get("trustStoreSha256"):
        raise NativeGuestError("DEB/Arch fixture trust store differs")
    harness = stage / "scripts/test_linux_public_install.py"
    scripts = harness.parent.lstat()
    if not stat.S_ISDIR(scripts.st_mode) or scripts.st_uid != 0 or scripts.st_mode & 0o022:
        raise NativeGuestError("DEB/Arch harness stage is unsafe")
    if _sha_staged_file(harness, max_bytes=1_000_000) != intent["harnessSha256"]:
        raise NativeGuestError("DEB/Arch harness bytes differ")
    argv = ["python3", "-B", str(harness), "--launcher", "/opt/vpn-control/bin/vpn-control",
            "--expected-target-version", intent["targetVersion"], "--confirm-owned-disposable-vm",
            "--require-same-source-recovery", "--retained-fixture-auth"]
    if intent["distribution"] == "arch":
        argv.extend(("--arch-source-fixture", str(stage)))
    environment = dict(os.environ)
    for inherited in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        environment.pop(inherited, None)
    environment["JAVA_TOOL_OPTIONS"] = (f"-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort={ready['port']} "
                                        f"-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort={ready['port']} "
                                        f"-Djavax.net.ssl.trustStore={stage / 'trust.jks'} "
                                        "-Djavax.net.ssl.trustStorePassword=changeit")
    return argv, environment


def _update(intent: Mapping[str, Any], stage: Path, runner: Any) -> dict[str, Any]:
    argv, environment = _update_setup(intent, stage)
    completed = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                       env=environment, timeout=1500, check=False)
    if len(completed.stdout) > 1_000_000 or len(completed.stderr) > 65536:
        raise NativeGuestError("DEB/Arch harness output exceeded bounds")
    values = _json_objects(completed.stdout)
    if len(values) != 2 or not isinstance(values[0].get("evidence"), str):
        raise NativeGuestError("DEB/Arch harness result is incomplete")
    result = values[1]
    if (result.get("targetVersion") != intent["targetVersion"]
            or result.get("sourceFingerprint") != intent["sourceFingerprint"]):
        raise NativeGuestError("DEB/Arch harness result source differs")
    return {**result, "exitCode": completed.returncode}


def _rollback(intent: Mapping[str, Any], stage: Path, runner: Any,
              *, trace_factory: Any = None, evidence_reader: Any = None) -> dict[str, Any]:
    if intent["guestRole"] != "arch-rollback" or intent["distribution"] != "arch":
        raise NativeGuestError("Arch rollback role differs")
    argv, environment = _update_setup(intent, stage)
    scripts = stage / "scripts"
    if not stat.S_ISDIR(scripts.lstat().st_mode):
        raise NativeGuestError("Arch rollback verifier stage is unsafe")
    sys.path.insert(0, str(scripts))
    try:
        import arch_public_update
    finally:
        sys.path.pop(0)
    if Path(arch_public_update.__file__).resolve() != (scripts / "arch_public_update.py").resolve():
        raise NativeGuestError("Arch rollback verifier module differs")
    verify_arch_bundle_base = arch_public_update.verify_arch_bundle_base
    try:
        from .linux_deb_arch_rollback import (MoveTrace, _accepted, _evidence_path,
                                              _protected, _recover_owner, classify_move_trace)
    except ImportError:  # guest executes the staged file directly
        from linux_deb_arch_rollback import (MoveTrace, _accepted, _evidence_path,
                                             _protected, _recover_owner, classify_move_trace)
    trace_factory = trace_factory or MoveTrace
    evidence_reader = evidence_reader or _evidence_path
    launcher = Path("/opt/vpn-control/bin/vpn-control")
    before = verify_arch_bundle_base(launcher, stage)
    if before.get("sourceFingerprint") != intent["sourceFingerprint"]:
        raise NativeGuestError("Arch rollback installed base differs from source fixture")
    icon = Path("/usr/share/icons/hicolor/256x256/apps/vpn-control.png")
    icon_info = icon.lstat()
    if not stat.S_ISREG(icon_info.st_mode) or icon_info.st_uid != 0:
        raise NativeGuestError("Arch rollback fault target is unsafe")
    attributes = runner(["lsattr", "-d", str(icon)], capture_output=True, text=True, timeout=30, check=False)
    if attributes.returncode != 0 or "i" in attributes.stdout.split()[0]:
        raise NativeGuestError("Arch rollback fault target has unexpected attributes")
    trace = trace_factory()
    try:
        injected = runner(["sudo", "-n", "/usr/bin/chattr", "+i", str(icon)],
                          capture_output=True, text=True, timeout=120, check=False)
    except Exception:
        trace.close()
        raise
    if injected.returncode != 0:
        trace.close()
        raise NativeGuestError("Arch rollback fault injection failed")
    try:
        completed = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                           env=environment, timeout=1500, check=False)
        if completed.returncode == 0 or len(completed.stdout) > 1_000_000:
            raise NativeGuestError("Arch rollback did not produce failed public install")
        evidence = evidence_reader(completed.stdout)
        accepted = _accepted(evidence)
        protected = _protected(accepted["data"]["jobId"])
    except Exception:
        trace.close()
        # Preserve the injected fault while the protected outcome is unknown.
        raise
    cleared = runner(["sudo", "-n", "/usr/bin/chattr", "-i", str(icon)],
                     capture_output=True, text=True, timeout=120, check=False)
    observed_trace = trace.close()
    if cleared.returncode != 0:
        raise NativeGuestError("Arch rollback fault cleanup is unknown")
    restored_attributes = runner(["lsattr", "-d", str(icon)], capture_output=True, text=True,
                                 timeout=30, check=False)
    if restored_attributes.returncode != 0 or restored_attributes.stdout != attributes.stdout:
        raise NativeGuestError("Arch rollback original icon attributes differ")
    classified = classify_move_trace(observed_trace)
    if classified.get("inodeTraceMatched") is not True:
        raise NativeGuestError("Arch rollback kernel move trace differs")
    after = verify_arch_bundle_base(launcher, stage)
    if after != before:
        raise NativeGuestError("Arch rollback installed base differs after failure")
    if (icon.lstat().st_dev, icon.lstat().st_ino) != (icon_info.st_dev, icon_info.st_ino):
        raise NativeGuestError("Arch rollback original icon inode differs")
    recovery = _recover_owner(evidence, accepted, protected, runner)
    return {"exitCode": completed.returncode, "accepted": accepted,
            "protectedReceipt": protected, "replacementRecoveryObservation": recovery,
            "rollback": {"baseTreeRestored": True, "failedReplacementRemoved": True,
                         "inodeTraceMatched": True}, "targetVersion": intent["targetVersion"],
            "sourceFingerprint": intent["sourceFingerprint"]}


def fixed_guest_action(raw: Mapping[str, Any], *, runner: Any = subprocess.run) -> dict[str, Any]:
    """Run one fixed native case; caller must supply an already journaled intent."""
    intent = _request(raw)
    if os.getuid() == 0:
        raise NativeGuestError("DEB/Arch public guest action requires vpnfixture")
    stage = _stage(intent["guestRole"])
    stored = json.loads(_read_small_owned(stage / "worker-intent.json", max_bytes=8192))
    if stored != intent:
        raise NativeGuestError("DEB/Arch guest intent differs from root-owned stage")
    if not _guest_quiet():
        raise NativeGuestError("DEB/Arch guest owner, runtime, package process, or job is active")
    _claim(intent["guestRole"], intent["correlationId"])
    if intent["profile"] == "fresh-deb-dependencies":
        return _fresh_deb(intent, stage, runner)
    if intent["profile"] == "package-update":
        return _update(intent, stage, runner)
    if intent["profile"] == "arch-rollback":
        return _rollback(intent, stage, runner)
    raise NativeGuestError("DEB/Arch guest profile is unavailable")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-json", required=True)
    parser.add_argument("--confirm-owned-disposable-guest", action="store_true")
    args = parser.parse_args()
    if not args.confirm_owned_disposable_guest:
        raise NativeGuestError("Disposable guest confirmation is absent")
    intent = json.loads(args.run_json)
    result = fixed_guest_action(intent)
    print("VPN_PARITY_RESULT=" + json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
