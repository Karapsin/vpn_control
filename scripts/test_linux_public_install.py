#!/usr/bin/env python3
"""DESTRUCTIVE TO THE INSTALLED APP: run ONLY in an owned disposable Linux VM.

Uses the installed public launcher and unchanged production update URL/trust/hash
checks. Keeps evidence and never kills a package manager, installer, or owner.
Run from a controlling TTY as the ordinary VM user; enter polkit credentials at
the native prompt. No credentials are accepted as arguments or written to logs.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time
import uuid

from prepare_desktop_update_fixture import image_identity


def timed_update_command(action, seconds):
    return ("--timeout-seconds", str(seconds), "updates", action)


def require(value, message):
    if not value:
        raise RuntimeError(message)


def protected_receipt(job):
    require(str(uuid.UUID(job)) == job, "Noncanonical job identity")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in ("var", "lib", "vpn-control-install-jobs", job):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            info = os.fstat(descriptor)
            require(info.st_uid == 0 and not info.st_mode & 0o022, "Untrusted protected receipt ancestry")
        leaf = os.open("status.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            info = os.fstat(leaf)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o022, "Untrusted protected receipt")
            raw = os.read(leaf, 4097)
            require(len(raw) <= 4096, "Receipt exceeds bound")
            result = json.loads(raw)
            require(result.get("jobId") == job and result.get("version") == 1, "Receipt identity mismatch")
            return result
        finally:
            os.close(leaf)
    finally:
        os.close(descriptor)


def verify_recovered_install(accepted, receipt, recovery):
    require(receipt.get("phase") == "SUCCEEDED" and receipt.get("code") == "OK"
            and receipt.get("jobId") == accepted.get("data", {}).get("jobId"), "Missing correlated protected success")
    require(recovery.get("ok") is True and recovery.get("code") == "OK" and recovery.get("final") is True,
            "Replacement owner did not recover terminal installation success")
    require(recovery.get("operationId") == accepted.get("operationId") and recovery.get("controllerId")
            and recovery["controllerId"] != accepted.get("controllerId"), "Recovery must belong to the new owner and exact operation")
    data = recovery.get("data", {})
    require(data.get("jobId") == receipt["jobId"] and data.get("originControllerId") == accepted.get("controllerId")
            and data.get("originRequestId") == accepted.get("requestId"), "Recovery correlation differs from the accepted handoff")


def installed_debian_packages():
    result = subprocess.run(["dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Abbrev}\t${Version}\n"],
                            capture_output=True, text=True, timeout=30, check=True)
    return {fields[0]: fields[2] for line in result.stdout.splitlines()
            if len(fields := line.split("\t")) == 3 and fields[1].startswith("ii")}


def require_package_managed_launcher(launcher):
    """Reject a copied fixture image before it can be counted as an update recovery."""
    checks = (
        (["dpkg-query", "--search", str(launcher)], r"(?m)^vpn-control(?::[^\s:]+)?:\s"),
        (["rpm", "--query", "--file", "--queryformat", "%{NAME}\\n", str(launcher)], r"\Avpn-control\n?\Z"),
        (["pacman", "--query", "--owns", "--quiet", str(launcher)], r"\Avpn-control\n?\Z"),
    )
    unavailable = 0
    for command, expected in checks:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        except FileNotFoundError:
            unavailable += 1
            continue
        if result.returncode == 0 and re.search(expected, result.stdout):
            return
    require(unavailable != len(checks), "No supported Linux package ownership query is available")
    raise RuntimeError("Same-source recovery requires the base launcher to be owned by vpn-control package metadata")


def launch_fixture_owner(launcher, workspace, log, environment):
    # Keep the owner's lifetime independent of the native-prompt driver's
    # controlling session. The CLI still registers its exact-owner tty agent.
    return subprocess.Popen([str(launcher), "--state-dir", str(workspace), "serve"],
                            stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=environment,
                            start_new_session=True)


def run(launcher, target_version, confirmed, same_source_recovery=False, fresh_deb_dependencies=False):
    require(confirmed and os.uname().sysname == "Linux" and os.getuid() != 0,
            "Explicit owned-disposable-VM confirmation and non-root Linux user required")
    with open("/dev/tty", "rb"):
        pass
    launcher = launcher.resolve(strict=True)
    marker = launcher.parent.parent / "TEST-ONLY-INSTALL-FIXTURE.json"
    fixture = json.loads(marker.read_text())
    require(fixture.get("testOnly") is True and fixture.get("productionTrustChanged") is False,
            "Requires the marked metadata-only cloned app image, installed root-owned in the VM")
    require(launcher.read_bytes()[:4] == b"\x7fELF", "Requires the native packaged launcher")
    for path in (launcher, *launcher.parents):
        info = path.stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, "Installed image ancestry must be root-owned/non-writable")
    if same_source_recovery:
        require(fixture.get("sameSourceBuild") is True and len(fixture.get("sourceFingerprint", "")) == 64,
                "Same-source recovery requires the property-built immutable source fixture")
        require(image_identity(launcher.parent.parent, fixture["version"]) ==
                {key: fixture[key] for key in ("codeFingerprint", "mainJar", "mainJarSha256")}, "Installed base image differs from source fixture")
        require_package_managed_launcher(launcher)
    before_packages = None
    if fresh_deb_dependencies:
        before_packages = installed_debian_packages()
        require("xdg-utils" not in before_packages and not Path("/usr/share/desktop-directories").exists(),
                "Fresh dependency evidence requires absent xdg-utils and desktop-directories before the public install")
        audit = subprocess.run(["dpkg", "--audit"], capture_output=True, text=True, timeout=30, check=True)
        require(not audit.stdout.strip(), "Use a fresh guest with no interrupted package configuration")
    evidence = Path(tempfile.mkdtemp(prefix="vpn-public-install-evidence-"))
    workspace = evidence / "workspace"
    print(json.dumps({"evidence": str(evidence), "workspace": str(workspace)}), flush=True)
    environment = dict(os.environ)
    environment.pop("DISPLAY", None)
    environment.pop("WAYLAND_DISPLAY", None)
    count = 0

    def invoke(*arguments, seconds=90):
        nonlocal count
        count += 1
        out = evidence / f"cli-{count}.json"
        err = evidence / f"cli-{count}.stderr"
        with out.open("wb") as stdout, err.open("wb") as stderr:
            process = subprocess.Popen([str(launcher), "--state-dir", str(workspace), "--json", *arguments],
                                       stdout=stdout, stderr=stderr, env=environment)
        try:
            process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"CLI timeout; retained process {process.pid}, evidence {evidence}; outcome UNKNOWN") from None
        (evidence / f"cli-{count}.exit").write_text(str(process.returncode) + "\n")
        require(out.stat().st_size <= 1024 * 1024 and err.stat().st_size <= 65536, "CLI output exceeds bound")
        result = json.loads(out.read_text())
        require(result.get("schemaVersion") == 1, "Invalid public result envelope")
        return process.returncode, result

    def ok(*arguments, seconds=90):
        exit_code, result = invoke(*arguments, seconds=seconds)
        require(exit_code == 0 and result.get("code") == "OK" and result.get("final") is True,
                f"Public command failed: {arguments}: {result}")
        return result

    def start_owner():
        with (evidence / f"serve-{time.time_ns()}.log").open("wb") as log:
            process = launch_fixture_owner(launcher, workspace, log, environment)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            require(process.poll() is None, "Fixture owner exited before activation")
            if (workspace / "activation.port").exists():
                return process
            time.sleep(0.1)
        raise RuntimeError("Fixture owner readiness timeout; processes/evidence retained")

    owner = start_owner()
    baseline = ok("status")
    require(baseline["data"].get("runtimeRunning") is False, "Synthetic workspace unexpectedly connected")
    ok("updates", "check", seconds=180)
    checked = ok("updates", "status")["data"]
    require(checked.get("available") is True and checked.get("compatible") is True
            and checked.get("availableVersion") == target_version,
            f"No newer trusted matching asset for the specified version/VM architecture: {checked}")
    ok(*timed_update_command("download", 600), seconds=630)
    require(ok("updates", "status")["data"].get("phase") == "ready", "Download did not become verified/ready")
    exit_code, accepted = invoke(*timed_update_command("install", 240), seconds=270)
    require(exit_code == 0 and accepted.get("code") == "ACCEPTED" and accepted.get("final") is False
            and accepted.get("data", {}).get("handoffReady") is True,
            f"Installation not handed off; preserve evidence and inspect before retry: {accepted}")
    job = accepted["data"]["jobId"]
    operation = accepted["operationId"]
    require(str(uuid.UUID(operation)) == operation, "Missing durable operation identity")
    owner.wait(timeout=30)
    # Never hold an app admission lock while waiting for replacement, and never kill the installer.
    deadline = time.monotonic() + 600
    receipt = None
    while time.monotonic() < deadline:
        try:
            receipt = protected_receipt(job)
        except FileNotFoundError:
            pass
        if receipt and receipt.get("phase") in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
        time.sleep(0.5)
    require(receipt and receipt.get("phase") == "SUCCEEDED" and receipt.get("code") == "OK",
            f"No protected installation success; do not retry/kill pending worker: {receipt}")
    version = subprocess.run([str(launcher), "--version"], capture_output=True, text=True, timeout=30)
    require(version.returncode == 0 and target_version in version.stdout, "Replacement does not report target product version")
    # A published old replacement is separate evidence. The source-matched path
    # requires exact next-owner correlation; missing support cannot count as OK.
    try:
        exit_code, recovery = invoke("operations", "status", operation)
    except (RuntimeError, ValueError) as error:
        recovery = {"unavailable": str(error)}
    if same_source_recovery:
        require(image_identity(launcher.parent.parent, target_version)["codeFingerprint"] == fixture["codeFingerprint"],
                "Replacement code differs from the frozen source pair")
        verify_recovered_install(accepted, receipt, recovery)
    dependency_evidence = None
    if fresh_deb_dependencies:
        after_packages = installed_debian_packages()
        require("xdg-utils" in after_packages and Path("/usr/share/desktop-directories").is_dir(),
                "The package transaction did not acquire/register desktop prerequisites")
        require(all(name in after_packages for name in before_packages), "The package transaction removed an existing package")
        dependency_evidence = {"installed": {name: value for name, value in after_packages.items() if name not in before_packages},
                               "changed": {name: [before_packages[name], value] for name, value in after_packages.items()
                                           if name in before_packages and before_packages[name] != value}}
    result = {"productionTrustedInstallSucceeded": True, "targetVersion": target_version,
              "accepted": accepted, "protectedReceipt": receipt, "replacementRecoveryObservation": recovery,
              "sameSourceRecoveryProven": same_source_recovery, "sourceFingerprint": fixture.get("sourceFingerprint"),
              "freshDependencyEvidence": dependency_evidence, "evidence": str(evidence)}
    (evidence / "install-result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--expected-target-version", required=True)
    parser.add_argument("--confirm-owned-disposable-vm", action="store_true")
    parser.add_argument("--require-same-source-recovery", action="store_true")
    parser.add_argument("--require-fresh-deb-dependencies", action="store_true")
    args = parser.parse_args()
    run(args.launcher, args.expected_target_version, args.confirm_owned_disposable_vm,
        args.require_same_source_recovery, args.require_fresh_deb_dependencies)
