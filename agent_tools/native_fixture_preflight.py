"""Typed, read-only admission checks for the fixed native scenario adapters.

Each requirement states its evidence scope.  A caller's assertion is never a
substitute for a local byte check or a current configured-host observation.
This module does not start a scenario, read a secret, or change a guest.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import re
import stat
import json
import subprocess
import tempfile
from typing import Any, Callable, Mapping

try:
    from . import ssh_transport
except ImportError:  # CLI fallback
    import ssh_transport  # type: ignore[no-redef]


Dispatch = Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]]
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ARTIFACT = re.compile(r"^sha256-([0-9a-f]{64})$")
_SCENARIOS = {
    "linux-public-update-preflight": frozenset({"host", "environment", "bundleManifestArtifactId"}),
    "linux-scheduled-refresh": frozenset({"host", "environment", "bundleManifestArtifactId",
                                           "scenarioInputArtifactId", "scenarioCorrelationId"}),
    "linux-scheduled-refresh-fixture-ready": frozenset({"host", "environment", "expectedTestUrl"}),
    "windows-credential-validity-v1": frozenset({"host", "environment"}),
}
_FIELDS = ("artifact", "bundle", "host", "fixtureRoot", "vmIdentity", "credentialInput",
           "scenarioInput", "package", "desktopJar", "protectedOwner", "ownedWorkspace", "endpoint", "certificate",
           "settings", "benchmarkSettings", "workspace", "protocol", "prompt")
_RELATIVE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,191}$")


class NativeFixturePreflightError(ValueError):
    pass


def _request(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or value.get("scenarioId") not in _SCENARIOS:
        raise NativeFixturePreflightError("Fixture scenario is not allowlisted.")
    required = _SCENARIOS[value["scenarioId"]]
    optional = {"timeoutSeconds"}
    if value["scenarioId"] == "linux-scheduled-refresh-fixture-ready":
        optional.add("certificateRelativePath")
    if not required | {"scenarioId"} <= set(value) or set(value) - required - {"scenarioId"} - optional:
        raise NativeFixturePreflightError("Fixture preflight fields do not match the scenario contract.")
    result = dict(value)
    for field in ("host", "environment"):
        if not isinstance(result[field], str) or not _TOKEN.fullmatch(result[field]):
            raise NativeFixturePreflightError(f"Fixture {field} is invalid.")
    for field in ("bundleManifestArtifactId", "scenarioInputArtifactId"):
        if field in result and (not isinstance(result[field], str) or not _ARTIFACT.fullmatch(result[field])):
            raise NativeFixturePreflightError(f"Fixture {field} is invalid.")
    if result["scenarioId"] == "linux-scheduled-refresh-fixture-ready":
        url = result["expectedTestUrl"]
        if not isinstance(url, str) or len(url) > 2048 or not url.startswith("https://") or any(ord(char) < 32 for char in url):
            raise NativeFixturePreflightError("Expected validation URL must use HTTPS.")
        relative = result.get("certificateRelativePath")
        if relative is not None and (not isinstance(relative, str) or not _RELATIVE.fullmatch(relative)
                                     or any(part in ("", ".", "..") for part in relative.split("/"))):
            raise NativeFixturePreflightError("Fixture certificate path is unsafe.")
    if result["scenarioId"] == "linux-scheduled-refresh":
        if not isinstance(result["scenarioCorrelationId"], str) or not _TOKEN.fullmatch(result["scenarioCorrelationId"]):
            raise NativeFixturePreflightError("Fixture scenario correlation is invalid.")
    timeout = result.get("timeoutSeconds", 15)
    if type(timeout) is not int or not 3 <= timeout <= 30:
        raise NativeFixturePreflightError("Fixture timeoutSeconds must be an integer from 3 through 30.")
    result["timeoutSeconds"] = timeout
    return result


def _requirement(state: str, reason: str, scope: str) -> dict[str, str]:
    return {"state": state, "reason": reason, "evidenceScope": scope}


def _call(dispatcher: Dispatch, surface: str, action: str, inputs: Mapping[str, Any]) -> Mapping[str, Any] | None:
    try:
        result = dispatcher(surface, action, inputs)
        return result if isinstance(result, Mapping) else None
    except Exception:
        return None


def _configured(root: Path, host: str) -> Any | None:
    try:
        return ssh_transport.load_config(root).hosts.get(host)
    except (OSError, ValueError):
        return None


def _private_nonempty_file(path: Path, *, maximum: int) -> bool:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= maximum)
        finally:
            os.close(fd)
    except OSError:
        return False


def _remote_linux_refresh(root: Path, host: str, expected_url: str, timeout: int,
                          certificate: PurePosixPath | None) -> Mapping[str, Any] | None:
    """Run only the checked-in read-only guest probe over configured SSH."""
    try:
        config = ssh_transport.load_config(root)
        source = (root / "scripts" / "native_fixture_preflight.py").read_text(encoding="utf-8")
        command = ["python3", "-c", f"exec({source!r})", "--expected-url", expected_url,
                   "--timeout", str(min(timeout, 15))]
        if certificate is not None:
            command.extend(("--certificate", str(certificate)))
        argv = ssh_transport.build_ssh_argv(config, host, timeout, command=command)
        connection = ssh_transport.connection_host(config, host)
        def run(environment: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=environment,
                                  timeout=timeout + 2, check=False)
        if connection.password is not None:
            with tempfile.TemporaryDirectory(prefix="vpn-control-fixture-preflight-") as temporary:
                _, environment = ssh_transport._askpass_environment(connection.password, Path(temporary))
                done = run(environment)
        else:
            done = run()
        if done.returncode not in (0, 1) or len(done.stdout) > 4096:
            return None
        value = json.loads(done.stdout.decode("utf-8"))
        if (not isinstance(value, dict) or value.get("profile") != "linux-scheduled-refresh"
                or not isinstance(value.get("checks"), dict)
                or set(value["checks"]) != {"workspace", "settings", "benchmarkSettings", "protocol", "certificate", "endpoint"}
                or any(type(item) is not bool for item in value["checks"].values())):
            return None
        return value
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.TimeoutExpired):
        return None


def _remote_linux_static(root: Path, host: str, input_bytes: bytes, timeout: int) -> Mapping[str, Any] | None:
    """Probe installed package/JAR and protected owner using a fixed guest helper."""
    try:
        config = ssh_transport.load_config(root)
        source = (root / "scripts" / "native_fixture_preflight.py").read_text(encoding="utf-8")
        argv = ssh_transport.build_ssh_argv(config, host, timeout,
            command=("python3", "-c", f"exec({source!r})", "--static-admission"))
        connection = ssh_transport.connection_host(config, host)
        def run(environment: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(argv, input=input_bytes, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=environment, timeout=timeout + 2, check=False)
        if connection.password is not None:
            with tempfile.TemporaryDirectory(prefix="vpn-control-fixture-static-") as temporary:
                _, environment = ssh_transport._askpass_environment(connection.password, Path(temporary))
                done = run(environment)
        else:
            done = run()
        if done.returncode not in (0, 1) or len(done.stdout) > 1024:
            return None
        value = json.loads(done.stdout.decode("utf-8"))
        if (not isinstance(value, dict) or value.get("profile") != "linux-scheduled-refresh-static"
                or not isinstance(value.get("checks"), dict)
                or set(value["checks"]) != {"package", "desktopJar", "protectedOwner", "ownedWorkspace"}
                or any(type(item) is not bool for item in value["checks"].values())):
            return None
        return value
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.TimeoutExpired):
        return None


_REMOTE_ROOT = """import json,os,stat,sys
try:
 path=sys.argv[1]
 info=os.stat(path,follow_symlinks=False)
 ready=stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700
 print(json.dumps({'ready':ready},separators=(',',':')))
except Exception:
 print(json.dumps({'ready':False},separators=(',',':')))
"""


def _remote_root_status(root: Path, host: str, remote_root: PurePosixPath, timeout: int) -> bool | None:
    try:
        config = ssh_transport.load_config(root)
        argv = ssh_transport.build_ssh_argv(config, host, timeout,
            command=("python3", "-c", f"exec({_REMOTE_ROOT!r})", str(remote_root)))
        connection = ssh_transport.connection_host(config, host)
        def run(environment: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, env=environment, timeout=timeout + 2, check=False)
        if connection.password is not None:
            with tempfile.TemporaryDirectory(prefix="vpn-control-fixture-root-") as temporary:
                _, environment = ssh_transport._askpass_environment(connection.password, Path(temporary))
                done = run(environment)
        else:
            done = run()
        if done.returncode or len(done.stdout) > 128:
            return None
        value = json.loads(done.stdout.decode("utf-8"))
        return value["ready"] if isinstance(value, dict) and type(value.get("ready")) is bool else None
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.TimeoutExpired):
        return None


def check(root: Path | str, request: Mapping[str, Any], dispatcher: Dispatch) -> dict[str, Any]:
    """Return current scoped requirements; unknown and failed both deny admission."""
    asked = _request(request)  # Validate every field before any network operation.
    scenario = asked["scenarioId"]
    host = _configured(Path(root), asked["host"])
    requirements = {name: _requirement("not-applicable", "scenario_does_not_use_requirement", "scenario-contract")
                    for name in _FIELDS}
    configured_root = (host.fixture_transfer_root if host is not None
                       and isinstance(host.fixture_transfer_root, PurePosixPath)
                       and host.fixture_transfer_root.is_absolute() else None)
    root_status = (_remote_root_status(Path(root), asked["host"], configured_root, asked["timeoutSeconds"])
                   if configured_root is not None else False)
    requirements["fixtureRoot"] = _requirement("ready" if root_status is True else
        "failed" if root_status is False else "unknown",
        "current_private_transfer_root" if root_status is True else
        "fixture_transfer_root_unavailable", "read-only-guest-probe")

    if scenario in {"linux-public-update-preflight", "linux-scheduled-refresh"}:
        artifact_id = asked["bundleManifestArtifactId"]
        digest = _ARTIFACT.fullmatch(artifact_id).group(1)
        verified = _call(dispatcher, "vm", "artifact-verify", {"artifactId": artifact_id})
        location = verified.get("location") if verified else None
        local_path = location.get("localPath") if isinstance(location, Mapping) else None
        valid_artifact = (verified is not None and verified.get("verification") == "verified"
                          and isinstance(local_path, str) and Path(local_path).name == "native-scenario-manifest.json")
        requirements["artifact"] = _requirement("ready" if valid_artifact else "failed" if verified else "unknown",
            "registered_manifest_bytes_verified" if valid_artifact else "manifest_bytes_unavailable",
            "registered-local-artifact")
        bundle = (_call(dispatcher, "vm", "bundle-verify", {"path": str(Path(local_path).parent),
                   "manifestSha256": digest}) if valid_artifact else None)
        expected_bundle = ("linux-public-update-driver" if scenario == "linux-public-update-preflight"
                           else "linux-scheduled-refresh-driver")
        valid_bundle = bundle is not None and bundle.get("ok", True) is True and bundle.get("scenarioId") == expected_bundle
        requirements["bundle"] = _requirement("ready" if valid_bundle else "failed" if bundle else "unknown",
            "frozen_import_bundle_verified" if valid_bundle else "bundle_unavailable_or_changed", "frozen-local-bundle")
    elif scenario == "windows-credential-validity-v1":
        credential = getattr(host, "windows_credential_probe", None) if host else None
        configured = credential is not None and credential.environment == asked["environment"]
        secret_path = getattr(credential, "credential_path", None)
        secret_ready = configured and isinstance(secret_path, Path) and _private_nonempty_file(secret_path, maximum=512)
        requirements["credentialInput"] = _requirement("ready" if secret_ready else "failed",
            "private_input_present_validity_requires_fixed_probe" if secret_ready else "private_input_unavailable",
            "private-host-inventory")
    if scenario == "linux-scheduled-refresh":
        frozen = _call(dispatcher, "vm", "artifact-verify", {"artifactId": asked["scenarioInputArtifactId"]})
        location = frozen.get("location") if frozen else None
        path = location.get("localPath") if isinstance(location, Mapping) else None
        input_ready = False
        input_bytes: bytes | None = None
        if frozen and frozen.get("verification") == "verified" and isinstance(path, str):
            try:
                with Path(path).open("rb") as handle:
                    raw = handle.read(65537)
                item = json.loads(raw)
                input_ready = (len(raw) <= 65536 and isinstance(item, dict)
                    and item.get("schema") == "vpn-control.linux-scheduled-refresh.input"
                    and item.get("schemaVersion") == 1 and item.get("scenarioId") == scenario
                    and item.get("correlationId") == asked["scenarioCorrelationId"])
                if input_ready:
                    input_bytes = raw
            except (OSError, ValueError, UnicodeError):
                pass
        requirements["scenarioInput"] = _requirement("ready" if input_ready else "failed" if frozen else "unknown",
            "current_typed_input_bytes" if input_ready else "scenario_input_unavailable_or_mismatched", "registered-local-artifact")
        static = _remote_linux_static(Path(root), asked["host"], input_bytes, asked["timeoutSeconds"]) if input_bytes else None
        checks = static.get("checks", {}) if static else {}
        for name in ("package", "desktopJar", "protectedOwner", "ownedWorkspace"):
            state = "ready" if checks.get(name) is True else "failed" if checks.get(name) is False else "unknown"
            requirements[name] = _requirement(state, "current_guest_probe" if state == "ready" else
                "guest_probe_failed" if state == "failed" else "guest_probe_unavailable", "read-only-guest-probe")
        for name in ("workspace", "settings", "benchmarkSettings", "protocol", "certificate", "endpoint"):
            requirements[name] = _requirement("deferred", "runner_checks_after_owned_fixture_preparation", "fixed-runner")
    if scenario == "linux-scheduled-refresh-fixture-ready":
        root_path = getattr(host, "fixture_transfer_root", None) if host else None
        relative = asked.get("certificateRelativePath")
        cert = root_path / relative if isinstance(root_path, PurePosixPath) and relative else None
        remote = _remote_linux_refresh(Path(root), asked["host"], asked["expectedTestUrl"],
                                       asked["timeoutSeconds"], cert)
        checks = remote.get("checks", {}) if remote else {}
        for name in ("workspace", "settings", "benchmarkSettings", "protocol", "certificate", "endpoint"):
            state = "ready" if checks.get(name) is True else "failed" if checks.get(name) is False else "unknown"
            requirements[name] = _requirement(state, "current_guest_probe" if state == "ready" else
                "guest_probe_failed" if state == "failed" else "guest_probe_unavailable", "read-only-guest-probe")

    inputs: dict[str, Any] = {"hostAlias": asked["host"], "timeoutSeconds": asked["timeoutSeconds"]}
    if scenario == "windows-credential-validity-v1" and host is not None and getattr(host, "windows_credential_probe", None):
        credential = host.windows_credential_probe
        inputs.update({"observeHost": True, "vmIdentity": {"pid": credential.qemu_pid,
                       "startTicks": credential.qemu_start_ticks}})
    observed = _call(dispatcher, "vm", "environment-status", inputs)
    components = observed.get("components") if observed else None
    ssh = components.get("ssh") if isinstance(components, Mapping) else None
    host_ready = (observed is not None and observed.get("source") == "live-tool"
                  and observed.get("requestedProbesReady") is True and isinstance(ssh, Mapping)
                  and ssh.get("status") == "available" and ssh.get("freshness") == "fresh")
    requirements["host"] = _requirement("ready" if host_ready else "unknown",
        "current_configured_ssh_probe" if host_ready else "host_probe_unavailable", "live-tool")
    if scenario == "windows-credential-validity-v1":
        live = components.get("host") if isinstance(components, Mapping) else None
        identity = (live.get("observation") or {}).get("vmIdentity") if isinstance(live, Mapping) else None
        matched = isinstance(identity, Mapping) and identity.get("state") == "matched" and live.get("freshness") == "fresh"
        requirements["vmIdentity"] = _requirement("ready" if matched else "unknown",
            "current_qemu_generation_matched" if matched else "vm_generation_unavailable", "live-tool")
    # The Linux adapter only imports a frozen bundle. It does not consume an
    # endpoint, TLS certificate, settings or credential, and cannot see a prompt.
    # The Windows validity adapter consumes private credential input but prompt
    # admission is internal to its fixed operation, not an assertion here.
    admitted_states = {"ready", "not-applicable", "deferred"} if scenario == "linux-scheduled-refresh" else {"ready", "not-applicable"}
    ready = all(item["state"] in admitted_states for item in requirements.values())
    return {"scenarioId": scenario, "host": asked["host"], "environment": asked["environment"],
            "phase": "before-fixture-preparation" if scenario == "linux-scheduled-refresh" else "current",
            "ready": ready, "requirements": requirements}
