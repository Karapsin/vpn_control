"""Small, fail-closed OpenSSH transport helpers for private VM inventory files.

The inventory intentionally stays outside version control at ``.vm-hosts.local.json``.
This module never includes passwords in command arguments, exceptions, or probe results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import tempfile
from typing import Any, Iterable, Mapping, Sequence


CONFIG_FILENAME = ".vm-hosts.local.json"
CONFIG_SCHEMA_VERSION = 1
DEFAULT_TIMEOUT_SECONDS = 15
MAX_TIMEOUT_SECONDS = 60
MAX_OUTPUT_CHARS = 2_000
_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_USER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class SshConfigError(ValueError):
    """A private VM inventory is missing or cannot safely be used."""


class ProbeStatus(str, Enum):
    OK = "ok"
    CONFIG_ERROR = "config_error"
    TIMEOUT = "timeout"
    AUTHENTICATION_FAILED = "authentication_failed"
    HOST_KEY_FAILED = "host_key_failed"
    CONNECTION_FAILED = "connection_failed"
    SSH_FAILED = "ssh_failed"


@dataclass(frozen=True)
class WindowsCredentialRecoveryAdmission:
    task_name: str
    task_path: str
    expected_last_result: int
    expected_task_execute: str
    expected_task_principal: str
    expected_task_arguments_sha256: str
    expected_task_state: str


@dataclass(frozen=True)
class WindowsCredentialProbe:
    environment: str
    qga_socket_path: PurePosixPath
    qemu_pid: int
    qemu_start_ticks: int
    account_name: str
    expected_sid: str
    credential_path: Path
    recovery_admission: WindowsCredentialRecoveryAdmission | None = None


@dataclass(frozen=True)
class SshHost:
    alias: str
    host: str
    port: int
    user: str
    identity_file: Path
    known_hosts_file: Path | PurePosixPath
    proxy_jump: str | None = None
    transport: str = "direct"
    gateway: str | None = None
    remote_host_alias: str | None = None
    remote_control_path: PurePosixPath | None = None
    fixture_transfer_root: PurePosixPath | None = None
    android_devices: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    password: str | None = field(default=None, repr=False, compare=False)
    windows_credential_probe: WindowsCredentialProbe | None = field(default=None, repr=False)


@dataclass(frozen=True)
class SshConfig:
    root: Path
    hosts: Mapping[str, SshHost]


@dataclass(frozen=True)
class ProbeResult:
    host: str
    status: ProbeStatus
    output: str = ""

    @property
    def ok(self) -> bool:
        return self.status is ProbeStatus.OK

    def as_dict(self) -> dict[str, str | bool]:
        """Return a server-safe representation without connection credentials."""
        return {"host": self.host, "status": self.status.value, "ok": self.ok, "output": self.output}


def _reject_duplicate_keys(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SshConfigError("Configuration contains a duplicate entry.")
        result[key] = value
    return result


def _private_config_path(root: Path) -> Path:
    return Path(root).resolve() / CONFIG_FILENAME


def _validate_private_file(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise SshConfigError("Private VM inventory must be a regular file.")
    if os.name == "posix":
        if metadata.st_uid != os.getuid():
            raise SshConfigError("Private VM inventory must be owned by the current user.")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise SshConfigError("Private VM inventory must have mode 0600.")


def _read_private_config(path: Path) -> str:
    """Read via one descriptor on POSIX; Windows native inventories fail closed."""
    if os.name != "posix":
        # Python does not provide an ACL-safe, no-reparse-point open primitive
        # portable across supported Windows hosts. Do not claim private-secret
        # protection until a native implementation exists.
        raise SshConfigError("Private VM inventory is unsupported on Windows until ACL validation is implemented.")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError as exc:
        raise SshConfigError("Private VM inventory is not configured.") from exc
    except OSError as exc:
        raise SshConfigError("Private VM inventory must be a regular file.") from exc
    try:
        metadata = os.fstat(descriptor)
        _validate_private_file(metadata)
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            contents = handle.read(1_048_577)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(contents) > 1_048_576:
        raise SshConfigError("Private VM inventory is too large.")
    try:
        return contents.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SshConfigError("Private VM inventory is not valid JSON.") from exc


def _string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or _CONTROL_RE.search(value):
        raise SshConfigError(f"Invalid {field_name} in private VM inventory.")
    return value


def _path(value: Any, field_name: str) -> Path:
    candidate = Path(_string(value, field_name)).expanduser()
    if not candidate.is_absolute():
        raise SshConfigError(f"{field_name} must be an absolute path.")
    return candidate


def _remote_path(value: Any, field_name: str) -> PurePosixPath:
    candidate = PurePosixPath(_string(value, field_name))
    if not candidate.is_absolute():
        raise SshConfigError(f"{field_name} must be an absolute POSIX path.")
    return candidate


def _ssh_host(value: Any) -> str:
    host = _string(value, "host")
    # OpenSSH accepts a hostname after its options. Reject option-looking or
    # separator-bearing values so a private inventory cannot create extra hops.
    if host.startswith("-") or any(char.isspace() for char in host) or "," in host:
        raise SshConfigError("Invalid host in private VM inventory.")
    return host


def _ssh_user(value: Any) -> str:
    user = _string(value, "user")
    if not _USER_RE.fullmatch(user):
        raise SshConfigError("Invalid user in private VM inventory.")
    return user


def _android_devices(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        raise SshConfigError("androidDevices must be an object.")
    result = {}
    for alias, profile in value.items():
        if not isinstance(alias, str) or not _ALIAS_RE.fullmatch(alias):
            raise SshConfigError("Invalid Android device alias.")
        if not isinstance(profile, dict) or set(profile) != {"adb", "cli", "serial", "expectedAvd", "api"}:
            raise SshConfigError("Android device requires explicit executable and device identity fields.")
        for key in ("adb", "cli"):
            path = _remote_path(profile[key], key)
            if path == PurePosixPath("/") or ".." in path.parts:
                raise SshConfigError("Invalid Android executable path.")
        if not re.fullmatch(r"emulator-[0-9]+", _string(profile["serial"], "serial")):
            raise SshConfigError("Invalid Android emulator serial.")
        if not _ALIAS_RE.fullmatch(_string(profile["expectedAvd"], "expectedAvd")):
            raise SshConfigError("Invalid Android AVD identity.")
        if type(profile["api"]) is not int or profile["api"] not in {29, 35}:
            raise SshConfigError("Unsupported Android fixture API.")
        result[alias] = dict(profile)
    return result


def _windows_credential_probe(value: Any) -> WindowsCredentialProbe:
    fields = {"environment", "qgaSocketPath", "qemuPid", "qemuStartTicks", "accountName", "expectedSid", "credentialPath"}
    if not isinstance(value, dict) or not fields <= set(value) or set(value) - fields - {"recoveryAdmission"}:
        raise SshConfigError("Windows probe requires explicit VM and account identity fields.")
    environment = _string(value["environment"], "environment")
    if not _ALIAS_RE.fullmatch(environment):
        raise SshConfigError("Invalid Windows fixture identity.")
    socket_path = _remote_path(value["qgaSocketPath"], "qgaSocketPath")
    if socket_path == PurePosixPath("/") or ".." in socket_path.parts:
        raise SshConfigError("Invalid Windows fixture socket path.")
    if any(type(value[key]) is not int or value[key] <= 0 for key in ("qemuPid", "qemuStartTicks")):
        raise SshConfigError("Windows fixture requires a live process generation.")
    sid = _string(value["expectedSid"], "expectedSid")
    if not re.fullmatch(r"S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+", sid):
        raise SshConfigError("Invalid Windows fixture account identity.")
    admission = None
    if "recoveryAdmission" in value:
        recovery = value["recoveryAdmission"]
        recovery_fields = {"taskName", "taskPath", "expectedLastResult", "expectedTaskExecute", "expectedTaskPrincipal", "expectedTaskArgumentsSha256", "expectedTaskState"}
        if not isinstance(recovery, dict) or set(recovery) != recovery_fields:
            raise SshConfigError("Credential recovery requires an exact task binding.")
        if type(recovery["expectedLastResult"]) is not int or not 0 <= recovery["expectedLastResult"] <= 0xffffffff:
            raise SshConfigError("Invalid credential recovery task result.")
        digest = recovery["expectedTaskArgumentsSha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise SshConfigError("Invalid credential recovery action digest.")
        if recovery["expectedTaskState"] not in ("Ready", "Disabled"):
            raise SshConfigError("Credential recovery requires an inactive task state.")
        admission = WindowsCredentialRecoveryAdmission(
            _string(recovery["taskName"], "taskName"), _string(recovery["taskPath"], "taskPath"),
            recovery["expectedLastResult"], _string(recovery["expectedTaskExecute"], "expectedTaskExecute"),
            _string(recovery["expectedTaskPrincipal"], "expectedTaskPrincipal"), digest, recovery["expectedTaskState"])
    return WindowsCredentialProbe(environment, socket_path, value["qemuPid"], value["qemuStartTicks"],
                                  _ssh_user(value["accountName"]), sid, _path(value["credentialPath"], "credentialPath"), admission)


def _host_from_entry(alias: str, entry: Any) -> SshHost:
    if not _ALIAS_RE.fullmatch(alias):
        raise SshConfigError("Private VM inventory contains an invalid host alias.")
    if not isinstance(entry, dict):
        raise SshConfigError("Each VM host entry must be an object.")
    allowed = {"host", "port", "user", "identityFile", "knownHostsFile", "proxyJump", "password", "transport", "gateway", "remoteHostAlias", "remoteControlPath", "fixtureTransferRoot", "androidDevices", "windowsCredentialProbe"}
    required = {"host", "port", "user", "identityFile", "knownHostsFile"}
    if set(entry) - allowed or required - set(entry):
        raise SshConfigError("Private VM inventory contains unsupported or missing host fields.")
    port = entry["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise SshConfigError("Invalid port in private VM inventory.")
    proxy_jump = entry.get("proxyJump")
    if proxy_jump is not None:
        proxy_jump = _string(proxy_jump, "proxyJump")
        if not _ALIAS_RE.fullmatch(proxy_jump):
            raise SshConfigError("Invalid proxyJump in private VM inventory.")
    password = entry.get("password")
    if password is not None:
        password = _string(password, "password")
    transport = entry.get("transport", "direct")
    if transport not in {"direct", "nested"}:
        raise SshConfigError("Invalid transport in private VM inventory.")
    gateway = entry.get("gateway")
    remote_host_alias = entry.get("remoteHostAlias")
    remote_control_path = entry.get("remoteControlPath")
    if transport == "nested":
        gateway = _string(gateway, "gateway")
        remote_host_alias = _string(remote_host_alias, "remoteHostAlias")
        remote_control_path = _remote_path(remote_control_path, "remoteControlPath")
        if not _ALIAS_RE.fullmatch(gateway) or not _ALIAS_RE.fullmatch(remote_host_alias):
            raise SshConfigError("Invalid nested transport alias in private VM inventory.")
    elif any(value is not None for value in (gateway, remote_host_alias, remote_control_path)):
        raise SshConfigError("Direct hosts cannot include nested transport fields.")
    known_hosts_file: Path | PurePosixPath = (
        _remote_path(entry["knownHostsFile"], "knownHostsFile") if transport == "nested"
        else _path(entry["knownHostsFile"], "knownHostsFile")
    )
    fixture_root = None
    if "fixtureTransferRoot" in entry:
        fixture_root = _remote_path(entry["fixtureTransferRoot"], "fixtureTransferRoot")
        if fixture_root == PurePosixPath("/") or ".." in fixture_root.parts:
            raise SshConfigError("fixtureTransferRoot must name a dedicated absolute directory.")
    return SshHost(
        alias=alias,
        host=_ssh_host(entry["host"]),
        port=port,
        user=_ssh_user(entry["user"]),
        identity_file=_path(entry["identityFile"], "identityFile"),
        known_hosts_file=known_hosts_file,
        proxy_jump=proxy_jump,
        transport=transport,
        gateway=gateway,
        remote_host_alias=remote_host_alias,
        remote_control_path=remote_control_path,
        fixture_transfer_root=fixture_root,
        android_devices=_android_devices(entry.get("androidDevices", {})),
        password=password,
        windows_credential_probe=_windows_credential_probe(entry["windowsCredentialProbe"]) if "windowsCredentialProbe" in entry else None,
    )


def _validate_proxy_graph(hosts: Mapping[str, SshHost]) -> None:
    for host in hosts.values():
        if host.proxy_jump:
            raise SshConfigError("proxyJump is not supported; use an explicit nested transport.")
        if host.gateway and (host.gateway not in hosts or hosts[host.gateway].transport != "direct"):
            raise SshConfigError("Nested transport must reference a direct gateway host.")
    for alias in hosts:
        seen: set[str] = set()
        current = alias
        while (jump := hosts[current].proxy_jump) is not None:
            if jump in seen or jump == alias:
                raise SshConfigError("Private VM inventory has a proxy jump cycle.")
            seen.add(current)
            current = jump


def load_config(root: Path | str) -> SshConfig:
    """Load the private version-one inventory, rejecting insecure or malformed input."""
    path = _private_config_path(Path(root))
    try:
        raw = json.loads(_read_private_config(path), object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as exc:
        raise SshConfigError("Private VM inventory is not valid JSON.") from exc
    if (not isinstance(raw, dict) or not {"schemaVersion", "hosts"} <= set(raw)
            or set(raw) - {"schemaVersion", "hosts", "nativeBaselines"}
            or ("nativeBaselines" in raw and not isinstance(raw["nativeBaselines"], dict))):
        raise SshConfigError("Private VM inventory has unsupported fields.")
    if isinstance(raw["schemaVersion"], bool) or raw["schemaVersion"] != CONFIG_SCHEMA_VERSION or not isinstance(raw["hosts"], dict):
        raise SshConfigError("Private VM inventory has an unsupported schema.")
    hosts = {alias: _host_from_entry(alias, entry) for alias, entry in raw["hosts"].items()}
    _validate_proxy_graph(hosts)
    return SshConfig(root=Path(root).resolve(), hosts=hosts)


def inventory(root: Path | str) -> tuple[str, ...]:
    """List configured aliases only; hosts, users, and credentials remain private."""
    return tuple(sorted(load_config(root).hosts))


def build_ssh_argv(config: SshConfig, host: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, command: Sequence[str] = ("true",), ssh_binary: str = "ssh") -> list[str]:
    """Build an argv-only OpenSSH invocation. No values are shell-interpolated."""
    if host not in config.hosts:
        raise SshConfigError("Unknown VM host alias.")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise SshConfigError("SSH timeout must be between 1 and 60 seconds.")
    if not command or any(not isinstance(part, str) or _CONTROL_RE.search(part) for part in command):
        raise SshConfigError("SSH command must be a non-empty sequence of safe strings.")
    ssh_binary = _string(ssh_binary, "ssh executable")
    target = config.hosts[host]
    # A nested route first authenticates to its declared gateway. The remote ssh
    # command is shell-quoted because OpenSSH sends remote commands as text.
    # Every component still comes from the validated private inventory.
    if target.transport == "nested":
        assert target.gateway and target.remote_host_alias and target.remote_control_path
        gateway_argv = build_ssh_argv(config, target.gateway, timeout_seconds, command=("true",), ssh_binary=ssh_binary)
        remote_command = [
            "ssh", "-S", str(target.remote_control_path), "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={target.known_hosts_file}",
            target.remote_host_alias, shlex.join(command),
        ]
        return [*gateway_argv[:-1], " ".join(shlex.quote(part) for part in remote_command)]
    connection_host = config.hosts[target.gateway] if target.transport == "nested" else target
    argv = [
        ssh_binary, "-p", str(target.port), "-l", target.user,
        "-i", str(target.identity_file), "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={target.known_hosts_file}",
        "-o", f"ConnectTimeout={timeout_seconds}", "-o", "NumberOfPasswordPrompts=1",
        "-o", f"BatchMode={'no' if connection_host.password is not None else 'yes'}",
    ]
    argv.extend([target.host, shlex.join(command)])
    return argv


def _sanitized_output(value: str | bytes | None, passwords: Iterable[str]) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = value or ""
    value = value.replace("\r", "").replace("\x00", "")
    for password in passwords:
        value = value.replace(password, "[redacted]")
    return value[:MAX_OUTPUT_CHARS]


def _status_for_output(output: str) -> ProbeStatus:
    lowered = output.lower()
    if "host key verification failed" in lowered or "remote host identification has changed" in lowered or "host key" in lowered and "verification" in lowered:
        return ProbeStatus.HOST_KEY_FAILED
    if "permission denied" in lowered or "authentication failed" in lowered:
        return ProbeStatus.AUTHENTICATION_FAILED
    if any(token in lowered for token in ("connection refused", "no route to host", "could not resolve hostname", "connection timed out", "network is unreachable")):
        return ProbeStatus.CONNECTION_FAILED
    return ProbeStatus.SSH_FAILED


def _askpass_environment(password: str, directory: Path) -> tuple[Path, dict[str, str]]:
    helper = directory / "askpass"
    password_file = directory / "password"
    descriptor = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
        handle.write(password)
    helper.write_text("#!/bin/sh\ncat \"$VPN_CONTROL_SSH_PASSWORD_FILE\"\n", encoding="utf-8")
    helper.chmod(0o700)
    environment = os.environ.copy()
    environment.update({
        "SSH_ASKPASS": str(helper),
        "SSH_ASKPASS_REQUIRE": "force",
        "DISPLAY": environment.get("DISPLAY", "vpn-control-askpass"),
        "VPN_CONTROL_SSH_PASSWORD_FILE": str(password_file),
    })
    return helper, environment


def probe(root: Path | str, host: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, ssh_binary: str = "ssh") -> ProbeResult:
    """Run a bounded read-only ``true`` command over SSH and classify its outcome."""
    try:
        config = load_config(root)
        argv = build_ssh_argv(config, host, timeout_seconds, ssh_binary=ssh_binary)
    except SshConfigError as exc:
        return ProbeResult(host=host, status=ProbeStatus.CONFIG_ERROR, output=str(exc))
    target = config.hosts[host]
    connection_host = config.hosts[target.gateway] if target.transport == "nested" else target
    passwords = tuple(candidate.password for candidate in config.hosts.values() if candidate.password)
    environment: dict[str, str] | None = None
    try:
        if connection_host.password is not None:
            with tempfile.TemporaryDirectory(prefix="vpn-control-askpass-") as directory:
                _, environment = _askpass_environment(connection_host.password, Path(directory))
                completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_seconds + 1, env=environment, check=False)
        else:
            completed = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_seconds + 1, check=False)
    except subprocess.TimeoutExpired as exc:
        _sanitized_output(exc.stdout, passwords)
        _sanitized_output(exc.stderr, passwords)
        return ProbeResult(host=host, status=ProbeStatus.TIMEOUT, output="SSH probe timed out.")
    except OSError as exc:
        _sanitized_output(str(exc), passwords)
        return ProbeResult(host=host, status=ProbeStatus.SSH_FAILED, output="SSH executable could not be started.")
    output = _sanitized_output(completed.stdout, passwords) + _sanitized_output(completed.stderr, passwords)
    if completed.returncode == 0:
        return ProbeResult(host=host, status=ProbeStatus.OK, output="SSH connectivity verified.")
    status = _status_for_output(output)
    return ProbeResult(host=host, status=status, output=f"SSH probe failed: {status.value}.")
