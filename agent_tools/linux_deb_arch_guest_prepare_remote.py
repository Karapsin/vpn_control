"""Fixed, durable host side of disposable DEB/Arch guest preparation.

The only host alias is ``archlinux``. One private role claim is written before
transfer or QEMU creation. A lost SSH response is observed by status, never
replayed. The host worker uses the frozen transfer inventory; it does not take
commands, paths, ports, or package bytes from a caller.
"""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import fcntl
from pathlib import Path
import re
import shlex
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
from typing import Any, Mapping


_ROLES = {"ubuntu-fresh": ("ubuntu", 2330), "ubuntu-update": ("ubuntu", 2331),
          "arch-update": ("arch", 2332), "arch-rollback": ("arch", 2333)}
_HOST_ROOT = Path("/home/kardinal/.vpn-control-parity-prepare")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_MAX_TRANSFER = 3 * 1024 * 1024 * 1024


class RemotePreparationError(ValueError):
    pass


def _need(value: bool, reason: str) -> None:
    if not value:
        raise RemotePreparationError(reason)


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _private(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    _need(info.st_uid == os.getuid() and
          (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and
          stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600),
          "Host preparation job path is unsafe")


def _write_once(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)


def _read_private(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
              stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= maximum,
              "Host preparation job record is unsafe")
        data = os.read(descriptor, info.st_size + 1)
        _need(len(data) == info.st_size, "Host preparation job record changed")
        return data
    finally:
        os.close(descriptor)


def verify_transfer(data: bytes, role: str, correlation: str, source_sha: str,
                    artifact_ids: Mapping[str, str]) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Verify every archive member and exact identity before host materialization."""
    _need(role in _ROLES and isinstance(correlation, str) and _UUID.fullmatch(correlation) is not None
          and isinstance(source_sha, str) and _SHA.fullmatch(source_sha) is not None and
          isinstance(data, bytes) and 0 < len(data) <= _MAX_TRANSFER,
          "Host preparation transfer identity is invalid")
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for member in archive:
                name = member.name
                _need(member.isfile() and not name.startswith("/") and ".." not in Path(name).parts
                      and re.fullmatch(r"(?:guest|host)/[A-Za-z0-9_./-]+|transfer-manifest\.json", name)
                      and name not in files and 0 < member.size <= 1024 * 1024 * 1024
                      and len(files) < 64, "Host preparation archive member is unsafe")
                source = archive.extractfile(member)
                _need(source is not None, "Host preparation archive member is absent")
                content = source.read(member.size + 1)
                _need(len(content) == member.size, "Host preparation archive member changed")
                files[name] = content
    except (tarfile.TarError, OSError) as error:
        raise RemotePreparationError("Host preparation archive cannot be read") from error
    _need("transfer-manifest.json" in files, "Host preparation transfer manifest is absent")
    try:
        manifest = json.loads(files.pop("transfer-manifest.json"))
    except (UnicodeError, ValueError) as error:
        raise RemotePreparationError("Host preparation transfer manifest is invalid") from error
    _need(isinstance(manifest, dict) and set(manifest) ==
          {"schemaVersion", "correlationId", "sourceSha", "sourceFingerprint", "guestRole",
           "guestPort", "artifactIds", "files"} and manifest["schemaVersion"] == 1 and
          manifest["correlationId"] == correlation and manifest["sourceSha"] == source_sha and
          manifest["guestRole"] == role and manifest["guestPort"] == _ROLES[role][1] and
          manifest["artifactIds"] == artifact_ids and
          isinstance(manifest["sourceFingerprint"], str) and
          _HASH.fullmatch(manifest["sourceFingerprint"]) is not None and
          isinstance(manifest["files"], dict) and set(manifest["files"]) == set(files),
          "Host preparation transfer manifest differs")
    for name, content in files.items():
        _need(manifest["files"][name] ==
              {"sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest()},
              "Host preparation transfer file differs")
    required = {"host/prepare_linux_install_vm.py", "host/fixture_environment.py",
                "host/worker.py", "guest/agent_tools/linux_deb_arch_guest_prepare_remote.py",
                "guest/agent_tools/linux_deb_arch_native_driver.py",
                "guest/agent_tools/linux_deb_arch_rollback.py",
                "guest/fixture/fixture-receipt.json"}
    _need(required <= set(files) and any(name.startswith("guest/target.") for name in files),
          "Host preparation transfer is incomplete")
    return manifest, files


def host_submit(data: bytes, role: str, correlation: str, source_sha: str,
                artifact_ids: Mapping[str, str], *, root: Path = _HOST_ROOT,
                worker_source: bytes | None = None) -> dict[str, Any]:
    """Claim one role, then preserve exact bytes and launch exactly one worker."""
    manifest, files = verify_transfer(data, role, correlation, source_sha, artifact_ids)
    root.mkdir(mode=0o700, exist_ok=True)
    _private(root, directory=True)
    claim = root / (role + ".claim")
    _write_once(claim, _canonical({"guestRole": role, "correlationId": correlation,
                                   "sourceSha": source_sha,
                                   "transferSha256": hashlib.sha256(data).hexdigest()}))
    job = root / correlation
    job.mkdir(mode=0o700)
    _private(job, directory=True)
    _write_once(job / "transfer.tar", data)
    _write_once(job / "manifest.json", _canonical(manifest))
    if worker_source is None:
        worker_source = files["host/worker.py"]
    _need(worker_source == files["host/worker.py"],
          "Host preparation worker bytes differ from frozen transfer")
    _write_once(job / "worker.py", worker_source)
    for name, content in files.items():
        destination = job / name
        parent = job
        for part in Path(name).parts[:-1]:
            parent = parent / part
            parent.mkdir(mode=0o700, exist_ok=True)
            _private(parent, directory=True)
        _private(destination.parent, directory=True)
        _write_once(destination, content)
    _write_once(job / "state.json", _canonical({"state": "running", "phase": "submitted",
        "guestRole": role, "correlationId": correlation, "sourceSha": source_sha,
        "artifactIds": artifact_ids}))
    with (job / "worker.log").open("xb") as log:
        log.flush()
        worker = subprocess.Popen([sys.executable, "-I", "-B", str(job / "worker.py"),
                                  "--host-worker", role, correlation], stdin=subprocess.DEVNULL,
                                 stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                 close_fds=True)
    _write_once(job / "worker-identity.json", _canonical({"pid": worker.pid,
        "startTicks": _ticks(worker.pid)}))
    return {"state": "submitted", "correlationId": correlation}


def host_status(role: str, correlation: str, *, root: Path = _HOST_ROOT,
                check_worker: bool = True) -> dict[str, Any]:
    _need(role in _ROLES and isinstance(correlation, str) and _UUID.fullmatch(correlation) is not None,
          "Host preparation status identity is invalid")
    _private(root, directory=True)
    claim = json.loads(_read_private(root / (role + ".claim"), 1024))
    _need(claim.get("guestRole") == role and claim.get("correlationId") == correlation,
          "Host preparation role claim differs")
    job = root / correlation
    _private(job, directory=True)
    state = json.loads(_read_private(job / "state.json", 16384))
    _need(state.get("guestRole") == role and state.get("correlationId") == correlation and
          state.get("sourceSha") == claim.get("sourceSha") and
          state.get("state") in {"running", "failed", "unknown", "ready"},
          "Host preparation status differs")
    if state["state"] == "ready":
        try:
            sealed = (isinstance(state.get("guestManifest"), dict) and
                isinstance(state.get("preparationReceipt"), dict) and
                _canonical(state["guestManifest"]) == _read_private(job / "guest-manifest.json", 8192) and
                _canonical(state["preparationReceipt"]) ==
                _read_private(job / "preparation-receipt.json", 16384))
        except (OSError, ValueError, TypeError):
            sealed = False
        _need(sealed, "Host preparation sealed receipts differ")
    if state["state"] == "running" and check_worker:
        try:
            worker = json.loads(_read_private(job / "worker-identity.json", 1024))
            pid, ticks = worker["pid"], worker["startTicks"]
            alive = (type(pid) is int and pid > 0 and type(ticks) is int and ticks > 0 and
                     _ticks(pid) == ticks and _process_state(pid) != "Z")
        except (OSError, ValueError, TypeError, KeyError):
            alive = False
        if not alive:
            return {**state, "state": "unknown", "reason": "worker-exited-or-unreadable"}
    return state


def _ticks(pid: int) -> int:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    fields = raw.rsplit(")", 1)[1].split()
    value = int(fields[19])
    _need(value > 0, "Preparation process generation is invalid")
    return value


def _process_state(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    return raw.rsplit(")", 1)[1].split()[0]


def _digest(path: Path, maximum: int = 1024 * 1024 * 1024) -> str:
    info = path.lstat()
    _need(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum,
          "Preparation file is absent or unsafe")
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(*argv: str, timeout: int = 120, input_data: bytes | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(argv, input=input_data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False)
    _need(result.returncode == 0 and len(result.stdout) <= 64 * 1024 and
          len(result.stderr) <= 64 * 1024, "Fixed preparation command failed")
    return result


def _guest_idle(distribution: str, *, proc_root: Path = Path("/proc"),
                app_root: Path = Path("/opt/vpn-control"),
                jobs: Path = Path("/var/lib/vpn-control-install-jobs")) -> None:
    """Fail closed if a package, owner, runtime, or protected job might be active."""
    _need(os.geteuid() == 0 and distribution in {"ubuntu", "arch"},
          "Guest preparation requires the exact root guest")
    if jobs.exists() or jobs.is_symlink():
        _need(_guest_jobs_clear(jobs),
              "Guest protected installer state is present")
    _need(not app_root.exists() and not app_root.is_symlink(),
          "Guest app is already installed")
    count = 0
    for entry in proc_root.iterdir():
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        count += 1
        _need(count <= 4096, "Guest process inventory exceeds bound")
        try:
            raw = (entry / "cmdline").read_bytes()[:65537]
        except FileNotFoundError:
            if not entry.exists():
                continue
            raise RemotePreparationError("Guest process changed during observation")
        except OSError as error:
            raise RemotePreparationError("Guest process is unreadable") from error
        _need(len(raw) <= 65536, "Guest process command exceeds bound")
        if not raw:  # Kernel threads have no userspace executable.
            continue
        try:
            executable = os.path.basename(os.readlink(entry / "exe")).removesuffix(" (deleted)")
        except FileNotFoundError:
            if not entry.exists():
                continue
            raise RemotePreparationError("Guest process executable changed")
        except OSError as error:
            raise RemotePreparationError("Guest process executable is unreadable") from error
        _need(executable not in {"vpn-control", "sing-box", "apt-get", "apt", "dpkg",
                                 "pacman", "packagekitd"},
              "Guest app, runtime, or package manager is active")
    if distribution == "ubuntu":
        _need(subprocess.run(["dpkg-query", "-W", "vpn-control"],
              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10).returncode != 0,
              "Guest app package is already installed")
        audit = _run("dpkg", "--audit", timeout=20)
        _need(not audit.stdout.strip(), "Guest package database needs repair")


def _guest_jobs_clear(jobs: Path) -> bool:
    """A dangling symlink is never an absent protected-job root."""
    if jobs.is_symlink():
        return False
    if not jobs.exists():
        return True
    return jobs.is_dir() and not any(jobs.iterdir())


def _arch_base(stage: Path, base_version: str, expected_sha: str) -> None:
    archive_path = stage / "base.tar.gz"
    _need(_digest(archive_path) == expected_sha, "Arch base package differs")
    install_source = stage / "scripts/install_arch_desktop_update.sh"
    expected_installer = _digest(install_source, 1024 * 1024)
    extracted = stage / "arch-base-extracted"
    extracted.mkdir(mode=0o700)
    with tarfile.open(archive_path, "r:gz") as archive:
        names: set[str] = set()
        for member in archive:
            parts = Path(member.name).parts
            _need(parts and parts[0] == "vpn-control-arch-update" and
                  ".." not in parts and not member.name.startswith("/") and
                  (member.isfile() or member.isdir() or member.issym()) and
                  member.name not in names and len(names) < 100_000,
                  "Arch base archive member is unsafe")
            if member.issym():
                target = Path(member.linkname)
                _need(not target.is_absolute() and ".." not in target.parts,
                      "Arch base archive link is unsafe")
            names.add(member.name)
        archive.extractall(extracted, filter="data")
    bundle_root = extracted / "vpn-control-arch-update"
    _need(_digest(bundle_root / "install.sh", 1024 * 1024) == expected_installer,
          "Arch base installer differs from frozen source")
    _run("bash", str(bundle_root / "install.sh"), str(bundle_root), timeout=900)
    launcher = Path("/opt/vpn-control/bin/vpn-control")
    observed = _run(str(launcher), "--version", timeout=30).stdout.decode("utf-8", "replace")
    _need(_arch_displayed_version(observed) == base_version,
          "Arch installed base version differs")
    sys.path.insert(0, str(stage / "scripts"))
    try:
        from arch_public_update import verify_arch_bundle_base
        verified = verify_arch_bundle_base(launcher, stage / "fixture")
    finally:
        sys.path.remove(str(stage / "scripts"))
    _need(verified.get("version") == base_version and verified.get("sameSourceBuild") is True,
          "Arch installed base differs from source bundle")
    _run("pacman", "-Dk", timeout=30)


def _arch_displayed_version(output: str) -> str | None:
    """Extract exactly one complete three-part displayed product version."""
    if not isinstance(output, str) or len(output) > 1024:
        return None
    matches = re.findall(r"(?<![0-9])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9])", output)
    return matches[0] if len(matches) == 1 else None


def _debian_base(stage: Path, base_version: str, expected_sha: str) -> None:
    package = stage / "base.deb"
    _need(_digest(package) == expected_sha, "DEB base package differs")
    _run("apt-get", "install", "-y", "--no-install-recommends", "--", str(package), timeout=900)
    observed = _run("dpkg-query", "-W", "-f=${Version}", "vpn-control", timeout=20).stdout.decode()
    _need(observed.split("-", 1)[0] == base_version, "DEB installed base version differs")
    audit = _run("dpkg", "--audit", timeout=30)
    _need(not audit.stdout.strip(), "DEB package database needs repair")


def _probe_server(stage: Path, ready: Mapping[str, Any], correlation: str) -> None:
    port = ready.get("port")
    _need(type(port) is int and 1024 <= port <= 65535, "Guest fixture port is invalid")
    with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
        connection.sendall(b"CONNECT github.com:443 HTTP/1.1\r\nHost: github.com:443\r\n\r\n")
        response = bytearray()
        while not response.endswith(b"\r\n\r\n"):
            block = connection.recv(1)
            _need(bool(block) and len(response) < 4096,
                  "Guest fixture CONNECT header is incomplete")
            response.extend(block)
        _need(response == b"HTTP/1.1 200 Connection Established\r\n\r\n",
              "Guest fixture CONNECT probe failed")
        context = ssl.create_default_context(cafile=str(stage / "fixture-certificate.pem"))
        with context.wrap_socket(connection, server_hostname="github.com") as tls:
            tls.sendall(("GET /Karapsin/vpn_control/releases/latest/download/update-manifest.json "
                "HTTP/1.1\r\nHost: github.com\r\nX-Vpn-Control-Probe-Id: " + correlation +
                "\r\n\r\n").encode())
            received = bytearray()
            while block := tls.recv(65536):
                received.extend(block)
                _need(len(received) <= 1024 * 1024, "Guest fixture probe response exceeds bound")
    _need(received.startswith(b"HTTP/1.1 200 OK\r\n"), "Guest fixture manifest probe failed")
    event = json.loads((stage / "fixture/probe-events" / (correlation + ".json")).read_bytes())
    _need(event.get("correlationId") == correlation and event.get("connectAccepted") is True and
          event.get("tlsSucceeded") is True and event.get("exactManifestGet") is True and
          event.get("manifestSha256") == ready.get("manifestSha256") and
          event.get("peerCertificateSha256") == ready.get("peerCertificateSha256"),
          "Guest fixture probe receipt differs")


def guest_prepare(stage: Path, role: str, correlation: str) -> dict[str, Any]:
    """Effectful one-shot guest phase; called only after frozen archive staging."""
    _need(role in _ROLES and _UUID.fullmatch(correlation) is not None and
          stage == Path("/var/lib/vpn-control-parity") / role and os.geteuid() == 0,
          "Guest preparation stage identity differs")
    manifest = json.loads((stage / "transfer-manifest.json").read_bytes())
    _need(manifest.get("guestRole") == role and manifest.get("correlationId") == correlation,
          "Guest preparation manifest differs")
    distribution = _ROLES[role][0]
    _guest_idle(distribution)
    receipt = json.loads((stage / "fixture/fixture-receipt.json").read_bytes())
    base, target = receipt["builds"]
    fixture = {"sourceFingerprint": receipt["sourceFingerprint"],
               "baseVersion": base["version"], "targetVersion": target["version"],
               "codeFingerprint": base["codeFingerprint"]}
    base_sha = manifest["artifactIds"]["basePackage"].removeprefix("sha256-")
    baseline: dict[str, Any] = {"installedBaseVersion": None, "installedPackageSha256": None,
        "codeFingerprint": None, "cleanPackageDatabase": True,
        "xdgUtilsAbsent": None, "desktopDirectoryAbsent": None}
    if role == "ubuntu-fresh":
        absent = subprocess.run(["dpkg-query", "-W", "xdg-utils"], stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=20).returncode != 0
        _need(absent and not Path("/usr/share/desktop-directories").exists(),
              "Fresh DEB dependency baseline is not absent")
        baseline["xdgUtilsAbsent"] = True
        baseline["desktopDirectoryAbsent"] = True
        intent = {"profile": "fresh-deb-dependencies", "distribution": distribution,
            "guestRole": role, "correlationId": correlation,
            "sourceSha": manifest["sourceSha"],
            "sourceFingerprint": fixture["sourceFingerprint"],
            "targetVersion": fixture["targetVersion"],
            "targetSha256": manifest["artifactIds"]["targetPackage"].removeprefix("sha256-"),
            "fixtureReceiptArtifactId": manifest["artifactIds"]["fixtureReceipt"],
            "trustStoreSha256": None, "harnessSha256": None}
        worker_raw = _canonical(intent)
        worker_path = stage / "worker-intent.json"
        _write_once(worker_path, worker_raw)
        worker_path.chmod(0o644)
        return {"baseline": baseline, "fixture": None, "publicCli": None,
                "workerIntentSha256": hashlib.sha256(worker_raw).hexdigest()}
    if distribution == "ubuntu":
        _debian_base(stage, fixture["baseVersion"], base_sha)
    else:
        _arch_base(stage, fixture["baseVersion"], base_sha)
    baseline.update(installedBaseVersion=fixture["baseVersion"],
                    installedPackageSha256=base_sha,
                    codeFingerprint=fixture["codeFingerprint"])
    certificate = stage / "fixture-certificate.pem"
    private_key = stage / "fixture-private-key.pem"
    trust = stage / "trust.jks"
    _run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=github.com", "-addext", "subjectAltName=DNS:github.com",
         "-keyout", str(private_key), "-out", str(certificate), timeout=60)
    private_key.chmod(0o600)
    certificate.chmod(0o644)
    _run("keytool", "-importcert", "-noprompt", "-alias", "vpn-control-fixture",
         "-file", str(certificate), "-keystore", str(trust), "-storetype", "PKCS12",
         "-storepass", "fixtureonly", timeout=60)
    trust.chmod(0o644)
    state_dir = stage / "server-state"
    state_dir.mkdir(mode=0o755)
    log = state_dir / "server.log"
    with log.open("xb") as output:
        subprocess.Popen([sys.executable, "-B",
            str(stage / "scripts/prepare_desktop_update_fixture.py"), "serve",
            "--directory", str(stage / "fixture"), "--certificate", str(certificate),
            "--private-key", str(private_key), "--ready-file", str(state_dir / "ready.json"),
            "--confirm-owned-disposable-guest"], stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
    ready_path = state_dir / "ready.json"
    for _ in range(100):
        if ready_path.exists():
            break
        time.sleep(0.1)
    _need(ready_path.is_file() and not ready_path.is_symlink(),
          "Guest fixture server did not become ready")
    ready = json.loads(ready_path.read_bytes())
    receipt_raw = (stage / "fixture/fixture-receipt.json").read_bytes()
    _need(ready.get("sourceFingerprint") == fixture["sourceFingerprint"] and
          ready.get("fixtureReceiptSha256") == hashlib.sha256(receipt_raw).hexdigest() and
          ready.get("manifest") == receipt["manifest"] and
          isinstance(ready.get("manifestSha256"), str) and
          ready["manifestSha256"] == hashlib.sha256(json.dumps(
              receipt["manifest"], separators=(",", ":")).encode()).hexdigest(),
          "Guest fixture READY source or manifest differs")
    server_pid = ready.get("serverPid")
    server_ticks = _ticks(server_pid) if type(server_pid) is int and server_pid > 0 else None
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    _need(server_ticks is not None and
          ready.get("serverProcessStartIdentity") == f"linux:{boot_id}:{server_ticks}",
          "Guest fixture server process is unavailable")
    _probe_server(stage, ready, correlation)
    _need(_ticks(server_pid) == server_ticks,
          "Guest fixture server generation changed during probe")
    public = {"port": ready["port"], "sourceFingerprint": ready["sourceFingerprint"],
              "manifestSha256": ready["manifestSha256"],
              "readySha256": _digest(ready_path, 65536)}
    public_raw = _canonical(public)
    public_path = stage / "public-fixture.json"
    _write_once(public_path, public_raw)
    public_path.chmod(0o644)
    intent = {"profile": "arch-rollback" if role == "arch-rollback" else "package-update",
        "distribution": distribution, "guestRole": role, "correlationId": correlation,
        "sourceSha": manifest["sourceSha"], "sourceFingerprint": fixture["sourceFingerprint"],
        "targetVersion": fixture["targetVersion"],
        "targetSha256": manifest["artifactIds"]["targetPackage"].removeprefix("sha256-"),
        "fixtureReceiptArtifactId": manifest["artifactIds"]["fixtureReceipt"],
        "trustStoreSha256": _digest(trust, 1024 * 1024),
        "harnessSha256": _digest(stage / "scripts/test_linux_public_install.py", 1024 * 1024)}
    worker_raw = _canonical(intent)
    worker_path = stage / "worker-intent.json"
    _write_once(worker_path, worker_raw)
    worker_path.chmod(0o644)
    _need(_run("systemctl", "is-active", "polkit", timeout=15).stdout.strip() == b"active" and
          Path("/dev/pts").is_dir() and
          subprocess.run(["passwd", "-S", "vpnfixture"], capture_output=True,
                         timeout=15).stdout.split()[1:2] in ([b"L"], [b"LK"]),
          "Guest polkit, PTY or locked credential baseline is unavailable")
    fixture_evidence = {"serverPid": server_pid, "serverStartTicks": server_ticks,
        "readySha256": public["readySha256"], "manifestSha256": ready["manifestSha256"],
        "certificateSha256": _digest(certificate, 65536),
        "trustStoreSha256": intent["trustStoreSha256"],
        "publicFixtureSha256": hashlib.sha256(public_raw).hexdigest()}
    return {"baseline": baseline, "fixture": fixture_evidence,
            "publicCli": {"polkitReady": True, "ptyReady": True, "credentialReady": True},
            "workerIntentSha256": hashlib.sha256(worker_raw).hexdigest()}


_GUEST_BOOTSTRAP = r'''import hashlib,io,json,os,stat,subprocess,sys,tarfile
from pathlib import Path
role,correlation,digest,size=sys.argv[1:]
roles=('ubuntu-fresh','ubuntu-update','arch-update','arch-rollback')
if os.geteuid()!=0 or role not in roles or not 0<int(size)<=3221225472:raise ValueError('identity')
if os.path.lexists('/opt/vpn-control'):raise ValueError('existing app')
jobs=Path('/var/lib/vpn-control-install-jobs')
if (jobs.exists() or jobs.is_symlink()) and (jobs.is_symlink() or not jobs.is_dir() or any(jobs.iterdir())):raise ValueError('protected jobs')
stage=Path('/var/lib/vpn-control-parity')/role
if stage.exists() or stage.is_symlink():raise ValueError('role already staged')
raw=sys.stdin.buffer.read(int(size)+1)
if len(raw)!=int(size) or hashlib.sha256(raw).hexdigest()!=digest:raise ValueError('transfer differs')
files={}
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
 for member in archive:
  name=member.name
  if not member.isfile() or name.startswith('/') or '..' in Path(name).parts or name in files or len(files)>64:raise ValueError('member')
  if name.startswith('guest/') or name=='transfer-manifest.json':
   source=archive.extractfile(member);content=source.read(member.size+1)
   if len(content)!=member.size:raise ValueError('member bytes')
   files[name]=content
manifest=json.loads(files.pop('transfer-manifest.json'))
if manifest.get('guestRole')!=role or manifest.get('correlationId')!=correlation:raise ValueError('manifest')
for name,content in files.items():
 if not name.startswith('guest/') or manifest['files'].get(name)!={'sizeBytes':len(content),'sha256':hashlib.sha256(content).hexdigest()}:raise ValueError('inventory')
parent=stage.parent
parent.mkdir(mode=0o755,exist_ok=True)
for path in (Path('/var'),Path('/var/lib'),parent):
 info=path.lstat()
 if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('stage ancestry')
stage.mkdir(mode=0o755)
for name,content in sorted(files.items()):
 relative=Path(name).relative_to('guest')
 target=stage/relative
 target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
 fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o444 if name.startswith('guest/fixture/packages/target/') else 0o644)
 with os.fdopen(fd,'wb') as output:output.write(content);output.flush();os.fsync(output.fileno())
with (stage/'transfer-manifest.json').open('xb') as output:output.write(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()+b'\n')
worker=stage/'agent_tools/linux_deb_arch_guest_prepare_remote.py'
result=subprocess.run([sys.executable,'-I','-B',str(worker),'--guest-prep',role,correlation],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=1800)
if result.returncode or len(result.stdout)>16384:raise ValueError('guest preparation failed')
print(result.stdout.decode(),end='')
'''


def _replace_state(job: Path, value: Mapping[str, Any]) -> None:
    data = _canonical(value)
    _need(len(data) <= 16 * 1024, "Host preparation state exceeds bound")
    temporary = job / (".state-" + str(os.getpid()))
    _write_once(temporary, data)
    os.replace(temporary, job / "state.json")
    parent = os.open(job, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _host_ssh(tree: Path, port: int, command: tuple[str, ...]) -> list[str]:
    _need(port in {2330, 2331, 2332, 2333} and tree.name.startswith("vpn-control-install-vm-parity-"),
          "Host guest SSH identity differs")
    return ["ssh", "-T", "-p", str(port), "-i", str(tree / "client-key"),
            "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + str(tree / "known-hosts"),
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "vpnfixture@127.0.0.1", shlex.join(command)]


def _host_capacity(*, proc_root: Path = Path("/proc")) -> dict[str, int]:
    """Read complete Linux memory/QEMU allocation facts before a 6 GiB boot."""
    memory: dict[str, int] = {}
    for line in (proc_root / "meminfo").read_text(encoding="ascii").splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "kB" and parts[0].endswith(":"):
            memory[parts[0][:-1]] = int(parts[1]) // 1024
    _need(all(key in memory for key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree")) and
          memory["MemTotal"] >= 12 * 1024 and
          memory["MemAvailable"] >= 9 * 1024 and
          memory["SwapTotal"] >= memory["SwapFree"] >= 0 and
          memory["SwapTotal"] - memory["SwapFree"] <= 1024,
          "Host QEMU memory admission is incomplete")
    guests = 0
    reserved = 0
    for entry in proc_root.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="ascii").strip()
        except FileNotFoundError:
            if not entry.exists():
                continue
            raise RemotePreparationError("Host process inventory changed")
        except OSError as error:
            raise RemotePreparationError("Host process inventory is unreadable") from error
        if not comm.startswith("qemu-system-"):
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
        except OSError as error:
            raise RemotePreparationError("Host QEMU command is unreadable") from error
        argv = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
        _need(0 < len(raw) <= 16384 and argv.count("-m") == 1,
              "Host QEMU allocation is unknown")
        index = argv.index("-m")
        _need(index + 1 < len(argv) and re.fullmatch(r"[1-9][0-9]{2,5}", argv[index + 1]) is not None,
              "Host QEMU allocation is unknown")
        reserved += int(argv[index + 1])
        guests += 1
        _need(guests <= 8, "Host QEMU count exceeds bound")
    _need(guests < 4 and memory["MemAvailable"] >= 9 * 1024 and
          memory["MemTotal"] >= reserved + 6 * 1024 + 2 * 1024,
          "Host QEMU capacity is unavailable")
    return {"physicalMiB": memory["MemTotal"], "availableMiB": memory["MemAvailable"],
            "swapUsedMiB": memory["SwapTotal"] - memory["SwapFree"],
            "runningQemuCount": guests, "runningQemuMiB": reserved,
            "requestedMiB": 6 * 1024}


def _launch_qemu(job: Path, argv: list[str]) -> subprocess.Popen:
    """Serialize fixed-role launches across this host's preparation workers."""
    root = job.parent
    lock_path = root / "resource.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
              stat.S_IMODE(info.st_mode) == 0o600,
              "Host QEMU resource lock is unsafe")
        fcntl.flock(fd, fcntl.LOCK_EX)
        _host_capacity()
        with (job / "qemu.log").open("xb") as output:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output,
                                       stderr=subprocess.STDOUT, start_new_session=True,
                                       close_fds=True)
        _ticks(process.pid)
        return process
    finally:
        os.close(fd)


def run_host_worker(role: str, correlation: str, *, root: Path = _HOST_ROOT) -> None:
    """Prepare one new QEMU tree and its guest stage, then seal evidence."""
    _need(role in _ROLES and _UUID.fullmatch(correlation) is not None,
          "Host worker role or correlation differs")
    job = root / correlation
    state = host_status(role, correlation, root=root, check_worker=False)
    _need(state["state"] == "running" and state["phase"] == "submitted",
          "Host worker state is not the one-shot submission")
    distribution, port = _ROLES[role]
    tree = Path("/home/kardinal/vpn-control-install-vm-parity-" + role)
    _need(not tree.exists() and not tree.is_symlink(), "Host QEMU role tree already exists")
    manifest = json.loads(_read_private(job / "manifest.json", 64 * 1024))
    transfer = _read_private(job / "transfer.tar", _MAX_TRANSFER)
    verify_transfer(transfer, role, correlation, state["sourceSha"], state["artifactIds"])
    _replace_state(job, {**state, "phase": "preparing-qemu"})
    prepare = job / "host/prepare_linux_install_vm.py"
    _run(sys.executable, "-B", str(prepare), "--directory", str(tree),
         "--ssh-port", str(port), "--distribution", distribution, timeout=2400)
    launch = json.loads((tree / "launch.json").read_bytes())
    argv = launch.get("qemu")
    _need(isinstance(argv, list) and argv and all(isinstance(part, str) for part in argv) and
          any("file=" + str(tree / "task.qcow2") in part for part in argv) and
          any("hostfwd=tcp:127.0.0.1:" + str(port) + "-:22" in part for part in argv),
          "Host QEMU launch differs")
    policy = importlib.util.spec_from_file_location("fixed_qemu_policy", job / "host/fixture_environment.py")
    _need(policy is not None and policy.loader is not None,
          "Host QEMU launch policy is unavailable")
    module = importlib.util.module_from_spec(policy)
    policy.loader.exec_module(module)
    module.validate_qemu_argv(argv)
    qemu = _launch_qemu(job, argv)
    _replace_state(job, {**state, "phase": "booting-guest", "qemuPid": qemu.pid,
                         "qemuStartTicks": _ticks(qemu.pid)})
    ssh = _host_ssh(tree, port, ("sudo", "-n", "cloud-init", "status", "--wait"))
    _run(*ssh, timeout=1800)
    _need(qemu.poll() is None and _ticks(qemu.pid) > 0,
          "Host QEMU process exited before guest stage")
    _replace_state(job, {**state, "phase": "staging-guest", "qemuPid": qemu.pid,
                         "qemuStartTicks": _ticks(qemu.pid)})
    guest_command = ("sudo", "-n", "python3", "-I", "-B", "-c", _GUEST_BOOTSTRAP,
                     role, correlation, hashlib.sha256(transfer).hexdigest(), str(len(transfer)))
    result = _run(*_host_ssh(tree, port, guest_command), timeout=2400,
                  input_data=transfer)
    facts = json.loads(result.stdout)
    _need(isinstance(facts, dict) and set(facts) ==
          {"baseline", "fixture", "publicCli", "workerIntentSha256"},
          "Guest preparation facts are incomplete")
    disk = (tree / "task.qcow2").stat()
    qemu_ticks = _ticks(qemu.pid)
    guest = {"schemaVersion": 1, "host": "archlinux", "profile":
             "fresh-deb-dependencies" if role == "ubuntu-fresh" else
             "arch-rollback" if role == "arch-rollback" else "package-update",
             "distribution": distribution, "guestRole": role,
             "sourceSha": state["sourceSha"], "tree": str(tree), "sshPort": port,
             "qemuPid": qemu.pid, "qemuStartTicks": qemu_ticks,
             "diskDevice": disk.st_dev, "diskInode": disk.st_ino, "pristine": True}
    guest_raw = _canonical(guest)
    guest_id = "sha256-" + hashlib.sha256(guest_raw).hexdigest()
    scoped = json.loads((job / "guest/fixture/fixture-receipt.json").read_bytes())
    base = scoped["builds"][0]
    receipt = {"schemaVersion": 1, "host": "archlinux", "profile": guest["profile"],
        "distribution": distribution, "guestRole": role,
        "sourceSha": state["sourceSha"], "sourceFingerprint": manifest["sourceFingerprint"],
        "correlationId": correlation, "guestManifestArtifactId": guest_id,
        **{label + "ArtifactId": state["artifactIds"][label] for label in
           ("fixtureReceipt", "basePackage", "targetPackage", "bundleManifest")},
        "qemu": {"pid": qemu.pid, "startTicks": qemu_ticks,
                 "diskDevice": disk.st_dev, "diskInode": disk.st_ino,
                 "sshPort": port, "tree": str(tree)},
        "baseline": facts["baseline"], "fixture": facts["fixture"],
        "publicCli": facts["publicCli"],
        "safety": {"ownerRuntimeOff": True, "protectedJobsTerminal": True,
                   "rootOwnedStage": True},
        "stage": "/var/lib/vpn-control-parity/" + role,
        "workerIntentSha256": facts["workerIntentSha256"], "state": "ready"}
    receipt["nativeWorkerSha256"] = manifest["files"]["guest/agent_tools/linux_deb_arch_native_driver.py"]["sha256"]
    receipt["rollbackWorkerSha256"] = manifest["files"]["guest/agent_tools/linux_deb_arch_rollback.py"]["sha256"]
    _need(base["sourceFingerprint"] == manifest["sourceFingerprint"] and
          qemu.poll() is None and _ticks(qemu.pid) == qemu_ticks,
          "Host guest source or QEMU generation changed")
    _write_once(job / "guest-manifest.json", guest_raw)
    _write_once(job / "preparation-receipt.json", _canonical(receipt))
    _replace_state(job, {"state": "ready", "phase": "sealed", "guestRole": role,
        "correlationId": correlation, "sourceSha": state["sourceSha"],
        "artifactIds": state["artifactIds"], "guestManifest": guest,
        "preparationReceipt": receipt})


_REMOTE_SUBMIT = r'''import hashlib,importlib.util,io,json,os,stat,sys,tarfile
from pathlib import Path
role,correlation,source,digest,size,artifacts=sys.argv[1:]
if role not in ('ubuntu-fresh','ubuntu-update','arch-update','arch-rollback') or not 0<int(size)<=3221225472:raise ValueError('identity')
root=Path('/home/kardinal/.vpn-control-parity-prepare')
root.mkdir(mode=0o700,exist_ok=True)
info=root.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('root')
data=sys.stdin.buffer.read(int(size)+1)
if len(data)!=int(size) or hashlib.sha256(data).hexdigest()!=digest:raise ValueError('transfer')
worker=None
with tarfile.open(fileobj=io.BytesIO(data),mode='r:') as archive:
 for member in archive:
  if member.name=='host/worker.py' and member.isfile() and 0<member.size<=1000000:
   worker=archive.extractfile(member).read(member.size+1)
if worker is None or len(worker)>1000000:raise ValueError('worker')
loader=root/('candidate-'+correlation+'.py')
fd=os.open(loader,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream:stream.write(worker);stream.flush();os.fsync(stream.fileno())
spec=importlib.util.spec_from_file_location('fixed_guest_prep',loader)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
print(json.dumps(module.host_submit(data,role,correlation,source,json.loads(artifacts),worker_source=worker)))
'''

_REMOTE_STATUS = r'''import importlib.util,json,os,stat,sys
from pathlib import Path
role,correlation=sys.argv[1:]
root=Path('/home/kardinal/.vpn-control-parity-prepare')
candidate=root/('candidate-'+correlation+'.py')
info=candidate.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('candidate')
spec=importlib.util.spec_from_file_location('fixed_guest_prep',candidate)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
print(json.dumps(module.host_status(role,correlation)))
'''


class FixedRemoteDriver:
    """Local transport; only the fixed archlinux alias and role are addressable."""

    def __init__(self, root: Path | str, *, runner: Any = subprocess.run):
        self.root = Path(root).resolve(strict=True)
        self.runner = runner

    def submit(self, request: Any, admitted: Mapping[str, Any]) -> Mapping[str, Any]:
        from agent_tools import linux_deb_arch_guest_prepare as prep, ssh_transport
        raw, _ = prep.transfer_bundle(self.root, request, admitted)
        config = ssh_transport.load_config(self.root)
        host = config.hosts.get("archlinux")
        _need(host is not None and host.user == "kardinal" and host.password is None,
              "Fixed Linux preparation host is unavailable")
        command = ("python3", "-I", "-B", "-c", _REMOTE_SUBMIT,
                   request.guest_role, request.correlation_id, request.source_sha,
                   hashlib.sha256(raw).hexdigest(), str(len(raw)),
                   json.dumps(dict(request.artifact_ids), sort_keys=True, separators=(",", ":")))
        argv = ssh_transport.build_ssh_argv(config, "archlinux", 60, command=command)
        done = self.runner(argv, input=raw, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, timeout=1800)
        _need(done.returncode == 0 and len(done.stdout) <= 4096,
              "Fixed Linux preparation submission is uncertain")
        result = json.loads(done.stdout)
        _need(result == {"state": "submitted", "correlationId": request.correlation_id},
              "Fixed Linux preparation submission differs")
        return result

    def status(self, request: Any) -> Mapping[str, Any]:
        from agent_tools import ssh_transport
        config = ssh_transport.load_config(self.root)
        host = config.hosts.get("archlinux")
        _need(host is not None and host.user == "kardinal" and host.password is None,
              "Fixed Linux preparation host is unavailable")
        command = ("python3", "-I", "-B", "-c", _REMOTE_STATUS,
                   request.guest_role, request.correlation_id)
        argv = ssh_transport.build_ssh_argv(config, "archlinux", 30, command=command)
        done = self.runner(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=35)
        _need(done.returncode == 0 and len(done.stdout) <= 16384,
              "Fixed Linux preparation status is unavailable")
        result = json.loads(done.stdout)
        _need(isinstance(result, dict) and result.get("correlationId") == request.correlation_id and
              result.get("sourceSha") == request.source_sha and
              result.get("guestRole") == request.guest_role and
              result.get("artifactIds") == request.artifact_ids and
              result.get("state") in {"running", "failed", "unknown", "ready"},
              "Fixed Linux preparation status differs")
        if result["state"] != "ready":
            return result
        return self._admit_ready(request, result)

    def _admit_ready(self, request: Any, remote: Mapping[str, Any]) -> Mapping[str, Any]:
        from agent_tools import (linux_deb_arch_acceptance as acceptance,
                                 linux_deb_arch_guest_prepare as prep,
                                 linux_deb_arch_transport as transport,
                                 native_artifact_registry)
        guest = remote.get("guestManifest")
        receipt = remote.get("preparationReceipt")
        _need(isinstance(guest, dict) and isinstance(receipt, dict),
              "Fixed Linux preparation receipts are absent")
        guest_raw = _canonical(guest)
        receipt_raw = _canonical(receipt)
        guest_id = "sha256-" + hashlib.sha256(guest_raw).hexdigest()
        receipt_id = "sha256-" + hashlib.sha256(receipt_raw).hexdigest()
        captured = {key: acceptance._verified_artifact(self.root, identifier,
                    prep._KINDS[key], request.source_sha)
                    for key, identifier in request.artifact_ids.items()}
        fixture = acceptance._fixture(request, captured)
        acceptance._bundle(captured)
        bundle = json.loads(captured["bundleManifest"]["path"].read_bytes())
        harness = next((entry["sha256"] for entry in bundle["files"]
                       if entry["path"] == "scripts/test_linux_public_install.py"), None)
        _need(isinstance(harness, str) and _HASH.fullmatch(harness) is not None,
              "Fixed Linux preparation harness digest is absent")
        trust = None if request.profile == "fresh-deb-dependencies" else receipt.get("fixture", {}).get("trustStoreSha256")
        worker_raw = prep.worker_intent_bytes(request, fixture, trust,
            None if request.profile == "fresh-deb-dependencies" else harness)
        worker_sha = hashlib.sha256(worker_raw).hexdigest()
        source_worker_digests = {}
        for label, name in (("native", "linux_deb_arch_native_driver.py"),
                            ("rollback", "linux_deb_arch_rollback.py")):
            source = subprocess.run(["git", "-C", str(self.root), "show",
                request.source_sha + ":agent_tools/" + name],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15, check=False)
            _need(source.returncode == 0 and 0 < len(source.stdout) <= 1024 * 1024,
                  "Fixed Linux preparation worker source is unavailable")
            source_worker_digests[label] = hashlib.sha256(source.stdout).hexdigest()
        prep.validate_receipt(request, receipt, fixture, guest,
                              guest_manifest_artifact_id=guest_id,
                              worker_intent_sha256=worker_sha,
                              native_worker_sha256=source_worker_digests["native"],
                              rollback_worker_sha256=source_worker_digests["rollback"])
        artifacts = {**request.artifact_ids, "guestManifest": guest_id,
                     "preparationReceipt": receipt_id}
        intent = acceptance.Intent.parse({"profile": request.profile,
            "distribution": request.distribution, "correlationId": request.correlation_id,
            "sourceSha": request.source_sha, "artifactIds": artifacts})
        observed = transport.FixedLiveObserver(self.root)(intent, guest, receipt)
        _need(observed.get("ready") is True and observed.get("qemuPid") == guest["qemuPid"] and
              observed.get("qemuStartTicks") == guest["qemuStartTicks"] and
              observed.get("diskDevice") == guest["diskDevice"] and
              observed.get("diskInode") == guest["diskInode"] and
              observed.get("ownerRuntimeOff") is True and
              observed.get("protectedJobsTerminal") is True and
              observed.get("packageProcessesOff") is True and
              observed.get("profileUnused") is True,
              "Fixed Linux preparation live guest differs")
        journal = prep._journal_dir(self.root, create=False)
        _need(journal is not None, "Fixed Linux preparation local journal is absent")
        evidence = journal / request.correlation_id
        evidence.mkdir(mode=0o700, exist_ok=True)
        _private(evidence, directory=True)
        for name, raw, kind in (("guest-manifest.json", guest_raw, "guest-manifest"),
                                ("preparation-receipt.json", receipt_raw, "linux-guest-preparation")):
            path = evidence / name
            if path.exists() or path.is_symlink():
                _need(_read_private(path, 16384) == raw,
                      "Fixed Linux preparation local receipt conflicts")
            else:
                _write_once(path, raw)
            native_artifact_registry.register_artifact(self.root, {
                "platform": "linux", "artifactKind": kind, "localPath": str(path),
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                "evidenceClass": "local-verified", "sourceSha": request.source_sha,
                "sourceFingerprint": fixture["sourceFingerprint"]})
        return {"state": "ready", "correlationId": request.correlation_id,
                "sourceSha": request.source_sha, "guestRole": request.guest_role,
                "artifactIds": dict(request.artifact_ids),
                "guestManifestArtifactId": guest_id,
                "preparationReceiptArtifactId": receipt_id,
                "liveReady": True}


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--host-worker":
        _, _, role, correlation = sys.argv
        try:
            run_host_worker(role, correlation)
        except BaseException as error:
            job = _HOST_ROOT / correlation
            try:
                prior = host_status(role, correlation, check_worker=False)
                phase = prior.get("phase", "unknown")
                classified = "failed" if phase == "submitted" else "unknown"
                _replace_state(job, {"state": classified, "phase": phase,
                    "guestRole": role, "correlationId": correlation,
                    "sourceSha": prior["sourceSha"], "artifactIds": prior["artifactIds"],
                    "reason": type(error).__name__})
            except BaseException:
                pass
            raise SystemExit(1)
    elif len(sys.argv) == 4 and sys.argv[1] == "--guest-prep":
        _, _, role, correlation = sys.argv
        result = guest_prepare(Path("/var/lib/vpn-control-parity") / role, role, correlation)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        raise SystemExit("Fixed remote preparation worker requires a fixed role and correlation")
