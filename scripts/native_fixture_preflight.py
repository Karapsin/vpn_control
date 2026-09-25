"""Read-only desktop refresh fixture probe, safe to run on an owned Linux guest.

The script reads the desktop's fixed user workspace and makes one bounded HTTPS
request to its exact configured validation URL. It prints only categorical
admission evidence; workspace values, response bodies and errors stay private.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
from urllib.parse import urlsplit


def _regular_user_file(path: Path, maximum: int) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and 0 < info.st_size <= maximum)


def _settings(path: Path, expected_url: str, require_find_best: bool = True) -> dict[str, bool]:
    if not _regular_user_file(path, 4 * 1024 * 1024):
        return {"workspace": False, "settings": False, "benchmarkSettings": False}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        validation = data["validation_settings"]
        policy = data["subscription_refresh_policy"]
        enabled = data["find_best_after_subscription_refresh"]
        numeric = tuple(validation[key] for key in ("batch_size", "subscription_refresh_concurrency",
                                                  "retry_count", "active_verification_window_size"))
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return {"workspace": True, "settings": False, "benchmarkSettings": False}
    settings = (isinstance(validation, dict) and validation.get("test_url") == expected_url
                and isinstance(policy, str) and policy != "OFF" and enabled is require_find_best)
    benchmark = (settings and all(type(item) is int for item in numeric)
                 and numeric[0] > 0 and numeric[1] > 0 and numeric[2] >= 0 and numeric[3] > 0)
    return {"workspace": True, "settings": settings, "benchmarkSettings": benchmark}


def _target(url: str) -> tuple[str, int, str] | None:
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.fragment or len(url) > 2048 or any(ord(c) < 32 for c in url)):
            return None
        port = parsed.port or 443
        if not 1 <= port <= 65535:
            return None
        return parsed.hostname, port, (parsed.path or "/") + ("?" + parsed.query if parsed.query else "")
    except ValueError:
        return None


def _endpoint(url: str, timeout: int, certificate_path: Path | None) -> dict[str, bool]:
    target = _target(url)
    if target is None:
        return {"protocol": False, "certificate": False, "endpoint": False}
    hostname, port, path = target
    result = {"protocol": True, "certificate": False, "endpoint": False}
    if certificate_path is not None and not _regular_user_file(certificate_path, 1024 * 1024):
        return result
    try:
        context = ssl.create_default_context(cafile=str(certificate_path) if certificate_path else None)
        with socket.create_connection((hostname, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                result["certificate"] = True  # Verified hostname and validity window.
                request = (f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n"
                           "User-Agent: vpn-control-fixture-preflight\r\n\r\n").encode("ascii")
                tls.sendall(request)
                status = tls.recv(128).split(b"\r\n", 1)[0]
                result["endpoint"] = status.startswith(b"HTTP/1.") and status[9:12] in (b"200", b"204")
    except (OSError, UnicodeError, ValueError, ssl.SSLError):
        pass
    return result


def linux_scheduled_refresh(expected_url: str, timeout: int, certificate_path: Path | None = None,
                            workspace: Path | None = None, require_find_best: bool = True) -> dict[str, object]:
    if type(timeout) is not int or not 1 <= timeout <= 15:
        raise ValueError("Timeout must be 1..15 seconds")
    path = workspace if workspace is not None else Path.home() / ".vpn-control-desktop" / "workspace.json"
    checks = _settings(path, expected_url, require_find_best)
    checks.update(_endpoint(expected_url, timeout, certificate_path))
    return {"profile": "linux-scheduled-refresh", "checks": checks,
            "ready": all(checks.values())}


def linux_scheduled_static(typed_input: dict[str, object]) -> dict[str, object]:
    """Probe installed bytes and a protected, stopped controller before staging."""
    checks = {"package": False, "desktopJar": False, "protectedOwner": False}
    expected_package = typed_input.get("expectedPackageNevra")
    expected_jar = typed_input.get("expectedDesktopJarSha256")
    protected = typed_input.get("protectedStateDir")
    controller = typed_input.get("protectedControllerId")
    if (not isinstance(expected_package, str) or not isinstance(expected_jar, str)
            or not isinstance(protected, str) or not protected.startswith("/")
            or not isinstance(controller, str)):
        return {"profile": "linux-scheduled-refresh-static", "checks": checks, "ready": False}
    try:
        package = subprocess.run(["rpm", "-q", "vpn-control"], capture_output=True, text=True,
                                 timeout=10, check=False)
        verified = subprocess.run(["rpm", "-V", "vpn-control"], capture_output=True, text=True,
                                  timeout=10, check=False)
        checks["package"] = (package.returncode == 0 and package.stdout.strip() == expected_package
                              and verified.returncode == 0 and not verified.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        jars = list(Path("/opt/vpn-control/lib/app").glob("desktopApp-*.jar"))
        if len(jars) == 1 and jars[0].is_file() and not jars[0].is_symlink():
            digest = hashlib.sha256()
            with jars[0].open("rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            checks["desktopJar"] = digest.hexdigest() == expected_jar
    except OSError:
        pass
    try:
        result = subprocess.run(["/opt/vpn-control/bin/vpn-control", "--state-dir", protected,
                                 "--json", "status"], capture_output=True, text=True, timeout=10, check=False)
        if result.returncode == 0 and len(result.stdout) <= 65536:
            status = json.loads(result.stdout)
            data = status.get("data") if isinstance(status, dict) else None
            checks["protectedOwner"] = (isinstance(status, dict) and status.get("controllerId") == controller
                and isinstance(data, dict) and data.get("runtimeRunning") is False)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return {"profile": "linux-scheduled-refresh-static", "checks": checks,
            "ready": all(checks.values())}


def main() -> int:
    if sys.argv[1:] == ["--static-admission"]:
        try:
            raw = sys.stdin.buffer.read(65537)
            if not 0 < len(raw) <= 65536:
                raise ValueError()
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError()
            result = linux_scheduled_static(value)
        except (ValueError, UnicodeError):
            result = {"profile": "linux-scheduled-refresh-static", "checks":
                      {"package": False, "desktopJar": False, "protectedOwner": False}, "ready": False}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["ready"] else 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-url", required=True)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--certificate")
    parser.add_argument("--refresh-only", action="store_true")
    args = parser.parse_args()
    result = linux_scheduled_refresh(args.expected_url, args.timeout,
                                     Path(args.certificate) if args.certificate else None,
                                     require_find_best=not args.refresh_only)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
