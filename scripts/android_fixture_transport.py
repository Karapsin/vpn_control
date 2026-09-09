"""Scoped transport setup for disposable Android HTTPS fixtures."""
import subprocess
import re
from urllib.parse import urlsplit


def _tcp_port(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError(f"Fixture {label} port must be a TCP port")
    return value


def fixture_proxy(device_port: int) -> str:
    return f"127.0.0.1:{_tcp_port(device_port, 'device')}"


def _reverse_tcp_port(token: str) -> int:
    if not token.startswith("tcp:"):
        raise ValueError("Fixture reverse endpoint must be TCP")
    value = token.removeprefix("tcp:")
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError("Fixture reverse TCP port must be decimal")
    return _tcp_port(int(value), "reverse")


def parse_reverse_inventory(raw: str) -> dict[int, int]:
    """Parse `adb reverse --list` output without accepting ambiguous routes."""
    if not isinstance(raw, str):
        raise ValueError("Fixture reverse inventory must be text")
    routes: dict[int, int] = {}
    for line in raw.splitlines():
        fields = line.split()
        if not fields:
            continue
        # A selected transport can prepend its serial to the normal two endpoints.
        if len(fields) == 2:
            device, host = fields
        elif len(fields) == 3 and fields[0] and not fields[0].startswith("tcp:"):
            _, device, host = fields
        else:
            raise ValueError("Malformed fixture reverse inventory record")
        device_port = _reverse_tcp_port(device)
        if device_port in routes:
            raise ValueError("Duplicate fixture reverse target route")
        routes[device_port] = _reverse_tcp_port(host)
    return routes


def verify_device_socks_greeting(adb, device_port: int) -> None:
    """Require an end-to-end no-auth SOCKS greeting through the device route."""
    device_port = _tcp_port(device_port, "device")
    try:
        reply = adb.socks_greeting(device_port)
    except TimeoutError as error:
        raise RuntimeError("Fixture SOCKS greeting timed out") from error
    except EOFError as error:
        raise RuntimeError("Fixture SOCKS route closed before replying") from error
    except OSError as error:
        raise RuntimeError("Fixture SOCKS route is unavailable") from error
    if not isinstance(reply, bytes):
        raise RuntimeError("Fixture SOCKS greeting returned invalid bytes")
    if not reply:
        raise RuntimeError("Fixture SOCKS route closed before replying")
    if len(reply) != 2:
        raise RuntimeError("Fixture SOCKS greeting reply was partial")
    if reply != b"\x05\x00":
        raise RuntimeError("Fixture SOCKS greeting was rejected")


def adb_device_socks_greeting(adb_command: list[str], device_port: int, *, command_runner=subprocess.run) -> bytes:
    """Read one SOCKS greeting from a device route through an ADB exec-out pipe."""
    device_port = _tcp_port(device_port, "device")
    command = (
        "{ toybox printf '\\005\\001\\000'; toybox sleep 1; } | "
        f"toybox nc -w 2 -W 2 127.0.0.1 {device_port} | "
        "toybox dd bs=1 count=2 2>/dev/null"
    )
    try:
        result = command_runner([*adb_command, "exec-out", "sh", "-c", command], check=False,
                                capture_output=True, timeout=6)
    except subprocess.TimeoutExpired as error:
        raise TimeoutError("ADB SOCKS greeting timed out") from error
    except OSError as error:
        raise OSError("ADB SOCKS greeting could not start") from error
    if result.returncode:
        raise OSError("ADB SOCKS greeting command failed")
    return result.stdout


def verify_socks_validation_url(
    validation_url: str,
    socks_port: int,
    *,
    user_agent: str,
    command_runner=subprocess.run,
) -> str:
    """Run the configured HTTPS validation URL through a SOCKS peer with normal TLS."""
    socks_port = _tcp_port(socks_port, "SOCKS")
    parsed = urlsplit(validation_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Fixture validation URL must be a credential-free HTTPS URL")
    if not isinstance(user_agent, str) or not user_agent or "\r" in user_agent or "\n" in user_agent:
        raise ValueError("Fixture validation user agent must be a nonempty single line")
    command = [
        "curl", "--silent", "--show-error", "--output", "/dev/null", "--write-out", "%{http_code}",
        "--user-agent", user_agent,
        "--connect-timeout", "3", "--max-time", "8", "--proxy", f"socks5h://127.0.0.1:{socks_port}",
        "--noproxy", "",
        validation_url,
    ]
    try:
        result = command_runner(command, check=False, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired as error:
        raise TimeoutError("Fixture HTTPS validation timed out") from error
    except OSError as error:
        raise OSError("Fixture HTTPS validation could not start") from error
    if result.returncode:
        raise RuntimeError("Fixture HTTPS validation request failed")
    status = result.stdout.strip()
    if not re.fullmatch(r"[0-9]{3}", status):
        raise RuntimeError("Fixture HTTPS validation returned an invalid status")
    if not 200 <= int(status) <= 399:
        raise RuntimeError("Fixture HTTPS validation returned a non-success status")
    return status


def _establish_fixture_reverse(adb, device_port: int, host_port: int) -> tuple[int, int]:
    """Create a fixture route without clearing or replacing another route."""
    device_port = _tcp_port(device_port, "device")
    host_port = _tcp_port(host_port, "host")
    if adb.shell_id() != "uid=2000":
        # adbd restart clears all reverse mappings, so refuse to erase another fixture.
        if adb.reverse_inventory():
            raise RuntimeError("Fixture restart would clear existing reverse mappings")
        adb.unroot()
        adb.wait_for_device()
        if adb.shell_id() != "uid=2000":
            raise RuntimeError("Fixture setup requires public adbd")
    if adb.reverse_mapping(device_port) is not None:
        raise RuntimeError("Fixture target route already exists")
    adb.reverse(device_port, host_port)
    return device_port, host_port


def establish_fixture_transport(adb, device_port: int, host_port: int) -> None:
    device_port, _ = _establish_fixture_reverse(adb, device_port, host_port)
    adb.set_global_proxy(fixture_proxy(device_port))


def establish_socks_fixture_transport(adb, device_port: int, host_port: int) -> None:
    """Create a SOCKS route only after device-side greeting admission."""
    device_port, _ = _establish_fixture_reverse(adb, device_port, host_port)
    verify_device_socks_greeting(adb, device_port)


def cleanup_fixture_transport(adb, device_port: int, host_port: int, previous_proxy: str) -> None:
    """Restore only a fixture route and proxy state that still have our ownership."""
    device_port = _tcp_port(device_port, "device")
    host_port = _tcp_port(host_port, "host")
    if not isinstance(previous_proxy, str):
        raise ValueError("Fixture proxy baseline must be text")
    if adb.shell_id() != "uid=2000":
        raise RuntimeError("Fixture cleanup requires public adbd")
    if adb.reverse_mapping(device_port) != host_port:
        raise RuntimeError("Fixture reverse mapping ownership changed")
    current_proxy = adb.global_proxy()
    fixture_value = fixture_proxy(device_port)
    if current_proxy == fixture_value:
        # If this throws, the route remains usable and cleanup can be retried.
        adb.set_global_proxy(previous_proxy)
    elif current_proxy != previous_proxy:
        raise RuntimeError("Fixture proxy ownership changed")
    # A prior remove may have failed after baseline restoration; retry is safe.
    adb.remove_reverse(device_port)
