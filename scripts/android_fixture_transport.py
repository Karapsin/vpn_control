"""Scoped transport setup for disposable Android HTTPS fixtures."""


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


def establish_fixture_transport(adb, device_port: int, host_port: int) -> None:
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
    adb.set_global_proxy(fixture_proxy(device_port))


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
