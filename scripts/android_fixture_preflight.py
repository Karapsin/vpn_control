"""Fail-closed preflight helpers for reversible Android fixture inspections."""

from collections.abc import Mapping


EFFECTIVE_PROXY_FIELDS = (
    "http_proxy",
    "global_http_proxy_host",
    "global_http_proxy_port",
    "global_http_proxy_pac",
    "global_http_proxy_exclusion_list",
)

_DISABLED_PROXY_VALUES = frozenset((None, "", "null"))
_DISABLED_PROXY_PORTS = _DISABLED_PROXY_VALUES | frozenset(("0", "-1"))


def read_effective_proxy(read_global_setting) -> dict[str, str | None]:
    """Read every Android setting that can independently retain a global proxy."""
    if not callable(read_global_setting):
        raise ValueError("Effective proxy reader must be callable")
    settings = {field: read_global_setting(field) for field in EFFECTIVE_PROXY_FIELDS}
    if any(value is not None and not isinstance(value, str) for value in settings.values()):
        raise ValueError("Effective proxy settings must be text or unset")
    return settings


def require_disconnected_effective_proxy(settings: Mapping[str, str | None]) -> dict[str, str | None]:
    """Accept only an entirely disabled Android global-proxy representation."""
    if not isinstance(settings, Mapping) or set(settings) != set(EFFECTIVE_PROXY_FIELDS):
        raise ValueError("Effective proxy settings are incomplete")
    values = dict(settings)
    if any(value is not None and not isinstance(value, str) for value in values.values()):
        raise ValueError("Effective proxy settings must be text or unset")
    disabled = (
        values["http_proxy"] in _DISABLED_PROXY_VALUES | frozenset((":0",)),
        values["global_http_proxy_host"] in _DISABLED_PROXY_VALUES,
        values["global_http_proxy_port"] in _DISABLED_PROXY_PORTS,
        values["global_http_proxy_pac"] in _DISABLED_PROXY_VALUES,
        values["global_http_proxy_exclusion_list"] in _DISABLED_PROXY_VALUES,
    )
    if not all(disabled):
        raise ValueError("Fixture effective proxy baseline is not approved")
    return values


def require_terminal_operation_history(response: Mapping, controller: str) -> list[dict]:
    """Accept same-owner terminal operation history while rejecting any active work."""
    if not isinstance(controller, str) or not controller:
        raise ValueError("Operation history requires a controller")
    if (not isinstance(response, Mapping) or response.get("ok") is not True or
            response.get("final") is not True or response.get("code") != "OK" or
            response.get("controllerId") != controller or response.get("operationId") is not None):
        raise ValueError("Operation history requires a final same-owner envelope")
    data = response.get("data")
    if not isinstance(data, Mapping) or data.get("scope") != "android-provider-operations":
        raise ValueError("Operation history has an invalid data scope")
    entries = data.get("operations")
    if not isinstance(entries, list):
        raise ValueError("Operation history entries must be a list")
    required_text = ("id", "operation", "requestId", "phase", "code")
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("Operation history entry is malformed")
        if (entry.get("controllerId") != controller or entry.get("final") is not True or
                entry.get("code") in ("OUTCOME_UNKNOWN", "ACCEPTED") or
                entry.get("cancellable") is not False or not isinstance(entry.get("restartRequired"), bool) or
                isinstance(entry.get("configurationRevision"), bool) or
                not isinstance(entry.get("configurationRevision"), int) or entry["configurationRevision"] < 0 or
                any(not isinstance(entry.get(key), str) or not entry[key] for key in required_text)):
            raise ValueError("Operation history contains a nonterminal or malformed operation")
    return entries


def source_inspection_guard(status_response):
    """Return the exact public controller/revision guard for a source mutation."""
    if (not isinstance(status_response, dict) or status_response.get("ok") is not True or
            status_response.get("final") is not True or status_response.get("code") != "OK"):
        raise ValueError("Source inspection requires a final successful status")
    controller = status_response.get("controllerId")
    revision = status_response.get("configurationRevision")
    if (not isinstance(controller, str) or not controller or isinstance(revision, bool) or
            not isinstance(revision, int) or revision < 0):
        raise ValueError("Source inspection requires controller and revision")
    data = status_response.get("data")
    if not isinstance(data, dict):
        raise ValueError("Source inspection requires status data")
    if (data.get("runtimeRunning") is not False or data.get("runtimeObservation") != "stopped" or
            "selectedLocationId" not in data or data["selectedLocationId"] is not None):
        raise ValueError("Source inspection requires an unselected authoritative OFF state")
    return {"controllerId": controller, "configurationRevision": revision}
