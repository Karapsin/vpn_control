"""Fail-closed preflight helpers for reversible Android fixture inspections."""

from collections.abc import Mapping
import re


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


def post_install_mutation_guard(status_response, operations_response):
    """Reacquire the Android owner and revision after an APK install.

    Installation may create a new controller epoch.  A fixture must use this
    fresh public status for its next guarded mutation, rather than retaining a
    controller/revision pair captured before installation.
    """
    guard = source_inspection_guard(status_response)
    require_terminal_operation_history(operations_response, guard["controllerId"])
    return guard


def admission_readback_guard(status_response, operations_response, routing_response, backup):
    """Validate one owner-scoped public snapshot and its private full backup.

    Readback deliberately permits a selected/running session.  Callers must
    separately establish the state required by each prospective mutation.
    """
    def envelope(value, label, owner=None):
        if (not isinstance(value, Mapping) or value.get("ok") is not True or
                value.get("final") is not True or value.get("code") != "OK" or
                value.get("operationId") is not None or
                not isinstance(value.get("controllerId"), str) or
                not value["controllerId"] or
                (owner is not None and value["controllerId"] != owner)):
            raise ValueError(f"{label} requires a final same-owner envelope")
        revision = value.get("configurationRevision")
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise ValueError(f"{label} requires a valid revision")
        return value["controllerId"], revision

    owner, revision = envelope(status_response, "Status")
    if not isinstance(status_response.get("data"), Mapping):
        raise ValueError("Status has no data")
    operations_owner, operations_revision = envelope(operations_response, "Operations", owner)
    require_terminal_operation_history(operations_response, owner)
    routing_owner, routing_revision = envelope(routing_response, "Routing", owner)
    if (operations_owner != owner or routing_owner != owner or
            operations_revision != revision or routing_revision != revision):
        raise ValueError("Readback revision changed")
    routing = routing_response.get("data")
    if not isinstance(routing, Mapping) or not isinstance(routing.get("routing"), Mapping):
        raise ValueError("Routing readback is incomplete")
    if (not isinstance(backup, Mapping) or
            not isinstance(backup.get("path"), str) or not backup["path"].startswith("/") or
            not re.fullmatch(r"[0-9a-f]{64}", str(backup.get("sha256"))) or
            isinstance(backup.get("size"), bool) or not isinstance(backup.get("size"), int) or
            not 0 < backup["size"] <= 67_108_864 or
            backup.get("type") != "vpn_control_routing_rules" or
            backup.get("version") != 7 or backup.get("rulesType") != "object" or
            backup.get("matchesReadback") is not True):
        raise ValueError("Full routing backup is invalid")
    return {"controllerId": owner, "configurationRevision": revision,
            "backupSha256": backup["sha256"], "backupSize": backup["size"]}
