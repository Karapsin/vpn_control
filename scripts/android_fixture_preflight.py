"""Fail-closed preflight for a reversible Android source-scope inspection."""


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
