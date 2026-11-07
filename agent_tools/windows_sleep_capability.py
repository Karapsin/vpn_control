"""Conservative projection of the owned English powercfg /a observation.

This reports a capability, never permission to request sleep. Other languages,
missing S3 rows and conflicting rows remain unrecognized.
"""

_AVAILABLE = "The following sleep states are available on this system:"
_UNAVAILABLE = "The following sleep states are not available on this system:"


def observe_s3(lines):
    if (type(lines) is not list or not 1 <= len(lines) <= 100
            or any(type(line) is not str or len(line) > 1024
                   or any(char in line for char in "\r\n\0") for line in lines)
            or sum(map(len, lines)) > 16384):
        raise ValueError("windows_sleep_capability_unrecognized")
    section = None
    headings = set()
    rows = []
    for index, line in enumerate(lines):
        if line in {_AVAILABLE, _UNAVAILABLE}:
            if line in headings:
                raise ValueError("windows_sleep_capability_unrecognized")
            headings.add(line)
            section = line
        elif line == "    Standby (S3)":
            if section is None:
                raise ValueError("windows_sleep_capability_unrecognized")
            reasons = []
            for following in lines[index + 1:]:
                if not following.strip() or not following.startswith("\t"):
                    break
                reasons.append(following.strip())
            rows.append((section, reasons))
    if (headings != {_AVAILABLE, _UNAVAILABLE} or len(rows) != 1
            or (rows[0][0] == _UNAVAILABLE) != bool(rows[0][1])):
        raise ValueError("windows_sleep_capability_unrecognized")
    supported = rows[0][0] == _AVAILABLE
    return {"schemaVersion": 1, "state": "supported" if supported else "unsupported",
            "reason": None if supported else "windows_s3_unsupported",
            "nativeReasons": rows[0][1], "powerAllowed": False}
