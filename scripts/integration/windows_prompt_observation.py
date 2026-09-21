#!/usr/bin/env python3
"""Pure, credential-free freshness guard for a reviewed Windows UAC observation.

The screenshot hash only binds this input attempt to the current captured frame; it
does not recognise UAC UI. Animated or blinking prompt content can therefore reject
an otherwise safe attempt and must be reviewed by the caller.
"""

import math
import re
from collections.abc import Mapping


DEFAULT_MAX_AGE_SECONDS = 15.0
_FIELDS = frozenset((
    "observedAt", "screenshotSha256", "qemuIdentity", "operationId", "operationTerminal",
))
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _finite_timestamp(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError("%s timestamp must be finite and non-negative" % name)
    return float(value)


def _identity(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError("%s identity must be a non-empty string" % name)
    return value


def _hash(value, name):
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("%s screenshot hash must be lowercase SHA-256" % name)
    return value


def run_if_current(metadata, *, expected_qemu_identity, expected_operation_id,
                   current_screenshot_sha256, now, max_age_seconds=DEFAULT_MAX_AGE_SECONDS,
                   action):
    """Call ``action`` once only after a fresh, exact, non-terminal observation.

    ``metadata`` deliberately accepts only the five nonsecret observation fields.
    The guard retains neither metadata nor the callback after this call.
    """
    if not isinstance(metadata, Mapping) or set(metadata) != _FIELDS:
        raise ValueError("metadata must contain only prompt observation fields")
    if not callable(action):
        raise ValueError("action callback is required")
    observed_at = _finite_timestamp(metadata["observedAt"], "observation")
    current_time = _finite_timestamp(now, "current")
    maximum = _finite_timestamp(max_age_seconds, "max_age")
    if not 0 < maximum <= DEFAULT_MAX_AGE_SECONDS:
        raise ValueError("max_age must be positive and at most 15 seconds")
    screenshot = _hash(metadata["screenshotSha256"], "observed")
    if screenshot != _hash(current_screenshot_sha256, "current"):
        raise ValueError("current screenshot hash changed")
    if _identity(metadata["qemuIdentity"], "observed QEMU") != _identity(expected_qemu_identity, "expected QEMU"):
        raise ValueError("QEMU identity changed")
    if _identity(metadata["operationId"], "observed operation") != _identity(expected_operation_id, "expected operation"):
        raise ValueError("operation identity changed")
    if metadata["operationTerminal"] is not False:
        raise ValueError("operation is terminal or has an invalid terminal state")
    age = current_time - observed_at
    if age < 0:
        raise ValueError("observation timestamp is in the future")
    if age > maximum:
        raise ValueError("stale prompt observation")
    action()
    return {"ageSeconds": age, "screenshotSha256": screenshot}
