#!/usr/bin/env python3
"""Pure, credential-free freshness guard for a reviewed Windows UAC observation.

The screenshot hash only binds this input attempt to the current captured frame; it
does not recognise UAC UI. Animated or blinking prompt content can therefore reject
an otherwise safe attempt and must be reviewed by the caller.
"""

import hashlib
import math
import re
from collections.abc import Mapping


DEFAULT_MAX_AGE_SECONDS = 15.0
DEFAULT_LOGIN_MAX_AGE_SECONDS = 5.0
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


def _ppm_crop(frame, rect, width, height):
    """Return RGB pixels in a bounded P6 screenshot crop."""
    if not isinstance(frame, bytes):
        raise ValueError("screenshot must be P6 bytes")
    parts = frame.split(b"\n", 3)
    if len(parts) != 4 or parts[:3] != [b"P6", f"{width} {height}".encode(), b"255"]:
        raise ValueError("unexpected screenshot format or dimensions")
    pixels = parts[3]
    if len(pixels) != width * height * 3:
        raise ValueError("incomplete screenshot")
    if (not isinstance(rect, (tuple, list)) or len(rect) != 4 or
            any(isinstance(v, bool) or not isinstance(v, int) for v in rect)):
        raise ValueError("invalid screenshot crop")
    x0, y0, x1, y1 = rect
    if not (0 <= x0 < x1 <= width and 0 <= y0 < y1 <= height):
        raise ValueError("screenshot crop out of bounds")
    return b"".join(pixels[(y * width + x0) * 3:(y * width + x1) * 3]
                    for y in range(y0, y1))


def _selected_account(frame, profile, account):
    crop = _ppm_crop(frame, profile["accountRect"], profile["width"], profile["height"])
    expected = _hash(profile["accountCropSha256ByName"][account], "expected account crop")
    if hashlib.sha256(crop).hexdigest() != expected:
        raise ValueError("selected account changed")


def run_login_if_current(metadata, *, expected_qemu_identity, expected_account_name,
                         profile, capture_frame, now, read_credential,
                         type_credential, submit,
                         max_age_seconds=DEFAULT_LOGIN_MAX_AGE_SECONDS):
    """Submit a credential only for the freshly observed selected account.

    The caller supplies a reviewed account-specific screenshot profile. This
    helper never stores, returns, or logs the private credential or screenshots.
    """
    if not isinstance(metadata, Mapping) or set(metadata) != {"observedAt", "qemuIdentity", "accountName"}:
        raise ValueError("metadata must contain only login observation fields")
    if not isinstance(profile, Mapping):
        raise ValueError("login screenshot profile is required")
    callbacks = (capture_frame, read_credential, type_credential, submit)
    if not all(callable(callback) for callback in callbacks):
        raise ValueError("login callbacks are required")
    observed_at = _finite_timestamp(metadata["observedAt"], "observation")
    current_time = _finite_timestamp(now, "current")
    maximum = _finite_timestamp(max_age_seconds, "max_age")
    if not 0 < maximum <= DEFAULT_LOGIN_MAX_AGE_SECONDS or not 0 <= current_time - observed_at <= maximum:
        raise ValueError("stale login observation")
    if _identity(metadata["qemuIdentity"], "observed QEMU") != _identity(expected_qemu_identity, "expected QEMU"):
        raise ValueError("QEMU identity changed")
    account = _identity(expected_account_name, "expected account")
    if _identity(metadata["accountName"], "observed account") != account:
        raise ValueError("selected account changed")
    if account not in profile.get("accountCropSha256ByName", {}):
        raise ValueError("no reviewed crop for selected account")
    width, height = profile["width"], profile["height"]
    if (isinstance(width, bool) or isinstance(height, bool) or
            not isinstance(width, int) or not isinstance(height, int) or
            width <= 0 or height <= 0):
        raise ValueError("invalid screenshot dimensions")

    before = capture_frame()
    _selected_account(before, profile, account)
    field = _ppm_crop(before, profile["fieldRect"], width, height)
    bright = sum(max(field[i:i + 3]) >= 240 for i in range(0, len(field), 3))
    limit = profile["maxEmptyFieldBrightPixels"]
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0 or bright > limit:
        raise ValueError("password field is not empty")
    caps = _ppm_crop(before, profile["capsRect"], width, height)
    if any(value >= 240 for value in caps):
        raise ValueError("Caps Lock indicator is on or changed")

    credential = read_credential()
    type_credential(credential)
    after = capture_frame()
    _selected_account(after, profile, account)
    submit()
    return {"ageSeconds": current_time - observed_at, "accountName": account}
