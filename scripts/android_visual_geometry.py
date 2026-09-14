#!/usr/bin/env python3
"""Classify the primary Android display geometry used by visual capture.

The Android API 35 Pixel 6 emulator can expose a short-lived stale WindowManager
allocation after its first boot: SystemUI and the cutout use 128 pixels, while
the status-bar surface remains at the 24dp default (63 pixels at 420dpi).  The
caller owns polling and any reboot; this module only parses one dump and makes
the outcome deterministic.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
import sys


READY = "ready"
TRANSIENT = "transient"
REBOOT_REQUIRED = "reboot_required"

_DISPLAY_ID = re.compile(r"^\s*displayId=(?P<display_id>\d+)\b", re.MULTILINE)
_DISPLAY_FRAME = re.compile(
    r"mDisplayFrame=Rect\(\s*0,\s*0\s*-\s*(?P<width>\d+),\s*(?P<height>\d+)\)",
)
_CUTOUT = re.compile(
    r"mDisplayCutout=DisplayCutout\{.*?insets=Rect\(\s*\d+,\s*(?P<top>\d+)\s*-",
)
_STATUS_BAR = re.compile(
    r"InsetsSource\b.*?type=statusBars\s+frame=\[\s*(?P<left>\d+),\s*(?P<top>\d+)\]"
    r"\[\s*(?P<right>\d+),\s*(?P<bottom>\d+)\]\s+visible=(?P<visible>true|false)",
)


class GeometryParseError(ValueError):
    """The dump did not include a complete primary-display insets state."""


@dataclass(frozen=True)
class PrimaryDisplayGeometry:
    width: int
    height: int
    cutout_top: int
    status_bar_height: int
    status_bar_visible: bool


def _primary_display_section(dumpsys_window_displays: str) -> str:
    displays = list(_DISPLAY_ID.finditer(dumpsys_window_displays))
    for index, display in enumerate(displays):
        if int(display.group("display_id")) != 0:
            continue
        end = displays[index + 1].start() if index + 1 < len(displays) else len(dumpsys_window_displays)
        return dumpsys_window_displays[display.start():end]
    raise GeometryParseError("dumpsys window displays did not contain primary displayId=0")


def parse_primary_display_geometry(dumpsys_window_displays: str) -> PrimaryDisplayGeometry:
    """Extract the primary display's cutout and status-bar allocation only."""
    section = _primary_display_section(dumpsys_window_displays)
    frame = _DISPLAY_FRAME.search(section)
    cutout = _CUTOUT.search(section)
    status_bar = _STATUS_BAR.search(section)
    if not frame or not cutout or not status_bar:
        raise GeometryParseError("primary display geometry was incomplete")
    status_top = int(status_bar.group("top"))
    status_bottom = int(status_bar.group("bottom"))
    return PrimaryDisplayGeometry(
        width=int(frame.group("width")),
        height=int(frame.group("height")),
        cutout_top=int(cutout.group("top")),
        status_bar_height=max(0, status_bottom - status_top),
        status_bar_visible=status_bar.group("visible") == "true",
    )


def classify_primary_display_geometry(dumpsys_window_displays: str) -> str:
    """Return whether the owned emulator can capture or needs a normal reboot.

    A zero-sized or hidden status bar is normal while SystemUI is coming up and
    is deliberately transient rather than a reboot request.  A nonzero cutout
    taller than a visible, nonzero status bar is the observed stale allocation.
    """
    geometry = parse_primary_display_geometry(dumpsys_window_displays)
    if (
        geometry.width == 0
        or geometry.height == 0
        or not geometry.status_bar_visible
        or geometry.status_bar_height == 0
    ):
        return TRANSIENT
    if geometry.cutout_top > geometry.status_bar_height:
        return REBOOT_REQUIRED
    return READY


def main() -> int:
    """Read one ``dumpsys window displays`` response and fail closed when unsafe.

    This command deliberately has no ADB or reboot behavior.  The capture wrapper
    invokes it only after it has proved that its selected serial is task-owned.
    """
    try:
        outcome = classify_primary_display_geometry(sys.stdin.read())
    except GeometryParseError as exc:
        print(f"Android visual geometry is incomplete: {exc}. Do not capture yet.", file=sys.stderr)
        return 2
    if outcome == READY:
        return 0
    if outcome == TRANSIENT:
        print(
            "Android visual primary display is still initializing; wait for a nonzero visible status bar.",
            file=sys.stderr,
        )
        return 3
    print(
        "Android visual primary status bar is shorter than its cutout; reboot the validated owned AVD, then retry.",
        file=sys.stderr,
    )
    return 4


if __name__ == "__main__":
    raise SystemExit(main())
