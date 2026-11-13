#!/usr/bin/env python3
"""Region evidence of Windows OS-owned visual scenes (VISUAL-002, VISUAL-004).

A Windows OS-owned scene image is the target surface's own region, located by native identity.
The full screen of the same moment is kept beside it as ``<scene>.frame.png`` and described by
``<scene>.region.json``: target identity, rectangle, canonical placement and stable-frame attempts.
The frame is diagnostic evidence and is never compared.

``check`` validates that evidence: the record's own consistency, the PNG sizes, and that every part
of the scene image equals its rectangle in the diagnostic frame (the rest is fill). ``crop`` is the
crop step for the secure-desktop scene: it turns retained full VM frames of one prompt into the same
evidence, at the rectangle the capture route located by native identity inside the guest. Standard
library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

if __package__:
    from . import visual_regression
else:
    import visual_regression


SCHEMA_VERSION = 1
PART_GAP = 8
FILL_RGB = (0, 0, 0)
MAX_STABLE_ATTEMPTS = 20
MAX_PARTS = 4
REQUIRED_FIELDS = (
    "schema_version", "platform", "scene", "image", "image_size", "frame", "frame_size", "screen",
    "fill_rgb", "parts", "stable_frame", "occlusion",
)


class RegionEvidenceError(ValueError):
    pass


def image_name(scene_id: str) -> str:
    return f"{scene_id}.png"


def frame_name(scene_id: str) -> str:
    return f"{scene_id}.frame.png"


def record_name(scene_id: str) -> str:
    return f"{scene_id}.region.json"


def requires_region(platform: str, scene: dict[str, Any]) -> bool:
    """Every Windows OS-owned scene is a region capture (VISUAL-002)."""
    return platform == "windows" and scene.get("geometry_required", True) is False


def _unique_fields(rows: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in rows:
        if key in value:
            raise RegionEvidenceError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def load_record(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_fields)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegionEvidenceError(f"unreadable region record {path.name}: {exc}") from exc
    if not isinstance(value, dict):
        raise RegionEvidenceError(f"region record {path.name} must be a JSON object")
    return value


def _int(value: object, label: str) -> int:
    if type(value) is not int:
        raise RegionEvidenceError(f"{label} must be an integer")
    return value


def _pair(value: object, label: str) -> tuple[int, int]:
    if not isinstance(value, list) or len(value) != 2:
        raise RegionEvidenceError(f"{label} must be a pair of integers")
    return _int(value[0], label), _int(value[1], label)


def _rect(value: object, label: str) -> tuple[int, int, int, int]:
    if not isinstance(value, list) or len(value) != 4:
        raise RegionEvidenceError(f"{label} must be [left, top, right, bottom]")
    left, top, right, bottom = (_int(item, label) for item in value)
    if right <= left or bottom <= top:
        raise RegionEvidenceError(f"{label} is empty: {value}")
    return left, top, right, bottom


def _inside(inner: tuple[int, int, int, int], outer: tuple[int, int, int, int]) -> bool:
    return inner[0] >= outer[0] and inner[1] >= outer[1] and inner[2] <= outer[2] and inner[3] <= outer[3]


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise RegionEvidenceError(f"{label} must be a non-empty string")
    return value


def validate_record(record: dict[str, Any], *, scene_id: str, platform: str) -> dict[str, Any]:
    """Checks a region record against itself; returns its normalized geometry."""
    missing = [field for field in REQUIRED_FIELDS if field not in record]
    if missing:
        raise RegionEvidenceError("region record lacks " + ", ".join(missing))
    if record["schema_version"] != SCHEMA_VERSION:
        raise RegionEvidenceError("region record schema_version must be 1")
    if record["platform"] != platform or record["scene"] != scene_id:
        raise RegionEvidenceError(f"region record names {record['platform']}/{record['scene']}, not {platform}/{scene_id}")
    if record["image"] != image_name(scene_id) or record["frame"] != frame_name(scene_id):
        raise RegionEvidenceError("region record must name the scene image and its diagnostic frame")
    image_size = _pair(record["image_size"], "image_size")
    frame_size = _pair(record["frame_size"], "frame_size")
    if min(image_size) <= 0:
        raise RegionEvidenceError("image_size must be positive")
    screen = _rect(record["screen"], "screen")
    if (screen[2] - screen[0], screen[3] - screen[1]) != frame_size:
        raise RegionEvidenceError("frame_size must equal the captured screen")
    fill = record["fill_rgb"]
    if not isinstance(fill, list) or len(fill) != 3 or any(type(item) is not int or not 0 <= item <= 255 for item in fill):
        raise RegionEvidenceError("fill_rgb must be three integers from 0 to 255")
    parts = record["parts"]
    if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_PARTS:
        raise RegionEvidenceError(f"parts must list 1 to {MAX_PARTS} surfaces")
    geometry: list[tuple[tuple[int, int, int, int], tuple[int, int]]] = []
    placed: list[tuple[int, int, int, int]] = []
    for index, part in enumerate(parts):
        label = f"parts[{index}]"
        if not isinstance(part, dict):
            raise RegionEvidenceError(f"{label} must be an object")
        _text(part.get("role"), f"{label}.role")
        target = part.get("target")
        if not isinstance(target, dict):
            raise RegionEvidenceError(f"{label}.target must be the surface's native identity")
        _text(target.get("kind"), f"{label}.target.kind")
        _text(target.get("locator"), f"{label}.target.locator")
        if not isinstance(part.get("placement"), dict):
            raise RegionEvidenceError(f"{label}.placement must be an object")
        rect = _rect(part.get("rect"), f"{label}.rect")
        if not _inside(rect, screen):
            raise RegionEvidenceError(f"{label}.rect {list(rect)} lies outside the captured screen")
        offset = _pair(part.get("offset"), f"{label}.offset")
        box = (offset[0], offset[1], offset[0] + rect[2] - rect[0], offset[1] + rect[3] - rect[1])
        if not _inside(box, (0, 0, image_size[0], image_size[1])):
            raise RegionEvidenceError(f"{label} does not fit the scene image")
        if any(box[0] < other[2] and other[0] < box[2] and box[1] < other[3] and other[1] < box[3] for other in placed):
            raise RegionEvidenceError(f"{label} overlaps another part in the scene image")
        placed.append(box)
        geometry.append((rect, offset))
    # VISUAL-002: several surfaces are stacked in one fixed layout, as the Kotlin capture composes them.
    size, offsets = stack_layout([(rect[2] - rect[0], rect[3] - rect[1]) for rect, _ in geometry])
    if image_size != size or [offset for _, offset in geometry] != offsets:
        raise RegionEvidenceError(
            f"parts must be stacked top to bottom, left-aligned and {PART_GAP} px apart in a {size[0]}x{size[1]} image",
        )
    stable = record["stable_frame"]
    if not isinstance(stable, dict):
        raise RegionEvidenceError("stable_frame must be an object")
    attempts = _int(stable.get("attempts"), "stable_frame.attempts")
    maximum = _int(stable.get("max_attempts"), "stable_frame.max_attempts")
    if not 2 <= attempts <= maximum <= MAX_STABLE_ATTEMPTS:
        raise RegionEvidenceError(
            f"stable_frame needs 2 <= attempts <= max_attempts <= {MAX_STABLE_ATTEMPTS}; got {attempts}/{maximum}",
        )
    if not isinstance(record["occlusion"], dict):
        raise RegionEvidenceError("occlusion must be an object")
    return {
        "image_size": image_size,
        "frame_size": frame_size,
        "screen": screen,
        "fill": tuple(fill),
        "parts": geometry,
    }


def verify_images(
    geometry: dict[str, Any],
    image: visual_regression.PngImage,
    frame: visual_regression.PngImage,
) -> None:
    """Every part equals its rectangle in the frame of the same moment; the rest is fill."""
    if (image.width, image.height) != geometry["image_size"]:
        raise RegionEvidenceError(f"scene image is {image.width}x{image.height}, record says {geometry['image_size']}")
    if (frame.width, frame.height) != geometry["frame_size"]:
        raise RegionEvidenceError(f"diagnostic frame is {frame.width}x{frame.height}, record says {geometry['frame_size']}")
    screen_left, screen_top = geometry["screen"][0], geometry["screen"][1]
    covered = bytearray(image.width * image.height)
    for index, (rect, offset) in enumerate(geometry["parts"]):
        width = rect[2] - rect[0]
        for row in range(rect[3] - rect[1]):
            source = ((rect[1] - screen_top + row) * frame.width + rect[0] - screen_left) * 4
            target = ((offset[1] + row) * image.width + offset[0]) * 4
            if image.pixels[target : target + width * 4] != frame.pixels[source : source + width * 4]:
                raise RegionEvidenceError(f"parts[{index}] differs from its rectangle in the diagnostic frame at row {row}")
            start = (offset[1] + row) * image.width + offset[0]
            covered[start : start + width] = b"\x01" * width
    fill = bytes(geometry["fill"])
    for pixel, flag in enumerate(covered):
        if not flag and image.pixels[pixel * 4 : pixel * 4 + 3] != fill:
            raise RegionEvidenceError(f"scene image pixel {pixel % image.width},{pixel // image.width} is outside every part but not fill")


def check_scene(platform: str, scene_id: str, directory: Path) -> dict[str, Any]:
    """Validates one scene's region evidence in a capture directory and returns its record."""
    record = load_record(directory / record_name(scene_id))
    geometry = validate_record(record, scene_id=scene_id, platform=platform)
    try:
        image = visual_regression.read_png(directory / image_name(scene_id))
        frame = visual_regression.read_png(directory / frame_name(scene_id))
    except (OSError, ValueError) as exc:
        raise RegionEvidenceError(f"unreadable region evidence image: {exc}") from exc
    verify_images(geometry, image, frame)
    return record


def stack_layout(sizes: list[tuple[int, int]], gap: int = PART_GAP) -> tuple[tuple[int, int], list[tuple[int, int]]]:
    """Parts stacked top to bottom, left-aligned, ``gap`` pixels apart (as the Kotlin capture does)."""
    if not sizes or any(width <= 0 or height <= 0 for width, height in sizes):
        raise RegionEvidenceError("parts need a positive size")
    offsets: list[tuple[int, int]] = []
    y = 0
    for index, (_, height) in enumerate(sizes):
        if index:
            y += gap
        offsets.append((0, y))
        y += height
    return (max(width for width, _ in sizes), y), offsets


def compose(
    frame: visual_regression.PngImage,
    screen: tuple[int, int, int, int],
    rects: list[tuple[int, int, int, int]],
) -> tuple[visual_regression.PngImage, list[tuple[int, int]]]:
    (width, height), offsets = stack_layout([(rect[2] - rect[0], rect[3] - rect[1]) for rect in rects])
    pixels = bytearray(bytes((*FILL_RGB, 255)) * (width * height))
    for rect, offset in zip(rects, offsets):
        if not _inside(rect, screen):
            raise RegionEvidenceError(f"region {list(rect)} lies outside the frame")
        part_width = rect[2] - rect[0]
        for row in range(rect[3] - rect[1]):
            source = ((rect[1] - screen[1] + row) * frame.width + rect[0] - screen[0]) * 4
            target = ((offset[1] + row) * width + offset[0]) * 4
            pixels[target : target + part_width * 4] = frame.pixels[source : source + part_width * 4]
    return visual_regression.PngImage(width, height, bytes(pixels)), offsets


def _write_new(path: Path, payload: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(payload)


def crop_frames(
    *,
    platform: str,
    scene_id: str,
    frames: list[Path],
    region: dict[str, Any],
    output: Path,
) -> dict[str, Any]:
    """Crop step for a scene whose surface was located inside a VM: full frames in, region evidence out.

    ``region`` comes from the capture route: the target's native identity and its rectangle in
    framebuffer pixels. The first frame whose crop equals the previous frame's crop (the later
    frame of the first identical pair) is published, and that full frame is kept.
    """
    if region.get("schema_version") != SCHEMA_VERSION or region.get("platform") != platform or region.get("scene") != scene_id:
        raise RegionEvidenceError("region input must be schema 1 for the requested platform and scene")
    if not 2 <= len(frames) <= MAX_STABLE_ATTEMPTS:
        raise RegionEvidenceError(f"the crop step needs 2 to {MAX_STABLE_ATTEMPTS} consecutive full frames")
    frame_size = _pair(region.get("frame_size"), "frame_size")
    raw_parts = region.get("parts")
    if not isinstance(raw_parts, list) or not 1 <= len(raw_parts) <= MAX_PARTS:
        raise RegionEvidenceError(f"region input must list 1 to {MAX_PARTS} parts")
    screen = (0, 0, frame_size[0], frame_size[1])
    rects = []
    for index, part in enumerate(raw_parts):
        if not isinstance(part, dict) or not isinstance(part.get("target"), dict):
            raise RegionEvidenceError(f"parts[{index}] needs its native target identity")
        _text(part.get("role"), f"parts[{index}].role")
        _text(part["target"].get("kind"), f"parts[{index}].target.kind")
        _text(part["target"].get("locator"), f"parts[{index}].target.locator")
        rect = _rect(part.get("rect"), f"parts[{index}].rect")
        if not _inside(rect, screen):
            raise RegionEvidenceError(f"parts[{index}].rect {list(rect)} lies outside the {frame_size[0]}x{frame_size[1]} frame")
        rects.append(rect)
    if not isinstance(region.get("occlusion"), dict):
        raise RegionEvidenceError("region input must state its occlusion evidence")
    decoded = []
    for path in frames:
        try:
            raw = path.read_bytes()
            image = visual_regression.read_png(path)
        except (OSError, ValueError) as exc:
            raise RegionEvidenceError(f"unreadable full frame {path.name}: {exc}") from exc
        if (image.width, image.height) != frame_size:
            raise RegionEvidenceError(f"full frame {path.name} is {image.width}x{image.height}, not {frame_size[0]}x{frame_size[1]}")
        decoded.append((raw, image, compose(image, screen, rects)))
    stable = next((index for index in range(1, len(decoded)) if decoded[index][2][0] == decoded[index - 1][2][0]), None)
    if stable is None:
        raise RegionEvidenceError(f"no two consecutive crops were identical in {len(decoded)} frames (unstable-frame)")
    raw, _, (image, offsets) = decoded[stable]
    record = {
        "schema_version": SCHEMA_VERSION,
        "platform": platform,
        "scene": scene_id,
        "image": image_name(scene_id),
        "image_size": [image.width, image.height],
        "frame": frame_name(scene_id),
        "frame_size": list(frame_size),
        "screen": list(screen),
        "fill_rgb": list(FILL_RGB),
        "parts": [
            {
                "role": part["role"],
                "target": part["target"],
                "rect": list(rect),
                "offset": list(offset),
                "placement": part.get("placement") if isinstance(part.get("placement"), dict) else {"policy": "os-placed"},
            }
            for part, rect, offset in zip(raw_parts, rects, offsets)
        ],
        "stable_frame": {
            "attempts": stable + 1,
            "max_attempts": len(decoded),
            "frames_sha256": [hashlib.sha256(item[0]).hexdigest() for item in decoded],
        },
        "occlusion": region["occlusion"],
        "source": {"crop_step": "scripts/visual_region.py", "frame_sha256": hashlib.sha256(raw).hexdigest()},
    }
    validate_record(record, scene_id=scene_id, platform=platform)
    output.mkdir(parents=True, exist_ok=True)
    targets = [output / image_name(scene_id), output / frame_name(scene_id), output / record_name(scene_id)]
    existing = [path.name for path in targets if path.exists() or path.is_symlink()]
    if existing:
        raise RegionEvidenceError("refusing to replace existing capture evidence: " + ", ".join(existing))
    encoded = visual_regression.encode_png(image)
    _write_new(targets[1], raw)
    _write_new(targets[0], encoded)
    _write_new(targets[2], (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    check_scene(platform, scene_id, output)
    return record


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    actions = parser.add_subparsers(dest="action", required=True)
    check = actions.add_parser("check", help="validate one scene's region evidence")
    check.add_argument("--platform", required=True, choices=("windows",))
    check.add_argument("--scene", required=True)
    check.add_argument("--dir", required=True, type=Path)
    crop = actions.add_parser("crop", help="crop retained full VM frames into region evidence")
    crop.add_argument("--platform", required=True, choices=("windows",))
    crop.add_argument("--scene", required=True)
    crop.add_argument("--frame", required=True, action="append", type=Path, help="consecutive full frames, oldest first")
    crop.add_argument("--region", required=True, type=Path, help="region input written by the capture route")
    crop.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.action == "check":
            record = check_scene(args.platform, args.scene, args.dir)
        else:
            record = crop_frames(
                platform=args.platform,
                scene_id=args.scene,
                frames=args.frame,
                region=load_record(args.region),
                output=args.output,
            )
    except RegionEvidenceError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "scene": record["scene"], "image_size": record["image_size"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
