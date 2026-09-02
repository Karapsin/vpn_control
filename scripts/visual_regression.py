#!/usr/bin/env python3
"""Verify VPN Control PNG screenshots and UI geometry without third-party packages."""

from __future__ import annotations

import argparse
import json
import math
import shutil
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "visual-tests" / "scenes.json"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


@dataclass(frozen=True)
class PngImage:
    width: int
    height: int
    pixels: bytes  # RGBA, row-major.


def _paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    if above_distance <= upper_left_distance:
        return above
    return upper_left


def read_png(path: Path) -> PngImage:
    raw = path.read_bytes()
    if not raw.startswith(PNG_SIGNATURE):
        raise ValueError(f"{path} is not a PNG")
    position = len(PNG_SIGNATURE)
    width = height = color_type = bit_depth = interlace = None
    compressed = bytearray()
    while position < len(raw):
        if position + 12 > len(raw):
            raise ValueError(f"{path} has a truncated PNG chunk")
        length = struct.unpack(">I", raw[position : position + 4])[0]
        kind = raw[position + 4 : position + 8]
        data_start = position + 8
        data_end = data_start + length
        payload = raw[data_start:data_end]
        if data_end + 4 > len(raw):
            raise ValueError(f"{path} has a truncated {kind!r} chunk")
        expected_crc = struct.unpack(">I", raw[data_end : data_end + 4])[0]
        actual_crc = zlib.crc32(kind + payload) & 0xFFFFFFFF
        if expected_crc != actual_crc:
            raise ValueError(f"{path} has an invalid {kind.decode('ascii', 'replace')} CRC")
        position = data_end + 4
        if kind == b"IHDR":
            width, height, bit_depth, color_type, compression, filtering, interlace = struct.unpack(
                ">IIBBBBB", payload,
            )
            if compression != 0 or filtering != 0:
                raise ValueError(f"{path} uses unsupported PNG compression/filtering")
        elif kind == b"IDAT":
            compressed.extend(payload)
        elif kind == b"IEND":
            break
    if None in (width, height, color_type, bit_depth, interlace):
        raise ValueError(f"{path} is missing IHDR")
    if bit_depth != 8 or interlace != 0 or color_type not in {0, 2, 4, 6}:
        raise ValueError(f"{path} must be a non-interlaced 8-bit gray/RGB/RGBA PNG")
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[color_type]
    stride = width * channels
    decoded = zlib.decompress(bytes(compressed))
    expected_length = height * (stride + 1)
    if len(decoded) != expected_length:
        raise ValueError(f"{path} decoded to {len(decoded)} bytes, expected {expected_length}")
    rows: list[bytearray] = []
    cursor = 0
    for _ in range(height):
        filter_type = decoded[cursor]
        cursor += 1
        source = decoded[cursor : cursor + stride]
        cursor += stride
        previous = rows[-1] if rows else bytearray(stride)
        row = bytearray(stride)
        for index, value in enumerate(source):
            left = row[index - channels] if index >= channels else 0
            above = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            if filter_type == 0:
                restored = value
            elif filter_type == 1:
                restored = value + left
            elif filter_type == 2:
                restored = value + above
            elif filter_type == 3:
                restored = value + ((left + above) // 2)
            elif filter_type == 4:
                restored = value + _paeth(left, above, upper_left)
            else:
                raise ValueError(f"{path} uses unsupported PNG filter {filter_type}")
            row[index] = restored & 0xFF
        rows.append(row)
    rgba = bytearray(width * height * 4)
    output = 0
    for row in rows:
        for offset in range(0, len(row), channels):
            if color_type == 0:
                red = green = blue = row[offset]
                alpha = 255
            elif color_type == 2:
                red, green, blue = row[offset : offset + 3]
                alpha = 255
            elif color_type == 4:
                red = green = blue = row[offset]
                alpha = row[offset + 1]
            else:
                red, green, blue, alpha = row[offset : offset + 4]
            rgba[output : output + 4] = bytes((red, green, blue, alpha))
            output += 4
    return PngImage(width=width, height=height, pixels=bytes(rgba))


def _chunk(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)


def write_png(path: Path, image: PngImage) -> None:
    if len(image.pixels) != image.width * image.height * 4:
        raise ValueError("RGBA pixel buffer has the wrong size")
    scanlines = bytearray()
    stride = image.width * 4
    for row in range(image.height):
        scanlines.append(0)
        start = row * stride
        scanlines.extend(image.pixels[start : start + stride])
    payload = PNG_SIGNATURE
    payload += _chunk(b"IHDR", struct.pack(">IIBBBBB", image.width, image.height, 8, 6, 0, 0, 0))
    payload += _chunk(b"IDAT", zlib.compress(bytes(scanlines), level=9))
    payload += _chunk(b"IEND", b"")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def _compare(baseline: PngImage, actual: PngImage, max_delta: int) -> tuple[dict[str, float | int], PngImage]:
    if (baseline.width, baseline.height) != (actual.width, actual.height):
        raise ValueError(
            f"dimension mismatch: baseline={baseline.width}x{baseline.height}, "
            f"actual={actual.width}x{actual.height}",
        )
    changed_pixels = 0
    absolute_error = 0
    diff = bytearray(len(actual.pixels))
    pixel_count = actual.width * actual.height
    for pixel in range(pixel_count):
        offset = pixel * 4
        deltas = [abs(actual.pixels[offset + channel] - baseline.pixels[offset + channel]) for channel in range(3)]
        absolute_error += sum(deltas)
        changed = max(deltas) > max_delta
        if changed:
            changed_pixels += 1
            intensity = min(255, max(deltas) * 8)
            diff[offset : offset + 4] = bytes((255, intensity // 5, intensity // 5, 255))
        else:
            gray = sum(actual.pixels[offset : offset + 3]) // 9
            diff[offset : offset + 4] = bytes((gray, gray, gray, 255))
    metrics: dict[str, float | int] = {
        "width": actual.width,
        "height": actual.height,
        "changed_pixels": changed_pixels,
        "changed_ratio": changed_pixels / pixel_count,
        "mean_channel_error": absolute_error / (pixel_count * 3),
    }
    return metrics, PngImage(actual.width, actual.height, bytes(diff))


def _contact_sheet(images: Iterable[PngImage]) -> PngImage:
    items = list(images)
    width = sum(item.width for item in items)
    height = max(item.height for item in items)
    pixels = bytearray(bytes((8, 17, 31, 255)) * width * height)
    x_offset = 0
    for item in items:
        for row in range(item.height):
            source_start = row * item.width * 4
            target_start = (row * width + x_offset) * 4
            pixels[target_start : target_start + item.width * 4] = item.pixels[
                source_start : source_start + item.width * 4
            ]
        x_offset += item.width
    return PngImage(width, height, bytes(pixels))


def _overlap(first: list[float], second: list[float]) -> bool:
    return first[0] < second[2] and first[2] > second[0] and first[1] < second[3] and first[3] > second[1]


def validate_geometry(path: Path, required_elements: list[str]) -> list[str]:
    if not path.is_file():
        return [f"missing geometry report: {path}"]
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"invalid geometry report {path}: {exc}"]
    viewport = root.get("viewport")
    elements = root.get("elements")
    if not isinstance(viewport, list) or len(viewport) != 2 or not all(isinstance(value, (int, float)) for value in viewport):
        return [f"{path}: viewport must be [width, height]"]
    if not isinstance(elements, list):
        return [f"{path}: elements must be a list"]
    errors: list[str] = []
    by_id: dict[str, dict[str, object]] = {}
    for element in elements:
        if not isinstance(element, dict) or not isinstance(element.get("id"), str):
            errors.append(f"{path}: every element needs a stable string id")
            continue
        identifier = str(element["id"])
        if identifier in by_id:
            errors.append(f"{path}: duplicate element id {identifier}")
        by_id[identifier] = element
        if element.get("visible", True) is False:
            continue
        bounds = element.get("bounds")
        if not isinstance(bounds, list) or len(bounds) != 4 or not all(isinstance(value, (int, float)) and math.isfinite(value) for value in bounds):
            errors.append(f"{path}: {identifier} has invalid bounds")
            continue
        left, top, right, bottom = bounds
        if left < 0 or top < 0 or right > viewport[0] or bottom > viewport[1] or right <= left or bottom <= top:
            errors.append(f"{path}: {identifier} is clipped or outside the viewport: {bounds}")
        if element.get("interactive") is True:
            if not str(element.get("label", "")).strip():
                errors.append(f"{path}: interactive element {identifier} has no accessible label")
            if element.get("allow_small") is not True and (right - left < 48 or bottom - top < 48):
                errors.append(f"{path}: interactive element {identifier} is smaller than 48x48: {bounds}")
        if element.get("text") is True:
            contrast = element.get("contrast_ratio")
            minimum_contrast = 3.0 if element.get("large_text") is True else 4.5
            if not isinstance(contrast, (int, float)) or not math.isfinite(contrast):
                errors.append(f"{path}: text element {identifier} has no measured contrast ratio")
            elif contrast < minimum_contrast:
                errors.append(
                    f"{path}: text element {identifier} contrast {contrast:.2f} is below {minimum_contrast:.1f}",
                )
    missing = sorted(set(required_elements) - set(by_id))
    if missing:
        errors.append(f"{path}: missing required elements: {', '.join(missing)}")
    interactive = [
        element for element in by_id.values()
        if element.get("visible", True) is not False and element.get("interactive") is True
        and isinstance(element.get("bounds"), list)
    ]
    for index, first in enumerate(interactive):
        first_allow = set(str(value) for value in first.get("allow_overlap_with", []))
        for second in interactive[index + 1 :]:
            second_allow = set(str(value) for value in second.get("allow_overlap_with", []))
            if str(second["id"]) in first_allow or str(first["id"]) in second_allow:
                continue
            if _overlap(first["bounds"], second["bounds"]):
                errors.append(f"{path}: interactive elements {first['id']} and {second['id']} overlap")
    return errors


def _load_manifest(path: Path) -> dict[str, object]:
    root = json.loads(path.read_text(encoding="utf-8"))
    if root.get("schema_version") != 1 or not isinstance(root.get("scenes"), list):
        raise ValueError("visual manifest must use schema_version 1 and contain scenes")
    return root


def _scenes_for_platform(manifest: dict[str, object], platform: str) -> list[dict[str, object]]:
    scenes = [scene for scene in manifest["scenes"] if platform in scene.get("platforms", [])]
    identifiers = [scene.get("id") for scene in scenes]
    if any(not isinstance(identifier, str) or not identifier for identifier in identifiers):
        raise ValueError("every visual scene needs a non-empty id")
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"duplicate visual scene id for {platform}")
    return scenes


def verify(args: argparse.Namespace) -> int:
    manifest = _load_manifest(args.manifest)
    thresholds = manifest.get("thresholds", {})
    max_delta = int(thresholds.get("max_channel_delta", 8))
    max_ratio = float(thresholds.get("max_changed_ratio", 0.0002))
    max_mean = float(thresholds.get("max_mean_channel_error", 0.25))
    scenes = _scenes_for_platform(manifest, args.platform)
    report_root = args.report_dir / args.platform
    report_root.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []
    failed = False
    for scene in scenes:
        scene_id = str(scene["id"])
        baseline_path = args.baseline_dir / args.platform / f"{scene_id}.png"
        actual_path = args.actual_dir / f"{scene_id}.png"
        geometry_path = args.actual_dir / f"{scene_id}.geometry.json"
        result: dict[str, object] = {"id": scene_id, "baseline": str(baseline_path), "actual": str(actual_path)}
        errors: list[str] = []
        try:
            if not baseline_path.is_file():
                raise ValueError(f"missing Git LFS baseline: {baseline_path}")
            if not actual_path.is_file():
                raise ValueError(f"missing actual screenshot: {actual_path}")
            baseline = read_png(baseline_path)
            actual = read_png(actual_path)
            diff_path = report_root / f"{scene_id}.diff.png"
            contact_path = report_root / f"{scene_id}.contact.png"
            if (baseline.width, baseline.height) != (actual.width, actual.height):
                diff = PngImage(
                    max(baseline.width, actual.width),
                    max(baseline.height, actual.height),
                    bytes((255, 0, 0, 255))
                    * max(baseline.width, actual.width)
                    * max(baseline.height, actual.height),
                )
                metrics = {
                    "baseline_width": baseline.width,
                    "baseline_height": baseline.height,
                    "width": actual.width,
                    "height": actual.height,
                }
                errors.append(
                    f"dimension mismatch: baseline={baseline.width}x{baseline.height}, "
                    f"actual={actual.width}x{actual.height}",
                )
            else:
                metrics, diff = _compare(baseline, actual, max_delta)
                if metrics["changed_ratio"] > max_ratio:
                    errors.append(f"changed ratio {metrics['changed_ratio']:.6f} exceeds {max_ratio:.6f}")
                if metrics["mean_channel_error"] > max_mean:
                    errors.append(f"mean channel error {metrics['mean_channel_error']:.6f} exceeds {max_mean:.6f}")
            result["metrics"] = metrics
            write_png(diff_path, diff)
            write_png(contact_path, _contact_sheet((baseline, actual, diff)))
            result["diff"] = str(diff_path)
            result["contact_sheet"] = str(contact_path)
        except (OSError, ValueError, zlib.error) as exc:
            errors.append(str(exc))
        if scene.get("geometry_required", True):
            errors.extend(validate_geometry(geometry_path, list(scene.get("required_elements", []))))
        result["errors"] = errors
        result["passed"] = not errors
        failed = failed or bool(errors)
        results.append(result)
    summary = {
        "schema_version": 1,
        "platform": args.platform,
        "scene_count": len(results),
        "passed": not failed and bool(results),
        "thresholds": {
            "max_channel_delta": max_delta,
            "max_changed_ratio": max_ratio,
            "max_mean_channel_error": max_mean,
        },
        "scenes": results,
    }
    (report_root / "report.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for result in results:
        state = "PASS" if result["passed"] else "FAIL"
        print(f"{state} {args.platform}/{result['id']}")
        for error in result["errors"]:
            print(f"  {error}")
    if not results:
        print(f"No visual scenes are defined for {args.platform}", file=sys.stderr)
        return 1
    return 1 if failed else 0


def record(args: argparse.Namespace) -> int:
    manifest = _load_manifest(args.manifest)
    scenes = _scenes_for_platform(manifest, args.platform)
    missing = [scene["id"] for scene in scenes if not (args.actual_dir / f"{scene['id']}.png").is_file()]
    if missing:
        print("Cannot record incomplete baseline set: " + ", ".join(str(item) for item in missing), file=sys.stderr)
        return 1
    target = args.baseline_dir / args.platform
    target.mkdir(parents=True, exist_ok=True)
    for scene in scenes:
        scene_id = str(scene["id"])
        source = args.actual_dir / f"{scene_id}.png"
        read_png(source)
        shutil.copyfile(source, target / source.name)
    print(f"Recorded {len(scenes)} {args.platform} baselines in {target}")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("verify", "record"))
    parser.add_argument("--platform", required=True, choices=("android", "linux", "windows", "macos"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--baseline-dir", type=Path, default=ROOT / "visual-tests" / "baselines")
    parser.add_argument("--actual-dir", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, default=ROOT / "build" / "visual-reports")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    return verify(args) if args.action == "verify" else record(args)


if __name__ == "__main__":
    raise SystemExit(main())
