#!/usr/bin/env python3
"""Select app-owned or native visual scene IDs without fabricating either class."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def select_scene_ids(
    manifest_path: Path,
    platform: str,
    kind: str,
    requested_csv: str = "",
) -> list[str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    requested = {value.strip() for value in requested_csv.split(",") if value.strip()}
    platform_scenes = [
        scene for scene in manifest["scenes"]
        if platform in scene.get("platforms", [])
    ]
    known = {str(scene["id"]) for scene in platform_scenes}
    unknown = sorted(requested - known)
    if unknown:
        raise ValueError(f"unknown {platform} visual scenes: {', '.join(unknown)}")
    geometry_required = kind == "app"
    return [
        str(scene["id"])
        for scene in platform_scenes
        if bool(scene.get("geometry_required", True)) is geometry_required
        and (not requested or str(scene["id"]) in requested)
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--platform", required=True, choices=("android", "linux", "windows", "macos"))
    parser.add_argument("--kind", required=True, choices=("app", "native"))
    parser.add_argument("--requested", default="")
    args = parser.parse_args()
    try:
        selected = select_scene_ids(args.manifest, args.platform, args.kind, args.requested)
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(",".join(selected))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
