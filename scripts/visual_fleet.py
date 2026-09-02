#!/usr/bin/env python3
"""Preflight and invoke a platform GUI capture driver on a self-hosted runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import locale
import os
import platform as host_platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "visual-tests" / "scenes.json"


def scenes_for(manifest: Path, platform: str) -> list[dict[str, object]]:
    root = json.loads(manifest.read_text(encoding="utf-8"))
    if root.get("schema_version") != 1:
        raise ValueError("visual scene manifest schema must be 1")
    scenes = [scene for scene in root.get("scenes", []) if platform in scene.get("platforms", [])]
    if not scenes:
        raise ValueError(f"no scenes are defined for {platform}")
    return scenes


def machine_fingerprint(platform: str) -> dict[str, object]:
    configured_driver = os.environ.get("VPN_CONTROL_VISUAL_CAPTURE_COMMAND", "").strip()
    driver_executable = shlex.split(configured_driver)[0] if configured_driver else ""
    values: dict[str, object] = {
        "schema_version": 1,
        "visual_platform": platform,
        "host_system": host_platform.system(),
        "host_release": host_platform.release(),
        "host_machine": host_platform.machine(),
        "python": host_platform.python_version(),
        "locale": locale.getlocale(),
        "display": os.environ.get("DISPLAY", ""),
        "wayland_display": os.environ.get("WAYLAND_DISPLAY", ""),
        "session_type": os.environ.get("XDG_SESSION_TYPE", ""),
        "runner_name": os.environ.get("RUNNER_NAME", ""),
        "driver_executable": driver_executable,
    }
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":")).encode("utf-8")
    values["fingerprint_sha256"] = hashlib.sha256(canonical).hexdigest()
    return values


def _check_host(platform: str) -> list[str]:
    system = host_platform.system().lower()
    errors: list[str] = []
    expected_system = {"linux": "linux", "windows": "windows", "macos": "darwin"}
    windows_vm_host = platform == "windows" and system == "linux" and os.environ.get(
        "VPN_CONTROL_VISUAL_WINDOWS_VM", "",
    ) == "1"
    if platform in expected_system and system != expected_system[platform] and not windows_vm_host:
        errors.append(f"{platform} capture requires {expected_system[platform]}, found {system}")
    if platform == "android" and shutil.which("adb") is None:
        errors.append("Android capture requires adb")
    if platform in {"linux", "windows", "macos"}:
        if system == "linux" and platform != "windows" and not (
            os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        ):
            errors.append("Linux visual capture requires a GUI DISPLAY or WAYLAND_DISPLAY")
    git = shutil.which("git")
    if git is None:
        errors.append("git is required")
    else:
        lfs = subprocess.run([git, "lfs", "version"], cwd=ROOT, text=True, capture_output=True, check=False)
        if lfs.returncode != 0:
            errors.append("Git LFS is required to hydrate canonical PNG baselines")
    if not os.environ.get("VPN_CONTROL_VISUAL_CAPTURE_COMMAND", "").strip():
        errors.append("VPN_CONTROL_VISUAL_CAPTURE_COMMAND must name the enrolled platform automation driver")
    if os.environ.get("VPN_CONTROL_VISUAL_FLEET", "") != "1":
        errors.append("VPN_CONTROL_VISUAL_FLEET=1 is required on dedicated visual runners")
    return errors


def preflight(args: argparse.Namespace) -> int:
    try:
        scenes = scenes_for(args.manifest, args.platform)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    errors = _check_host(args.platform)
    baseline_dir = args.baseline_dir / args.platform
    missing_baselines = [scene["id"] for scene in scenes if not (baseline_dir / f"{scene['id']}.png").is_file()]
    if missing_baselines and not args.allow_missing_baselines:
        errors.append("missing Git LFS baselines: " + ", ".join(str(item) for item in missing_baselines))
    fingerprint = machine_fingerprint(args.platform)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "machine.json").write_text(json.dumps(fingerprint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors:
        print("Visual runner preflight failed:", file=sys.stderr)
        for error in errors:
            print(f" - {error}", file=sys.stderr)
        return 1
    print(f"[vpn-control] {args.platform} visual runner preflight passed for {len(scenes)} scenes")
    return 0


def capture(args: argparse.Namespace) -> int:
    if preflight(args) != 0:
        return 1
    scenes = scenes_for(args.manifest, args.platform)
    command = shlex.split(os.environ["VPN_CONTROL_VISUAL_CAPTURE_COMMAND"])
    command.extend(
        [
            "--platform", args.platform,
            "--manifest", str(args.manifest.resolve()),
            "--output", str(args.output.resolve()),
        ],
    )
    try:
        completed = subprocess.run(command, cwd=ROOT, check=False)
    except OSError as exc:
        print(f"Could not start visual capture driver: {exc}", file=sys.stderr)
        return 1
    if completed.returncode != 0:
        print(f"Visual capture driver failed with exit code {completed.returncode}", file=sys.stderr)
        return completed.returncode
    missing: list[str] = []
    for scene in scenes:
        scene_id = str(scene["id"])
        if not (args.output / f"{scene_id}.png").is_file():
            missing.append(f"{scene_id}.png")
        if scene.get("geometry_required", True) and not (args.output / f"{scene_id}.geometry.json").is_file():
            missing.append(f"{scene_id}.geometry.json")
    if missing:
        print("Visual capture driver returned an incomplete scene set:", file=sys.stderr)
        for path in missing:
            print(f" - {path}", file=sys.stderr)
        return 1
    print(f"[vpn-control] captured {len(scenes)} {args.platform} visual scenes")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "capture"))
    parser.add_argument("--platform", required=True, choices=("android", "linux", "windows", "macos"))
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--baseline-dir", type=Path, default=ROOT / "visual-tests" / "baselines")
    parser.add_argument("--output", type=Path, default=ROOT / "build" / "visual-actual")
    parser.add_argument("--allow-missing-baselines", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    return preflight(args) if args.action == "preflight" else capture(args)


if __name__ == "__main__":
    raise SystemExit(main())
