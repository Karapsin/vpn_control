#!/usr/bin/env python3
"""Capture macOS secure surfaces headlessly from the managed Tart VM."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import struct
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VM_NAME = os.environ.get("VPN_CONTROL_VISUAL_MACOS_VM", "vpn-control-visual-macos")
VM_USER = os.environ.get("VPN_CONTROL_VISUAL_MACOS_USER", "admin")
VM_PASSWORD = os.environ.get("VPN_CONTROL_VISUAL_MACOS_PASSWORD", "admin")
CANONICAL_SIZE = (1280, 800)
SECURE_SCENES = ("macos-gatekeeper", "macos-install-confirmation")


class CaptureError(RuntimeError):
    pass


def run_checked(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if completed.returncode != 0:
        raise CaptureError(completed.stderr.strip() or completed.stdout.strip() or "command failed")
    return completed


def vnc_client() -> str:
    configured = os.environ.get("VPN_CONTROL_VNCDO", "").strip()
    candidates = [configured, shutil.which("vncdo") or "", str(ROOT / ".agent_venv/bin/vncdo")]
    client = next((candidate for candidate in candidates if candidate and Path(candidate).is_file()), "")
    if not client:
        raise CaptureError(
            "headless macOS secure-surface capture requires vncdotool from "
            "agent_tools/requirements-mcp.txt"
        )
    return client


def png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()[:24]
    if len(data) != 24 or data[:8] != b"\x89PNG\r\n\x1a\n" or data[12:16] != b"IHDR":
        raise CaptureError("VNC capture did not produce a PNG framebuffer")
    return struct.unpack(">II", data[16:24])


def vnc_command(ip_address: str, *commands: str) -> list[str]:
    return [
        vnc_client(), "-s", f"{ip_address}::5900", "-u", VM_USER, "-p", VM_PASSWORD,
        "--nocursor", *commands,
    ]


def capture_frame(ip_address: str, output: Path) -> None:
    # Connecting to macOS screen sharing displays a short platform banner. Keep the same
    # headless VNC session alive until that OS-owned transient has disappeared.
    run_checked(vnc_command(ip_address, "pause", "20", "capture", str(output)), timeout=45)
    size = png_size(output)
    if size != CANONICAL_SIZE:
        raise CaptureError(f"macOS framebuffer is {size[0]}x{size[1]}; expected 1280x800")


def guest_uid() -> str:
    value = run_checked(["tart", "exec", VM_NAME, "id", "-u", VM_USER], timeout=30).stdout.strip()
    if not value.isdigit():
        raise CaptureError(f"could not resolve the {VM_USER} console-user ID")
    return value


def guest_shell(script: str, *, timeout: int = 15 * 60) -> None:
    run_checked(["tart", "exec", VM_NAME, "/bin/zsh", "-lc", script], timeout=timeout)


def build_package() -> None:
    guest_shell(
        'cd "/Volumes/My Shared Files/vpn-control" && '
        "export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home && "
        "./scripts/package_macos_desktop.sh --skip-tests --skip-package-regression-tests",
        timeout=30 * 60,
    )


def prepare_gatekeeper_scene() -> None:
    guest_shell(
        "set -e; "
        "rm -rf /tmp/vpncontrol-gatekeeper /tmp/vpncontrol-gatekeeper-mount; "
        "mkdir -p /tmp/vpncontrol-gatekeeper /tmp/vpncontrol-gatekeeper-mount; "
        'dmg=$(find "/Volumes/My Shared Files/vpn-control/dist/macos" -maxdepth 1 '
        "-type f -name '*.dmg' | sort | tail -n 1); "
        'hdiutil attach -nobrowse -quiet -mountpoint /tmp/vpncontrol-gatekeeper-mount "$dmg"; '
        'app=$(find /tmp/vpncontrol-gatekeeper-mount -maxdepth 1 -type d -name "*.app" -print -quit); '
        'ditto "$app" /tmp/vpncontrol-gatekeeper/vpn-control.app; '
        "hdiutil detach /tmp/vpncontrol-gatekeeper-mount -quiet; "
        "xattr -r -w com.apple.quarantine '0081;68b84740;VPN Control;' "
        "/tmp/vpncontrol-gatekeeper/vpn-control.app",
    )


def open_gatekeeper_scene(uid: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "tart", "exec", VM_NAME, "sudo", "launchctl", "asuser", uid,
            "sudo", "-u", VM_USER, "open", "/tmp/vpncontrol-gatekeeper/vpn-control.app",
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def open_install_confirmation(uid: str) -> subprocess.Popen[str]:
    return subprocess.Popen(
        [
            "tart", "exec", VM_NAME, "sudo", "launchctl", "asuser", uid,
            "sudo", "-u", VM_USER, "osascript", "-e",
            'do shell script "/usr/bin/true" with administrator privileges '
            'with prompt "Install VPN Control 2.0.0"',
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def dismiss(ip_address: str) -> None:
    run_checked(vnc_command(ip_address, "key", "esc"), timeout=30)


def freeze_guest_clock() -> None:
    guest_shell(
        "sudo systemsetup -setusingnetworktime off >/dev/null && sudo date 0903120026.00 >/dev/null",
        timeout=30,
    )


def restore_guest_clock() -> None:
    guest_shell("sudo systemsetup -setusingnetworktime on >/dev/null 2>&1 || true", timeout=30)


def capture_requested(scene_ids: list[str], output: Path) -> None:
    unknown = sorted(set(scene_ids) - set(SECURE_SCENES))
    if unknown:
        raise CaptureError("the Tart secure-surface driver cannot capture: " + ", ".join(unknown))
    ip_address = run_checked(["tart", "ip", VM_NAME], timeout=30).stdout.strip()
    if not ip_address:
        raise CaptureError("the managed macOS VM has no reachable IP address")
    uid = guest_uid()
    output.mkdir(parents=True, exist_ok=True)
    guest_shell(f"pkill -u {VM_USER} -x osascript >/dev/null 2>&1 || true", timeout=30)
    dismiss(ip_address)
    time.sleep(2)
    if "macos-gatekeeper" in scene_ids:
        build_package()
        prepare_gatekeeper_scene()
    try:
        for scene_id in scene_ids:
            process: subprocess.Popen[str] | None = None
            try:
                freeze_guest_clock()
                if scene_id == "macos-gatekeeper":
                    process = open_gatekeeper_scene(uid)
                else:
                    process = open_install_confirmation(uid)
                time.sleep(4)
                capture_frame(ip_address, output / f"{scene_id}.png")
            finally:
                dismiss(ip_address)
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
    finally:
        restore_guest_clock()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--platform", choices=("macos",), required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--scenes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    requested = json.loads(args.scenes.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    known = {scene.get("id") for scene in manifest.get("scenes", [])}
    if not isinstance(requested, list) or any(scene not in known for scene in requested):
        raise CaptureError("requested macOS secure scenes are not in the visual manifest")
    capture_requested([str(scene) for scene in requested], args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
