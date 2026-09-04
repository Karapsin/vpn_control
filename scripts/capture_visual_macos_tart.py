#!/usr/bin/env python3
"""Capture macOS secure surfaces headlessly from the managed Tart VM."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import struct
import subprocess
import time
import zlib
from pathlib import Path

from visual_regression import read_png


ROOT = Path(__file__).resolve().parents[1]
VM_NAME = os.environ.get("VPN_CONTROL_VISUAL_MACOS_VM", "vpn-control-visual-macos")
VM_USER = os.environ.get("VPN_CONTROL_VISUAL_MACOS_USER", "admin")
VM_PASSWORD = os.environ.get("VPN_CONTROL_VISUAL_MACOS_PASSWORD", "admin")
VM_JAVA_HOME = os.environ.get("VPN_CONTROL_VISUAL_MACOS_JAVA_HOME", "/opt/homebrew/opt/openjdk@17")
CANONICAL_SIZE = (1280, 800)
SECURE_SCENES = ("macos-gatekeeper", "macos-install-confirmation")
FILE_DIALOG_SCENES = ("macos-open-dialog", "macos-save-dialog")


class CaptureError(RuntimeError):
    pass


def run_checked(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise CaptureError(f"{Path(command[0]).name} timed out after {timeout} seconds") from error
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


def _paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    upper_left_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= upper_left_distance:
        return left
    return above if above_distance <= upper_left_distance else upper_left


def visible_pixel_ratio(path: Path) -> float:
    """Return the share of non-black pixels in an 8-bit RGB/RGBA VNC PNG."""
    data = path.read_bytes()
    if len(data) < 33 or data[:8] != b"\x89PNG\r\n\x1a\n":
        raise CaptureError("VNC capture did not produce a PNG framebuffer")
    width, height = struct.unpack(">II", data[16:24])
    bit_depth, color_type, interlace = data[24], data[25], data[28]
    channels = {2: 3, 6: 4}.get(color_type)
    if bit_depth != 8 or channels is None or interlace != 0:
        raise CaptureError("VNC capture must be a non-interlaced 8-bit RGB/RGBA PNG")
    compressed = bytearray()
    position = 8
    while position + 12 <= len(data):
        length = struct.unpack(">I", data[position : position + 4])[0]
        kind = data[position + 4 : position + 8]
        payload_start = position + 8
        payload_end = payload_start + length
        if payload_end + 4 > len(data):
            raise CaptureError("VNC capture PNG is truncated")
        if kind == b"IDAT":
            compressed.extend(data[payload_start:payload_end])
        position = payload_end + 4
        if kind == b"IEND":
            break
    raw = zlib.decompress(bytes(compressed))
    stride = width * channels
    expected = height * (stride + 1)
    if len(raw) != expected:
        raise CaptureError("VNC capture PNG has an unexpected pixel payload")
    previous = bytearray(stride)
    visible = 0
    offset = 0
    for _row in range(height):
        filter_type = raw[offset]
        offset += 1
        encoded = raw[offset : offset + stride]
        offset += stride
        decoded = bytearray(stride)
        for index, value in enumerate(encoded):
            left = decoded[index - channels] if index >= channels else 0
            above = previous[index]
            upper_left = previous[index - channels] if index >= channels else 0
            predictor = {
                0: 0,
                1: left,
                2: above,
                3: (left + above) // 2,
                4: _paeth(left, above, upper_left),
            }.get(filter_type)
            if predictor is None:
                raise CaptureError(f"VNC capture PNG uses unsupported filter {filter_type}")
            decoded[index] = (value + predictor) & 0xFF
        for pixel in range(0, stride, channels):
            if max(decoded[pixel : pixel + 3]) > 8:
                visible += 1
        previous = decoded
    return visible / (width * height)


def background_changed_ratio(path: Path) -> float:
    """Compare the unobscured guest background with the canonical macOS scene."""
    baseline = read_png(ROOT / "visual-tests/baselines/macos/macos-install-confirmation.png")
    actual = read_png(path)
    if (baseline.width, baseline.height) != CANONICAL_SIZE or (
        actual.width,
        actual.height,
    ) != CANONICAL_SIZE:
        raise CaptureError("macOS background validation requires the canonical 1280x800 viewport")
    changed = 0
    compared = 0
    # Stay clear of the secure dialog, Dock animation, menu clock, and VNC's one-pixel edge
    # artifacts. These three stable wallpaper regions still intersect every observed Finder or
    # notification contaminant, including the persistent top-right permission education banner.
    regions = ((50, 100, 350, 650), (930, 130, 1230, 650), (930, 45, 1230, 115))
    for left, top, right, bottom in regions:
        for y in range(top, bottom):
            for x in range(left, right):
                offset = (y * CANONICAL_SIZE[0] + x) * 4
                if max(
                    abs(actual.pixels[offset + channel] - baseline.pixels[offset + channel])
                    for channel in range(3)
                ) > 12:
                    changed += 1
                compared += 1
    return changed / compared


def foreground_changed_ratio(actual_path: Path, background_path: Path, scene_id: str) -> float:
    """Return how much of the expected secure-dialog area differs from clean wallpaper."""
    regions = {
        "macos-gatekeeper": (500, 135, 780, 385),
        "macos-install-confirmation": (500, 115, 780, 445),
    }
    if scene_id not in regions:
        raise CaptureError(f"no secure-dialog validation region for {scene_id}")
    actual = read_png(actual_path)
    background = read_png(background_path)
    if (actual.width, actual.height) != CANONICAL_SIZE or (
        background.width,
        background.height,
    ) != CANONICAL_SIZE:
        raise CaptureError("macOS secure-dialog validation requires the canonical 1280x800 viewport")
    left, top, right, bottom = regions[scene_id]
    changed = 0
    compared = (right - left) * (bottom - top)
    for y in range(top, bottom):
        for x in range(left, right):
            offset = (y * CANONICAL_SIZE[0] + x) * 4
            if max(
                abs(actual.pixels[offset + channel] - background.pixels[offset + channel])
                for channel in range(3)
            ) > 12:
                changed += 1
    return changed / compared


def right_edge_overlay_ratio(path: Path) -> float:
    """Detect a partially open Notification Center outside the stable comparison regions."""
    image = read_png(path)
    if (image.width, image.height) != CANONICAL_SIZE:
        raise CaptureError("macOS edge validation requires the canonical 1280x800 viewport")
    bright = 0
    compared = 0
    # Start below the menu bar so the small upper-right Screen Sharing/sidebar tab is included.
    for y in range(35, 700):
        for x in range(1260, 1280):
            offset = (y * CANONICAL_SIZE[0] + x) * 4
            if min(image.pixels[offset : offset + 3]) > 100:
                bright += 1
            compared += 1
    return bright / compared


def vnc_command(ip_address: str, *commands: str) -> list[str]:
    return [
        vnc_client(), "-s", f"{ip_address}::5900", "-u", VM_USER, "-p", VM_PASSWORD,
        "--nocursor", *commands,
    ]


def capture_frame(ip_address: str, output: Path) -> None:
    # Connecting to macOS screen sharing displays a short platform banner. Keep the same
    # headless VNC session alive until that OS-owned transient has disappeared.
    failures: list[str] = []
    for attempt in range(3):
        # Screen Sharing's own control banner has occasionally remained past 20 seconds on a busy
        # VM. Forty seconds was the first duration that stayed clean under repeated release load.
        pause = "40"
        try:
            run_checked(
                vnc_command(ip_address, "pause", pause, "capture", str(output)),
                timeout=120,
            )
            size = png_size(output)
            if size != CANONICAL_SIZE:
                raise CaptureError(f"macOS framebuffer is {size[0]}x{size[1]}; expected 1280x800")
            if visible_pixel_ratio(output) >= 0.01:
                return
            failures.append("blank framebuffer")
        except CaptureError as error:
            failures.append(str(error))
    raise CaptureError("macOS VNC capture failed three times: " + "; ".join(failures))


def capture_ready_frame(ip_address: str, output: Path) -> None:
    """Capture a dialog already announced by the isolated guest test."""
    capture_frame(ip_address, output)


def guest_uid() -> str:
    value = run_checked(["tart", "exec", VM_NAME, "id", "-u", VM_USER], timeout=30).stdout.strip()
    if not value.isdigit():
        raise CaptureError(f"could not resolve the {VM_USER} console-user ID")
    return value


def guest_shell(script: str, *, timeout: int = 15 * 60) -> subprocess.CompletedProcess[str]:
    return run_checked(["tart", "exec", VM_NAME, "/bin/zsh", "-lc", script], timeout=timeout)


def reboot_guest() -> None:
    """Reboot the isolated guest and prove that a new boot completed."""
    before = guest_shell("/usr/sbin/sysctl -n kern.boottime", timeout=30).stdout.strip()
    try:
        run_checked(["tart", "exec", VM_NAME, "sudo", "/sbin/shutdown", "-r", "now"], timeout=30)
    except CaptureError:
        # tart exec can lose its transport while the requested reboot is already in progress.
        pass
    time.sleep(5)
    deadline = time.monotonic() + 180
    failures: list[str] = []
    while time.monotonic() < deadline:
        try:
            after = guest_shell("/usr/sbin/sysctl -n kern.boottime", timeout=30).stdout.strip()
            if after and after != before:
                return
            failures.append("guest boot timestamp did not change")
        except CaptureError as error:
            failures.append(str(error))
        time.sleep(2)
    raise CaptureError("macOS guest did not complete its verified reboot: " + "; ".join(failures[-3:]))


def ensure_guest_capture_permissions(uid: str) -> None:
    """Repair and verify the two Tart permissions required by headless capture."""
    result = guest_shell(
        "set -e; "
        'system_db="/Library/Application Support/com.apple.TCC/TCC.db"; '
        'user_db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"; '
        'screen=$(sudo sqlite3 "$system_db" '
        '"select auth_value from access where service=\'kTCCServiceScreenCapture\' '
        'and client like \'%/tart-guest-agent\' limit 1;"); '
        'automation=$(sqlite3 "$user_db" '
        '"select auth_value from access where service=\'kTCCServiceAppleEvents\' '
        'and client like \'%/tart-guest-agent\' and indirect_object_identifier=\'com.apple.finder\' '
        'limit 1;"); '
        '[[ -n "$screen" && -n "$automation" ]] || { '
        'echo "managed Tart VM has not initialized Screen Recording and Finder Automation consent" >&2; '
        "exit 1; }; "
        'changed=0; '
        'if [[ "$screen" != 2 ]]; then sudo sqlite3 "$system_db" '
        '"update access set auth_value=2,auth_reason=3,last_modified=strftime(\'%s\',\'now\'),'
        'last_reminded=strftime(\'%s\',\'now\') where service=\'kTCCServiceScreenCapture\' '
        'and client like \'%/tart-guest-agent\';"; changed=1; fi; '
        'if [[ "$automation" != 2 ]]; then sqlite3 "$user_db" '
        '"update access set auth_value=2,auth_reason=3,last_modified=strftime(\'%s\',\'now\'),'
        'last_reminded=strftime(\'%s\',\'now\') where service=\'kTCCServiceAppleEvents\' '
        'and client like \'%/tart-guest-agent\' and indirect_object_identifier=\'com.apple.finder\';"; '
        'changed=1; fi; '
        'printf "%s" "$changed"',
        timeout=30,
    )
    if result.stdout.strip() == "1":
        # Restart only Tart's isolated guest helper so TCC reloads the repaired rows. The daemon
        # transporting tart exec remains alive and launchd immediately recreates the user agent.
        run_checked(
            [
                "tart", "exec", VM_NAME, "sudo", "launchctl", "kickstart", "-k",
                f"gui/{uid}/org.cirruslabs.tart-guest-agent",
            ],
            timeout=30,
        )
        time.sleep(5)
    verified = guest_shell(
        "set -e; "
        'system_db="/Library/Application Support/com.apple.TCC/TCC.db"; '
        'user_db="$HOME/Library/Application Support/com.apple.TCC/TCC.db"; '
        'test "$(sudo sqlite3 "$system_db" '
        '"select auth_value from access where service=\'kTCCServiceScreenCapture\' '
        'and client like \'%/tart-guest-agent\' limit 1;")" = 2; '
        'test "$(sqlite3 "$user_db" '
        '"select auth_value from access where service=\'kTCCServiceAppleEvents\' '
        'and client like \'%/tart-guest-agent\' and indirect_object_identifier=\'com.apple.finder\' '
        'limit 1;")" = 2; '
        'printf ready',
        timeout=30,
    )
    if verified.stdout.strip() != "ready":
        raise CaptureError("managed Tart VM capture permissions could not be verified")


def prepare_guest_checkout() -> str:
    target_sha = os.environ.get("VPN_CONTROL_VISUAL_TARGET_SHA", "").strip()
    if not target_sha:
        target_sha = run_checked(["git", "rev-parse", "HEAD"], timeout=30).stdout.strip()
    if len(target_sha) != 40 or any(character not in "0123456789abcdef" for character in target_sha):
        raise CaptureError("macOS visual capture requires a full lowercase target SHA")
    checkout = f"/Users/{VM_USER}/.vpn-control-visual/checkouts/{target_sha}"
    source = "/Volumes/My Shared Files/vpn-control"
    quoted_checkout = shlex.quote(checkout)
    quoted_source = shlex.quote(source)
    quoted_sha = shlex.quote(target_sha)
    guest_shell(
        "set -e; "
        f"mkdir -p {shlex.quote(str(Path(checkout).parent))}; "
        f"if [[ ! -d {quoted_checkout}/.git ]]; then "
        f"git clone --no-local --no-checkout {quoted_source} {quoted_checkout}; fi; "
        f"git -C {quoted_checkout} checkout --detach --force {quoted_sha}; "
        f"test \"$(git -C {quoted_checkout} rev-parse HEAD)\" = {quoted_sha}",
        timeout=10 * 60,
    )
    return checkout


def build_package(checkout: str) -> str:
    configured = os.environ.get("VPN_CONTROL_VISUAL_MACOS_DMG", "").strip()
    if configured:
        guest_shell(f"test -r {shlex.quote(configured)}", timeout=30)
        return configured
    result = guest_shell(
        f"cd {shlex.quote(checkout)} && "
        f"export JAVA_HOME={shlex.quote(VM_JAVA_HOME)} && "
        "export GRADLE_OPTS='-Dorg.gradle.project.compose.desktop.packaging.checkJdkVendor=false' && "
        "./scripts/package_macos_desktop.sh --skip-tests --skip-package-regression-tests >/tmp/vpn-control-macos-package.log && "
        "find dist/macos -maxdepth 1 -type f -name '*.dmg' | sort | tail -n 1",
        timeout=30 * 60,
    )
    package = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
    if not package:
        raise CaptureError("macOS visual package build returned no DMG")
    return f"{checkout}/{package}" if not package.startswith("/") else package


def prepare_gatekeeper_scene(package: str) -> None:
    quoted_package = shlex.quote(package)
    guest_shell(
        "set -e; "
        "rm -rf /tmp/vpncontrol-gatekeeper /tmp/vpncontrol-gatekeeper-mount; "
        "mkdir -p /tmp/vpncontrol-gatekeeper /tmp/vpncontrol-gatekeeper-mount; "
        f"hdiutil attach -nobrowse -quiet -mountpoint /tmp/vpncontrol-gatekeeper-mount {quoted_package}; "
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


def dismiss_notification_banner(ip_address: str) -> None:
    # Wait until macOS's own Screen Sharing banner no longer covers the queued Java banner, then
    # provide enough intermediate pointer events for Notification Center to treat the motion as a
    # swipe rather than a single jump. Restarting Notification Center would replay the queued banner.
    run_checked(
        vnc_command(
            ip_address,
            "pause", "20", "move", "1080", "70", "mousedown", "1",
            "move", "1130", "70", "move", "1180", "70", "move", "1230", "70",
            "move", "1275", "70", "mouseup", "1",
        ),
        timeout=60,
    )


def resolve_pending_permission_dialog(ip_address: str) -> None:
    """Dismiss permission requests that were queued before TCC repair completed."""
    # A stale Screen Recording request keeps returning until its Deny button is acknowledged even
    # after the managed VM's TCC row has been repaired. A stale Finder Automation sheet instead
    # needs its already-verified Allow action. This recovery runs only after the clean-background
    # detector finds contamination; the fixed-coordinate clicks land on wallpaper if the sheet has
    # already disappeared.
    run_checked(vnc_command(ip_address, "move", "824", "304", "click", "1"), timeout=30)
    time.sleep(2)
    run_checked(vnc_command(ip_address, "move", "699", "341", "click", "1"), timeout=30)
    time.sleep(2)
    # Remove any notification education banner that accompanied the permission request.
    dismiss_notification_banner(ip_address)


def reset_guest_ui(ip_address: str) -> None:
    del ip_address  # Cleanup stays guest-local so it cannot alter macOS keyboard/pointer modality.
    guest_shell(
        f"pkill -u {shlex.quote(VM_USER)} -x osascript >/dev/null 2>&1 || true; "
        f"pkill -u {shlex.quote(VM_USER)} -f '/vpn-control.app/Contents/MacOS/vpn-control$' "
        ">/dev/null 2>&1 || true; "
        "sudo pkill -9 -f '^/System/Library/CoreServices/CoreServicesUIAgent.app/Contents/MacOS/CoreServicesUIAgent$' "
        ">/dev/null 2>&1 || true; "
        "sudo killall Finder >/dev/null 2>&1 || true",
        timeout=30,
    )
    guest_shell(
        "osascript -e 'tell application \"Finder\" to close every window' >/dev/null 2>&1 || true",
        timeout=30,
    )
    time.sleep(2)


def await_clean_guest_ui(ip_address: str, output: Path) -> Path:
    probe = output / ".macos-clean-preflight.png"
    for _attempt in range(3):
        reset_guest_ui(ip_address)
        capture_frame(ip_address, probe)
        background_change = background_changed_ratio(probe)
        edge_overlay = right_edge_overlay_ratio(probe)
        if background_change <= 0.0002 and edge_overlay <= 0.01:
            return probe
        if edge_overlay > 0.01:
            run_checked(vnc_command(ip_address, "move", "50", "600", "click", "1"), timeout=30)
            time.sleep(2)
        else:
            resolve_pending_permission_dialog(ip_address)
    raise CaptureError(
        "macOS guest still contains a window, notification, or permission surface after three cleanups"
    )


def capture_secure_frame(ip_address: str, screenshot: Path, scene_id: str) -> None:
    for _attempt in range(3):
        capture_frame(ip_address, screenshot)
        background_change = background_changed_ratio(screenshot)
        edge_overlay = right_edge_overlay_ratio(screenshot)
        if background_change <= 0.0002 and edge_overlay <= 0.01:
            return
        if edge_overlay > 0.01:
            # Clicking stable wallpaper closes a partially open Notification Center and leaves the
            # Gatekeeper window in the same inactive-button state as the canonical fixture.
            run_checked(vnc_command(ip_address, "move", "50", "600", "click", "1"), timeout=30)
            time.sleep(2)
        else:
            dismiss_notification_banner(ip_address)
    raise CaptureError(f"macOS capture contains a transient overlay for {scene_id}")


def freeze_guest_clock() -> None:
    guest_shell(
        "sudo systemsetup -setusingnetworktime off >/dev/null && sudo date 0903120026.00 >/dev/null",
        timeout=30,
    )


def restore_guest_clock() -> None:
    guest_shell("sudo systemsetup -setusingnetworktime on >/dev/null 2>&1 || true", timeout=30)


def capture_file_dialogs(ip_address: str, checkout: str, scene_ids: list[str], output: Path) -> None:
    guest_output = Path("/Volumes/My Shared Files/vpn-control") / output.relative_to(ROOT)
    exit_marker = output / ".macos-dialog-exit"
    exit_marker.unlink(missing_ok=True)
    guest_exit_marker = Path("/Volumes/My Shared Files/vpn-control") / exit_marker.relative_to(ROOT)
    inner = (
        "cd " + shlex.quote(checkout) + " && "
        "mkdir -p " + repr(str(guest_output)) + " && "
        "env JAVA_HOME=" + repr(VM_JAVA_HOME) + " VPN_CONTROL_VISUAL_ISOLATED=1 VPN_CONTROL_VISUAL_EXTERNAL_FRAMEBUFFER=1 "
        "GRADLE_OPTS='-Dorg.gradle.projectcachedir=/tmp/vpn-control-macos-visual-project-cache' "
        "./scripts/capture_visual_desktop.sh macos " + repr(str(guest_output)) + " " + repr(",".join(scene_ids))
    )
    wrapped = (
        "set +e; " + inner + "; capture_status=$?; printf '%s' \"$capture_status\" > "
        + shlex.quote(str(guest_exit_marker)) + "; exit \"$capture_status\""
    )
    guest_shell(
        "nohup /bin/zsh -lc " + shlex.quote(wrapped)
        + " >/tmp/vpn-control-macos-dialog-vnc.log 2>&1 &",
        timeout=30,
    )
    for scene_id in scene_ids:
        deadline = time.monotonic() + 180
        ready = output / f"{scene_id}.png.ready"
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.5)
        if not ready.exists():
            raise CaptureError(f"timed out waiting for isolated macOS dialog: {scene_id}")
        try:
            dismiss_notification_banner(ip_address)
            capture_ready_frame(ip_address, output / f"{scene_id}.png")
            (output / f"{scene_id}.png.captured").write_text("captured", encoding="utf-8")
        finally:
            ready.unlink(missing_ok=True)
    completion_deadline = time.monotonic() + 180
    while not exit_marker.exists() and time.monotonic() < completion_deadline:
        time.sleep(0.5)
    if not exit_marker.exists():
        raise CaptureError("timed out waiting for isolated macOS dialog capture to exit")
    status = exit_marker.read_text(encoding="utf-8").strip()
    exit_marker.unlink(missing_ok=True)
    if status != "0":
        log_tail = guest_shell("tail -n 40 /tmp/vpn-control-macos-dialog-vnc.log", timeout=30).stdout.strip()
        raise CaptureError(f"isolated macOS dialog capture failed with exit {status}: {log_tail}")


def capture_requested(scene_ids: list[str], output: Path) -> None:
    unknown = sorted(set(scene_ids) - set(SECURE_SCENES) - set(FILE_DIALOG_SCENES))
    if unknown:
        raise CaptureError("the Tart secure-surface driver cannot capture: " + ", ".join(unknown))
    ip_address = run_checked(["tart", "ip", VM_NAME], timeout=30).stdout.strip()
    if not ip_address:
        raise CaptureError("the managed macOS VM has no reachable IP address")
    uid = guest_uid()
    ensure_guest_capture_permissions(uid)
    checkout = prepare_guest_checkout()
    output.mkdir(parents=True, exist_ok=True)
    reset_guest_ui(ip_address)
    file_dialog_scenes = [scene for scene in scene_ids if scene in FILE_DIALOG_SCENES]
    if file_dialog_scenes:
        capture_file_dialogs(ip_address, checkout, file_dialog_scenes, output)
    package = build_package(checkout) if "macos-gatekeeper" in scene_ids else ""
    secure_scenes = [scene for scene in SECURE_SCENES if scene in scene_ids]
    if secure_scenes:
        # Authorization Services caches both successful and cancelled administrator prompts.
        # A verified reboot gives every repeated secure capture the same clean authorization state.
        reboot_guest()
        ip_address = run_checked(["tart", "ip", VM_NAME], timeout=30).stdout.strip()
        uid = guest_uid()
        ensure_guest_capture_permissions(uid)
        # Reload the Dock only once. This drops orphaned minimized windows while preserving the
        # single Gatekeeper launch icon expected by the following install-confirmation scene.
        reset_guest_ui(ip_address)
        guest_shell("killall Dock >/dev/null 2>&1 || true", timeout=30)
        time.sleep(3)
    try:
        for scene_id in secure_scenes:
            scene_error: CaptureError | None = None
            for launch_attempt in range(3):
                process: subprocess.Popen[str] | None = None
                background: Path | None = None
                try:
                    background = await_clean_guest_ui(ip_address, output)
                    if scene_id == "macos-gatekeeper":
                        prepare_gatekeeper_scene(package)
                    freeze_guest_clock()
                    if scene_id == "macos-gatekeeper":
                        process = open_gatekeeper_scene(uid)
                    else:
                        process = open_install_confirmation(uid)
                    time.sleep(4)
                    screenshot = output / f"{scene_id}.png"
                    capture_secure_frame(ip_address, screenshot, scene_id)
                    if foreground_changed_ratio(screenshot, background, scene_id) < 0.2:
                        raise CaptureError(f"macOS secure surface did not appear for {scene_id}")
                    scene_error = None
                except CaptureError as error:
                    scene_error = error
                finally:
                    if background is not None:
                        background.unlink(missing_ok=True)
                    dismiss(ip_address)
                    if process is not None and process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                if scene_error is None:
                    break
                if launch_attempt == 2:
                    raise CaptureError(
                        f"macOS secure scene failed after three launch attempts: {scene_id}: {scene_error}"
                    ) from scene_error
                restore_guest_clock()
                reboot_guest()
                ip_address = run_checked(["tart", "ip", VM_NAME], timeout=30).stdout.strip()
                uid = guest_uid()
                ensure_guest_capture_permissions(uid)
                reset_guest_ui(ip_address)
                guest_shell("killall Dock >/dev/null 2>&1 || true", timeout=30)
                time.sleep(3)
    finally:
        restore_guest_clock()
        reset_guest_ui(ip_address)


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
