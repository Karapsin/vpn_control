#!/usr/bin/env python3
"""Plan, bootstrap, and run agent-owned visual capture environments."""

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
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "visual-tests" / "scenes.json"
ENVIRONMENTS_PATH = ROOT / "visual-tests" / "environments.json"
RUNTIME_ROOT = ROOT / ".runtime" / "visual-vms"
PLATFORMS = ("android", "linux", "windows", "macos")


class VisualPlatformError(ValueError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise VisualPlatformError(f"expected JSON object: {path}")
    return value


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_hash(path: Path) -> str:
    return _canonical_hash(_read_json(path))


def _head_sha() -> str:
    completed = _run(["git", "rev-parse", "HEAD"], timeout=30)
    value = completed.stdout.strip()
    if completed.returncode != 0 or len(value) != 40:
        raise VisualPlatformError(completed.stderr.strip() or "could not resolve capture HEAD")
    return value


def _run(command: list[str], *, timeout: int = 120, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def _state_path(platform: str) -> Path:
    return RUNTIME_ROOT / "state" / f"{platform}.json"


def _write_state(platform: str, value: dict[str, Any]) -> None:
    path = _state_path(platform)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_state(platform: str) -> dict[str, Any]:
    path = _state_path(platform)
    if not path.is_file():
        return {}
    value = _read_json(path)
    return value if value.get("platform") == platform else {}


def _which_any(*names: str) -> str | None:
    return next((value for name in names if (value := shutil.which(name))), None)


def _android_tool(name: str) -> str | None:
    direct = shutil.which(name)
    if direct:
        return direct
    candidates: list[Path] = []
    for raw in (os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT")):
        if raw:
            sdk = Path(raw)
            candidates.extend((sdk / "platform-tools" / name, sdk / "emulator" / name))
            candidates.extend(sorted((sdk / "cmdline-tools").glob(f"*/bin/{name}")))
    candidates.extend(
        [
            Path("/opt/homebrew/share/android-commandlinetools/platform-tools") / name,
            Path("/opt/homebrew/share/android-commandlinetools/emulator") / name,
            Path("/opt/homebrew/share/android-commandlinetools/cmdline-tools/latest/bin") / name,
        ],
    )
    return next((str(path) for path in candidates if path.is_file()), None)


def _android_avds() -> set[str]:
    emulator = _android_tool("emulator")
    if not emulator:
        return set()
    completed = _run([emulator, "-list-avds"], timeout=30)
    if completed.returncode != 0:
        return set()
    return {line.strip() for line in completed.stdout.splitlines() if line.strip()}


def _running_android_avds(adb: str) -> dict[str, str]:
    completed = _run([adb, "devices"], timeout=30)
    if completed.returncode != 0:
        return {}
    result: dict[str, str] = {}
    for line in completed.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2 or parts[1] != "device" or not parts[0].startswith("emulator-"):
            continue
        serial = parts[0]
        queried = _run([adb, "-s", serial, "emu", "avd", "name"], timeout=30)
        if queried.returncode != 0:
            continue
        name = next(
            (value.strip() for value in queried.stdout.splitlines() if value.strip() and value.strip() != "OK"),
            "",
        )
        if name:
            result[name] = serial
    return result


def scenes_for(platform: str) -> list[dict[str, Any]]:
    manifest = _read_json(MANIFEST_PATH)
    if manifest.get("schema_version") != 1:
        raise VisualPlatformError("visual manifest schema must be 1")
    scenes = [
        scene for scene in manifest.get("scenes", [])
        if isinstance(scene, dict) and platform in scene.get("platforms", [])
    ]
    if not scenes:
        raise VisualPlatformError(f"no visual scenes are defined for {platform}")
    secure = set(manifest.get("capture_contract", {}).get("secure_scene_ids", []))
    for scene in scenes:
        scene["required_capability"] = "secure_desktop" if scene.get("id") in secure else (
            "app" if scene.get("geometry_required", True) else "native"
        )
    return scenes


def _tart_names() -> set[str]:
    if not shutil.which("tart"):
        return set()
    completed = _run(["tart", "list", "--format", "json"], timeout=30)
    if completed.returncode == 0:
        try:
            payload = json.loads(completed.stdout or "[]")
            if isinstance(payload, list):
                return {str(item.get("Name", item.get("name", ""))) for item in payload if isinstance(item, dict)}
        except json.JSONDecodeError:
            pass
    completed = _run(["tart", "list"], timeout=30)
    return {
        token
        for line in completed.stdout.splitlines()[1:]
        if len((parts := line.split())) >= 2
        for token in [parts[1]]
    } if completed.returncode == 0 else set()


def local_probe(platform: str) -> dict[str, Any]:
    environments = _read_json(ENVIRONMENTS_PATH)
    config = environments["platforms"][platform]
    system = host_platform.system().lower()
    capabilities: set[str] = set()
    backend = ""
    detail = ""
    if platform == "android":
        required = (_android_tool("adb"), _android_tool("emulator"), _android_tool("avdmanager"))
        avd_name = str(config["local"]["avd_name"])
        if all(required) and avd_name in _android_avds():
            backend = "android-emulator"
            capabilities.update(("app", "native"))
        elif all(required):
            detail = f"Android visual AVD {avd_name} is not installed"
        else:
            detail = "Android adb, emulator, and avdmanager are required"
    elif platform == "linux":
        if system == "linux" and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            backend = "native-linux"
            capabilities.update(("app", "native"))
        else:
            vm_name = str(config["local"]["vm_name"])
            if vm_name in _tart_names():
                backend = "tart-linux"
                capabilities.update(("app", "native"))
            else:
                detail = f"local Linux GUI or Tart VM {vm_name} is not ready"
    elif platform == "windows":
        if system == "windows" and os.environ.get("VPN_CONTROL_VISUAL_ISOLATED") == "1":
            backend = "native-windows"
            capabilities.update(("app", "native", "secure_desktop"))
        else:
            name = str(config["local"]["libvirt_name"])
            completed = _run(["virsh", "dominfo", name], timeout=30) if shutil.which("virsh") else None
            if completed is not None and completed.returncode == 0:
                backend = "libvirt-windows"
                capabilities.update(("app", "native", "secure_desktop"))
            else:
                disk = ROOT / str(config["local"]["qemu_disk"])
                ready_marker = ROOT / str(config["local"]["qemu_ready_marker"])
                if (
                    disk.is_file()
                    and ready_marker.is_file()
                    and _which_any("qemu-system-aarch64", "qemu-system-x86_64")
                ):
                    backend = "qemu-windows"
                    capabilities.update(("app", "native", "secure_desktop"))
                elif disk.is_file():
                    detail = "the managed Windows disk exists but has not passed agent provisioning checks"
                else:
                    detail = "a Windows 11 client VM is required for secure-desktop capture"
    elif platform == "macos":
        if system == "darwin" and os.environ.get("VPN_CONTROL_VISUAL_ISOLATED") == "1":
            backend = "native-macos"
            capabilities.update(("app", "native", "secure_desktop"))
        else:
            vm_name = str(config["local"]["vm_name"])
            if vm_name in _tart_names():
                backend = "tart-macos"
                capabilities.update(("app", "native", "secure_desktop"))
            else:
                detail = f"isolated native session or Tart VM {vm_name} is not ready"
    return {
        "ready": bool(backend),
        "backend": backend,
        "capabilities": sorted(capabilities),
        "detail": detail,
    }


def capture_plan(platform: str) -> dict[str, Any]:
    environments = _read_json(ENVIRONMENTS_PATH)
    config = environments["platforms"][platform]
    local = local_probe(platform)
    hosted_capabilities = set(config["hosted"]["capabilities"])
    # Hosted Apple Silicon workers do not expose the Hypervisor framework
    # required by an Android API 35 emulator. Android visual evidence is
    # therefore always captured by an agent-started isolated emulator.
    if platform == "android":
        hosted_capabilities.clear()
    local_capabilities = set(local["capabilities"])
    routes: dict[str, list[str]] = {"local": [], "hosted": [], "blocked": []}
    for scene in scenes_for(platform):
        scene_id = str(scene["id"])
        capability = str(scene["required_capability"])
        if capability in local_capabilities:
            routes["local"].append(scene_id)
        elif capability in hosted_capabilities:
            routes["hosted"].append(scene_id)
        else:
            routes["blocked"].append(scene_id)
    return {
        "platform": platform,
        "canonical_environment": config["canonical_environment"],
        "local": local,
        "hosted_runner": config["hosted"]["runner"],
        "routes": routes,
        "release_capable": not routes["blocked"],
    }


def bootstrap_commands(platform: str) -> list[list[str]]:
    config = _read_json(ENVIRONMENTS_PATH)["platforms"][platform]
    system = host_platform.system().lower()
    if platform == "android":
        sdkmanager = _android_tool("sdkmanager") or "sdkmanager"
        avdmanager = _android_tool("avdmanager") or "avdmanager"
        local = config["local"]
        system_image = str(
            local["system_image_arm64"]
            if host_platform.machine().lower() in {"arm64", "aarch64"}
            else local["system_image"]
        )
        return [
            [sdkmanager, "platform-tools", "emulator", system_image],
            [
                avdmanager, "create", "avd", "--force", "--name", str(local["avd_name"]),
                "--package", system_image, "--device", str(local["device"]),
            ],
        ]
    if platform in {"linux", "macos"} and system == "darwin":
        local = config["local"]
        return [["tart", "clone", str(local["image"]), str(local["vm_name"])]]
    if platform == "windows" and system == "darwin":
        return [[str(ROOT / "scripts" / "bootstrap_windows_visual_vm.sh")]]
    return []


def bootstrap(platform: str, *, dry_run: bool) -> dict[str, Any]:
    before = local_probe(platform)
    if before["ready"]:
        return {"platform": platform, "changed": False, "probe": before, "commands": []}
    commands = bootstrap_commands(platform)
    if not commands:
        raise VisualPlatformError(f"no local bootstrap adapter is available: {before['detail']}")
    if dry_run:
        return {
            "platform": platform,
            "changed": False,
            "probe": before,
            "commands": [shlex.join(command) for command in commands],
        }
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for index, command in enumerate(commands):
        input_text = "no\n" if platform == "android" and index == 1 else None
        completed = _run(command, timeout=2 * 60 * 60, input_text=input_text)
        results.append({
            "command": shlex.join(command),
            "returncode": completed.returncode,
            "stdout": completed.stdout[-2000:],
            "stderr": completed.stderr[-2000:],
        })
        if completed.returncode != 0:
            raise VisualPlatformError(f"visual bootstrap failed: {shlex.join(command)}\n{completed.stderr[-1000:]}")
    return {"platform": platform, "changed": True, "probe": local_probe(platform), "results": results}


def start_platform(platform: str, *, dry_run: bool = False) -> dict[str, Any]:
    probe = local_probe(platform)
    if not probe["ready"]:
        raise VisualPlatformError(f"local visual environment is not ready: {probe['detail']}")
    backend = str(probe["backend"])
    config = _read_json(ENVIRONMENTS_PATH)["platforms"][platform]["local"]
    command: list[str] | None = None
    started_by_agent = False
    identifier = backend
    if backend == "android-emulator":
        adb = _android_tool("adb") or "adb"
        avd_name = str(config["avd_name"])
        running = _running_android_avds(adb)
        if avd_name in running:
            identifier = running[avd_name]
        else:
            emulator = _android_tool("emulator") or "emulator"
            port = int(config["emulator_port"])
            identifier = f"emulator-{port}"
            command = [
                emulator, "-avd", avd_name, "-port", str(port), "-no-snapshot-save", "-no-boot-anim",
                "-gpu", "swiftshader_indirect", "-no-audio",
            ]
            started_by_agent = True
    elif backend.startswith("tart-"):
        vm_name = str(config["vm_name"])
        identifier = vm_name
        running = _run(["tart", "list"], timeout=30)
        if vm_name not in "\n".join(line for line in running.stdout.splitlines() if "running" in line.lower()):
            display = str(config.get("display", "")).strip()
            if display and not dry_run:
                configured = _run(
                    ["tart", "set", vm_name, "--display", display, "--no-display-refit"],
                    timeout=30,
                )
                if configured.returncode != 0:
                    raise VisualPlatformError(
                        configured.stderr.strip() or f"could not configure {vm_name} at {display}"
                    )
            command = [
                "tart", "run", "--no-graphics", "--dir", f"vpn-control:{ROOT}", vm_name,
            ]
            started_by_agent = True
    elif backend == "libvirt-windows":
        vm_name = str(config["libvirt_name"])
        identifier = vm_name
        state = _run(["virsh", "domstate", vm_name], timeout=30)
        if "running" not in state.stdout.lower():
            command = ["virsh", "start", vm_name]
            started_by_agent = True
    elif backend == "qemu-windows":
        command = [str(ROOT / "scripts" / "start_windows_visual_vm.sh")]
        started_by_agent = True
        identifier = str(config["qemu_disk"])
    if dry_run:
        return {
            "platform": platform,
            "backend": backend,
            "started_by_agent": started_by_agent,
            "command": shlex.join(command) if command else "",
        }
    process_id = 0
    if command:
        if backend in {"android-emulator", "qemu-windows"} or backend.startswith("tart-"):
            log_dir = RUNTIME_ROOT / "logs"
            log_dir.mkdir(parents=True, exist_ok=True)
            log = (log_dir / f"{platform}.log").open("ab")
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            process_id = process.pid
            log.close()
        else:
            completed = _run(command, timeout=120)
            if completed.returncode != 0:
                raise VisualPlatformError(completed.stderr.strip() or f"could not start {backend}")
    if backend == "android-emulator":
        adb = _android_tool("adb") or "adb"
        deadline = time.monotonic() + 5 * 60
        booted = False
        while time.monotonic() < deadline:
            completed = _run([adb, "-s", identifier, "shell", "getprop", "sys.boot_completed"], timeout=30)
            if completed.returncode == 0 and completed.stdout.strip() == "1":
                booted = True
                break
            time.sleep(2)
        if not booted:
            if started_by_agent:
                _run([adb, "-s", identifier, "emu", "kill"], timeout=30)
            raise VisualPlatformError(f"Android visual emulator did not boot: {identifier}")
        for setting in (
            ("global", "window_animation_scale", "0"),
            ("global", "transition_animation_scale", "0"),
            ("global", "animator_duration_scale", "0"),
            ("system", "font_scale", "1.0"),
        ):
            completed = _run([adb, "-s", identifier, "shell", "settings", "put", *setting], timeout=30)
            if completed.returncode != 0:
                raise VisualPlatformError(f"could not freeze Android visual setting: {' '.join(setting)}")
    state = {
        "schema_version": 1,
        "platform": platform,
        "backend": backend,
        "identifier": identifier,
        "started_by_agent": started_by_agent,
        "pid": process_id,
        "started_at_epoch": int(time.time()),
    }
    _write_state(platform, state)
    return state


def stop_platform(platform: str, *, dry_run: bool = False) -> dict[str, Any]:
    state = _read_state(platform)
    if not state:
        return {"platform": platform, "stopped": False, "reason": "no agent-owned lifecycle state"}
    if state.get("started_by_agent") is not True:
        return {"platform": platform, "stopped": False, "reason": "environment predated this agent run"}
    backend = str(state.get("backend", ""))
    identifier = str(state.get("identifier", ""))
    command: list[str] | None = None
    if backend == "android-emulator":
        command = [_android_tool("adb") or "adb", "-s", identifier, "emu", "kill"]
    elif backend.startswith("tart-"):
        command = ["tart", "stop", identifier]
    elif backend == "libvirt-windows":
        command = ["virsh", "shutdown", identifier]
    elif backend == "qemu-windows":
        qmp = RUNTIME_ROOT / "windows" / "qmp.sock"
        if qmp.exists() and shutil.which("socat"):
            command = ["socat", "-", f"UNIX-CONNECT:{qmp}"]
        else:
            raise VisualPlatformError("QEMU VM can be stopped only through its QMP socket; refusing a broad process kill")
    if dry_run:
        return {
            "platform": platform,
            "stopped": False,
            "command": shlex.join(command) if command else "",
        }
    if command:
        completed = _run(
            command,
            timeout=120,
            input_text=(
                '{"execute":"qmp_capabilities"}\n{"execute":"system_powerdown"}\n'
                if backend == "qemu-windows" else None
            ),
        )
        if completed.returncode != 0:
            raise VisualPlatformError(completed.stderr.strip() or f"could not stop {backend}")
    _state_path(platform).unlink(missing_ok=True)
    return {"platform": platform, "stopped": True, "backend": backend}


def dispatch_hosted(platform: str, target_sha: str, ref: str | None = None) -> dict[str, Any]:
    if len(target_sha) != 40 or any(char not in "0123456789abcdef" for char in target_sha):
        raise VisualPlatformError("target SHA must be 40 lowercase hexadecimal characters")
    if not ref:
        branch = _run(["git", "branch", "--show-current"], timeout=30)
        ref = branch.stdout.strip() if branch.returncode == 0 else ""
    if not ref:
        raise VisualPlatformError("hosted capture requires an explicit branch ref")
    hosted_scenes = capture_plan(platform)["routes"]["hosted"]
    if not hosted_scenes:
        raise VisualPlatformError(f"no {platform} scenes require a hosted fallback")
    command = [
        "gh", "workflow", "run", "visual-regression.yml", "--ref", ref,
        "-f", f"target_sha={target_sha}", "-f", f"platform={platform}",
        "-f", f"scenes={','.join(hosted_scenes)}",
    ]
    completed = _run(command, timeout=180)
    if completed.returncode != 0:
        raise VisualPlatformError(completed.stderr.strip() or "could not dispatch hosted visual capture")
    return {
        "platform": platform,
        "provider": "hosted",
        "ref": ref,
        "scene_count": len(hosted_scenes),
        "command": shlex.join(command),
    }


def download_hosted(platform: str, target_sha: str, output: Path, *, timeout_seconds: int = 60 * 60) -> dict[str, Any]:
    title = f"Visual Capture / {platform} / {target_sha}"
    deadline = time.monotonic() + timeout_seconds
    selected: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        listed = _run(
            [
                "gh", "run", "list", "--workflow", "visual-regression.yml", "--event", "workflow_dispatch",
                "--limit", "100", "--json", "databaseId,displayTitle,status,conclusion,headSha,url",
            ],
            timeout=120,
        )
        if listed.returncode != 0:
            raise VisualPlatformError(listed.stderr.strip() or "could not query hosted visual capture")
        try:
            runs = json.loads(listed.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise VisualPlatformError(f"invalid GitHub run list: {exc}") from exc
        matches = [
            run for run in runs
            if isinstance(run, dict)
            and run.get("displayTitle") == title
            and run.get("headSha") == target_sha
        ]
        if matches:
            selected = max(matches, key=lambda run: int(run.get("databaseId") or 0))
            if selected.get("status") == "completed":
                break
        time.sleep(15)
    if not selected or selected.get("status") != "completed":
        raise VisualPlatformError(f"hosted visual capture did not complete before timeout: {title}")
    if selected.get("conclusion") != "success":
        run_id = str(selected.get("databaseId"))
        failed = _run(["gh", "run", "view", run_id, "--log-failed"], timeout=180)
        excerpt = (failed.stdout or failed.stderr)[-4000:]
        raise VisualPlatformError(f"hosted visual capture failed: {selected.get('url')}\n{excerpt}")
    output.mkdir(parents=True, exist_ok=True)
    artifact = f"visual-capture-{platform}-{target_sha}"
    downloaded = _run(
        ["gh", "run", "download", str(selected["databaseId"]), "--name", artifact, "--dir", str(output)],
        timeout=15 * 60,
    )
    if downloaded.returncode != 0:
        raise VisualPlatformError(downloaded.stderr.strip() or "could not download hosted visual evidence")
    return {
        "platform": platform,
        "provider": "hosted",
        "run_id": selected["databaseId"],
        "url": selected.get("url", ""),
        "output": str(output),
    }


def stamp_capture(
    platform: str,
    target_sha: str,
    provider: str,
    output: Path,
    scene_ids: list[str],
) -> dict[str, Any]:
    if provider not in {"local", "hosted"}:
        raise VisualPlatformError("capture provider must be local or hosted")
    if len(target_sha) != 40 or any(char not in "0123456789abcdef" for char in target_sha):
        raise VisualPlatformError("capture target SHA must be 40 lowercase hexadecimal characters")
    known = {str(scene["id"]): scene for scene in scenes_for(platform)}
    unknown = sorted(set(scene_ids) - set(known))
    if unknown:
        raise VisualPlatformError("capture requested unknown scenes: " + ", ".join(unknown))
    files: dict[str, dict[str, str]] = {}
    missing: list[str] = []
    for scene_id in scene_ids:
        scene = known[scene_id]
        paths = {"actual": output / f"{scene_id}.png"}
        if scene.get("geometry_required", True):
            paths["geometry"] = output / f"{scene_id}.geometry.json"
        entry: dict[str, str] = {}
        for kind, path in paths.items():
            if not path.is_file():
                missing.append(path.name)
                continue
            entry[kind] = path.name
            entry[f"{kind}_sha256"] = _file_hash(path)
        files[scene_id] = entry
    if missing:
        raise VisualPlatformError("capture returned an incomplete set: " + ", ".join(missing))
    environment = {
        "canonical_environment": _read_json(ENVIRONMENTS_PATH)["platforms"][platform]["canonical_environment"],
        "host_system": host_platform.system(),
        "host_release": host_platform.release(),
        "host_machine": host_platform.machine(),
        "locale": locale.getlocale(),
        "display": os.environ.get("DISPLAY", ""),
        "wayland_display": os.environ.get("WAYLAND_DISPLAY", ""),
    }
    metadata = {
        "schema_version": 1,
        "platform": platform,
        "provider": provider,
        "target_sha": target_sha,
        "manifest_sha256": _json_hash(MANIFEST_PATH),
        "environment": environment,
        "environment_sha256": hashlib.sha256(
            json.dumps(environment, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        ).hexdigest(),
        "scenes": files,
    }
    metadata_path = output / f"capture-{provider}.json"
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"metadata": str(metadata_path), "scene_count": len(scene_ids)}


def run_local_driver(platform: str, driver: str, output: Path, scene_ids: list[str]) -> dict[str, Any]:
    command = shlex.split(driver)
    if not command:
        raise VisualPlatformError("a local capture driver command is required")
    output.mkdir(parents=True, exist_ok=True)
    scene_file = output / "requested-scenes.json"
    scene_file.write_text(json.dumps(scene_ids, indent=2) + "\n", encoding="utf-8")
    command.extend(
        [
            "--platform", platform,
            "--manifest", str(MANIFEST_PATH),
            "--scenes", str(scene_file),
            "--output", str(output.resolve()),
        ],
    )
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise VisualPlatformError(f"local capture driver failed with exit code {completed.returncode}")
    provider = os.environ.get("VPN_CONTROL_VISUAL_PROVIDER", "local").strip() or "local"
    configured_sha = os.environ.get("VPN_CONTROL_VISUAL_TARGET_SHA", "").strip()
    target_sha = configured_sha or _head_sha()
    if target_sha != _head_sha():
        raise VisualPlatformError("capture target SHA does not equal the checked-out HEAD")
    evidence = stamp_capture(platform, target_sha, provider, output, scene_ids)
    return {
        "platform": platform,
        "provider": provider,
        "scene_count": len(scene_ids),
        "output": str(output),
        **evidence,
    }


def verify_capture_provenance(platform: str, target_sha: str, actual_dir: Path) -> list[Path]:
    expected = {str(scene["id"]) for scene in scenes_for(platform)}
    covered: set[str] = set()
    metadata_paths = sorted(actual_dir.glob("capture-*.json"))
    if not metadata_paths:
        raise VisualPlatformError("visual capture provenance is missing")
    for metadata_path in metadata_paths:
        metadata = _read_json(metadata_path)
        if (
            metadata.get("schema_version") != 1
            or metadata.get("platform") != platform
            or metadata.get("target_sha") != target_sha
            or metadata.get("manifest_sha256") != _json_hash(MANIFEST_PATH)
        ):
            raise VisualPlatformError(f"capture provenance does not match target: {metadata_path}")
        environment = metadata.get("environment")
        if not isinstance(environment, dict) or metadata.get("environment_sha256") != hashlib.sha256(
            json.dumps(environment, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        ).hexdigest():
            raise VisualPlatformError(f"capture environment fingerprint is invalid: {metadata_path}")
        files = metadata.get("scenes")
        if not isinstance(files, dict):
            raise VisualPlatformError(f"capture provenance has no scenes: {metadata_path}")
        for scene_id, values in files.items():
            if scene_id not in expected or not isinstance(values, dict):
                raise VisualPlatformError(f"capture provenance has an unexpected scene: {scene_id}")
            for kind in ("actual", "geometry"):
                raw_path = str(values.get(kind, ""))
                expected_hash = str(values.get(f"{kind}_sha256", ""))
                if not raw_path:
                    continue
                if Path(raw_path).name != raw_path:
                    raise VisualPlatformError(f"capture provenance path is not a file name: {raw_path}")
                path = actual_dir / raw_path
                if not path.is_file() or not expected_hash or _file_hash(path) != expected_hash:
                    raise VisualPlatformError(f"captured {kind} changed after stamping: {platform}/{scene_id}")
            covered.add(scene_id)
    missing = sorted(expected - covered)
    if missing:
        raise VisualPlatformError("capture provenance does not cover every scene: " + ", ".join(missing))
    return metadata_paths


def verify_and_ingest(platform: str, target_sha: str, actual_dir: Path) -> dict[str, Any]:
    provenance = verify_capture_provenance(platform, target_sha, actual_dir)
    report_dir = ROOT / "build" / "visual-reports"
    verify = _run(
        [
            sys.executable, "scripts/visual_regression.py", "verify", "--platform", platform,
            "--actual-dir", str(actual_dir), "--report-dir", str(report_dir),
        ],
        timeout=30 * 60,
    )
    report = report_dir / platform / "report.json"
    if not report.is_file():
        raise VisualPlatformError("visual comparator did not produce a report")
    ingest = _run(
        [
            sys.executable, "scripts/visual_review.py", "ingest", "--target-sha", target_sha,
            "--platform", platform, "--report", str(report), "--actual-dir", str(actual_dir),
        ],
        timeout=120,
    )
    if ingest.returncode != 0:
        raise VisualPlatformError(ingest.stdout.strip() or ingest.stderr.strip())
    return {
        "platform": platform,
        "automation_passed": verify.returncode == 0,
        "report": str(report),
        "capture_provenance": [str(path) for path in provenance],
        "comparator_stdout": verify.stdout[-4000:],
        "review": json.loads(ingest.stdout),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    for action in ("probe", "plan"):
        command = subparsers.add_parser(action)
        command.add_argument("--platform", required=True, choices=PLATFORMS)
    command = subparsers.add_parser("bootstrap")
    command.add_argument("--platform", required=True, choices=PLATFORMS)
    command.add_argument("--dry-run", action="store_true")
    for action in ("start", "stop"):
        command = subparsers.add_parser(action)
        command.add_argument("--platform", required=True, choices=PLATFORMS)
        command.add_argument("--dry-run", action="store_true")
    command = subparsers.add_parser("dispatch-hosted")
    command.add_argument("--platform", required=True, choices=PLATFORMS)
    command.add_argument("--target-sha", required=True)
    command.add_argument("--ref")
    command = subparsers.add_parser("download-hosted")
    command.add_argument("--platform", required=True, choices=PLATFORMS)
    command.add_argument("--target-sha", required=True)
    command.add_argument("--output", required=True, type=Path)
    command.add_argument("--timeout-seconds", type=int, default=60 * 60)
    command = subparsers.add_parser("capture-local")
    command.add_argument("--platform", required=True, choices=PLATFORMS)
    command.add_argument("--driver", required=True)
    command.add_argument("--output", required=True, type=Path)
    command.add_argument("--scene", action="append")
    command = subparsers.add_parser("stamp")
    command.add_argument("--platform", required=True, choices=PLATFORMS)
    command.add_argument("--target-sha", required=True)
    command.add_argument("--provider", required=True, choices=("local", "hosted"))
    command.add_argument("--output", required=True, type=Path)
    command.add_argument("--scene", action="append", required=True)
    command = subparsers.add_parser("verify")
    command.add_argument("--platform", required=True, choices=PLATFORMS)
    command.add_argument("--target-sha", required=True)
    command.add_argument("--actual-dir", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.action == "probe":
            result = local_probe(args.platform)
        elif args.action == "plan":
            result = capture_plan(args.platform)
        elif args.action == "bootstrap":
            result = bootstrap(args.platform, dry_run=args.dry_run)
        elif args.action == "start":
            result = start_platform(args.platform, dry_run=args.dry_run)
        elif args.action == "stop":
            result = stop_platform(args.platform, dry_run=args.dry_run)
        elif args.action == "dispatch-hosted":
            result = dispatch_hosted(args.platform, args.target_sha, args.ref)
        elif args.action == "download-hosted":
            result = download_hosted(
                args.platform, args.target_sha, args.output, timeout_seconds=args.timeout_seconds,
            )
        elif args.action == "capture-local":
            selected = args.scene or [str(scene["id"]) for scene in scenes_for(args.platform)]
            result = run_local_driver(args.platform, args.driver, args.output, selected)
        elif args.action == "stamp":
            result = stamp_capture(args.platform, args.target_sha, args.provider, args.output, args.scene)
        else:
            result = verify_and_ingest(args.platform, args.target_sha, args.actual_dir)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, VisualPlatformError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
