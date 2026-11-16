#!/usr/bin/env python3
"""Build step of the `Gradle Cache Warm` workflow (.github/workflows/gradle-cache-warm.yml).

STABLE INTERFACE: main's frozen copy of the warm workflow runs this file by its
path, with no arguments, in a checkout of a newer dev commit after `Set up
Gradle`. Keep the path and the no-argument call; everything else it uses is
resolved here from the same dev checkout, so dev may rename those helpers.

Runs, for the current runner OS, the Gradle compilation tasks behind the CI jobs
on that OS without executing any test, so the Gradle User Home that setup-gradle
saves afterwards holds their dependencies and, for development sources, their
task outputs. On Linux it first installs the pinned Android native build tools,
and it applies the CI build-cache policy (scripts/gradle_ci_cache.py) itself.
The workflow chose and checked out the commit.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DESKTOP = (":desktopApp:compileKotlin", ":desktopApp:testClasses")
# Fast Checks, Android Release APK and Linux Desktop Package run on ubuntu-24.04.
TASKS = {
    "Linux": DESKTOP + (
        ":shared:model:desktopTestClasses",
        ":shared:core:desktopTestClasses",
        ":shared:ui:desktopTestClasses",
        ":app:compileDebugKotlin",
        ":app:compileDebugUnitTestKotlin",
        ":app:compileDebugAndroidTestKotlin",
        ":app:compileReleaseKotlin",
    ),
    "macOS": DESKTOP,
    "Windows": DESKTOP,
}


def runner_os(environment: dict[str, str]) -> str:
    name = environment.get("RUNNER_OS") or {"Darwin": "macOS"}.get(platform.system(), platform.system())
    if name not in TASKS:
        raise SystemExit(f"No Gradle warm tasks for runner OS {name!r}.")
    return name


def build_command(name: str) -> list[str]:
    wrapper = ROOT / ("gradlew.bat" if name == "Windows" else "gradlew")
    return [str(wrapper), "--continue", *TASKS[name]]


def prepare_commands(name: str) -> list[list[str]]:
    """Toolchain setup the OS's tasks need before Gradle runs."""
    if name == "Linux":
        return [["bash", str(ROOT / "scripts/prepare_android_native_tools.sh")]]
    return []


def build_environment(environment: dict[str, str]) -> dict[str, str]:
    """Apply the CI build-cache policy and return the Gradle build's environment."""
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import gradle_ci_cache
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    decision = gradle_ci_cache.decide(environment, ROOT)
    options = gradle_ci_cache.install(decision, environment)
    print("[vpn-control] Gradle build cache " + json.dumps(decision, sort_keys=True), flush=True)
    result = dict(environment)
    joined = " ".join(part for part in (environment.get("GRADLE_OPTS", ""), options) if part)
    if joined:
        result["GRADLE_OPTS"] = joined
    return result


def main() -> int:
    name = runner_os(dict(os.environ))
    for command in prepare_commands(name):
        print("[vpn-control] " + " ".join(command), flush=True)
        subprocess.run(command, cwd=ROOT, check=True)
    environment = build_environment(dict(os.environ))
    command = build_command(name)
    print("[vpn-control] " + " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT, env=environment).returncode


if __name__ == "__main__":
    raise SystemExit(main())
