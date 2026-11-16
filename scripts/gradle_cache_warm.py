#!/usr/bin/env python3
"""Build step of the `Gradle Cache Warm` workflow (.github/workflows/gradle-cache-warm.yml).

Runs, for the current runner OS, the Gradle compilation tasks behind the CI jobs
on that OS without executing any test, so the Gradle User Home that setup-gradle
saves afterwards holds their dependencies and, for development sources, their
task outputs. scripts/gradle_cache_warm_source.py chose and checked out the commit.
"""
from __future__ import annotations

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


def main() -> int:
    command = build_command(runner_os(dict(os.environ)))
    print("[vpn-control] " + " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT).returncode


if __name__ == "__main__":
    raise SystemExit(main())
