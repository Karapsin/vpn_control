#!/usr/bin/env python3
"""Exercise the real desktop task graph through Gradle's configuration cache."""

import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COMMAND = [
    str(ROOT / ("gradlew.bat" if os.name == "nt" else "gradlew")),
    "--configuration-cache",
    "--configuration-cache-problems=fail",
    ":desktopApp:compileKotlin",
    "--dry-run",
]


def probe() -> tuple[subprocess.CompletedProcess[str], float]:
    started = time.monotonic()
    result = subprocess.run(COMMAND, cwd=ROOT, capture_output=True, text=True, timeout=180)
    return result, time.monotonic() - started


def main() -> None:
    first, first_seconds = probe()
    if first.returncode:
        raise AssertionError(
            f"First configuration-cache probe failed in {first_seconds:.2f}s:\n"
            f"{first.stdout[-5000:]}\n{first.stderr[-5000:]}"
        )
    second, second_seconds = probe()
    if second.returncode:
        raise AssertionError(
            f"Second configuration-cache probe failed in {second_seconds:.2f}s:\n"
            f"{second.stdout[-5000:]}\n{second.stderr[-5000:]}"
        )
    if "Reusing configuration cache." not in second.stdout:
        raise AssertionError(
            "Second task graph did not reuse the configuration cache:\n"
            f"{second.stdout[-5000:]}\n{second.stderr[-5000:]}"
        )
    print(
        "Gradle configuration cache reused: "
        f"first={first_seconds:.2f}s second={second_seconds:.2f}s"
    )


if __name__ == "__main__":
    main()
