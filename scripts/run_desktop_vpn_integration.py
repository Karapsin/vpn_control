#!/usr/bin/env python3
"""Run the package's guarded TUN probe against a no-egress local SOCKS fixture."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


TOKEN = "vpn-control-full-vpn-ok"
TARGET_URL = "http://198.18.0.1/probe"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=90)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    launcher = args.launcher.resolve()
    if not launcher.is_file():
        raise SystemExit(f"launcher does not exist: {launcher}")

    repo_root = Path(__file__).resolve().parent.parent
    fixture = repo_root / "scripts/integration/socks_http_fixture.py"
    with tempfile.TemporaryDirectory(prefix="vpn-control-full-vpn-") as temporary:
        temporary_path = Path(temporary)
        ready_file = temporary_path / "fixture-port"
        state_dir = temporary_path / "state"
        fixture_process = subprocess.Popen(
            [sys.executable, str(fixture), "--token", TOKEN, "--ready-file", str(ready_file)],
        )
        try:
            port = wait_for_port_file(ready_file, fixture_process)
            environment = dict(os.environ)
            environment["VPN_CONTROL_ALLOW_DISPOSABLE_INTEGRATION"] = "1"
            result = subprocess.run(
                [
                    str(launcher),
                    "--vpn-integration-test",
                    "--integration-socks-port",
                    str(port),
                    "--integration-target-url",
                    TARGET_URL,
                    "--integration-expected-body",
                    TOKEN,
                    "--integration-state-dir",
                    str(state_dir),
                ],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=args.timeout,
            )
            print(result.stdout, end="")
            return result.returncode
        finally:
            fixture_process.terminate()
            try:
                fixture_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                fixture_process.kill()
                fixture_process.wait(timeout=5)


def wait_for_port_file(path: Path, process: subprocess.Popen[bytes]) -> int:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.is_file():
            return int(path.read_text(encoding="utf-8").strip())
        if process.poll() is not None:
            raise RuntimeError(f"SOCKS fixture exited with code {process.returncode}")
        time.sleep(0.05)
    raise TimeoutError("timed out waiting for SOCKS fixture")


if __name__ == "__main__":
    raise SystemExit(main())
