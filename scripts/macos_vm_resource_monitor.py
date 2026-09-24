#!/usr/bin/env python3
"""Foreground, receipt-producing resource monitor for one owned Tart VM."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any


NORMAL_PRESSURE = "1"
VM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ObservationError(RuntimeError):
    pass


def write_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)


def append_json(path: Path, value: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as output:
        json.dump(value, output, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


def command(args: list[str], timeout: float = 20) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ObservationError(f"unable to observe {' '.join(args[:2])}: {error}") from error


def tart_state(tart: str, vm_name: str) -> dict[str, Any]:
    result = command([tart, "get", vm_name, "--format", "json"])
    if result.returncode != 0:
        raise ObservationError("unable to read Tart VM state")
    try:
        state = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ObservationError("Tart VM state was not JSON") from error
    if not isinstance(state, dict):
        raise ObservationError("Tart VM state was not an object")
    return state


def pressure(sysctl: str) -> str:
    result = command([sysctl, "-n", "kern.memorystatus_vm_pressure_level"])
    if result.returncode != 0:
        raise ObservationError("unable to observe host memory pressure")
    return result.stdout.strip()


def swap(sysctl: str) -> str:
    result = command([sysctl, "vm.swapusage"])
    if result.returncode != 0:
        raise ObservationError("unable to observe host swap")
    return result.stdout.strip()


def validate_admission(tart: str, sysctl: str, vm_name: str) -> None:
    if not VM_NAME.fullmatch(vm_name):
        raise ObservationError("VM name is not a single safe Tart name")
    state = tart_state(tart, vm_name)
    if state.get("State") != "stopped" or state.get("Running") is not False:
        raise ObservationError("owned Tart VM is not stopped")
    if pressure(sysctl) != NORMAL_PRESSURE:
        raise ObservationError("host memory pressure is not normal")


def monitor(args: argparse.Namespace) -> int:
    evidence = Path(args.evidence_dir)
    if evidence.exists():
        raise ObservationError("evidence directory already exists")
    evidence.mkdir(mode=0o700, parents=True)
    validate_admission(args.tart, args.sysctl, args.vm_name)

    with (evidence / "tart.log").open("x", encoding="utf-8") as tart_log:
        child = subprocess.Popen(
            [args.tart, "run", "--no-graphics", "--no-audio", "--no-clipboard", args.vm_name],
            stdout=tart_log,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        write_json(
            evidence / "process.json",
            {
                "childPid": child.pid,
                "childSessionId": os.getsid(child.pid),
                "monitorPid": os.getpid(),
                "monitorSessionId": os.getsid(0),
                "vm": args.vm_name,
            },
        )
        while child.poll() is None:
            try:
                sample_pressure = pressure(args.sysctl)
                sample_swap = swap(args.sysctl)
            except ObservationError as error:
                write_json(evidence / "observation-failure.json", {"error": str(error), "childPid": child.pid})
                # The child may be an unknown real VM. Do not stop or signal it.
                return 2
            append_json(
                evidence / "samples.jsonl",
                {"childExit": child.poll(), "pressure": sample_pressure, "swap": sample_swap, "time": time.time()},
            )
            if sample_pressure != NORMAL_PRESSURE:
                try:
                    stopped = command(
                        [args.tart, "stop", args.vm_name, "--timeout", "60"],
                        timeout=args.stop_timeout_seconds,
                    )
                except ObservationError as error:
                    write_json(
                        evidence / "stop-uncertain.json",
                        {"childPid": child.pid, "error": str(error), "pressure": sample_pressure},
                    )
                    # The stop request may have reached Tart. Preserve the child
                    # and its receipts rather than issuing a duplicate stop.
                    return 2
                write_json(
                    evidence / "stop.json",
                    {"code": stopped.returncode, "stderr": stopped.stderr, "stdout": stopped.stdout},
                )
            time.sleep(args.interval_seconds)

        exit_code = child.wait()
        try:
            final_state: dict[str, Any] | None = tart_state(args.tart, args.vm_name)
            state_error: str | None = None
        except ObservationError as error:
            final_state = None
            state_error = str(error)
        write_json(
            evidence / "terminal.json",
            {"childExit": exit_code, "state": final_state, "stateObservationError": state_error, "vm": args.vm_name},
        )
        return exit_code


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm-name", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--tart", default="tart")
    parser.add_argument("--sysctl", default="sysctl")
    parser.add_argument("--interval-seconds", type=float, default=5.0)
    parser.add_argument("--stop-timeout-seconds", type=float, default=75.0)
    parsed = parser.parse_args()
    if parsed.interval_seconds <= 0:
        parser.error("--interval-seconds must be positive")
    if parsed.stop_timeout_seconds <= 0:
        parser.error("--stop-timeout-seconds must be positive")
    return parsed


def main() -> int:
    try:
        return monitor(parse_args())
    except ObservationError as error:
        print(f"macOS VM resource monitor: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
