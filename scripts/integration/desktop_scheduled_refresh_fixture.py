#!/usr/bin/env python3
"""Read-only, bounded evidence collector for one already-scheduled desktop refresh.

The caller owns fixture admission, controller lifetime, and scheduler settings.  This
tool only observes the *next* scheduled operation, samples the already-running
mixed SOCKS listener with curl, and writes raw CLI and ledger evidence.  It never
starts/stops an owner or changes settings.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Callable


SCHEDULED_REQUEST_PREFIX = "scheduled-refresh:"
PRODUCT_USER_AGENT = "VPNControlDesktop/1.0"


class ObservationError(RuntimeError):
    pass


def mixed_loopback_port(state_dir: Path) -> int:
    """Return only the product's named mixed loopback inbound port.

    Looking for any ``listen_port`` can accidentally select a management or
    verification listener.  The persisted desktop runtime config is authoritative.
    """
    config = state_dir / "runtime-config.json"
    try:
        document = json.loads(config.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ObservationError(f"Cannot read runtime config {config}: {error}") from error
    inbounds = document.get("inbounds") if isinstance(document, dict) else None
    if not isinstance(inbounds, list):
        raise ObservationError("Runtime config has no inbounds array")
    matches = [item for item in inbounds if isinstance(item, dict)
               and item.get("type") == "mixed" and item.get("tag") == "mixed-in"
               and item.get("listen") == "127.0.0.1"]
    if len(matches) != 1:
        raise ObservationError("Expected exactly one loopback mixed-in inbound")
    port = matches[0].get("listen_port")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ObservationError("mixed-in has no valid listen_port")
    return port


def read_ready(ready_file: Path) -> dict[str, Any]:
    try:
        ready = json.loads(ready_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ObservationError(f"Cannot read fixture readiness {ready_file}: {error}") from error
    if not isinstance(ready, dict) or ready.get("httpsHost") != "localhost":
        raise ObservationError("Fixture readiness must name localhost HTTPS")
    port = ready.get("httpsPort")
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ObservationError("Fixture readiness has no valid httpsPort")
    return ready


def scheduled_operation(document: dict[str, Any], previous_ids: set[str]) -> dict[str, Any] | None:
    rows = document.get("data", {}).get("operations", [])
    if not isinstance(rows, list):
        raise ObservationError("operations list did not contain an operations array")
    matches = [row for row in rows if isinstance(row, dict) and row.get("id") not in previous_ids
               and str(row.get("requestId", "")).startswith(SCHEDULED_REQUEST_PREFIX)
               and row.get("operation") == "subscriptions.refresh"]
    if len(matches) > 1:
        raise ObservationError("More than one new scheduled refresh was observed")
    return matches[0] if matches else None


def ledger_rows(ledger: Path) -> list[dict[str, Any]]:
    try:
        lines = ledger.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ObservationError(f"Cannot read HTTP ledger {ledger}: {error}") from error
    rows: list[dict[str, Any]] = []
    for line in lines:
        if line.strip():
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ObservationError(f"Malformed HTTP ledger line: {error}") from error
            if not isinstance(row, dict):
                raise ObservationError("HTTP ledger row is not an object")
            rows.append(row)
    return rows


def ledger_intersection(rows: list[dict[str, Any]], started: float, finished: float,
                        samples: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    def within(row: dict[str, Any], left: float, right: float) -> bool:
        stamp = row.get("timestamp")
        return isinstance(stamp, (int, float)) and left <= stamp <= right and row.get("path") == "/subscription"

    operation = [row for row in rows if within(row, started, finished)
                 and row.get("userAgent") == PRODUCT_USER_AGENT]
    traffic: list[dict[str, Any]] = []
    for sample in samples:
        if sample["returncode"] == 0:
            traffic.extend(row for row in rows if within(row, sample["startedAt"], sample["finishedAt"])
                           and str(row.get("userAgent", "")).startswith("curl/"))
    return {"scheduled": operation, "traffic": traffic}


def require_curl(path: str) -> None:
    candidate = Path(path)
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise ObservationError(f"curl executable is unavailable: {path}")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def status_identity(document: dict[str, Any]) -> dict[str, Any]:
    data = document.get("data")
    if not isinstance(data, dict) or not document.get("controllerId"):
        raise ObservationError("status did not identify the controller")
    identity = {"controllerId": document["controllerId"], "runtimeRunning": data.get("runtimeRunning"),
                "runtimeId": data.get("runtimeId"), "activeLocationId": data.get("activeLocationId")}
    if identity["runtimeRunning"] is not True or not identity["runtimeId"]:
        raise ObservationError("opening status did not retain an active runtime")
    return identity


def output_text(value: object) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value or "")


def observe(arguments: argparse.Namespace, run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
            now: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    """Collect a receipt.  Expected failures return a truthful non-passing receipt."""
    evidence = Path(arguments.evidence_dir)
    if evidence.exists():
        return {"result": "failed", "partial": True, "readOnly": True,
                "failure": f"Evidence directory already exists: {evidence}"}
    evidence.mkdir(parents=True)
    receipt: dict[str, Any] = {"result": "failed", "partial": True, "readOnly": True}
    try:
        require_curl(arguments.curl)
        port = mixed_loopback_port(Path(arguments.state_dir))
        ready = read_ready(Path(arguments.ready_file))
        if not Path(arguments.ca_file).is_file():
            raise ObservationError("CA file is unavailable")
        command_prefix = [arguments.launcher, "--state-dir", arguments.state_dir, "--json"]

        def cli(name: str, tail: list[str], allow_failure: bool = False, timeout: float | None = None) -> dict[str, Any]:
            argv = command_prefix + tail
            try:
                result = run(argv, capture_output=True, text=True,
                             timeout=arguments.command_timeout if timeout is None else timeout)
            except subprocess.TimeoutExpired as error:
                write_json(evidence / name, {"argv": argv, "timeout": error.timeout,
                                             "stdout": output_text(error.stdout), "stderr": output_text(error.stderr)})
                raise ObservationError(f"CLI command timed out: {' '.join(tail)}") from error
            raw = {"argv": command_prefix + tail, "returncode": result.returncode,
                   "stdout": result.stdout, "stderr": result.stderr}
            write_json(evidence / name, raw)
            if result.returncode != 0 and not allow_failure:
                raise ObservationError(f"CLI command failed: {' '.join(tail)}")
            try:
                document = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise ObservationError(f"CLI returned invalid JSON for {' '.join(tail)}") from error
            if not isinstance(document, dict):
                raise ObservationError(f"CLI returned non-object JSON for {' '.join(tail)}")
            if not document.get("ok") and not allow_failure:
                raise ObservationError(f"CLI rejected {' '.join(tail)}")
            return document

        opening = cli("status-opening.json", ["status"])
        pinned = status_identity(opening)

        def pinned_cli(name: str, tail: list[str], allow_failure: bool = False,
                       timeout: float | None = None) -> dict[str, Any]:
            document = cli(name, tail, allow_failure, timeout)
            if document.get("controllerId") != pinned["controllerId"]:
                raise ObservationError("Controller epoch changed during observation")
            return document

        baseline = pinned_cli("operations-baseline.json", ["operations", "list"])
        previous_ids = {str(item.get("id")) for item in baseline.get("data", {}).get("operations", [])
                        if isinstance(item, dict) and item.get("id") is not None}
        ledger = Path(arguments.ledger)
        baseline_ledger = ledger.read_text(encoding="utf-8")
        (evidence / "http-ledger-baseline.jsonl").write_text(baseline_ledger, encoding="utf-8")
        started = now()
        deadline = started + arguments.max_duration
        observed: dict[str, Any] | None = None
        samples: list[dict[str, Any]] = []
        poll = 0
        terminal_seen = False

        def sample(index: int) -> None:
            sample_started = now()
            gap_before = sample_started - (samples[-1]["finishedAt"] if samples else started)
            argv = [arguments.curl, "--silent", "--show-error", "--fail", "--max-time", str(arguments.curl_timeout),
                   "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{port}", "--cacert", arguments.ca_file,
                   f"https://localhost:{ready['httpsPort']}/subscription"]
            try:
                result = run(argv, capture_output=True, text=True, timeout=arguments.curl_timeout + 1)
                samples.append({"argv": result.args or argv, "returncode": result.returncode, "stdout": result.stdout,
                                "stderr": result.stderr, "startedAt": sample_started, "finishedAt": now()})
            except subprocess.TimeoutExpired as error:
                samples.append({"argv": argv, "timeout": error.timeout, "stdout": output_text(error.stdout),
                                "stderr": output_text(error.stderr), "returncode": None,
                                "startedAt": sample_started, "finishedAt": now()})
                write_json(evidence / "traffic-samples.json", samples)
                raise ObservationError("curl sampler timed out") from error
            samples[-1]["gapBeforeSeconds"] = gap_before
            write_json(evidence / "traffic-samples.json", samples)

        while now() < deadline:
            # This sample records traffic before each poll, including before
            # discovery and around a fast scheduled operation. Polling still
            # leaves measured gaps; the receipt reports them.
            sample(len(samples))
            listing = pinned_cli(f"operations-poll-{poll:04d}.json", ["operations", "list"])
            candidate = scheduled_operation(listing, previous_ids)
            if candidate is not None:
                observed = candidate
                terminal_seen = candidate.get("final") is True
                if terminal_seen:
                    break
            if observed is not None and not terminal_seen:
                # Keep sampling/polling until the exact newly observed identity
                # reaches terminal state, instead of blocking in operations wait.
                if candidate is not None and candidate.get("final") is True:
                    terminal_seen = True
                    break
            poll += 1
            sleep(arguments.poll_interval)
        if observed is None:
            raise ObservationError("No new scheduled refresh was observed before deadline")
        if not terminal_seen:
            raise ObservationError("Scheduled refresh did not reach a terminal result before deadline")
        terminal_observed_at = now()
        sample(len(samples))
        remaining = deadline - now()
        if remaining <= 0:
            raise ObservationError("No post-terminal continuity sample before deadline")
        wait = pinned_cli("scheduled-operation-wait.json", ["operations", "wait", str(observed["id"])],
                          allow_failure=True, timeout=min(arguments.command_timeout, remaining))
        if wait.get("operationId") != observed["id"]:
            raise ObservationError("operations wait did not return the selected scheduled operation")
        finished = now()
        closing = pinned_cli("status-closing.json", ["status"])
        closing_identity = status_identity(closing)
        if closing_identity != pinned:
            raise ObservationError("Controller runtime identity changed during scheduled refresh")
        write_json(evidence / "scheduled-operation-observed.json", observed)
        final_ledger = ledger.read_text(encoding="utf-8")
        (evidence / "http-ledger-final.jsonl").write_text(final_ledger, encoding="utf-8")
        intersections = ledger_intersection(ledger_rows(ledger), started, finished, samples)
        write_json(evidence / "http-ledger-intersection.json", intersections)
        scheduled_hits = intersections["scheduled"]
        hit_time = scheduled_hits[0].get("timestamp") if scheduled_hits else None
        before = [sample for sample in samples if sample.get("returncode") == 0 and sample["finishedAt"] <= hit_time] if isinstance(hit_time, (int, float)) else []
        after = [sample for sample in samples if sample.get("returncode") == 0 and sample["startedAt"] >= hit_time] if isinstance(hit_time, (int, float)) else []
        # A pair of successful edge probes cannot hide a failed probe during the
        # observed event.  Keep every result (including failures) in the receipt
        # and require the complete baseline-to-post-terminal continuity window.
        window_samples = [sample for sample in samples if started <= sample["startedAt"] <= finished]
        all_samples_succeeded = bool(window_samples) and all(sample.get("returncode") == 0 for sample in window_samples)
        max_inter_probe_gap = max((sample.get("gapBeforeSeconds", 0.0) for sample in window_samples), default=0.0)
        final_unsampled_gap = finished - window_samples[-1]["finishedAt"] if window_samples else 0.0
        continuity = bool(wait.get("final") is True and scheduled_hits and intersections["traffic"] and before and after and all_samples_succeeded)
        receipt.update({"operation": observed, "observationStartedAt": started, "terminalObservedAt": terminal_observed_at,
                        "finishedAt": finished, "openingStatus": opening, "closingStatus": closing, "wait": wait,
                        "operationOutcome": {"final": wait.get("final"), "code": wait.get("code")},
                        "samples": samples, "continuityWindow": {"startedAt": started, "scheduledHitAt": hit_time,
                        "terminalObservedAt": terminal_observed_at, "finishedAt": finished, "sampleCount": len(window_samples),
                        "allSamplesSucceeded": all_samples_succeeded, "maxInterProbeGapSeconds": max_inter_probe_gap,
                        "finalUnsampledGapSeconds": final_unsampled_gap,
                        "maxObservedGapSeconds": max(max_inter_probe_gap, final_unsampled_gap)}, "ledgerIntersection": intersections,
                        "result": "passed" if continuity else "failed", "partial": not continuity})
        if not continuity:
            receipt["failure"] = "Continuity requires fresh scheduled HTTP evidence and every sampled probe through terminal to succeed"
    except (ObservationError, subprocess.SubprocessError, OSError) as error:
        receipt["failure"] = str(error)
    write_json(evidence / "scheduled-refresh-receipt.json", receipt)
    return receipt


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--ready-file", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--curl", default="/usr/bin/curl")
    parser.add_argument("--max-duration", type=float, required=True)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--curl-timeout", type=float, default=3.0)
    parser.add_argument("--command-timeout", type=float, default=10.0)
    result = parser.parse_args(argv)
    if result.max_duration <= 0 or result.poll_interval <= 0 or result.curl_timeout <= 0 or result.command_timeout <= 0:
        parser.error("durations must be positive")
    return result


def main(argv: list[str] | None = None) -> int:
    receipt = observe(parse_args(argv))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
