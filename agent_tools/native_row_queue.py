"""The Windows discovery queue's reset decision table, and the suspect mark a start drift puts on the previous row.

A product row run with no reset since its install asks its job to prove its start (the driver's clean_start: every job
since the install passed or was refused, then a read-only census before any publish). The queue reads how each row ended
(row_end) and decides the next step (decide):

  row end                                      next step
  passed (rc 0)                                the next row with no reset; a reset first when the row changes what is
                                               installed (CHANGES_INSTALL: update, reboot and autostart-migration rows)
  known (rc 1), start drift                    mark the previous row since the reset suspect (mark_suspect), reset, and
                                               run the same row once more as a new operation; a second drift stops
                                               after a reset
  known (rc 1), unproven start                 reset and run the same row once more (no mark: nothing was seen left)
  known (rc 1), any other end                  reset before the next row
  anything unsettled (rc 3), a failed reset    stop: read the original's status; never replay, never reset over it

A start drift is state a row left behind that the next row's start found: a clean-start census drift
(clean_start_drift:*, a process, task, service, firewall rule or Run entry of the product) or an install that differs at
publish (installed_tree_differs, installed_registration_differs:*). The census before the previous row proved that row's
own start clean, so the previous row left it, and that row's evidence must not count: native_scenario_windows' matrix
classifies a suspect row "suspect", never "passed". An unproven start (clean_start_census_unreadable, _unclean_job,
_unordered) proves no leak, so it only resets. No fixed sleep anywhere: each operation's own readiness admission is what
it waits for.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable, Mapping

RESET = "windows-msi-base-reset"
# Rows whose pass leaves another install or an open chain behind: the next row needs a reset.
CHANGES_INSTALL = ("windows-public-update.", "windows-reboot-", "windows-autostart-migration.")
START_DRIFT = re.compile(r"(?:clean_start_drift:.+|installed_tree_differs|installed_registration_differs:.+)\Z")
UNPROVEN_START = re.compile(r"clean_start_(?:census_unreadable|unclean_job|unordered)\Z")
SUSPECTS = (".rag_index", "native-scenario-suspects")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,120}\Z")

# Steps.
NEXT, RESET_NEXT, RETRY, STOP = "next", "reset-then-next", "reset-then-retry", "stop"


def row_end(operation: str, scenario: str, collected: Mapping[str, Any], receipt: Mapping[str, Any] | None) -> dict[str, Any]:
    """How the queue reads a row: rc 0 passed; 1 this new operation ended known (failed, or refused before any guest
    effect); 3 anything else, which is read, never replayed. drift names a start drift, unproven an unproven start."""
    complete = collected.get("state") == "terminal" and collected.get("collectionState") == "complete"
    code = collected.get("exitCode") if complete else collected.get("executionExitCode")
    failure = (receipt or {}).get("failure") if complete else collected.get("executionFailure")
    refused = (collected.get("state") == "unknown" and collected.get("reason") == "terminal_collection_unverified"
               and collected.get("executionState") == "terminal" and code == 2)
    if complete and code == 0 and (receipt or {}).get("result") == "passed":
        rc = 0
    elif complete and code in (1, 2) or refused:
        rc = 1
    else:
        rc = 3
    known = rc == 1 and isinstance(failure, str)
    return {"operation": operation, "scenario": scenario, "rc": rc, "exitCode": code, "failure": failure,
            "drift": known and START_DRIFT.fullmatch(failure) is not None,
            "unproven": known and UNPROVEN_START.fullmatch(failure) is not None,
            "state": collected.get("state"), "reason": collected.get("reason")}


def decide(end: Mapping[str, Any] | None, *, attempts: int, previous: str | None) -> dict[str, Any]:
    """The next step after one row end: {"step", "suspect"}; suspect is the previous row's operation, or None."""
    if not end or end.get("rc") not in (0, 1, 3):
        return {"step": STOP, "suspect": None}
    if end["rc"] == 0:
        return {"step": RESET_NEXT if str(end.get("scenario", "")).startswith(CHANGES_INSTALL) else NEXT, "suspect": None}
    if end["rc"] == 3:
        return {"step": STOP, "suspect": None}
    suspect = previous if end.get("drift") else None
    if (end.get("drift") or end.get("unproven")) and attempts == 1:
        return {"step": RETRY, "suspect": suspect}
    return {"step": RESET_NEXT, "suspect": suspect}


def _directory(root: Path, create: bool) -> Path:
    directory = Path(root).joinpath(*SUSPECTS)
    if create:
        directory.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
    info = os.lstat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise OSError("native_row_suspects_unsafe")
    return directory


def mark_suspect(root: Path | str, correlation: str, *, detected_by: str, failure: str) -> dict[str, Any]:
    """Record, create-only and private, that a row's evidence is suspect: the next row's start found what it left."""
    if not (isinstance(correlation, str) and _UUID.fullmatch(correlation) and isinstance(detected_by, str)
            and _UUID.fullmatch(detected_by) and isinstance(failure, str) and _TOKEN.fullmatch(failure)):
        raise ValueError("native_row_suspect_invalid")
    record = {"schemaVersion": 1, "correlationId": correlation, "detectedBy": detected_by, "failure": failure}
    path = _directory(Path(root), True) / (correlation + ".json")
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        existing = suspect(root, correlation)
        if existing is None:
            raise ValueError("native_row_suspect_unreadable") from None
        return existing  # The first detection stands; a mark is never cleared.
    try:
        os.write(descriptor, (json.dumps(record, sort_keys=True) + "\n").encode())
    finally:
        os.close(descriptor)
    return record


def suspect(root: Path | str, correlation: str) -> dict[str, Any] | None:
    """The suspect mark of a row, or None. A mark that exists but cannot be read is suspect too (fail closed)."""
    if not (isinstance(correlation, str) and _UUID.fullmatch(correlation)):
        return None
    path = Path(root).joinpath(*SUSPECTS, correlation + ".json")
    if not os.path.lexists(path):
        return None
    unreadable = {"schemaVersion": 1, "correlationId": correlation, "detectedBy": None, "failure": "suspect_mark_unreadable"}
    try:
        _directory(Path(root), False)
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                return unreadable
            value = json.loads(os.read(descriptor, 4097))
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        return unreadable
    if type(value) is not dict or value.get("correlationId") != correlation:
        return unreadable
    return value


def run_queue(root: Path | str, scenarios: list[str], run_row: Callable[[str, str], Mapping[str, Any] | None],
              reset: Callable[[], Mapping[str, Any] | None], *, prior: str | None = None) -> dict[str, Any]:
    """Run each scenario once, resetting only where decide says so. run_row(scenario, prior) and reset() return the
    row's rowEnd (or None when unreadable). Returns {"code": 0 or 3, "suspects": [...], "ran": [...]}."""
    suspects: list[str] = []
    ran: list[str] = []
    previous: str | None = None  # The last passed product row since the reset that prior names.

    def do_reset() -> str | None:
        ran.append(RESET)
        end = reset()
        return end["operation"] if end and end.get("rc") == 0 and isinstance(end.get("operation"), str) else None

    for scenario in scenarios:
        attempts = 0
        while True:
            if prior is None:
                prior, previous = do_reset(), None
                if prior is None:
                    return {"code": 3, "suspects": suspects, "ran": ran, "stop": RESET}
            attempts += 1
            ran.append(scenario)
            end = run_row(scenario, prior)
            decision = decide(end, attempts=attempts, previous=previous)
            if decision["suspect"] is not None and end:
                mark_suspect(root, decision["suspect"], detected_by=end["operation"], failure=end["failure"])
                suspects.append(decision["suspect"])
            if decision["step"] == STOP:
                return {"code": 3, "suspects": suspects, "ran": ran, "stop": scenario}
            if decision["step"] == NEXT:
                previous = end["operation"]
                break
            prior, previous = None, None
            if decision["step"] == RESET_NEXT:
                break
    return {"code": 0, "suspects": suspects, "ran": ran}
