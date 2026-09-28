"""Fixed, journaled dispatch and observation of same-source Linux RPM fixtures."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid
from typing import Mapping

from scripts.version_metadata import VERSION_PATTERN, parse_version


REPOSITORY = "Karapsin/vpn_control"
WORKFLOW = "linux-desktop.yml"
SHA = re.compile(r"[0-9a-f]{40}\Z")


def _run(argv):
    return subprocess.run(argv, text=True, capture_output=True, timeout=60, check=False)


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _correlation(value):
    try:
        _require(isinstance(value, str) and str(uuid.UUID(value)) == value,
                 "correlationId must be a canonical UUID")
    except (ValueError, AttributeError) as error:
        raise ValueError("correlationId must be a canonical UUID") from error


def _owned_directory(path, private=False):
    info = path.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
             not (info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)) and
             (not private or not (info.st_mode & (stat.S_IRWXG | stat.S_IRWXO))),
             "Unsafe fixture dispatch directory")


def _journal_path(root, correlation, create=False):
    root = Path(root).resolve(strict=True)
    runtime = root / ".runtime"
    _require(not runtime.is_symlink(), "Unsafe runtime directory")
    if create:
        runtime.mkdir(mode=0o700, exist_ok=True)
    if not runtime.exists():
        return None
    _owned_directory(runtime)
    directory = runtime / "linux-rpm-fixture-dispatch"
    _require(not directory.is_symlink(), "Unsafe fixture dispatch directory")
    if create:
        directory.mkdir(mode=0o700, exist_ok=True)
    if not directory.exists():
        return None
    _owned_directory(directory, private=True)
    return directory / (correlation + ".json")


def _read_journal(path):
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
             not (info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)),
             "Unsafe fixture dispatch journal")
    return json.loads(path.read_text(encoding="utf-8"))


def _unknown(correlation, reason):
    return {"state": "unknown", "correlationId": correlation, "reason": reason, "replayAllowed": False}


def dispatch(root, request: Mapping, runner=None):
    _require(isinstance(request, Mapping) and set(request) ==
             {"sourceSha", "baseVersion", "correlationId"}, "Invalid Linux fixture dispatch inputs")
    source, base, correlation = (request[key] for key in ("sourceSha", "baseVersion", "correlationId"))
    _require(isinstance(source, str) and SHA.fullmatch(source), "Invalid sourceSha")
    _correlation(correlation)
    _require(isinstance(base, str), "Invalid baseVersion")
    parse_version(base)
    runner = runner or _run
    try:
        tracked = runner(["git", "-C", str(Path(root).resolve(strict=True)), "show",
                          source + ":gradle.properties"])
    except Exception as error:
        raise ValueError("Tracked target version is unavailable") from error
    match = VERSION_PATTERN.search(tracked.stdout) if tracked.returncode == 0 else None
    _require(match is not None and parse_version(base) < parse_version(match.group(1)),
             "Fixture baseVersion must precede tracked target version")
    path = _journal_path(root, correlation, create=True)
    intent = {"schemaVersion": 1, "workflow": WORKFLOW, "repository": REPOSITORY,
              "sourceSha": source, "baseVersion": base, "targetVersion": match.group(1),
              "correlationId": correlation}
    if path.exists():
        _require(_read_journal(path) == intent,
                 "Correlation journal already binds another request")
        return _unknown(correlation, "existing-intent")
    try:
        remote = runner(["git", "ls-remote", "origin", "refs/heads/dev"])
    except Exception:
        return _unknown(correlation, "remote-source-unavailable")
    if remote.returncode != 0 or remote.stdout.split("\t", 1)[0].strip() != source:
        return _unknown(correlation, "remote-dev-sha-mismatch")
    encoded = (json.dumps(intent, sort_keys=True) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(descriptor, encoded[offset:])
            _require(written > 0, "Fixture dispatch journal write made no progress")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        result = runner(["gh", "workflow", "run", WORKFLOW, "--ref", "dev", "--repo", REPOSITORY,
                         "-f", "fixture_base_version=" + base, "-f", "correlation_id=" + correlation])
    except Exception:
        return _unknown(correlation, "dispatch-response-unavailable")
    if result.returncode != 0:
        return _unknown(correlation, "dispatch-result-uncertain")
    return {"state": "submitted", "correlationId": correlation, "sourceSha": source,
            "replayAllowed": False}


def status(root, request: Mapping, runner=None):
    _require(isinstance(request, Mapping) and set(request) == {"correlationId"},
             "Invalid Linux fixture status inputs")
    correlation = request["correlationId"]
    _correlation(correlation)
    path = _journal_path(root, correlation)
    if path is None or not path.exists():
        return _unknown(correlation, "missing-intent")
    intent = _read_journal(path)
    _require(intent.get("schemaVersion") == 1 and intent.get("correlationId") == correlation and
             intent.get("workflow") == WORKFLOW and intent.get("repository") == REPOSITORY and
             isinstance(intent.get("sourceSha"), str) and SHA.fullmatch(intent["sourceSha"]),
             "Invalid fixture dispatch journal")
    _require(isinstance(intent.get("baseVersion"), str), "Invalid fixture base version journal")
    _require(isinstance(intent.get("targetVersion"), str) and
             parse_version(intent["baseVersion"]) < parse_version(intent["targetVersion"]),
             "Invalid fixture version journal")
    runner = runner or _run
    try:
        response = runner(["gh", "run", "list", "--repo", REPOSITORY, "--workflow", WORKFLOW,
                           "--event", "workflow_dispatch", "--limit", "100", "--json",
                           "databaseId,headSha,displayTitle,status,conclusion,url"])
        if response.returncode != 0:
            return _unknown(correlation, "run-list-unavailable")
        runs = json.loads(response.stdout)
    except Exception:
        return _unknown(correlation, "run-list-unavailable")
    if not isinstance(runs, list):
        return _unknown(correlation, "invalid-run-list")
    title = "Linux RPM fixture " + correlation
    matches = [run for run in runs if isinstance(run, dict) and run.get("displayTitle") == title]
    if len(matches) != 1:
        return _unknown(correlation, "missing-or-duplicate-run")
    run = matches[0]
    run_id = run.get("databaseId")
    if run.get("headSha") != intent["sourceSha"] or type(run_id) is not int or run_id <= 0:
        return _unknown(correlation, "run-source-mismatch")
    common = {"correlationId": correlation, "sourceSha": intent["sourceSha"],
              "baseVersion": intent["baseVersion"], "targetVersion": intent["targetVersion"],
              "runId": run_id, "replayAllowed": False}
    if run.get("status") != "completed":
        return {"state": "pending", **common}
    if run.get("conclusion") != "success":
        return {"state": "failed", "conclusion": run.get("conclusion"), **common}
    try:
        response = runner(["gh", "api", f"repos/{REPOSITORY}/actions/runs/{run_id}/artifacts"])
        if response.returncode != 0:
            return _unknown(correlation, "artifact-list-unavailable")
        artifacts = json.loads(response.stdout).get("artifacts")
    except Exception:
        return _unknown(correlation, "artifact-list-unavailable")
    name = "vpn-control-linux-update-fixture-" + correlation
    if not isinstance(artifacts, list):
        return _unknown(correlation, "invalid-artifact-list")
    matches = [asset for asset in artifacts if isinstance(asset, dict) and asset.get("name") == name]
    if len(matches) != 1 or type(matches[0].get("id")) is not int or matches[0]["id"] <= 0 or matches[0].get("expired") is not False:
        return _unknown(correlation, "missing-or-duplicate-artifact")
    return {"state": "complete", "artifactId": matches[0]["id"],
            "artifactName": name, **common}
