"""Fixed, journaled dispatch and observation of same-source Windows MSI fixtures."""

from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import resource
import stat
import subprocess
import tempfile
import uuid
from typing import Mapping
import zipfile

from scripts.version_metadata import VERSION_PATTERN, parse_version


REPOSITORY = "Karapsin/vpn_control"
WORKFLOW = "windows-desktop.yml"
SHA = re.compile(r"[0-9a-f]{40}\Z")
CALLER = ".github/workflows/windows-desktop.yml"
REUSABLE = ".github/workflows/windows-update-fixture.yml"
_MAX_COMPRESSED_BYTES = 2 * 1024 ** 3
_MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024
_MAX_PLAN_BYTES = 1024 * 1024
_MAX_FAILED_LOG_BYTES = 8 * 1024 * 1024
_MAX_FAILED_EXCERPT_CHARS = 32 * 1024


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
    directory = runtime / "windows-msi-fixture-dispatch"
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


def _source_workflow_contract(root, source, runner):
    """Require correlation wiring in the exact source being dispatched."""
    contents = []
    for path in (CALLER, REUSABLE):
        try:
            result = runner(["git", "-C", str(Path(root).resolve(strict=True)), "show", source + ":" + path])
        except Exception as error:
            raise ValueError("Tracked Windows fixture workflow is unavailable") from error
        _require(result.returncode == 0 and isinstance(result.stdout, str),
                 "Tracked Windows fixture workflow is unavailable")
        contents.append(result.stdout)
    caller, reusable = contents
    _require(all(text in caller for text in (
        "correlation_id:", "correlation_id: ${{ inputs.correlation_id }}",
        "format('Windows MSI fixture {0}', inputs.correlation_id)",
        'str(uuid.UUID(value)) == value',
        "github.ref == 'refs/heads/dev'", "uses: ./.github/workflows/windows-update-fixture.yml")),
        "Exact-source Windows caller does not bind fixture correlation")
    _require(all(text in reusable for text in (
        "correlation_id:", "format('vpn-control-windows-update-fixture-{0}', inputs.correlation_id)",
        "[Guid]::TryParseExact", "fixture-receipt.json", "packages/base/**", "packages/target/**")),
        "Exact-source Windows artifact does not bind fixture correlation")


def dispatch(root, request: Mapping, runner=None):
    _require(isinstance(request, Mapping) and set(request) ==
             {"sourceSha", "baseVersion", "correlationId"}, "Invalid Windows fixture dispatch inputs")
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
    _source_workflow_contract(root, source, runner)
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
             "Invalid Windows fixture status inputs")
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
    title = "Windows MSI fixture " + correlation
    matches = []
    for _ in range(2):
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
        matches = [run for run in runs if isinstance(run, dict) and run.get("displayTitle") == title]
        if matches:
            break
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
    name = "vpn-control-windows-update-fixture-" + correlation
    if not isinstance(artifacts, list):
        return _unknown(correlation, "invalid-artifact-list")
    matches = [asset for asset in artifacts if isinstance(asset, dict) and asset.get("name") == name]
    if len(matches) != 1 or type(matches[0].get("id")) is not int or matches[0]["id"] <= 0 or matches[0].get("expired") is not False:
        return _unknown(correlation, "missing-or-duplicate-artifact")
    return {"state": "complete", "artifactId": matches[0]["id"],
            "artifactName": name, **common}


def _read_failed_log(run_id):
    """Capture a fixed gh command with a child-enforced file-size bound."""
    command = ["gh", "run", "view", str(run_id), "--repo", REPOSITORY, "--log-failed"]
    try:
        with tempfile.TemporaryFile() as stream:
            def limit_output():
                hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
                limit = _MAX_FAILED_LOG_BYTES if hard == resource.RLIM_INFINITY else min(_MAX_FAILED_LOG_BYTES, hard)
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard))
            result = subprocess.run(command, stdout=stream, stderr=subprocess.DEVNULL,
                                    timeout=90, check=False, preexec_fn=limit_output)
            size = os.fstat(stream.fileno()).st_size
            if result.returncode != 0 or not 0 < size < _MAX_FAILED_LOG_BYTES:
                return None
            stream.seek(0)
            return stream.read(_MAX_FAILED_LOG_BYTES)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def _failed_excerpt(raw):
    text = raw.decode("utf-8", errors="replace")
    text = re.sub(r"-----BEGIN [^-\n]*PRIVATE KEY-----.*?-----END [^-\n]*PRIVATE KEY-----",
                  "[REDACTED PRIVATE KEY]", text, flags=re.DOTALL)
    text = re.sub(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "[REDACTED]", text)
    text = re.sub(r"(?im)(authorization\s*:\s*)[^\r\n]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\b((?:password|token|secret|api[_-]?key)\s*[:=]\s*)[^\s,;]+",
                  r"\1[REDACTED]", text)
    text = re.sub(r"(?i)https?://[^\s<>\"']+", "[REDACTED URL]", text)
    text = re.sub(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+", r"C:\\Users\\[REDACTED]", text)
    text = re.sub(r"/(?:Users|home)/[^/\s]+", "/[REDACTED USER]", text)
    lines = text.splitlines()
    marker = re.compile(r"(?i)(FAIL:|ERROR:|Traceback|AssertionError|exit 1|Process completed with exit code|Exception:)")
    selected = set()
    for index, line in enumerate(lines):
        if marker.search(line):
            selected.update(range(max(0, index - 2), min(len(lines), index + 4)))
    excerpt = "\n".join(lines[index] for index in sorted(selected)) if selected else "\n".join(lines[-200:])
    return excerpt[-_MAX_FAILED_EXCERPT_CHARS:]


def failed_log(root, request: Mapping, runner=None, log_reader=None):
    """Read a bounded failed log only for one journal-bound terminal failed run."""
    _require(isinstance(request, Mapping) and set(request) == {"correlationId"},
             "Invalid Windows fixture failed-log inputs")
    correlation = request["correlationId"]
    _correlation(correlation)
    observed = status(root, {"correlationId": correlation}, runner=runner)
    if observed["state"] != "failed" or observed.get("conclusion") != "failure":
        return _unknown(correlation, "exact-terminal-failure-unavailable")
    reader = log_reader or _read_failed_log
    raw = reader(observed["runId"])
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_FAILED_LOG_BYTES:
        return _unknown(correlation, "failed-log-unavailable")
    return {"state": "failed-log", "correlationId": correlation, "sourceSha": observed["sourceSha"],
            "runId": observed["runId"], "conclusion": "failure", "logSha256": hashlib.sha256(raw).hexdigest(),
            "capturedBytes": len(raw), "excerpt": _failed_excerpt(raw), "replayAllowed": False}


def _download_zip(artifact_id, output):
    command = ["gh", "api", "-H", "Accept: application/vnd.github+json",
               f"repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"]
    try:
        with output.open("xb") as stream:
            # The child cannot write more than this limit, including before
            # the parent regains control. Do not buffer the archive in memory.
            def limit_output():
                hard = resource.getrlimit(resource.RLIMIT_FSIZE)[1]
                limit = _MAX_COMPRESSED_BYTES if hard == resource.RLIM_INFINITY else min(_MAX_COMPRESSED_BYTES, hard)
                resource.setrlimit(resource.RLIMIT_FSIZE, (limit, hard))
            result = subprocess.run(command, stdout=stream, stderr=subprocess.DEVNULL,
                                    timeout=900, check=False, preexec_fn=limit_output)
            stream.flush(); os.fsync(stream.fileno())
            bounded = os.fstat(stream.fileno()).st_size <= _MAX_COMPRESSED_BYTES
        return result.returncode == 0 and bounded
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def _extract_zip(archive, destination):
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        _require(0 < len(members) <= 20000, "Windows fixture archive count is unsafe")
        _require(sum(item.file_size for item in members) <= 4 * 1024 ** 3,
                 "Windows fixture archive size is unsafe")
        names = set()
        for item in members:
            name = item.filename
            path = PurePosixPath(name)
            _require(name not in names and name and not name.startswith("/") and "\\" not in name and
                     ":" not in name and all(part not in ("", ".", "..") for part in path.parts) and
                     not stat.S_ISLNK(item.external_attr >> 16), "Windows fixture archive path is unsafe")
            names.add(name)
            target = destination.joinpath(*path.parts)
            if item.is_dir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                continue
            _require(item.file_size <= 1024 ** 3, "Windows fixture archive member is too large")
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with package.open(item) as source, target.open("xb") as output:
                remaining = item.file_size
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    _require(bool(chunk), "Windows fixture archive member ended early")
                    output.write(chunk); remaining -= len(chunk)
                _require(not source.read(1), "Windows fixture archive member length changed")
                output.flush(); os.fsync(output.fileno())


def _digest(path):
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), "Windows fixture file is unsafe")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return info.st_size, digest.hexdigest()


def _bounded_json(path, limit):
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and 0 < info.st_size <= limit,
             "Windows fixture provenance JSON size is unsafe")
    return json.loads(path.read_bytes())


def _verify_extracted(directory, run):
    receipt_path = directory / "fixture-receipt.json"
    try:
        receipt = _bounded_json(receipt_path, _MAX_RECEIPT_BYTES)
        snapshot = _bounded_json(directory / "snapshot.json", _MAX_SNAPSHOT_BYTES)
        plan = _bounded_json(directory / "build-plan.json", _MAX_PLAN_BYTES)
        base, target = receipt["builds"]
        _require(receipt["schemaVersion"] == 1 and receipt["testOnly"] is True and
                 receipt["productionTrustChanged"] is False and receipt["architecture"] == "x86_64" and
                 str(receipt["nativeOs"]).startswith("Windows-"), "Windows fixture receipt is invalid")
        _require(base["label"] == "base" and target["label"] == "target" and
                 base["version"] == run["baseVersion"] and target["version"] == run["targetVersion"] and
                 base["codeFingerprint"] == target["codeFingerprint"] and
                 isinstance(base["codeFingerprint"], str) and re.fullmatch(r"[0-9a-f]{64}", base["codeFingerprint"]) and
                 isinstance(receipt["sourceFingerprint"], str) and re.fullmatch(r"[0-9a-f]{64}", receipt["sourceFingerprint"]) and
                 base["sourceFingerprint"] == target["sourceFingerprint"] == receipt["sourceFingerprint"],
                 "Windows fixture version/source binding changed")
        fingerprint = hashlib.sha256(json.dumps(snapshot["files"], sort_keys=True,
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        _require(snapshot["schemaVersion"] == 1 and snapshot["sourceHead"] == run["sourceSha"] and
                 snapshot["canonicalVersion"] == run["targetVersion"] and
                 snapshot["sourceFingerprint"] == plan["sourceFingerprint"] ==
                 receipt["sourceFingerprint"] == fingerprint and
                 plan["schemaVersion"] == 1 and plan["testOnly"] is True and
                 plan["productionTrustChanged"] is False and plan["platform"] == "windows" and
                 plan["architecture"] == "x86_64" and plan["packageFamily"] == "default" and
                 [(stage["label"], stage["version"]) for stage in plan["stages"]] ==
                 [("base", run["baseVersion"]), ("target", run["targetVersion"])],
                 "Windows fixture snapshot/plan source binding changed")
        assets = []
        for label, build in (("base", base), ("target", target)):
            msi = [asset for asset in build["assets"] if asset["fileName"].endswith(".msi")]
            _require(len(msi) == 1, "Windows fixture MSI count changed")
            asset = msi[0]
            path = directory / "packages" / label / ("vpn-control-" + build["version"] + ".msi")
            size, digest = _digest(path)
            _require(asset["fileName"] == path.name and asset["platform"] == "windows" and
                     asset["architecture"] == "x86_64" and asset["displayVersion"] == build["version"] and
                     asset["sizeBytes"] == size and asset["sha256"] == digest,
                     "Windows fixture MSI bytes differ from receipt")
            assets.append({"label": label, "path": str(path), "size": size, "sha256": digest,
                           "artifactId": "sha256-" + digest})
        receipt_size, receipt_hash = _digest(receipt_path)
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, json.JSONDecodeError) as error:
        raise ValueError("Windows fixture extraction is not verified") from error
    return {"sourceSha": run["sourceSha"], "sourceFingerprint": receipt["sourceFingerprint"],
            "receipt": {"path": str(receipt_path), "size": receipt_size, "sha256": receipt_hash,
                        "artifactId": "sha256-" + receipt_hash}, "packages": assets}


def collect(root, request: Mapping, runner=None, downloader=None):
    """Download one exact hosted artifact to a private ignored directory once."""
    _require(isinstance(request, Mapping) and set(request) == {"correlationId"},
             "Invalid Windows fixture collect inputs")
    correlation = request["correlationId"]
    _correlation(correlation)
    observed = status(root, {"correlationId": correlation}, runner=runner)
    if observed["state"] != "complete":
        return _unknown(correlation, "hosted-artifact-not-complete")
    root = Path(root).resolve(strict=True)
    runtime = root / ".runtime"
    _require(not runtime.is_symlink(), "Windows fixture runtime directory is unsafe")
    parent = runtime / "windows-msi-fixture-collect"
    _require(not parent.is_symlink(), "Windows fixture collection directory is unsafe")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _owned_directory(parent, private=True)
    stage = parent / correlation
    if stage.exists() or stage.is_symlink():
        return _unknown(correlation, "existing-collection")
    stage.mkdir(mode=0o700)
    parent_fd = os.open(parent, os.O_RDONLY)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    intent = {key: observed[key] for key in ("correlationId", "sourceSha", "baseVersion", "targetVersion",
                                               "runId", "artifactId", "artifactName")}
    path = stage / "intent.json"
    with path.open("xb") as output:
        output.write((json.dumps(intent, sort_keys=True, separators=(",", ":")) + "\n").encode())
        output.flush(); os.fsync(output.fileno())
    directory = os.open(stage, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)
    archive = stage / "artifact.zip"
    download = downloader or _download_zip
    if not download(observed["artifactId"], archive):
        return _unknown(correlation, "artifact-download-uncertain")
    extracted = stage / "extracted"
    extracted.mkdir(mode=0o700)
    try:
        _extract_zip(archive, extracted)
        verified = _verify_extracted(extracted, observed)
    except (OSError, ValueError, zipfile.BadZipFile):
        return _unknown(correlation, "artifact-bytes-unverified")
    return {"state": "collected", "correlationId": correlation, "runId": observed["runId"],
            "hostedArtifactId": observed["artifactId"], "sourceSha": observed["sourceSha"],
            "directory": str(extracted), "replayAllowed": False, **verified}
