"""Durable batches for the small set of already-approved native scenario actions.

This is not a shell scheduler.  Recipes expand to a fixed graph and invoke the
existing MCP workflow actions through an injected dispatcher.  A durable node
intent is written before an effectful scenario start; an unknown start is never
reissued by ``resume``.
"""
from __future__ import annotations

from contextlib import contextmanager
try:
    import fcntl
except ImportError:  # pragma: no cover - private journals require POSIX.
    fcntl = None  # type: ignore[assignment]
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid
from typing import Any, Callable, Mapping

try:
    from . import native_fixture_preflight
except ImportError:
    import native_fixture_preflight  # type: ignore[no-redef]

_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_ARTIFACT = re.compile(r"^sha256-([0-9a-f]{64})$")
_VERSION = 2
_RECIPE = "linux-public-update-preflight"
_WINDOWS_RECIPE = "windows-credential-validity-v1"
_SCHEDULED_RECIPE = "linux-scheduled-refresh"
Dispatch = Callable[[str, str, Mapping[str, Any]], Mapping[str, Any]]


class NativeScenarioBatchError(ValueError):
    pass


def _token(value: object, name: str) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise NativeScenarioBatchError(f"Batch {name} is invalid.")
    return value


def _plan(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or value.get("recipe") not in {_RECIPE, _WINDOWS_RECIPE, _SCHEDULED_RECIPE}:
        raise NativeScenarioBatchError("Batch recipe is not allowlisted.")
    if value["recipe"] == _RECIPE:
        required = {"batchId", "recipe", "host", "environment", "bundleManifestArtifactId", "scenarioCorrelationId"}
        optional: set[str] = set()
    elif value["recipe"] == _WINDOWS_RECIPE:
        required = {"batchId", "recipe", "host", "environment", "probeCorrelationId"}
        optional = set()
    else:
        required = {"batchId", "recipe", "host", "environment", "bundleManifestArtifactId",
                    "scenarioInputArtifactId", "scenarioCorrelationId"}
        optional = set()
    if not required <= set(value) or set(value) - required - optional:
        raise NativeScenarioBatchError("Batch plan has unsupported or missing fields.")
    strings = required - {"bundleManifestArtifactId", "scenarioInputArtifactId"}
    result = {key: _token(value[key], key) for key in strings}
    for field in ("bundleManifestArtifactId", "scenarioInputArtifactId"):
        if field in value:
            artifact = value[field]
            if not isinstance(artifact, str) or not _ARTIFACT.fullmatch(artifact):
                raise NativeScenarioBatchError(f"Batch {field} is invalid.")
            result[field] = artifact
    if result["recipe"] == _WINDOWS_RECIPE:
        try:
            if str(uuid.UUID(result["probeCorrelationId"])) != result["probeCorrelationId"]:
                raise ValueError()
        except ValueError as error:
            raise NativeScenarioBatchError("Windows probe correlationId must be a canonical UUID.") from error
    elif result["recipe"] == _SCHEDULED_RECIPE:
        try:
            if str(uuid.UUID(result["scenarioCorrelationId"])) != result["scenarioCorrelationId"]:
                raise ValueError()
            native_fixture_preflight._request({"scenarioId": _SCHEDULED_RECIPE,
                "host": result["host"], "environment": result["environment"],
                "bundleManifestArtifactId": result["bundleManifestArtifactId"],
                "scenarioInputArtifactId": result["scenarioInputArtifactId"],
                "scenarioCorrelationId": result["scenarioCorrelationId"]})
        except (ValueError, native_fixture_preflight.NativeFixturePreflightError) as error:
            raise NativeScenarioBatchError("Scheduled refresh plan inputs are invalid.") from error
    return dict(sorted(result.items()))


def _nodes(plan: Mapping[str, str]) -> dict[str, dict[str, Any]]:
    if plan["recipe"] == _SCHEDULED_RECIPE:
        digest = _ARTIFACT.fullmatch(plan["bundleManifestArtifactId"]).group(1)
        correlation = plan["scenarioCorrelationId"]
        preflight = {"scenarioId": _SCHEDULED_RECIPE, "host": plan["host"],
            "environment": plan["environment"], "bundleManifestArtifactId": plan["bundleManifestArtifactId"],
            "scenarioInputArtifactId": plan["scenarioInputArtifactId"],
            "scenarioCorrelationId": correlation}
        result = {
            "artifact": {"surface": "vm", "action": "artifact-verify", "inputs": {"artifactId": plan["bundleManifestArtifactId"]}, "after": [], "mode": "preflight"},
            "scenarioInput": {"surface": "vm", "action": "artifact-verify", "inputs": {"artifactId": plan["scenarioInputArtifactId"]}, "after": [], "mode": "preflight"},
            "fixture": {"surface": "fixture", "action": "check", "inputs": preflight, "after": [], "mode": "preflight"},
            "start": {"surface": "vm", "action": "scenario-start", "inputs": {"scenarioId": _SCHEDULED_RECIPE,
                "host": plan["host"], "environment": plan["environment"], "bundleHash": digest,
                "artifactIds": {"bundleManifest": plan["bundleManifestArtifactId"],
                                "scenarioInput": plan["scenarioInputArtifactId"]},
                "correlationId": correlation}, "after": ["artifact", "scenarioInput", "fixture"], "mode": "mutation"},
            "status": {"surface": "vm", "action": "scenario-status", "inputs": {"correlationId": correlation},
                       "after": ["start"], "mode": "observe"},
            "collect": {"surface": "vm", "action": "scenario-collect", "inputs": {"correlationId": correlation},
                        "scenarioId": _SCHEDULED_RECIPE,
                        "after": ["status"], "mode": "collect", "afterTerminal": True},
        }
        _ensure_acyclic(result)
        return result
    if plan["recipe"] == _WINDOWS_RECIPE:
        correlation = plan["probeCorrelationId"]
        inputs = {"host": plan["host"], "correlationId": correlation, "timeoutSeconds": 15}
        result = {
            "fixture": {"surface": "fixture", "action": "check", "inputs": {"scenarioId": _WINDOWS_RECIPE,
                "host": plan["host"], "environment": plan["environment"]}, "after": [], "mode": "preflight"},
            "start": {"surface": "vm", "action": "windows-credential-probe-start", "inputs": inputs,
                      "after": ["fixture"], "mode": "mutation"},
            "status": {"surface": "vm", "action": "windows-credential-probe-status", "inputs": inputs,
                       "after": ["start"], "mode": "observe"},
            "collect": {"surface": "vm", "action": "windows-credential-probe-status", "inputs": inputs,
                        "after": ["status"], "mode": "collect", "afterTerminal": True},
        }
        _ensure_acyclic(result)
        return result
    digest = _ARTIFACT.fullmatch(plan["bundleManifestArtifactId"]).group(1)  # validated by _plan
    correlation = plan["scenarioCorrelationId"]
    result = {
        "artifact": {"surface": "vm", "action": "artifact-verify", "inputs": {"artifactId": plan["bundleManifestArtifactId"]}, "after": [], "mode": "preflight"},
        "fixture": {"surface": "fixture", "action": "check", "inputs": {"scenarioId": "linux-public-update-preflight", "host": plan["host"], "environment": plan["environment"], "bundleManifestArtifactId": plan["bundleManifestArtifactId"]}, "after": [], "mode": "preflight"},
        "start": {"surface": "vm", "action": "scenario-start", "inputs": {"scenarioId": "linux-public-update-preflight", "host": plan["host"], "environment": plan["environment"], "bundleHash": digest, "artifactIds": {"bundleManifest": plan["bundleManifestArtifactId"]}, "correlationId": correlation}, "after": ["artifact", "fixture"], "mode": "mutation"},
        "status": {"surface": "vm", "action": "scenario-status", "inputs": {"correlationId": correlation}, "after": ["start"], "mode": "observe"},
        # Existing scenario collect is read-only and owns only its exact correlation.
        "collect": {"surface": "vm", "action": "scenario-collect", "inputs": {"correlationId": correlation}, "after": ["status"], "mode": "collect", "afterTerminal": True},
    }
    _ensure_acyclic(result)
    return result


def _ensure_acyclic(nodes: Mapping[str, Mapping[str, Any]]) -> None:
    seen: set[str] = set(); visiting: set[str] = set()
    def visit(name: str) -> None:
        if name in visiting: raise NativeScenarioBatchError("Batch dependency graph contains a cycle.")
        if name in seen: return
        if name not in nodes: raise NativeScenarioBatchError("Batch dependency graph is invalid.")
        visiting.add(name)
        for item in nodes[name].get("after", []): visit(item)
        visiting.remove(name); seen.add(name)
    for name in nodes: visit(name)


class NativeScenarioBatch:
    def __init__(self, journal_directory: Path | str, dispatcher: Dispatch, *, repository_root: Path | str | None = None,
                 preflight: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None):
        self.directory = Path(journal_directory); self.dispatcher = dispatcher
        self.preflight = preflight or (lambda request: native_fixture_preflight.check(
            Path(repository_root) if repository_root is not None else self.directory.parent.parent, request, dispatcher))

    def plan(self, request: Mapping[str, Any]) -> dict[str, Any]:
        plan = _plan(request)
        with self._lock():
            current = self._read(plan["batchId"])
            if current is not None:
                if current["plan"] != plan: raise NativeScenarioBatchError("Batch ID belongs to a different immutable plan.")
                return self._public(current, duplicate=True)
            record = {"version": _VERSION, "plan": plan, "nodes": {name: {"state": "pending", "outcome": None, "evidence": {}} for name in _nodes(plan)}}
            self._create(record); return self._public(record)

    def start(self, batch_id: str) -> dict[str, Any]:
        return self._advance(_token(batch_id, "batchId"), allow_mutation=True)

    def status(self, batch_id: str) -> dict[str, Any]:
        return self._advance(_token(batch_id, "batchId"), allow_mutation=False)

    def resume(self, batch_id: str) -> dict[str, Any]:
        # A new observer may collect status, but can never convert an unknown
        # mutation back to pending or submit it again.
        return self.status(batch_id)

    def collect(self, batch_id: str) -> dict[str, Any]:
        result = self.status(batch_id)
        result["collection"] = result["nodes"]["collect"]["evidence"]
        return result

    def _advance(self, batch_id: str, *, allow_mutation: bool) -> dict[str, Any]:
        # Invoke one ready node at a time outside the file lock.  Re-read before
        # committing so an older observation cannot overwrite a later terminal fact.
        attempted: set[str] = set()
        while True:
            with self._lock():
                record = self._require(batch_id); name = self._ready(record, allow_mutation, attempted)
                if name is None:
                    self._block(record); self._write(record); return self._public(record)
                node = _nodes(record["plan"])[name]
                attempted.add(name)
                if node["mode"] == "mutation":
                    # No cached readiness survives until a later mutation. A
                    # new live observation is required immediately beforehand.
                    try:
                        fresh = self._invoke(_nodes(record["plan"])["fixture"])
                    except Exception:
                        fresh = None
                    fresh_result = self._outcome(_nodes(record["plan"])["fixture"], fresh)
                    record["nodes"]["fixture"] = fresh_result
                    if fresh_result["state"] != "success":
                        record["nodes"][name] = {"state": "blocked", "outcome": "fresh_preflight_not_ready", "evidence": {}}
                        self._write(record)
                        continue
                    record["nodes"][name]["state"] = "submitting"; self._write(record)
            try:
                response = self._invoke(node)
                if not isinstance(response, Mapping): raise ValueError()
            except Exception:
                response = None
            with self._lock():
                current = self._require(batch_id)
                state = current["nodes"][name]["state"]
                if state not in {"pending", "submitting", "waiting"}: continue
                current["nodes"][name] = self._outcome(node, response)
                self._write(current)

    def _invoke(self, node: Mapping[str, Any]) -> Mapping[str, Any]:
        if node["surface"] == "fixture":
            return self.preflight(dict(node["inputs"]))
        return self.dispatcher(node["surface"], node["action"], dict(node["inputs"]))

    @staticmethod
    def _outcome(node: Mapping[str, Any], value: Mapping[str, Any] | None) -> dict[str, Any]:
        if value is None: return {"state": "unknown" if node["mode"] == "mutation" else "waiting", "outcome": "observer_unavailable", "evidence": {}}
        state = value.get("state")
        evidence = {key: value[key] for key in ("state", "exitCode", "correlationId", "success", "errorCategory")
                    if key in value and isinstance(value[key], (str, int))}
        if isinstance(value.get("reason"), str):
            evidence["reason"] = value["reason"][:128]
        paths = value.get("evidencePaths")
        if isinstance(paths, list):
            evidence["evidencePaths"] = [path for path in paths[:8] if isinstance(path, str)
                                         and path.startswith("/") and len(path) <= 512]
        expected = node["inputs"].get("correlationId")
        if expected is not None and value.get("correlationId") != expected:
            return {"state": "unknown" if node["mode"] == "mutation" else "failed",
                    "outcome": "correlation_mismatch", "evidence": {}}
        if node["action"] == "scenario-collect" and node["inputs"].get("correlationId"):
            summary = value.get("scenarioEvidence")
            if node.get("scenarioId") == _SCHEDULED_RECIPE:
                # The fixed remote collector returns a bounded typed summary,
                # not arbitrary runner JSON or guest paths.
                if not isinstance(summary, Mapping) or summary.get("correlationId") != expected:
                    return {"state": "waiting", "outcome": "observer_unknown", "evidence": evidence}
                cleanup = summary.get("cleanup")
                if not isinstance(cleanup, Mapping):
                    return {"state": "waiting", "outcome": "observer_unknown", "evidence": evidence}
                evidence["scenarioEvidence"] = {
                    "correlationId": expected,
                    "result": summary.get("result") if summary.get("result") in {"passed", "failed"} else "unknown",
                    "mode": summary.get("mode") if summary.get("mode") in {"refresh-only", "refresh-find-best"} else None,
                    "exitCode": summary.get("exitCode") if type(summary.get("exitCode")) is int else None,
                    "preflightReady": summary.get("preflightReady") if type(summary.get("preflightReady")) is bool else None,
                    "cleanup": {"state": cleanup.get("state") if cleanup.get("state") in {"complete", "incomplete", "preserved-for-recovery", "not-started"} else "unknown",
                                **{key: cleanup.get(key) if type(cleanup.get(key)) is bool else None
                                   for key in ("ownerStopped", "protectedPreserved", "workspaceRemoved")}},
                }
                for key in ("scheduledOperationId", "scheduledCode"):
                    item = summary.get(key)
                    if isinstance(item, str) and len(item) <= 128 and all(char.isalnum() or char in "_.:-" for char in item):
                        evidence["scenarioEvidence"][key] = item
                measured = summary.get("secondaryTotalMs")
                if type(measured) in (int, float) and 0 <= measured <= 3600000:
                    evidence["scenarioEvidence"]["secondaryTotalMs"] = measured
                traffic = summary.get("traffic")
                if isinstance(traffic, Mapping):
                    evidence["scenarioEvidence"]["traffic"] = {key: traffic.get(key) if type(traffic.get(key)) is bool else None
                        for key in ("oldPortContinuity", "portMigrated", "postTransitionTraffic")}
        if node["action"] == "artifact-verify":
            ok = value.get("verification") == "verified"
        elif node["surface"] == "fixture":
            if value.get("ready") is not True:
                states = [item.get("state") for item in value.get("requirements", {}).values() if isinstance(item, Mapping)]
                return {"state": "failed" if "failed" in states else "waiting", "outcome": "preflight_not_ready", "evidence": {}}
            ok = True
        elif node["action"] == "windows-credential-probe-start":
            if state in {"unknown", "intent"}:
                return {"state": "unknown", "outcome": "submit_unknown", "evidence": evidence}
            ok = state == "submitted" or (state == "terminal" and value.get("success") is True)
        elif node["action"] == "windows-credential-probe-status" and node["mode"] == "observe":
            if state in {"submitted", "unknown", "intent"}:
                return {"state": "waiting", "outcome": "observer_unknown", "evidence": evidence}
            ok = state == "terminal" and value.get("success") is True
        elif node["action"] == "scenario-start":
            if state in {"unknown", "submitting"}: return {"state": "unknown", "outcome": "submit_unknown", "evidence": evidence}
            ok = state == "submitted" or (state == "terminal" and value.get("exitCode") == 0)
        elif node["action"] == "scenario-status":
            if state == "submitted": return {"state": "waiting", "outcome": "running", "evidence": evidence}
            if state == "unknown": return {"state": "waiting", "outcome": "observer_unknown", "evidence": evidence}
            ok = state == "terminal" and value.get("exitCode") == 0
        else:  # A bounded, correlation-scoped terminal observer.
            ok = state == "terminal"
        return {"state": "success" if ok else "failed", "outcome": "accepted" if ok else "rejected", "evidence": evidence}

    def _ready(self, record: Mapping[str, Any], allow_mutation: bool, attempted: set[str]) -> str | None:
        graph = _nodes(record["plan"])
        for name, node in graph.items():
            status = record["nodes"][name]["state"]
            if status not in {"pending", "waiting"} or name in attempted: continue
            if node["mode"] == "mutation" and not allow_mutation: continue
            predecessors = [record["nodes"][item]["state"] for item in node["after"]]
            allowed = ({"success", "failed", "unknown", "submitting"} if name == "status" else
                       {"success", "failed", "unknown"} if node.get("afterTerminal") else {"success"})
            if all(value in allowed for value in predecessors): return name
        return None

    def _block(self, record: dict[str, Any]) -> None:
        graph = _nodes(record["plan"])
        for name, node in graph.items():
            if record["nodes"][name]["state"] != "pending": continue
            predecessor = [record["nodes"][item]["state"] for item in node["after"]]
            allowed = ({"success", "failed", "unknown", "submitting"} if name == "status" else
                       {"success", "failed", "unknown"} if node.get("afterTerminal") else {"success"})
            if any(value in {"failed", "unknown", "blocked"} and value not in allowed for value in predecessor):
                record["nodes"][name] = {"state": "blocked", "outcome": "dependency_not_admitted", "evidence": {}}

    def _path(self, batch_id: str) -> Path: return self.directory / (batch_id + ".json")
    def _ensure(self) -> None:
        if os.name != "posix" or fcntl is None: raise NativeScenarioBatchError("Durable batch execution requires POSIX private journal support.")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(self.directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077: raise NativeScenarioBatchError("Batch journal is unsafe.")
    @contextmanager
    def _lock(self):
        self._ensure(); fd = os.open(self.directory / ".batch.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try: fcntl.flock(fd, fcntl.LOCK_EX); yield
        finally: os.close(fd)
    def _read(self, batch_id: str) -> dict[str, Any] | None:
        try:
            path = self._path(batch_id); info = os.lstat(path)
            if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077: raise ValueError
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError: return None
        except (OSError, ValueError, json.JSONDecodeError) as error: raise NativeScenarioBatchError("Batch journal is unreadable.") from error
        self._validate(value, batch_id); return value
    def _require(self, batch_id: str) -> dict[str, Any]:
        value = self._read(batch_id)
        if value is None: raise NativeScenarioBatchError("Batch plan does not exist.")
        return value
    def _validate(self, value: Any, batch_id: str) -> None:
        if not isinstance(value, dict) or set(value) != {"version", "plan", "nodes"} or value.get("version") != _VERSION: raise NativeScenarioBatchError("Batch journal is invalid.")
        plan = _plan(value["plan"])
        if plan["batchId"] != batch_id or not isinstance(value["nodes"], dict) or set(value["nodes"]) != set(_nodes(plan)): raise NativeScenarioBatchError("Batch journal is invalid.")
        for node in value["nodes"].values():
            if not isinstance(node, dict) or set(node) != {"state", "outcome", "evidence"} or not isinstance(node["evidence"], dict) or node["state"] not in {"pending", "submitting", "waiting", "success", "failed", "unknown", "blocked"} or node["outcome"] is not None and node["outcome"] not in {"observer_unavailable", "submit_unknown", "observer_unknown", "accepted", "rejected", "running", "dependency_not_admitted", "preflight_not_ready", "fresh_preflight_not_ready", "correlation_mismatch"}: raise NativeScenarioBatchError("Batch node is invalid.")
    def _write(self, record: Mapping[str, Any]) -> None:
        self._validate(record, record["plan"]["batchId"]); self._ensure(); fd, temporary = tempfile.mkstemp(prefix=".batch-", dir=self.directory)
        try:
            os.fchmod(fd, 0o600); os.write(fd, (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()); os.fsync(fd); os.close(fd); fd = -1; os.replace(temporary, self._path(record["plan"]["batchId"]))
            directory_fd = os.open(self.directory, os.O_RDONLY); os.fsync(directory_fd); os.close(directory_fd)
        finally:
            if fd >= 0: os.close(fd)
            try: os.unlink(temporary)
            except FileNotFoundError: pass
    def _create(self, record: Mapping[str, Any]) -> None:
        self._validate(record, record["plan"]["batchId"]); self._ensure()
        try: fd = os.open(self._path(record["plan"]["batchId"]), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError: raise NativeScenarioBatchError("Batch plan already exists.")
        with os.fdopen(fd, "wb") as f: f.write((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()); f.flush(); os.fsync(f.fileno())
        directory_fd = os.open(self.directory, os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    @staticmethod
    def _public(record: Mapping[str, Any], duplicate: bool = False) -> dict[str, Any]:
        result = {"batchId": record["plan"]["batchId"], "recipe": record["plan"]["recipe"], "nodes": {name: dict(value) for name, value in record["nodes"].items()}}
        states = {name: node["state"] for name, node in record["nodes"].items()}
        if any(state == "failed" for state in states.values()):
            result["state"] = "failed"
        elif any(state == "blocked" for state in states.values()):
            result["state"] = "blocked"
        elif any(state == "unknown" for state in states.values()):
            result["state"] = "unknown"
        elif all(state == "success" for state in states.values()):
            result["state"] = "success"
        elif all(state == "pending" for state in states.values()):
            result["state"] = "pending"
        else:
            result["state"] = "running"
        if record["plan"]["recipe"] == _SCHEDULED_RECIPE:
            collected = record["nodes"]["collect"].get("evidence", {}).get("scenarioEvidence")
            result["cleanup"] = (dict(collected["cleanup"]) if isinstance(collected, Mapping)
                and isinstance(collected.get("cleanup"), Mapping) else
                {"state": "unknown", "reason": "correlated_scenario_receipt_unavailable"})
        else:
            result["cleanup"] = {"state": "not_applicable", "reason": "recipe_has_no_owned_cleanup_adapter"}
        if duplicate: result["duplicate"] = True
        return result
