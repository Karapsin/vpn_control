#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence


docs_assistant = importlib.import_module(
    f"{__package__}.docs_assistant" if __package__ else "docs_assistant"
)

try:  # The repository tests intentionally run without the optional MCP package.
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - covered by launcher/integration smoke checks.
    FastMCP = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX_DIR = REPO_ROOT / docs_assistant.DEFAULT_INDEX_DIR
AGENT_TEST_PYTHON = next(
    (
        str(candidate)
        for candidate in (
            REPO_ROOT / ".agent_venv" / "bin" / "python",
            REPO_ROOT / ".agent_venv" / "Scripts" / "python.exe",
        )
        if candidate.is_file()
    ),
    sys.executable,
)
RECEIPT_PATH = INDEX_DIR / "prepush_receipt.json"
WATCH_STATE_PATH = INDEX_DIR / "github_watch.json"
REQUIRED_WORKFLOWS_PATH = REPO_ROOT / ".github" / "required-workflows.json"
MAX_OUTPUT_CHARS = 5000
DISCOVERY_TIMEOUT_SECONDS = 5 * 60
WATCH_TIMEOUT_SECONDS = 55 * 60
POLL_SECONDS = 15

SERVER_INSTRUCTIONS = (
    "MANDATORY: call prepare_start before normal repository inspection, edits, or tests. "
    "Use docs and change_impact before broad searches. Never stop the VPN/runtime without "
    "explicit user approval. Preserve unrelated dirty changes. Before finishing, use "
    "run_checks(level='prepush'), then git_workflow for push and exact-SHA CI verification. "
    "The server is fixed to the VPN Control repository root. "
    "Public documentation is in README.md and docs/; coding-agent documentation is in "
    "AGENTS.md, agent_docs/, and agent_tools/README.md."
)

AREA_DOCS: dict[str, list[str]] = {
    "android": [
        "agent_docs/architecture.md",
        "agent_docs/state-ownership.md",
        "agent_docs/smoke-android.md",
    ],
    "desktop": [
        "agent_docs/architecture.md",
        "agent_docs/state-ownership.md",
        "agent_docs/desktop-lifecycle.md",
    ],
    "localization": [
        "agent_docs/localization.md",
        "agent_docs/test-matrix.md",
    ],
    "runtime": [
        "agent_docs/runtime-troubleshooting.md",
        "agent_docs/sing-box-contract.md",
    ],
    "release": [
        "agent_docs/developer-release-checklist.md",
        "agent_docs/native-runtime-artifacts.md",
    ],
    "docs": ["docs/README.md", "agent_docs/development.md"],
    "agent_tools": ["agent_tools/README.md", "agent_docs/development.md"],
    "ssh": ["docs/ssh-routing.md"],
}

FOCUSED_COMMANDS: dict[str, list[list[str]]] = {
    "android": [
        ["./gradlew", ":app:testDebugUnitTest", ":app:compileDebugKotlin"],
    ],
    "desktop": [["./gradlew", ":desktopApp:test"]],
    "localization": [
        ["./scripts/check_localization.py"],
        ["./scripts/status_catalog_tool.py", "check"],
        ["./gradlew", ":shared:ui:desktopTest", ":app:compileDebugKotlin"],
    ],
    "runtime": [["./gradlew", ":shared:core:desktopTest", ":desktopApp:test"]],
    "release": [
        ["./scripts/check_release_hygiene.sh"],
        ["./gradlew", ":app:assembleRelease"],
    ],
    "docs": [["git", "diff", "--check"], ["./scripts/check_docs_hygiene.sh"]],
    "agent_tools": [
        [AGENT_TEST_PYTHON, "-m", "unittest", "discover", "-s", "agent_tools/tests"],
        ["./scripts/check_docs_hygiene.sh"],
    ],
}

PREPUSH_COMMANDS = [
    ["git", "diff", "--check"],
    ["./scripts/check_release_hygiene.sh"],
    ["./scripts/check_docs_hygiene.sh"],
    [AGENT_TEST_PYTHON, "-m", "unittest", "discover", "-s", "agent_tools/tests"],
    ["./scripts/check_localization.py"],
    ["./scripts/status_catalog_tool.py", "check"],
    [
        "./gradlew",
        ":shared:model:desktopTest",
        ":shared:core:desktopTest",
        ":shared:ui:desktopTest",
        ":desktopApp:test",
        ":app:testDebugUnitTest",
        ":app:compileDebugKotlin",
    ],
]

SENSITIVE_PARTS = {
    ".agent_venv",
    ".rag_index",
    ".runtime",
    "build",
    "dist",
    "runtime-bin",
    "sing-box",
}
GLOB_CHARS = set("*?[]{}")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def prepare_start(task: str, area: str | None = None) -> dict[str, Any]:
    """Synchronize safely, build the docs index, and route the task."""
    if not task.strip():
        return _error("prepare_start", "task is required")
    commands: list[dict[str, Any]] = []
    initial = _repo_state()
    fetch = _run(["git", "fetch", "origin", "main"], timeout=180)
    commands.append(fetch)
    if not fetch["ok"]:
        return _error(
            "prepare_start",
            "Could not fetch origin/main; repository freshness is unknown.",
            blockers=[_command_blocker("fetch", fetch)],
            command_results=commands,
        )

    state = _repo_state()
    if state.get("branch") != "main":
        if state.get("dirty"):
            return _error(
                "prepare_start",
                "The worktree is dirty on a non-main branch; automatic switching is unsafe.",
                blockers=[{"phase": "branch", "state": state}],
                command_results=commands,
            )
        switched = _run(["git", "switch", "main"])
        commands.append(switched)
        if not switched["ok"]:
            return _error(
                "prepare_start",
                "Could not switch the clean worktree to main.",
                blockers=[_command_blocker("branch", switched)],
                command_results=commands,
            )
        state = _repo_state()

    ahead, behind, relation_error = _ahead_behind()
    if relation_error:
        return _error(
            "prepare_start",
            "Could not compare HEAD with origin/main.",
            blockers=[relation_error],
            command_results=commands,
        )
    if ahead and behind:
        return _error(
            "prepare_start",
            "main and origin/main have diverged; resolve explicitly before editing.",
            blockers=[{"phase": "sync", "ahead": ahead, "behind": behind}],
            command_results=commands,
        )
    if behind:
        if state.get("dirty"):
            return _error(
                "prepare_start",
                "main is behind origin/main and the worktree is dirty; automatic pull is unsafe.",
                blockers=[{"phase": "sync", "ahead": ahead, "behind": behind}],
                command_results=commands,
            )
        pulled = _run(["git", "pull", "--ff-only", "origin", "main"], timeout=180)
        commands.append(pulled)
        if not pulled["ok"]:
            return _error(
                "prepare_start",
                "Fast-forward pull failed.",
                blockers=[_command_blocker("pull", pulled)],
                command_results=commands,
            )

    try:
        build = docs_assistant.build_docs_index(REPO_ROOT, INDEX_DIR)
    except Exception as exc:  # noqa: BLE001 - return a structured MCP blocker.
        return _error(
            "prepare_start",
            "Documentation index build failed.",
            blockers=[{"phase": "rag_index", "message": str(exc)}],
            command_results=commands,
        )

    selected_area = _infer_area(task, area, _changed_paths())
    route = _route(task, selected_area)
    final_state = _repo_state()
    warnings = []
    if ahead:
        warnings.append(f"Local main is {ahead} commit(s) ahead of origin/main.")
    if initial.get("dirty"):
        warnings.append("The pre-existing dirty worktree was preserved.")
    return {
        "ok": True,
        "tool": "prepare_start",
        "summary": "Startup workflow completed.",
        "result": {
            "repository": final_state,
            "area": selected_area,
            "required_instruction_files": route,
            "docs_index": {"files": build.file_count, "chunks": build.chunk_count},
            "warnings": warnings,
        },
        "command_results": commands,
        "next_actions": [
            "Read the routed instruction files.",
            "Call change_impact before broad repository inspection or edits.",
        ],
    }


def docs(query: str, mode: str = "search", top_k: int = 3) -> dict[str, Any]:
    """Search or answer from the repository-local documentation index."""
    if mode not in {"search", "ask"}:
        return _error("docs", "mode must be 'search' or 'ask'")
    if top_k < 1 or top_k > 20:
        return _error("docs", "top_k must be between 1 and 20")
    try:
        rebuilt, warnings = docs_assistant.ensure_docs_index(REPO_ROOT, INDEX_DIR)
        if mode == "ask":
            answer = docs_assistant.ask_docs(query, INDEX_DIR, top_k=top_k)
            result: dict[str, Any] = {
                "answer": answer.answer,
                "citations": answer.citations,
            }
        else:
            matches = docs_assistant.search_docs(query, INDEX_DIR, top_k=top_k)
            result = {
                "matches": [
                    {
                        "citation": match.chunk.citation,
                        "heading": match.chunk.heading,
                        "snippet": docs_assistant.snippet(match.chunk.text, 500),
                        "score": round(match.score, 4),
                    }
                    for match in matches
                ]
            }
        result["index_rebuilt"] = rebuilt is not None
        result["freshness_warnings"] = warnings
        return {"ok": True, "tool": "docs", "summary": f"Docs {mode} completed.", "result": result}
    except Exception as exc:  # noqa: BLE001
        return _error("docs", f"Documentation retrieval failed: {exc}")


def change_impact(
    task: str,
    area: str | None = None,
    paths: list[str] | None = None,
) -> dict[str, Any]:
    """Return focused docs, likely owners, and checks for a planned change."""
    requested_paths = _unique(paths or [])
    changed = _changed_paths()
    selected_area = _infer_area(task, area, [*requested_paths, *changed])
    search = docs(task, mode="search", top_k=4)
    references = search.get("result", {}).get("matches", []) if search.get("ok") else []
    return {
        "ok": True,
        "tool": "change_impact",
        "summary": "Change impact collected.",
        "result": {
            "area": selected_area,
            "required_instruction_files": _route(task, selected_area),
            "requested_paths": requested_paths,
            "currently_changed_paths": changed,
            "rag_references": references,
            "recommended_checks": [_display(command) for command in _commands_for(selected_area, "focused")],
            "safety": _safety_notes(task, selected_area),
        },
    }


def workflow_status(
    task: str | None = None,
    area: str | None = None,
    instructions_read: bool = False,
) -> dict[str, Any]:
    """Report repository state, docs freshness, routing, and required next actions."""
    changed = _changed_paths()
    selected_area = _infer_area(task or "repository work", area, changed)
    warnings = docs_assistant.index_freshness_warnings(REPO_ROOT, INDEX_DIR)
    route = _route(task or "repository work", selected_area)
    receipt = _read_json(RECEIPT_PATH)
    receipt_valid = bool(receipt and receipt.get("fingerprint") == _snapshot_fingerprint())
    missing = []
    if not instructions_read:
        missing.append("Read the required instruction files before editing.")
    if warnings:
        missing.append("Rebuild the documentation index with prepare_start or docs.")
    return {
        "ok": not missing,
        "tool": "workflow_status",
        "summary": "Workflow status collected." if not missing else "Workflow status requires action.",
        "result": {
            "repository": _repo_state(),
            "area": selected_area,
            "changed_paths": changed,
            "required_instruction_files": [] if instructions_read else route,
            "recommended_checks": [_display(command) for command in _commands_for(selected_area, "focused")],
            "docs_index_fresh": not warnings,
            "prepush_receipt_valid": receipt_valid,
            "missing_mandatory_actions": missing,
        },
    }


def run_checks(
    area: str = "auto",
    level: str = "focused",
    dry_run: bool = False,
) -> dict[str, Any]:
    """Run focused checks or the complete pre-push validation tier."""
    if level not in {"focused", "prepush"}:
        return _error("run_checks", "level must be 'focused' or 'prepush'")
    selected_area = _infer_area("validation", None if area == "auto" else area, _changed_paths())
    commands = _commands_for(selected_area, level)
    if dry_run:
        return {
            "ok": True,
            "tool": "run_checks",
            "summary": "Check plan generated without executing commands.",
            "result": {"area": selected_area, "level": level, "commands": [_display(c) for c in commands]},
        }

    results = []
    for command in commands:
        result = _run(command, timeout=50 * 60)
        results.append(result)
        if not result["ok"]:
            return _error(
                "run_checks",
                f"Validation failed: {_display(command)}",
                blockers=[_command_blocker("check", result)],
                command_results=results,
            )

    receipt = None
    if level == "prepush":
        receipt = {
            "version": 1,
            "fingerprint": _snapshot_fingerprint(),
            "head": _git_stdout(["rev-parse", "HEAD"]),
            "commands": [_display(command) for command in commands],
            "created_at_epoch": int(time.time()),
        }
        _write_json(RECEIPT_PATH, receipt)
    return {
        "ok": True,
        "tool": "run_checks",
        "summary": "All requested checks passed.",
        "result": {
            "area": selected_area,
            "level": level,
            "commands": [_display(command) for command in commands],
            "prepush_receipt": str(RECEIPT_PATH.relative_to(REPO_ROOT)) if receipt else None,
        },
        "command_results": results,
    }


def git_workflow(
    action: str,
    message: str | None = None,
    paths: list[str] | None = None,
    sha: str | None = None,
) -> dict[str, Any]:
    """Commit/push validated work or resume exact-SHA GitHub Actions verification."""
    if action not in {"commit", "push", "checks"}:
        return _error("git_workflow", "action must be 'commit', 'push', or 'checks'")
    if action == "checks":
        target = sha or _git_stdout(["rev-parse", "HEAD"])
        if not SHA_RE.fullmatch(target):
            return _error("git_workflow", "sha must be a full 40-character lowercase commit SHA")
        return _watch_required_workflows(target)

    state = _repo_state()
    if state.get("branch") != "main":
        return _error("git_workflow", "Commit and push operations require branch main.")
    receipt_error = _receipt_error()
    if receipt_error:
        return _error("git_workflow", receipt_error)

    commands: list[dict[str, Any]] = []
    if action == "commit":
        if not message or not message.strip():
            return _error("git_workflow", "message is required for action='commit'")
        requested = _unique(paths or [])
        if not requested:
            return _error("git_workflow", "Explicit paths are required for action='commit'")
        path_error = _validate_commit_paths(requested)
        if path_error:
            return _error("git_workflow", path_error)
        changed = _changed_paths()
        uncovered = [path for path in changed if not _path_is_covered(path, requested)]
        if uncovered:
            return _error(
                "git_workflow",
                "Explicit paths do not cover every changed path; unrelated work was not staged.",
                blockers=[{"phase": "paths", "uncovered": uncovered}],
            )
        add = _run(["git", "add", "--", *requested])
        commands.append(add)
        if not add["ok"]:
            return _error("git_workflow", "git add failed", blockers=[_command_blocker("add", add)])
        commit = _run(["git", "commit", "-m", message.strip()], timeout=180)
        commands.append(commit)
        if not commit["ok"]:
            return _error(
                "git_workflow",
                "git commit failed",
                blockers=[_command_blocker("commit", commit)],
                command_results=commands,
            )

    if _changed_paths():
        return _error(
            "git_workflow",
            "The worktree must be clean before push.",
            blockers=[{"phase": "push", "changed_paths": _changed_paths()}],
            command_results=commands,
        )
    push = _run(["git", "push", "origin", "HEAD:main"], timeout=10 * 60)
    commands.append(push)
    if not push["ok"]:
        return _error(
            "git_workflow",
            "Push to origin/main failed.",
            blockers=[_command_blocker("push", push)],
            command_results=commands,
        )
    target = _git_stdout(["rev-parse", "HEAD"])
    watched = _watch_required_workflows(target)
    watched["command_results"] = [*commands, *watched.get("command_results", [])]
    return watched


def _route(task: str, area: str) -> list[str]:
    files = ["AGENTS.md", "agent_docs/README.md", "agent_docs/development.md"]
    files.extend(AREA_DOCS.get(area, []))
    lowered = task.lower()
    if any(word in lowered for word in ("test", "check", "validate", "ci")):
        files.append("agent_docs/test-matrix.md")
    if any(word in lowered for word in ("vpn", "runtime", "sing-box")):
        files.extend(AREA_DOCS["runtime"])
    return [path for path in _unique(files) if (REPO_ROOT / path).is_file()]


def _infer_area(task: str, area: str | None, paths: list[str]) -> str:
    if area and area != "auto":
        normalized = area.strip().lower().replace("-", "_")
        aliases = {"ui": "localization", "mcp": "agent_tools", "rag": "agent_tools"}
        return aliases.get(normalized, normalized)
    joined = " ".join([task.lower(), *(path.lower() for path in paths)])
    rules = [
        ("agent_tools", ("mcp", "rag", "agent_tools", ".codex")),
        ("localization", ("localization", "i18n", "catalog", "translation", "settings_home")),
        ("ssh", ("ssh", "routing")),
        ("release", ("package", "release", "workflow", ".github")),
        ("runtime", ("sing-box", "runtime", "vpn service")),
        ("android", ("android", "app/src")),
        ("desktop", ("desktop", "desktopapp")),
        ("docs", ("readme", "docs/", "documentation")),
    ]
    for candidate, needles in rules:
        if any(needle in joined for needle in needles):
            return candidate
    return "docs"


def _commands_for(area: str, level: str) -> list[list[str]]:
    if level == "prepush":
        return [list(command) for command in PREPUSH_COMMANDS]
    commands = FOCUSED_COMMANDS.get(area)
    return [list(command) for command in (commands or FOCUSED_COMMANDS["docs"])]


def _safety_notes(task: str, area: str) -> list[str]:
    notes = ["Preserve unrelated dirty changes and stage only explicit paths."]
    if area in {"runtime", "desktop", "android"} or "vpn" in task.lower():
        notes.append("Do not stop a running VPN/runtime without explicit user approval.")
    if area == "localization":
        notes.append("Keep user-facing translations in JSON catalogs; preserve placeholders.")
    return notes


def _repo_state() -> dict[str, Any]:
    branch = _git_stdout(["branch", "--show-current"])
    head = _git_stdout(["rev-parse", "HEAD"])
    status = _run(["git", "status", "--short"])
    ahead, behind, _ = _ahead_behind()
    lines = [line for line in str(status.get("stdout", "")).splitlines() if line]
    return {
        "branch": branch,
        "head": head,
        "dirty": bool(lines),
        "changed_count": len(lines),
        "ahead": ahead,
        "behind": behind,
    }


def _ahead_behind() -> tuple[int | None, int | None, dict[str, Any] | None]:
    result = _run(["git", "rev-list", "--left-right", "--count", "HEAD...origin/main"])
    if not result["ok"]:
        return None, None, _command_blocker("compare", result)
    try:
        left, right = str(result["stdout"]).strip().split()
        return int(left), int(right), None
    except (TypeError, ValueError) as exc:
        return None, None, {"phase": "compare", "message": str(exc)}


def _changed_paths() -> list[str]:
    tracked = _run(["git", "diff", "--name-only", "HEAD"])
    untracked = _run(["git", "ls-files", "--others", "--exclude-standard"])
    values = []
    for result in (tracked, untracked):
        if result["ok"]:
            values.extend(line for line in str(result["stdout"]).splitlines() if line)
    return sorted(_unique(values))


def _snapshot_fingerprint() -> str:
    tracked_result = _run(["git", "ls-files", "-z"])
    untracked_result = _run(["git", "ls-files", "--others", "--exclude-standard", "-z"])
    if not tracked_result["ok"] or not untracked_result["ok"]:
        raise RuntimeError("Could not enumerate repository files for the pre-push fingerprint")
    names = {
        name
        for result in (tracked_result, untracked_result)
        for name in str(result["stdout"]).split("\0")
        if name
    }
    digest = hashlib.sha256()
    for name in sorted(names):
        path = REPO_ROOT / name
        if not path.is_file():
            continue
        digest.update(name.encode("utf-8", errors="surrogateescape"))
        digest.update(b"\0")
        digest.update(str(path.stat().st_mode & 0o777).encode("ascii"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _receipt_error() -> str | None:
    receipt = _read_json(RECEIPT_PATH)
    if not receipt:
        return "A successful run_checks(level='prepush') receipt is required."
    try:
        current = _snapshot_fingerprint()
    except RuntimeError as exc:
        return str(exc)
    if receipt.get("fingerprint") != current:
        return "Repository contents changed after pre-push checks; rerun run_checks(level='prepush')."
    return None


def _validate_commit_paths(paths: list[str]) -> str | None:
    for raw in paths:
        if not raw or raw in {".", "./"}:
            return "Repository-root pathspecs are not allowed."
        if os.path.isabs(raw) or raw.startswith(":"):
            return f"Unsafe pathspec: {raw}"
        if GLOB_CHARS & set(raw):
            return f"Globs are not allowed in commit paths: {raw}"
        path = Path(raw)
        if ".." in path.parts:
            return f"Parent traversal is not allowed: {raw}"
        if any(part in SENSITIVE_PARTS for part in path.parts):
            return f"Generated, runtime, or sensitive path is not allowed: {raw}"
        try:
            (REPO_ROOT / path).resolve().relative_to(REPO_ROOT)
        except ValueError:
            return f"Path escapes the repository: {raw}"
    return None


def _path_is_covered(changed: str, requested: list[str]) -> bool:
    return any(changed == item.rstrip("/") or changed.startswith(item.rstrip("/") + "/") for item in requested)


def _required_workflows() -> list[dict[str, str]]:
    data = _read_json(REQUIRED_WORKFLOWS_PATH)
    entries = data.get("required_push") if data else None
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"Invalid required workflow manifest: {REQUIRED_WORKFLOWS_PATH}")
    workflows = []
    for entry in entries:
        if not isinstance(entry, dict) or not entry.get("name") or not entry.get("workflow"):
            raise ValueError("Every required workflow needs name and workflow fields")
        workflows.append({"name": str(entry["name"]), "workflow": str(entry["workflow"])})
    return workflows


def _watch_required_workflows(sha: str) -> dict[str, Any]:
    try:
        required = _required_workflows()
    except ValueError as exc:
        return _error("git_workflow", str(exc))
    required_names = {item["name"] for item in required}
    started = time.monotonic()
    command_results: list[dict[str, Any]] = []
    latest: dict[str, dict[str, Any]] = {}
    while True:
        listed = _run(
            [
                "gh",
                "run",
                "list",
                "--commit",
                sha,
                "--limit",
                "100",
                "--json",
                "databaseId,workflowName,status,conclusion,url,headSha",
            ],
            timeout=120,
        )
        command_results.append(listed)
        if not listed["ok"]:
            return _error(
                "git_workflow",
                "Could not query GitHub Actions.",
                blockers=[_command_blocker("github", listed)],
                command_results=command_results,
            )
        try:
            runs = json.loads(str(listed["stdout"]) or "[]")
        except json.JSONDecodeError as exc:
            return _error("git_workflow", f"Invalid gh run list output: {exc}")
        latest = {}
        for run in runs if isinstance(runs, list) else []:
            if not isinstance(run, dict) or run.get("headSha") != sha:
                continue
            name = str(run.get("workflowName", ""))
            if name not in required_names:
                continue
            previous = latest.get(name)
            if previous is None or int(run.get("databaseId") or 0) > int(previous.get("databaseId") or 0):
                latest[name] = run
        missing = sorted(required_names - set(latest))
        failures = {
            name: run
            for name, run in latest.items()
            if run.get("status") == "completed" and run.get("conclusion") != "success"
        }
        state = {
            "sha": sha,
            "updated_at_epoch": int(time.time()),
            "missing": missing,
            "runs": latest,
        }
        _write_json(WATCH_STATE_PATH, state)
        if failures:
            logs = []
            for name, run in failures.items():
                run_id = str(run.get("databaseId"))
                log = _run(["gh", "run", "view", run_id, "--log-failed"], timeout=180)
                command_results.append(log)
                logs.append({"workflow": name, "run_id": run_id, "excerpt": _bounded(log.get("stdout") or log.get("stderr"), 8000)})
            return _error(
                "git_workflow",
                "One or more required workflows failed for the exact pushed SHA.",
                blockers=[{"phase": "ci", "failures": failures, "failed_log_excerpts": logs}],
                command_results=command_results,
            )
        complete = len(latest) == len(required_names) and all(
            run.get("status") == "completed" and run.get("conclusion") == "success"
            for run in latest.values()
        )
        if complete:
            return {
                "ok": True,
                "tool": "git_workflow",
                "summary": "Push and all required exact-SHA workflows completed successfully.",
                "result": {"sha": sha, "workflows": latest},
                "command_results": command_results,
            }
        elapsed = time.monotonic() - started
        if missing and elapsed >= DISCOVERY_TIMEOUT_SECONDS:
            return _error(
                "git_workflow",
                "Required workflows did not appear for the exact SHA within the discovery window.",
                blockers=[{"phase": "ci_discovery", "sha": sha, "missing": missing}],
                command_results=command_results,
            )
        if elapsed >= WATCH_TIMEOUT_SECONDS:
            return _error(
                "git_workflow",
                "Required workflows did not finish within the watch window.",
                blockers=[{"phase": "ci_timeout", "sha": sha, "missing": missing, "runs": latest}],
                command_results=command_results,
            )
        time.sleep(POLL_SECONDS)


def _run(command: list[str], timeout: int = 120) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": completed.returncode == 0,
            "command": _display(command),
            "returncode": completed.returncode,
            "stdout": _bounded(completed.stdout),
            "stderr": _bounded(completed.stderr),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "command": _display(command),
            "returncode": None,
            "stdout": _bounded(getattr(exc, "stdout", "") or ""),
            "stderr": _bounded(str(exc)),
        }


def _git_stdout(arguments: list[str]) -> str:
    result = _run(["git", *arguments])
    return str(result.get("stdout", "")).strip() if result["ok"] else ""


def _display(command: list[str]) -> str:
    return shlex.join(str(part) for part in command)


def _bounded(value: Any, limit: int = MAX_OUTPUT_CHARS) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 16].rstrip() + "\n...[truncated]"


def _command_blocker(phase: str, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": phase,
        "command": result.get("command"),
        "returncode": result.get("returncode"),
        "message": result.get("stderr") or result.get("stdout") or "command failed",
    }


def _error(
    tool: str,
    summary: str,
    *,
    blockers: list[dict[str, Any]] | None = None,
    command_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "ok": False,
        "tool": tool,
        "summary": summary,
        "blockers": blockers or [{"phase": "validate", "message": summary}],
    }
    if command_results:
        value["command_results"] = command_results
    return value


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _json_print(value: dict[str, Any]) -> int:
    print(json.dumps(value, indent=2, ensure_ascii=False))
    return 0 if value.get("ok") else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vpn-control-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("serve")
    start = subparsers.add_parser("prepare-start")
    start.add_argument("task")
    start.add_argument("--area")
    docs_parser = subparsers.add_parser("docs")
    docs_parser.add_argument("query")
    docs_parser.add_argument("--mode", choices=("search", "ask"), default="search")
    docs_parser.add_argument("--top-k", type=int, default=3)
    impact = subparsers.add_parser("change-impact")
    impact.add_argument("task")
    impact.add_argument("--area")
    impact.add_argument("--path", action="append", dest="paths")
    status = subparsers.add_parser("workflow-status")
    status.add_argument("--task")
    status.add_argument("--area")
    status.add_argument("--instructions-read", action="store_true")
    checks = subparsers.add_parser("run-checks")
    checks.add_argument("--area", default="auto")
    checks.add_argument("--level", choices=("focused", "prepush"), default="focused")
    checks.add_argument("--dry-run", action="store_true")
    git_parser = subparsers.add_parser("git-workflow")
    git_parser.add_argument("action", choices=("commit", "push", "checks"))
    git_parser.add_argument("--message")
    git_parser.add_argument("--path", action="append", dest="paths")
    git_parser.add_argument("--sha")
    args = parser.parse_args(argv)

    if args.command == "serve":
        if MCP_SERVER is None:
            print("MCP dependency is missing; run agent_tools/mcp_server.sh", file=sys.stderr)
            return 2
        MCP_SERVER.run(transport="stdio")
        return 0
    if args.command == "prepare-start":
        return _json_print(prepare_start(args.task, args.area))
    if args.command == "docs":
        return _json_print(docs(args.query, args.mode, args.top_k))
    if args.command == "change-impact":
        return _json_print(change_impact(args.task, args.area, args.paths))
    if args.command == "workflow-status":
        return _json_print(workflow_status(args.task, args.area, args.instructions_read))
    if args.command == "run-checks":
        return _json_print(run_checks(args.area, args.level, args.dry_run))
    return _json_print(git_workflow(args.action, args.message, args.paths, args.sha))


MCP_SERVER = None
if FastMCP is not None:  # pragma: no branch - depends on the optional launcher environment.
    MCP_SERVER = FastMCP("vpn-control-agent-tools", instructions=SERVER_INSTRUCTIONS)
    MCP_SERVER.tool()(prepare_start)
    MCP_SERVER.tool()(docs)
    MCP_SERVER.tool()(change_impact)
    MCP_SERVER.tool()(workflow_status)
    MCP_SERVER.tool()(run_checks)
    MCP_SERVER.tool()(git_workflow)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
