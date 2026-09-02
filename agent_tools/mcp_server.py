#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import date
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
RELEASE_RECEIPT_PATH = INDEX_DIR / "release_receipt.json"
WATCH_STATE_PATH = INDEX_DIR / "github_watch.json"
REQUIRED_WORKFLOWS_PATH = REPO_ROOT / ".github" / "required-workflows.json"
MAX_OUTPUT_CHARS = 5000
DISCOVERY_TIMEOUT_SECONDS = 5 * 60
WATCH_TIMEOUT_SECONDS = 55 * 60
POLL_SECONDS = 15
WORK_BRANCH = "dev"
RELEASE_BRANCH = "main"
CHANGELOG_PATH = REPO_ROOT / "docs" / "CHANGELOG.md"
UNRELEASED_CHANGELOG_THRESHOLD = 10
VERSION_RE = re.compile(r"^vpnControlVersion=([^\s]+)$", flags=re.MULTILINE)
README_VERSION_RE = re.compile(r"\*\*Version:\*\*\s+`([^`]+)`")
UNRELEASED_HEADING_RE = re.compile(r"^##\s+Unreleased\s*$", flags=re.IGNORECASE | re.MULTILINE)

SERVER_INSTRUCTIONS = (
    "MANDATORY: call prepare_start before normal repository inspection, edits, or tests. "
    "Use docs and change_impact before broad searches. Never stop the VPN/runtime without "
    "explicit user approval. Preserve unrelated dirty changes. Before finishing, use "
    "run_checks(level='prepush'), then git_workflow for push and exact-SHA CI verification on dev. "
    "Publishing is allowed only after an explicit user release command through release_workflow. "
    "The server is fixed to the VPN Control repository root. "
    "Product invariants are centralized in agent_docs/contracts.md. "
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
        "agent_docs/contracts.md",
        "agent_docs/runtime-troubleshooting.md",
        "agent_docs/sing-box-development.md",
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
    [sys.executable, "scripts/check_ui_theme.py"],
    [sys.executable, "scripts/test_visual_regression.py"],
    [sys.executable, "scripts/test_visual_fleet.py"],
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
        ":app:compileDebugAndroidTestKotlin",
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
    fetch = _run(["git", "fetch", "origin", WORK_BRANCH, RELEASE_BRANCH], timeout=180)
    commands.append(fetch)
    if not fetch["ok"]:
        return _error(
            "prepare_start",
            "Could not fetch origin/dev and origin/main; repository freshness is unknown.",
            blockers=[_command_blocker("fetch", fetch)],
            command_results=commands,
        )

    state = _repo_state()
    if state.get("branch") != WORK_BRANCH:
        if state.get("dirty"):
            return _error(
                "prepare_start",
                "The worktree is dirty outside dev; automatic switching is unsafe.",
                blockers=[{"phase": "branch", "state": state}],
                command_results=commands,
            )
        switched = _run(["git", "switch", WORK_BRANCH])
        commands.append(switched)
        if not switched["ok"]:
            return _error(
                "prepare_start",
                "Could not switch the clean worktree to dev.",
                blockers=[_command_blocker("branch", switched)],
                command_results=commands,
            )
        state = _repo_state()

    ahead, behind, relation_error = _ahead_behind(f"origin/{WORK_BRANCH}")
    if relation_error:
        return _error(
            "prepare_start",
            "Could not compare HEAD with origin/dev.",
            blockers=[relation_error],
            command_results=commands,
        )
    if ahead and behind:
        return _error(
            "prepare_start",
            "dev and origin/dev have diverged; resolve explicitly before editing.",
            blockers=[{"phase": "sync", "ahead": ahead, "behind": behind}],
            command_results=commands,
        )
    if behind:
        if state.get("dirty"):
            return _error(
                "prepare_start",
                "dev is behind origin/dev and the worktree is dirty; automatic pull is unsafe.",
                blockers=[{"phase": "sync", "ahead": ahead, "behind": behind}],
                command_results=commands,
            )
        pulled = _run(["git", "pull", "--ff-only", "origin", WORK_BRANCH], timeout=180)
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
        warnings.append(f"Local dev is {ahead} commit(s) ahead of origin/dev.")
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
    version_requirement = _version_bump_requirement(changed)
    advisory = _advisory_runs(_git_stdout(["rev-parse", "HEAD"]))
    missing = []
    if not instructions_read:
        missing.append("Read the required instruction files before editing.")
    if warnings:
        missing.append("Rebuild the documentation index with prepare_start or docs.")
    if version_requirement["missing"]:
        missing.append("Run version_bump(...) for non-documentation changes.")
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
            "version_bump_requirement": version_requirement,
            "advisory_workflows": advisory,
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


def version_bump(
    summary: str | None = None,
    change_type: str = "implementation",
    dry_run: bool = False,
    force_release: bool = False,
) -> dict[str, Any]:
    """Apply the repository's changelog and four-part version policy."""
    normalized_type = change_type.strip().lower().replace("-", "_")
    release_change = normalized_type in {"release", "release_artifact", "publish"}
    docs_only = normalized_type in {"docs", "documentation", "docs_only"}
    if force_release and not release_change:
        return _error("version_bump", "force_release requires a release-oriented change_type")
    if force_release and summary is not None:
        return _error("version_bump", "Omit summary when force_release is enabled")
    if not force_release and not docs_only and not (summary or "").strip():
        return _error("version_bump", "A concise changelog summary is required")
    if docs_only and not release_change:
        return {
            "ok": True,
            "tool": "version_bump",
            "summary": "Documentation-only work does not change version metadata.",
            "result": {"decision": "no_bump"},
        }

    try:
        gradle_text = (REPO_ROOT / "gradle.properties").read_text(encoding="utf-8")
        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        changelog_text = CHANGELOG_PATH.read_text(encoding="utf-8")
        current_version = _parse_required(VERSION_RE, gradle_text, "Gradle version")
        _parse_version(current_version)
        readme_version = _parse_required(README_VERSION_RE, readme_text, "README version")
        if readme_version != current_version:
            raise ValueError("README and Gradle versions do not match")
        unreleased = _unreleased_bullets(changelog_text)
    except (OSError, ValueError) as exc:
        return _error("version_bump", f"Could not read version metadata: {exc}")

    if force_release and not unreleased:
        return _error("version_bump", "Forced release requires non-empty Unreleased notes")
    bullet = "" if force_release else _format_changelog_bullet(summary or "")
    planned_bullets = unreleased if force_release else [*unreleased, bullet]
    should_bump = force_release or len(planned_bullets) >= UNRELEASED_CHANGELOG_THRESHOLD
    next_version = _increment_version(current_version) if should_bump else None
    result = {
        "decision": "bump" if should_bump else "unreleased",
        "current_version": current_version,
        "planned_version": next_version,
        "unreleased_count": len(planned_bullets),
        "threshold": UNRELEASED_CHANGELOG_THRESHOLD,
        "changelog_entry": bullet or None,
    }
    if dry_run:
        return {
            "ok": True,
            "tool": "version_bump",
            "summary": "Version policy dry run completed.",
            "result": result,
        }

    try:
        if not should_bump:
            _atomic_write(CHANGELOG_PATH, _append_unreleased_bullet(changelog_text, bullet))
        else:
            assert next_version is not None
            updated_gradle = VERSION_RE.sub(f"vpnControlVersion={next_version}", gradle_text, count=1)
            updated_readme = README_VERSION_RE.sub(f"**Version:** `{next_version}`", readme_text, count=1)
            release_section = (
                f"## {next_version} - {date.today().isoformat()}\n\n"
                + "\n".join(planned_bullets)
                + "\n"
            )
            updated_changelog = _release_unreleased(changelog_text, release_section)
            _atomic_write(REPO_ROOT / "gradle.properties", updated_gradle)
            _atomic_write(REPO_ROOT / "README.md", updated_readme)
            _atomic_write(CHANGELOG_PATH, updated_changelog)
    except (OSError, ValueError) as exc:
        return _error("version_bump", f"Could not update version metadata: {exc}")
    return {
        "ok": True,
        "tool": "version_bump",
        "summary": (
            f"Bumped VPN Control to {next_version}."
            if should_bump
            else f"Added Unreleased changelog entry ({len(planned_bullets)}/{UNRELEASED_CHANGELOG_THRESHOLD})."
        ),
        "result": result,
    }


def release_workflow(action: str = "status") -> dict[str, Any]:
    """Prepare or publish a release only after an explicit user command."""
    if action not in {"status", "merge-dev", "publish"}:
        return _error("release_workflow", "action must be 'status', 'merge-dev', or 'publish'")
    if action == "merge-dev":
        return _merge_dev_for_release()
    if action == "status":
        readiness = _release_readiness()
        if readiness["blockers"]:
            return _error(
                "release_workflow",
                "Release has blockers.",
                blockers=readiness["blockers"],
                command_results=readiness["command_results"],
            )
        receipt = {
            "fingerprint": _snapshot_fingerprint(),
            "sha": readiness["sha"],
            "version": readiness["version"],
            "created_at_epoch": int(time.time()),
        }
        _write_json(RELEASE_RECEIPT_PATH, receipt)
        return {
            "ok": True,
            "tool": "release_workflow",
            "summary": "Release is ready for an explicit publish command.",
            "result": readiness,
            "command_results": readiness["command_results"],
        }

    receipt = _read_json(RELEASE_RECEIPT_PATH)
    current_sha = _git_stdout(["rev-parse", "HEAD"])
    if (
        not receipt
        or receipt.get("sha") != current_sha
        or receipt.get("fingerprint") != _snapshot_fingerprint()
    ):
        return _error(
            "release_workflow",
            "Publish requires a current successful release_workflow(action='status') receipt.",
        )
    dispatched = _run(
        [
            "gh", "workflow", "run", "release-publish.yml", "--ref", RELEASE_BRANCH,
            "-f", f"target_sha={current_sha}",
        ],
        timeout=180,
    )
    if not dispatched["ok"]:
        return _error(
            "release_workflow",
            "Could not dispatch the manual release publisher.",
            blockers=[_command_blocker("publish", dispatched)],
            command_results=[dispatched],
        )
    return {
        "ok": True,
        "tool": "release_workflow",
        "summary": "Manual release publisher dispatched.",
        "result": {"sha": current_sha, "version": receipt.get("version")},
        "command_results": [dispatched],
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
    if state.get("branch") != WORK_BRANCH:
        return _error("git_workflow", "Commit and push operations require branch dev.")
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
        version_requirement = _version_bump_requirement(changed)
        if version_requirement["missing"]:
            return _error(
                "git_workflow",
                "Non-documentation changes require version_bump(...).",
                blockers=[{"phase": "version_bump", **version_requirement}],
            )
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
    push = _run(["git", "push", "origin", f"HEAD:{WORK_BRANCH}"], timeout=10 * 60)
    commands.append(push)
    if not push["ok"]:
        return _error(
            "git_workflow",
            "Push to origin/dev failed.",
            blockers=[_command_blocker("push", push)],
            command_results=commands,
        )
    target = _git_stdout(["rev-parse", "HEAD"])
    watched = _watch_required_workflows(target)
    watched["command_results"] = [*commands, *watched.get("command_results", [])]
    return watched


def _route(task: str, area: str) -> list[str]:
    files = ["AGENTS.md", "agent_docs/README.md", "agent_docs/development.md", "agent_docs/contracts.md"]
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
    remote = f"origin/{branch}" if branch in {WORK_BRANCH, RELEASE_BRANCH} else f"origin/{WORK_BRANCH}"
    ahead, behind, _ = _ahead_behind(remote)
    lines = [line for line in str(status.get("stdout", "")).splitlines() if line]
    return {
        "branch": branch,
        "head": head,
        "dirty": bool(lines),
        "changed_count": len(lines),
        "ahead": ahead,
        "behind": behind,
    }


def _ahead_behind(remote: str | None = None) -> tuple[int | None, int | None, dict[str, Any] | None]:
    comparison = remote or f"origin/{WORK_BRANCH}"
    result = _run(["git", "rev-list", "--left-right", "--count", f"HEAD...{comparison}"])
    if not result["ok"]:
        return None, None, _command_blocker("compare", result)
    try:
        left, right = str(result["stdout"]).strip().split()
        return int(left), int(right), None
    except (TypeError, ValueError) as exc:
        return None, None, {"phase": "compare", "message": str(exc)}


def _changed_paths() -> list[str]:
    tracked = _run(["git", "diff", "--name-only", "HEAD"], output_limit=None)
    untracked = _run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        output_limit=None,
    )
    values = []
    for result in (tracked, untracked):
        if result["ok"]:
            values.extend(line for line in str(result["stdout"]).splitlines() if line)
    return sorted(_unique(values))


def _snapshot_fingerprint() -> str:
    tracked_result = _run(["git", "ls-files", "-z"], output_limit=None)
    untracked_result = _run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        output_limit=None,
    )
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


def _merge_dev_for_release() -> dict[str, Any]:
    state = _repo_state()
    if state.get("branch") != WORK_BRANCH or state.get("dirty"):
        return _error("release_workflow", "Release merge requires a clean dev worktree.")
    commands: list[dict[str, Any]] = []
    steps = [
        ["git", "fetch", "origin", WORK_BRANCH, RELEASE_BRANCH],
        ["git", "rev-parse", "HEAD"],
        ["git", "rev-parse", f"origin/{WORK_BRANCH}"],
    ]
    for command in steps:
        result = _run(command, timeout=180)
        commands.append(result)
        if not result["ok"]:
            return _error(
                "release_workflow", "Release synchronization failed.",
                blockers=[_command_blocker("release_merge", result)], command_results=commands,
            )
    if commands[1]["stdout"] != commands[2]["stdout"]:
        return _error(
            "release_workflow",
            "Local dev must exactly match origin/dev before release merge.",
            blockers=[{"phase": "release_merge", "message": "push and verify dev first"}],
            command_results=commands,
        )
    merge_steps = [
        ["git", "switch", RELEASE_BRANCH],
        ["git", "pull", "--ff-only", "origin", RELEASE_BRANCH],
        ["git", "merge", "--ff-only", f"origin/{WORK_BRANCH}"],
        ["git", "push", "origin", RELEASE_BRANCH],
    ]
    for command in merge_steps:
        result = _run(command, timeout=10 * 60)
        commands.append(result)
        if not result["ok"]:
            return _error(
                "release_workflow", "Release fast-forward failed.",
                blockers=[_command_blocker("release_merge", result)], command_results=commands,
            )
    sha = _git_stdout(["rev-parse", "HEAD"])
    release_dispatches = [
        (
            "release_integration",
            [
                "gh", "workflow", "run", "vpn-integration.yml", "--ref", RELEASE_BRANCH,
                "-f", "profile=all", "-f", f"target_sha={sha}",
            ],
        ),
        (
            "visual_regression",
            [
                "gh", "workflow", "run", "visual-regression.yml", "--ref", RELEASE_BRANCH,
                "-f", f"target_sha={sha}",
            ],
        ),
    ]
    for phase, command in release_dispatches:
        dispatched = _run(command, timeout=180)
        commands.append(dispatched)
        if dispatched["ok"]:
            continue
        return _error(
            "release_workflow", "main was updated, but a release gate could not be dispatched.",
            blockers=[_command_blocker(phase, dispatched)], command_results=commands,
        )
    return {
        "ok": True,
        "tool": "release_workflow",
        "summary": "Fast-forwarded dev to main and dispatched exhaustive VPN and visual release gates.",
        "result": {"sha": sha},
        "command_results": commands,
    }


def _release_readiness() -> dict[str, Any]:
    blockers: list[dict[str, Any]] = []
    command_results: list[dict[str, Any]] = []
    state = _repo_state()
    if state.get("branch") != RELEASE_BRANCH:
        blockers.append({"phase": "branch", "message": "release status requires branch main"})
    if state.get("dirty"):
        blockers.append({"phase": "worktree", "message": "release status requires a clean worktree"})
    fetch = _run(["git", "fetch", "--tags", "origin", WORK_BRANCH, RELEASE_BRANCH], timeout=180)
    command_results.append(fetch)
    if not fetch["ok"]:
        blockers.append(_command_blocker("fetch", fetch))
    sha = _git_stdout(["rev-parse", "HEAD"])
    for ref in (f"origin/{RELEASE_BRANCH}", f"origin/{WORK_BRANCH}"):
        value = _git_stdout(["rev-parse", ref])
        if not value or value != sha:
            blockers.append({"phase": "branch", "message": f"HEAD must exactly match {ref}"})
    try:
        gradle_text = (REPO_ROOT / "gradle.properties").read_text(encoding="utf-8")
        readme_text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        changelog_text = CHANGELOG_PATH.read_text(encoding="utf-8")
        version = _parse_required(VERSION_RE, gradle_text, "Gradle version")
        _parse_version(version)
        if _parse_required(README_VERSION_RE, readme_text, "README version") != version:
            blockers.append({"phase": "metadata", "message": "README and Gradle versions differ"})
        first_release = re.search(r"^##\s+([0-9]+(?:\.[0-9]+){3})\s+-", changelog_text, flags=re.MULTILINE)
        if first_release is None or first_release.group(1) != version:
            blockers.append({"phase": "metadata", "message": "latest changelog release does not match version"})
        if _unreleased_bullets(changelog_text):
            blockers.append({"phase": "metadata", "message": "Unreleased notes must be rolled before publishing"})
    except (OSError, ValueError) as exc:
        version = ""
        blockers.append({"phase": "metadata", "message": str(exc)})
    tag = f"v{version}" if version else ""
    if tag and _git_stdout(["tag", "--list", tag]):
        blockers.append({"phase": "tag", "message": f"tag already exists: {tag}"})

    run_list = _run(
        [
            "gh", "run", "list", "--commit", sha, "--limit", "100", "--json",
            "databaseId,displayTitle,workflowName,event,status,conclusion,url,headSha",
        ],
        timeout=120,
    )
    command_results.append(run_list)
    runs: list[dict[str, Any]] = []
    if not run_list["ok"]:
        blockers.append(_command_blocker("github", run_list))
    else:
        try:
            parsed = json.loads(str(run_list["stdout"]) or "[]")
            runs = parsed if isinstance(parsed, list) else []
        except json.JSONDecodeError as exc:
            blockers.append({"phase": "github", "message": str(exc)})
    try:
        required_workflows = {item["name"]: item for item in _required_workflows()}
    except ValueError as exc:
        required_workflows = {}
        blockers.append({"phase": "manifest", "message": str(exc)})
    latest: dict[str, dict[str, Any]] = {}
    integration: dict[str, Any] | None = None
    visual_regression: dict[str, Any] | None = None
    for run in runs:
        if not isinstance(run, dict) or run.get("headSha") != sha:
            continue
        name = str(run.get("workflowName", ""))
        if name == "VPN Integration":
            if (
                run.get("event") == "workflow_dispatch"
                and "VPN Integration / all /" in str(run.get("displayTitle", ""))
                and (
                    integration is None
                    or int(run.get("databaseId") or 0) > int(integration.get("databaseId") or 0)
                )
            ):
                integration = run
            continue
        if name == "Visual Regression":
            if (
                run.get("event") == "workflow_dispatch"
                and f"Visual Regression / {sha}" in str(run.get("displayTitle", ""))
                and (
                    visual_regression is None
                    or int(run.get("databaseId") or 0) > int(visual_regression.get("databaseId") or 0)
                )
            ):
                visual_regression = run
            continue
        requirement = required_workflows.get(name)
        if requirement is None or run.get("event") != requirement["event"]:
            continue
        previous = latest.get(name)
        if previous is None or int(run.get("databaseId") or 0) > int(previous.get("databaseId") or 0):
            latest[name] = run
    for name, requirement in sorted(required_workflows.items()):
        run = latest.get(name)
        if (
            not run
            or run.get("event") != requirement["event"]
            or run.get("status") != "completed"
            or run.get("conclusion") not in requirement["allowed_conclusions"]
        ):
            blockers.append({"phase": "ci", "message": f"missing exact-SHA success for {name}"})
    if (
        not integration
        or integration.get("event") != "workflow_dispatch"
        or "VPN Integration / all /" not in str(integration.get("displayTitle", ""))
        or integration.get("status") != "completed"
        or integration.get("conclusion") != "success"
    ):
        blockers.append({"phase": "integration", "message": "exhaustive dispatched VPN Integration must succeed"})
    if (
        not visual_regression
        or visual_regression.get("event") != "workflow_dispatch"
        or f"Visual Regression / {sha}" not in str(visual_regression.get("displayTitle", ""))
        or visual_regression.get("status") != "completed"
        or visual_regression.get("conclusion") != "success"
    ):
        blockers.append({"phase": "visual", "message": "exact-SHA Visual Regression must succeed on every platform"})
    return {
        "sha": sha,
        "version": version,
        "tag": tag,
        "runs": {
            **latest,
            **({"VPN Integration": integration} if integration else {}),
            **({"Visual Regression": visual_regression} if visual_regression else {}),
        },
        "blockers": blockers,
        "command_results": command_results,
    }


def _version_bump_requirement(changed: list[str]) -> dict[str, Any]:
    version_paths = {"docs/CHANGELOG.md", "gradle.properties", "README.md"}
    non_documentation = [
        path
        for path in changed
        if path not in version_paths
        and not path.endswith(".md")
        and not path.startswith(("docs/", "agent_docs/"))
    ]
    missing = []
    if non_documentation and "docs/CHANGELOG.md" not in changed:
        missing.append("docs/CHANGELOG.md")
    return {
        "non_documentation_paths": non_documentation,
        "required_paths": ["docs/CHANGELOG.md"] if non_documentation else [],
        "missing": missing,
    }


def _parse_required(pattern: re.Pattern[str], text: str, label: str) -> str:
    match = pattern.search(text)
    if match is None:
        raise ValueError(f"Could not parse {label}")
    return match.group(1)


def _parse_version(version: str) -> list[int]:
    parts = version.split(".")
    if len(parts) != 4 or any(not part.isdigit() for part in parts):
        raise ValueError("Version must have four numeric parts")
    values = [int(part) for part in parts]
    if any(value < 0 or value > 19 for value in values):
        raise ValueError("Version components must be between 0 and 19")
    return values


def _increment_version(version: str) -> str:
    values = _parse_version(version)
    for index in range(3, -1, -1):
        if values[index] < 19:
            values[index] += 1
            for reset_index in range(index + 1, 4):
                values[reset_index] = 0
            return ".".join(str(value) for value in values)
    raise ValueError("Version cannot be incremented without exceeding component limits")


def _unreleased_bounds(text: str) -> tuple[int, int, int] | None:
    match = UNRELEASED_HEADING_RE.search(text)
    if match is None:
        return None
    next_heading = re.search(r"^##\s+", text[match.end():], flags=re.MULTILINE)
    end = len(text) if next_heading is None else match.end() + next_heading.start()
    return match.start(), match.end(), end


def _unreleased_bullets(text: str) -> list[str]:
    bounds = _unreleased_bounds(text)
    if bounds is None:
        return []
    _, body_start, body_end = bounds
    return [line.rstrip() for line in text[body_start:body_end].splitlines() if line.startswith("- ")]


def _format_changelog_bullet(summary: str) -> str:
    value = summary.strip().rstrip(".")
    if not value:
        raise ValueError("Changelog summary cannot be empty")
    return f"- {value}."


def _append_unreleased_bullet(text: str, bullet: str) -> str:
    bounds = _unreleased_bounds(text)
    if bounds is None:
        first_heading = re.search(r"^##\s+", text, flags=re.MULTILINE)
        insertion = f"## Unreleased\n\n{bullet}\n\n"
        if first_heading is None:
            return text.rstrip() + "\n\n" + insertion
        return text[:first_heading.start()] + insertion + text[first_heading.start():]
    _, body_start, body_end = bounds
    body = text[body_start:body_end].strip()
    updated = f"{body}\n{bullet}" if body else bullet
    return text[:body_start].rstrip() + "\n\n" + updated + "\n\n" + text[body_end:].lstrip("\n")


def _release_unreleased(text: str, release_section: str) -> str:
    bounds = _unreleased_bounds(text)
    if bounds is None:
        raise ValueError("Changelog is missing Unreleased")
    start, _, end = bounds
    remaining = text[:start] + text[end:].lstrip("\n")
    first_heading = re.search(r"^##\s+", remaining, flags=re.MULTILINE)
    insertion = release_section.rstrip() + "\n\n"
    if first_heading is None:
        return remaining.rstrip() + "\n\n" + insertion
    return remaining[:first_heading.start()] + insertion + remaining[first_heading.start():]


def _atomic_write(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _required_workflows() -> list[dict[str, Any]]:
    data = _read_json(REQUIRED_WORKFLOWS_PATH)
    branch = data.get("branches", {}).get(WORK_BRANCH, {}) if data else {}
    entries = [
        entry
        for entry in branch.get("workflows", [])
        if isinstance(entry, dict) and entry.get("classification") == "required_push"
    ]
    if not entries:
        entries = data.get("required_push") if data else None
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"Invalid required workflow manifest: {REQUIRED_WORKFLOWS_PATH}")
    workflows = []
    for entry in entries:
        workflow = entry.get("workflow") or Path(str(entry.get("path", ""))).name
        if not isinstance(entry, dict) or not entry.get("name") or not workflow:
            raise ValueError("Every required workflow needs name and path fields")
        allowed = entry.get("allowed_conclusions", ["success"])
        if not isinstance(allowed, list) or not allowed:
            raise ValueError("Every required workflow needs allowed_conclusions")
        workflows.append(
            {
                "name": str(entry["name"]),
                "workflow": str(workflow),
                "event": str(entry.get("event", "push")),
                "allowed_conclusions": [str(value) for value in allowed],
            },
        )
    return workflows


def _advisory_workflow_names() -> set[str]:
    data = _read_json(REQUIRED_WORKFLOWS_PATH)
    entries = data.get("branches", {}).get(WORK_BRANCH, {}).get("workflows", []) if data else []
    return {
        str(entry["name"])
        for entry in entries
        if isinstance(entry, dict)
        and entry.get("classification") == "advisory_push"
        and entry.get("name")
    }


def _advisory_runs(sha: str) -> dict[str, dict[str, Any]]:
    names = _advisory_workflow_names()
    if not names:
        return {}
    result = _run(
        [
            "gh", "run", "list", "--commit", sha, "--limit", "100", "--json",
            "databaseId,workflowName,status,conclusion,url,headSha",
        ],
        timeout=120,
    )
    if not result["ok"]:
        return {}
    try:
        runs = json.loads(str(result["stdout"]) or "[]")
    except json.JSONDecodeError:
        return {}
    latest: dict[str, dict[str, Any]] = {}
    for run in runs if isinstance(runs, list) else []:
        if not isinstance(run, dict) or run.get("headSha") != sha:
            continue
        name = str(run.get("workflowName", ""))
        if name not in names:
            continue
        previous = latest.get(name)
        if previous is None or int(run.get("databaseId") or 0) > int(previous.get("databaseId") or 0):
            latest[name] = run
    return latest


def _watch_required_workflows(sha: str) -> dict[str, Any]:
    try:
        required = _required_workflows()
    except ValueError as exc:
        return _error("git_workflow", str(exc))
    required_by_name = {item["name"]: item for item in required}
    required_names = set(required_by_name)
    started = time.monotonic()
    poll_count = 0
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
                "databaseId,workflowName,event,status,conclusion,url,headSha",
            ],
            timeout=120,
        )
        poll_count += 1
        if not listed["ok"]:
            return _error(
                "git_workflow",
                "Could not query GitHub Actions.",
                blockers=[_command_blocker("github", listed)],
                command_results=[listed],
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
            if run.get("event") != required_by_name[name]["event"]:
                continue
            previous = latest.get(name)
            if previous is None or int(run.get("databaseId") or 0) > int(previous.get("databaseId") or 0):
                latest[name] = run
        missing = sorted(required_names - set(latest))
        failures = {
            name: run
            for name, run in latest.items()
            if run.get("status") == "completed"
            and run.get("conclusion") not in required_by_name[name]["allowed_conclusions"]
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
                logs.append({"workflow": name, "run_id": run_id, "excerpt": _bounded(log.get("stdout") or log.get("stderr"), 8000)})
            return _error(
                "git_workflow",
                "One or more required workflows failed for the exact pushed SHA.",
                blockers=[{"phase": "ci", "failures": failures, "failed_log_excerpts": logs}],
                command_results=[listed],
            )
        complete = len(latest) == len(required_names) and all(
            run.get("status") == "completed"
            and run.get("conclusion") in required_by_name[name]["allowed_conclusions"]
            for name, run in latest.items()
        )
        if complete:
            advisory = _advisory_runs(sha)
            return {
                "ok": True,
                "tool": "git_workflow",
                "summary": "Push and all required exact-SHA workflows completed successfully.",
                "result": {
                    "sha": sha,
                    "workflows": latest,
                    "advisory_workflows": advisory,
                    "poll_count": poll_count,
                },
                "command_results": [listed],
            }
        elapsed = time.monotonic() - started
        if missing and elapsed >= DISCOVERY_TIMEOUT_SECONDS:
            return _error(
                "git_workflow",
                "Required workflows did not appear for the exact SHA within the discovery window.",
                blockers=[{"phase": "ci_discovery", "sha": sha, "missing": missing}],
                command_results=[listed],
            )
        if elapsed >= WATCH_TIMEOUT_SECONDS:
            return _error(
                "git_workflow",
                "Required workflows did not finish within the watch window.",
                blockers=[{"phase": "ci_timeout", "sha": sha, "missing": missing, "runs": latest}],
                command_results=[listed],
            )
        time.sleep(POLL_SECONDS)


def _run(
    command: list[str],
    timeout: int = 120,
    output_limit: int | None = MAX_OUTPUT_CHARS,
) -> dict[str, Any]:
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
            "stdout": _bounded(completed.stdout, output_limit),
            "stderr": _bounded(completed.stderr, output_limit),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "ok": False,
            "command": _display(command),
            "returncode": None,
            "stdout": _bounded(getattr(exc, "stdout", "") or "", output_limit),
            "stderr": _bounded(str(exc), output_limit),
        }


def _git_stdout(arguments: list[str]) -> str:
    result = _run(["git", *arguments])
    return str(result.get("stdout", "")).strip() if result["ok"] else ""


def _display(command: list[str]) -> str:
    return shlex.join(str(part) for part in command)


def _bounded(value: Any, limit: int | None = MAX_OUTPUT_CHARS) -> str:
    text = str(value or "").strip()
    if limit is None:
        return text
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
    bump = subparsers.add_parser("version-bump")
    bump.add_argument("--summary")
    bump.add_argument("--change-type", default="implementation")
    bump.add_argument("--dry-run", action="store_true")
    bump.add_argument("--force-release", action="store_true")
    release = subparsers.add_parser("release-workflow")
    release.add_argument("action", choices=("status", "merge-dev", "publish"), default="status")
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
    if args.command == "version-bump":
        return _json_print(version_bump(args.summary, args.change_type, args.dry_run, args.force_release))
    if args.command == "release-workflow":
        return _json_print(release_workflow(args.action))
    return _json_print(git_workflow(args.action, args.message, args.paths, args.sha))


MCP_SERVER = None
if FastMCP is not None:  # pragma: no branch - depends on the optional launcher environment.
    MCP_SERVER = FastMCP("vpn-control-agent-tools", instructions=SERVER_INSTRUCTIONS)
    MCP_SERVER.tool()(prepare_start)
    MCP_SERVER.tool()(docs)
    MCP_SERVER.tool()(change_impact)
    MCP_SERVER.tool()(workflow_status)
    MCP_SERVER.tool()(run_checks)
    MCP_SERVER.tool()(version_bump)
    MCP_SERVER.tool()(release_workflow)
    MCP_SERVER.tool()(git_workflow)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
