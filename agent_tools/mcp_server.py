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
import uuid
from pathlib import Path
from typing import Any, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
_MCP_BOOT_TIME_NS = time.time_ns()
# Direct CLI/MCP execution has no package context.  Make the checked-in
# package available so fixed adapters can use qualified imports rather than
# resolving same-named guest fixture helpers from an inherited script path.
if not __package__ and str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

docs_assistant = importlib.import_module(
    f"{__package__}.docs_assistant" if __package__ else "docs_assistant"
)
local_build_environment = importlib.import_module(
    f"{__package__}.local_build_environment" if __package__ else "local_build_environment"
)
managed_check_lease = importlib.import_module(f"{__package__ or 'agent_tools'}.managed_check_lease")
check_output_retention = importlib.import_module(f"{__package__ or 'agent_tools'}.check_output_retention")

try:  # The repository tests intentionally run without the optional MCP package.
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover - covered by launcher/integration smoke checks.
    FastMCP = None  # type: ignore[assignment]


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
VISUAL_RECEIPT_ROOT = INDEX_DIR / "visual-review-receipts"
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
    "run_checks(level='prepush'), then git_workflow for a checkpoint or final push and exact-SHA CI verification on dev. "
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
        [AGENT_TEST_PYTHON, "-m", "unittest", "discover", "-s", "agent_tools/tests", "-t", "."],
        ["./scripts/check_docs_hygiene.sh"],
    ],
}

PREPUSH_COMMANDS = [
    ["git", "diff", "--check"],
    ["./scripts/check_release_hygiene.sh"],
    ["./scripts/check_docs_hygiene.sh"],
    [AGENT_TEST_PYTHON, "-m", "unittest", "discover", "-s", "agent_tools/tests", "-t", "."],
    [sys.executable, "scripts/check_ui_theme.py"],
    [sys.executable, "scripts/test_visual_regression.py"],
    [sys.executable, "scripts/test_visual_platform.py"],
    [sys.executable, "scripts/test_visual_review.py"],
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
        ":app:verifyDebugAndroidTestSignatures",
    ],
    [sys.executable, "scripts/test_desktop_sdk_independence.py"],
    [sys.executable, "scripts/test_windows_packaging_graph.py"],
    [sys.executable, "scripts/test_android_instrumentation_signatures.py"],
    [sys.executable, "scripts/test_windows_install_admission_diagnostic.py"],
]

SENSITIVE_PARTS = {
    ".vm-hosts.local.json",
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

    try:
        with managed_check_lease.acquire(REPO_ROOT):
            return _run_check_commands(selected_area, level, commands)
    except managed_check_lease.ManagedCheckLeaseError as error:
        return _error("run_checks", str(error), blockers=[{"phase": "check-lease", "state": error.state}])


def _run_check_commands(selected_area: str, level: str, commands: list[list[str]]) -> dict[str, Any]:
    checked_fingerprint = _snapshot_fingerprint() if level == "prepush" else None
    results = []
    output_fingerprint = checked_fingerprint or hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    for index, command in enumerate(commands):
        def capture(returncode, stdout, stderr):
            return check_output_retention.retain_completed_output(
                REPO_ROOT, label=f"{level}-{index}", returncode=returncode,
                stdout=stdout, stderr=stderr, source_fingerprint=output_fingerprint)
        result = _run(command, timeout=50 * 60, output_capture=capture)
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
        if _snapshot_fingerprint() != checked_fingerprint:
            return _error(
                "run_checks",
                "Repository contents changed during validation; freeze edits and rerun pre-push checks.",
                command_results=results,
            )
        receipt = {
            "version": 1,
            "fingerprint": checked_fingerprint,
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
    target_version: str | None = None,
) -> dict[str, Any]:
    """Apply the repository's unified three-part version policy."""
    normalized_type = change_type.strip().lower().replace("-", "_")
    release_change = normalized_type in {"release", "release_artifact", "publish"}
    docs_only = normalized_type in {"docs", "documentation", "docs_only"}
    if force_release and not release_change:
        return _error("version_bump", "force_release requires a release-oriented change_type")
    if target_version is not None and not (force_release and release_change):
        return _error("version_bump", "target_version requires an explicitly forced release")
    if force_release and summary is not None and target_version is None:
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
        if target_version is not None:
            _parse_migration_source_version(current_version)
            _parse_version(target_version)
            if _version_build_id(target_version) < _version_build_id(current_version):
                raise ValueError("target_version must not be older than the current version")
        else:
            _parse_version(current_version)
        readme_version = _parse_required(README_VERSION_RE, readme_text, "README version")
        if readme_version != current_version:
            raise ValueError("README and Gradle versions do not match")
        unreleased = _unreleased_bullets(changelog_text)
    except (OSError, ValueError) as exc:
        return _error("version_bump", f"Could not read version metadata: {exc}")

    if force_release and not unreleased and not (summary or "").strip():
        return _error("version_bump", "Forced release requires non-empty Unreleased notes")
    bullet = _format_changelog_bullet(summary or "") if (summary or "").strip() else ""
    planned_bullets = [*unreleased, *([bullet] if bullet else [])]
    should_bump = force_release or len(planned_bullets) >= UNRELEASED_CHANGELOG_THRESHOLD
    next_version = target_version or (_increment_version(current_version) if should_bump else None)
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
            if next_version == current_version:
                updated_changelog = _append_to_current_release(
                    changelog_text,
                    current_version,
                    planned_bullets,
                )
            else:
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
            (
                f"Rolled release notes into VPN Control {next_version}."
                if next_version == current_version
                else f"Bumped VPN Control to {next_version}."
            )
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
            "visual_receipt_sha256": readiness["visual_receipt_sha256"],
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
            "-f", f"visual_receipt_sha256={receipt.get('visual_receipt_sha256', '')}",
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
        "result": {
            "sha": current_sha,
            "version": receipt.get("version"),
            "visual_receipt_sha256": receipt.get("visual_receipt_sha256"),
        },
        "command_results": [dispatched],
    }


def _visual_command(arguments: list[str]) -> dict[str, Any]:
    completed = _run([sys.executable, "scripts/visual_review.py", *arguments], timeout=30 * 60)
    if not completed["ok"]:
        message = str(completed.get("stdout") or completed.get("stderr") or "visual review command failed")
        try:
            parsed = json.loads(message)
            message = str(parsed.get("error", message)) if isinstance(parsed, dict) else message
        except json.JSONDecodeError:
            pass
        return _error("visual_workflow", message, command_results=[completed])
    try:
        payload = json.loads(str(completed.get("stdout") or "{}"))
    except json.JSONDecodeError as exc:
        return _error("visual_workflow", f"Invalid visual review output: {exc}", command_results=[completed])
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        return _error("visual_workflow", str(payload.get("error", "visual review failed")), command_results=[completed])
    return {
        "ok": True,
        "tool": "visual_workflow",
        "summary": "Visual review state updated.",
        "result": payload.get("result", {}),
        "command_results": [completed],
    }


def visual_workflow(
    action: str,
    target_sha: str | None = None,
    platforms: list[str] | None = None,
    release: bool = False,
    post_status: bool = False,
) -> dict[str, Any]:
    """Start, inspect, or complete an exact-SHA agent visual review."""
    if action not in {"start", "status", "complete"}:
        return _error("visual_workflow", "action must be 'start', 'status', or 'complete'")
    sha = target_sha or _git_stdout(["rev-parse", "HEAD"])
    if not SHA_RE.fullmatch(sha):
        return _error("visual_workflow", "target_sha must be a full lowercase commit SHA")
    arguments = [action, "--target-sha", sha]
    if action == "start":
        for platform_name in platforms or ["android", "linux", "windows", "macos"]:
            arguments.extend(["--platform", platform_name])
        if release:
            arguments.append("--release")
        if post_status:
            arguments.append("--post-status")
    elif action == "complete" and post_status:
        arguments.append("--post-status")
    return _visual_command(arguments)


def visual_review(
    target_sha: str,
    platform: str,
    scene_id: str,
    verdict: str,
    notes: str | None = None,
) -> dict[str, Any]:
    """Record the agent's verdict after it has opened a captured visual scene."""
    arguments = [
        "record", "--target-sha", target_sha, "--platform", platform,
        "--scene-id", scene_id, "--verdict", verdict,
    ]
    if notes:
        arguments.extend(["--notes", notes])
    result = _visual_command(arguments)
    if result.get("ok"):
        result["tool"] = "visual_review"
        result["summary"] = f"Recorded agent visual verdict for {platform}/{scene_id}."
    return result


def git_workflow(
    action: str,
    message: str | None = None,
    paths: list[str] | None = None,
    sha: str | None = None,
) -> dict[str, Any]:
    """Commit/push validated work, defer checkpoint CI, or verify an exact SHA."""
    if action not in {"commit", "checkpoint", "push", "checks"}:
        return _error("git_workflow", "action must be 'commit', 'checkpoint', 'push', or 'checks'")
    if action == "checks":
        target = sha or _git_stdout(["rev-parse", "HEAD"])
        if not SHA_RE.fullmatch(target):
            return _error("git_workflow", "sha must be a full 40-character lowercase commit SHA")
        return _watch_required_workflows(target)
    if action == "checkpoint" and sha is not None:
        return _error("git_workflow", "checkpoint derives its pushed SHA; sha input is not accepted")

    state = _repo_state()
    if state.get("branch") != WORK_BRANCH:
        return _error("git_workflow", "Commit and push operations require branch dev.")
    receipt_error = _receipt_error()
    if receipt_error:
        return _error("git_workflow", receipt_error)

    commands: list[dict[str, Any]] = []
    if action in {"commit", "checkpoint"}:
        if not message or not message.strip():
            return _error("git_workflow", "message is required for commit or checkpoint")
        requested = _unique(paths or [])
        if not requested:
            return _error("git_workflow", "Explicit paths are required for commit or checkpoint")
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
    if action == "checkpoint":
        if not SHA_RE.fullmatch(target):
            return _error("git_workflow", "Pushed checkpoint SHA could not be verified locally.",
                          command_results=commands)
        return {
            "ok": True,
            "tool": "git_workflow",
            "summary": "Pushed intermediate dev checkpoint; required exact-SHA workflows are deferred.",
            "result": {"sha": target, "branch": WORK_BRANCH,
                       "requiredWorkflowsVerified": False,
                       "deferredReason": "intermediate-checkpoint"},
            "command_results": commands,
        }
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
    visual_started = _visual_command(
        [
            "start", "--target-sha", sha,
            "--platform", "android", "--platform", "linux", "--platform", "windows",
            "--platform", "macos", "--release", "--post-status",
        ],
    )
    if not visual_started.get("ok"):
        return _error(
            "release_workflow",
            "main was updated and exhaustive VPN integration was dispatched, but agent visual review could not start.",
            blockers=[{"phase": "visual", "message": visual_started.get("summary", "visual start failed")}],
            command_results=commands + visual_started.get("command_results", []),
        )
    return {
        "ok": True,
        "tool": "release_workflow",
        "summary": "Fast-forwarded dev to main, dispatched exhaustive VPN integration, and started agent visual review.",
        "result": {"sha": sha, "visual_review": visual_started.get("result", {})},
        "command_results": commands + visual_started.get("command_results", []),
    }


def _json_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_file_digest(path: Path) -> str:
    return _json_digest(_read_json(path))


def _visual_attestation(sha: str) -> dict[str, Any]:
    blockers: list[dict[str, Any]] = []
    commands: list[dict[str, Any]] = []
    receipt_path = VISUAL_RECEIPT_ROOT / f"{sha}.json"
    receipt = _read_json(receipt_path)
    digest = ""
    if not receipt:
        blockers.append({"phase": "visual", "message": "agent visual review receipt is missing for the exact SHA"})
    else:
        digest = str(receipt.get("receipt_sha256", ""))
        payload = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        if receipt.get("target_sha") != sha:
            blockers.append({"phase": "visual", "message": "agent visual review receipt SHA does not match"})
        if receipt.get("release") is not True or set(receipt.get("platforms", [])) != {
            "android", "linux", "windows", "macos",
        }:
            blockers.append({"phase": "visual", "message": "agent visual review receipt is not a full release review"})
        if not digest or digest != _json_digest(payload):
            blockers.append({"phase": "visual", "message": "agent visual review receipt digest is invalid"})
        manifest = REPO_ROOT / "visual-tests" / "scenes.json"
        environments = REPO_ROOT / "visual-tests" / "environments.json"
        if not manifest.is_file() or receipt.get("manifest_sha256") != _json_file_digest(manifest):
            blockers.append({"phase": "visual", "message": "visual scene manifest changed after agent review"})
        if not environments.is_file() or receipt.get("environments_sha256") != _json_file_digest(environments):
            blockers.append({"phase": "visual", "message": "visual environment contract changed after agent review"})
        scenes = receipt.get("scenes")
        if not isinstance(scenes, dict) or not scenes:
            blockers.append({"phase": "visual", "message": "agent visual review receipt has no scenes"})
        elif any(
            not isinstance(scene, dict)
            or scene.get("automation") != "pass"
            or scene.get("review") != "pass"
            for scene in scenes.values()
        ):
            blockers.append({"phase": "visual", "message": "agent visual receipt contains an unpassed scene"})
        else:
            manifest_value = _read_json(manifest)
            expected_scenes = {
                f"{platform}/{scene.get('id')}"
                for scene in manifest_value.get("scenes", [])
                if isinstance(scene, dict) and isinstance(scene.get("platforms"), list)
                for platform in scene["platforms"]
                if platform in {"android", "linux", "windows", "macos"}
            }
            if set(scenes) != expected_scenes:
                blockers.append({"phase": "visual", "message": "agent visual receipt scene inventory is incomplete"})
            evidence_files: list[tuple[str, str, str]] = []
            for key, scene in scenes.items():
                for path_key, hash_key in (
                    ("actual", "actual_sha256"),
                    ("contact_sheet", "contact_sha256"),
                    ("geometry", "geometry_sha256"),
                ):
                    raw_path = str(scene.get(path_key, ""))
                    expected = str(scene.get(hash_key, ""))
                    if raw_path:
                        evidence_files.append((f"{key} {path_key}", raw_path, expected))
            for platform, report in receipt.get("reports", {}).items():
                if isinstance(report, dict):
                    evidence_files.append(
                        (f"{platform} report", str(report.get("path", "")), str(report.get("sha256", ""))),
                    )
            for platform, captures in receipt.get("captures", {}).items():
                if isinstance(captures, list):
                    for capture in captures:
                        if isinstance(capture, dict):
                            evidence_files.append(
                                (
                                    f"{platform} capture provenance",
                                    str(capture.get("path", "")),
                                    str(capture.get("sha256", "")),
                                ),
                            )
            for label, raw_path, expected in evidence_files:
                path = Path(raw_path)
                if not path.is_file() or not expected or _file_digest(path) != expected:
                    blockers.append({"phase": "visual", "message": f"visual evidence changed or is missing: {label}"})

    repository_result = _run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"], timeout=120,
    )
    commands.append(repository_result)
    status: dict[str, Any] | None = None
    if not repository_result["ok"] or not str(repository_result.get("stdout", "")).strip():
        blockers.append(_command_blocker("visual_status", repository_result))
    else:
        repository = str(repository_result["stdout"]).strip()
        status_result = _run(
            ["gh", "api", f"repos/{repository}/commits/{sha}/statuses", "--paginate"], timeout=120,
        )
        commands.append(status_result)
        if not status_result["ok"]:
            blockers.append(_command_blocker("visual_status", status_result))
        else:
            try:
                statuses = json.loads(str(status_result.get("stdout") or "[]"))
            except json.JSONDecodeError as exc:
                statuses = []
                blockers.append({"phase": "visual_status", "message": str(exc)})
            if isinstance(statuses, list):
                matches = [
                    value for value in statuses
                    if isinstance(value, dict) and value.get("context") == "vpn-control/agent-visual"
                ]
                status = max(matches, key=lambda value: int(value.get("id") or 0), default=None)
            if (
                not status
                or status.get("state") != "success"
                or not digest
                or digest[:16] not in str(status.get("description", ""))
            ):
                blockers.append({
                    "phase": "visual_status",
                    "message": "latest exact-SHA vpn-control/agent-visual status must match the local receipt",
                })
    return {
        "receipt": receipt,
        "receipt_sha256": digest,
        "status": status,
        "blockers": blockers,
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
        first_release = re.search(r"^##\s+([0-9]+(?:\.[0-9]+){2})\s+-", changelog_text, flags=re.MULTILINE)
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
    visual_attestation = _visual_attestation(sha)
    blockers.extend(visual_attestation["blockers"])
    command_results.extend(visual_attestation["command_results"])
    return {
        "sha": sha,
        "version": version,
        "tag": tag,
        "visual_receipt_sha256": visual_attestation["receipt_sha256"],
        "runs": {
            **latest,
            **({"VPN Integration": integration} if integration else {}),
            **({"Agent Visual Review": visual_attestation["status"]} if visual_attestation["status"] else {}),
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
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ValueError("Version must have three numeric parts")
    values = [int(part) for part in parts]
    if values[0] < 1 or any(value < 0 or value > 19 for value in values):
        raise ValueError("Version major must be 1..19 and other components must be 0..19")
    return values


def _parse_migration_source_version(version: str) -> list[int]:
    parts = version.split(".")
    if len(parts) not in {3, 4} or any(not part.isdigit() for part in parts):
        raise ValueError("Migration source version must have three or four numeric parts")
    values = [int(part) for part in parts]
    if any(value < 0 or value > 19 for value in values):
        raise ValueError("Version components must be between 0 and 19")
    return values


def _version_build_id(version: str) -> int:
    values = _parse_migration_source_version(version)
    if len(values) == 3:
        values.append(0)
    result = 0
    for value in values:
        result = result * 20 + value
    return result


def _increment_version(version: str) -> str:
    values = _parse_version(version)
    for index in range(2, -1, -1):
        if values[index] < 19:
            values[index] += 1
            for reset_index in range(index + 1, 3):
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


def _append_to_current_release(text: str, version: str, bullets: list[str]) -> str:
    """Roll Unreleased notes into an unpublished, already-versioned release section."""
    bounds = _unreleased_bounds(text)
    if bounds is None:
        raise ValueError("Changelog is missing Unreleased")
    start, _, end = bounds
    remaining = text[:start] + text[end:].lstrip("\n")
    heading = re.compile(rf"^##\s+{re.escape(version)}\s+-[^\n]*$", flags=re.MULTILINE)
    match = heading.search(remaining)
    if match is None:
        raise ValueError(f"Changelog is missing the current {version} release section")
    body_start = match.end()
    next_heading = re.search(r"^##\s+", remaining[body_start:], flags=re.MULTILINE)
    body_end = body_start + next_heading.start() if next_heading else len(remaining)
    current_body = remaining[body_start:body_end].strip()
    appended = "\n".join([part for part in (current_body, *bullets) if part])
    updated_section = f"{remaining[match.start():body_start]}\n\n{appended}\n\n"
    return remaining[:match.start()] + updated_section + remaining[body_end:].lstrip("\n")


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
                log = _run(["gh", "run", "view", run_id, "--log-failed"], timeout=180, output_limit=None)
                logs.append({"workflow": name, "run_id": run_id, "excerpt": _failure_log_excerpt(log.get("stdout") or log.get("stderr"))})
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


def _failure_log_excerpt(value: Any, limit: int = 8000) -> str:
    """Keep causal error context and the final summary within the MCP bound."""
    text = str(value or "")
    if len(text) <= limit:
        return text
    lines = text.splitlines(keepends=True)
    error = re.compile(r"FAIL(?:ED)?[: ]|ERROR[: ]|Traceback |AssertionError|Exception|\berror:|##\[error\]")
    selected: list[str] = []
    end = 0
    for index, line in enumerate(lines):
        if not error.search(line):
            continue
        start = max(end, index - 2)
        stop = min(len(lines), index + 25)
        if start >= stop:
            continue
        if start > end:
            selected.append("\n...[context omitted]...\n")
        selected.extend(lines[start:stop])
        end = stop
        if sum(map(len, selected)) >= limit - 1600:
            break
    if not selected:
        marker = "...[earlier output omitted]...\n"
        return marker + text[-(limit - len(marker)):]
    marker = "\n...[remaining context omitted; log tail follows]...\n"
    tail = text[-1500:]
    return "".join(selected)[:limit - len(marker) - len(tail)] + marker + tail


def _run(
    command: list[str],
    timeout: int = 120,
    output_limit: int | None = MAX_OUTPUT_CHARS,
    output_capture=None,
) -> dict[str, Any]:
    try:
        environment = local_build_environment.apply(REPO_ROOT, dict(os.environ))
    except local_build_environment.LocalBuildEnvironmentError as exc:
        return {"ok": False, "command": _display(command), "returncode": None,
                "stdout": "", "stderr": str(exc)}
    environment.pop("DYLD_INSERT_LIBRARIES", None)
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            text=output_capture is None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            env=environment,
        )
        retention = None
        retention_error = None
        if output_capture is not None:
            try:
                retention = output_capture(completed.returncode, completed.stdout, completed.stderr)
            except (check_output_retention.RetentionError, OSError) as error:
                # A completed child remains completed; failure to retain its
                # evidence must not produce a successful validation receipt.
                retention_error = (str(error) if isinstance(error, check_output_retention.RetentionError)
                                   else "retention_io_error")
        def excerpt(value: Any) -> str:
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            if completed.returncode == 0 or output_limit is None:
                return _bounded(value, output_limit)
            if output_limit <= 0:
                return ""
            # Keep causal failures and the terminal summary after noisy setup.
            # The existing extractor needs room for its marker and tail; apply
            # the caller's exact cap after extracting for very small limits.
            return _failure_log_excerpt(_bounded(value, None), max(2000, output_limit))[-output_limit:]
        return {
            "ok": completed.returncode == 0 and retention_error is None,
            "command": _display(command),
            "returncode": completed.returncode,
            "stdout": excerpt(completed.stdout),
            "stderr": excerpt(completed.stderr),
            **({"completionOutput": retention,
                "completionOutputScope": "repository" if retention and retention["label"].startswith("prepush-") else "runner-source"}
               if retention is not None else {}),
            **({"retentionError": retention_error} if retention_error is not None else {}),
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
    text = str(value or "")
    text = re.sub(
        r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ [^\r\n]+\[\d+:\d+\] "
        r"\[AppleSharpener\] (?:Windows: Loaded enableSharpener: [01], customRadius: [\d.]+|"
        r"Not in Dock process \(bundle ID: [^\r\n]*\), skipping setup)\r?\n?",
        "", text, flags=re.MULTILINE,
    ).strip()
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


def _ssh_channel_workflow(action: str, host: str | None, timeout_seconds: int,
                          identity: dict[str, Any] | None, transfer: Any, device: Any) -> dict[str, Any]:
    """Expose connection admission without commands, paths or private captures."""
    unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown",
               "connectionOnly": True, "replayAllowed": False, "nativeActionAllowed": False,
               "failurePhase": "input", "reason": "invalid_channel_input"}
    method = action.removeprefix("connection-channel-")
    selected = False
    try:
        if (host != "archlinux" or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
                or transfer is not None or device is not None or type(identity) is not dict):
            return unknown
        fields = {"correlationId"}
        if method == "ensure" and "receiptSha256" in identity:
            fields.add("receiptSha256")
        if (set(identity) != fields or type(identity["correlationId"]) is not str
                or not _valid_uuid(identity["correlationId"])):
            return unknown
        digest = identity.get("receiptSha256")
        if "receiptSha256" in identity and (type(digest) is not str or re.fullmatch("[0-9a-f]{64}", digest) is None):
            return unknown
        correlation = uuid.UUID(identity["correlationId"]).hex
        unknown = {**unknown, "failurePhase": "parser", "reason": "invalid_channel_result",
                   "correlationId": identity["correlationId"], "requestedCorrelationId": identity["correlationId"]}
        adapter = importlib.import_module(f"{__package__ or 'agent_tools'}.ssh_fresh_nested_channel")
        source_fingerprint = hashlib.sha256(Path(adapter.__file__).read_bytes()).hexdigest()
        def retain_capture(capture):
            check_output_retention.retain_observation_capture(
                REPO_ROOT, label="ssh-channel-" + method + "-" + correlation,
                capture=capture, source_fingerprint=source_fingerprint)
        if method == "ensure":
            result = adapter.ensure_channel(REPO_ROOT, host, correlation, digest,
                                            _private_capture=retain_capture)
        else:
            result = getattr(adapter, method)(REPO_ROOT, host, correlation,
                                               _private_capture=retain_capture)
        if type(result) is not dict:
            return unknown
        if method == "ensure" and "outerOptions" in result:
            if set(result) != {"correlationId", "receiptSha256", "outerReceiptSha256", "outerOptions", "innerOptions"}:
                return unknown
            candidate = result["correlationId"]
            if type(candidate) is not str or re.fullmatch("[0-9a-f]{32}", candidate) is None:
                return unknown
            suffix = ("-o", "ControlMaster=no", "-o", "ControlPersist=no", "-o", "ProxyCommand=false")
            outer = result["outerOptions"]
            inner = result["innerOptions"]
            if (type(outer) is not tuple or len(outer) != 8 or outer[0] != "-S"
                    or type(outer[1]) is not str or not outer[1].startswith("/") or len(outer[1].encode()) > 85
                    or outer[2:] != suffix or type(inner) is not tuple
                    or inner != ("-S", "/tmp/vpn-channel-" + candidate + "/m", *suffix)):
                return unknown
            if any(type(result[key]) is not str or re.fullmatch("[0-9a-f]{64}", result[key]) is None
                   for key in ("receiptSha256", "outerReceiptSha256")):
                return unknown
            unknown = {**unknown, "failurePhase": "selection",
                       "correlationId": str(uuid.UUID(candidate))}
            selector = importlib.import_module(f"{__package__ or 'agent_tools'}.ssh_channel_selection")
            publication = selector.select_channel(REPO_ROOT, host, candidate, result["receiptSha256"])
            expected = {"state": "selected", "host": host, "correlationId": candidate,
                        "receiptSha256": result["receiptSha256"]}
            if type(publication) is dict and publication == expected:
                selected = True
                result = {"state": "ready", "correlationId": candidate,
                          "receiptSha256": result["receiptSha256"], "outerReceiptSha256": result["outerReceiptSha256"],
                          "nativeActionAllowed": False, "replayAllowed": False}
            elif type(publication) is dict and publication.get("state") == "unknown":
                if type(publication.get("correlationId")) is not str or publication["correlationId"] != candidate:
                    return unknown
                result = {"correlationId": candidate, "failurePhase": "selection", **publication}
            else:
                return unknown
        if (result.get("nativeActionAllowed") is not False or result.get("replayAllowed") is not False
                or type(result.get("state")) is not str or result["state"] not in {"ready", "ended", "unknown"}):
            return unknown
        state = result["state"]
        base = {"state", "nativeActionAllowed", "replayAllowed"}
        candidate = result.get("correlationId", correlation)
        if (type(candidate) is not str or re.fullmatch("[0-9a-f]{32}", candidate) is None
                or (method != "ensure" and candidate != correlation)):
            return unknown
        public = {**{key: value for key, value in unknown.items() if key not in {"failurePhase", "reason"}},
                  "correlationId": str(uuid.UUID(candidate)),
                  "requestedCorrelationId": identity["correlationId"]}
        if state == "unknown":
            diagnostic_fields = {"failureReason", "exceptionClass", "errno"}
            if set(result) - (base | {"correlationId", "failurePhase", "reason"} | diagnostic_fields):
                return unknown
            supplied = set(result) & diagnostic_fields
            if supplied:
                if (supplied != diagnostic_fields or "failurePhase" not in result
                        or type(result["failureReason"]) is not str
                        or result["failureReason"] not in adapter._REMOTE_REASONS
                        or type(result["exceptionClass"]) is not str
                        or result["exceptionClass"] not in adapter._EXCEPTION_CLASSES
                        or (result["errno"] is not None
                            and (type(result["errno"]) is not int or not 0 <= result["errno"] <= 255))):
                    return unknown
                public.update({key: result[key] for key in diagnostic_fields})
            phases = {"input", "inventory", "route", "channel_journal", "outer_receipt", "outer_reuse", "intent",
                      "transport", "capture_retention", "parser", "closing", "prepare_stage", "launch", "remote_intent",
                      "master_snapshot", "arch_identity", "master_closing", "publication", "selection"}
            reasons = {"outer_prompt_unavailable", "credential_unavailable", "intent_absent", "intent_binding_changed"}
            public.update(failurePhase="parser", reason="channel_admission_unknown")
            for key, choices in (("failurePhase", phases), ("reason", reasons)):
                if key in result:
                    if type(result[key]) is not str or result[key] not in choices:
                        return unknown
                    public[key] = result[key]
            return public
        if state == "ended":
            if set(result) != base | {"correlationId"}:
                return unknown
            return {**public, "ok": True, "state": "ended"}
        if set(result) != base | {"correlationId", "receiptSha256", "outerReceiptSha256"}:
            return unknown
        if any(type(result[key]) is not str or re.fullmatch("[0-9a-f]{64}", result[key]) is None
               for key in ("receiptSha256", "outerReceiptSha256")):
            return unknown
        return {**public, "ok": True, "state": "ready", "receiptSha256": result["receiptSha256"],
                "outerReceiptSha256": result["outerReceiptSha256"], **({"selected": True} if selected else {})}
    except (OSError, ValueError, TypeError, KeyError, ImportError, AttributeError):
        return unknown


def _ssh_workflow_impl(action: str = "inventory", host: str | None = None, timeout_seconds: int = 15, identity: dict[str, Any] | None = None, transfer: dict[str, Any] | None = None, device: str | None = None) -> dict[str, Any]:
    """Inspect configured SSH hosts, recover a nested connection, or transfer owned fixture helpers."""
    if action in {"connection-channel-prepare", "connection-channel-status", "connection-channel-ensure"}:
        return _ssh_channel_workflow(action, host, timeout_seconds, identity, transfer, device)
    transport = importlib.import_module(f"{__package__}.ssh_transport" if __package__ else "ssh_transport")
    try:
        if action in {"connection-master-status", "gateway-tmux-status-diagnostic"}:
            unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown",
                       "diagnosticOnly": True, "replayAllowed": False,
                       "launchAllowed": False, "nativeActionAllowed": False}
            try:
                if (host != "archlinux" or type(timeout_seconds) is not int
                        or not 1 <= timeout_seconds <= 60 or transfer is not None or device is not None):
                    return unknown
                if action == "connection-master-status":
                    if identity is not None:
                        return unknown
                    adapter = importlib.import_module(f"{__package__}.ssh_connection_recovery" if __package__ else "ssh_connection_recovery")
                    result = adapter.configured_master_fenced_status(REPO_ROOT, host, timeout_seconds)
                    if (type(result) is not dict
                            or set(result) != {"nestedState", "socketState", "failurePhase", "replayAllowed", "launchAllowed", "nativeActionAllowed"}
                            or type(result["nestedState"]) is not str or result["nestedState"] not in {"ready", "unknown", "absent"}
                            or type(result["socketState"]) is not str or result["socketState"] not in {"ready", "unknown", "absent", "refused"}
                            or type(result["failurePhase"]) is not str or result["failurePhase"] not in {
                                "configuration", "outer_admission", "socket_query", "closing_admission", "socket_parser", "capture_retention", "none"}
                            or any(result[k] is not False for k in ("replayAllowed", "launchAllowed", "nativeActionAllowed"))):
                        return unknown
                    if result["nestedState"] in {"ready", "absent"}:
                        if result["socketState"] != result["nestedState"] or result["failurePhase"] != "none":
                            return unknown
                    elif (result["socketState"] not in {"unknown", "refused"}
                          or result["failurePhase"] == "none"
                          or (result["socketState"] == "refused" and result["failurePhase"] != "socket_parser")):
                        return unknown
                    return {**unknown, **result, "ok": result["nestedState"] != "unknown",
                            "state": "observed" if result["nestedState"] != "unknown" else "unknown"}
                if (type(identity) is not dict or set(identity) != {"correlationId"}
                        or type(identity["correlationId"]) is not str or not _valid_uuid(identity["correlationId"])):
                    return unknown
                adapter = _agent_module("ssh_gateway_tmux_master_ssh")
                result = adapter.configured_status_diagnostic(REPO_ROOT, dict(identity))
                if type(result) is not dict or result.get("nativeActionAllowed") is not False or result.get("replayAllowed") is not False:
                    return unknown
                if result.get("state") == "unknown":
                    if (set(result) != {"state", "replayAllowed", "failurePhase", "nativeActionAllowed"}
                            or type(result["failurePhase"]) is not str or result["failurePhase"] not in {"source", "config", "authority", "localmaster", "remotequery", "parser"}):
                        return unknown
                    return {**unknown, **result}
                fields = {"state", "correlationId", "replayAllowed", "nativeActionAllowed"}
                if result.get("correlationId") != identity["correlationId"]:
                    return unknown
                if result.get("state") == "prepared":
                    if set(result) != fields:
                        return unknown
                elif result.get("state") == "ended":
                    if set(result) != fields | {"exitCode"} or type(result["exitCode"]) is not int:
                        return unknown
                elif result.get("state") == "ready":
                    if (set(result) != fields | {"readyPin", "controlPath", "recoveryCorrelationId", "adoptionAllowed"}
                            or result["adoptionAllowed"] is not False
                            or result["recoveryCorrelationId"] != identity["correlationId"].replace("-", "")
                            or type(result["controlPath"]) is not str or not result["controlPath"].startswith("/")
                            or len(result["controlPath"].encode()) > 85):
                        return unknown
                    adapter.valid_pin(result["readyPin"])
                else:
                    return unknown
                return {**unknown, **{k: v for k, v in result.items() if k != "controlPath"}, "ok": True}
            except (OSError, ValueError, TypeError, KeyError, AttributeError, ImportError, subprocess.SubprocessError):
                return unknown
        if action == "tmux-disconnect-probe":
            unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown",
                       "replayAllowed": False, "productAcceptance": False}
            if (host != "archlinux" or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
                    or transfer is not None or device is not None or type(identity) is not dict
                    or set(identity) != {"hop", "correlationId"}
                    or identity["hop"] not in ("gateway", "archlinux")
                    or type(identity["correlationId"]) is not str or not _valid_uuid(identity["correlationId"])):
                return unknown
            probe = None
            try:
                adapter = _agent_module("ssh_tmux_disconnect_probe")
                probe = adapter.Probe(REPO_ROOT, identity["hop"], identity["correlationId"])
                for method, expected in ((probe.prepare, "prepared"), (probe.release, "released"),
                                         (probe.disconnect, "disconnected")):
                    result = method()
                    if (type(result) is not dict or set(result) != {"state", "replayAllowed"}
                            or result["state"] != expected or result["replayAllowed"] is not False):
                        return unknown
                deadline = time.monotonic() + 35
                while True:
                    result = probe.observe()
                    if (type(result) is not dict
                            or set(result) != {"state", "sequence", "replayAllowed", "productAcceptance"}
                            or result["state"] not in ("prepared", "released", "running", "completed")
                            or type(result["sequence"]) is not int or not 0 <= result["sequence"] <= 20
                            or result["replayAllowed"] is not False or result["productAcceptance"] is not False):
                        return unknown
                    if result["state"] == "completed":
                        if result["sequence"] != 20:
                            return unknown
                        return {"tool": "ssh_workflow", "ok": True, **result,
                                "hop": identity["hop"], "correlationId": identity["correlationId"]}
                    if time.monotonic() >= deadline:
                        return unknown
                    time.sleep(4)
            except (OSError, ValueError, TypeError, KeyError, ImportError, subprocess.SubprocessError):
                return unknown
            finally:
                if probe is not None:
                    probe.close()
        if action == "gateway-tmux-reconciliation-status":
            unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown", "replayAllowed": False}
            if (host != "archlinux" or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
                    or any(value is not None for value in (identity, transfer, device))):
                return unknown
            try:
                adapter = _agent_module("ssh_gateway_tmux_reconciliation_status")
                result = adapter.observe(REPO_ROOT)
                if (type(result) is not dict
                        or set(result) != {"state", "replayAllowed", "launchAllowed", "adoptionAllowed"}
                        or result["state"] not in ("published", "adopted", "unknown")
                        or any(result[key] is not False for key in
                               ("replayAllowed", "launchAllowed", "adoptionAllowed"))):
                    return unknown
                return {"tool": "ssh_workflow", "ok": result["state"] != "unknown", **result}
            except (OSError, ValueError, TypeError, ImportError):
                return unknown
        if action in ("gateway-tmux-availability", "gateway-tmux-prepare", "gateway-tmux-release", "gateway-tmux-status"):
            unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown", "replayAllowed": False}
            method = action.removeprefix("gateway-tmux-")
            if (host != "archlinux" or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
                    or transfer is not None or device is not None):
                return unknown
            if method == "availability":
                if identity is not None:
                    return unknown
                inputs = {}
            else:
                if (type(identity) is not dict or set(identity) != {"correlationId"}
                        or not isinstance(identity["correlationId"], str) or not _valid_uuid(identity["correlationId"])):
                    return unknown
                inputs = dict(identity)
            try:
                adapter = _agent_module("ssh_gateway_tmux_master_ssh")
                result = adapter.operate(REPO_ROOT, method, inputs)
                if type(result) is not dict:
                    return unknown
                if method == "availability":
                    if (set(result) != {"available", "reason", "nativeActionAllowed"}
                            or type(result["available"]) is not bool or result["nativeActionAllowed"] is not False
                            or result["reason"] != ("available" if result["available"] else "tmux_unavailable")):
                        return unknown
                    return {"tool": "ssh_workflow", "ok": True, **result}
                if result.get("replayAllowed") is not False or result.get("correlationId") != inputs["correlationId"]:
                    return unknown
                state = result.get("state")
                fields = {"state", "correlationId", "replayAllowed"}
                if method == "prepare":
                    if state != "prepared" or set(result) != fields | {"anchorPin"}:
                        return unknown
                    adapter.valid_pin(result["anchorPin"])
                elif method == "release":
                    if state != "released" or set(result) != fields:
                        return unknown
                elif state == "ready":
                    if (set(result) != fields | {"readyPin", "controlPath", "recoveryCorrelationId", "adoptionAllowed"}
                            or result["adoptionAllowed"] is not False
                            or result["recoveryCorrelationId"] != inputs["correlationId"].replace("-", "")
                            or not isinstance(result["controlPath"], str) or not result["controlPath"].startswith("/")
                            or len(result["controlPath"].encode()) > 85):
                        return unknown
                    adapter.valid_pin(result["readyPin"])
                elif state == "ended":
                    if set(result) != fields | {"exitCode"} or type(result["exitCode"]) is not int:
                        return unknown
                elif state != "prepared" or set(result) != fields:
                    return unknown
                return {"tool": "ssh_workflow", "ok": True, **{k: v for k, v in result.items() if k != "controlPath"}}
            except (OSError, ValueError, TypeError, ImportError):
                return unknown
        if action in {"connection-nested-orphan-archive", "connection-nested-orphan-archive-status", "android-availability"}:
            transport._session_module()
            routes = importlib.import_module(f"{__package__}.ssh_acceptance_observation_routes" if __package__ else "agent_tools.ssh_acceptance_observation_routes")
            return routes.dispatch(REPO_ROOT, action, host, timeout_seconds, identity, transfer, device)
        if action == "inventory":
            return {"ok": True, "tool": "ssh_workflow", "hosts": list(transport.inventory(REPO_ROOT))}
        if action == "probe" and host:
            return {"tool": "ssh_workflow", **transport.probe(REPO_ROOT, host, timeout_seconds).as_dict()}
        if action in ("connection-session-close", "connection-session-close-status"):
            unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown", "replayAllowed": False}
            if (not isinstance(host, str) or not transport._ALIAS_RE.fullmatch(host)
                    or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
                    or transfer is not None or device is not None
                    or not isinstance(identity, dict) or set(identity) != {"receiptSha256"}
                    or not isinstance(identity["receiptSha256"], str)
                    or re.fullmatch(r"[0-9a-f]{64}", identity["receiptSha256"]) is None):
                return unknown
            try:
                transport._session_module()
                close = _agent_module("ssh_connection_session_close")
                operation = close.close if action == "connection-session-close" else close.status
                result = operation(REPO_ROOT, host, identity["receiptSha256"])
            except (OSError, ValueError, TypeError, ImportError):
                return unknown
            state = "exit_sent" if action == "connection-session-close" else "closed"
            if result == {"state": "unknown", "host": host, "replayAllowed": False}:
                return unknown
            if (not isinstance(result, dict) or result.get("replayAllowed") is not False
                    or result != {"state": state, "host": host, "receiptSha256": identity["receiptSha256"], "replayAllowed": False}):
                return unknown
            return {"tool": "ssh_workflow", "ok": True, **result}
        if action in ("connection-session-retire", "connection-session-retirement-status"):
            unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown", "replayAllowed": False}
            if (not isinstance(host, str) or not transport._ALIAS_RE.fullmatch(host)
                    or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
                    or transfer is not None or device is not None
                    or not isinstance(identity, dict) or set(identity) != {"receiptSha256"}
                    or not isinstance(identity["receiptSha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", identity["receiptSha256"])):
                return unknown
            try:
                # Match the transport's package bootstrap for fresh CLI scripts.
                transport._session_module()
                retirement = importlib.import_module(f"{__package__}.ssh_connection_session_retirement" if __package__ else "agent_tools.ssh_connection_session_retirement")
                operation = retirement.retire if action == "connection-session-retire" else retirement.status
                result = operation(REPO_ROOT, host, identity["receiptSha256"])
            except (OSError, ValueError, TypeError, ImportError):
                return unknown
            if (not isinstance(result, dict) or result.get("replayAllowed") is not False
                    or result != {"state": "retired", "host": host, "receiptSha256": identity["receiptSha256"], "replayAllowed": False}):
                return unknown
            return {"tool": "ssh_workflow", "ok": True, **result}
        if action in ("connection-session-prepare", "connection-session-status"):
            unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown", "replayAllowed": False}
            if (not isinstance(host, str) or not transport._ALIAS_RE.fullmatch(host)
                    or type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60
                    or transfer is not None or device is not None):
                return unknown
            status = action == "connection-session-status"
            if status:
                if (not isinstance(identity, dict) or set(identity) != {"receiptSha256"}
                        or not isinstance(identity["receiptSha256"], str)
                        or not re.fullmatch(r"[0-9a-f]{64}", identity["receiptSha256"])):
                    return unknown
            elif identity is not None:
                return unknown
            try:
                session = transport._session_module()
                result = (session.admission(REPO_ROOT, host, identity["receiptSha256"]) if status
                          else session.prepare(REPO_ROOT, host))
            except (OSError, ValueError, TypeError, ImportError):
                return unknown
            if not isinstance(result, dict) or result.get("host") != host:
                return unknown
            if result.get("state") == "ready":
                keys = {"state", "host", "receiptSha256"} | (set() if status else {"created"})
                if (set(result) != keys or not isinstance(result.get("receiptSha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", result["receiptSha256"])
                        or not status and type(result.get("created")) is not bool
                        or status and result["receiptSha256"] != identity["receiptSha256"]):
                    return unknown
                return {"tool": "ssh_workflow", "ok": True, "replayAllowed": False, **result}
            if (set(result) == {"state", "host", "phase"} and result.get("state") == "unknown"
                    and result.get("phase") in session._PHASES):
                return {**unknown, "host": host, "phase": result["phase"]}
            return unknown
        if action == "connection-recover" and host:
            recovery = importlib.import_module(f"{__package__}.ssh_connection_recovery" if __package__ else "ssh_connection_recovery")
            return {"tool": "ssh_workflow", "host": host, **recovery.recover(REPO_ROOT, host, timeout_seconds)}
        if action == "connection-adopt":
            unknown = {"tool": "ssh_workflow", "ok": False, "state": "unknown", "replayAllowed": False}
            if (not isinstance(host, str) or not host or type(timeout_seconds) is not int
                    or not 1 <= timeout_seconds <= 60 or any(value is not None for value in (identity, transfer, device))):
                return unknown
            adoption = importlib.import_module(f"{__package__}.ssh_recovery_adoption" if __package__ else "ssh_recovery_adoption")
            try:
                result = adoption.adopt(REPO_ROOT, host, timeout_seconds)
            except (OSError, ValueError, TypeError):
                return unknown
            if (not isinstance(result, dict) or set(result) != {"state", "nextAction", "replayAllowed"}
                    or result.get("replayAllowed") is not False
                    or (result.get("state"), result.get("nextAction")) not in
                    (("ready", "configured-probe"), ("unknown", "inspect-recovery"))):
                return unknown
            return {"tool": "ssh_workflow", "host": host, "ok": result["state"] == "ready", **result}
        if action in ("forward-open", "forward-status", "forward-close") and host:
            forward = importlib.import_module(f"{__package__}.ssh_forward" if __package__ else "ssh_forward")
            if action == "forward-open":
                result = forward.open_forward(REPO_ROOT, host)
            elif action == "forward-status":
                result = forward.status(REPO_ROOT, host)
            else:
                result = forward.close(REPO_ROOT, identity or {}, host)
            return {"tool": "ssh_workflow", **result}
        if action in ("apk-publish", "apk-status") and host:
            publisher = importlib.import_module(f"{__package__}.ssh_transfer" if __package__ else "ssh_transfer")
            try:
                if action == "apk-status":
                    result = publisher.android_apk_stage_status(REPO_ROOT, host, identity or {}, timeout_seconds=timeout_seconds)
                else:
                    required = {"apkPath", "manifestPath", "receiptPath", "owner", "environment", "correlationId"}
                    if not isinstance(transfer, dict) or set(transfer) != required or any(not isinstance(value, str) or not value for value in transfer.values()):
                        return _error("ssh_workflow", "APK publication requires exactly apkPath, manifestPath, receiptPath, owner, environment and correlationId as nonempty strings.")
                    result = publisher.publish_android_apk(REPO_ROOT, host, transfer["apkPath"], transfer["manifestPath"],
                        transfer["receiptPath"], transfer["owner"], transfer["environment"], transfer["correlationId"], timeout_seconds=timeout_seconds)
                return {"tool": "ssh_workflow", **result}
            except publisher.SshTransferError as error:
                return _error("ssh_workflow", str(error))
        if action == "android-observe" and host and device:
            configured = transport.load_config(REPO_ROOT).hosts.get(host)
            if configured is None or device not in configured.android_devices:
                return _error("ssh_workflow", "Unknown configured Android device alias.")
            observer = importlib.import_module(f"{__package__}.android_observation" if __package__ else "android_observation")
            try:
                result = observer.observe(REPO_ROOT, host, configured.android_devices[device], timeout_seconds)
                return {"tool": "ssh_workflow", "ok": result.get("available") is True, **result}
            except observer.AndroidObservationError as error:
                return _error("ssh_workflow", str(error))
        if action == "job-status" and host and identity:
            jobs = importlib.import_module(f"{__package__}.ssh_jobs" if __package__ else "ssh_jobs")
            try:
                return {"tool": "ssh_workflow", **jobs.observe(REPO_ROOT, host, identity, timeout_seconds).as_dict()}
            except jobs.SshJobError as error:
                return _error("ssh_workflow", str(error))
        if action in ("fixture-publish", "fixture-status") and host:
            publisher = importlib.import_module(f"{__package__}.ssh_transfer" if __package__ else "ssh_transfer")
            try:
                if action == "fixture-status":
                    result = publisher.status(REPO_ROOT, host, identity or {}, timeout_seconds=timeout_seconds)
                else:
                    required = {"sourceDirectory", "owner", "environment", "correlationId"}
                    if not isinstance(transfer, dict) or set(transfer) != required:
                        return _error("ssh_workflow", "Fixture publication requires sourceDirectory, owner, environment and correlationId.")
                    if any(not isinstance(value, str) or not value for value in transfer.values()):
                        return _error("ssh_workflow", "Fixture publication fields must be nonempty strings.")
                    result = publisher.publish(REPO_ROOT, host, transfer["sourceDirectory"], transfer["owner"],
                                               transfer["environment"], transfer["correlationId"], timeout_seconds=timeout_seconds)
                return {"tool": "ssh_workflow", **result}
            except publisher.SshTransferError as error:
                return _error("ssh_workflow", str(error))
        return _error("ssh_workflow", "Use inventory, probe, or job-status with a configured host alias and job identity.")
    except transport.SshConfigError:
        return _error("ssh_workflow", "Private host configuration is missing or invalid; check the documented schema and permissions.")


def _native_fixed_dispatch(surface: str, action: str, inputs: dict[str, Any]) -> dict[str, Any]:
    """Dispatch only existing fixed adapters; batches cannot invoke arbitrary tools."""
    vm_actions = {"artifact-verify", "bundle-verify", "environment-status", "credential-status",
                  "windows-credential-probe-start", "windows-credential-probe-status",
                  "windows-vm-swtpm-repair-preflight", "windows-vm-swtpm-repair-start", "windows-vm-swtpm-repair-status",
                  "windows-vm-swtpm-owner-observe",
                  "scenario-start", "scenario-status", "scenario-resume", "scenario-collect",
                  "rpm-public-install-start", "rpm-public-install-status", "rpm-public-install-collect"}
    ssh_actions = {"inventory", "probe", "job-status", "android-observe"}
    if surface == "vm" and action in vm_actions:
        return _vm_workflow_impl(action, inputs)
    if surface == "ssh" and action in ssh_actions:
        if set(inputs) - {"host", "timeout_seconds", "identity", "device"}:
            raise ValueError("Fixed SSH adapter received unsupported fields.")
        return _ssh_workflow_impl(action=action, **inputs)
    raise ValueError("Native batch adapter is not allowlisted.")


_VM_NATIVE_ADAPTERS = (
    "native_review_source_closure",
    "ssh_tmux_disconnect_probe",
    "ssh_gateway_tmux_master_ssh",
    "ssh_gateway_tmux_reconciliation_status",
    "ssh_connection_session_close",
    "windows_cp117_cp95_task_retire", "windows_cp117_e848_http_task_retire", "windows_cp117_c32_retained_task_retire", "windows_cp117_source_pre_effect_close",
    "windows_cp117_cp95_retained_tasks", "windows_cp117_e848_http_task",
    "native_vm_baseline_config", "native_vm_baseline_inventory", "native_acceptance_matrix", "native_fixture_preflight",
    "native_scenario_batch", "native_artifact_reuse", "native_acceptance_overview", "native_scenario_execution",
    "native_scenario_ssh", "native_artifact_registry", "native_environment",
    "native_environment_observation", "native_scenario_bundle", "native_next_action",
    "native_response_diagnostics", "native_build_timing", "native_parity_response_projection",
    "native_failure_evidence", "macos_installer_recovery", "native_rpm_public_install_adapter",
    "native_rpm_public_install_ssh", "android_admission_readback", "windows_msi_public_scenario", "windows_vm_swtpm_repair",
    "linux_update_fixture_workflow", "linux_rpm_fixture_server_lifecycle", "linux_rpm_workspace_recovery", "linux_vm_readonly_inventory", "arch_ai_loop_observe", "arch_qemu_holder_census", "windows_vm_baseline_inventory", "windows_parallel_vm_source_inventory", "windows_parallel_vm_prepare_transport", "windows_vm_secureboot_inventory", "windows_vm_virt_firmware_admission", "windows_vm_virt_firmware_install", "windows_vm_secureboot_clone", "windows_vm_secureboot_fresh", "windows_vm_driver_fetch", "windows_vm_fresh_setup", "windows_vm_optical_boot", "windows_vm_optical_boot_attempt2", "windows_vm_optical_boot_attempt3", "windows_vm_optical_post_collect", "windows_vm_optical_current_screen", "windows_update_fixture_workflow", "windows_update_fixture_server", "linux_rpm_base_prepare", "linux_rpm_protected_job_observe", "linux_owner_public_quit", "windows_msi_base_prepare", "windows_msi_transfer_endpoint", "windows_msi_http_transfer", "windows_msiexec_service_diagnostic",
    "windows_msi_owner_observe", "windows_msi_owner_census", "windows_msi_owner_diagnostic", "windows_msi_owner_liveness", "windows_msi_stale_lock_recovery", "windows_msi_stale_lock_reconcile", "windows_msi_owner_relaunch", "windows_msi_owner_public_status", "windows_msi_owner_public_status_retry", "windows_msi_owner_public_status_third", "windows_msi_owner_relaunch_quit", "windows_msi_owner_relaunch_quit_v2", "windows_msi_owner_relaunch_quit_v3", "windows_msi_owner_relaunch_quit_v4", "windows_msi_owner_quit_phase_diagnostic", "windows_msi_target_prepare",
    "windows_update_fixture_stage", "windows_update_fixture_stage_recovery", "windows_update_fixture_http_stage", "windows_update_fixture_guest_create_abort", "windows_update_fixture_download_abort", "windows_update_fixture_download_abort_current", "windows_large_artifact_transfer", "windows_cp117_campaign_rebase", "windows_cp117_e66_successor", "windows_cp117_guest_abort_successor", "windows_cp117_download_abort_successor", "windows_cp117_download_abort_current_successor", "windows_cp117_campaign_status", "windows_cp117_staged_fixture_retire", "windows_cp117_c32_archive_admission", "windows_cp117_c32_host_archive", "windows_cp117_historical_base_archives", "windows_cp117_c32_absence", "windows_cp117_source_campaign", "windows_cp117_guest_agent_recovery", "windows_cp117_guest_agent_recovery_successor", "windows_cp117_retirement_recovery", "windows_fixture_phase_status", "windows_fixture_credentials", "windows_fixture_python_download_preflight", "windows_fixture_python_host_source", "windows_fixture_python_acquire_transfer", "windows_fixture_python_guest_install", "windows_fixture_package_mode_repair", "windows_fixture_server_abort_successor", "windows_fixture_server_second_abort_successor", "windows_fixture_server_resume", "windows_fixture_post_resource_diagnostic", "windows_fixture_acl_preflight",
    "windows_fixture_owner_network", "windows_fixture_network_probe",
    "windows_vm_setup_language_next",
    "windows_vm_setup_keyboard_next",
    "windows_vm_setup_install_disk_proof",
    "windows_vm_setup_install_focus",
    "windows_vm_setup_install_ack",
    "windows_vm_setup_install_next",
    "android_package_install", "android_public_inspect", "android_document_acceptance", "android_document_retry", "android_document_retry_unknown", "android_document_recovery", "android_action_acceptance", "android_runtime_acceptance", "android_obsolete_consent_denial", "android_vpn_permission_reset", "android_consent_grant_acceptance", "android_consent_acceptance", "android_native_fixture_lifecycle", "android_endpoint_admission", "android_recovered_endpoint_stage_cleanup", "android_installer_dispatch", "android_cli_stage",
    "macos_fixture_guest_stage", "macos_machine_server_stop", "linux_guest_park", "linux_package_fixture_build", "linux_deb_arch_guest_prepare", "linux_deb_arch_guest_prepare_remote",
    "linux_deb_arch_acceptance", "linux_deb_arch_transport", "linux_deb_arch_host_supervisor", "tmux_workflow_routes", "android_coldboot_product_routes", "android_api35_large_routing_routes", "android_fixture_tls_routes", "android_api35_remaining_proxy_status_routes",
)


def _agent_module(name: str) -> Any:
    """Load a fixed native adapter from this repository's package."""
    if name not in _VM_NATIVE_ADAPTERS:
        raise ValueError("Unknown fixed native adapter.")
    module = importlib.import_module(f"{__package__ or 'agent_tools'}.{name}")
    source = getattr(module, "__file__", None)
    if not isinstance(source, str) or not source.endswith(".py"):
        raise ValueError("Fixed native adapter source is unavailable.")
    try:
        modified_ns = Path(source).stat().st_mtime_ns
    except OSError as error:
        raise ValueError("Fixed native adapter source is unavailable.") from error
    if modified_ns > _MCP_BOOT_TIME_NS:
        raise ValueError("MCP adapter source changed after this server started; use the fresh-process mcp_tool.sh route or restart MCP.")
    return module


def _valid_uuid(value: str) -> bool:
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _windows_parallel_copy_result(value: Any, correlation: str, action: str, adapter: Any) -> dict[str, Any]:
    """Validate only the fixed copy transport's actual producer DTOs."""
    def need(condition):
        if not condition:
            raise ValueError("windows-parallel-copy-receipt-invalid")
    def fields(row, keys):
        need(type(row) is dict and set(row) == set(keys))
    def number(value, minimum=1):
        return type(value) is int and minimum <= value <= 2**63 - 1
    def sha(value):
        return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
    def flags(row):
        need(all(row.get(key) is False for key in ("nativeGuestStarted", "launchAdmitted", "productAcceptance")))
    def generation(value, mode, uid, length=9, gid=1000):
        need(type(value) is list and len(value) == length and all(number(v, 0) for v in value)
             and value[0] > 0 and value[1] > 0 and value[2] == mode and value[3] == uid
             and value[4] == gid)
        if length == 9:
            need(value[5] == 1 and 0 < value[6] <= 120 * 1024**3)
    def pin(row, maximum=65537):
        fields(row, ("generation", "sha256"))
        generation(row["generation"], 0o100600, 0, gid=0)
        need(row["generation"][6] <= maximum and sha(row["sha256"]))
    def identity(row, supervisor=True):
        keys = ("schemaVersion", "correlationId", "pid", "startTicks", "programSha256", "supervisorSha256") if supervisor else (
            "correlationId", "pid", "startTicks", "programSha256", "workerPin")
        fields(row, keys)
        need(row["correlationId"] == correlation and number(row["pid"]) and number(row["startTicks"])
             and sha(row["programSha256"]))
        if supervisor:
            need(type(row["schemaVersion"]) is int and row["schemaVersion"] == 1 and sha(row["supervisorSha256"]))
        else:
            pin(row["workerPin"], 262144)
    base = {"state", "nativeGuestStarted", "launchAdmitted", "productAcceptance", "evidenceLeaf", "originalTransportPid"}
    need(type(value) is dict and value.get("state") in ("submitted", "running", "prepared", "unknown"))
    flags(value)
    method = "start" if action.endswith("-start") else "status"
    need(type(value.get("evidenceLeaf")) is str and re.fullmatch(
        r"windows-parallel-vm-copy-" + method + r"-[0-9a-f]{32}", value["evidenceLeaf"]) is not None)
    need(value.get("originalTransportPid") is None and value["state"] == "unknown"
         or number(value.get("originalTransportPid")))
    state = value["state"]
    if state in ("submitted", "running"):
        fields(value, base | {"identity"})
        need(state == ("submitted" if method == "start" else "running"))
        identity(value["identity"])
    elif "terminal" in value:
        fields(value, base | {"identity", "copyIdentity", "terminal", "result"})
        need(method == "status")
        identity(value["identity"])
        identity(value["copyIdentity"], False)
        child = value["copyIdentity"]
        terminal = value["terminal"]
        fields(terminal, set(child) | {"exitCode", "stdoutEof", "outputBytes", "retainedBytes", "overflow", "rawPin"})
        need(all(json.dumps(terminal[key], sort_keys=True) == json.dumps(child[key], sort_keys=True) for key in child))
        need(terminal["programSha256"] == value["identity"]["programSha256"])
        need(type(terminal["exitCode"]) is int and -255 <= terminal["exitCode"] <= 255
             and terminal["stdoutEof"] is True and type(terminal["overflow"]) is bool
             and number(terminal["outputBytes"], 0) and number(terminal["retainedBytes"], 0)
             and terminal["retainedBytes"] == min(terminal["outputBytes"], 65537)
             and terminal["overflow"] is (terminal["outputBytes"] > 65536))
        pin(terminal["rawPin"])
        need(terminal["rawPin"]["generation"][6] == terminal["retainedBytes"])
        result = value["result"]
        flags(result)
        need(result.get("state") == state)
        if state == "prepared":
            fields(result, {"state", "correlationId", "template", "templateSha256", "templateGeneration", "overlays",
                            "nativeGuestStarted", "launchAdmitted", "productAcceptance", "ordinaryQemuReadAccessConfigured"})
            need(terminal["exitCode"] == 0 and terminal["overflow"] is False
                 and result["correlationId"] == correlation and sha(result["templateSha256"])
                 and result["template"] == str(adapter.core.TEMPLATE_ROOT / "template.qcow2")
                 and result["ordinaryQemuReadAccessConfigured"] is True)
            generation(result["templateGeneration"], 0o100440, 0)
            rows = result["overlays"]
            need(type(rows) is list and len(rows) == 2)
            for row, destination in zip(rows, adapter.inventory.DESTINATIONS):
                fields(row, ("path", "generation", "guestGeneration"))
                need(row["path"] == str(Path(destination) / "disk.qcow2"))
                generation(row["generation"], 0o100600, 1000)
                generation(row["guestGeneration"], 0o40700, 1000, 5)
        else:
            fields(result, ("state", "reason", "nativeGuestStarted", "launchAdmitted", "productAcceptance"))
            need(type(result["reason"]) is str)
            value = {**value, "result": {**result, "reason": "copy-native-unknown"}}
    else:
        need(state == "unknown")
        extras = set(value) - base
        need(extras in ({"reason", "replayAllowed"}, {"reason"}, {"reason", "correlationId", "pid", "startTicks"},
                        {"reason", "identity", "originalSupervisorAlive"}))
        need(type(value["reason"]) is str)
        if "replayAllowed" in value:
            need(value["replayAllowed"] is False)
        if "correlationId" in value:
            need(value["correlationId"] == correlation
                 and (value["pid"] is None or number(value["pid"]))
                 and (value["startTicks"] is None or number(value["startTicks"])))
        if "identity" in value:
            identity(value["identity"])
            need(value["originalSupervisorAlive"] is True)
        value = {**value, "reason": "copy-native-unknown"}
    return value


def _vm_workflow_impl(action: str, inputs: dict[str, Any]) -> dict[str, Any]:
    """Validate staged inputs or calculate memory admission; neither action starts a VM."""
    workflow = importlib.import_module(f"{__package__}.vm_workflow" if __package__ else "vm_workflow")
    try:
        if not isinstance(inputs, dict):
            return _error("vm_workflow", "VM workflow inputs must be an object.")
        if action == "source-review-close":
            required = {"manifestPath", "manifestSha256"}
            allowed = required | {"packetManifestPath", "packetManifestSha256",
                                  "proofPath", "proofSha256"}
            if not required <= set(inputs) or set(inputs) - allowed:
                return _error("vm_workflow", "Invalid source closure input fields.")
            try:
                result = _agent_module("native_review_source_closure").close_review_sources(
                    inputs["manifestPath"], inputs["manifestSha256"],
                    packet_manifest_path=inputs.get("packetManifestPath"),
                    packet_manifest_sha256=inputs.get("packetManifestSha256"),
                    proof_path=inputs.get("proofPath"), proof_sha256=inputs.get("proofSha256"))
                return {"tool": "vm_workflow", "ok": True, **result}
            except (ValueError, TypeError, OSError):
                return _error("vm_workflow", "Source closure authentication failed.")
        if action == "android-api35-large-routing-observe":
            return _agent_module("android_api35_large_routing_routes").dispatch(REPO_ROOT, action, inputs)
        if action == "android-coldboot-product-api29-observe":
            return _agent_module("android_coldboot_product_routes").dispatch(REPO_ROOT, action, inputs)
        if action in {"linux-package-tmux-resource-prepare", "linux-package-tmux-availability", "linux-package-tmux-preflight", "linux-package-tmux-start", "linux-package-tmux-status", "linux-package-tmux-collect", "arch-tmux-install-preflight", "arch-tmux-install-start", "arch-tmux-install-status"}:
            return _agent_module("tmux_workflow_routes").dispatch(REPO_ROOT, action, inputs)
        if action == "acceptance-status":
            overview = _agent_module("native_acceptance_overview")
            matrix = _agent_module("native_acceptance_matrix")
            registry = _agent_module("native_artifact_registry")
            try:
                source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
                artifacts = overview.read_artifact_index(REPO_ROOT, source, registry)
                report = overview.matrix_status_readonly(REPO_ROOT, source, matrix, registry, artifacts)
                artifact_verification = overview.verify_local_artifact_bytes(artifacts, registry)
                known = overview.discover_source_correlations(
                    REPO_ROOT, source, artifacts, _agent_module("android_document_acceptance"),
                    _agent_module("linux_rpm_workspace_recovery"),
                    _agent_module("linux_rpm_fixture_server_lifecycle"))
                summaries = {"macos": overview.read_macos_denial_summary(REPO_ROOT, source, artifacts)}
                def observe_correlation(item: dict[str, Any], current_source: str,
                                        index: dict[str, Any]) -> dict[str, Any]:
                    action, correlation = item["statusAction"], item["correlationId"]
                    payload = ({"host": "archlinux", "correlationId": correlation}
                               if action == "windows-msi-public-status" else
                               {"cleanupCorrelationId": correlation}
                               if action == "linux-rpm-workspace-cleanup-status" else
                               {"correlationId": correlation})
                    observed = _vm_workflow_impl(action, payload)
                    if observed.get("correlationId") != correlation or observed.get("state") in {None, "unknown"}:
                        return {}
                    bound_source = observed.get("sourceSha")
                    details: dict[str, Any] = {}
                    if item["platform"] == "android":
                        document = _agent_module("android_document_acceptance")
                        intent = document._load(REPO_ROOT, correlation)
                        if (not isinstance(intent, dict) or intent.get("device") not in {"api29", "api35"} or
                                not isinstance(intent.get("artifactId"), str) or
                                intent["artifactId"] not in index.get("records", {}) or
                                "cliStageCorrelationId" not in intent):
                            return {}
                        bound_source = index["records"][intent["artifactId"]].get("sourceSha")
                        details = {"ownerIdentity": intent.get("expectedOwner"),
                                   "deviceAlias": intent["device"]}
                    elif item["platform"] == "linux":
                        server = _agent_module("linux_rpm_fixture_server_lifecycle")
                        public_correlation = correlation
                        if action == "linux-rpm-workspace-cleanup-status":
                            recovery = _agent_module("linux_rpm_workspace_recovery")
                            saved = recovery._read_cleanup_journal(recovery._cleanup_journal(REPO_ROOT, correlation))
                            public_correlation = saved["correlationId"]
                        intent = server._journal(REPO_ROOT, public_correlation)
                        bound_source = intent.get("sourceSha") if isinstance(intent, dict) else None
                    return {"state": "verified", "correlationId": correlation,
                            "sourceSha": bound_source, "operationState": observed["state"], **details}
                def observe_owner(item: dict[str, Any]) -> dict[str, Any]:
                    action, payload = item["action"], item["inputs"]
                    observed = (_ssh_workflow_impl("android-observe", payload["host"],
                                                  payload["timeoutSeconds"], device=payload["device"])
                                if action == "android-observe" else _vm_workflow_impl(action, payload))
                    if action == "android-observe":
                        if (observed.get("available") is True and observed.get("ownerConsistency") == "consistent" and
                                isinstance(observed.get("status"), dict) and
                                isinstance(observed["status"].get("controllerId"), str)):
                            return {"state": "running", "evidenceScope": "owner", "source": "live-tool",
                                    "controllerId": observed["status"]["controllerId"],
                                    "deviceAlias": payload["device"]}
                    elif action == "linux-rpm-owner-observe":
                        if observed.get("state") == "observed" and observed.get("pid") == payload["pid"] and observed.get("startTicks") == payload["startTicks"]:
                            return {"state": "running", "evidenceScope": "owner", "source": "live-tool",
                                    "pid": observed["pid"], "startTicks": observed["startTicks"],
                                    "runtimeRunning": observed.get("runtimeRunning")}
                    elif action == "linux-owner-public-quit-status":
                        if observed.get("state") == "terminal" and observed.get("result") == "passed" and observed.get("ownerGenerationGone") is True:
                            return {"state": "stopped", "evidenceScope": "owner", "source": "live-tool"}
                    elif (observed.get("state") == "READY" and observed.get("source") == "live-tool" and
                          observed.get("ready") is True and observed.get("nativeActionAllowed") is False):
                        return {"state": "running", "evidenceScope": "guest", "source": "live-tool"}
                    return {}
                result = overview.acceptance_status(report, inputs, artifacts,
                    correlation_observer=observe_correlation, owner_observer=observe_owner,
                    artifact_verification=artifact_verification, known_correlations=known,
                    local_native_summaries=summaries)
                if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip() != source:
                    raise ValueError("Source changed during read-only acceptance status.")
                checkout = overview.checkout_state(REPO_ROOT)
                return {"tool": "vm_workflow", "ok": True, "evidenceClass": "read-only-acceptance", **result, **checkout}
            except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "read-only-acceptance-evidence-unavailable",
                        "worktreeDirty": None, "checkoutExact": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action == "vm-preflight-batch":
            overview = _agent_module("native_acceptance_overview")
            result = overview.batch_preflight(inputs, _vm_workflow_impl)
            return {"tool": "vm_workflow", "ok": result["observationsComplete"],
                    "evidenceClass": "read-only-environment", **result}
        if action == "build-timing-report":
            timing = _agent_module("native_build_timing")
            source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
            result = timing.report(REPO_ROOT, source, inputs)
            if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip() != source:
                return _error("vm_workflow", "Build timing source changed during the read-only report.")
            return {"tool": "vm_workflow", "ok": True, "evidenceClass": "source-bound-build-timing", **result}
        if action == "baseline-source-inventory":
            if inputs:
                return {"tool": "vm_workflow", "ok": False,
                        "reason": "baseline-source-inventory-requires-empty-inputs",
                        "nativeActionAllowed": False, "readinessVerified": False}
            try:
                inventory = _agent_module("native_vm_baseline_inventory")
                result = inventory.configured_source_metadata(REPO_ROOT)
                return {"tool": "vm_workflow", "ok": True, **result}
            except (ValueError, OSError, TypeError, KeyError) as error:
                reason = getattr(error, "reason", "metadata_unavailable")
                if reason not in ("baselines_not_configured", "invalid_inventory",
                                  "invalid_source_configuration", "metadata_unavailable"):
                    reason = "metadata_unavailable"
                return {"tool": "vm_workflow", "ok": False,
                        "reason": reason,
                        "nativeActionAllowed": False, "readinessVerified": False}
        if action in {"baseline-capture", "baseline-verify", "baseline-restore", "baseline-preflight"}:
            baselines = _agent_module("native_vm_baseline_config")
            result = baselines.handle(REPO_ROOT, action, inputs)
            return {"tool": "vm_workflow", "ok": True, **result}
        if action == "matrix-equivalence-record":
            # This records provenance only. An unknown result must be inspected
            # using matrix-status; it never grants replay or current CI success.
            unknown = {"tool": "vm_workflow", "ok": False, "state": "unknown",
                       "replayAllowed": False, "nativeActionPerformed": False,
                       "currentChecksCompleted": False}
            if (set(inputs) != {"receiptId", "artifactSetId", "targetSourceSHA", "reviewerAttestation"}
                    or not isinstance(inputs["receiptId"], str)
                    or re.fullmatch(r"native-acceptance-[0-9a-f]{32}", inputs["receiptId"]) is None
                    or not isinstance(inputs["artifactSetId"], str)
                    or re.fullmatch(r"artifact-set-[0-9a-f]{64}", inputs["artifactSetId"]) is None
                    or not isinstance(inputs["targetSourceSHA"], str)
                    or re.fullmatch(r"[0-9a-f]{40}", inputs["targetSourceSHA"]) is None
                    or not isinstance(inputs["reviewerAttestation"], str)
                    or not inputs["reviewerAttestation"].strip()
                    or len(inputs["reviewerAttestation"]) > 240):
                return unknown
            try:
                result = _agent_module("native_acceptance_matrix").matrix_equivalence_record(REPO_ROOT, inputs)
            except (ValueError, TypeError, OSError):
                return unknown
            if (not isinstance(result, dict)
                    or set(result) != {"linkId", "receiptId", "originalSourceSHA", "targetSourceSHA", "requiredCurrentChecks"}
                    or not isinstance(result["linkId"], str)
                    or re.fullmatch(r"native-equivalence-[0-9a-f]{32}", result["linkId"]) is None
                    or result["receiptId"] != inputs["receiptId"]
                    or result["targetSourceSHA"] != inputs["targetSourceSHA"]
                    or not isinstance(result["originalSourceSHA"], str)
                    or re.fullmatch(r"[0-9a-f]{40}", result["originalSourceSHA"]) is None
                    or result["requiredCurrentChecks"] not in (["exact-sha-ci"], ["exact-sha-ci", "changed-tool-tests"])):
                return unknown
            return {"tool": "vm_workflow", "ok": True, **result,
                    "nativeActionPerformed": False, "currentChecksCompleted": False}
        if action in {"matrix-record", "matrix-retract", "matrix-status"}:
            matrix = _agent_module("native_acceptance_matrix")
            if action == "matrix-record":
                result = matrix.matrix_record(REPO_ROOT, inputs)
            elif action == "matrix-retract":
                result = matrix.matrix_retract(REPO_ROOT, inputs)
            else:
                if set(inputs) - {"sourceSha"}:
                    return _error("vm_workflow", "Matrix status accepts only an optional sourceSha.")
                source = subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
                if inputs.get("sourceSha", source) != source:
                    return _error("vm_workflow", "Acceptance status must use current HEAD; historical receipts remain visible in its report.")
                result = matrix.matrix_status(REPO_ROOT, source)
            return {"tool": "vm_workflow", "ok": True, **result}
        if action == "fixture-preflight":
            preflight = _agent_module("native_fixture_preflight")
            result = preflight.check(REPO_ROOT, inputs, _native_fixed_dispatch)
            return {"tool": "vm_workflow", "ok": result.get("ready") is True, **result}
        if action == "macos-installer-recovery-status":
            recovery = _agent_module("macos_installer_recovery")
            result = recovery.diagnose(inputs)
            return {"tool": "vm_workflow", "ok": True, **result}
        if action in {"macos-machine-server-stop-start", "macos-machine-server-stop-status",
                      "macos-machine-server-stop-collect"}:
            stop = _agent_module("macos_machine_server_stop")
            if action.endswith("-start"):
                required = {"schemaVersion", "sourceSha", "correlationId", "scenario", "jobId",
                            "operationId", "bootSessionUuid", "reservationId", "fixtureReceiptArtifactId",
                            "serverInstanceId", "serverPid", "serverProcessStartIdentity", "readySha256"}
                if (set(inputs) != required or type(inputs["schemaVersion"]) is not int or
                        inputs["schemaVersion"] != 1 or
                        not isinstance(inputs["sourceSha"], str) or
                        re.fullmatch(r"[0-9a-f]{40}", inputs["sourceSha"]) is None or
                        not isinstance(inputs["correlationId"], str) or not _valid_uuid(inputs["correlationId"]) or
                        not isinstance(inputs["scenario"], str) or
                        inputs["scenario"] not in {"install", "rollback"} or
                        type(inputs["serverPid"]) is not int or inputs["serverPid"] <= 0 or
                        not isinstance(inputs["serverProcessStartIdentity"], str) or
                        re.fullmatch(r"darwin:[1-9][0-9]*:[0-9]{1,6}", inputs["serverProcessStartIdentity"]) is None or
                        not isinstance(inputs["readySha256"], str) or
                        re.fullmatch(r"[0-9a-f]{64}", inputs["readySha256"]) is None or
                        not isinstance(inputs["fixtureReceiptArtifactId"], str) or
                        re.fullmatch(r"sha256-[0-9a-f]{64}", inputs["fixtureReceiptArtifactId"]) is None or
                        any(not isinstance(inputs[key], str) or not inputs[key] for key in
                            ("jobId", "operationId", "bootSessionUuid", "reservationId", "serverInstanceId"))):
                    return _error("vm_workflow", "Mac server stop requires exact accepted campaign and server identity.")
            elif (set(inputs) != {"correlationId"} or
                  not isinstance(inputs.get("correlationId"), str) or
                  not _valid_uuid(inputs["correlationId"])):
                return _error("vm_workflow", "Mac server stop observation requires only canonical correlationId.")
            try:
                if action.endswith("-start"):
                    result = stop.start(REPO_ROOT, inputs)
                else:
                    method = stop.status if action.endswith("-status") else stop.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": action.endswith("-status") and result.get("state") == "complete",
                        "evidenceClass": "current-mac-server-stop" if action.endswith("-status") else
                                         "historical-mac-server-stop" if action.endswith("-collect") else
                                         "native-fixture-server-stop",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "mac-server-stop-outcome-unavailable",
                        "correlationId": inputs.get("correlationId"),
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
        if action in {"macos-fixture-guest-stage-start", "macos-fixture-guest-stage-status", "macos-fixture-guest-stage-collect"}:
            stage = _agent_module("macos_fixture_guest_stage")
            try:
                if action.endswith("-start"):
                    required = {"correlationId", "sourceSha", "guestRoot", "baseSha256", "baseSizeBytes",
                                "targetSha256", "targetSizeBytes"}
                    if set(inputs) != required:
                        return _error("vm_workflow", "macOS fixture guest stage requires exact artifact fields.")
                    registry = _agent_module("native_artifact_registry")
                    fingerprints = []
                    for label in ("base", "target"):
                        observed = registry.verify_artifact(REPO_ROOT, "sha256-" + inputs[f"{label}Sha256"])
                        artifact = observed.get("artifact", {})
                        if (observed.get("verification") != "verified" or artifact.get("platform") != "macos" or
                            artifact.get("artifactKind") != "desktop-package" or
                            artifact.get("sourceSha") != inputs["sourceSha"] or
                            artifact.get("size") != inputs[f"{label}SizeBytes"]):
                            return _error("vm_workflow", "macOS fixture guest stage artifacts are not verified for source.")
                        fingerprints.append(artifact.get("sourceFingerprint"))
                    if not fingerprints[0] or fingerprints[0] != fingerprints[1]:
                        return _error("vm_workflow", "macOS fixture guest stage package sources differ.")
                    result = stage.start(REPO_ROOT, inputs)
                else:
                    if set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "macOS fixture guest stage observation requires only correlationId.")
                    method = stage.status if action.endswith("-status") else stage.collect
                    result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result, "evidenceClass": "fixture-mode-repair",
                        "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"batch-plan", "batch-start", "batch-status", "batch-resume", "batch-collect"}:
            batch_module = _agent_module("native_scenario_batch")
            def batch_preflight(request):
                if request.get("scenarioId") == "linux-rpm-public-install-recovery":
                    rpm = _agent_module("native_rpm_public_install_ssh")
                    return rpm.preflight(REPO_ROOT, request)
                fixture = _agent_module("native_fixture_preflight")
                return fixture.check(REPO_ROOT, request, _native_fixed_dispatch)
            batch = batch_module.NativeScenarioBatch(REPO_ROOT / ".rag_index" / "native-batches",
                                                     _native_fixed_dispatch, repository_root=REPO_ROOT,
                                                     preflight=batch_preflight)
            if action == "batch-plan":
                result = batch.plan(inputs)
            else:
                if set(inputs) != {"batchId"} or not isinstance(inputs["batchId"], str):
                    return _error("vm_workflow", "Batch observation/execution requires only its immutable batchId.")
                result = getattr(batch, action.removeprefix("batch-"))(inputs["batchId"])
            return {"tool": "vm_workflow", "ok": result.get("state") not in {"failed", "blocked", "unknown"}, **result}
        if action in {"rpm-public-install-start", "rpm-public-install-status", "rpm-public-install-collect"}:
            rpm = _agent_module("native_rpm_public_install_ssh")
            boundary = _agent_module("native_rpm_public_install_adapter")
            fixed = boundary.RpmPublicInstallAdapter(rpm.RpmPublicInstallSshDriver(REPO_ROOT))
            try:
                if action == "rpm-public-install-start":
                    result = fixed.start(inputs)
                else:
                    if set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "RPM observation requires only correlationId.")
                    result = getattr(fixed, "status" if action.endswith("-status") else "collect")(inputs["correlationId"])
                accepted = result.get("state") in {"submitted", "running"} or (result.get("state") == "terminal" and result.get("exitCode") == 0)
                return {"tool": "vm_workflow", "ok": accepted, "evidenceClass": "installed-package", "productAction": True, **result}
            except (ValueError, OSError, KeyError) as error:
                return _error("vm_workflow", str(error))
        if action in {"linux-rpm-fixture-dispatch", "linux-rpm-fixture-status"}:
            fixture = _agent_module("linux_update_fixture_workflow")
            try:
                method = fixture.dispatch if action.endswith("-dispatch") else fixture.status
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "pending", "complete"},
                        "evidenceClass": "fixture-build", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"linux-rpm-fixture-server-start", "linux-rpm-fixture-server-status", "linux-rpm-fixture-server-collect", "linux-rpm-fixture-server-stop"}:
            server = _agent_module("linux_rpm_fixture_server_lifecycle")
            try:
                method = {"linux-rpm-fixture-server-start": server.start,
                          "linux-rpm-fixture-server-status": server.status,
                          "linux-rpm-fixture-server-collect": server.collect,
                          "linux-rpm-fixture-server-stop": server.stop}[action]
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": (result.get("state") in {"submitted", "ready"} or
                               (action == "linux-rpm-fixture-server-stop" and
                                result.get("state") == "terminal" and
                                result.get("result") == "stopped" and
                                result.get("pidfdExitObserved") is True)) and
                              result.get("replayAllowed") is not True,
                        "evidenceClass": "native-fixture-endpoint",
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "linux-rpm-workspace-recovery-status":
            recovery = _agent_module("linux_rpm_workspace_recovery")
            try:
                if set(inputs) != {"correlationId"} or not isinstance(inputs["correlationId"], str) or \
                        not _valid_uuid(inputs["correlationId"]):
                    return _error("vm_workflow", "RPM workspace recovery status requires only a canonical correlationId UUID.")
                result = recovery.status(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "observed",
                        "evidenceClass": "native-workspace-recovery", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"linux-rpm-workspace-cleanup-start", "linux-rpm-workspace-cleanup-status"}:
            recovery = _agent_module("linux_rpm_workspace_recovery")
            try:
                required = {"correlationId", "cleanupCorrelationId"} if action.endswith("-start") else {"cleanupCorrelationId"}
                if set(inputs) != required or any(not isinstance(inputs[key], str) or
                                                  not _valid_uuid(inputs[key]) for key in required):
                    return _error("vm_workflow", "RPM workspace cleanup requires exact canonical correlation UUID fields.")
                method = recovery.cleanup_start if action.endswith("-start") else recovery.cleanup_status
                result = method(REPO_ROOT, inputs)
                complete = (result.get("state") == "terminal" and result.get("result") == "passed" and
                            result.get("workspaceRemoved") is True and result.get("replayAllowed") is False)
                return {"tool": "vm_workflow", **result, "ok": complete,
                        "evidenceClass": "native-workspace-cleanup", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"linux-owner-public-quit-start", "linux-owner-public-quit-status", "linux-owner-public-quit-collect"}:
            owner_quit = _agent_module("linux_owner_public_quit")
            try:
                method = {"linux-owner-public-quit-start": owner_quit.start,
                          "linux-owner-public-quit-status": owner_quit.status,
                          "linux-owner-public-quit-collect": owner_quit.collect}[action]
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "pending"} or
                              (result.get("state") == "terminal" and result.get("result") == "passed"),
                        "evidenceClass": "native-owner-transition",
                        "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "linux-rpm-protected-job-observe":
            protected_jobs = _agent_module("linux_rpm_protected_job_observe")
            try:
                result = protected_jobs.observe(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == "observed",
                        "evidenceClass": "native-preflight", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"windows-msi-fixture-dispatch", "windows-msi-fixture-status", "windows-msi-fixture-collect", "windows-msi-fixture-failed-log"}:
            fixture = _agent_module("windows_update_fixture_workflow")
            try:
                method = {"windows-msi-fixture-dispatch": fixture.dispatch,
                          "windows-msi-fixture-status": fixture.status,
                          "windows-msi-fixture-collect": fixture.collect,
                          "windows-msi-fixture-failed-log": fixture.failed_log}[action]
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "pending", "complete", "collected", "failed-log"} and
                              result.get("replayAllowed") is False,
                        "evidenceClass": "hosted-fixture", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-fixture-python-preflight":
            server = _agent_module("windows_update_fixture_server")
            try:
                required = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId",
                            "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
                if set(inputs) != required:
                    return _error("vm_workflow", "Windows Python preflight requires exact campaign and artifact fields.")
                result = server.python_preflight(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == "observed" and result.get("serverReady") is False,
                        "evidenceClass": "native-preflight", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-fixture-python-inventory-diagnostic":
            server = _agent_module("windows_update_fixture_server")
            required = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId",
                        "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
            if not isinstance(inputs, dict) or set(inputs) != required:
                return _error("vm_workflow", "Windows Python inventory diagnostic requires exact campaign and artifact fields.")
            try:
                server._request(inputs)
            except (ValueError, TypeError, AttributeError) as error:
                return _error("vm_workflow", str(error))
            identifiers = {name: inputs[name] for name in ("leaseId", "stageCorrelationId", "serverCorrelationId")}
            try:
                result = server.python_inventory_diagnostic(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", **identifiers, "serverReady": False}
            candidate_fields = {"location", "pythonExeSha256", "pythonVersion", "signer"}
            valid_candidate = lambda candidate: (isinstance(candidate, dict) and set(candidate) == candidate_fields
                                                  and candidate.get("location") in {"owner-local", "program-files"}
                                                  and isinstance(candidate.get("pythonExeSha256"), str)
                                                  and bool(server._HASH.fullmatch(candidate["pythonExeSha256"]))
                                                  and isinstance(candidate.get("pythonVersion"), str)
                                                  and len(candidate["pythonVersion"]) <= 64
                                                  and bool(re.fullmatch(r"3\.1[1-4](?:\.[0-9]+)?(?:[ .].*)?", candidate["pythonVersion"]))
                                                  and candidate.get("signer") == "python-software-foundation")
            valid = (isinstance(result, dict)
                     and set(result) == {"state", "leaseId", "stageCorrelationId", "serverCorrelationId",
                                         "candidateCount", "candidates", "serverReady"}
                     and result.get("state") == "observed"
                     and all(result.get(name) == value for name, value in identifiers.items())
                     and type(result.get("candidateCount")) is int and 0 <= result["candidateCount"] <= 16
                     and isinstance(result.get("candidates"), list)
                     and result["candidateCount"] == len(result["candidates"])
                     and all(valid_candidate(candidate) for candidate in result["candidates"])
                     and result.get("serverReady") is False)
            if not valid:
                result = {"state": "unknown", **identifiers, "serverReady": False}
            return {"tool": "vm_workflow", **result, "ok": valid,
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False, "replayAllowed": False}
        if action == "windows-fixture-python-download-preflight":
            preflight = _agent_module("windows_fixture_python_download_preflight")
            server = _agent_module("windows_update_fixture_server")
            required = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
            if not isinstance(inputs, dict) or set(inputs) != required:
                return _error("vm_workflow", "Windows Python download preflight requires exact campaign and artifact fields.")
            try:
                server._request(inputs)
            except (ValueError, TypeError, AttributeError) as error:
                return _error("vm_workflow", str(error))
            ids = {name: inputs[name] for name in ("leaseId", "stageCorrelationId", "serverCorrelationId")}
            unknown_endpoint = {"classification": "unknown", "phase": "remote-transport-unknown", "tlsSha256": "unknown", "statusCode": "unknown", "contentLength": "unknown"}
            try:
                result = preflight.preflight(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", **ids, "candidateCount": 0, "serverReady": False, "installerSha256": preflight._SHA256, **unknown_endpoint}
            valid = (isinstance(result, dict) and set(result) == {"state", "leaseId", "stageCorrelationId", "serverCorrelationId", "candidateCount", "serverReady", "installerSha256", "classification", "phase", "tlsSha256", "statusCode", "contentLength"}
                     and result.get("state") == "observed" and all(result.get(name) == value for name, value in ids.items())
                     and result.get("candidateCount") == 0 and result.get("serverReady") is False and result.get("installerSha256") == preflight._SHA256
                     and result.get("classification") in {"reachable", "unreachable", "unknown"}
                     and result.get("phase") in preflight._PHASES
                     and (result.get("tlsSha256") == "unknown" or (isinstance(result.get("tlsSha256"), str) and preflight._HASH.fullmatch(result["tlsSha256"])))
                     and (result.get("statusCode") == "unknown" or (type(result.get("statusCode")) is int and 100 <= result["statusCode"] <= 599))
                     and (result.get("contentLength") == "unknown" or (type(result.get("contentLength")) is int and 0 <= result["contentLength"] <= 1_073_741_824)))
            if not valid:
                result = {"state": "unknown", **ids, "candidateCount": 0, "serverReady": False, "installerSha256": preflight._SHA256, **unknown_endpoint}
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "causal-diagnostic", "productAction": False, "nativeActionAllowed": False, "replayAllowed": False}
        if action == "windows-fixture-python-host-source-observe":
            source = _agent_module("windows_fixture_python_host_source")
            server = _agent_module("windows_update_fixture_server")
            required = {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}
            if not isinstance(inputs, dict) or set(inputs) != required:
                return _error("vm_workflow", "Python source observation requires exact campaign and artifact fields.")
            try:
                request = server._request(inputs)
                server._admit_campaign(REPO_ROOT, request, require_credentials=True)
                result = source.observe(REPO_ROOT, {"host": "archlinux", "timeoutSeconds": 30})
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            valid = (isinstance(result, dict) and set(result) == {"state", *flags}
                     and result.get("state") in {"present", "absent-or-mismatch", "unknown"}
                     and all(result.get(name) is value for name, value in flags.items()))
            if not valid:
                result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] != "unknown", "evidenceClass": "causal-diagnostic", "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-fixture-python-acquire-start", "windows-fixture-python-acquire-status",
                      "windows-fixture-python-acquire-collect", "windows-fixture-python-acquire-reconcile",
                      "windows-fixture-python-install-start", "windows-fixture-python-install-status",
                      "windows-fixture-python-install-collect"}:
            acquire = _agent_module("windows_fixture_python_acquire_transfer")
            install = _agent_module("windows_fixture_python_guest_install")
            starting = action.endswith("-start")
            module = install if "-install-" in action else acquire
            if starting:
                try:
                    request = module._request(inputs)
                except (ValueError, TypeError, KeyError, AttributeError) as error:
                    return _error("vm_workflow", str(error))
                correlation = request["correlationId"]
            else:
                if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"}
                        or not acquire._canonical(inputs.get("correlationId"))):
                    return _error("vm_workflow", "Exact CP117 Python correlation is required.")
                correlation = inputs["correlationId"]
            method = (module.start if starting else module.reconcile if action.endswith("-reconcile")
                      else module.collect if action.endswith("-collect") else module.status)
            try:
                result = method(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
            if (isinstance(result, dict) and result.get("nativeActionAllowed") is False
                    and result.get("productAction") is False):
                result = {key: value for key, value in result.items()
                          if key not in {"nativeActionAllowed", "productAction"}}
            states = ({"submitted", "unknown"} if starting else
                      {"observed", "unknown"} if action.endswith("-reconcile") else
                      {"succeeded", "failed", "running", "blocked", "unknown", "intent-absent"} if module is install else
                      {"downloaded", "failed", "running", "blocked", "unknown", "intent-absent"})
            optional = ({"task", "leaf", "installer", "result"} if module is acquire else
                        {"intent", "private", "task", "installer", "result", "registry", "python"})
            allowed_values = {"task": {"absent", "ready", "running", "queued", "disabled", "mismatch"},
                              "leaf": {"absent", "verified"}, "installer": {"absent", "verified"},
                              "result": {"absent", "running", "succeeded", "failed", "unknown"},
                              "intent": {"absent", "verified"}, "private": {"absent", "verified"},
                              "registry": {"absent", "verified"}, "python": {"absent", "verified"}}
            valid = (isinstance(result, dict) and set(result) >= {"state", "correlationId", "replayAllowed"}
                     and set(result) <= {"state", "correlationId", "replayAllowed"} | optional
                     and result.get("state") in states and result.get("correlationId") == correlation
                     and result.get("replayAllowed") is False
                     and all(result.get(key) in allowed_values[key] for key in (set(result) & optional)))
            if not valid:
                result = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] not in {"unknown", "intent-absent", "blocked", "failed"},
                    "evidenceClass": "causal-diagnostic" if not starting else "native-fixture",
                    "productAction": False, "nativeActionAllowed": False}
        if action == "windows-fixture-python-acquire-failure-detail":
            acquire = _agent_module("windows_fixture_python_acquire_transfer")
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"}
                    or not acquire._canonical(inputs.get("correlationId"))):
                return _error("vm_workflow", "Exact CP117 Python failure correlation is required.")
            correlation = inputs["correlationId"]
            try:
                result = acquire.failure_detail(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
            valid = (isinstance(result, dict)
                     and set(result) == {"state", "correlationId", "replayAllowed", "resultCode", "partial", "signer", "parseErrors", "phase"}
                     and result.get("state") == "observed" and result.get("correlationId") == correlation
                     and result.get("replayAllowed") is False and type(result.get("resultCode")) is int
                     and -2147483648 <= result["resultCode"] <= 4294967295
                     and result.get("partial") in {"absent", "incomplete", "digest-mismatch", "digest-verified", "unknown"}
                     and result.get("signer") in {"valid", "invalid", "not-checked"}
                     and type(result.get("parseErrors")) is int and 0 <= result["parseErrors"] <= 64
                     and result.get("phase") in {"unknown", "identity", "leaf", "network", "headers", "body", "write", "hash", "signer", "move"})
            if not valid:
                result = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "causal-diagnostic",
                    "productAction": False, "nativeActionAllowed": False}
        if action == "windows-fixture-python-install-diagnostic":
            install = _agent_module("windows_fixture_python_guest_install")
            acquire = _agent_module("windows_fixture_python_acquire_transfer")
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"}
                    or not acquire._canonical(inputs.get("correlationId"))):
                return _error("vm_workflow", "Exact CP117 Python install correlation is required.")
            correlation = inputs["correlationId"]
            try:
                result = install.diagnose(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
            valid = (isinstance(result, dict) and set(result) == {"state", "correlationId", "replayAllowed", "phase", "reason"}
                     and result.get("state") == "observed" and result.get("correlationId") == correlation
                     and result.get("replayAllowed") is False
                     and result.get("phase") in {"profile", "appdata", "local", "vpncontrol", "leaf", "installer", "digest", "complete"}
                     and result.get("reason") in {"none", "missing-or-unreadable", "reparse", "type", "acl-unreadable", "foreign-owner", "acl-foreign-write", "acl-creator-owner-template", "acl-foreign-read", "acl-deny", "digest-mismatch"}
                     and (result["phase"] == "complete") == (result["reason"] == "none"))
            if not valid:
                result = {"state": "unknown", "correlationId": correlation, "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "causal-diagnostic",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-fixture-package-mode-repair-start", "windows-fixture-package-mode-repair-status",
                      "windows-fixture-package-mode-repair-collect"}:
            repair = _agent_module("windows_fixture_package_mode_repair")
            starting = action.endswith("-start")
            fields = {"serverCorrelationId", "repairCorrelationId"} if starting else {"repairCorrelationId"}
            if (not isinstance(inputs, dict) or set(inputs) != fields
                    or not all(repair._canonical(inputs.get(field)) for field in fields)):
                return _error("vm_workflow", "Exact CP117 package-mode repair correlations are required.")
            correlation = inputs["repairCorrelationId"]
            try:
                operation = repair.start if starting else repair.collect if action.endswith("-collect") else repair.status
                result = operation(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "repairCorrelationId": correlation,
                          "replayAllowed": False, "nativeActionAllowed": False}
            valid = (isinstance(result, dict)
                     and set(result) == {"state", "repairCorrelationId", "replayAllowed", "nativeActionAllowed"}
                     and result.get("state") == "repaired" and result.get("repairCorrelationId") == correlation
                     and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            if not valid:
                result = {"state": "unknown", "repairCorrelationId": correlation,
                          "replayAllowed": False, "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "native-fixture",
                    "productAction": False}
        if action == "windows-fixture-package-mode-repair-diagnostic":
            repair = _agent_module("windows_fixture_package_mode_repair")
            if (not isinstance(inputs, dict) or set(inputs) != {"repairCorrelationId"}
                    or not repair._canonical(inputs.get("repairCorrelationId"))):
                return _error("vm_workflow", "Exact CP117 package-mode repair correlation is required.")
            correlation = inputs["repairCorrelationId"]
            try:
                result = repair.diagnose(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "repairCorrelationId": correlation, "replayAllowed": False}
            valid = (isinstance(result, dict)
                     and set(result) == {"state", "repairCorrelationId", "phase", "replayAllowed"}
                     and result.get("state") == "diagnosed" and result.get("repairCorrelationId") == correlation
                     and result.get("replayAllowed") is False
                     and result.get("phase") in {"intent-absent", "binding", "remote", "attribute-set", "file-fact",
                                                  "syntax-invalid",
                                                  "guest-launch", "guest-wait", "guest-exit", "guest-truncated",
                                                  "guest-output", "guest-parse"})
            if not valid:
                result = {"state": "unknown", "repairCorrelationId": correlation, "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "causal-diagnostic",
                    "productAction": False, "nativeActionAllowed": False}
        if action == "windows-fixture-server-static-diagnostic":
            server = _agent_module("windows_update_fixture_server")
            if (not isinstance(inputs, dict) or set(inputs) != {"serverCorrelationId"}
                    or not server._canonical(inputs.get("serverCorrelationId"))):
                return _error("vm_workflow", "Exact CP117 server diagnostic correlation is required.")
            correlation = inputs["serverCorrelationId"]
            try:
                result = server.diagnose_static(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "serverCorrelationId": correlation, "replayAllowed": False}
            valid = (isinstance(result, dict) and result.get("serverCorrelationId") == correlation
                     and result.get("replayAllowed") is False
                     and ((set(result) == {"state", "serverCorrelationId", "import", "certificate", "resources", "resourceGate", "replayAllowed"}
                           and result.get("state") == "observed"
                           and result.get("import") in {"ok", "failed", "skipped"}
                           and result.get("certificate") in {"ok", "failed", "skipped"}
                           and result.get("resources") in {"ok", "failed", "skipped"}
                           and result.get("resourceGate") in {"skipped", "receipt", "receipt-contract", "builds",
                                                               "manifest", "package-asset", "package-mode", "other", "complete"}
                           and (result["resources"] == "ok") == (result["resourceGate"] == "complete")
                           and (result["resources"] == "skipped") == (result["resourceGate"] == "skipped"))
                          or (set(result) == {"state", "serverCorrelationId", "phase", "replayAllowed"}
                              and result.get("state") == "diagnosed"
                              and result.get("phase") in {"descriptor", "stage", "remote", "binding",
                                                           "guest-launch", "guest-wait", "guest-exit",
                                                           "guest-output-truncated",
                                                           "guest-output-bytes", "guest-parse"})))
            if not valid:
                result = {"state": "unknown", "serverCorrelationId": correlation, "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "causal-diagnostic",
                    "productAction": False, "nativeActionAllowed": False}
        if action == "windows-fixture-server-diagnostic":
            server = _agent_module("windows_update_fixture_server")
            if (not isinstance(inputs, dict) or set(inputs) != {"serverCorrelationId"}
                    or not server._canonical(inputs.get("serverCorrelationId"))):
                return _error("vm_workflow", "Exact CP117 server diagnostic correlation is required.")
            correlation = inputs["serverCorrelationId"]
            try:
                result = server.diagnose_status(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "serverCorrelationId": correlation, "replayAllowed": False}
            valid = (isinstance(result, dict) and set(result) == {"state", "serverCorrelationId", "task", "lastResult", "ready", "stateContent", "stageAcl", "stateAcl", "replayAllowed"}
                     and result.get("state") == "observed" and result.get("serverCorrelationId") == correlation
                     and result.get("replayAllowed") is False
                     and result.get("task") in {"absent", "running", "ready", "queued", "disabled", "mismatch"}
                     and result.get("ready") in {"absent", "present"}
                     and result.get("stateContent") in {"empty", "probe-events", "ready-present", "other", "unknown"}
                     and result.get("stageAcl") in {"expected", "mismatch", "unknown"}
                     and result.get("stateAcl") in {"expected", "mismatch", "unknown"}
                     and (result.get("lastResult") == "unknown" or
                          (type(result.get("lastResult")) is int and -2147483648 <= result["lastResult"] <= 4294967295)))
            if not valid:
                result = {"state": "unknown", "serverCorrelationId": correlation, "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "causal-diagnostic",
                    "productAction": False, "nativeActionAllowed": False}
        if action == "windows-fixture-server-abort-diagnostic":
            server = _agent_module("windows_update_fixture_server")
            if (not isinstance(inputs, dict) or set(inputs) != {"cleanupCorrelationId"}
                    or not server._canonical(inputs.get("cleanupCorrelationId"))):
                return _error("vm_workflow", "Exact CP117 server abort diagnostic correlation is required.")
            correlation = inputs["cleanupCorrelationId"]
            try:
                result = server.diagnose_abort(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "cleanupCorrelationId": correlation, "replayAllowed": False}
            valid = (isinstance(result, dict) and result.get("cleanupCorrelationId") == correlation
                     and result.get("replayAllowed") is False
                     and ((set(result) == {"state", "cleanupCorrelationId", "phase", "replayAllowed"}
                           and result.get("state") == "diagnosed"
                           and result.get("phase") in {"intent", "descriptor", "remote", "binding", "journal", "guest-task"})
                          or (set(result) == {"state", "cleanupCorrelationId", "task", "result", "stdout", "stderr", "replayAllowed"}
                              and result.get("state") == "observed"
                              and result.get("task") in {"running", "terminal"}
                              and result.get("result") in {"unknown", "zero", "nonzero"}
                              and result.get("stdout") in {"unknown", "absent", "false", "true", "invalid"}
                              and result.get("stderr") in {"unknown", "absent", "false", "true", "invalid"})))
            if not valid:
                result = {"state": "unknown", "cleanupCorrelationId": correlation, "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "causal-diagnostic",
                    "productAction": False, "nativeActionAllowed": False}
        if action == "windows-fixture-stage-diagnostic":
            stage = _agent_module("windows_update_fixture_stage")
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"}
                    or not isinstance(inputs["correlationId"], str)
                    or not stage._UUID.fullmatch(inputs["correlationId"])):
                return _error("vm_workflow", "Exact fixture stage diagnostic correlation is required.")
            try:
                result = stage.diagnose(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "correlationId": inputs["correlationId"],
                          "binding": "unverified", "phase": "qga-protocol",
                          "replayAllowed": False, "nativeActionAllowed": False}
            if (not isinstance(result, dict) or set(result) != {"state", "correlationId", "binding",
                                                            "phase", "replayAllowed", "nativeActionAllowed"}
                    or result.get("state") != "unknown"
                    or result.get("correlationId") != inputs["correlationId"]
                    or result.get("binding") not in {"exact", "mismatch", "unverified"}
                    or result.get("phase") not in (stage._DIAGNOSTIC_PHASES |
                                                      {"local-intent", "local-artifact", "descriptor"})
                    or result.get("binding") != (
                        "unverified" if result.get("phase") in {"local-intent", "local-artifact", "qga-protocol"}
                        else "mismatch" if result.get("phase") in {"descriptor", "remote-binding-mismatch"}
                        else "exact")
                    or result.get("replayAllowed") is not False
                    or result.get("nativeActionAllowed") is not False):
                result = {"state": "unknown", "correlationId": inputs["correlationId"],
                          "binding": "unverified", "phase": "qga-protocol",
                          "replayAllowed": False, "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": result["phase"] != "qga-protocol",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-fixture-stage-recover-7f27":
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 stage recovery host is required.")
            recovery = _agent_module("windows_update_fixture_stage_recovery")
            try:
                result = recovery.recover(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "correlationId": recovery._CORRELATION,
                          "replayAllowed": False}
            recovered = (isinstance(result, dict)
                         and set(result) == {"state", "correlationId", "cleanupReceiptSha256", "replayAllowed"}
                         and result.get("state") == "recovered"
                         and result.get("correlationId") == recovery._CORRELATION
                         and isinstance(result.get("cleanupReceiptSha256"), str)
                         and recovery._HASH.fullmatch(result["cleanupReceiptSha256"])
                         and result.get("replayAllowed") is False)
            unknown = result == {"state": "unknown", "correlationId": recovery._CORRELATION,
                                 "replayAllowed": False}
            if not (recovered or unknown):
                result = {"state": "unknown", "correlationId": recovery._CORRELATION,
                          "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": recovered,
                    "evidenceClass": "native-recovery", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-fixture-stage-recover-7f27-diagnostic":
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 stage recovery diagnostic host is required.")
            recovery = _agent_module("windows_update_fixture_stage_recovery")
            try:
                result = recovery.diagnose(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "diagnosed", "correlationId": recovery._CORRELATION,
                          "phase": "remote-stage", "recoveryAllowed": False,
                          "nativeActionAllowed": False}
            allowed_phases = {"local-intent", "local-artifact", "local-descriptor", "campaign",
                              "remote-stage", "host-submitter", "qga-create-task", "guest-stage", "idle",
                              "closure", "recovered", "remote-absent", "remote-empty",
                              "remote-binding-only"}
            recoverable_phases = {"closure", "recovered", "remote-absent", "remote-empty",
                                  "remote-binding-only"}
            campaign_details = {"record-missing", "record-unsafe", "identity-mismatch",
                                "active-role-required", "closed-required", "remote-confirm",
                                "active-role", "closed", "local-admission", "predecessor-evidence",
                                "resume-state"}
            if (not isinstance(result, dict)
                    or set(result) != ({"state", "correlationId", "phase", "recoveryAllowed",
                                        "nativeActionAllowed"} |
                                       ({"campaignDetail"} if result.get("phase") == "campaign" else set()))
                    or result.get("state") != "diagnosed"
                    or result.get("correlationId") != recovery._CORRELATION
                    or result.get("phase") not in allowed_phases
                    or (result.get("campaignDetail") not in campaign_details
                        if result.get("phase") == "campaign" else "campaignDetail" in result)
                    or result.get("recoveryAllowed") is not (result.get("phase") in recoverable_phases)
                    or result.get("nativeActionAllowed") is not False):
                result = {"state": "diagnosed", "correlationId": recovery._CORRELATION,
                          "phase": "remote-stage", "recoveryAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": True,
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-cp117-campaign-rebase":
            rebase = _agent_module("windows_cp117_campaign_rebase")
            try:
                request = rebase._request(inputs)
                result = rebase.start(REPO_ROOT, request)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact CP117 campaign rebase request is required.")
            valid_active = (isinstance(result, dict)
                            and set(result) == {"state", "leaseId", "previousLeaseId",
                                                "baseTerminalReceiptSha256", "replayAllowed"}
                            and result.get("state") == "active"
                            and result.get("leaseId") == request["leaseId"]
                            and result.get("previousLeaseId") == request["previousLeaseId"]
                            and isinstance(result.get("baseTerminalReceiptSha256"), str)
                            and rebase._ARTIFACT.fullmatch("sha256-" + result["baseTerminalReceiptSha256"])
                            and result.get("replayAllowed") is False)
            valid_unknown = result == {"state": "unknown", "leaseId": request["leaseId"],
                                      "replayAllowed": False}
            if not (valid_active or valid_unknown):
                result = {"state": "unknown", "leaseId": request["leaseId"],
                          "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": valid_active,
                    "evidenceClass": "native-campaign", "productAction": False,
                    "nativeActionAllowed": False}
        if action in {"windows-cp117-e66-successor-start",
                      "windows-cp117-e66-successor-status",
                      "windows-cp117-e66-successor-reconcile",
                      "windows-cp117-e66-successor-resume-begin"}:
            successor = _agent_module("windows_cp117_e66_successor")
            try:
                request = successor._request(inputs)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact retired-e66 successor request is required.")
            operation = {
                "windows-cp117-e66-successor-start": successor.start,
                "windows-cp117-e66-successor-status": successor.status,
                "windows-cp117-e66-successor-reconcile": successor.reconcile,
                "windows-cp117-e66-successor-resume-begin": successor.resume_begin,
            }[action]
            try:
                result = operation(REPO_ROOT, request)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False}
            active = {"state": "active", "leaseId": request["newLeaseId"], **flags}
            partial = (isinstance(result, dict) and action.endswith("-status")
                       and result in (
                           {"state": "closing", "leaseId": request["newLeaseId"],
                            "nextAction": "inspect-close-progress", **flags},
                           {"state": "opening", "leaseId": request["newLeaseId"],
                            "nextAction": "inspect-open-progress", **flags}))
            valid = result == active or partial
            if not valid:
                result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result,
                    "ok": valid and result["state"] == "active",
                    "evidenceClass": "causal-diagnostic" if action.endswith("-status") else "native-campaign",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-cp117-guest-abort-successor-start",
                      "windows-cp117-guest-abort-successor-status",
                      "windows-cp117-guest-abort-successor-reconcile",
                      "windows-cp117-guest-abort-successor-resume-begin"}:
            successor = _agent_module("windows_cp117_guest_abort_successor")
            try:
                request = successor._request(inputs)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact retired guest-create successor request is required.")
            operation = {
                "windows-cp117-guest-abort-successor-start": successor.start,
                "windows-cp117-guest-abort-successor-status": successor.status,
                "windows-cp117-guest-abort-successor-reconcile": successor.reconcile,
                "windows-cp117-guest-abort-successor-resume-begin": successor.resume_begin,
            }[action]
            try:
                result = operation(REPO_ROOT, request)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False}
            active = {"state": "active", "leaseId": request["newLeaseId"], **flags}
            partial = (isinstance(result, dict) and action.endswith("-status")
                       and result in (
                           {"state": "closing", "leaseId": request["newLeaseId"],
                            "nextAction": "inspect-close-progress", **flags},
                           {"state": "opening", "leaseId": request["newLeaseId"],
                            "nextAction": "inspect-open-progress", **flags}))
            valid = result == active or partial
            if not valid:
                result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result,
                    "ok": valid and result["state"] == "active",
                    "evidenceClass": "causal-diagnostic" if action.endswith("-status") else "native-campaign",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-cp117-download-abort-successor-start",
                      "windows-cp117-download-abort-successor-status",
                      "windows-cp117-download-abort-successor-reconcile",
                      "windows-cp117-download-abort-successor-resume-close",
                      "windows-cp117-download-abort-successor-resume-begin"}:
            successor = _agent_module("windows_cp117_download_abort_successor")
            try:
                request = successor._request(inputs)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact retired download successor request is required.")
            operation = {
                "windows-cp117-download-abort-successor-start": successor.start,
                "windows-cp117-download-abort-successor-status": successor.status,
                "windows-cp117-download-abort-successor-reconcile": successor.reconcile,
                "windows-cp117-download-abort-successor-resume-close": successor.resume_close,
                "windows-cp117-download-abort-successor-resume-begin": successor.resume_begin,
            }[action]
            try:
                result = operation(REPO_ROOT, request)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False}
            active = {"state": "active", "leaseId": request["newLeaseId"], **flags}
            closed = {"state": "closed", "leaseId": request["newLeaseId"], **flags}
            partial = (isinstance(result, dict) and action.endswith("-status")
                       and result in (
                           {"state": "closing", "leaseId": request["newLeaseId"],
                            "nextAction": "inspect-close-progress", **flags},
                           {"state": "closing", "leaseId": request["newLeaseId"],
                            "nextAction": "resume-close", **flags},
                           {"state": "opening", "leaseId": request["newLeaseId"],
                            "nextAction": "inspect-open-progress", **flags}))
            valid = result == active or (action.endswith("-resume-close") and result == closed) or partial
            if not valid:
                result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result,
                    "ok": valid and result["state"] in {"active", "closed"},
                    "evidenceClass": "causal-diagnostic" if action.endswith("-status") else "native-campaign",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-cp117-download-abort-current-successor-start",
                      "windows-cp117-download-abort-current-successor-status",
                      "windows-cp117-download-abort-current-successor-reconcile",
                      "windows-cp117-download-abort-current-successor-resume-close",
                      "windows-cp117-download-abort-current-successor-resume-begin"}:
            successor = _agent_module("windows_cp117_download_abort_current_successor")
            try:
                request = successor._request(inputs)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact current retired download successor request is required.")
            operation = {
                "windows-cp117-download-abort-current-successor-start": successor.start,
                "windows-cp117-download-abort-current-successor-status": successor.status,
                "windows-cp117-download-abort-current-successor-reconcile": successor.reconcile,
                "windows-cp117-download-abort-current-successor-resume-close": successor.resume_close,
                "windows-cp117-download-abort-current-successor-resume-begin": successor.resume_begin,
            }[action]
            try:
                result = operation(REPO_ROOT, request)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False}
            active = {"state": "active", "leaseId": request["newLeaseId"], **flags}
            closed = {"state": "closed", "leaseId": request["newLeaseId"], **flags}
            partial = (isinstance(result, dict) and action.endswith("-status")
                       and result in (
                           {"state": "closing", "leaseId": request["newLeaseId"],
                            "nextAction": "inspect-close-progress", **flags},
                           {"state": "closing", "leaseId": request["newLeaseId"],
                            "nextAction": "resume-close", **flags},
                           {"state": "opening", "leaseId": request["newLeaseId"],
                            "nextAction": "inspect-open-progress", **flags}))
            valid = result == active or (action.endswith("-resume-close") and result == closed) or partial
            if not valid:
                result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result,
                    "ok": valid and result["state"] in {"active", "closed"},
                    "evidenceClass": "causal-diagnostic" if action.endswith("-status") else "native-campaign",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-update-fixture-guest-create-abort-status",
                      "windows-update-fixture-guest-create-abort"}:
            guest_create_abort = _agent_module("windows_update_fixture_guest_create_abort")
            try:
                guest_create_abort._request(inputs)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact guest-create abort correlation is required.")
            operation = (guest_create_abort.status if action.endswith("-status")
                         else guest_create_abort.abort)
            try:
                result = operation(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": guest_create_abort._CORRELATION,
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            correlation = guest_create_abort._CORRELATION
            status_phases = {"binding", "shared-phase", "guest-create", "host-stage", "listener",
                             "campaign-identity", "campaign-server", "pending-finish", "campaign-remote",
                             "campaign-role", "retired", "ready", "ready-pending", "ready-cleaned",
                             "cleanup-marker", "retired-binding-invalid", "retired-shared-core-invalid",
                             "retired-receipt-invalid", "retired-campaign-invalid", "retired-marker-invalid",
                             "retired-guest-invalid", "retired-guest-leaf-present",
                             "retired-guest-interpreter-present", "retired-guest-wrapper-unknown",
                             "retired-guest-script-invalid", "unknown"}
            valid_status = (isinstance(result, dict)
                            and set(result) == {"state", "correlationId", "phase", "abortAllowed", *flags}
                            and result.get("state") == "diagnosed"
                            and result.get("correlationId") == correlation
                            and result.get("phase") in status_phases
                            and type(result.get("abortAllowed")) is bool
                            and result.get("abortAllowed") is (result.get("phase") in {
                                "ready", "ready-pending", "ready-cleaned"})
                            and all(result.get(name) is value for name, value in flags.items()))
            valid_abort = (isinstance(result, dict)
                           and ((set(result) == {"state", "correlationId", "cleanupReceiptSha256", *flags}
                                 and result.get("state") == "retired"
                                 and isinstance(result.get("cleanupReceiptSha256"), str)
                                 and re.fullmatch(r"[0-9a-f]{64}", result["cleanupReceiptSha256"]))
                                or (set(result) == {"state", "correlationId", *flags}
                                    and result.get("state") == "unknown"))
                           and result.get("correlationId") == correlation
                           and all(result.get(name) is value for name, value in flags.items()))
            valid = valid_status if action.endswith("-status") else valid_abort
            if not valid:
                result = ({"state": "diagnosed", "correlationId": correlation, "phase": "unknown",
                           "abortAllowed": False, **flags} if action.endswith("-status") else
                          {"state": "unknown", "correlationId": correlation, **flags})
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] in {"diagnosed", "retired"},
                    "evidenceClass": "causal-diagnostic" if action.endswith("-status") else "native-campaign",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-update-fixture-download-abort-status",
                      "windows-update-fixture-download-abort"}:
            download_abort = _agent_module("windows_update_fixture_download_abort")
            try:
                download_abort._request(inputs)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact download abort correlation is required.")
            operation = (download_abort.status if action.endswith("-status") else download_abort.abort)
            try:
                result = operation(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": download_abort._CORRELATION,
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            correlation = download_abort._CORRELATION
            status_phases = {"binding", "shared-phase", "listener-absent", "listener-listening",
                             "listener-served", "listener-stopped", "listener-unknown", "guest-task-present",
                             "guest-empty", "guest-bootstrap-present", "guest-runtime-or-installer-present",
                             "guest-unknown", "campaign", "retired-binding-invalid", "retired-marker",
                             "pending-finish", "pending-finish-marker", "ready",
                             "ready-pending", "ready-cleaned", "retired", "unknown"}
            valid_status = (isinstance(result, dict)
                            and set(result) == {"state", "correlationId", "phase", "abortAllowed", *flags}
                            and result.get("state") == "diagnosed"
                            and result.get("correlationId") == correlation
                            and result.get("phase") in status_phases
                            and type(result.get("abortAllowed")) is bool
                            and result.get("abortAllowed") is (result.get("phase") in {
                                "ready", "ready-pending", "ready-cleaned"})
                            and all(result.get(name) is value for name, value in flags.items()))
            valid_abort = (isinstance(result, dict)
                           and ((set(result) == {"state", "correlationId", "cleanupReceiptSha256", *flags}
                                 and result.get("state") == "retired"
                                 and isinstance(result.get("cleanupReceiptSha256"), str)
                                 and re.fullmatch(r"[0-9a-f]{64}", result["cleanupReceiptSha256"]))
                                or (set(result) == {"state", "correlationId", *flags}
                                    and result.get("state") == "unknown"))
                           and result.get("correlationId") == correlation
                           and all(result.get(name) is value for name, value in flags.items()))
            valid = valid_status if action.endswith("-status") else valid_abort
            if not valid:
                result = ({"state": "diagnosed", "correlationId": correlation, "phase": "unknown",
                           "abortAllowed": False, **flags} if action.endswith("-status") else
                          {"state": "unknown", "correlationId": correlation, **flags})
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] in {"diagnosed", "retired"},
                    "evidenceClass": "causal-diagnostic" if action.endswith("-status") else "native-campaign",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-update-fixture-download-task-cleanup-status",
                      "windows-update-fixture-download-task-cleanup"}:
            download_abort = _agent_module("windows_update_fixture_download_abort")
            try:
                download_abort._request(inputs)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact download task-cleanup correlation is required.")
            operation = (download_abort.task_cleanup_status if action.endswith("-status")
                         else download_abort.task_cleanup)
            try:
                result = operation(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": download_abort._CORRELATION,
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            correlation = download_abort._CORRELATION
            diagnostic_phases = {"not-submitted", "diagnostic-script-oversize",
                                 "qga-wrapper-timeout", "qga-wrapper-failed", "syntax-invalid",
                                 "task-action-mismatch", "task-metadata-error", "task-absent",
                                 "task-principal-mismatch", "task-action-count-mismatch",
                                 "task-state-unsupported", "task-task-info-failed",
                                 "task-action-hash-unknown", "task-running", "task-failed",
                                 "download-absent", "download-hash-mismatch", "guest-file-read-error",
                                 "download-complete", "unknown"}
            status_phases = {"binding", "guest-not-safe", "endpoint", "task-absent-unbound",
                             "ready", "cleaned", "unknown"} | {
                                 "diagnostic-" + phase for phase in diagnostic_phases}
            valid_status = (isinstance(result, dict)
                            and set(result) == {"state", "correlationId", "phase", "cleanupAllowed", *flags}
                            and result.get("state") == "diagnosed"
                            and result.get("correlationId") == correlation
                            and result.get("phase") in status_phases
                            and type(result.get("cleanupAllowed")) is bool
                            and result.get("cleanupAllowed") is (result.get("phase") == "ready")
                            and all(result.get(name) is value for name, value in flags.items()))
            valid_cleanup = (isinstance(result, dict)
                             and set(result) == {"state", "correlationId", *flags}
                             and result.get("state") in {"cleaned", "unknown"}
                             and result.get("correlationId") == correlation
                             and all(result.get(name) is value for name, value in flags.items()))
            valid = valid_status if action.endswith("-status") else valid_cleanup
            if not valid:
                result = ({"state": "diagnosed", "correlationId": correlation, "phase": "unknown",
                           "cleanupAllowed": False, **flags} if action.endswith("-status") else
                          {"state": "unknown", "correlationId": correlation, **flags})
            return {"tool": "vm_workflow", **result,
                    "ok": valid and result["state"] in {"diagnosed", "cleaned"},
                    "evidenceClass": "causal-diagnostic" if action.endswith("-status") else "causal-cleanup",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-update-fixture-download-abort-current-task-cleanup-status",
                      "windows-update-fixture-download-abort-current-task-cleanup",
                      "windows-update-fixture-download-abort-current-status",
                      "windows-update-fixture-download-abort-current"}:
            current_abort = _agent_module("windows_update_fixture_download_abort_current")
            try:
                current_abort._request(inputs)
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "Exact current download abort correlation is required.")
            operation = ({
                "windows-update-fixture-download-abort-current-task-cleanup-status": current_abort.task_cleanup_status,
                "windows-update-fixture-download-abort-current-task-cleanup": current_abort.task_cleanup,
                "windows-update-fixture-download-abort-current-status": current_abort.status,
                "windows-update-fixture-download-abort-current": current_abort.abort,
            }[action])
            try:
                result = operation(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": current_abort._CORRELATION,
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            correlation = current_abort._CORRELATION
            diagnostic_phases = {"not-submitted", "diagnostic-script-oversize",
                                 "qga-wrapper-timeout", "qga-wrapper-failed", "syntax-invalid",
                                 "task-action-mismatch", "task-metadata-error", "task-absent",
                                 "task-principal-mismatch", "task-action-count-mismatch",
                                 "task-state-unsupported", "task-task-info-failed",
                                 "task-action-hash-unknown", "task-running", "task-failed",
                                 "download-absent", "download-hash-mismatch", "guest-file-read-error",
                                 "download-complete", "unknown"}
            cleanup_phases = {"binding", "guest-not-safe", "endpoint", "task-absent-unbound",
                              "ready", "cleaned", "unknown"} | {
                                  "diagnostic-" + phase for phase in diagnostic_phases}
            abort_phases = {"binding", "shared-phase", "listener-absent", "listener-listening",
                            "listener-served", "listener-stopped", "listener-unknown", "guest-empty",
                            "guest-task-present", "guest-bootstrap-present", "guest-runtime-or-installer-present",
                            "guest-unknown", "campaign", "retired-binding-invalid", "retired-marker",
                            "pending-finish", "pending-finish-marker", "ready", "ready-pending",
                            "ready-cleaned", "retired", "unknown"}
            is_cleanup_status = action.endswith("task-cleanup-status")
            is_cleanup = action.endswith("task-cleanup")
            is_abort_status = action.endswith("-status") and not is_cleanup_status
            valid_status = (isinstance(result, dict)
                            and set(result) == {"state", "correlationId", "phase", "cleanupAllowed", *flags}
                            and result.get("state") == "diagnosed" and result.get("correlationId") == correlation
                            and result.get("phase") in cleanup_phases
                            and type(result.get("cleanupAllowed")) is bool
                            and result.get("cleanupAllowed") is (result.get("phase") == "ready")
                            and all(result.get(name) is value for name, value in flags.items()))
            valid_abort_status = (isinstance(result, dict)
                                  and set(result) == {"state", "correlationId", "phase", "abortAllowed", *flags}
                                  and result.get("state") == "diagnosed" and result.get("correlationId") == correlation
                                  and result.get("phase") in abort_phases
                                  and type(result.get("abortAllowed")) is bool
                                  and result.get("abortAllowed") is (result.get("phase") in {
                                      "ready", "ready-pending", "ready-cleaned"})
                                  and all(result.get(name) is value for name, value in flags.items()))
            valid_cleanup = (isinstance(result, dict) and set(result) == {"state", "correlationId", *flags}
                             and result.get("state") in {"cleaned", "unknown"}
                             and result.get("correlationId") == correlation
                             and all(result.get(name) is value for name, value in flags.items()))
            valid_abort = (isinstance(result, dict)
                           and ((set(result) == {"state", "correlationId", "cleanupReceiptSha256", *flags}
                                 and result.get("state") == "retired"
                                 and isinstance(result.get("cleanupReceiptSha256"), str)
                                 and re.fullmatch(r"[0-9a-f]{64}", result["cleanupReceiptSha256"]))
                                or (set(result) == {"state", "correlationId", *flags}
                                    and result.get("state") == "unknown"))
                           and result.get("correlationId") == correlation
                           and all(result.get(name) is value for name, value in flags.items()))
            valid = valid_status if is_cleanup_status else valid_cleanup if is_cleanup else valid_abort_status if is_abort_status else valid_abort
            if not valid:
                result = ({"state": "diagnosed", "correlationId": correlation, "phase": "unknown",
                           "cleanupAllowed": False, **flags} if is_cleanup_status else
                          {"state": "diagnosed", "correlationId": correlation, "phase": "unknown",
                           "abortAllowed": False, **flags} if is_abort_status else
                          {"state": "unknown", "correlationId": correlation, **flags})
            return {"tool": "vm_workflow", **result,
                    "ok": valid and result["state"] in {"diagnosed", "cleaned", "retired"},
                    "evidenceClass": "causal-diagnostic" if is_cleanup_status or is_abort_status else
                                     "causal-cleanup" if is_cleanup else "native-campaign",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-cp117-staged-fixture-retire-preflight", "windows-cp117-staged-fixture-retire-start", "windows-cp117-staged-fixture-retire-status", "windows-cp117-staged-fixture-retire-diagnose", "windows-cp117-staged-fixture-retire-parser", "windows-cp117-staged-fixture-retire-guard-diagnostic", "windows-cp117-staged-fixture-retire-boundary", "windows-cp117-staged-fixture-retire-tree", "windows-cp117-staged-fixture-retire-locks"}:
            if not isinstance(inputs, dict) or inputs != {}:
                return _error("vm_workflow", "Fixed CP117 staged fixture retirement takes no inputs.")
            retire = _agent_module("windows_cp117_staged_fixture_retire")
            method = {"windows-cp117-staged-fixture-retire-preflight": retire.preflight,
                      "windows-cp117-staged-fixture-retire-start": retire.start,
                      "windows-cp117-staged-fixture-retire-status": retire.status,
                      "windows-cp117-staged-fixture-retire-diagnose": retire.diagnose,
                      "windows-cp117-staged-fixture-retire-parser": retire.diagnose_parser,
                      "windows-cp117-staged-fixture-retire-guard-diagnostic": retire.diagnose_guard,
                      "windows-cp117-staged-fixture-retire-boundary": retire.diagnose_retirement_boundary,
                      "windows-cp117-staged-fixture-retire-tree": retire.diagnose_tree,
                      "windows-cp117-staged-fixture-retire-locks": retire.diagnose_locks}[action]
            try:
                result = method(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}
            projected = _agent_module("native_parity_response_projection").project(action, None, result)
            return {"tool": "vm_workflow", **projected, "evidenceClass": "native-fixture"}
        if action in {"windows-cp117-guest-agent-recovery-successor-preflight", "windows-cp117-guest-agent-recovery-successor-parser", "windows-cp117-guest-agent-recovery-successor-start", "windows-cp117-guest-agent-recovery-successor-status", "windows-cp117-guest-agent-recovery-preflight", "windows-cp117-guest-agent-recovery-parser", "windows-cp117-guest-agent-recovery-start", "windows-cp117-guest-agent-recovery-status", "windows-cp117-guest-agent-recovery-diagnose", "windows-cp117-guest-agent-recovery-journal"}:
            if inputs != {}:
                return _error("vm_workflow", "Fixed CP117 guest agent recovery takes no inputs.")
            successor = action.startswith("windows-cp117-guest-agent-recovery-successor-")
            prefix = "windows-cp117-guest-agent-recovery-successor-" if successor else "windows-cp117-guest-agent-recovery-"
            recovery = _agent_module("windows_cp117_guest_agent_recovery_successor" if successor else "windows_cp117_guest_agent_recovery")
            try:
                result = recovery.workflow(REPO_ROOT, action.removeprefix(prefix), inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = dict(recovery._UNKNOWN)
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            valid = (isinstance(result, dict) and set(result) <= {"state", "recoveryCorrelationId", "phase", "scripts", "guard", *flags}
                     and all(result.get(key) is value for key, value in flags.items())
                     and result.get("state") in {"ready", "passed", "submitted", "terminal", "blocked", "unknown", "diagnosed", "not-started"}
                     and result.get("recoveryCorrelationId", recovery._RECOVERY) == recovery._RECOVERY
                     and result.get("phase", "parser") in {"parser", "guest-exec", "guest-status", "powershell-terminal", "json-shape", "census-ready", "service-identity", "transport", "binding", "fresh", "tree", "lock", "census", "journal", "predecessor", "successor"})
            if "guard" in result:
                valid = valid and result["guard"] in recovery._JOURNAL_CODES
            if "scripts" in result:
                scripts=result["scripts"]
                valid = valid and isinstance(scripts,dict) and set(scripts)=={"validator","census","task","submit","status"} and all(value in {"valid","invalid","guest-exec","guest-status","powershell-terminal","json-shape","transport","oversize"} for value in scripts.values())
            if not valid: result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] in {"ready", "passed", "submitted", "terminal", "diagnosed"},
                    "evidenceClass": "native-recovery"}
        if action in {"windows-cp117-retirement-recovery-preflight", "windows-cp117-retirement-recovery-parser", "windows-cp117-retirement-recovery-start", "windows-cp117-retirement-recovery-status", "windows-cp117-retirement-recovery-finish"}:
            if inputs != {}:return _error("vm_workflow", "Fixed retirement recovery takes no inputs.")
            recovery = _agent_module("windows_cp117_retirement_recovery")
            try:result = recovery.workflow(REPO_ROOT, action.removeprefix("windows-cp117-retirement-recovery-"), inputs)
            except (ValueError, OSError, KeyError, TypeError):result = dict(recovery._UNKNOWN)
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            valid = (isinstance(result, dict) and set(result) <= {"state", "phase", "reason", "stageCorrelationId", "leaseId", *flags}
                     and all(result.get(key) is value for key, value in flags.items())
                     and result.get("state") in {"ready", "passed", "retired", "guest-terminal", "after-delete", "blocked", "unknown", "not-started"}
                     and result.get("stageCorrelationId", recovery.retire._STAGE) == recovery.retire._STAGE
                     and result.get("leaseId", recovery.retire._LEASE) == recovery.retire._LEASE
                     and result.get("phase", "binding") in {"binding", "fresh", "service", "census", "parser"}
                     and result.get("reason", "admission") in {"admission", "remaining-result"})
            if not valid:result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] in {"ready", "passed", "retired", "guest-terminal"}, "evidenceClass": "native-recovery"}
        if action == "windows-cp117-historical-base-archives":
            if inputs != {}: return _error("vm_workflow", "Fixed historical archive observation takes no inputs.")
            observer = _agent_module("windows_cp117_historical_base_archives")
            result = observer.observe(REPO_ROOT, inputs)
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            valid = (isinstance(result, dict) and set(result) == {"state", "phases", *flags}
                and isinstance(result.get("state"), str) and result["state"] in {"ready", "blocked", "unknown"}
                and all(result.get(k) is v for k, v in flags.items()))
            phases = result.get("phases") if isinstance(result, dict) else None
            allowed_phases = {"archived", "local-history", "remote-absence", "unknown", *("remote-" + phase for phase in ("guard", "root", "lock", "closed", "active", "stage", "exec", "status", "output", "identity", "task", "leaf", "result", "process", "installer", "product", "generation", "recheck", "transport"))}
            allowed_phases.update("remote-" + phase for phase in ("parser", "output-envelope", "output-truncated", "output-stderr-progress", "output-stderr-error", "output-stderr-other", "output-empty", "output-json", "output-shape"))
            valid = valid and isinstance(phases, dict) and set(phases) == {"transfer-recovery", "unknown-closure"} and all(isinstance(v, str) and v in allowed_phases for v in phases.values())
            valid = valid and ((result["state"] == "ready") == all(v == "archived" for v in phases.values()))
            if not valid: result = {"state": "unknown", "phases": {"transfer-recovery": "unknown", "unknown-closure": "unknown"}, **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] == "ready", "evidenceClass": "native-history"}
        if action in {"windows-cp117-c32-host-archive-start", "windows-cp117-c32-host-archive-status"}:
            if inputs != {}: return _error("vm_workflow", "Fixed host metadata archive takes no inputs.")
            archive = _agent_module("windows_cp117_c32_host_archive")
            result = (archive.start if action.endswith("-start") else archive.status)(REPO_ROOT, inputs)
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            valid = (isinstance(result, dict) and set(result) == {"state", *flags}
                and isinstance(result.get("state"), str) and result["state"] in {"archived", "blocked", "not-started", "unknown"}
                and all(result.get(k) is v for k, v in flags.items()))
            if not valid: result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] == "archived", "evidenceClass": "native-history"}
        if action == "windows-cp117-c32-host-archive-self-test":
            if inputs != {}: return _error("vm_workflow", "Fixed host archive self-test takes no inputs.")
            archive = _agent_module("windows_cp117_c32_host_archive")
            result = archive.self_test(REPO_ROOT, inputs)
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False, "componentOnly": True}
            valid = (isinstance(result, dict) and set(result) <= {"state", "cases", *flags}
                and isinstance(result.get("state"), str) and result["state"] in {"passed", "failed", "unknown"}
                and all(result.get(k) is v for k, v in flags.items()))
            if "cases" in result:
                cases = result["cases"]
                valid = valid and isinstance(cases, dict) and set(cases) == {"exclusive-rename", "destination-race"} and all(isinstance(v, str) and v in {"passed", "failed", "unknown"} for v in cases.values())
                valid = valid and ((result["state"] == "passed") == all(v == "passed" for v in cases.values()))
            elif result.get("state") != "unknown": valid = False
            if not valid: result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] == "passed", "evidenceClass": "component"}
        if action == "windows-cp117-c32-retained-parser":
            if inputs != {}:return _error("vm_workflow", "Fixed retained parser takes no inputs.")
            observer=_agent_module("windows_cp117_c32_absence")
            try:
                config,target,descriptor=observer.base._descriptor(REPO_ROOT)
                result=observer.parse_retained(REPO_ROOT,config,target,descriptor)
            except (OSError,ValueError,KeyError,TypeError):result={"state":"unknown","phase":"transport","strict":"failed","diagnostic":"failed"}
            valid=(isinstance(result,dict) and set(result)=={"state","phase","strict","diagnostic"}
                and result["state"] in {"observed","unknown"} and result["phase"] in {"ast","binding","transport"}
                and all(result[k] in {"passed","failed"} for k in ("strict","diagnostic")))
            if not valid:result={"state":"unknown","phase":"transport","strict":"failed","diagnostic":"failed"}
            observed=valid and result["state"]=="observed" and result["phase"]=="ast"
            passed=observed and all(result[k]=="passed" for k in ("strict","diagnostic"))
            return {"tool":"vm_workflow","state":"passed" if passed else "failed" if observed else "unknown","phase":result["phase"],"scripts":{k:result[k] for k in ("strict","diagnostic")},
                "replayAllowed":False,"nativeActionAllowed":False,"productAction":False,"ok":passed,"evidenceClass":"native-parser"}
        if action in {"windows-cp117-c32-archive-diagnose", "windows-cp117-c32-archive-preflight"}:
            if not isinstance(inputs, dict) or set(inputs) != {"leaseId"}:
                return _error("vm_workflow", "Fixed archive observation requires its new lease only.")
            archive = _agent_module("windows_cp117_c32_archive_admission")
            try:
                method = archive.diagnose if action.endswith("-diagnose") else archive.preflight
                result = method(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            valid = (isinstance(result, dict) and set(result) <= {"state", "phase", "absence", "retainedGuard", "retainedPhase", "hostBaseStage", "hostFailure", "hostKnownMask", "hostEntryCount", "hostFileMode", "correlationId", "baseTerminalReceiptSha256", "cleanupReceiptSha256", *flags}
                and all(result.get(k) is v for k, v in flags.items())
                and result.get("state") in {"ready", "blocked", "observed", "unknown"}
                and result.get("phase", "local-ready") in {"request", "history", "transfer-binding", "terminal-cleanup-dispatch", "local-ready", "closed", "cleanup", "absence", "host-history"}
                and result.get("hostBaseStage", "absent") in {"absent", "retained"}
                and result.get("retainedGuard", "ready") in {"ready","TASK","TASK_COUNT","TASK_STATE","TASK_ACTION_COUNT","TASK_EXEC","TASK_TRIGGER_COUNT","TASK_TRIGGER_NULL","TASK_INFO","PRINCIPAL","ACTION","ROOT","OWNER","TREE","FILE","RESULT_SIZE","RESULT_READ","RESULT_JSON","RESULT_UTF8_BOM","RESULT_UTF16_LE","RESULT_UTF16_BE","runtime-error"}
                and result.get("retainedPhase", "transport") in {"binding","script","transport","guest-exec","guest-status","running","terminal","json-shape","task","task-info","principal","action","root","owner","tree","file","result"}
                and result.get("hostFailure", "parents") in {"parents","group","leaf","binding","dispatch"}
                and result.get("hostFileMode", "unobserved") in {"unobserved","0600","0644","0664","0666"}
                and result.get("hostKnownMask", "00") in {"00","01","10","11"}
                and type(result.get("hostEntryCount", 0)) is int and 0<=result.get("hostEntryCount", 0)<=9
                and result.get("correlationId", "c32cb108-4d48-407e-9153-40774559ba50") == "c32cb108-4d48-407e-9153-40774559ba50"
                and all(isinstance(result[k], str) and re.fullmatch(r"[0-9a-f]{64}", result[k]) for k in ("baseTerminalReceiptSha256", "cleanupReceiptSha256") if k in result))
            if "absence" in result:
                census=result["absence"]
                valid=valid and (census=="unknown" or (isinstance(census,dict)
                    and set(census)=={"baseTask","transferTask","guestLeaf","baseMsi","correlationProcess"}
                    and all(v in {"absent","present","ambiguous"} for v in census.values())))
            if not valid: result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] in {"observed", "ready"}, "evidenceClass": "native-history"}
        if action in {"windows-cp117-c32-retained-task-retire-preflight", "windows-cp117-c32-retained-task-retire-start", "windows-cp117-c32-retained-task-retire-status"}:
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            retirement = "d8917ee1-667f-4ee6-9af7-b8d33f3e6fb9"
            task = "VpnControlMcpBase-c32cb108-4d48-407e-9153-40774559ba50"
            fallback = {"state": "unknown", **flags}
            if not isinstance(inputs, dict) or inputs != {}:
                return _error("vm_workflow", "Fixed c32 retained-task retirement takes no inputs.")
            module = _agent_module("windows_cp117_c32_retained_task_retire")
            try: result = module.workflow(REPO_ROOT, action.rsplit("-", 1)[1], {})
            except (ValueError, OSError, KeyError, TypeError): result = fallback
            blocked = {"intent", "platform", "binding", "lease", "terminal", "parser", "descriptor"}
            unknown = {"generation", "lease", "parser", "remote", "recheck"}
            valid = isinstance(result, dict) and all(result.get(k) is v for k, v in flags.items())
            if valid and result.get("state") == "ready":
                valid = set(result) == {"state", "retirementCorrelationId", "task", *flags} and result.get("retirementCorrelationId") == retirement and result.get("task") == task
            elif valid and result.get("state") == "terminal":
                valid = set(result) == {"state", "retirementCorrelationId", "task", *flags} and result.get("retirementCorrelationId") == retirement and result.get("task") == task
            elif valid and result.get("state") == "blocked":
                valid = set(result) == {"state", "phase", *flags} and isinstance(result.get("phase"), str) and result["phase"] in blocked
            elif valid and result.get("state") == "unknown":
                valid = (set(result) == {"state", *flags} or (set(result) == {"state", "phase", *flags} and isinstance(result.get("phase"), str) and result["phase"] in unknown))
            else: valid = False
            if not valid: result = fallback
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] in {"ready", "terminal"}, "evidenceClass": "native-history"}
        if action in {"windows-cp117-source-pre-effect-status", "windows-cp117-source-pre-effect-close", "windows-cp117-source-pre-effect-diagnose"}:
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            fallback = {"state": "unknown", "phase": "local-intent", "correlationId": "67eeeedb-a618-42d5-8e31-821650d16302", **flags}
            if not isinstance(inputs, dict) or inputs != {}:
                return _error("vm_workflow", "Fixed source closure takes no inputs.")
            module = _agent_module("windows_cp117_source_pre_effect_close")
            try: result = module.workflow(REPO_ROOT, action.rsplit("-", 1)[1], {})
            except (ValueError, OSError, KeyError, TypeError): result = fallback
            phases = {"local-intent", "pair", "descriptor", "local-journal", "remote-journal", "guest-census", "readiness", "marker-conflict", "verified-absence", "closed"}
            remote_phases = getattr(module, "_GUEST_CENSUS_PHASES", frozenset())
            guest_phases = {"observed", *remote_phases} if isinstance(remote_phases, (set, frozenset)) else {"observed"}
            valid = (isinstance(result, dict) and result.get("correlationId") == fallback["correlationId"]
                     and all(result.get(k) is False for k in flags))
            if action.endswith("-diagnose"):
                diagnostic = {"state", "phase", "guestCensusPhase", "correlationId", *flags}
                generic = {"state", "phase", "correlationId", *flags}
                valid = valid and ((set(result) == diagnostic and result.get("phase") == "guest-census"
                                    and isinstance(result.get("guestCensusPhase"), str) and result["guestCensusPhase"] in guest_phases
                                    and ((result.get("state") == "observed") == (result.get("guestCensusPhase") == "observed")))
                                   or (set(result) == generic and result.get("state") == "unknown"
                                       and isinstance(result.get("phase"), str) and result["phase"] in phases))
            elif valid and result.get("state") == "closed":
                valid = (set(result) == {"state", "correlationId", "closureReceiptSha256", *flags}
                         and isinstance(result.get("closureReceiptSha256"), str)
                         and re.fullmatch(r"[0-9a-f]{64}", result["closureReceiptSha256"]) is not None)
            elif valid:
                valid = (set(result) == set(fallback) and result.get("state") in {"observed", "unknown"}
                         and isinstance(result.get("phase"), str) and result["phase"] in phases
                         and (result["state"] != "observed" or result["phase"] in {"verified-absence", "closed"}))
            if not valid: result = fallback
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] in {"observed", "closed"}, "evidenceClass": "native-history"}
        if action == "windows-cp117-cp95-task-retire-successor-admission-diagnose":
            if not isinstance(inputs, dict) or inputs != {}:
                return _error("vm_workflow", "Fixed successor diagnosis takes no inputs.")
            module = _agent_module("windows_cp117_cp95_task_retire")
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            fallback = {"state": "unknown", "phase": "intent", "retirementCorrelationId": "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86", "tailCorrelationId": "7cc61627-2881-4cc3-887d-a5bf545ed2ca", **flags}
            stages = {"parent", "descriptor", "specs", "closure", "old-child", "successor-child", "lease", "tailplan", "fresh", "ready"}
            phases = stages | {stage + "-" + kind for stage in stages for kind in {"oserror", "valueerror", "typeerror", "keyerror", "indexerror"}}
            try:
                result = module.successor_admission_diagnose(REPO_ROOT, {})
            except (ValueError, OSError, KeyError, TypeError):
                result = fallback
            valid = (isinstance(result, dict) and set(result) == set(fallback) and
                     result.get("state") == "diagnosed" and isinstance(result.get("phase"), str) and result["phase"] in phases and
                     all(result.get(key) == fallback[key] for key in ("retirementCorrelationId", "tailCorrelationId")) and
                     all(result.get(key) is False for key in flags))
            return {"tool": "vm_workflow", **(result if valid else fallback), "ok": valid, "evidenceClass": "native-observation"}
        if action in {"windows-cp117-cp95-task-retire-diagnose", "windows-cp117-cp95-task-retire-finish-diagnose", "windows-cp117-cp95-task-retire-tail-diagnose"}:
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            fallback = {"state": "unknown", "phase": "intent",
                        "retirementCorrelationId": "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86", **flags}
            tail = action.endswith("-tail-diagnose")
            if tail:
                fallback["tailCorrelationId"] = "60c5d5da-1d80-492b-90b5-7a4a9ad48b34"
            if not isinstance(inputs, dict) or inputs != {}:
                return _error("vm_workflow", "Fixed CP95 journal diagnosis takes no inputs.")
            module = _agent_module("windows_cp117_cp95_task_retire")
            try:
                result = (module.finish_diagnose(REPO_ROOT, {}) if action.endswith("-finish-diagnose")
                          else module.tail_diagnose(REPO_ROOT, {}) if tail
                          else module.workflow(REPO_ROOT, "diagnose", {}))
            except (ValueError, OSError, KeyError, TypeError):
                result = fallback
            phases = {"intent", "descriptor", "generation", "remote-stage", "remote-file",
                      "remote-encoding", "remote-decoder", "archive", "terminal", "complete"}
            phases |= {"remote-file-" + phase for phase in {"root-absent", "root-unsafe", "binding-absent",
                       "archive-absent", "terminal-absent", "file-unsafe", "access", "readable"}}
            if action.endswith("-finish-diagnose"):
                phases = {"process", "binding", "archive", "task", "root", "terminal", "ready", "unknown"} | {"task-query", *{"task-present-" + str(i) for i in range(1, 6)}}
            if tail:
                phases = {"parent-intent", "child-intent-absent", "child-intent", "remote-file", "unknown"} | {"remote-file-" + phase for phase in {"root-absent", "root-unsafe", "binding-absent", "archive-absent", "terminal-absent", "file-unsafe", "access", "readable"}}
            valid = (isinstance(result, dict) and set(result) == set(fallback) and
                     result.get("state") == "diagnosed" and isinstance(result.get("phase"), str) and
                     result["phase"] in phases and
                     result.get("retirementCorrelationId") == fallback["retirementCorrelationId"] and
                     all(result.get(key) is False for key in flags) and
                     (not tail or result.get("tailCorrelationId") == fallback["tailCorrelationId"]))
            if not valid:
                result = fallback
            return {"tool": "vm_workflow", **result, "ok": valid, "evidenceClass": "native-history"}
        if action in {"windows-cp117-cp95-task-retire-successor-start", "windows-cp117-cp95-task-retire-successor-status", "windows-cp117-cp95-task-retire-tail-close-pre-effect", "windows-cp117-cp95-task-retire-tail-start", "windows-cp117-cp95-task-retire-tail-status", "windows-cp117-cp95-task-retire-finish", "windows-cp117-cp95-task-retire-preflight", "windows-cp117-cp95-task-retire-start", "windows-cp117-cp95-task-retire-status", "windows-cp117-e848-http-task-retire-preflight", "windows-cp117-e848-http-task-retire-start", "windows-cp117-e848-http-task-retire-status"}:
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            closure = action == "windows-cp117-cp95-task-retire-tail-close-pre-effect"
            successor = action in {"windows-cp117-cp95-task-retire-successor-start", "windows-cp117-cp95-task-retire-successor-status"}
            tail = closure or successor or action in {"windows-cp117-cp95-task-retire-tail-start", "windows-cp117-cp95-task-retire-tail-status"}
            e848 = action.startswith("windows-cp117-e848-")
            fallback = {"state": "unknown", "phase": "proof", "retirementCorrelationId": "477365c8-3c78-4d5c-83c9-2f6de2bd5997" if e848 else "9a5d3d6a-5f43-4a3f-9e4e-f90b9cc86e86", **flags}
            if tail:
                fallback["tailCorrelationId"] = "7cc61627-2881-4cc3-887d-a5bf545ed2ca" if successor else "60c5d5da-1d80-492b-90b5-7a4a9ad48b34"
            if not isinstance(inputs, dict) or inputs != {}:
                return _error("vm_workflow", "Fixed CP95 task retirement takes no inputs.")
            module = _agent_module("windows_cp117_e848_http_task_retire" if e848 else "windows_cp117_cp95_task_retire")
            try:
                result = (module.successor_start(REPO_ROOT, {}) if action == "windows-cp117-cp95-task-retire-successor-start"
                          else module.successor_status(REPO_ROOT, {}) if action == "windows-cp117-cp95-task-retire-successor-status"
                          else module.tail_close_pre_effect(REPO_ROOT, {}) if closure
                          else module.tail_start(REPO_ROOT, {}) if action == "windows-cp117-cp95-task-retire-tail-start"
                          else module.tail_status(REPO_ROOT, {}) if action == "windows-cp117-cp95-task-retire-tail-status"
                          else module.workflow(REPO_ROOT, action.rsplit("-", 1)[1], {}))
            except (ValueError, OSError, KeyError, TypeError): result = fallback
            phases = getattr(module, "_PHASES", frozenset())
            diagnostic_phases = getattr(module, "_DIAGNOSTIC_PHASES", frozenset())
            valid = (isinstance(phases, (set, frozenset)) and isinstance(diagnostic_phases, (set, frozenset))
                     and isinstance(result, dict) and isinstance(result.get("state"), str) and result["state"] in {"not-started", "ready", "blocked", "unknown", "retired", "closed"}
                     and isinstance(result.get("phase"), str) and result["phase"] in phases
                     and result.get("retirementCorrelationId") == fallback["retirementCorrelationId"]
                     and all(result.get(k) is False for k in flags)
                     and (result["state"] != "retired" or result["phase"] == "complete") and
                     (result["state"] != "closed" or (closure and result["phase"] == "tail-closure-complete")))
            allowed = {"state", "phase", "retirementCorrelationId", *flags}
            if tail:
                allowed.add("tailCorrelationId")
                valid = valid and result.get("tailCorrelationId") == fallback["tailCorrelationId"]
            diagnostic = result.get("snapshotDiagnostic") if isinstance(result, dict) else None
            if diagnostic is None:
                valid = valid and set(result) == allowed
            else:
                valid = valid and not e848 and result.get("state") == "blocked" and set(result) == allowed | {"snapshotDiagnostic"}
                valid = valid and isinstance(diagnostic, dict) and set(diagnostic) <= {"phase", "rawBytes", "wireBytes"} and "phase" in diagnostic
                valid = valid and isinstance(diagnostic.get("phase"), str) and diagnostic["phase"] in diagnostic_phases and all(type(diagnostic[k]) is int and 0 <= diagnostic[k] <= 150000 for k in ("rawBytes", "wireBytes") if k in diagnostic)
                valid = valid and result.get("phase") == "snapshot-output-" + diagnostic["phase"]
            if not valid: result = fallback
            return {"tool": "vm_workflow", **result, "ok": valid and (result["state"] in {"ready", "retired"} or (closure and result["state"] == "closed")), "evidenceClass": "native-history"}
        if action == "windows-cp117-cp95-retained-tasks":
            flags={"replayAllowed":False,"nativeActionAllowed":False,"productAction":False}
            fallback={"state":"unknown","phase":"proof",**flags}
            if not isinstance(inputs,dict) or inputs!={}:
                return _error("vm_workflow","Fixed CP95 task observation takes no inputs.")
            module=_agent_module("windows_cp117_cp95_retained_tasks")
            try: result=module.status(REPO_ROOT,{})
            except (ValueError,OSError,KeyError,TypeError):result=fallback
            minimal={"state","phase",*flags}
            full={"state","profiles","activeInstallerCount","opaquePowerShellCount",*flags}
            phases={"platform","local-intent","dispatch","python-intent","descriptor","active-lease","command","qga","proof","generation","recheck"}
            valid=isinstance(result,dict) and all(result.get(k) is False for k in flags)
            if valid and result.get("state")=="unknown":
                valid=set(result)==minimal and isinstance(result.get("phase"),str) and result["phase"] in phases
            elif valid and result.get("state") in {"ready","blocked"}:
                valid=(set(result)==(full if result["state"]=="ready" else full|{"phase"})
                       and (result["state"]!="blocked" or result.get("phase")=="proof")
                       and all(type(result.get(k)) is int and 0<=result[k]<=16 for k in ("activeInstallerCount","opaquePowerShellCount")))
                names=("acquire-194eb94d","acquire-26ced2bf","acquire-7b721c91","acquire-f4930053","python-f4930053")
                profiles=result.get("profiles")
                valid=valid and isinstance(profiles,list) and len(profiles)==5
                if valid:
                    for name,item in zip(names,profiles):
                        valid=(isinstance(item,dict) and set(item)=={"profile","state","result","correlatedProcess"}
                               and item.get("profile")==name and isinstance(item.get("state"),str)
                               and item["state"] in {"absent","mismatch","running","ready-unproven","terminal","unknown"}
                               and isinstance(item.get("result"),str) and item["result"] in {"unknown","succeeded","failed"}
                               and isinstance(item.get("correlatedProcess"),str) and item["correlatedProcess"] in {"absent","present","unknown"}
                               and ((item["state"]=="terminal")== (item["result"] in {"succeeded","failed"})))
                        if not valid:break
                if valid:
                    ready=(result["activeInstallerCount"]==0 and result["opaquePowerShellCount"]==0
                           and all(p["state"]=="terminal" and p["correlatedProcess"]=="absent" for p in profiles))
                    valid=(result["state"]=="ready")==ready
            else:valid=False
            if not valid:result=fallback
            return {"tool":"vm_workflow",**result,"ok":valid and result["state"]=="ready","evidenceClass":"native-history"}
        if action == "windows-cp117-e848-http-task":
            flags={"replayAllowed":False,"nativeActionAllowed":False,"productAction":False}
            if not isinstance(inputs,dict) or inputs!={}:
                return _error("vm_workflow","Fixed retained HTTP task observation takes no inputs.")
            module=_agent_module("windows_cp117_e848_http_task")
            try: result=module.observe(REPO_ROOT,{})
            except (ValueError,OSError,KeyError,TypeError):result={"state":"unknown","phase":"remote-transport","proof":"unverified",**flags}
            phases={"platform","local-history","local-active","generation","remote-transport","remote-root","remote-lock","remote-closed","remote-active","remote-stage","remote-parser","remote-exec","remote-status","remote-output","remote-output-bom","remote-output-encoding","remote-output-envelope","remote-output-truncated","remote-output-stderr-progress","remote-output-stderr-error","remote-output-stderr-other","remote-output-empty","remote-output-json","remote-output-shape","remote-identity","remote-task","remote-process","remote-installer","remote-recheck","task-state","task-principal","task-settings","task-action","task-port","task-terminal","process","installer","verified"}
            valid=(isinstance(result,dict) and set(result)=={"state","phase","proof",*flags}
                   and all(result.get(k) is False for k in flags)
                   and isinstance(result.get("phase"),str) and result["phase"] in phases|{"task-trigger","task-execution-limit"}
                   and result.get("state") in {"ready","blocked","unknown"}
                   and ((result["state"]=="ready" and result["phase"]=="verified" and result["proof"]=="terminal-success")
                        or (result["state"]!="ready" and result["phase"]!="verified" and result["proof"]=="unverified")))
            if not valid:result={"state":"unknown","phase":"remote-output","proof":"unverified",**flags}
            return {"tool":"vm_workflow",**result,"ok":valid and result["state"]=="ready","evidenceClass":"native-history"}
        if action in {"windows-cp117-source-campaign-reservation-diagnose", "windows-cp117-source-campaign-preflight", "windows-cp117-source-campaign-start", "windows-cp117-source-campaign-status", "windows-cp117-source-campaign-diagnose", "windows-cp117-source-campaign-terminal-reconcile", "windows-cp117-source-campaign-finish", "windows-cp117-source-campaign-parser"}:
            campaign = _agent_module("windows_cp117_source_campaign")
            try:
                result = campaign.workflow(REPO_ROOT, action.removeprefix("windows-cp117-source-campaign-"), inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            from agent_tools import windows_cp117_source_projection as source_projection
            projected = source_projection.project(action.removeprefix("windows-cp117-source-campaign-"), result)
            return {"tool": "vm_workflow", **projected, "evidenceClass": "native-campaign"}
        if action == "windows-cp117-campaign-status":
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 campaign status host is required.")
            campaign_status = _agent_module("windows_cp117_campaign_status")
            try:
                result = campaign_status.status(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "nextAction": "inspect-prerequisites",
                          "replayAllowed": False, "nativeActionAllowed": False}
            minimal = {"state", "nextAction", "replayAllowed", "nativeActionAllowed"}
            full = minimal | {"leaseId", "sourceSha", "fixtureReceiptArtifactId",
                              "baseMsiArtifactId", "targetMsiArtifactId", "guestGeneration", "role"}
            valid = (isinstance(result, dict) and
                     ((set(result) == minimal and result.get("state") == "unknown"
                       and result.get("nextAction") in {"inspect-prerequisites", "missing-prerequisite"})
                      or (set(result) == full and result.get("state") in {"active", "closing", "closed"}
                          and result.get("nextAction") in {"inspect-active-role", "inspect-active-campaign",
                                                             "inspect-close-progress", "inspect-closed-campaign"}
                          and isinstance(result.get("leaseId"), str)
                          and _agent_module("windows_cp117_campaign_rebase")._UUID.fullmatch(result["leaseId"])
                          and isinstance(result.get("sourceSha"), str)
                          and _agent_module("windows_msi_base_prepare")._SHA.fullmatch(result["sourceSha"])
                          and all(isinstance(result.get(key), str) and re.fullmatch(r"sha256-[0-9a-f]{64}", result[key])
                                  for key in ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"))
                          and isinstance(result.get("guestGeneration"), dict)
                          and set(result["guestGeneration"]) == {"socketPath", "qemuPid", "startTicks"}
                          and isinstance(result["guestGeneration"]["socketPath"], str)
                          and type(result["guestGeneration"]["qemuPid"]) is int
                          and type(result["guestGeneration"]["startTicks"]) is int
                          and (result.get("role") is None or result.get("role") in {
                              "base", "stage", "credentials", "credentials-cleanup", "server-start",
                              "server-stop", "owner-network", "network-probe", "target", "public"})))
                     and result.get("replayAllowed") is False
                     and result.get("nativeActionAllowed") is False)
            if not valid:
                result = {"state": "unknown", "nextAction": "inspect-prerequisites",
                          "replayAllowed": False, "nativeActionAllowed": False}
            projected = dict(result)
            projected["campaignNextAction"] = projected.pop("nextAction")
            return {"tool": "vm_workflow", **projected, "ok": valid and result["state"] != "unknown",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-cp117-campaign-diagnostic":
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 campaign diagnostic host is required.")
            campaign_status = _agent_module("windows_cp117_campaign_status")
            try:
                result = campaign_status.diagnose(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "phase": "projection", "replayAllowed": False,
                          "nativeActionAllowed": False}
            if (not isinstance(result, dict)
                    or set(result) != {"state", "phase", "replayAllowed", "nativeActionAllowed"}
                    or result.get("state") != "unknown"
                    or result.get("phase") not in campaign_status._PHASES
                    or result.get("replayAllowed") is not False
                    or result.get("nativeActionAllowed") is not False):
                result = {"state": "unknown", "phase": "projection", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": True,
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-update-fixture-phase-status":
            phases = _agent_module("windows_fixture_phase_status")
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"}
                    or not isinstance(inputs["correlationId"], str)
                    or not _agent_module("windows_update_fixture_http_stage")._canonical(inputs["correlationId"])):
                return _error("vm_workflow", "Exact Windows fixture phase correlation is required.")
            try:
                result = phases.status(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}
            base_fields = {"state", "correlationId", "phase", "nextFact", "source", "vm",
                           "campaign", "replayAllowed", "nativeActionAllowed", "productAction"}
            next_by_phase = {"intent-absent": "prepare-not-accepted",
                             "source-receipt-mismatch": "inspect-source-receipts",
                             "vm-binding-mismatch": "inspect-vm-binding",
                             "campaign-unbound": "inspect-campaign-receipt",
                             "transfer-unobserved": "observe-transfer-receipt",
                             "guest-create-or-download-unobserved": "observe-guest-receipt",
                             "extract-unobserved": "observe-extract-receipt",
                             "collected": "collection-receipt-present",
                             "observation-unknown": "observation-incomplete",
                             "pre-effect-aborted": "retire-aborted-stage"}
            observation = result.get("observation") if isinstance(result, dict) else None
            valid_observation = (observation is None or
                                 (isinstance(observation, dict) and set(observation) == {
                                     "listener", "guest", "collect"}
                                  and observation.get("listener") in {"absent", "listening", "served", "stopped", "unknown"}
                                  and observation.get("guest") in {"absent", "created", "downloaded", "hash-mismatch", "unknown"}
                                  and observation.get("collect") in {"absent", "collected"}))
            valid = (isinstance(result, dict) and
                     ((set(result) == (base_fields | ({"observation"} if observation is not None else set()))
                       and result.get("state") == "observed"
                       and result.get("correlationId") == inputs["correlationId"]
                       and result.get("phase") in phases.PHASES
                       and result.get("nextFact") == ("inspect-campaign-receipt"
                           if result["phase"] == "pre-effect-aborted" and result.get("campaign") != "role-active"
                           else next_by_phase[result["phase"]])
                       and (result["phase"] != "pre-effect-aborted" or observation is None)
                       and result.get("source") in {"absent", "unverified", "mismatch", "bound"}
                       and result.get("vm") in {"unobserved", "mismatch", "bound"}
                       and result.get("campaign") in {"unobserved", "unknown", "active", "role-active",
                                                      "pending-role", "pending-finish", "closed"}
                       and valid_observation
                       and result.get("replayAllowed") is False
                       and result.get("nativeActionAllowed") is False
                       and result.get("productAction") is False)
                      or result == {"state": "unknown", "replayAllowed": False,
                                    "nativeActionAllowed": False, "productAction": False}))
            if not valid:
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] == "observed",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-update-fixture-http-stage-extract-diagnostic":
            transfer = _agent_module("windows_update_fixture_http_stage")
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"}
                    or inputs.get("correlationId") != "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"):
                return _error("vm_workflow", "Exact stage-extract diagnostic correlation is required.")
            try:
                result = transfer.workflow(REPO_ROOT, "stage-extract-diagnostic", inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            phases = {"local-binding-invalid", "not-placed", "remote-stage-absent",
                      "remote-stage-partial", "remote-binding-mismatch", "remote-dispatch-malformed",
                      "guest-stage-absent", "guest-stage-partial", "guest-stage-full", "receipt-pending",
                      "receipt-absent", "receipt-present-unverified", "qga-protocol",
                      "remote-layout-invalid", "guest-stage-probe-failed", "dispatch-status-unknown",
                      "result-read-failed", "receipt-invalid"}
            valid = (isinstance(result, dict)
                     and set(result) == {"state", "correlationId", "binding", "phase", *flags}
                     and result.get("state") == "diagnosed"
                     and result.get("correlationId") == inputs["correlationId"]
                     and result.get("binding") in {"exact", "mismatch", "unverified"}
                     and result.get("phase") in phases
                     and all(result.get(name) is value for name, value in flags.items()))
            if not valid:
                result = {"state": "unknown", **flags}
            return {"tool": "vm_workflow", **result, "ok": valid,
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-fixture-credentials-diagnostic":
            credentials = _agent_module("windows_fixture_credentials")
            if (not isinstance(inputs, dict) or inputs != {
                    "correlationId": "791b5235-9ca7-409c-96bc-c341047c7fb4"}):
                return _error("vm_workflow", "Exact credentials diagnostic correlation is required.")
            try:
                result = credentials.diagnostic(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": inputs["correlationId"],
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            valid = (isinstance(result, dict)
                     and ((set(result) == {"state", "correlationId", "binding", "phase", "nextReadOnly", *flags}
                           and result.get("state") == "diagnosed" and result.get("correlationId") == inputs["correlationId"]
                           and result.get("binding") == "exact"
                           and result.get("phase") in {"pre-effect", "task-running", "ready-uncommitted", "terminal-failed", "partial",
                                                       "host-group-absent", "host-journal-absent", "host-binding-mismatch",
                                                       "host-layout-unsafe", "guest-observer-failed"}
                           and result.get("nextReadOnly") in {"credentials-abort-status", "credential-diagnostic", "credentials-status"})
                          or (set(result) == {"state", "correlationId", *flags}
                              and result.get("state") == "unknown" and result.get("correlationId") == inputs["correlationId"]))
                     and all(result.get(name) is value for name, value in flags.items()))
            if not valid:
                result = {"state": "unknown", "correlationId": inputs["correlationId"], **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] == "diagnosed",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-fixture-credentials-failure-detail":
            credentials = _agent_module("windows_fixture_credentials")
            if (not isinstance(inputs, dict) or inputs != {
                    "correlationId": "791b5235-9ca7-409c-96bc-c341047c7fb4"}):
                return _error("vm_workflow", "Exact credentials failure-detail correlation is required.")
            try:
                result = credentials.failure_detail(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": inputs["correlationId"],
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            valid = (isinstance(result, dict)
                     and ((set(result) == {"state", "correlationId", "binding", "taskLastResult",
                                            "safeStage", "directory", "directoryAcl", "files", "provenance",
                                            "provenanceAcl", "nextReadOnly", *flags}
                           and result.get("state") == "detailed"
                           and result.get("correlationId") == inputs["correlationId"]
                           and result.get("binding") == "exact"
                           and type(result.get("taskLastResult")) is int
                           and 0 <= result["taskLastResult"] <= 4294967295
                           and result.get("safeStage") in {"before-directory", "directory-unsafe", "directory-acl",
                                                           "before-file-write", "file-write-or-integrity", "before-provenance",
                                                           "provenance-unsafe", "provenance-acl", "after-provenance"}
                           and result.get("directory") in {"absent", "present", "unsafe"}
                           and result.get("directoryAcl") in {"absent", "verified", "mismatch", "unavailable"}
                           and result.get("files") in {"all-absent", "all-exact", "mixed"}
                           and result.get("provenance") in {"absent", "present", "unsafe"}
                           and result.get("provenanceAcl") in {"absent", "verified", "mismatch", "unavailable"}
                           and result.get("nextReadOnly") == "credentials-abort-status")
                          or (set(result) == {"state", "correlationId", *flags}
                              and result.get("state") == "unknown"
                              and result.get("correlationId") == inputs["correlationId"]))
                     and all(result.get(name) is value for name, value in flags.items()))
            if not valid:
                result = {"state": "unknown", "correlationId": inputs["correlationId"], **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] == "detailed",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-fixture-credentials-provenance-acl-shape":
            credentials = _agent_module("windows_fixture_credentials")
            if (not isinstance(inputs, dict) or inputs != {
                    "correlationId": "791b5235-9ca7-409c-96bc-c341047c7fb4"}):
                return _error("vm_workflow", "Exact credentials provenance ACL correlation is required.")
            try:
                result = credentials.provenance_acl_shape(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": inputs["correlationId"],
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            valid = (isinstance(result, dict)
                     and ((set(result) == {"state", "correlationId", "binding", "schemaVersion", "protected",
                                            "aceCount", "principals", "rights", "origin", "inheritance",
                                            "propagation", "nextReadOnly", *flags}
                           and result.get("state") == "classified"
                           and result.get("correlationId") == inputs["correlationId"]
                           and result.get("binding") == "exact" and result.get("schemaVersion") == 1
                           and result.get("protected") in {"protected", "unprotected"}
                           and result.get("aceCount") in {"three", "other"}
                           and result.get("principals") in {"exact", "duplicate", "unexpected", "missing",
                                                            "unexpected-and-missing", "unavailable"}
                           and result.get("rights") in {"all-allow-full-control", "contains-other"}
                           and result.get("origin") in {"all-explicit", "inherited-present"}
                           and result.get("inheritance") in {"file-only", "other"}
                           and result.get("propagation") in {"none", "other"}
                           and result.get("nextReadOnly") == "credentials-abort-status")
                          or (set(result) == {"state", "correlationId", *flags}
                              and result.get("state") == "unknown"
                              and result.get("correlationId") == inputs["correlationId"]))
                     and all(result.get(name) is value for name, value in flags.items()))
            if not valid:
                result = {"state": "unknown", "correlationId": inputs["correlationId"], **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] == "classified",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-fixture-credentials-pre-effect-guard-probe":
            credentials = _agent_module("windows_fixture_credentials")
            if (not isinstance(inputs, dict) or inputs != {
                    "correlationId": "6161b4ae-3634-4312-ac85-1bacd0001dfa"}):
                return _error("vm_workflow", "Exact credentials pre-effect guard correlation is required.")
            try:
                result = credentials.pre_effect_guard_probe(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "correlationId": inputs["correlationId"],
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            flags = {"replayAllowed": False, "nativeActionAllowed": False,
                     "productAction": False}
            valid = (isinstance(result, dict)
                     and ((set(result) == {"state", "correlationId", "binding", "localPayload", "remoteRoleGuard", *flags}
                           and result.get("state") == "observed" and result.get("correlationId") == inputs["correlationId"]
                           and result.get("binding") == "exact" and result.get("localPayload") == "metadata-admitted"
                           and result.get("remoteRoleGuard") in {"matched", "rejected"})
                          or (set(result) == {"state", "correlationId", *flags}
                              and result.get("state") == "unknown" and result.get("correlationId") == inputs["correlationId"]))
                     and all(result.get(name) is value for name, value in flags.items()))
            if not valid:
                result = {"state": "unknown", "correlationId": inputs["correlationId"], **flags}
            return {"tool": "vm_workflow", **result, "ok": valid and result["state"] == "observed",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action in {"windows-fixture-acl-preflight", "windows-fixture-acl-preflight-status"} or action.startswith("windows-fixture-stage-") or action.startswith("windows-fixture-credentials-") or action.startswith("windows-fixture-server-") or action.startswith("windows-fixture-owner-network-") or action.startswith("windows-fixture-network-probe-"):
            lifecycle = {
                "windows-fixture-stage-start": ("windows_update_fixture_stage", "start", {"host", "correlationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}, {"correlationId"}, {"submitted"}),
                "windows-fixture-stage-status": ("windows_update_fixture_stage", "status", {"correlationId"}, {"correlationId"}, {"running", "staged-not-server-ready"}),
                "windows-fixture-stage-collect": ("windows_update_fixture_stage", "collect", {"correlationId"}, {"correlationId"}, {"staged-not-server-ready"}),
                "windows-fixture-credentials-start": ("windows_fixture_credentials", "start", {"host", "leaseId", "stageCorrelationId", "correlationId"}, {"leaseId", "stageCorrelationId", "correlationId"}, {"submitted"}),
                "windows-fixture-credentials-status": ("windows_fixture_credentials", "status", {"correlationId"}, {"correlationId"}, {"ready"}),
                "windows-fixture-credentials-collect": ("windows_fixture_credentials", "collect", {"correlationId"}, {"correlationId"}, {"ready"}),
                "windows-fixture-server-start": ("windows_update_fixture_server", "start", {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}, {"leaseId", "stageCorrelationId", "serverCorrelationId"}, {"submitted"}),
                "windows-fixture-server-acl-preflight": ("windows_update_fixture_server", "acl_preflight", {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"}, {"leaseId", "stageCorrelationId", "serverCorrelationId"}, {"ready"}),
                "windows-fixture-server-status": ("windows_update_fixture_server", "status", {"serverCorrelationId"}, {"serverCorrelationId"}, {"live"}),
                "windows-fixture-server-collect": ("windows_update_fixture_server", "collect", {"serverCorrelationId"}, {"serverCorrelationId"}, {"live"}),
                "windows-fixture-server-stop-start": ("windows_update_fixture_server", "stop_start", {"leaseId", "serverCorrelationId", "cleanupCorrelationId"}, {"leaseId", "serverCorrelationId", "cleanupCorrelationId"}, {"submitted"}),
                "windows-fixture-server-stop-status": ("windows_update_fixture_server", "stop_status", {"cleanupCorrelationId"}, {"cleanupCorrelationId"}, {"running", "stopped"}),
                "windows-fixture-server-stop-collect": ("windows_update_fixture_server", "stop_collect", {"cleanupCorrelationId"}, {"cleanupCorrelationId"}, {"stopped"}),
                "windows-fixture-credentials-cleanup-start": ("windows_fixture_credentials", "cleanup_start", {"host", "leaseId", "stageCorrelationId", "correlationId"}, {"leaseId", "stageCorrelationId", "correlationId"}, {"submitted"}),
                "windows-fixture-credentials-cleanup-status": ("windows_fixture_credentials", "cleanup_status", {"correlationId"}, {"correlationId"}, {"running", "cleaned"}),
                "windows-fixture-credentials-cleanup-collect": ("windows_fixture_credentials", "cleanup_collect", {"correlationId"}, {"correlationId"}, {"cleaned"}),
                "windows-fixture-server-abort-start": ("windows_update_fixture_server", "abort_start", {"leaseId", "serverCorrelationId", "cleanupCorrelationId"}, {"leaseId", "serverCorrelationId", "cleanupCorrelationId"}, {"submitted"}),
                "windows-fixture-server-abort-status": ("windows_update_fixture_server", "abort_status", {"cleanupCorrelationId"}, {"cleanupCorrelationId"}, {"running", "stopped"}),
                "windows-fixture-server-abort-collect": ("windows_update_fixture_server", "abort_collect", {"cleanupCorrelationId"}, {"cleanupCorrelationId"}, {"stopped"}),
                "windows-fixture-server-abort-successor-start": ("windows_fixture_server_abort_successor", "start", {"successorCleanupCorrelationId"}, {"successorCleanupCorrelationId"}, {"submitted"}),
                "windows-fixture-server-abort-successor-status": ("windows_fixture_server_abort_successor", "status", {"successorCleanupCorrelationId"}, {"successorCleanupCorrelationId"}, {"running", "cleaned"}),
                "windows-fixture-server-abort-successor-diagnostic": ("windows_fixture_server_abort_successor", "diagnose", {"successorCleanupCorrelationId"}, {"successorCleanupCorrelationId"}, {"observed", "diagnosed"}),
                "windows-fixture-server-second-abort-successor-start": ("windows_fixture_server_second_abort_successor", "start", {"successorCorrelationId"}, {"successorCorrelationId"}, {"submitted"}),
                "windows-fixture-server-second-abort-successor-status": ("windows_fixture_server_second_abort_successor", "status", {"successorCorrelationId"}, {"successorCorrelationId"}, {"cleaned"}),
                "windows-fixture-server-second-abort-successor-diagnostic": ("windows_fixture_server_second_abort_successor", "diagnose", {"successorCorrelationId"}, {"successorCorrelationId"}, {"observed", "diagnosed"}),
                "windows-fixture-server-second-abort-recovery-diagnose": ("windows_fixture_server_second_abort_successor", "resume_diagnose", {"recoveryCorrelationId"}, {"recoveryCorrelationId"}, {"observed", "diagnosed"}),
                "windows-fixture-server-second-abort-recovery-start": ("windows_fixture_server_second_abort_successor", "resume_start", {"recoveryCorrelationId"}, {"recoveryCorrelationId"}, {"submitted"}),
                "windows-fixture-server-second-abort-recovery-status": ("windows_fixture_server_second_abort_successor", "resume_status", {"recoveryCorrelationId"}, {"recoveryCorrelationId"}, {"cleaned"}),
                "windows-fixture-server-resume-no-dispatch-start": ("windows_fixture_server_resume", "start", {"serverCorrelationId"}, {"serverCorrelationId"}, {"submitted"}),
                "windows-fixture-server-post-resource-diagnostic": ("windows_fixture_post_resource_diagnostic", "diagnose", {"serverCorrelationId"}, {"serverCorrelationId"}, {"diagnosed"}),
                "windows-fixture-server-probe-events-acl-diagnostic": ("windows_fixture_post_resource_diagnostic", "diagnose_events_acl", {"serverCorrelationId"}, {"serverCorrelationId"}, {"observed"}),
                "windows-fixture-acl-preflight": ("windows_fixture_acl_preflight", "preflight", {"stageCorrelationId"}, {"stageCorrelationId"}, {"ready"}),
                "windows-fixture-acl-preflight-status": ("windows_fixture_acl_preflight", "status", {"stageCorrelationId"}, {"stageCorrelationId"}, {"observed"}),
                "windows-fixture-credentials-abort-start": ("windows_fixture_credentials", "abort_start", {"correlationId"}, {"correlationId"}, {"submitted"}),
                "windows-fixture-credentials-abort-status": ("windows_fixture_credentials", "abort_status", {"correlationId"}, {"correlationId"}, {"running", "aborted-cleaned"}),
                "windows-fixture-credentials-abort-collect": ("windows_fixture_credentials", "abort_collect", {"correlationId"}, {"correlationId"}, {"aborted-cleaned"}),
                "windows-fixture-owner-network-start": ("windows_fixture_owner_network", "start", {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "ownerNetworkCorrelationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId", "controllerId", "ownerPid", "ownerStartedAtUtc"}, {"leaseId", "stageCorrelationId", "serverCorrelationId", "ownerNetworkCorrelationId"}, {"submitted"}),
                "windows-fixture-owner-network-status": ("windows_fixture_owner_network", "status", {"ownerNetworkCorrelationId"}, {"ownerNetworkCorrelationId"}, {"correlated"}),
                "windows-fixture-owner-network-collect": ("windows_fixture_owner_network", "collect", {"ownerNetworkCorrelationId"}, {"ownerNetworkCorrelationId"}, {"correlated"}),
                "windows-fixture-network-probe-start": ("windows_fixture_network_probe", "start", {"host", "leaseId", "stageCorrelationId", "serverCorrelationId", "probeCorrelationId", "sourceSha", "fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId", "controllerId", "ownerPid", "ownerStartedAtUtc"}, {"leaseId", "stageCorrelationId", "serverCorrelationId", "probeCorrelationId"}, {"submitted"}),
                "windows-fixture-network-probe-status": ("windows_fixture_network_probe", "status", {"probeCorrelationId"}, {"probeCorrelationId"}, {"correlated"}),
                "windows-fixture-network-probe-collect": ("windows_fixture_network_probe", "collect", {"probeCorrelationId"}, {"probeCorrelationId"}, {"correlated"}),
            }
            route = lifecycle.get(action)
            if route is None:
                return _error("vm_workflow", "Unknown fixed Windows fixture lifecycle action.")
            module_name, method_name, fields, uuid_fields, passing_states = route
            if not isinstance(inputs, dict) or set(inputs) != fields or ("host" in fields and inputs.get("host") != "archlinux"):
                return _error("vm_workflow", "Windows fixture lifecycle requires exact CP117 fields.")
            if any(not isinstance(inputs[key], str) or not _valid_uuid(inputs[key]) for key in uuid_fields):
                return _error("vm_workflow", "Windows fixture lifecycle correlation is invalid.")
            if len({inputs[key] for key in uuid_fields}) != len(uuid_fields):
                return _error("vm_workflow", "Windows fixture lifecycle correlations must differ.")
            if "sourceSha" in fields and (not isinstance(inputs["sourceSha"], str) or not re.fullmatch(r"[0-9a-f]{40}", inputs["sourceSha"])):
                return _error("vm_workflow", "Windows fixture lifecycle source SHA is invalid.")
            for key in ("fixtureReceiptArtifactId", "baseMsiArtifactId", "targetMsiArtifactId"):
                if key in fields and (not isinstance(inputs[key], str) or not re.fullmatch(r"sha256-[0-9a-f]{64}", inputs[key])):
                    return _error("vm_workflow", "Windows fixture lifecycle artifact identity is invalid.")
            if "controllerId" in fields and (not isinstance(inputs["controllerId"], str) or not _valid_uuid(inputs["controllerId"])):
                return _error("vm_workflow", "Windows fixture controller identity is invalid.")
            if "ownerPid" in fields and (type(inputs["ownerPid"]) is not int or inputs["ownerPid"] <= 0):
                return _error("vm_workflow", "Windows fixture owner PID is invalid.")
            if "ownerStartedAtUtc" in fields and (not isinstance(inputs["ownerStartedAtUtc"], str) or not re.fullmatch(r"20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", inputs["ownerStartedAtUtc"])):
                return _error("vm_workflow", "Windows fixture owner start time is invalid.")
            try:
                adapter = _agent_module(module_name)
                result = getattr(adapter, method_name)(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result, "ok": result.get("state") in passing_states and result.get("replayAllowed") is False,
                        "evidenceClass": "native-fixture", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                if action in {
                        "windows-fixture-server-second-abort-successor-start",
                        "windows-fixture-server-second-abort-successor-status",
                        "windows-fixture-server-second-abort-successor-diagnostic",
                        "windows-fixture-server-second-abort-recovery-diagnose",
                        "windows-fixture-server-second-abort-recovery-start",
                        "windows-fixture-server-second-abort-recovery-status"}:
                    correlation_key = ("recoveryCorrelationId" if "-recovery-" in action
                                       else "successorCorrelationId")
                    return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                            "reason": "windows-fixture-lifecycle-unavailable",
                            correlation_key: inputs[correlation_key], "replayAllowed": False,
                            "nativeActionAllowed": False, "productAction": False}
                return _error("vm_workflow", str(error))
        if action in {"linux-rpm-base-prepare-preflight", "linux-rpm-base-prepare-start", "linux-rpm-base-prepare-status"}:
            base = _agent_module("linux_rpm_base_prepare")
            try:
                method = {"linux-rpm-base-prepare-preflight": base.preflight,
                          "linux-rpm-base-prepare-start": base.start,
                          "linux-rpm-base-prepare-status": base.status}[action]
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"ready", "submitted", "running"} or
                              (result.get("state") == "terminal" and result.get("result") == "passed"),
                        "evidenceClass": "native-preflight" if action.endswith("-preflight") else "installed-package",
                        "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "linux-rpm-owner-observe":
            base = _agent_module("linux_rpm_base_prepare")
            try:
                result = base.observe_owner(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "observed",
                        "evidenceClass": "native-observation", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "rpm-proc-observe":
            rpm = _agent_module("native_rpm_public_install_ssh")
            try:
                result = rpm.observe_proc(REPO_ROOT, inputs)
                state = result.get("procState")
                return {"tool": "vm_workflow", **result, "state": state,
                        "ok": state == "clear"}
            except (ValueError, OSError, KeyError) as error:
                return _error("vm_workflow", str(error))
        if action == "rpm-proc-observe-privileged":
            rpm = _agent_module("native_rpm_public_install_ssh")
            try:
                result = rpm.observe_proc_privileged(REPO_ROOT, inputs)
                state = result.get("procState")
                return {"tool": "vm_workflow", **result, "state": state,
                        "ok": state == "clear"}
            except (ValueError, OSError, KeyError) as error:
                return _error("vm_workflow", str(error))
        if action == "android-admission-readback":
            required = {"host", "device", "correlationId"}
            optional = {"expectedBaseSha256", "timeoutSeconds"}
            if not isinstance(inputs, dict) or not required <= set(inputs) or set(inputs) - required - optional:
                return _error("vm_workflow", "Android admission readback requires a configured host/device and correlationId only, with optional expectedBaseSha256 and timeoutSeconds.")
            reader = _agent_module("android_admission_readback")
            try:
                result = reader.readback(REPO_ROOT, inputs["host"], inputs["device"], inputs["correlationId"],
                    expected_base_sha256=inputs.get("expectedBaseSha256"), timeout_seconds=inputs.get("timeoutSeconds", 45))
                outcome = result.get("outcome")
                return {"tool": "vm_workflow", **result,
                        "state": "unknown" if outcome == "unknown" else outcome,
                        "ok": outcome == "admitted"}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "android-admission-status":
            required = {"host", "device", "correlationId"}
            if not isinstance(inputs, dict) or not required <= set(inputs) or set(inputs) - required - {"timeoutSeconds"}:
                return _error("vm_workflow", "Android admission status requires a configured host/device and exact correlationId, with optional timeoutSeconds.")
            reader = _agent_module("android_admission_readback")
            try:
                result = reader.readback_status(REPO_ROOT, inputs["host"], inputs["device"], inputs["correlationId"],
                    timeout_seconds=inputs.get("timeoutSeconds", 45))
                outcome = result.get("outcome")
                return {"tool": "vm_workflow", **result,
                        "state": "unknown" if outcome == "unknown" else outcome,
                        "ok": result.get("ok") is True}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "android-admission-preflight":
            required = {"host", "device", "correlationId"}
            if not isinstance(inputs, dict) or not required <= set(inputs) or set(inputs) - required - {"timeoutSeconds"}:
                return _error("vm_workflow", "Android admission preflight requires configured host/device and exact correlationId, with optional timeoutSeconds.")
            reader = _agent_module("android_admission_readback")
            try:
                result = reader.preflight(REPO_ROOT, inputs["host"], inputs["device"], inputs["correlationId"],
                    timeout_seconds=inputs.get("timeoutSeconds", 60))
                outcome = result.get("outcome")
                return {"tool": "vm_workflow", **result,
                        "state": "unknown" if outcome == "unknown" else outcome,
                        "ok": outcome == "admitted"}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-readback-start", "android-readback-status", "android-readback-collect"}:
            reader = _agent_module("android_admission_readback")
            try:
                if action == "android-readback-start":
                    if not isinstance(inputs, dict) or set(inputs) != {"host", "device", "correlationId", "expectedBaseSha256"}:
                        return _error("vm_workflow", "Android async readback start requires exact host, device, correlationId and expectedBaseSha256.")
                    result = reader.async_start(REPO_ROOT, inputs["host"], inputs["device"],
                        inputs["correlationId"], inputs["expectedBaseSha256"])
                else:
                    if not isinstance(inputs, dict) or set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "Android async readback observation requires only correlationId.")
                    method = reader.async_status if action.endswith("-status") else reader.async_collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                observed = result.get("state") in {"submitted", "running", "complete"}
                return {"tool": "vm_workflow", **result, "ok": observed,
                        "admissionReady": (action == "android-readback-collect" and
                                           result.get("state") == "complete" and result.get("ok") is True),
                        "evidenceClass": "native-admission", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-package-install-start", "android-package-install-status", "android-package-install-collect"}:
            installer = _agent_module("android_package_install")
            try:
                if action.endswith("-start"):
                    required = {"host", "device", "correlationId", "artifactId", "stageIdentity",
                                "backupCorrelationId", "expectedBackupSha256", "expectedOldBaseSha256",
                                "expectedOwner", "expectedRevision"}
                    if set(inputs) != required:
                        return _error("vm_workflow", "Android package install start requires exact admitted fixture fields.")
                    result = installer.start(REPO_ROOT, inputs["host"], inputs["device"], inputs["correlationId"],
                        inputs["artifactId"], inputs["stageIdentity"], inputs["backupCorrelationId"],
                        inputs["expectedBackupSha256"], inputs["expectedOldBaseSha256"],
                        inputs["expectedOwner"], inputs["expectedRevision"])
                else:
                    if set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "Android package install observation requires only correlationId.")
                    method = installer.status if action.endswith("-status") else installer.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "running"} or
                              (result.get("state") == "complete" and result.get("ok") is True),
                        "evidenceClass": "installed-package", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "android-package-install-reconcile":
            installer = _agent_module("android_package_install")
            try:
                required = {"installCorrelationId", "currentReadbackCorrelationId",
                            "expectedCurrentOwner", "expectedCurrentRevision"}
                if set(inputs) != required:
                    return _error("vm_workflow", "Android install lease reconciliation requires exact terminal and current readback fields.")
                result = installer.reconcile_terminal_lease(REPO_ROOT, inputs["installCorrelationId"],
                    inputs["currentReadbackCorrelationId"], inputs["expectedCurrentOwner"],
                    inputs["expectedCurrentRevision"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == "complete" and result.get("leaseReleased") is True and
                              result.get("replayAllowed") is False,
                        "evidenceClass": "native-lease-reconciliation", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-package-install-unknown-proof", "android-package-install-unknown-release"}:
            required = {"installCorrelationId", "currentReadbackCorrelationId",
                        "expectedCurrentOwner", "expectedCurrentRevision"}
            if action.endswith("-release"):
                required.add("reviewedProofSha256")
            if (not isinstance(inputs, dict) or set(inputs) != required or
                    any(not isinstance(inputs[key], str) or not _valid_uuid(inputs[key])
                        for key in ("installCorrelationId", "currentReadbackCorrelationId", "expectedCurrentOwner")) or
                    type(inputs["expectedCurrentRevision"]) is not int or inputs["expectedCurrentRevision"] < 0 or
                    (action.endswith("-release") and
                     (not isinstance(inputs["reviewedProofSha256"], str) or
                      re.fullmatch(r"[0-9a-f]{64}", inputs["reviewedProofSha256"]) is None))):
                return _error("vm_workflow", "Android unknown-install recovery requires exact reviewed correlations, owner, revision and proof digest.")
            installer = _agent_module("android_package_install")
            try:
                args = (REPO_ROOT, inputs["installCorrelationId"], inputs["currentReadbackCorrelationId"],
                        inputs["expectedCurrentOwner"], inputs["expectedCurrentRevision"])
                if action.endswith("-proof"):
                    result = installer.prove_unknown_install(*args)
                    proof_sha = result.get("proofSha256")
                    admitted = (result.get("ok") is True and
                                result.get("correlationId") == inputs["installCorrelationId"] and
                                result.get("state") == "proved" and
                                isinstance(proof_sha, str) and
                                re.fullmatch(r"[0-9a-f]{64}", proof_sha) is not None and
                                result.get("leaseReleased") is False and result.get("replayAllowed") is False)
                else:
                    result = installer.release_unknown_install_lease(*args, inputs["reviewedProofSha256"])
                    admitted = (result.get("ok") is True and
                                result.get("correlationId") == inputs["installCorrelationId"] and
                                result.get("reviewedProofSha256") == inputs["reviewedProofSha256"] and
                                result.get("state") == "complete" and result.get("leaseReleased") is True and
                                result.get("replayAllowed") is False)
                return {"tool": "vm_workflow", **result, "ok": bool(admitted),
                        "evidenceClass": "native-lease-reconciliation", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-cli-stage-start", "android-cli-stage-status", "android-cli-stage-collect"}:
            stage = _agent_module("android_cli_stage")
            try:
                if action.endswith("-start"):
                    if set(inputs) != {"host", "correlationId", "artifactId"}:
                        return _error("vm_workflow", "Android CLI stage requires exact host, correlationId and artifactId.")
                    result = stage.start(REPO_ROOT, inputs["host"], inputs["correlationId"], inputs["artifactId"])
                else:
                    if set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "Android CLI stage observation requires only correlationId.")
                    method = stage.status if action.endswith("-status") else stage.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                return {"tool": "vm_workflow", **result, "evidenceClass": "native-cli-stage",
                        "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-document-acceptance-start", "android-document-acceptance-status", "android-document-acceptance-collect"}:
            document = _agent_module("android_document_acceptance")
            try:
                if action.endswith("-start"):
                    required = {"host", "device", "correlationId", "artifactId", "cliStageCorrelationId",
                                "expectedOwner", "expectedRevision"}
                    if not isinstance(inputs, dict) or set(inputs) != required:
                        return _error("vm_workflow", "Android document start requires exact admitted fixture fields.")
                    result = document.start(REPO_ROOT, inputs["host"], inputs["device"], inputs["correlationId"],
                                            inputs["artifactId"], inputs["cliStageCorrelationId"],
                                            inputs["expectedOwner"], inputs["expectedRevision"])
                else:
                    if not isinstance(inputs, dict) or set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "Android document observation requires only correlationId.")
                    method = document.status if action.endswith("-status") else document.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "running"} or
                              (result.get("state") == "complete" and result.get("ok") is True),
                        "evidenceClass": "native-document-acceptance", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-document-retry-start", "android-document-retry-status", "android-document-retry-collect"}:
            retry = _agent_module("android_document_retry")
            try:
                if action.endswith("-start"):
                    required = {"host", "device", "correlationId", "artifactId", "cliStageCorrelationId",
                                "openingReadbackCorrelationId", "expectedBackupSha256", "expectedOwner", "expectedRevision"}
                    if not isinstance(inputs, dict) or set(inputs) != required:
                        return _error("vm_workflow", "Android document retry start requires exact admitted fixture fields.")
                    result = retry.start(REPO_ROOT, inputs["host"], inputs["device"], inputs["correlationId"],
                                         inputs["artifactId"], inputs["cliStageCorrelationId"],
                                         inputs["openingReadbackCorrelationId"], inputs["expectedBackupSha256"],
                                         inputs["expectedOwner"], inputs["expectedRevision"])
                else:
                    if not isinstance(inputs, dict) or set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "Android document retry observation requires only correlationId.")
                    method = retry.status if action.endswith("-status") else retry.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "running"} or
                              (result.get("state") == "complete" and result.get("ok") is True),
                        "evidenceClass": "native-document-retry", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-document-retry-recovery-start", "android-document-retry-recovery-status",
                      "android-document-retry-recovery-collect", "android-document-retry-recovery-finalize"}:
            retry = _agent_module("android_document_retry")
            try:
                if action.endswith("-start"):
                    required = {"host", "device", "recoveryCorrelationId", "unknownRetryCorrelationId",
                                "openingReadbackCorrelationId", "currentReadbackCorrelationId", "artifactId",
                                "cliStageCorrelationId", "expectedOwner", "expectedRevision"}
                    if not isinstance(inputs, dict) or set(inputs) != required:
                        return _error("vm_workflow", "Android retry recovery requires exact original and current guards.")
                    result = retry.recovery_start(REPO_ROOT, inputs["host"], inputs["device"],
                        inputs["recoveryCorrelationId"], inputs["unknownRetryCorrelationId"],
                        inputs["openingReadbackCorrelationId"], inputs["currentReadbackCorrelationId"],
                        inputs["artifactId"], inputs["cliStageCorrelationId"],
                        inputs["expectedOwner"], inputs["expectedRevision"])
                elif action.endswith("-finalize"):
                    required = {"recoveryCorrelationId", "closingReadbackCorrelationId", "expectedOwner", "expectedRevision"}
                    if not isinstance(inputs, dict) or set(inputs) != required:
                        return _error("vm_workflow", "Android retry recovery finalize requires exact closing guard.")
                    result = retry.recovery_finalize(REPO_ROOT, inputs["recoveryCorrelationId"],
                        inputs["closingReadbackCorrelationId"], inputs["expectedOwner"], inputs["expectedRevision"])
                else:
                    if not isinstance(inputs, dict) or set(inputs) != {"recoveryCorrelationId"}:
                        return _error("vm_workflow", "Android retry recovery observation requires only correlation.")
                    method = retry.recovery_status if action.endswith("-status") else retry.recovery_collect
                    result = method(REPO_ROOT, inputs["recoveryCorrelationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "running"} or
                              (result.get("state") == "complete" and result.get("ok") is True),
                        "evidenceClass": "native-document-retry-recovery",
                        "productAction": action.endswith("-start") or action.endswith("-finalize")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-document-retry-unknown-diagnose", "android-document-retry-unknown-close"}:
            unknown_retry = _agent_module("android_document_retry_unknown")
            try:
                required = {"unknownCorrelationId", "openingReadbackCorrelationId", "currentReadbackCorrelationId"}
                if not isinstance(inputs, dict) or set(inputs) != required:
                    return _error("vm_workflow", "Android retry unknown proof requires exact correlations.")
                method = unknown_retry.diagnose if action.endswith("-diagnose") else unknown_retry.close
                result = method(REPO_ROOT, inputs["unknownCorrelationId"],
                    inputs["openingReadbackCorrelationId"], inputs["currentReadbackCorrelationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("ok") is True,
                        "evidenceClass": "native-document-retry-unknown",
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-consent-grant-acceptance-reconcile-status", "android-consent-grant-acceptance-reconcile-diagnose"}:
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"} or
                    not isinstance(inputs["correlationId"], str) or not _valid_uuid(inputs["correlationId"])):
                return _error("vm_workflow", "Reconciliation observation requires only the original canonical correlation.")
            helper = _agent_module("android_consent_grant_acceptance")
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            result = None
            try:
                method = helper.reconcile_status if action.endswith("-status") else helper.reconcile_diagnose
                result = method(REPO_ROOT, inputs["correlationId"])
            except (ValueError, OSError, KeyError, TypeError):
                pass
            base_keys = {"ok", "state", "reason", "correlationId", *flags}
            base_valid = (isinstance(result, dict) and result.get("correlationId") == inputs["correlationId"] and
                          all(result.get(k) is False for k in flags))
            enums = {"workerState": {"terminal", "live", "reused", "unknown"}, "grantRecords": {"absent", "present"},
                     "baselineRecord": {"absent", "present"}, "remoteMarker": {"absent", "valid", "invalid"},
                     "remoteClaim": {"absent", "owned", "foreign", "changed"}, "lockState": {"free", "busy", "missing", "unsafe"}}
            observed_keys = base_keys | {"records", "localMarker", "localClaims", "currentProof"}
            records = result.get("records") if isinstance(result, dict) else None
            claims = result.get("localClaims") if isinstance(result, dict) else None
            observed = (base_valid and set(result) in (observed_keys, observed_keys | {"historicalSourceSettings"}) and
                        result.get("ok") is True and result.get("state") == "observed" and result.get("reason") is None and
                        isinstance(records, dict) and set(records) == set(enums) and
                        all(isinstance(records[k], str) and records[k] in values for k, values in enums.items()) and
                        isinstance(result.get("localMarker"), str) and result["localMarker"] in {"absent", "valid", "invalid"} and
                        isinstance(claims, dict) and set(claims) == {"shared", "document"} and
                        all(isinstance(v, str) and v in {"absent", "owned", "foreign", "changed", "unsafe"} for v in claims.values()) and
                        isinstance(result.get("currentProof"), str) and result["currentProof"] in {"not-probed", "matched", "drift"} and
                        ("historicalSourceSettings" not in result or (isinstance(result["historicalSourceSettings"], str) and result["historicalSourceSettings"] in {"unavailable", "matched", "drift"})))
            reasons = getattr(helper, "_RECONCILE_REASONS", ())
            checkpoints = getattr(helper, "_RECONCILE_CHECKPOINTS", frozenset())
            unknown = (base_valid and isinstance(reasons, tuple) and isinstance(checkpoints, (set, frozenset)) and
                       set(result) in (base_keys, base_keys | {"checkpoint"}) and result.get("ok") is False and result.get("state") == "unknown" and
                       isinstance(result.get("reason"), str) and result["reason"] in reasons and
                       ("checkpoint" not in result or (isinstance(result["checkpoint"], str) and result["checkpoint"] in checkpoints)))
            projection = ({key: result[key] for key in ("state", "reason", "records", "localMarker", "localClaims", "currentProof", "historicalSourceSettings", "checkpoint") if key in result}
                          if observed or unknown else {"state": "unknown", "reason": "grant-reconciliation-observation-unavailable"})
            return {"tool": "vm_workflow", **projection, **flags, "ok": bool(observed),
                    "correlationId": inputs["correlationId"], "evidenceClass": "native-observation"}
        if action == "android-consent-grant-acceptance-reconcile":
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"} or
                    not isinstance(inputs["correlationId"], str) or not _valid_uuid(inputs["correlationId"])):
                return _error("vm_workflow", "Grant reconciliation requires only the original correlation.")
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            result = None
            try:
                result = _agent_module("android_consent_grant_acceptance").reconcile(REPO_ROOT, inputs["correlationId"])
            except (ValueError, OSError, KeyError, TypeError):
                pass
            proof = result.get("proof") if isinstance(result, dict) else None
            true_keys = {"workerTerminal", "noGrantIntents", "configurationGenerationUnchanged", "fullRoutingUnchanged", "packageUnchanged", "currentSourceSettingsStable", "currentRuntimeStable", "currentOperationsStable", "permissionAbsent", "runtimeOff"}
            hashes = {"retainedBindingsSha256", "currentSnapshotSha256"}
            valid = (isinstance(result, dict) and set(result) == {"ok", "state", "reason", "correlationId", *flags, "proof", "claimsReleased", "originalOutcome", "grantObserved"} and
                     result.get("ok") is True and result.get("state") == "closed" and result.get("reason") is None and
                     result.get("correlationId") == inputs["correlationId"] and all(result.get(k) is False for k in flags) and
                     result.get("claimsReleased") is True and result.get("originalOutcome") == "unknown" and result.get("grantObserved") is False and
                     isinstance(proof, dict) and set(proof) == true_keys | hashes | {"historicalSourceSettingsAvailable"} and
                     all(proof[k] is True for k in true_keys) and type(proof["historicalSourceSettingsAvailable"]) is bool and
                     all(isinstance(proof[k], str) and re.fullmatch(r"[0-9a-f]{64}", proof[k]) is not None for k in hashes))
            projection = ({"state": "closed", "claimsReleased": True, "originalOutcome": "unknown", "grantObserved": False, "proof": dict(proof)}
                          if valid else {"state": "unknown", "reason": "grant-no-effect-closure-unavailable"})
            return {"tool": "vm_workflow", **projection, **flags, "ok": valid,
                    "correlationId": inputs["correlationId"], "evidenceClass": "native-reconciliation"}
        if action == "android-obsolete-consent-denial-collect":
            if (not isinstance(inputs, dict) or set(inputs) != {"denialId"} or
                    not isinstance(inputs["denialId"], str) or not _valid_uuid(inputs["denialId"])):
                return _error("vm_workflow", "Obsolete dialog collection requires only its canonical denial correlation.")
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            result = None
            try:
                result = _agent_module("android_obsolete_consent_denial").collect(REPO_ROOT, inputs["denialId"])
            except (ValueError, OSError, KeyError, TypeError):
                pass
            proof = result.get("proof") if isinstance(result, dict) else None
            ids = {"denialId", "closureId", "originalCorrelationId", "observationId"}
            hashes = {"intentSha256", "tapSha256"}
            false_keys = {"grantObserved", "permissionGranted", "runtimeStarted"}
            valid = (isinstance(result, dict) and
                     set(result) == {"ok", "state", "reason", "denialId", *flags, "originalOutcome",
                                     "grantObserved", "proof", "remoteClaimReleased", "claimsReleased"} and
                     result.get("ok") is True and result.get("state") == "complete" and result.get("reason") is None and
                     result.get("denialId") == inputs["denialId"] and all(result.get(k) is False for k in flags) and
                     result.get("originalOutcome") == "unknown" and result.get("grantObserved") is False and
                     result.get("claimsReleased") is True and result.get("remoteClaimReleased") is True and
                     isinstance(proof, dict) and set(proof) == ids | hashes | false_keys | {"schema", "originalOutcome", "uiAbsent", "scope"} and
                     type(proof.get("schema")) is int and proof["schema"] == 1 and
                     all(isinstance(proof[k], str) and _valid_uuid(proof[k]) for k in ids) and
                     proof["denialId"] == inputs["denialId"] and
                     proof["denialId"] not in {proof["closureId"], proof["originalCorrelationId"]} and
                     all(isinstance(proof[k], str) and re.fullmatch(r"[0-9a-f]{64}", proof[k]) is not None for k in hashes) and
                     all(proof[k] is False for k in false_keys) and proof["uiAbsent"] is True and
                     proof["originalOutcome"] == "unknown" and proof["scope"] == "obsolete-dialog-denial")
            return {"tool": "vm_workflow", "ok": valid, "state": "complete" if valid else "unknown",
                    "reason": None if valid else "obsolete-dialog-collection-unavailable", **inputs, **flags,
                    "claimsReleased": valid, "remoteClaimReleased": valid, "originalOutcome": "unknown",
                    "grantObserved": False, "evidenceClass": "native-reconciliation",
                    **({"proof": dict(proof)} if valid else {})}
        if action == "android-consent-grant-prompt-collect":
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId", "observationId"} or
                    any(not isinstance(inputs[k], str) or not _valid_uuid(inputs[k]) for k in inputs)):
                return _error("vm_workflow", "Prompt collection requires canonical original and observation correlations.")
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False, "claimsReleased": False}
            result = None
            try:
                result = _agent_module("android_consent_grant_acceptance").prompt_collect(REPO_ROOT, inputs["correlationId"], inputs["observationId"])
            except (ValueError, OSError, KeyError, TypeError):
                pass
            parent = REPO_ROOT / ".rag_index/android-consent-grant-acceptance" / ("prompt-" + inputs["correlationId"] + "-" + inputs["observationId"])
            expected_paths = {name: str(parent / name) for name in ("ui.xml", "ui.png", "binding.json", "operation-observation.json")}
            valid = (isinstance(result, dict) and set(result) == {"ok", "state", "reason", "correlationId", "observationId", "localPaths", *flags} and
                     result.get("ok") is True and result.get("state") == "complete" and result.get("reason") is None and
                     result.get("correlationId") == inputs["correlationId"] and result.get("observationId") == inputs["observationId"] and
                     all(result.get(k) is False for k in flags) and result.get("localPaths") == expected_paths)
            return {"tool": "vm_workflow", "ok": valid, "state": "complete" if valid else "unknown",
                    "reason": None if valid else "prompt-collection-unavailable", **inputs, **flags,
                    "evidenceClass": "native-observation", "artifactCount": 4 if valid else 0}
        if action == "android-consent-grant-acceptance-diagnose":
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"} or
                    not isinstance(inputs["correlationId"], str) or not _valid_uuid(inputs["correlationId"])):
                return _error("vm_workflow", "Grant diagnosis requires only the original canonical correlation.")
            flags = {"replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
            result = None
            try:
                result = _agent_module("android_consent_grant_acceptance").diagnose(REPO_ROOT, inputs["correlationId"])
            except (ValueError, OSError, KeyError, TypeError):
                pass
            checks = result.get("checks") if isinstance(result, dict) else None
            facts = result.get("facts") if isinstance(result, dict) else None
            check_keys = {"runtimeOff", "runtimeStopped", "vpnMode", "selectionNull", "activeNull", "locationsEmpty", "sourceCurrentLocations", "subscriptionNull"}
            enums = {"configuredMode": {"vpn", "proxy-only", "missing", "other"},
                     "runtimeObservation": {"stopped", "running", "unknown", "missing", "other"},
                     "sourceMode": {"current-locations", "subscription", "missing", "other"},
                     "subscriptionBinding": {"null", "empty", "selected", "missing", "other"},
                     "locationShape": {"array", "missing", "other"}, "operationShape": {"array", "other"}}
            bool_keys = {"locationCountTruncated", "operationCountTruncated", "operationsTerminal", "selectedFieldPresent", "activeFieldPresent"}
            valid = (isinstance(result, dict) and set(result) == {"ok", "state", "reason", "correlationId", *flags, "historicalReason", "observationClass", "checks", "facts"} and
                     result.get("ok") is True and result.get("state") == "diagnosed" and result.get("reason") is None and
                     result.get("correlationId") == inputs["correlationId"] and all(result.get(k) is False for k in flags) and
                     result.get("historicalReason") == "baseline_not_empty_off" and result.get("observationClass") == "fresh-current-baseline" and
                     isinstance(checks, dict) and set(checks) == check_keys and all(type(v) is bool for v in checks.values()) and
                     isinstance(facts, dict) and set(facts) == set(enums) | bool_keys | {"locationCount", "operationCount"} and
                     all(isinstance(facts[k], str) and facts[k] in values for k, values in enums.items()) and
                     all(type(facts[k]) is bool for k in bool_keys) and
                     all(type(facts[k]) is int and 0 <= facts[k] <= 128 for k in ("locationCount", "operationCount")))
            projection = ({"state": "diagnosed", "historicalReason": "baseline_not_empty_off", "observationClass": "fresh-current-baseline", "checks": dict(checks), "facts": dict(facts)}
                          if valid else {"state": "unknown", "reason": "grant-diagnostic-proof-unavailable"})
            return {"tool": "vm_workflow", **projection, **flags, "ok": valid,
                    "correlationId": inputs["correlationId"], "evidenceClass": "native-observation"}
        if action in {"android-consent-grant-acceptance-start", "android-consent-grant-acceptance-status",
                      "android-consent-grant-acceptance-collect"}:
            start_action = action.endswith("-start")
            required = ({"host", "device", "correlationId", "artifactId", "cliStageCorrelationId",
                         "openingReadbackCorrelationId", "expectedBackupSha256",
                         "expectedOwner", "expectedRevision"} if start_action else {"correlationId"})
            if not isinstance(inputs, dict) or set(inputs) != required:
                return _error("vm_workflow", "Android consent grant requires exact receipt bindings.")
            uuid_keys = ({"correlationId", "cliStageCorrelationId", "openingReadbackCorrelationId",
                          "expectedOwner"} if start_action else {"correlationId"})
            if any(not isinstance(inputs[key], str) or not _valid_uuid(inputs[key]) for key in uuid_keys):
                return _error("vm_workflow", "Android consent grant requires canonical correlations.")
            if start_action and (not isinstance(inputs["artifactId"], str) or
                    re.fullmatch(r"sha256-[0-9a-f]{64}", inputs["artifactId"]) is None or
                    not isinstance(inputs["expectedBackupSha256"], str) or
                    re.fullmatch(r"[0-9a-f]{64}", inputs["expectedBackupSha256"]) is None or
                    type(inputs["expectedRevision"]) is not int or inputs["expectedRevision"] < 0):
                return _error("vm_workflow", "Android consent grant requires exact artifact and revision.")
            if start_action and (inputs["host"] != "archlinux" or inputs["device"] != "api35"):
                return _error("vm_workflow", "Android grant requires the configured disposable API35 route.")
            reset = _agent_module("android_consent_grant_acceptance")
            try:
                if start_action:
                    result = reset.start(REPO_ROOT, inputs["host"], inputs["device"], inputs["correlationId"], inputs["artifactId"],
                        inputs["cliStageCorrelationId"], inputs["openingReadbackCorrelationId"],
                        inputs["expectedBackupSha256"], inputs["expectedOwner"], inputs["expectedRevision"])
                else:
                    method = reset.status if action.endswith("-status") else reset.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
            except (ValueError, OSError, KeyError, TypeError):
                result = None
            projected = _agent_module("native_parity_response_projection").project(
                action, inputs["correlationId"], result)
            return {"tool": "vm_workflow", **projected,
                    "evidenceClass": "native-consent-grant-acceptance"}
        if action in {"android-vpn-permission-reset-start", "android-vpn-permission-reset-status",
                      "android-vpn-permission-reset-collect"}:
            start_action = action.endswith("-start")
            required = ({"correlationId", "artifactId", "cliStageCorrelationId",
                         "openingReadbackCorrelationId", "expectedBackupSha256",
                         "expectedOwner", "expectedRevision"} if start_action else {"correlationId"})
            if not isinstance(inputs, dict) or set(inputs) != required:
                return _error("vm_workflow", "Android permission reset requires exact receipt bindings.")
            uuid_keys = ({"correlationId", "cliStageCorrelationId", "openingReadbackCorrelationId",
                          "expectedOwner"} if start_action else {"correlationId"})
            if any(not isinstance(inputs[key], str) or not _valid_uuid(inputs[key]) for key in uuid_keys):
                return _error("vm_workflow", "Android permission reset requires canonical correlations.")
            if start_action and (not isinstance(inputs["artifactId"], str) or
                    re.fullmatch(r"sha256-[0-9a-f]{64}", inputs["artifactId"]) is None or
                    not isinstance(inputs["expectedBackupSha256"], str) or
                    re.fullmatch(r"[0-9a-f]{64}", inputs["expectedBackupSha256"]) is None or
                    type(inputs["expectedRevision"]) is not int or inputs["expectedRevision"] < 0):
                return _error("vm_workflow", "Android permission reset requires exact artifact and revision.")
            reset = _agent_module("android_vpn_permission_reset")
            try:
                if start_action:
                    result = reset.start(REPO_ROOT, inputs["correlationId"], inputs["artifactId"],
                        inputs["cliStageCorrelationId"], inputs["openingReadbackCorrelationId"],
                        inputs["expectedBackupSha256"], inputs["expectedOwner"], inputs["expectedRevision"])
                else:
                    method = reset.status if action.endswith("-status") else reset.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
            except (ValueError, OSError, KeyError, TypeError):
                result = None
            projected = _agent_module("native_parity_response_projection").project(
                action, inputs["correlationId"], result)
            return {"tool": "vm_workflow", **projected,
                    "evidenceClass": "native-vpn-permission-reset"}
        if action in {"android-runtime-acceptance-start", "android-runtime-acceptance-status",
                      "android-runtime-acceptance-collect"}:
            required = ({"correlationId", "endpointCorrelationId", "cliStageCorrelationId"}
                        if action.endswith("-start") else {"correlationId"})
            if (not isinstance(inputs, dict) or set(inputs) != required or
                    any(not isinstance(inputs[key], str) or not _valid_uuid(inputs[key])
                        for key in required)):
                return _error("vm_workflow", "Android runtime requires exact canonical correlations.")
            runtime = _agent_module("android_runtime_acceptance")
            try:
                if action.endswith("-start"):
                    result = runtime.start(REPO_ROOT, inputs["correlationId"],
                        inputs["endpointCorrelationId"], inputs["cliStageCorrelationId"])
                else:
                    method = runtime.status if action.endswith("-status") else runtime.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
            except (ValueError, OSError, KeyError, TypeError):
                result = None
            projected = _agent_module("native_parity_response_projection").project(
                action, inputs["correlationId"], result)
            return {"tool": "vm_workflow", **projected,
                    "evidenceClass": "native-runtime-acceptance"}
        if action in {"android-action-acceptance-start", "android-action-acceptance-status",
                      "android-action-acceptance-collect"}:
            action_fixture = _agent_module("android_action_acceptance")
            try:
                if action.endswith("-start"):
                    required = {"host", "device", "correlationId", "artifactId", "backupCorrelationId",
                                "expectedBackupSha256", "expectedOwner", "expectedRevision"}
                    if not isinstance(inputs, dict) or set(inputs) != required:
                        return _error("vm_workflow", "Android action start requires exact guarded fixture fields.")
                    result = action_fixture.start(REPO_ROOT, inputs["host"], inputs["device"],
                        inputs["correlationId"], inputs["artifactId"], inputs["backupCorrelationId"],
                        inputs["expectedBackupSha256"], inputs["expectedOwner"], inputs["expectedRevision"])
                else:
                    if not isinstance(inputs, dict) or set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "Android action observation requires only correlationId.")
                    method = action_fixture.status if action.endswith("-status") else action_fixture.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "running"} or
                              (result.get("state") == "complete" and result.get("ok") is True),
                        "evidenceClass": "native-action-acceptance", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "android-api35-remaining-proxy-status":
            unknown = {"tool": "vm_workflow", "ok": False, "state": "diagnostic-only",
                       "reason": "observation_unknown", "productAdmitted": False,
                       "acceptanceComplete": False, "replayAllowed": False, "productAction": False}
            if type(inputs) is not dict or inputs:
                return unknown
            try:
                result = _agent_module("android_api35_remaining_proxy_status_routes").dispatch(REPO_ROOT, action, {})
                keys = {"tool", "ok", "state", "reason", "productAdmitted", "acceptanceComplete",
                        "replayAllowed", "receiptSha256", "receiptBytes", "controllerId",
                        "configurationRevision", "runtimeOff", "fourProxyRowsAbsent", "exclusionEmpty",
                        "binderProxyClear", "originalOperationOutcome", "historicalUnknownsPreserved", "recordCount"}
                if (type(result) is not dict or set(result) != keys or
                    result["tool"] != "vm_workflow" or result["ok"] is not True or
                    result["state"] != "remaining-proxy-restored" or result["reason"] != "observed" or
                    any(result[name] is not False for name in ("productAdmitted", "acceptanceComplete", "replayAllowed")) or
                    any(result[name] is not True for name in ("runtimeOff", "fourProxyRowsAbsent", "exclusionEmpty", "binderProxyClear", "historicalUnknownsPreserved")) or
                    result["originalOperationOutcome"] != "unknown" or
                    type(result["receiptBytes"]) is not int or not 0 < result["receiptBytes"] <= 8388608 or
                    type(result["configurationRevision"]) is not int or result["configurationRevision"] != 0 or
                    type(result["recordCount"]) is not int or result["recordCount"] != 4 or
                    type(result["receiptSha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", result["receiptSha256"]) is None or
                    type(result["controllerId"]) is not str or re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", result["controllerId"]) is None):
                    return unknown
                return {**result, "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return unknown
        if action == "android-fixture-tls-mint":
            required = {"campaignId", "sourceSha", "baseArtifactId", "targetArtifactId"}
            if (not isinstance(inputs, dict) or set(inputs) not in (required, required | {"sourceRoot"}) or
                    not isinstance(inputs.get("campaignId"), str) or not _valid_uuid(inputs["campaignId"]) or
                    not isinstance(inputs.get("sourceSha"), str) or not re.fullmatch(r"[0-9a-f]{40}", inputs["sourceSha"]) or
                    any(not isinstance(inputs[key], str) or not re.fullmatch(r"sha256-[0-9a-f]{64}", inputs[key])
                        for key in ("baseArtifactId", "targetArtifactId")) or
                    ("sourceRoot" in inputs and (not isinstance(inputs["sourceRoot"], str) or
                     not 1 <= len(inputs["sourceRoot"]) <= 4096 or "\x00" in inputs["sourceRoot"] or
                     not Path(inputs["sourceRoot"]).is_absolute()))):
                return _error("vm_workflow", "TLS mint requires exact source-bound local fixture fields.")
            try:
                result = _agent_module("android_fixture_tls_routes").run(REPO_ROOT, inputs)
                if (set(result) != {"ok", "campaignId", "receipt", "deviceMutationPerformed", "evidenceDirectory"} or
                        result["ok"] is not True or result["campaignId"] != inputs["campaignId"] or
                        result["deviceMutationPerformed"] is not False):
                    raise ValueError("TLS route result invalid")
                def tls_pin(value):
                    return (type(value) is dict and set(value) == {"sha256", "bytes", "generation"} and
                            type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) and
                            type(value["bytes"]) is int and 0 < value["bytes"] <= 1048576 and
                            type(value["generation"]) is list and len(value["generation"]) == 8 and
                            all(type(item) is int and item >= 0 for item in value["generation"]) and
                            value["generation"][2] == value["bytes"] and value["generation"][5] == 0o600 and
                            value["generation"][7] == 1)
                receipt = result["receipt"]
                if (type(receipt) is not dict or set(receipt) != {"schema", "campaignId", "tlsReceipt",
                        "nestedBinding", "verifiedPlanSha256", "deviceMutationAllowed"} or
                        type(receipt["schema"]) is not int or receipt["schema"] != 1 or
                        receipt["campaignId"] != inputs["campaignId"] or receipt["deviceMutationAllowed"] is not False or
                        type(receipt["verifiedPlanSha256"]) is not str or
                        not re.fullmatch(r"[0-9a-f]{64}", receipt["verifiedPlanSha256"]) or
                        not tls_pin(receipt["tlsReceipt"])):
                    raise ValueError("TLS receipt invalid")
                binding = receipt["nestedBinding"]
                if (type(binding) is not dict or set(binding) != {"nestedName", "nestedGeneration", "materialPins"} or
                        type(binding["nestedName"]) is not str or not binding["nestedName"].startswith("android-fixture-tls-") or
                        not _valid_uuid(binding["nestedName"].removeprefix("android-fixture-tls-")) or
                        type(binding["nestedGeneration"]) is not list or len(binding["nestedGeneration"]) != 8 or
                        any(type(item) is not int or item < 0 for item in binding["nestedGeneration"]) or
                        binding["nestedGeneration"][5] != 0o700 or binding["nestedGeneration"][7] < 2 or
                        type(binding["materialPins"]) is not dict or set(binding["materialPins"]) !=
                        {"ca-key.pem", "ca.pem", "leaf-key.pem", "leaf.pem", "receipt.json"} or
                        not all(tls_pin(pin) for pin in binding["materialPins"].values()) or
                        binding["materialPins"]["receipt.json"] != receipt["tlsReceipt"] or
                        result["evidenceDirectory"] != str(REPO_ROOT.resolve() / ".runtime" / "parity-evidence" /
                                                          ("android-fixture-tls-route-" + inputs["campaignId"]))):
                    raise ValueError("TLS nested binding invalid")
                return {"tool": "vm_workflow", "ok": True, "campaignId": result["campaignId"],
                        "receipt": result["receipt"], "evidenceDirectory": result["evidenceDirectory"],
                        "deviceMutationPerformed": False, "deviceMutationAllowed": False,
                        "productAction": False, "evidenceClass": "local-only-tls-fixture"}
            except (ValueError, OSError, KeyError, TypeError):
                return _error("vm_workflow", "TLS mint did not produce a verified receipt; preserve its campaign evidence.")
        if action in {"android-native-fixture-start", "android-native-fixture-status",
                      "android-native-fixture-stop", "android-native-fixture-collect"}:
            fixture = _agent_module("android_native_fixture_lifecycle")
            start_fields = {"host", "device", "campaignId", "planPath", "certificatePath", "privateKeyPath"}
            allowed_fields = ((start_fields, start_fields | {"sourceRoot"})
                              if action.endswith("-start") else ({"campaignId"},))
            if (set(inputs) not in allowed_fields or
                    ("sourceRoot" in inputs and
                     (not isinstance(inputs["sourceRoot"], str) or
                      not 1 <= len(inputs["sourceRoot"]) <= 4096 or
                      "\x00" in inputs["sourceRoot"] or not Path(inputs["sourceRoot"]).is_absolute())) or
                    not isinstance(inputs.get("campaignId"), str) or
                    not _valid_uuid(inputs["campaignId"])):
                return _error("vm_workflow", "Android fixture requires exact canonical campaign request.")
            if action.endswith("-start"):
                if (not isinstance(inputs["host"], str) or
                        not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", inputs["host"]) or
                        not isinstance(inputs["device"], str) or
                        not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", inputs["device"]) or
                        any(not isinstance(inputs[key], str) or not Path(inputs[key]).is_absolute()
                            for key in ("planPath", "certificatePath", "privateKeyPath"))):
                    return _error("vm_workflow", "Android fixture start requires configured aliases and absolute local paths.")
            try:
                if action.endswith("-start"):
                    result = fixture.start(REPO_ROOT, inputs["host"], inputs["device"], inputs["campaignId"],
                                           inputs["planPath"], inputs["certificatePath"], inputs["privateKeyPath"],
                                           **({"source_root": inputs["sourceRoot"]} if "sourceRoot" in inputs else {}))
                else:
                    method = {"android-native-fixture-status": fixture.status,
                              "android-native-fixture-stop": fixture.stop,
                              "android-native-fixture-collect": fixture.collect}[action]
                    result = method(REPO_ROOT, inputs["campaignId"])
                return {"tool": "vm_workflow", **result, "evidenceClass": "host-only-fixture",
                        "productAction": False, "deviceMutationAllowed": False,
                        "installerTargetAdmitted": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "campaignId": inputs["campaignId"], "replayAllowed": False,
                        "deviceMutationAllowed": False, "installerTargetAdmitted": False,
                        "productAction": False, "reason": "android-host-fixture-outcome-unavailable"}
        if action == "android-endpoint-cleanup-mount-diagnostic":
            required = {"correlationId", "readmissionCorrelationId"}
            if (not isinstance(inputs, dict) or set(inputs) != required or
                    any(not isinstance(inputs[key], str) or not _valid_uuid(inputs[key]) for key in required) or
                    inputs["correlationId"] == inputs["readmissionCorrelationId"]):
                return _error("vm_workflow", "Mount diagnosis requires exact original and readmission correlations.")
            endpoint = _agent_module("android_endpoint_admission")
            flags = {"replayAllowed": False, "productMutationAllowed": False, "installerTargetAdmitted": False}
            result = None
            try:
                result = endpoint.cleanup_mount_diagnostic(REPO_ROOT, inputs["correlationId"], inputs["readmissionCorrelationId"])
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                pass
            diagnostic = result.get("mountDiagnostic") if isinstance(result, dict) else None
            valid = (isinstance(result, dict) and set(result) == {"ok", "state", "reason", *required, *flags, "observationOnly", "mountDiagnostic"} and
                     result.get("ok") is False and result.get("state") == "partial" and result.get("reason") == "readmission_target_mount_observed" and
                     all(result.get(k) == inputs[k] for k in required) and result.get("observationOnly") is True and all(result.get(k) is False for k in flags) and
                     isinstance(diagnostic, dict) and set(diagnostic) == {"targetEntryCount", "entries", "ownCaRelation", "openingTargetMountRecorded"} and
                     type(diagnostic.get("targetEntryCount")) is int and 0 <= diagnostic["targetEntryCount"] <= 16 and
                     isinstance(diagnostic.get("entries"), list) and len(diagnostic["entries"]) == diagnostic["targetEntryCount"] and
                     diagnostic.get("openingTargetMountRecorded") is False and isinstance(diagnostic.get("ownCaRelation"), str) and
                     diagnostic["ownCaRelation"] in {"absent", "owned", "foreign", "other"} and
                     all(isinstance(entry, dict) and set(entry) == {"rootRelation", "filesystem"} and
                         isinstance(entry.get("rootRelation"), str) and entry["rootRelation"] in {"stage-exact", "stage-descendant", "target-exact", "target-descendant", "root", "other"} and
                         isinstance(entry.get("filesystem"), str) and entry["filesystem"] in {"ext4", "tmpfs", "overlay", "erofs", "fuse", "f2fs", "other"} for entry in diagnostic["entries"]))
            projection = ({"state": "partial", "reason": "readmission_target_mount_observed", "mountDiagnostic": diagnostic}
                          if valid else {"state": "unknown", "reason": "cleanup-mount-diagnostic-unavailable"})
            reasons = getattr(endpoint, "_READMISSION_REASONS", frozenset())
            command_diagnostic = result.get("commandDiagnostic") if isinstance(result, dict) else None
            command_valid = (isinstance(command_diagnostic, dict) and
                             set(command_diagnostic) == {"phase", "outcome", "stderrClass"} and
                             all(isinstance(command_diagnostic.get(key), str) and
                                 isinstance(getattr(endpoint, allowed, None), frozenset) and
                                 command_diagnostic[key] in getattr(endpoint, allowed)
                                 for key, allowed in (("phase", "_COMMAND_PHASES"), ("outcome", "_COMMAND_OUTCOMES"), ("stderrClass", "_COMMAND_STDERR_CLASSES"))))
            finite_unknown = (isinstance(reasons, frozenset) and isinstance(result, dict) and
                              (set(result) == {"ok", "state", "reason", *required, *flags, "observationOnly"} or
                               (command_valid and set(result) == {"ok", "state", "reason", *required, *flags, "observationOnly", "commandDiagnostic"})) and
                              result.get("state") == "unknown" and result.get("ok") is False and
                              all(result.get(k) == inputs[k] for k in required) and result.get("observationOnly") is True and
                              all(result.get(k) is False for k in flags) and isinstance(result.get("reason"), str) and result["reason"] in reasons)
            if finite_unknown:
                projection = {"state": "unknown", "reason": result["reason"]}
                if command_valid:
                    projection["commandDiagnostic"] = dict(command_diagnostic)
            return {"tool": "vm_workflow", **projection, **flags, **inputs, "ok": False,
                    "observationOnly": True, "nativeActionAllowed": False, "productAction": False, "evidenceClass": "native-observation"}
        if action == "android-endpoint-mount-diagnostic-collect":
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId", "diagnosticCorrelationId"} or
                    any(not isinstance(inputs[k], str) or not _valid_uuid(inputs[k]) for k in inputs) or
                    inputs["correlationId"] == inputs["diagnosticCorrelationId"]):
                return _error("vm_workflow", "Mount collection requires distinct canonical endpoint and diagnostic correlations.")
            result = None
            try:
                result = _agent_module("android_endpoint_admission").mount_diagnostic_collect(REPO_ROOT, inputs["correlationId"], inputs["diagnosticCorrelationId"])
            except (ValueError, OSError, KeyError, TypeError):
                pass
            parent = REPO_ROOT / ".rag_index/android-endpoint-admission" / ("mount-diagnostic-" + inputs["correlationId"] + "-" + inputs["diagnosticCorrelationId"])
            keys = {"ok", "state", "reason", "correlationId", "diagnosticCorrelationId", "observationOnly", "replayAllowed", "installerTargetAdmitted", "productMutationAllowed", "localPath", "sha256", "bytes"}
            valid = (isinstance(result, dict) and set(result) == keys and result.get("ok") is True and
                     result.get("state") == "complete" and result.get("reason") is None and
                     all(result.get(k) == inputs[k] for k in inputs) and result.get("observationOnly") is True and
                     all(result.get(k) is False for k in ("replayAllowed", "installerTargetAdmitted", "productMutationAllowed")) and
                     result.get("localPath") == str(parent / "mount-diagnostic.json") and
                     isinstance(result.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", result["sha256"]) is not None and
                     type(result.get("bytes")) is int and 0 < result["bytes"] <= 524288)
            return {"tool": "vm_workflow", "ok": valid, "state": "complete" if valid else "unknown",
                    "reason": None if valid else "mount-collection-unavailable", **inputs,
                    "observationOnly": True, "replayAllowed": False, "nativeActionAllowed": False, "productAction": False,
                    "evidenceClass": "native-observation", **({"sha256": result["sha256"], "bytes": result["bytes"]} if valid else {})}
        if action == "android-recovered-endpoint-stage-collect":
            required = {"correlationId", "historicalCorrelationId", "recoveryCorrelationId", "stageCorrelationId"}
            if (not isinstance(inputs, dict) or set(inputs) != required or
                    any(not isinstance(inputs[k], str) or not _valid_uuid(inputs[k]) for k in required) or
                    len(set(inputs.values())) != 4):
                return _error("vm_workflow", "Recovered-stage collection requires four distinct canonical correlations.")
            flags = {"replayAllowed": False, "productMutationAllowed": False, "installerTargetAdmitted": False}
            result = None
            try:
                result = _agent_module("android_recovered_endpoint_stage_cleanup").collect(
                    REPO_ROOT, inputs["correlationId"], inputs["historicalCorrelationId"],
                    inputs["recoveryCorrelationId"], inputs["stageCorrelationId"])
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                pass
            keys = {"ok", "state", "reason", "correlationId", "recoveryCorrelationId", "stageCorrelationId",
                    "stageOnly", "observationOnly", "device", *flags}
            valid = (isinstance(result, dict) and set(result) == keys and result.get("ok") is True and
                     result.get("state") == "cleaned" and result.get("reason") is None and
                     all(result.get(k) == inputs[k] for k in ("correlationId", "recoveryCorrelationId", "stageCorrelationId")) and
                     result.get("stageOnly") is True and result.get("observationOnly") is False and
                     all(result.get(k) is False for k in flags) and isinstance(result.get("device"), dict) and
                     set(result["device"]) == {"uid", "api", "avd"} and result["device"]["uid"] == "2000" and
                     type(result["device"]["api"]) is int and result["device"]["api"] == 29 and
                     isinstance(result["device"]["avd"], str) and
                     re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", result["device"]["avd"]) is not None)
            return {"tool": "vm_workflow", "ok": valid, "state": "cleaned" if valid else "unknown",
                    "reason": None if valid else "recovered-stage-collection-unavailable", **inputs, **flags,
                    "observationOnly": False, "nativeActionAllowed": False, "productAction": False,
                    "originalOutcome": "unknown", "stageOnly": True, "evidenceClass": "native-reconciliation",
                    **({"device": dict(result["device"])} if valid else {})}
        if action == "android-endpoint-cleanup-readmitted-status":
            required = {"correlationId", "readmissionCorrelationId"}
            if (not isinstance(inputs, dict) or set(inputs) != required or
                    any(not isinstance(inputs[key], str) or not _valid_uuid(inputs[key]) for key in required) or
                    inputs["correlationId"] == inputs["readmissionCorrelationId"]):
                return _error("vm_workflow", "Cleanup terminal status requires exact distinct correlations.")
            endpoint = _agent_module("android_endpoint_admission")
            flags = {"replayAllowed": False, "productMutationAllowed": False, "installerTargetAdmitted": False}
            result = None
            try:
                result = endpoint.cleanup_readmitted_status(REPO_ROOT, inputs["correlationId"], inputs["readmissionCorrelationId"])
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                pass
            base_keys = {"ok", "state", "reason", "correlationId", "readmissionCorrelationId", "observationOnly", *flags}
            valid = (isinstance(result, dict) and result.get("correlationId") == inputs["correlationId"] and
                     result.get("readmissionCorrelationId") == inputs["readmissionCorrelationId"] and
                     result.get("observationOnly") is True and all(result.get(k) is False for k in flags))
            cleaned = False
            if valid and set(result) == base_keys | {"result"} and result.get("ok") is True and result.get("state") == "cleaned" and result.get("reason") is None:
                proof = result["result"]
                cleaned = (isinstance(proof, dict) and set(proof) == {"state", "reason", "correlationId", "device", "packageSha256", "owner", "revision", "caSha256", "reversePorts"} and
                           proof.get("state") == "cleaned" and proof.get("reason") is None and proof.get("correlationId") == inputs["correlationId"] and
                           isinstance(proof.get("device"), dict) and set(proof["device"]) == {"uid", "api", "avd"} and
                           proof["device"]["uid"] == "2000" and type(proof["device"]["api"]) is int and proof["device"]["api"] == 29 and
                           isinstance(proof["device"]["avd"], str) and 0 < len(proof["device"]["avd"]) <= 128 and
                           isinstance(proof.get("owner"), str) and _valid_uuid(proof["owner"]) and
                           type(proof.get("revision")) is int and proof["revision"] >= 0 and proof.get("reversePorts") == [] and
                           all(isinstance(proof.get(k), str) and re.fullmatch(r"[0-9a-f]{64}", proof[k]) for k in ("packageSha256", "caSha256")))
            reasons = getattr(endpoint, "_READMISSION_REASONS", frozenset())
            unknown = (valid and isinstance(reasons, frozenset) and set(result) == base_keys and result.get("ok") is False and
                       result.get("state") == "unknown" and isinstance(result.get("reason"), str) and result["reason"] in reasons)
            return {"tool": "vm_workflow", "ok": bool(cleaned), "state": "cleaned" if cleaned else "unknown",
                    "reason": None if cleaned else result["reason"] if unknown else "cleanup-readmitted-status-unavailable",
                    **inputs, **flags, "observationOnly": True, "nativeActionAllowed": False, "productAction": False,
                    "evidenceClass": "native-observation"}
        if action == "android-endpoint-cleanup-readmission-status":
            required = {"correlationId", "readmissionCorrelationId"}
            if (not isinstance(inputs, dict) or set(inputs) != required or
                    any(not isinstance(inputs[key], str) or not _valid_uuid(inputs[key]) for key in required) or
                    inputs["correlationId"] == inputs["readmissionCorrelationId"]):
                return _error("vm_workflow", "Cleanup status requires exact original and readmission correlations.")
            endpoint = _agent_module("android_endpoint_admission")
            flags = {"replayAllowed": False, "productMutationAllowed": False, "installerTargetAdmitted": False}
            result = None
            try:
                result = endpoint.cleanup_readmission_status(REPO_ROOT, inputs["correlationId"], inputs["readmissionCorrelationId"])
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                pass
            reasons = getattr(endpoint, "_READMISSION_REASONS", frozenset())
            local_reasons = {"readmission_request_changed", "readmission_local_api_changed", "readmission_local_child_present", "readmission_local_lease_changed", "readmission_local_device_changed", "readmission_local_guard_unverified", "readmission_local_record_unverified"}
            base_keys = {"ok", "state", "reason", "correlationId", "readmissionCorrelationId", "observationOnly", *flags}
            valid = (isinstance(reasons, frozenset) and isinstance(result, dict) and
                     set(result) in (base_keys, base_keys | {"freshGuardVerified", "receiptPresent"}) and
                     result.get("ok") is False and isinstance(result.get("state"), str) and result["state"] in {"unknown", "partial"} and
                     result.get("correlationId") == inputs["correlationId"] and result.get("readmissionCorrelationId") == inputs["readmissionCorrelationId"] and
                     result.get("observationOnly") is True and all(result.get(k) is False for k in flags) and
                     isinstance(result.get("reason"), str) and result["reason"] in reasons | local_reasons)
            if valid and "freshGuardVerified" in result:
                valid = (type(result["freshGuardVerified"]) is bool and type(result["receiptPresent"]) is bool and
                         (result["state"] == "partial") == result["freshGuardVerified"] and
                         (result["state"] != "partial" or result["reason"] in {"readmission_receipt_absent", "readmission_receipt_present"}) and
                         result["receiptPresent"] == (result["reason"] == "readmission_receipt_present"))
            elif valid:
                valid = result["state"] == "unknown"
            projection = ({key: result[key] for key in ("state", "reason", "freshGuardVerified", "receiptPresent") if key in result}
                          if valid else {"state": "unknown", "reason": "cleanup-readmission-status-unavailable"})
            return {"tool": "vm_workflow", **projection, **flags, "ok": False,
                    **inputs, "observationOnly": True, "nativeActionAllowed": False, "productAction": False,
                    "evidenceClass": "native-observation"}
        if action in {"android-endpoint-cleanup-readmission", "android-endpoint-cleanup-readmitted"}:
            required = {"correlationId", "readmissionCorrelationId"}
            uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
            if (not isinstance(inputs, dict) or set(inputs) != required or
                    any(not isinstance(inputs[key], str) or re.fullmatch(uuid_pattern, inputs[key]) is None
                        for key in required) or inputs["correlationId"] == inputs["readmissionCorrelationId"]):
                return _error("vm_workflow", "Endpoint cleanup readmission requires two distinct canonical correlations.")
            endpoint = _agent_module("android_endpoint_admission")
            try:
                method = endpoint.cleanup_readmission if action.endswith("-readmission") else endpoint.cleanup_readmitted
                result = method(REPO_ROOT, inputs["correlationId"], inputs["readmissionCorrelationId"])
                base_keys = {"ok", "state", "reason", "correlationId", "replayAllowed",
                             "productMutationAllowed", "installerTargetAdmitted"}
                readmitting = action.endswith("-readmission")
                expected_keys = base_keys | ({"readmissionCorrelationId", "owner", "revision", "cleanupOnly"}
                                             if readmitting else {"result"})
                valid = (isinstance(result, dict) and set(result) == expected_keys and
                         result.get("correlationId") == inputs["correlationId"] and
                         result.get("ok") is True and result.get("reason") is None and
                         result.get("state") == ("ready" if readmitting else "cleaned") and
                         all(result.get(key) is False for key in
                             ("replayAllowed", "productMutationAllowed", "installerTargetAdmitted")))
                if valid and readmitting:
                    valid = (result.get("readmissionCorrelationId") == inputs["readmissionCorrelationId"] and
                             result.get("cleanupOnly") is True and isinstance(result.get("owner"), str) and
                             re.fullmatch(uuid_pattern, result["owner"]) is not None and
                             type(result.get("revision")) is int and result["revision"] >= 0)
                elif valid:
                    proof = result.get("result")
                    valid = (isinstance(proof, dict) and proof.get("correlationId") == inputs["correlationId"] and
                             proof.get("state") == "cleaned")
                projection = {"state": "ready" if readmitting else "cleaned", "cleanupOnly": True}
                if valid and readmitting:
                    projection.update(owner=result["owner"], revision=result["revision"])
                if not valid:
                    projection = {"state": "unknown", "reason": "android-endpoint-cleanup-readmission-unavailable"}
                return {"tool": "vm_workflow", **projection, "ok": valid,
                        "correlationId": inputs["correlationId"], "readmissionCorrelationId": inputs["readmissionCorrelationId"],
                        "evidenceClass": "native-android-endpoint", "productAction": False,
                        "installerTargetAdmitted": False, "productMutationAllowed": False,
                        "nativeActionAllowed": False, "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "android-endpoint-cleanup-readmission-unavailable",
                        "correlationId": inputs["correlationId"], "readmissionCorrelationId": inputs["readmissionCorrelationId"],
                        "installerTargetAdmitted": False, "productAction": False,
                        "productMutationAllowed": False, "nativeActionAllowed": False, "replayAllowed": False}
        if action in {"android-endpoint-admission-start", "android-endpoint-admission-status",
                      "android-endpoint-admission-cleanup"}:
            endpoint = _agent_module("android_endpoint_admission")
            if action.endswith("-start"):
                required = {"host", "device", "correlationId", "campaignId", "sourceSha",
                            "targetArtifactId", "caArtifactId", "backupCorrelationId",
                            "expectedOwner", "expectedRevision", "expectedBackupSha256"}
                if (set(inputs) not in (required, required | {"sourceRoot"}) or
                        ("sourceRoot" in inputs and
                         (not isinstance(inputs["sourceRoot"], str) or
                          not 1 <= len(inputs["sourceRoot"]) <= 4096 or
                          "\x00" in inputs["sourceRoot"] or not Path(inputs["sourceRoot"]).is_absolute())) or
                        any(not isinstance(inputs[key], str) or
                            re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                                         inputs[key]) is None
                            for key in ("correlationId", "campaignId", "backupCorrelationId")) or
                        any(not isinstance(inputs[key], str) or
                            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", inputs[key]) is None
                            for key in ("host", "device")) or
                        not isinstance(inputs["sourceSha"], str) or
                        re.fullmatch(r"[0-9a-f]{40}", inputs["sourceSha"]) is None or
                        any(not isinstance(inputs[key], str) or
                            re.fullmatch(r"sha256-[0-9a-f]{64}", inputs[key]) is None
                            for key in ("targetArtifactId", "caArtifactId")) or
                        not isinstance(inputs["expectedOwner"], str) or
                        not inputs["expectedOwner"] or len(inputs["expectedOwner"]) > 128 or
                        type(inputs["expectedRevision"]) is not int or inputs["expectedRevision"] < 0 or
                        not isinstance(inputs["expectedBackupSha256"], str) or
                        re.fullmatch(r"[0-9a-f]{64}", inputs["expectedBackupSha256"]) is None):
                    return _error("vm_workflow", "Android endpoint start requires exact source, host fixture, package, CA and guarded backup identities.")
            elif (set(inputs) != {"correlationId"} or
                  not isinstance(inputs["correlationId"], str) or
                  re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                               inputs["correlationId"]) is None):
                return _error("vm_workflow", "Android endpoint observation requires only canonical correlationId.")
            try:
                if action.endswith("-start"):
                    result = endpoint.start(REPO_ROOT, inputs["host"], inputs["device"],
                                            inputs["correlationId"], inputs["campaignId"],
                                            inputs["sourceSha"], inputs["targetArtifactId"],
                                            inputs["caArtifactId"], inputs["backupCorrelationId"],
                                            inputs["expectedOwner"], inputs["expectedRevision"],
                                            inputs["expectedBackupSha256"],
                                            **({"source_root": inputs["sourceRoot"]} if "sourceRoot" in inputs else {}))
                else:
                    method = endpoint.status if action.endswith("-status") else endpoint.cleanup
                    result = method(REPO_ROOT, inputs["correlationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("ok") is True and result.get("state") in {"ready", "cleaned"},
                        "evidenceClass": "native-android-endpoint",
                        "productAction": False, "installerTargetAdmitted": False,
                        "productMutationAllowed": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "android-endpoint-outcome-unavailable",
                        "correlationId": inputs["correlationId"],
                        "installerTargetAdmitted": False,
                        "productMutationAllowed": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
        if action in {"android-installer-dispatch-start", "android-installer-dispatch-status",
                      "android-installer-dispatch-collect", "android-installer-callback-handoff-ready",
                      "android-installer-callback-continue", "android-installer-callback-status-handoff-ready",
                      "android-installer-callback-status-continue", "android-installer-abort-prelaunch",
                      "android-installer-reconcile"}:
            installer = _agent_module("android_installer_dispatch")
            uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
            def canonical(value: Any) -> bool:
                return isinstance(value, str) and re.fullmatch(uuid_pattern, value) is not None
            if action == "android-installer-dispatch-start":
                required = {"host", "device", "correlationId", "sourceSha", "baseArtifactId",
                            "targetArtifactId", "backupCorrelationId", "inspectCorrelationId",
                            "expectedOwner", "expectedRevision", "expectedBackupSha256",
                            "expectedTerminal", "cliStageCorrelationId", "caArtifactId",
                            "leafArtifactId", "keyArtifactId"}
                if (set(inputs) != required or
                        any(not canonical(inputs[key]) for key in ("correlationId", "backupCorrelationId",
                                                                 "inspectCorrelationId", "cliStageCorrelationId")) or
                        any(not isinstance(inputs[key], str) or
                            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", inputs[key]) is None
                            for key in ("host", "device")) or
                        not isinstance(inputs["sourceSha"], str) or
                        re.fullmatch(r"[0-9a-f]{40}", inputs["sourceSha"]) is None or
                        any(not isinstance(inputs[key], str) or
                            re.fullmatch(r"sha256-[0-9a-f]{64}", inputs[key]) is None
                            for key in ("baseArtifactId", "targetArtifactId", "caArtifactId",
                                        "leafArtifactId", "keyArtifactId")) or
                        not isinstance(inputs["expectedOwner"], str) or
                        not inputs["expectedOwner"] or len(inputs["expectedOwner"]) > 128 or
                        type(inputs["expectedRevision"]) is not int or inputs["expectedRevision"] < 0 or
                        not isinstance(inputs["expectedBackupSha256"], str) or
                        re.fullmatch(r"[0-9a-f]{64}", inputs["expectedBackupSha256"]) is None or
                        not isinstance(inputs["expectedTerminal"], str) or
                        inputs["expectedTerminal"] not in {"installed", "cancelled"}):
                    return _error("vm_workflow", "Android installer dispatch requires exact source, artifact, AVD, owner and terminal identities.")
            else:
                required = ({"correlationId", "closingReadbackCorrelationId"} if action == "android-installer-abort-prelaunch" else
                            {"correlationId", "closingReadbackCorrelationId", "expectedClosingOwner",
                             "expectedClosingRevision"} if action == "android-installer-reconcile" else
                            {"correlationId"})
                if (set(inputs) != required or not canonical(inputs.get("correlationId")) or
                        ("closingReadbackCorrelationId" in required and
                         not canonical(inputs.get("closingReadbackCorrelationId"))) or
                        (action == "android-installer-reconcile" and
                         (not isinstance(inputs["expectedClosingOwner"], str) or
                          not inputs["expectedClosingOwner"] or len(inputs["expectedClosingOwner"]) > 128 or
                          type(inputs["expectedClosingRevision"]) is not int or
                          inputs["expectedClosingRevision"] < 0))):
                    return _error("vm_workflow", "Android installer observation or closure requires exact canonical correlations and owner fields.")
            try:
                if action == "android-installer-dispatch-start":
                    result = installer.start(REPO_ROOT, inputs["host"], inputs["device"],
                        inputs["correlationId"], inputs["sourceSha"], inputs["baseArtifactId"],
                        inputs["targetArtifactId"], inputs["backupCorrelationId"],
                        inputs["inspectCorrelationId"], inputs["expectedOwner"],
                        inputs["expectedRevision"], inputs["expectedBackupSha256"],
                        inputs["expectedTerminal"], inputs["cliStageCorrelationId"],
                        inputs["caArtifactId"], inputs["leafArtifactId"], inputs["keyArtifactId"])
                elif action in {"android-installer-dispatch-status", "android-installer-dispatch-collect"}:
                    method = installer.status if action.endswith("-status") else installer.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                elif action.startswith("android-installer-callback-"):
                    phase = "handoff-ready" if action.endswith("handoff-ready") else "continue"
                    method = installer.callback_status if "-callback-status-" in action else installer.callback
                    result = method(REPO_ROOT, inputs["correlationId"], phase)
                elif action == "android-installer-abort-prelaunch":
                    result = installer.abort_prelaunch(REPO_ROOT, inputs["correlationId"],
                                                       inputs["closingReadbackCorrelationId"])
                else:
                    result = installer.reconcile(REPO_ROOT, inputs["correlationId"],
                        inputs["closingReadbackCorrelationId"], inputs["expectedClosingOwner"],
                        inputs["expectedClosingRevision"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("ok") is True,
                        "evidenceClass": "native-android-installer-dispatch",
                        "productAction": action in {"android-installer-dispatch-start",
                                                    "android-installer-callback-handoff-ready",
                                                    "android-installer-callback-continue"},
                        "nativeActionAllowed": False, "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "android-installer-dispatch-outcome-unavailable",
                        "correlationId": inputs["correlationId"],
                        "nativeActionAllowed": False, "replayAllowed": False}
        if action == "android-consent-acceptance-preflight":
            if set(inputs) != {"host", "device", "cliStageCorrelationId"}:
                return _error("vm_workflow", "Android consent preflight requires exact host, device and stage correlation.")
            consent = _agent_module("android_consent_acceptance")
            result = consent.preflight(REPO_ROOT, inputs["host"], inputs["device"], inputs["cliStageCorrelationId"])
            return {"tool": "vm_workflow", "ok": result.get("ok") is True,
                    "evidenceClass": "read-only-android-consent", "productAction": False, **result}
        if action in {"android-consent-acceptance-start", "android-consent-acceptance-status",
                      "android-consent-acceptance-collect"}:
            consent = _agent_module("android_consent_acceptance")
            try:
                if action.endswith("-start"):
                    required = {"host", "device", "correlationId", "artifactId", "cliStageCorrelationId",
                                "openingReadbackCorrelationId", "expectedBackupSha256", "expectedOwner",
                                "expectedRevision"}
                    if set(inputs) != required:
                        return _error("vm_workflow", "Android consent denial start requires exact guarded fields.")
                    result = consent.start(REPO_ROOT, inputs["host"], inputs["device"],
                        inputs["correlationId"], inputs["artifactId"], inputs["cliStageCorrelationId"],
                        inputs["openingReadbackCorrelationId"], inputs["expectedBackupSha256"],
                        inputs["expectedOwner"], inputs["expectedRevision"])
                else:
                    if set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "Android consent denial observation requires only correlationId.")
                    method = consent.status if action.endswith("-status") else consent.collect
                    result = method(REPO_ROOT, inputs["correlationId"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "running"} or
                              (result.get("state") == "complete" and result.get("ok") is True),
                        "evidenceClass": "native-android-consent-denial", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"android-document-recovery-start", "android-document-recovery-status",
                      "android-document-recovery-collect", "android-document-recovery-finalize"}:
            recovery = _agent_module("android_document_recovery")
            try:
                if action.endswith("-start"):
                    required = {"host", "device", "recoveryCorrelationId", "unknownDocumentCorrelationId",
                                "openingReadbackCorrelationId", "currentReadbackCorrelationId", "artifactId",
                                "cliStageCorrelationId", "expectedOwner", "expectedRevision"}
                    if set(inputs) != required:
                        return _error("vm_workflow", "Android document recovery start requires exact guarded fields.")
                    result = recovery.start(REPO_ROOT, inputs["host"], inputs["device"],
                        inputs["recoveryCorrelationId"], inputs["unknownDocumentCorrelationId"],
                        inputs["openingReadbackCorrelationId"], inputs["currentReadbackCorrelationId"],
                        inputs["artifactId"], inputs["cliStageCorrelationId"],
                        inputs["expectedOwner"], inputs["expectedRevision"])
                elif action.endswith("-finalize"):
                    required = {"recoveryCorrelationId", "closingReadbackCorrelationId",
                                "expectedOwner", "expectedRevision"}
                    if set(inputs) != required:
                        return _error("vm_workflow", "Android document recovery finalization requires exact closing readback.")
                    result = recovery.finalize(REPO_ROOT, inputs["recoveryCorrelationId"],
                        inputs["closingReadbackCorrelationId"], inputs["expectedOwner"],
                        inputs["expectedRevision"])
                else:
                    if set(inputs) != {"recoveryCorrelationId"}:
                        return _error("vm_workflow", "Android document recovery observation requires only recoveryCorrelationId.")
                    method = recovery.status if action.endswith("-status") else recovery.collect
                    result = method(REPO_ROOT, inputs["recoveryCorrelationId"])
                complete = result.get("state") == "complete" and result.get("ok") is True
                return {"tool": "vm_workflow", **result,
                        "ok": (result.get("state") in {"submitted", "running"} and not action.endswith("-finalize")) or
                              (complete and (not action.endswith("-finalize") or result.get("leaseReleased") is True)),
                        "evidenceClass": "native-document-recovery", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "android-public-inspect":
            inspector = _agent_module("android_public_inspect")
            try:
                required = {"host", "device", "correlationId", "expectedBaseSha256", "expectedOwner", "expectedRevision"}
                if not required <= set(inputs) or set(inputs) - required - {"timeoutSeconds"}:
                    return _error("vm_workflow", "Android public inspection requires exact owner and package bindings.")
                result = inspector.inspect(REPO_ROOT, inputs["host"], inputs["device"], inputs["correlationId"],
                    inputs["expectedBaseSha256"], inputs["expectedOwner"], inputs["expectedRevision"],
                    timeout_seconds=inputs.get("timeoutSeconds", 60))
                return {"tool": "vm_workflow", **result, "ok": result.get("outcome") == "admitted" and result.get("ok") is True,
                        "evidenceClass": "native-observation", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-msi-preinstall-status":
            required = {"host", "jobId"}
            if not isinstance(inputs, dict) or not required <= set(inputs) or set(inputs) - required - {"timeoutSeconds"}:
                return _error("vm_workflow", "Windows MSI preinstall status requires configured host and exact jobId, with optional timeoutSeconds.")
            windows = _agent_module("windows_msi_public_scenario")
            try:
                result = windows.preinstall_status(REPO_ROOT, inputs["host"], inputs["jobId"],
                    timeout_seconds=inputs.get("timeoutSeconds", 15))
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "observed"}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-msi-powershell-preflight":
            if not isinstance(inputs, dict) or set(inputs) != {"host"}:
                return _error("vm_workflow", "Windows MSI PowerShell preflight requires only the configured host.")
            windows = _agent_module("windows_msi_public_scenario")
            try:
                result = windows.powershell_preflight(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "passed",
                        "evidenceClass": "native-preflight", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-msi-http-transfer":
            transfer = _agent_module("windows_msi_http_transfer")
            if not isinstance(inputs, dict) or not isinstance(inputs.get("phase"), str):
                return _error("vm_workflow", "CP117 transfer requires a fixed phase.")
            phase = inputs["phase"]
            payload = {key: value for key, value in inputs.items() if key != "phase"}
            if phase == "ps5-preflight":
                valid = payload == {"host": "archlinux"}
            elif phase == "prepare":
                try:
                    transfer.base._request(payload)
                    valid = True
                except (ValueError, TypeError, KeyError):
                    valid = False
            else:
                valid = (phase in transfer._PHASES and set(payload) == {"correlationId"}
                         and isinstance(payload["correlationId"], str)
                         and bool(transfer._UUID.fullmatch(payload["correlationId"])))
            if not valid:
                return _error("vm_workflow", "CP117 transfer phase inputs are invalid.")
            try:
                result = transfer.workflow(REPO_ROOT, phase, payload)
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
            allowed = {"state", "correlationId", "sha256", "length", "sourceSha",
                       "baseMsiArtifactId", "terminalReceiptSha256", "checks",
                       "replayAllowed", "nativeActionAllowed", "productAction"}
            diagnostic_fields = {"task", "principal", "action", "sid", "leaf", "reason"}
            detail_fields = {"principalUser", "principalLogon", "principalRunLevel",
                             "leafAt", "leafFault", "leafOwner"}
            listener_diagnostic_fields = set(transfer._LISTENER_DIAGNOSTIC_ENUMS)
            if phase in {"guest-diagnostic", "guest-diagnostic-detail"}:
                allowed |= diagnostic_fields
            if phase == "guest-diagnostic-detail":
                allowed |= detail_fields
            if phase == "listener-diagnostic":
                allowed |= listener_diagnostic_fields
            if phase == "guest-owner-census":
                allowed.add("paths")
            states = {"unknown", "prepared", "passed", "failed", "staged", "absent",
                      "partial", "hash-mismatch", "cleaned", "listening", "starting",
                      "served", "stopped", "submitted", "running", "downloaded",
                      "task-cleaned", "ready-for-base", "aborted", "aborted-cleaned",
                      "file-cleaned", "file-absent", "marked", "staged-for-base",
                      "present", "diagnosed", "census"}
            census_valid = True
            if phase == "guest-owner-census" and isinstance(result, dict) and result.get("state") == "census":
                paths = result.get("paths")
                census_valid = (isinstance(paths, dict) and set(paths) == transfer._CENSUS_NAMES
                                and all(isinstance(entry, dict) and set(entry) == {"kind", "reparse", "owner"}
                                        and entry["kind"] in transfer._CENSUS_KIND
                                        and entry["reparse"] in transfer._CENSUS_REPARSE
                                        and entry["owner"] in transfer._CENSUS_OWNER
                                        for entry in paths.values()))
            diagnostic_valid = (isinstance(result, dict) and
                                (phase not in {"guest-diagnostic", "guest-diagnostic-detail"} or result.get("state") != "diagnosed" or
                                (diagnostic_fields <= set(result)
                                 and result.get("task") in transfer._DIAGNOSTIC_TASK
                                 and result.get("principal") in transfer._DIAGNOSTIC_MATCH
                                 and result.get("action") in transfer._DIAGNOSTIC_MATCH
                                 and result.get("sid") in transfer._DIAGNOSTIC_MATCH
                                 and result.get("leaf") in transfer._DIAGNOSTIC_LEAF
                                 and result.get("reason") in transfer._DIAGNOSTIC_REASON
                                 and (phase != "guest-diagnostic-detail" or
                                      (detail_fields <= set(result)
                                       and result.get("principalUser") in transfer._DIAGNOSTIC_USER
                                       and result.get("principalLogon") in transfer._DIAGNOSTIC_MATCH
                                       and result.get("principalRunLevel") in transfer._DIAGNOSTIC_MATCH
                                       and result.get("leafAt") in transfer._DIAGNOSTIC_AT
                                       and result.get("leafFault") in transfer._DIAGNOSTIC_FAULT
                                       and result.get("leafOwner") in transfer._DIAGNOSTIC_OWNER)))))
            listener_diagnostic_valid = (isinstance(result, dict) and
                                         (phase != "listener-diagnostic" or result.get("state") != "diagnosed" or
                                          (listener_diagnostic_fields <= set(result) and
                                           all(result.get(key) in values for key, values in
                                               transfer._LISTENER_DIAGNOSTIC_ENUMS.items()))))
            if (not isinstance(result, dict) or set(result) - allowed
                    or result.get("state") not in states
                    or not diagnostic_valid
                    or not listener_diagnostic_valid
                    or not census_valid
                    or result.get("replayAllowed") is not False
                    or result.get("nativeActionAllowed") is not False
                    or result.get("productAction") is not False):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] not in {"unknown", "failed"},
                    "evidenceClass": "native-preflight" if phase == "ps5-preflight" else
                                     "causal-diagnostic" if phase in {"guest-diagnostic", "guest-diagnostic-detail", "guest-owner-census", "listener-diagnostic"} else
                                     "causal-status" if phase.endswith("status") or phase == "ready-for-base" else
                                     "native-transfer",
                    "productAction": False}
        if action == "windows-update-fixture-http-transfer":
            transfer = _agent_module("windows_update_fixture_http_stage")
            if not isinstance(inputs, dict) or not isinstance(inputs.get("phase"), str):
                return _error("vm_workflow", "Windows fixture transfer requires a fixed phase.")
            phase = inputs["phase"]
            payload = {key: value for key, value in inputs.items() if key != "phase"}
            try:
                if phase in {"prepare", "prepare-diagnostic", "bundle-diagnostic", "reserve-diagnostic",
                             "prior-stage-confirmation"}:
                    transfer._request(payload)
                elif ((phase not in transfer._PHASES and phase not in {
                       "stage-start-diagnostic", "host-staged-pre-effect-diagnostic",
                       "host-stage-probe", "guest-create-diagnostic", "guest-download-diagnostic",
                       "host-staged-pre-effect-close", "e66-pre-effect-recovery",
                       "e66-retire-aborted-stage", "e66-retire-aborted-stage-status"})
                      or set(payload) != {"correlationId"}
                      or not transfer._canonical(payload["correlationId"])):
                    raise ValueError("Invalid fixture transfer phase.")
            except (ValueError, TypeError, KeyError):
                return _error("vm_workflow", "Windows fixture transfer inputs are invalid.")
            if (phase in {"e66-pre-effect-recovery", "e66-retire-aborted-stage",
                          "e66-retire-aborted-stage-status"}
                    and payload["correlationId"] != transfer._E66_CORRELATION):
                return _error("vm_workflow", "Exact E66 recovery correlation is required.")
            if (phase == "guest-download-diagnostic"
                    and payload["correlationId"] != "e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"):
                return _error("vm_workflow", "Exact guest-download diagnostic correlation is required.")
            try:
                result = transfer.workflow(REPO_ROOT, phase, payload)
            except (ValueError, OSError, KeyError, TypeError, AttributeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False}
            fixed = {"state", "correlationId", "replayAllowed"}
            flags = {"nativeActionAllowed", "productAction"}
            expected = {
                "prepare": {"prepared": fixed | flags | {"bundleSha256", "bundleSize"}},
                "prepare-diagnostic": {"diagnosed": fixed | flags | {"phase", "preEffect"}},
                "bundle-diagnostic": {"diagnosed": fixed | flags | {"phase", "preEffect"}},
                "reserve-diagnostic": {"diagnosed": fixed | flags | {"phase", "preEffect"}},
                "prior-stage-confirmation": {"diagnosed": fixed | flags | {"phase", "preEffect"}},
                "stage-start-diagnostic": {"diagnosed": fixed | flags | {"phase", "preEffect"}},
                "host-stage-probe": {"diagnosed": fixed | flags | {"phase", "preEffect", "listenerStartAllowed"}},
                "guest-create-diagnostic": {"diagnosed": fixed | flags | {"phase", "preEffect", "interpreter"}},
                "guest-download-diagnostic": {"diagnosed": fixed | flags | {
                    "phase", "preEffect", "listener", "listenerServed", "task", "taskResult", "download"}},
                "host-staged-pre-effect-diagnostic": {"diagnosed": fixed | flags | {"phase", "preEffect"}},
                "host-staged-pre-effect-close": {"aborted": fixed | flags},
                "e66-pre-effect-recovery": {"aborted": fixed | flags},
                "e66-retire-aborted-stage": {"retired": fixed | flags},
                "e66-retire-aborted-stage-status": {
                    name: fixed | flags for name in ("ready", "pending-finish", "retired")},
                "status": {"prepared": fixed | flags | {"bundleSha256", "bundleSize"},
                           "aborted": fixed | flags | {"bundleSha256", "bundleSize"}},
                "stage-start": {"staged": fixed | {"sha256", "length"}},
                "listener-start": {"listening": fixed | flags},
                "listener-status": {name: fixed | flags for name in
                                    ("absent", "listening", "served", "stopped")},
                "guest-create": {"created": fixed},
                "guest-download": {"submitted": fixed},
                "stage-extract": {"staged": fixed},
                "collect": {"staged-not-server-ready": fixed | {"sourceSha",
                            "targetMsiSha256", "bundleSha256", "fileHashes", "serverReady"}},
                "cleanup": {"cleaned": fixed | flags},
            }
            state = result.get("state") if isinstance(result, dict) else None
            fields = expected.get(phase, {}).get(state)
            if state == "unknown":
                fields = fixed | flags
            valid = (isinstance(result, dict) and fields is not None
                     and set(result) == fields and result.get("replayAllowed") is False
                     and result.get("nativeActionAllowed", False) is False
                     and result.get("productAction", False) is False
                     and result.get("correlationId") == payload["correlationId"])
            if valid and phase == "status" and state == "aborted":
                valid = payload["correlationId"] == transfer._E66_CORRELATION
            if valid and "bundleSha256" in result:
                valid = isinstance(result["bundleSha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", result["bundleSha256"]))
            if valid and "sha256" in result:
                valid = isinstance(result["sha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", result["sha256"]))
            if valid and "sourceSha" in result:
                valid = isinstance(result["sourceSha"], str) and bool(re.fullmatch(r"[0-9a-f]{40}", result["sourceSha"]))
            if valid and "targetMsiSha256" in result:
                valid = isinstance(result["targetMsiSha256"], str) and bool(re.fullmatch(r"[0-9a-f]{64}", result["targetMsiSha256"]))
            for size_name in ("bundleSize", "length"):
                if valid and size_name in result:
                    valid = type(result[size_name]) is int and 0 < result[size_name] <= 1075838976
            if valid and state == "staged-not-server-ready":
                hashes = result["fileHashes"]
                valid = (result["serverReady"] is False and isinstance(hashes, dict)
                         and 0 < len(hashes) <= 32
                         and all(isinstance(name, str) and 0 < len(name) <= 128
                                 and re.fullmatch(r"[A-Za-z0-9_./-]+", name)
                                 and all(part not in {"", ".", ".."} for part in name.split("/"))
                                 and isinstance(digest, str)
                                 and re.fullmatch(r"[0-9a-f]{64}", digest)
                                 for name, digest in hashes.items()))
            if valid and phase in {"prepare-diagnostic", "bundle-diagnostic", "reserve-diagnostic",
                                   "prior-stage-confirmation", "stage-start-diagnostic",
                                   "host-staged-pre-effect-diagnostic"}:
                phases = ({"http-intent-present", "stage-intent-present", "shared-intent-present",
                           "local-journal-unreadable", "source-unadmitted", "vm-unbound",
                           "campaign-unbound", "ready-to-reserve"} if phase == "prepare-diagnostic"
                          else {"bundle-ready", "bundle-invalid", "bundle-unbuildable"}
                          if phase == "bundle-diagnostic" else
                          {"http-journal-unsafe", "vm-unbound", "campaign-unbound",
                           "stage-history-unsafe", "stage-intent-present",
                           "prior-stage-needs-confirmation", "reserve-ready-local"}
                          if phase == "reserve-diagnostic" else
                          {"confirmed", "old-closed-missing", "remote-status-mismatch",
                           "history-invalid", "unknown"}
                          if phase == "prior-stage-confirmation" else
                          {"artifact-invalid", "pair-fingerprint-invalid", "descriptor-invalid",
                           "intent-core-binding-invalid",
                           "campaign-not-claimed", "phase-ineligible", "remote-host-invalid",
                           "remote-host-next"}
                          if phase == "stage-start-diagnostic" else
                          {"not-host-staged", "host-stage-absent", "host-stage-present", "unknown"})
                valid = result["preEffect"] is True and result["phase"] in phases
            if valid and phase == "host-stage-probe":
                phases = {"host-stage-complete", "host-stage-partial", "host-stage-absent",
                          "not-host-staged", "local-binding-invalid", "unknown"}
                valid = (result["preEffect"] is True and result["phase"] in phases
                         and type(result["listenerStartAllowed"]) is bool
                         and result["listenerStartAllowed"] is (result["phase"] == "host-stage-complete"))
            if valid and phase == "guest-create-diagnostic":
                phases = {"not-guest-created", "diagnostic-script-oversize",
                          "guest-create-may-have-completed", "unknown"} | {
                    "guest-create-not-confirmed-" + name for name in
                    ("syntax-invalid", "ancestor-type", "ancestor-reparse",
                     "acl-construction-failed", "parent-absent", "parent-type", "parent-reparse",
                     "leaf-absent", "leaf-type", "leaf-reparse")}
                valid = (result["preEffect"] is True and result["phase"] in phases
                         and result["interpreter"] in {"absent", "present", "unknown"})
            if valid and phase == "guest-download-diagnostic":
                valid = (result["preEffect"] is True
                         and result["phase"] in {"not-submitted", "diagnostic-script-oversize",
                                                   "qga-wrapper-timeout", "qga-wrapper-failed", "syntax-invalid",
                                                   "task-action-mismatch", "task-metadata-error", "task-absent",
                                                   "task-principal-mismatch", "task-action-count-mismatch",
                                                   "task-state-unsupported", "task-task-info-failed",
                                                   "task-action-hash-unknown",
                                                   "task-running", "task-failed", "download-absent",
                                                   "download-hash-mismatch", "guest-file-read-error",
                                                   "download-complete", "unknown"}
                         and result["listener"] in {"absent", "listening", "served", "stopped", "unknown"}
                         and result["listenerServed"] in {"true", "false", "unknown"}
                         and ((result["listener"] == "served" and result["listenerServed"] == "true")
                              or (result["listener"] == "stopped" and result["listenerServed"] == "false")
                              or (result["listener"] in {"absent", "listening", "unknown"}
                                  and result["listenerServed"] == "unknown"))
                         and result["task"] in {"absent", "running", "completed", "failed", "metadata-error",
                                                "principal-mismatch", "action-count-mismatch", "state-unsupported",
                                                "task-info-failed", "action-hash-unknown", "unknown"}
                         and (result["taskResult"] == "unknown"
                              or (type(result["taskResult"]) is int and 0 <= result["taskResult"] <= 4294967295
                                  and result["task"] in {"completed", "failed"}))
                         and result["download"] in {"absent", "complete", "hash-mismatch", "read-error", "unknown"})
            if not valid:
                result = {"state": "unknown", "correlationId": payload["correlationId"],
                          "replayAllowed": False, "nativeActionAllowed": False,
                          "productAction": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] != "unknown",
                    "evidenceClass": "causal-diagnostic" if phase in {"prepare-diagnostic", "bundle-diagnostic", "reserve-diagnostic", "prior-stage-confirmation", "stage-start-diagnostic", "host-stage-probe", "guest-create-diagnostic", "guest-download-diagnostic", "host-staged-pre-effect-diagnostic"} else
                    "causal-status" if phase in {"status", "listener-status", "collect"}
                    else "native-transfer", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-msiexec-service-diagnostic":
            if (not isinstance(inputs, dict) or set(inputs) != {"action", "host"}
                    or inputs.get("action") not in {"preflight", "status"}
                    or inputs.get("host") != "archlinux"):
                return _error("vm_workflow", "Exact CP117 installer-service diagnostic inputs are required.")
            observer = _agent_module("windows_msiexec_service_diagnostic")
            try:
                result = observer.workflow(REPO_ROOT, inputs["action"], {"host": "archlinux"})
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False,
                          "readinessAdmitted": False}
            allowed = {"state", "correlationId", "sourceSha", "replayAllowed",
                       "nativeActionAllowed", "productAction", "readinessAdmitted"}
            valid = isinstance(result, dict) and result.get("state") in {"unknown", "passed", "observed"}
            if inputs["action"] == "status" and isinstance(result, dict) and result.get("state") == "observed":
                allowed |= observer._ENUMS.keys()
                valid = valid and all(result.get(key) in values for key, values in observer._ENUMS.items())
            if (not valid or set(result) - allowed
                    or (result.get("state") in {"passed", "observed"} and
                        (result.get("correlationId") != observer._CORRELATION or
                         not isinstance(result.get("sourceSha"), str) or
                         not observer._SOURCE.fullmatch(result["sourceSha"])))
                    or result.get("replayAllowed") is not False
                    or result.get("nativeActionAllowed") is not False
                    or result.get("productAction") is not False
                    or result.get("readinessAdmitted") is not False
                    or (result.get("state") == "passed" and inputs["action"] != "preflight")
                    or (result.get("state") == "observed" and inputs["action"] != "status")):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False, "productAction": False,
                          "readinessAdmitted": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"passed", "observed"},
                    "evidenceClass": "native-preflight" if inputs["action"] == "preflight" else "causal-diagnostic",
                    "productAction": False, "nativeActionAllowed": False,
                    "readinessAdmitted": False}
        if action in {"windows-msi-owner-census-preflight", "windows-msi-owner-census"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 owner census host is required.")
            census = _agent_module("windows_msi_owner_census")
            try:
                result = (census.preflight(REPO_ROOT, inputs) if action.endswith("-preflight")
                          else census.workflow(REPO_ROOT, inputs))
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            if action.endswith("-preflight"):
                valid = (isinstance(result, dict) and set(result) == {"state", "checks"}
                         and result.get("state") in {"passed", "failed", "unknown"}
                         and result.get("checks") == (["ps5-parse", "gzip"] if result.get("state") != "unknown" else []))
                if not valid:
                    result = {"state": "unknown", "checks": []}
            else:
                fields = {"state", "sourceSha", "controllerId", "installedCliSha256",
                          "parentPid", "parentStartedAtUtc", "childPid", "childStartedAtUtc",
                          "runtimeRunning", "replayAllowed", "nativeActionAllowed"}
                valid = (isinstance(result, dict) and
                         ((set(result) == fields and result.get("state") == "observed"
                           and isinstance(result.get("sourceSha"), str)
                           and _agent_module("windows_msi_base_prepare")._SHA.fullmatch(result["sourceSha"])
                           and isinstance(result.get("controllerId"), str)
                           and census._UUID.fullmatch(result["controllerId"])
                           and isinstance(result.get("installedCliSha256"), str)
                           and _agent_module("windows_msi_base_prepare")._HASH.fullmatch(result["installedCliSha256"])
                           and all(type(result.get(key)) is int and result[key] > 0 for key in ("parentPid", "childPid"))
                           and result["parentPid"] != result["childPid"]
                           and all(isinstance(result.get(key), str) and census._UTC.fullmatch(result[key])
                                   for key in ("parentStartedAtUtc", "childStartedAtUtc"))
                           and result["runtimeRunning"] is False
                           and result["replayAllowed"] is False and result["nativeActionAllowed"] is False)
                          or (result == {"state": "unknown", "replayAllowed": False,
                                         "nativeActionAllowed": False})))
                if not valid:
                    result = {"state": "unknown", "replayAllowed": False,
                              "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"passed", "observed"},
                    "evidenceClass": "native-preflight" if action.endswith("-preflight") else "causal-diagnostic",
                    "productAction": False, "nativeActionAllowed": False}
        if action == "windows-msi-owner-diagnostic":
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 owner diagnostic host is required.")
            diagnostic = _agent_module("windows_msi_owner_diagnostic")
            try:
                result = diagnostic.diagnose(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            if (not isinstance(result, dict) or
                    not ((set(result) == ({"state", "phase", "sourceSha", "correlationId",
                                           "replayAllowed", "nativeActionAllowed"} |
                                          ({"detail"} if result.get("phase") in {"state-directory", "state-files",
                                                                                  "endpoint-unavailable"} else set()))
                          and result.get("state") == "diagnosed"
                          and result.get("phase") in diagnostic._PHASES
                          and (result.get("detail") in diagnostic._STATE_DIRECTORY_DETAILS
                               if result.get("phase") == "state-directory" else
                               result.get("detail") in diagnostic._STATE_FILE_DETAILS
                               if result.get("phase") == "state-files" else
                               result.get("detail") in diagnostic._ENDPOINT_UNAVAILABLE_DETAILS
                               if result.get("phase") == "endpoint-unavailable" else "detail" not in result)
                          and result.get("correlationId") == diagnostic._CORRELATION
                          and isinstance(result.get("sourceSha"), str)
                          and diagnostic._SOURCE.fullmatch(result["sourceSha"])
                          and result.get("replayAllowed") is False
                          and result.get("nativeActionAllowed") is False)
                         or result == {"state": "unknown", "replayAllowed": False,
                                       "nativeActionAllowed": False})):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] == "diagnosed",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-msi-owner-liveness":
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 owner liveness host is required.")
            liveness = _agent_module("windows_msi_owner_liveness")
            try:
                result = liveness.observe(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            fields = {"state", "sourceSha", "correlationId", "ownerProcesses",
                      "installerProcesses", "consentProcesses", "runtimeProcesses",
                      "stateLeaves", "runtimeOff", "replayAllowed", "nativeActionAllowed"}
            valid = (isinstance(result, dict) and
                     ((set(result) == fields and result.get("state") in {"absent", "blocked"}
                       and isinstance(result.get("sourceSha"), str)
                       and liveness._SOURCE.fullmatch(result["sourceSha"])
                       and result.get("correlationId") == liveness._CORRELATION
                       and all(result.get(key) in liveness._COUNTS for key in (
                           "ownerProcesses", "installerProcesses", "consentProcesses", "runtimeProcesses"))
                       and result.get("stateLeaves") in liveness._LEAVES
                       and type(result.get("runtimeOff")) is bool
                       and result["runtimeOff"] is (result["runtimeProcesses"] == "none")
                       and (result["state"] != "absent" or
                            (all(result[key] == "none" for key in (
                                "ownerProcesses", "installerProcesses", "consentProcesses",
                                "runtimeProcesses", "stateLeaves")) and result["runtimeOff"] is True))
                       and result.get("replayAllowed") is False
                       and result.get("nativeActionAllowed") is False)
                      or result == {"state": "unknown", "replayAllowed": False,
                                    "nativeActionAllowed": False}))
            if not valid:
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"absent", "blocked"},
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action == "windows-msi-stale-lock-recover":
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 stale-lock recovery host is required.")
            recovery = _agent_module("windows_msi_stale_lock_recovery")
            try:
                result = recovery.recover(REPO_ROOT, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            if result not in ({"state": "recovered", "replayAllowed": False,
                               "nativeActionAllowed": False},
                              {"state": "unknown", "replayAllowed": False,
                               "nativeActionAllowed": False}):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] == "recovered",
                    "evidenceClass": "native-recovery", "productAction": False,
                    "nativeActionAllowed": False}
        if action in {"windows-msi-stale-lock-diagnose", "windows-msi-stale-lock-reconciliation-status"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 stale-lock diagnostic host is required.")
            recovery = _agent_module("windows_msi_stale_lock_recovery")
            try:
                result = (recovery.diagnose(REPO_ROOT, inputs) if action.endswith("diagnose")
                          else recovery.reconciliation_status(REPO_ROOT, inputs))
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            valid = (result == {"state": "unknown", "replayAllowed": False,
                                "nativeActionAllowed": False}
                     or (action.endswith("diagnose") and isinstance(result, dict)
                         and set(result) == ({"state", "category", "replayAllowed", "nativeActionAllowed"}
                                             | ({"win32Code"} if result.get("category") == "lock-open-other" else set()))
                         and result.get("state") == "diagnosed"
                         and result.get("category") in recovery._DIAGNOSTIC_CATEGORIES
                         and (type(result.get("win32Code")) is int and 0 <= result["win32Code"] <= 65535
                              if result.get("category") == "lock-open-other" else "win32Code" not in result)
                         and result.get("replayAllowed") is False
                         and result.get("nativeActionAllowed") is False)
                     or (action.endswith("reconciliation-status") and result == {
                         "state": "separate-one-shot-required", "replayAllowed": False,
                         "nativeActionAllowed": False}))
            if not valid:
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] != "unknown",
                    "evidenceClass": "causal-diagnostic", "productAction": False,
                    "nativeActionAllowed": False}
        if action in {"windows-msi-owner-relaunch-launch", "windows-msi-owner-relaunch-status",
                      "windows-msi-owner-relaunch-collect", "windows-msi-owner-relaunch-diagnose",
                      "windows-msi-owner-relaunch-detail", "windows-msi-owner-relaunch-endpoint-access"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 owner relaunch host is required.")
            relaunch = _agent_module("windows_msi_owner_relaunch")
            phase = action.removeprefix("windows-msi-owner-relaunch-")
            try:
                result = relaunch.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            diagnostic_valid = (phase == "diagnose" and isinstance(result, dict)
                and set(result) == {"state", "phase", "task", "owners", "endpoint",
                                    "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "diagnosed"
                and result.get("phase") in relaunch._DIAGNOSTIC_PHASES
                and result.get("task") in relaunch._TASK_STATES
                and result.get("owners") in relaunch._OWNER_STATES
                and result.get("endpoint") in relaunch._ENDPOINT_STATES
                and result.get("replayAllowed") is False
                and result.get("nativeActionAllowed") is False)
            detail_fields = {"state", "baseOwners", "quotedStateServe", "unquotedStateServe",
                             "otherSubcommand", "unrelated", "ownerIdentity", "endpoint",
                             "schemaVersion", "controllerId", "port", "token",
                             "replayAllowed", "nativeActionAllowed"}
            detail_valid = (phase == "detail" and isinstance(result, dict)
                and set(result) == detail_fields and result.get("state") == "detailed"
                and all(result.get(key) in relaunch._DETAIL_COUNTS for key in
                        ("baseOwners", "quotedStateServe", "unquotedStateServe",
                         "otherSubcommand", "unrelated"))
                and result.get("ownerIdentity") in relaunch._DETAIL_IDENTITY
                and result.get("endpoint") in relaunch._DETAIL_LEAF
                and all(result.get(key) in relaunch._DETAIL_FIELD for key in
                        ("schemaVersion", "controllerId", "port", "token"))
                and result.get("replayAllowed") is False
                and result.get("nativeActionAllowed") is False)
            endpoint_valid = (phase == "endpoint-access" and isinstance(result, dict)
                and set(result) == {"state", "endpoint", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "endpoint-access"
                and result.get("endpoint") in relaunch._ENDPOINT_ACCESS
                and result.get("replayAllowed") is False
                and result.get("nativeActionAllowed") is False)
            valid = (result == {"state": "unknown", "replayAllowed": False,
                                "nativeActionAllowed": False}
                     or diagnostic_valid or detail_valid or endpoint_valid
                     or (phase not in {"diagnose", "detail", "endpoint-access"} and isinstance(result, dict) and set(result) == {
                         "state", "sourceSha", "correlationId", "installedCliSha256",
                         "ownerPid", "sessionId", "runtimeRunning", "replayAllowed",
                         "nativeActionAllowed"} and result.get("state") == "launched"
                         and result.get("sourceSha") == relaunch._SOURCE
                         and result.get("correlationId") == relaunch._CORRELATION
                         and isinstance(result.get("installedCliSha256"), str)
                         and re.fullmatch(r"[0-9a-f]{64}", result["installedCliSha256"])
                         and type(result.get("ownerPid")) is int and result["ownerPid"] > 0
                         and result.get("sessionId") == 1
                         and result.get("runtimeRunning") is False
                         and result.get("replayAllowed") is False
                         and result.get("nativeActionAllowed") is False))
            if not valid:
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"launched", "diagnosed", "detailed", "endpoint-access"},
                    "evidenceClass": "native-owner-launch" if phase == "launch" else
                                     "causal-diagnostic" if phase in {"diagnose", "detail", "endpoint-access"} else "causal-status",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-msi-owner-public-status-start", "windows-msi-owner-public-status-status",
                      "windows-msi-owner-public-status-collect", "windows-msi-owner-public-status-diagnose"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 owner public status host is required.")
            public = _agent_module("windows_msi_owner_public_status")
            phase = action.removeprefix("windows-msi-owner-public-status-")
            try:
                result = public.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            valid = (result == {"state": "unknown", "replayAllowed": False,
                                "nativeActionAllowed": False}
                     or result == {"state": "pending", "replayAllowed": False,
                                   "nativeActionAllowed": False}
                     or result == {"state": "proved", "runtimeRunning": False,
                                   "replayAllowed": False, "nativeActionAllowed": False}
                     or (phase == "diagnose" and isinstance(result, dict)
                         and set(result) == {"state", "phase", "task", "replayAllowed", "nativeActionAllowed"}
                         and result.get("state") == "diagnosed"
                         and result.get("phase") in {"system-identity", "ancestors", "acl", "cli", "endpoint", "task"}
                         and result.get("task") in {"absent", "principal-mismatch", "action-mismatch",
                                                    "pending", "proved", "failed", "unknown"}
                         and result.get("replayAllowed") is False
                         and result.get("nativeActionAllowed") is False))
            if not valid:
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": result["state"] in {"proved", "diagnosed"},
                    "evidenceClass": "native-public-status" if result["state"] == "proved" else
                                     "causal-diagnostic" if result["state"] == "diagnosed" else "causal-status",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-msi-owner-public-status-retry-preflight", "windows-msi-owner-public-status-retry-start",
                      "windows-msi-owner-public-status-retry-status", "windows-msi-owner-public-status-retry-collect",
                      "windows-msi-owner-public-status-retry-diagnose",
                      "windows-msi-owner-public-status-retry-observe"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 owner public retry host is required.")
            retry = _agent_module("windows_msi_owner_public_status_retry")
            phase = ("retry-diagnostic" if action == "windows-msi-owner-public-status-retry-observe"
                     else action.removeprefix("windows-msi-owner-public-status-retry-"))
            try:
                result = retry.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = ({"state": "unknown", "gate": "unknown", "replayAllowed": False,
                           "nativeActionAllowed": False} if phase == "preflight" else
                          {"state": "unknown", "replayAllowed": False,
                           "nativeActionAllowed": False})
            valid = (result == {"state": "unknown", "replayAllowed": False,
                                "nativeActionAllowed": False}
                     if phase != "preflight" else result == {
                         "state": "unknown", "gate": "unknown", "replayAllowed": False,
                         "nativeActionAllowed": False})
            if phase == "preflight":
                valid = valid or (isinstance(result, dict)
                    and set(result) == {"state", "gate", "replayAllowed", "nativeActionAllowed"}
                    and result.get("state") in {"ready", "blocked"}
                    and result.get("gate") in ({"ready"} if result.get("state") == "ready" else
                                               {"system-identity", "scheduler", "account", "session", "task"})
                    and result.get("replayAllowed") is False
                    and result.get("nativeActionAllowed") is False)
            elif phase == "retry-diagnostic":
                valid = valid or (isinstance(result, dict)
                    and result.get("replayAllowed") is False
                    and result.get("nativeActionAllowed") is False
                    and ((set(result) == {"state", "stage", "replayAllowed", "nativeActionAllowed"}
                          and ((result.get("state") == "blocked" and result.get("stage") in {
                              "retry-intent", "base-binding", "source-hash", "relaunch-intent", "generation"})
                               or (result.get("state") == "unknown" and result.get("stage") == "task-observer")))
                         or (set(result) == {"state", "stage", "phase", "task", "replayAllowed", "nativeActionAllowed"}
                             and result.get("state") == "diagnosed" and result.get("stage") == "task-observer"
                             and result.get("phase") in {"system-identity", "ancestors", "acl", "cli", "endpoint", "task"}
                             and result.get("task") in {"absent", "principal-mismatch", "action-mismatch",
                                                        "pending", "proved", "failed", "unknown"})))
            elif phase == "diagnose":
                valid = valid or (isinstance(result, dict)
                    and set(result) == {"state", "phase", "task", "replayAllowed", "nativeActionAllowed"}
                    and result.get("state") == "diagnosed"
                    and result.get("phase") in {"system-identity", "ancestors", "acl", "cli", "endpoint", "task"}
                    and result.get("task") in {"absent", "principal-mismatch", "action-mismatch",
                                               "pending", "proved", "failed", "unknown"}
                    and result.get("replayAllowed") is False
                    and result.get("nativeActionAllowed") is False)
            else:
                valid = valid or result == {"state": "pending", "replayAllowed": False,
                                            "nativeActionAllowed": False} or result == {
                                                "state": "proved", "runtimeRunning": False,
                                                "replayAllowed": False, "nativeActionAllowed": False}
            if not valid:
                result = ({"state": "unknown", "gate": "unknown", "replayAllowed": False,
                           "nativeActionAllowed": False} if phase == "preflight" else
                          {"state": "unknown", "replayAllowed": False,
                           "nativeActionAllowed": False})
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"ready", "proved", "diagnosed"},
                    "evidenceClass": "native-preflight" if phase == "preflight" else
                                     "native-public-status" if result["state"] == "proved" else
                                     "causal-diagnostic" if phase in {"diagnose", "retry-diagnostic"} else "causal-status",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-msi-owner-public-status-third-start",
                      "windows-msi-owner-public-status-third-status",
                      "windows-msi-owner-public-status-third-collect",
                      "windows-msi-owner-public-status-third-observe"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 third public status host is required.")
            third = _agent_module("windows_msi_owner_public_status_third")
            phase = ("third-diagnostic" if action.endswith("-observe") else
                     action.removeprefix("windows-msi-owner-public-status-third-"))
            try:
                result = third.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            diagnostic_valid = (phase == "third-diagnostic" and isinstance(result, dict)
                and result.get("replayAllowed") is False
                and result.get("nativeActionAllowed") is False
                and ((set(result) == {"state", "stage", "replayAllowed", "nativeActionAllowed"}
                      and ((result.get("state") == "blocked" and result.get("stage") in {
                          "third-intent", "base-binding", "source-hash", "relaunch-intent", "generation"})
                           or (result.get("state") == "unknown" and result.get("stage") == "task-observer")))
                     or (set(result) == {"state", "stage", "phase", "task", "replayAllowed", "nativeActionAllowed"}
                         and result.get("state") == "diagnosed" and result.get("stage") == "task-observer"
                         and result.get("phase") in {"system-identity", "ancestors", "acl", "cli", "endpoint", "task"}
                         and result.get("task") in {"absent", "principal-mismatch", "action-mismatch",
                                                    "pending", "proved", "failed", "unknown"})))
            if (not diagnostic_valid if phase == "third-diagnostic" else result not in (
                              {"state": "unknown", "replayAllowed": False,
                               "nativeActionAllowed": False},
                              {"state": "pending", "replayAllowed": False,
                               "nativeActionAllowed": False},
                              {"state": "proved", "runtimeRunning": False,
                               "replayAllowed": False, "nativeActionAllowed": False})):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": result["state"] in {"proved", "diagnosed"},
                    "evidenceClass": "native-public-status" if result["state"] == "proved" else
                                     "causal-diagnostic" if phase == "third-diagnostic" else "causal-status",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-msi-owner-relaunch-quit-start", "windows-msi-owner-relaunch-quit-status",
                      "windows-msi-owner-relaunch-quit-collect", "windows-msi-owner-relaunch-quit-diagnose"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 relaunch quit host is required.")
            quit_adapter = _agent_module("windows_msi_owner_relaunch_quit")
            phase = action.removeprefix("windows-msi-owner-relaunch-quit-")
            try:
                result = quit_adapter.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            diagnostic_valid = (phase == "diagnose" and isinstance(result, dict)
                and set(result) == {"state", "phase", "task", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "diagnosed" and result.get("phase") in {"system", "tasks"}
                and result.get("task") in {"absent", "present", "prior-present",
                                           "owner-task-running", "ambiguous"}
                and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            unknown_result = {"state": "unknown", "replayAllowed": False,
                              "nativeActionAllowed": False}
            normal_valid = result == unknown_result or result in (
                ({"state": "submitted", "replayAllowed": False, "nativeActionAllowed": False},
                 {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False},
                 {"state": "exited", "runtimeRunning": False, "ownerExited": True,
                  "replayAllowed": False, "nativeActionAllowed": False})
                if phase == "start" else (
                    {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False},
                    {"state": "exited", "runtimeRunning": False, "ownerExited": True,
                     "replayAllowed": False, "nativeActionAllowed": False})
                if phase in {"status", "collect"} else ())
            if not (diagnostic_valid if phase == "diagnose" else normal_valid):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"submitted", "exited", "diagnosed"},
                    "evidenceClass": "native-owner-quit" if result["state"] == "exited" else
                                     "causal-diagnostic" if phase == "diagnose" else "causal-status",
                    "productAction": phase == "start", "nativeActionAllowed": False}
        if action in {"windows-msi-owner-relaunch-quit-v2-start", "windows-msi-owner-relaunch-quit-v2-status",
                      "windows-msi-owner-relaunch-quit-v2-collect", "windows-msi-owner-relaunch-quit-v2-diagnose",
                      "windows-msi-owner-relaunch-quit-v2-bootstrap-diagnostic"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 relaunch quit v2 host is required.")
            quit_adapter = _agent_module("windows_msi_owner_relaunch_quit_v2")
            phase = action.removeprefix("windows-msi-owner-relaunch-quit-v2-")
            try:
                result = quit_adapter.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            diagnostic_valid = (phase == "diagnose" and isinstance(result, dict)
                and set(result) == {"state", "phase", "task", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "diagnosed" and result.get("phase") in {"system", "tasks"}
                and result.get("task") in {"absent", "present", "ambiguous"}
                and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            bootstrap_valid = (phase == "bootstrap-diagnostic" and isinstance(result, dict)
                and set(result) == {"state", "gate", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "diagnosed"
                and result.get("gate") in {"scheduler", "account-sid", "status-task-present",
                                           "v1-task-present", "relaunch-task", "v1-process",
                                           "v2-task-present", "ready"}
                and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            unknown_result = {"state": "unknown", "replayAllowed": False,
                              "nativeActionAllowed": False}
            terminal_shapes = (
                {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False},
                {"state": "exited", "runtimeRunning": False, "ownerExited": True,
                 "replayAllowed": False, "nativeActionAllowed": False})
            normal_valid = result == unknown_result or result in (
                ({"state": "submitted", "replayAllowed": False,
                  "nativeActionAllowed": False}, *terminal_shapes)
                if phase == "start" else terminal_shapes if phase in {"status", "collect"} else ())
            if not (diagnostic_valid if phase == "diagnose" else
                    bootstrap_valid if phase == "bootstrap-diagnostic" else normal_valid):
                result = unknown_result
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"submitted", "exited", "diagnosed"},
                    "evidenceClass": "native-owner-quit" if result["state"] == "exited" else
                                     "causal-diagnostic" if phase in {"diagnose", "bootstrap-diagnostic"} else "causal-status",
                    "productAction": phase == "start", "nativeActionAllowed": False}
        if action in {"windows-msi-owner-relaunch-quit-v3-start", "windows-msi-owner-relaunch-quit-v3-status",
                      "windows-msi-owner-relaunch-quit-v3-collect", "windows-msi-owner-relaunch-quit-v3-diagnose",
                      "windows-msi-owner-relaunch-quit-v3-bootstrap-diagnostic",
                      "windows-msi-owner-relaunch-quit-v3-task-result"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 relaunch quit v3 host is required.")
            quit_adapter = _agent_module("windows_msi_owner_relaunch_quit_v3")
            phase = action.removeprefix("windows-msi-owner-relaunch-quit-v3-")
            try:
                result = quit_adapter.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            diagnostic_valid = (phase == "diagnose" and isinstance(result, dict)
                and set(result) == {"state", "phase", "task", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "diagnosed" and result.get("phase") in {"system", "tasks"}
                and result.get("task") in {"absent", "present", "ambiguous"}
                and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            bootstrap_valid = (phase == "bootstrap-diagnostic" and isinstance(result, dict)
                and set(result) == {"state", "gate", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "diagnosed"
                and result.get("gate") in {"scheduler", "account-sid", "status-task-present",
                                           "prior-quit-task-present", "relaunch-task", "v1-process",
                                           "v3-task-present", "ready"}
                and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            task_result_valid = (phase == "task-result" and isinstance(result, dict)
                and set(result) == {"state", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") in {"pending", "exited", "failed"}
                and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            unknown_result = {"state": "unknown", "replayAllowed": False,
                              "nativeActionAllowed": False}
            terminal_shapes = (
                {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False},
                {"state": "exited", "runtimeRunning": False, "ownerExited": True,
                 "replayAllowed": False, "nativeActionAllowed": False})
            normal_valid = result == unknown_result or result in (
                ({"state": "submitted", "replayAllowed": False,
                  "nativeActionAllowed": False}, *terminal_shapes)
                if phase == "start" else terminal_shapes if phase in {"status", "collect"} else ())
            if not (diagnostic_valid if phase == "diagnose" else
                    bootstrap_valid if phase == "bootstrap-diagnostic" else
                    task_result_valid if phase == "task-result" else normal_valid):
                result = unknown_result
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"submitted", "exited", "diagnosed"} and phase != "task-result",
                    "evidenceClass": "causal-diagnostic" if phase in {"diagnose", "bootstrap-diagnostic", "task-result"} else
                                     "native-owner-quit" if result["state"] == "exited" else "causal-status",
                    "productAction": phase == "start", "nativeActionAllowed": False}
        if action in {"windows-msi-owner-quit-phase-start", "windows-msi-owner-quit-phase-status",
                      "windows-msi-owner-quit-phase-collect"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 owner quit phase host is required.")
            diagnostic = _agent_module("windows_msi_owner_quit_phase_diagnostic")
            phase = action.removeprefix("windows-msi-owner-quit-phase-")
            try:
                result = diagnostic.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            unknown_result = {"state": "unknown", "replayAllowed": False,
                              "nativeActionAllowed": False}
            finite_status = (isinstance(result, dict)
                and set(result) == {"state", "phase", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "diagnosed"
                and result.get("phase") in {"passed", "identity", "ancestors", "cli",
                                           "owner-before", "endpoint", "public-status",
                                           "public-result", "owner-after", "task-error"}
                and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            normal_valid = result in (unknown_result,
                {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False})
            if phase == "start":
                normal_valid = normal_valid or result == {
                    "state": "submitted", "replayAllowed": False, "nativeActionAllowed": False}
            if not (finite_status or normal_valid):
                result = unknown_result
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"submitted", "diagnosed"},
                    "evidenceClass": "causal-diagnostic" if result["state"] == "diagnosed" else "causal-status",
                    "productAction": False, "nativeActionAllowed": False}
        if action in {"windows-msi-owner-relaunch-quit-v4-start", "windows-msi-owner-relaunch-quit-v4-status",
                      "windows-msi-owner-relaunch-quit-v4-collect", "windows-msi-owner-relaunch-quit-v4-diagnose"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 relaunch quit v4 host is required.")
            quit_adapter = _agent_module("windows_msi_owner_relaunch_quit_v4")
            phase = action.removeprefix("windows-msi-owner-relaunch-quit-v4-")
            try:
                result = quit_adapter.workflow(REPO_ROOT, phase, inputs)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            diagnostic_valid = (phase == "diagnose" and isinstance(result, dict)
                and set(result) == {"state", "phase", "task", "replayAllowed", "nativeActionAllowed"}
                and result.get("state") == "diagnosed" and result.get("phase") in {"system", "tasks"}
                and result.get("task") in {"absent", "present", "ambiguous"}
                and result.get("replayAllowed") is False and result.get("nativeActionAllowed") is False)
            unknown_result = {"state": "unknown", "replayAllowed": False,
                              "nativeActionAllowed": False}
            terminal_shapes = (
                {"state": "pending", "replayAllowed": False, "nativeActionAllowed": False},
                {"state": "exited", "runtimeRunning": False, "ownerExited": True,
                 "replayAllowed": False, "nativeActionAllowed": False})
            normal_valid = result == unknown_result or result in (
                ({"state": "submitted", "replayAllowed": False,
                  "nativeActionAllowed": False}, *terminal_shapes)
                if phase == "start" else terminal_shapes if phase in {"status", "collect"} else ())
            if not (diagnostic_valid if phase == "diagnose" else normal_valid):
                result = unknown_result
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] in {"submitted", "exited", "diagnosed"},
                    "evidenceClass": "native-owner-quit" if result["state"] == "exited" else
                                     "causal-diagnostic" if phase == "diagnose" else "causal-status",
                    "productAction": phase == "start", "nativeActionAllowed": False}
        if action in {"windows-msi-stale-lock-reconcile", "windows-msi-stale-lock-reconcile-status",
                      "windows-msi-stale-lock-reconcile-close"}:
            if not isinstance(inputs, dict) or inputs != {"host": "archlinux"}:
                return _error("vm_workflow", "Exact CP117 stale-lock reconciliation host is required.")
            reconcile = _agent_module("windows_msi_stale_lock_reconcile")
            phase = action.removeprefix("windows-msi-stale-lock-reconcile")
            try:
                result = (reconcile.status(REPO_ROOT, inputs) if phase == "-status" else
                          reconcile.close(REPO_ROOT, inputs) if phase == "-close" else
                          reconcile.reconcile(REPO_ROOT, inputs))
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            valid = (result in ({"state": "unknown", "replayAllowed": False,
                                "nativeActionAllowed": False},
                               {"state": "terminal-proven", "replayAllowed": False,
                                "nativeActionAllowed": False},
                               {"state": "recovered", "replayAllowed": False,
                                "nativeActionAllowed": False})
                     and (result.get("state") == "unknown" or
                          result["state"] == ("terminal-proven" if phase == "-status" else "recovered")))
            if not valid:
                result = {"state": "unknown", "replayAllowed": False,
                          "nativeActionAllowed": False}
            return {"tool": "vm_workflow", **result,
                    "ok": result["state"] != "unknown",
                    "evidenceClass": "causal-status" if phase == "-status" else "native-recovery",
                    "productAction": False, "nativeActionAllowed": False}
        if action == "windows-msi-base-finish-observed":
            if (not isinstance(inputs, dict) or set(inputs) != {"correlationId"}
                    or not isinstance(inputs["correlationId"], str)
                    or not _agent_module("windows_msi_base_prepare")._UUID.fullmatch(inputs["correlationId"])):
                return _error("vm_workflow", "Exact CP117 base finish correlation is required.")
            base = _agent_module("windows_msi_base_prepare")
            correlation = inputs["correlationId"]
            try:
                result = base.finish_observed(REPO_ROOT, correlation)
            except (ValueError, OSError, KeyError, TypeError):
                result = {"state": "unknown", "leaseId": correlation, "replayAllowed": False}
            if (not isinstance(result, dict) or set(result) != {"state", "leaseId", "replayAllowed"}
                    or result.get("state") not in {"active", "unknown"}
                    or result.get("leaseId") != correlation or result.get("replayAllowed") is not False):
                result = {"state": "unknown", "leaseId": correlation, "replayAllowed": False}
            return {"tool": "vm_workflow", **result, "ok": result["state"] == "active",
                    "evidenceClass": "causal-cleanup", "productAction": False}
        if action in {"windows-msi-base-preflight", "windows-msi-base-readiness", "windows-msi-base-start", "windows-msi-base-start-from-transfer", "windows-msi-base-status", "windows-msi-base-reconcile", "windows-msi-base-terminal-reconcile", "windows-msi-base-diagnostic", "windows-msi-base-stage-diagnostic", "windows-msi-base-transfer-preflight", "windows-msi-base-transfer-network-admission", "windows-msi-base-transfer-endpoint-probe", "windows-msi-base-transfer-endpoint-status", "windows-msi-base-transfer-endpoint-reconcile", "windows-msi-base-unknown-close", "windows-msi-base-unknown-close-status"}:
            base = _agent_module("windows_msi_base_prepare")
            try:
                method = {"windows-msi-base-preflight": base.powershell_preflight,
                          "windows-msi-base-readiness": base.readiness,
                          "windows-msi-base-start": base.start,
                          "windows-msi-base-start-from-transfer": base.start_from_transfer,
                          "windows-msi-base-status": base.status,
                          "windows-msi-base-reconcile": base.reconcile,
                          "windows-msi-base-terminal-reconcile": base.terminal_reconcile,
                          "windows-msi-base-diagnostic": base.diagnose,
                          "windows-msi-base-stage-diagnostic": base.stage_diagnose,
                          "windows-msi-base-transfer-preflight": base.transfer_preflight,
                          "windows-msi-base-transfer-network-admission": base.transfer_network_admission,
                          "windows-msi-base-transfer-endpoint-probe": _agent_module("windows_msi_transfer_endpoint").endpoint_probe,
                          "windows-msi-base-transfer-endpoint-status": _agent_module("windows_msi_transfer_endpoint").endpoint_probe_status,
                          "windows-msi-base-transfer-endpoint-reconcile": _agent_module("windows_msi_transfer_endpoint").endpoint_probe_reconcile,
                          "windows-msi-base-unknown-close": base.close_unknown,
                          "windows-msi-base-unknown-close-status": base.close_unknown_status}[action]
                result = method(REPO_ROOT, inputs)
                if action == "windows-msi-base-terminal-reconcile":
                    correlation = inputs.get("correlationId") if isinstance(inputs, dict) else None
                    terminal_fields = {"state", "correlationId", "result", "stage", "exitCode",
                                       "sourceSha", "baseArtifactId", "replayAllowed"}
                    unknown_fields = {"state", "correlationId", "replayAllowed"}
                    valid = (isinstance(result, dict) and result.get("correlationId") == correlation
                             and result.get("replayAllowed") is False and
                             ((set(result) == terminal_fields and result.get("state") == "terminal"
                               and result.get("result") == "PASSED" and result.get("stage") == "READBACK"
                               and type(result.get("exitCode")) is int and result["exitCode"] == 0
                               and isinstance(result.get("sourceSha"), str) and base._SHA.fullmatch(result["sourceSha"])
                               and isinstance(result.get("baseArtifactId"), str)
                               and result["baseArtifactId"].startswith("sha256-")
                               and base._HASH.fullmatch(result["baseArtifactId"][7:]))
                              or (set(result) == unknown_fields and result.get("state") == "unknown")))
                    if not valid:
                        result = {"state": "unknown", "correlationId": correlation,
                                  "replayAllowed": False}
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"passed", "ready", "submitted", "running"} or
                              (action == "windows-msi-base-transfer-endpoint-probe" and result.get("state") == "reachable") or
                              (action == "windows-msi-base-transfer-endpoint-status" and result.get("state") == "observed") or
                              (action == "windows-msi-base-transfer-endpoint-reconcile" and result.get("state") == "stopped") or
                              (result.get("state") == "terminal" and result.get("result") == "PASSED") or
                              (action in {"windows-msi-base-unknown-close", "windows-msi-base-unknown-close-status"}
                               and result.get("state") == "closed" and result.get("outcome") == "unknown-cleaned"),
                        "evidenceClass": "native-preflight" if action.endswith(("-preflight", "-readiness", "-admission", "-probe")) else
                                         "causal-status" if action.endswith("-endpoint-status") else
                                         "causal-cleanup" if action.endswith("-endpoint-reconcile") else
                                         "causal-diagnostic" if action.endswith("-diagnostic") else
                                         "causal-status" if action.endswith("-unknown-close-status") else
                                         "causal-cleanup" if action.endswith("-unknown-close") else
                                         "causal-reconciliation" if action.endswith("-reconcile") else "installed-package",
                        "productAction": action.endswith("-start") or action == "windows-msi-base-start-from-transfer"}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-msi-base-pre-effect-status":
            if set(inputs) != {"host"} or inputs["host"] != "archlinux":
                return _error("vm_workflow", "Windows base pre-effect status requires exact Arch host.")
            base = _agent_module("windows_msi_base_prepare")
            try:
                result = base.pre_effect_status(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "absent",
                        "evidenceClass": "read-only-pre-effect", "productAction": False,
                        "nativeActionAllowed": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-base-pre-effect-unavailable", "productAction": False,
                        "nativeActionAllowed": False}
        if action == "windows-msi-base-pre-effect-close":
            if set(inputs) != {"host"} or inputs["host"] != "archlinux":
                return _error("vm_workflow", "Windows base pre-effect closure requires exact Arch host.")
            base = _agent_module("windows_msi_base_prepare")
            try:
                result = base.close_pre_effect(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == "pre-effect-closed",
                        "evidenceClass": "pre-dispatch-campaign-closure", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-base-pre-effect-close-unavailable", "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-msi-owner-observe-preflight", "windows-msi-owner-observe-start", "windows-msi-owner-observe-status", "windows-msi-owner-observe-collect"}:
            observe = _agent_module("windows_msi_owner_observe")
            try:
                method = {"windows-msi-owner-observe-preflight": observe.powershell_preflight,
                          "windows-msi-owner-observe-start": observe.start,
                          "windows-msi-owner-observe-status": observe.status,
                          "windows-msi-owner-observe-collect": observe.collect}[action]
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"passed", "submitted", "running", "observed"},
                        "evidenceClass": "native-preflight" if action.endswith("-preflight") else "native-observation",
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"windows-msi-owner-quit-preflight", "windows-msi-owner-quit-start", "windows-msi-owner-quit-status", "windows-msi-owner-quit-collect"}:
            observe = _agent_module("windows_msi_owner_observe")
            start_fields = {"host", "correlationId", "sourceSha", "controllerId", "installedCliSha256",
                            "parentPid", "parentStartedAtUtc", "childPid", "childStartedAtUtc", "statusCorrelationId"}
            expected = ({"host"} if action.endswith("-preflight") else start_fields if action.endswith("-start")
                        else {"correlationId"})
            if (set(inputs) != expected or
                    ("host" in inputs and inputs["host"] != "archlinux") or
                    ("correlationId" in inputs and
                     (not isinstance(inputs["correlationId"], str) or not _valid_uuid(inputs["correlationId"]))) or
                    ("statusCorrelationId" in inputs and
                     (not isinstance(inputs["statusCorrelationId"], str) or not _valid_uuid(inputs["statusCorrelationId"])))):
                return _error("vm_workflow", "Windows owner quit requires exact fixed-host and correlation request.")
            try:
                method = {"windows-msi-owner-quit-preflight": observe.quit_powershell_preflight,
                          "windows-msi-owner-quit-start": observe.quit_start,
                          "windows-msi-owner-quit-status": observe.quit_status,
                          "windows-msi-owner-quit-collect": observe.quit_collect}[action]
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"passed", "submitted", "running", "observed", "cleaned", "quit-complete"},
                        "evidenceClass": "native-preflight" if action.endswith("-preflight") else "native-owner-quit",
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-owner-quit-outcome-unavailable",
                        "correlationId": inputs.get("correlationId"), "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-msi-target-preflight", "windows-msi-target-readiness", "windows-msi-target-start", "windows-msi-target-status"}:
            target = _agent_module("windows_msi_target_prepare")
            try:
                method = {"windows-msi-target-preflight": target.powershell_preflight,
                          "windows-msi-target-readiness": target.readiness,
                          "windows-msi-target-start": target.start,
                          "windows-msi-target-status": target.status}[action]
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"passed", "ready", "submitted", "running"} or
                              (result.get("state") == "terminal" and result.get("result") == "PASSED"),
                        "evidenceClass": "native-preflight" if action.endswith(("-preflight", "-readiness")) else "native-update-preparation",
                        "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"windows-msi-public-start", "windows-msi-public-status", "windows-msi-public-collect"}:
            windows = _agent_module("windows_msi_public_scenario")
            try:
                method = {"windows-msi-public-start": windows.start,
                          "windows-msi-public-status": windows.status,
                          "windows-msi-public-collect": windows.collect}[action]
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"submitted", "running", "observed"},
                        "evidenceClass": "installed-package", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action in {"artifact-set-freeze", "artifact-set-verify", "artifact-reuse-check"}:
            reuse = _agent_module("native_artifact_reuse")
            if action == "artifact-set-freeze":
                result = reuse.artifact_set_freeze(REPO_ROOT, inputs)
            elif action == "artifact-set-verify":
                if set(inputs) != {"artifactSetId"}:
                    return _error("vm_workflow", "Artifact set verification requires only artifactSetId.")
                result = reuse.artifact_set_verify(REPO_ROOT, inputs["artifactSetId"])
            else:
                result = reuse.artifact_reuse_check(REPO_ROOT, inputs)
            accepted = result.get("verification") != "mismatch" and result.get("decision") != "rebuild-required"
            return {"tool": "vm_workflow", "ok": accepted,
                    "evidenceScope": "artifact-byte-reuse" if action == "artifact-reuse-check" else "artifact-bytes", **result}
        if action == "artifact-cache-check":
            if set(inputs) != {"sourceSha", "artifactSetId"} or not isinstance(inputs["sourceSha"], str) or not re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", inputs["sourceSha"]):
                return _error("vm_workflow", "Artifact cache check requires exact sourceSha and artifactSetId.")
            reuse = _agent_module("native_artifact_reuse")
            result = reuse.artifact_reuse_check(REPO_ROOT, {"artifactSetId": inputs["artifactSetId"]})
            eligible = (result.get("decision") == "same-source" and
                        result.get("verification") == "verified" and
                        result.get("currentSourceSha") == inputs["sourceSha"] and
                        result.get("originalSourceSha") == inputs["sourceSha"] and
                        not result.get("reasons"))
            eligible = eligible and subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip() == inputs["sourceSha"]
            return {"tool": "vm_workflow", "ok": eligible, "cacheEligible": eligible,
                    "nativeActionAllowed": False, "productAction": False,
                    "evidenceClass": "source-bound-artifact-cache", **result}
        if action in ("android-proxy-recover", "android-proxy-recovery-status"):
            fields = {"host", "device", "expectedPort", "correlationId"} if action == "android-proxy-recover" else {"host", "device", "identity"}
            if set(inputs) != fields or any(not isinstance(inputs[key], str) or not inputs[key] for key in ("host", "device")):
                return _error("vm_workflow", "Proxy recovery requires an exact configured host/device and recovery identity.")
            if action == "android-proxy-recover" and (type(inputs["expectedPort"]) is not int or not 1 <= inputs["expectedPort"] <= 65535 or not isinstance(inputs["correlationId"], str)):
                return _error("vm_workflow", "Proxy recovery requires a task port and opaque correlation.")
            proxy_recovery = importlib.import_module(f"{__package__}.android_proxy_recovery" if __package__ else "android_proxy_recovery")
            try:
                if action == "android-proxy-recover":
                    result = proxy_recovery.recover_owned_stale_proxy(REPO_ROOT, inputs["host"], inputs["device"], inputs["expectedPort"], inputs["correlationId"])
                else:
                    result = proxy_recovery.observe_recovery(REPO_ROOT, inputs["host"], inputs["device"], inputs["identity"])
                return {"tool": "vm_workflow", **result}
            except proxy_recovery.AndroidProxyRecoveryError:
                return _error("vm_workflow", "Proxy recovery could not be admitted or observed; private diagnostics are retained locally.")
        if action in ("windows-credential-recover-start", "windows-credential-recover-status", "credential-status"):
            required = {"host", "correlationId"}
            optional = {"timeoutSeconds"}
            if action == "credential-status":
                required.add("handle")
                optional = set()
            if not required <= set(inputs) or set(inputs) - required - optional:
                return _error("vm_workflow", "Credential workflow requires only configured identity and an opaque correlation or handle.")
            if any(not isinstance(inputs[key], str) or not inputs[key] for key in required):
                return _error("vm_workflow", "Credential workflow identity fields must be nonempty strings.")
            timeout = inputs.get("timeoutSeconds", 15)
            if type(timeout) is not int or not 1 <= timeout <= 60:
                return _error("vm_workflow", "Credential workflow timeout must be between 1 and 60 seconds.")
            recovery = importlib.import_module(f"{__package__}.windows_credential_recovery_ssh" if __package__ else "windows_credential_recovery_ssh")
            try:
                if action == "credential-status":
                    result = recovery.credential_status(REPO_ROOT, inputs["host"], inputs["handle"], inputs["correlationId"])
                    accepted = result.get("available") is True
                else:
                    function = recovery.start if action.endswith("-start") else recovery.status
                    result = function(REPO_ROOT, inputs["host"], inputs["correlationId"], timeout_seconds=timeout)
                    accepted = result.get("state") in {"submitted", "verifying"} or (result.get("state") == "terminal" and result.get("success") is True)
                return {"tool": "vm_workflow", **result, "ok": accepted}
            except recovery.WindowsCredentialRecoveryError:
                return _error("vm_workflow", "Credential workflow could not be admitted or observed; private input details are withheld.")
        if action in ("windows-credential-probe-start", "windows-credential-probe-status"):
            if set(inputs) - {"host", "correlationId", "timeoutSeconds"} or not {"host", "correlationId"} <= set(inputs):
                return _error("vm_workflow", "Credential probe requires a configured host and correlationId only, with an optional timeoutSeconds.")
            if any(not isinstance(inputs[key], str) or not inputs[key] for key in ("host", "correlationId")):
                return _error("vm_workflow", "Credential probe identity fields must be nonempty strings.")
            timeout = inputs.get("timeoutSeconds", 15)
            if type(timeout) is not int or not 1 <= timeout <= 60:
                return _error("vm_workflow", "Credential probe timeout must be between 1 and 60 seconds.")
            probe = importlib.import_module(f"{__package__}.windows_credential_probe_ssh" if __package__ else "windows_credential_probe_ssh")
            try:
                function = probe.start if action.endswith("-start") else probe.status
                result = function(REPO_ROOT, inputs["host"], inputs["correlationId"], timeout_seconds=timeout)
                accepted = result.get("state") == "submitted" or (result.get("state") == "terminal" and result.get("success") is True)
                return {"tool": "vm_workflow", **result, "ok": accepted}
            except probe.WindowsCredentialProbeSshError:
                return _error("vm_workflow", "Configured Windows credential probe could not be admitted or observed; private input details are withheld.")
        if action in ("scenario-start", "scenario-status", "scenario-resume", "scenario-collect"):
            execution = _agent_module("native_scenario_execution")
            adapter = _agent_module("native_scenario_ssh")
            registry = _agent_module("native_artifact_registry")
            def resolve_bundle(plan):
                if set(plan.artifact_ids) != adapter.SCENARIO_ARTIFACT_KEYS.get(plan.scenario_id):
                    raise ValueError("Native scenario artifacts do not match its fixed recipe.")
                artifact_id = plan.artifact_ids["bundleManifest"]
                if artifact_id != "sha256-" + plan.bundle_hash:
                    raise ValueError("Registered bundle artifact differs from the frozen manifest hash.")
                verified = registry.verify_artifact(REPO_ROOT, artifact_id)
                if verified.get("verification") != "verified":
                    raise ValueError("Registered bundle manifest bytes are unavailable or changed.")
                location = verified["location"]
                manifest_path = Path(location["localPath"])
                if manifest_path.name != "native-scenario-manifest.json":
                    raise ValueError("Registered artifact is not a scenario manifest.")
                return manifest_path.parent
            def resolve_input(plan):
                verified = registry.verify_artifact(REPO_ROOT, plan.artifact_ids.get("scenarioInput"))
                if verified.get("verification") != "verified":
                    raise ValueError("Registered scenario input bytes are unavailable or changed.")
                return Path(verified["location"]["localPath"])
            executor = execution.ScenarioExecutor(REPO_ROOT / ".rag_index" / "native-scenario-executions",
                adapter.NativeScenarioSshDriver(REPO_ROOT, resolve_bundle, input_resolver=resolve_input))
            try:
                if action == "scenario-start":
                    expected = adapter.SCENARIO_ARTIFACT_KEYS.get(inputs.get("scenarioId"))
                    if expected is None or set(inputs.get("artifactIds", {})) != expected:
                        return _error("vm_workflow", "Scenario is unsupported or its registered artifacts do not match the fixed recipe.")
                    result = executor.start(inputs)
                else:
                    if set(inputs) != {"correlationId"}:
                        return _error("vm_workflow", "Scenario observation requires exactly correlationId.")
                    method = {"scenario-status": executor.status, "scenario-resume": executor.resume, "scenario-collect": executor.collect}[action]
                    result = method(inputs["correlationId"])
                accepted = result.get("state") == "submitted" or (result.get("state") == "terminal" and result.get("exitCode") == 0)
                product_action = result.get("scenarioId") == "linux-scheduled-refresh"
                return {"tool": "vm_workflow", "ok": accepted,
                        "evidenceClass": "installed-package" if product_action else "component",
                        "productAction": product_action, **result}
            except (ValueError, OSError) as error:
                return _error("vm_workflow", str(error))
        if action in ("environment-status", "environment-reserve", "environment-release"):
            environment = _agent_module("native_environment")
            try:
                if action == "environment-reserve":
                    result = environment.reserve_environment(REPO_ROOT, inputs)
                elif action == "environment-release":
                    result = environment.release_environment(REPO_ROOT, inputs)
                elif inputs.get("hostAlias"):
                    observer = _agent_module("native_environment_observation")
                    result = observer.observe_environment(REPO_ROOT, inputs)
                else:
                    result = environment.environment_status(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", "ok": True, **result}
            except (ValueError, OSError) as error:
                return _error("vm_workflow", str(error))
        if action in {"linux-guest-park-preflight", "linux-guest-park-start", "linux-guest-park-status"}:
            park = _agent_module("linux_guest_park")
            if action.endswith("-status"):
                if (set(inputs) != {"correlationId"} or
                        not isinstance(inputs.get("correlationId"), str) or
                        not _valid_uuid(inputs["correlationId"])):
                    return _error("vm_workflow", "Linux guest park status requires canonical correlationId only.")
            else:
                required = {"correlationId", "preparationCorrelationId", "guestRole", "sourceSha"}
                if (set(inputs) != required or
                        not all(isinstance(inputs[key], str) for key in required) or
                        not _valid_uuid(inputs["correlationId"]) or
                        not _valid_uuid(inputs["preparationCorrelationId"]) or
                        inputs["correlationId"] == inputs["preparationCorrelationId"] or
                        inputs["guestRole"] not in {"ubuntu-fresh", "ubuntu-update", "arch-update", "arch-rollback"} or
                        re.fullmatch(r"[0-9a-f]{40}", inputs["sourceSha"]) is None):
                    return _error("vm_workflow", "Linux guest park requires fixed role, exact source and distinct canonical correlations.")
            try:
                adapter = park.Adapter(REPO_ROOT, driver=park.FixedRemoteDriver(REPO_ROOT))
                method = adapter.status if action.endswith("-status") else (
                    adapter.preflight if action.endswith("-preflight") else adapter.start)
                result = method(inputs["correlationId"] if action.endswith("-status") else inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == ("ready" if action.endswith("-preflight") else "parked"),
                        "evidenceClass": "read-only-guest-park" if action.endswith(("-preflight", "-status")) else "native-guest-park",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, TimeoutError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "linux-guest-park-outcome-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"linux-package-fixture-build-preflight", "linux-package-fixture-build-start",
                      "linux-package-fixture-build-status", "linux-package-fixture-build-collect"}:
            build = _agent_module("linux_package_fixture_build")
            request_fields = {"sourceSha", "baseVersion", "targetVersion", "correlationId"}
            observing = action.endswith(("-status", "-collect"))
            source_root = inputs.get("sourceRoot")
            allowed_fields = ({"correlationId"},) if observing else (
                request_fields, request_fields | {"sourceRoot"})
            if (set(inputs) not in allowed_fields or
                    ("sourceRoot" in inputs and
                     (not isinstance(source_root, str) or not 1 <= len(source_root) <= 4096 or
                      "\x00" in source_root or not Path(source_root).is_absolute())) or
                    not isinstance(inputs.get("correlationId"), str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    (not action.endswith(("-status", "-collect")) and
                     (not isinstance(inputs["sourceSha"], str) or
                      re.fullmatch(r"[0-9a-f]{40}", inputs["sourceSha"]) is None or
                      not isinstance(inputs["baseVersion"], str) or
                      not isinstance(inputs["targetVersion"], str)))):
                return _error("vm_workflow", "Linux fixture build requires exact source, versions and canonical correlation.")
            try:
                method = {"linux-package-fixture-build-preflight": build.preflight,
                          "linux-package-fixture-build-start": build.start,
                          "linux-package-fixture-build-status": build.status,
                          "linux-package-fixture-build-collect": build.collect}[action]
                request = {key: value for key, value in inputs.items() if key != "sourceRoot"}
                result = (method(REPO_ROOT, request, source_root=source_root)
                          if "sourceRoot" in inputs else method(REPO_ROOT, request))
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"ready", "submitted", "running"},
                        "evidenceClass": "source-bound-package-fixture", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "linux-package-fixture-build-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"linux-package-fixture-build-pre-effect-status",
                      "linux-package-fixture-build-pre-effect-close"}:
            closing = action.endswith("-close")
            required = {"correlationId", "closureDigest"} if closing else {"correlationId"}
            if (set(inputs) != required or not isinstance(inputs.get("correlationId"), str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    (closing and (not isinstance(inputs.get("closureDigest"), str) or
                                  re.fullmatch(r"[0-9a-f]{64}", inputs["closureDigest"]) is None))):
                return _error("vm_workflow", "Linux build pre-effect closure requires exact correlation and proof.")
            build = _agent_module("linux_package_fixture_build")
            try:
                method = build.pre_effect_close if closing else build.pre_effect_status
                result = method(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in ({"closed"} if closing else {"ready", "closing", "closed"}),
                        "evidenceClass": "build-pre-effect-closure", "productAction": False,
                        "nativeActionAllowed": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "linux-build-pre-effect-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"linux-package-fixture-build-terminal-ready-status",
                      "linux-package-fixture-build-terminal-ready-close"}:
            closing = action.endswith("-close")
            required = {"correlationId", "closureDigest"} if closing else {"correlationId"}
            if (set(inputs) != required or not isinstance(inputs.get("correlationId"), str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    (closing and (not isinstance(inputs.get("closureDigest"), str) or
                                  re.fullmatch(r"[0-9a-f]{64}", inputs["closureDigest"]) is None))):
                return _error("vm_workflow", "Linux terminal-ready build closure requires exact correlation and proof.")
            build = _agent_module("linux_package_fixture_build")
            try:
                method = build.terminal_ready_close if closing else build.terminal_ready_status
                result = method(REPO_ROOT, inputs)
                admitted = (result.get("state") in ({"closed"} if closing else {"ready", "closing", "closed"}) and
                            result.get("correlationId") == inputs["correlationId"] and
                            isinstance(result.get("closureDigest"), str) and
                            re.fullmatch(r"[0-9a-f]{64}", result["closureDigest"]) is not None and
                            (not closing or result["closureDigest"] == inputs["closureDigest"]) and
                            result.get("replayAllowed") is False)
                return {"tool": "vm_workflow", **result, "ok": admitted,
                        "evidenceClass": "build-terminal-ready-closure", "productAction": False,
                        "nativeActionAllowed": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "linux-build-terminal-ready-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"linux-deb-arch-guest-prepare-preflight", "linux-deb-arch-guest-prepare-start",
                      "linux-deb-arch-guest-prepare-status"}:
            preparation = _agent_module("linux_deb_arch_guest_prepare")
            request_fields = {"profile", "distribution", "correlationId", "sourceSha", "artifactIds"}
            if set(inputs) != ({"correlationId"} if action.endswith("-status") else request_fields):
                return _error("vm_workflow", "Linux guest preparation requires exact source-bound request.")
            try:
                if action.endswith("-status"):
                    result = preparation.Adapter(REPO_ROOT,
                        driver=_agent_module("linux_deb_arch_guest_prepare_remote").FixedRemoteDriver(REPO_ROOT)).status(
                            inputs["correlationId"])
                else:
                    parsed = preparation.Request.parse(inputs)
                    if action.endswith("-preflight"):
                        result = preparation.preflight(REPO_ROOT, parsed)
                    else:
                        result = preparation.Adapter(REPO_ROOT,
                            driver=_agent_module("linux_deb_arch_guest_prepare_remote").FixedRemoteDriver(REPO_ROOT)).start(inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("inputsVerified") is True if action.endswith("-preflight") else
                              result.get("state") in {"submitted", "running", "ready"},
                        "evidenceClass": "read-only-guest-preparation" if action.endswith("-preflight") else "native-guest-preparation",
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "linux-guest-preparation-unavailable",
                        "correlationId": inputs.get("correlationId"), "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"linux-deb-arch-acceptance-preflight", "linux-deb-arch-acceptance-start",
                      "linux-deb-arch-acceptance-status"}:
            acceptance = _agent_module("linux_deb_arch_acceptance")
            request_fields = {"profile", "distribution", "correlationId", "sourceSha", "artifactIds"}
            if set(inputs) != ({"correlationId"} if action.endswith("-status") else request_fields):
                return _error("vm_workflow", "Linux native acceptance requires exact prepared source-bound request.")
            try:
                observer = _agent_module("linux_deb_arch_transport").FixedLiveObserver(REPO_ROOT)
                driver = _agent_module("linux_deb_arch_host_supervisor").FixedHostSupervisor(REPO_ROOT)
                adapter = acceptance.Adapter(REPO_ROOT, driver=driver,
                    admit=lambda intent: acceptance.preflight(REPO_ROOT, intent, observer))
                method = adapter.status if action.endswith("-status") else (
                    adapter.preflight if action.endswith("-preflight") else adapter.start)
                result = method(inputs["correlationId"] if action.endswith("-status") else inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("ready") is True if action.endswith("-preflight") else
                              result.get("state") in {"submitted", "running"} or
                              (result.get("state") == "terminal" and result.get("result") in
                               {"dependencies-installed", "installed", "rollback-restored"}),
                        "evidenceClass": "read-only-linux-native-admission" if action.endswith("-preflight") else "native-linux-acceptance",
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "linux-native-acceptance-unavailable",
                        "correlationId": inputs.get("correlationId"), "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action == "linux-vm-readonly-inventory":
            inventory = _agent_module("linux_vm_readonly_inventory")
            try:
                if not isinstance(inputs, dict) or set(inputs) != {"host", "timeoutSeconds"} or \
                        inputs["host"] != "archlinux" or type(inputs["timeoutSeconds"]) is not int or \
                        not 1 <= inputs["timeoutSeconds"] <= 30:
                    return _error("vm_workflow", "Linux VM inventory requires fixed archlinux host and bounded timeoutSeconds.")
                result = inventory.observe(REPO_ROOT, inputs["host"],
                                           timeout_seconds=inputs["timeoutSeconds"])
                complete = result.get("inventoryComplete") is True and result.get("nativeActionAllowed") is False
                return {"tool": "vm_workflow", **result, "state": "observed" if complete else "unknown",
                        "ok": complete,
                        "evidenceClass": "read-only-environment", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "arch-ai-loop-observe":
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 1 <= inputs["timeoutSeconds"] <= 30):
                return _error("vm_workflow", "ai_loop observation requires fixed Arch host and bounded timeoutSeconds.")
            try:
                observer = _agent_module("arch_ai_loop_observe")
                result = observer.observe(REPO_ROOT, inputs["timeoutSeconds"])
                fields = {"available", "outcome", "reason", "installation", "activity", "safeProjection"}
                if not isinstance(result, dict) or set(result) != fields:
                    raise ValueError("ai_loop observation is malformed")
                if result.get("available") is True:
                    if result.get("outcome") != "available" or result.get("reason") != "ok":
                        raise ValueError("ai_loop observation is contradictory")
                    raw = json.dumps({"schemaVersion": 1, "installation": result["installation"],
                                      "activity": result["activity"],
                                      "safeProjection": result["safeProjection"]}, separators=(",", ":"))
                    if len(raw) > 16_384 or observer._result(0, raw.encode("utf-8")) != result:
                        raise ValueError("ai_loop observation is malformed")
                elif (result.get("available") is not False or result.get("outcome") != "unknown"
                      or result.get("reason") not in {"timeout", "transport_unavailable", "oversized_output",
                                                      "transport_failed", "malformed_observation"}
                      or any(result.get(key) is not None for key in
                             ("installation", "activity", "safeProjection"))):
                    raise ValueError("ai_loop observation is malformed")
                available = result.get("available") is True and result.get("outcome") == "available"
                return {"tool": "vm_workflow", **result, "ok": available,
                        "state": "observed" if available else "unknown",
                        "evidenceClass": "read-only-tool-inventory", "nativeActionAllowed": False,
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "ai-loop-observation-unavailable", "host": "archlinux",
                        "nativeActionAllowed": False, "productAction": False}
        if action == "arch-qemu-holder-census":
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "timeoutSeconds"} or
                    inputs.get("host") != "archlinux" or
                    type(inputs.get("timeoutSeconds")) is not int or
                    not 1 <= inputs["timeoutSeconds"] <= 30):
                return _error("vm_workflow", "Arch QEMU census requires fixed host and bounded timeoutSeconds.")
            try:
                result = _agent_module("arch_qemu_holder_census").observe(REPO_ROOT, inputs)
                complete = (result.get("state") == "observed" and
                            result.get("inventoryComplete") is True and
                            result.get("nativeActionAllowed") is False)
                return {"tool": "vm_workflow", **result,
                        "state": "observed" if complete else "unknown", "ok": complete,
                        "evidenceClass": "read-only-environment", "productAction": False,
                        "nativeActionAllowed": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "arch-qemu-census-unavailable", "host": "archlinux",
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-parallel-vm-copy-start", "windows-parallel-vm-copy-status"}:
            correlation = inputs.get("correlationId")
            unknown = {"tool": "vm_workflow", "ok": False, "state": "unknown",
                       "reason": "windows-parallel-copy-unavailable", "host": "archlinux",
                       "correlationId": correlation if type(correlation) is str and _valid_uuid(correlation) else None,
                       "replayAllowed": False, "nativeGuestStarted": False, "launchAdmitted": False,
                       "productAcceptance": False, "productAction": False, "nativeActionAllowed": False}
            required = {"host", "correlationId", "timeoutSeconds"}
            if action.endswith("-start"):
                required.add("sourceEvidenceLeaf")
            if (type(inputs) is not dict or set(inputs) != required or inputs.get("host") != "archlinux"
                    or type(inputs.get("host")) is not str or type(correlation) is not str or not _valid_uuid(correlation)
                    or type(inputs.get("timeoutSeconds")) is not int or not 5 <= inputs["timeoutSeconds"] <= 60
                    or (action.endswith("-start") and (type(inputs["sourceEvidenceLeaf"]) is not str
                        or re.fullmatch(r"windows-parallel-vm-source-read-[0-9a-f]{32}", inputs["sourceEvidenceLeaf"]) is None))):
                return unknown
            try:
                adapter = _agent_module("windows_parallel_vm_prepare_transport")
                kwargs = {"host": "archlinux", "correlation_id": correlation, "timeout_seconds": inputs["timeoutSeconds"]}
                if action.endswith("-start"):
                    result = adapter.start(REPO_ROOT, source_evidence_leaf=inputs["sourceEvidenceLeaf"], **kwargs)
                else:
                    result = adapter.status(REPO_ROOT, **kwargs)
                result = _windows_parallel_copy_result(result, correlation, action, adapter)
                return {"tool": "vm_workflow", **result, "correlationId": correlation, "host": "archlinux",
                        "ok": result["state"] != "unknown", "replayAllowed": False,
                        "evidenceClass": "native-windows-template-copy", "productAction": False, "nativeActionAllowed": False}
            except Exception:
                return unknown
        if action == "windows-parallel-vm-source-inventory":
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows parallel source inventory requires fixed Arch host and bounded timeoutSeconds.")
            try:
                inventory = _agent_module("windows_parallel_vm_source_inventory")
                result = inventory.observe(REPO_ROOT, host="archlinux",
                                           timeout_seconds=inputs["timeoutSeconds"])
                metadata = {"toolSources", "remoteProgramSha256", "configuredTransportAuthority",
                            "evidenceLeaf", "rawReceipt", "transport"}
                if not isinstance(result, dict) or not metadata.issubset(result):
                    raise ValueError("windows-parallel-source-receipt-missing")
                def digest(value):
                    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None

                def pin(value, *, raw=False):
                    if type(value) is not dict or set(value) != {"sha256", "generation"} or not digest(value["sha256"]):
                        return False
                    generation = value["generation"]
                    return (type(generation) is list and len(generation) == 9
                            and all(type(item) is int and item >= 0 for item in generation)
                            and generation[0] > 0 and generation[1] > 0
                            and generation[2] & 0o170000 == 0o100000
                            and generation[3] == os.getuid() and generation[5] == 1
                            and (0 if raw else 1) <= generation[6] <= (inventory.MAX_OUTPUT + 1 if raw else 1048576)
                            and (not raw or generation[2] & 0o777 == 0o600))

                expected_sources = {str(REPO_ROOT / "agent_tools" / name) for name in (
                    "windows_parallel_vm_source_inventory.py", "ssh_transport.py",
                    "windows_credential_probe_ssh.py", "windows_cp117_bound_absence_completion.py",
                    "windows_vm_virt_firmware_install.py")}
                sources = result["toolSources"]
                trace = result["transport"]
                if (type(sources) is not dict or set(sources) != expected_sources
                        or not all(pin(value) for value in sources.values())
                        or not pin(result["rawReceipt"], raw=True)
                        or not digest(result["remoteProgramSha256"])
                        or not digest(result["configuredTransportAuthority"])
                        or type(result["evidenceLeaf"]) is not str
                        or re.fullmatch(r"windows-parallel-vm-source-read-[0-9a-f]{32}", result["evidenceLeaf"]) is None
                        or type(trace) is not dict
                        or set(trace) != {"pid", "stdoutEof", "exitCode", "reason", "clientTerminatedForBound"}
                        or type(trace["pid"]) is not int or trace["pid"] <= 0
                        or type(trace["stdoutEof"]) is not bool or type(trace["clientTerminatedForBound"]) is not bool
                        or not (trace["exitCode"] is None or type(trace["exitCode"]) is int and -255 <= trace["exitCode"] <= 255)
                        or trace["reason"] not in (None, "stdin-unavailable", "transport-deadline",
                                                  "transport-output-limit", "transport-nonzero")
                        or (trace["reason"] is None and (trace["exitCode"] != 0
                            or trace["stdoutEof"] is not True or trace["clientTerminatedForBound"] is not False))):
                    raise ValueError("windows-parallel-source-metadata-invalid")
                inventory.validate_report({key: value for key, value in result.items()
                                           if key not in metadata})
                return {"tool": "vm_workflow", **result,
                        "ok": result["state"] == "observed",
                        "evidenceClass": "read-only-windows-source", "productAction": False,
                        "nativeActionAllowed": False, "cloneAdmitted": False}
            except (ValueError, OSError, KeyError, TypeError, AttributeError) as error:
                reason = "windows-parallel-source-unavailable"
                if isinstance(error, ValueError) and error.args == ("ssh-connect-timeout-out-of-contract",):
                    reason = "ssh-connect-timeout-out-of-contract"
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "sourceState": "unknown", "reason": reason,
                        "host": "archlinux", "productAction": False,
                        "nativeActionAllowed": False, "cloneAdmitted": False}
        if action == "windows-vm-baseline-inventory":
            inventory = _agent_module("windows_vm_baseline_inventory")
            try:
                if (set(inputs) != {"host", "timeoutSeconds"} or inputs["host"] != "archlinux" or
                        type(inputs["timeoutSeconds"]) is not int or not 1 <= inputs["timeoutSeconds"] <= 30):
                    return _error("vm_workflow", "Windows baseline inventory requires fixed archlinux host and bounded timeoutSeconds.")
                result = inventory.observe(REPO_ROOT, inputs["host"],
                                           timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("inventoryComplete") is True and
                              result.get("nativeActionAllowed") is False,
                        "evidenceClass": "read-only-environment", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-vm-secureboot-inventory":
            if (set(inputs) != {"host", "qemuPid", "startTicks", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or type(inputs.get("qemuPid")) is not int or inputs["qemuPid"] != 3369984
                    or type(inputs.get("startTicks")) is not int or inputs["startTicks"] != 45177745
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 10 <= inputs["timeoutSeconds"] <= 60):
                return _error("vm_workflow", "Windows secure boot inventory requires exact Arch VM generation and bounded timeout.")
            inventory = _agent_module("windows_vm_secureboot_inventory")
            try:
                result = inventory.observe(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == "observed",
                        "evidenceClass": "read-only-secureboot-tpm-inventory",
                        "nativeActionAllowed": False, "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-vm-virt-firmware-admission":
            if (set(inputs) != {"host", "timeoutSeconds"} or inputs.get("host") != "archlinux"
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 10 <= inputs["timeoutSeconds"] <= 30):
                return _error("vm_workflow", "Virt-firmware admission requires exact Arch host and bounded timeout.")
            try:
                result = _agent_module("windows_vm_virt_firmware_admission").observe(REPO_ROOT, inputs)
                states = {"command-unavailable", "sudo-nopasswd-pacman", "sudo-listing-inconclusive",
                          "sudo-unavailable-or-auth-required"}
                state = result.get("state") if isinstance(result, dict) else None
                eligible = state == "sudo-nopasswd-pacman"
                if (not isinstance(result, dict) or set(result) != {"state", "host",
                        "noninteractivePacmanEligible", "nativeActionAllowed"}
                        or state not in states or result.get("host") != "archlinux"
                        or type(result.get("noninteractivePacmanEligible")) is not bool
                        or result["noninteractivePacmanEligible"] is not eligible
                        or result.get("nativeActionAllowed") is not False):
                    return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                            "noninteractivePacmanEligible": False, "nativeActionAllowed": False,
                            "productAction": False}
                return {"tool": "vm_workflow", "ok": True, "state": state, "host": "archlinux",
                        "noninteractivePacmanEligible": eligible,
                        "evidenceClass": "read-only-dependency-privilege", "nativeActionAllowed": False,
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "noninteractivePacmanEligible": False, "nativeActionAllowed": False,
                        "productAction": False}
        if action == "windows-vm-virt-firmware-install-preflight":
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("correlationId"), str)
                    or not _valid_uuid(inputs["correlationId"])
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 10 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Virt-firmware preflight requires exact Arch host, canonical correlation and bounded timeout.")
            try:
                result = _agent_module("windows_vm_virt_firmware_install").preflight(
                    REPO_ROOT, host=inputs["host"], correlation_id=inputs["correlationId"],
                    timeout_seconds=inputs["timeoutSeconds"])
                states = {"intent-existing", "transport-unavailable", "signature-policy-unavailable", "signature-policy-rejected",
                          "credential-metadata-invalid", "ready"}
                required = {"correlationId", "host", "state", "signaturePolicy", "transportDiagnostic",
                            "credentialMetadataValid", "safeStartAllowed", "newCorrelationRequired",
                            "nativeActionAllowed"}
                if (not isinstance(result, dict) or set(result) != required or result.get("correlationId") != inputs["correlationId"]
                        or result.get("host") != "archlinux" or result.get("state") not in states
                        or any(type(result.get(key)) is not bool for key in ("credentialMetadataValid", "safeStartAllowed", "newCorrelationRequired", "nativeActionAllowed"))):
                    raise ValueError("Virt-firmware preflight response is invalid.")
                return {"tool": "vm_workflow", **result, "ok": result["state"] == "ready",
                        "evidenceClass": "read-only-package-install-preflight", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "transport-unavailable",
                        "host": "archlinux", "correlationId": inputs.get("correlationId"),
                        "safeStartAllowed": False, "newCorrelationRequired": True,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-virt-firmware-install-start", "windows-vm-virt-firmware-install-status"}:
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("correlationId"), str)
                    or not _valid_uuid(inputs["correlationId"])
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 10 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Virt-firmware install requires exact Arch host, canonical correlation and bounded timeout.")
            installer = _agent_module("windows_vm_virt_firmware_install")
            try:
                method = installer.start if action.endswith("-start") else installer.status
                result = method(REPO_ROOT, host=inputs["host"], correlation_id=inputs["correlationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                valid_states = {"verified", "transaction-failed", "package-verification-failed", "unknown", "intent-absent"}
                required = {"correlationId", "host", "state", "package", "version",
                            "pacmanSignatureVerified", "packageIntegrityVerified", "firmwareToolPresent",
                            "replayAllowed", "nativeActionAllowed"}
                if (not isinstance(result, dict) or set(result) != required
                        or result.get("correlationId") != inputs["correlationId"]
                        or result.get("host") != "archlinux" or result.get("state") not in valid_states
                        or result.get("package") != "virt-firmware" or result.get("version") != "26.9-1"
                        or any(type(result.get(key)) is not bool for key in
                               ("pacmanSignatureVerified", "packageIntegrityVerified", "firmwareToolPresent",
                                "replayAllowed", "nativeActionAllowed"))
                        or result["replayAllowed"] is not False or result["nativeActionAllowed"] is not False):
                    raise ValueError("Virt-firmware install response is invalid.")
                return {"tool": "vm_workflow", **result, "ok": result["state"] == "verified",
                        "evidenceClass": "remote-package-install", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "host": "archlinux", "correlationId": inputs.get("correlationId"),
                        "replayAllowed": False, "nativeActionAllowed": False,
                        "productAction": action.endswith("-start")}
        if action == "windows-vm-swtpm-repair-preflight":
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"} or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("correlationId"), str) or not _valid_uuid(inputs["correlationId"])
                    or type(inputs.get("timeoutSeconds")) is not int or not 10 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "swtpm repair preflight requires exact Arch host, canonical correlation and bounded timeout.")
            try:
                result = _agent_module("windows_vm_swtpm_repair").preflight(REPO_ROOT, host=inputs["host"], correlation_id=inputs["correlationId"], timeout_seconds=inputs["timeoutSeconds"])
                required = {"correlationId", "host", "state", "packageIntegrityFailed", "activeSwtpmProcesses", "safeStartAllowed", "newCorrelationRequired", "nativeActionAllowed"}
                states = {"ready", "intent-existing", "integrity-failed", "verified", "package-not-exact", "active-swtpm-processes", "process-census-unavailable", "signature-policy-rejected", "credential-metadata-invalid", "transport-unavailable"}
                if (not isinstance(result, dict) or set(result) != required or result.get("correlationId") != inputs["correlationId"] or result.get("host") != "archlinux" or result.get("state") not in states or any(type(result.get(key)) is not bool for key in ("packageIntegrityFailed", "activeSwtpmProcesses", "safeStartAllowed", "newCorrelationRequired", "nativeActionAllowed"))):
                    raise ValueError("swtpm repair preflight response is invalid.")
                return {"tool": "vm_workflow", **result, "ok": result["state"] == "ready", "evidenceClass": "read-only-swtpm-repair-preflight", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "transport-unavailable", "host": "archlinux", "correlationId": inputs.get("correlationId"), "packageIntegrityFailed": False, "activeSwtpmProcesses": False, "safeStartAllowed": False, "newCorrelationRequired": True, "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-swtpm-repair-start", "windows-vm-swtpm-repair-status"}:
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"} or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("correlationId"), str) or not _valid_uuid(inputs["correlationId"])
                    or type(inputs.get("timeoutSeconds")) is not int or not 10 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "swtpm repair requires exact Arch host, canonical correlation and bounded timeout.")
            try:
                adapter = _agent_module("windows_vm_swtpm_repair")
                result = (adapter.start if action.endswith("-start") else adapter.status)(REPO_ROOT, host=inputs["host"], correlation_id=inputs["correlationId"], timeout_seconds=inputs["timeoutSeconds"])
                required = {"correlationId", "host", "state", "package", "version", "pacmanSignatureVerified", "packageIntegrityVerified", "activeSwtpmProcesses", "replayAllowed", "nativeActionAllowed"}
                states = {"verified", "already-healthy", "integrity-failed", "package-not-exact", "active-swtpm-processes", "process-census-unavailable", "transaction-failed", "unknown", "intent-absent"}
                if (not isinstance(result, dict) or set(result) != required or result.get("correlationId") != inputs["correlationId"] or result.get("host") != "archlinux" or result.get("state") not in states or result.get("package") != "swtpm" or result.get("version") != "0.10.2-1" or any(type(result.get(key)) is not bool for key in ("pacmanSignatureVerified", "packageIntegrityVerified", "activeSwtpmProcesses", "replayAllowed", "nativeActionAllowed")) or result["replayAllowed"] is not False or result["nativeActionAllowed"] is not False):
                    raise ValueError("swtpm repair response is invalid.")
                return {"tool": "vm_workflow", **result, "ok": result["state"] == "verified", "evidenceClass": "remote-swtpm-repair", "productAction": action.endswith("-start")}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown", "host": "archlinux", "correlationId": inputs.get("correlationId"), "package": "swtpm", "version": "0.10.2-1", "pacmanSignatureVerified": False, "packageIntegrityVerified": False, "activeSwtpmProcesses": False, "replayAllowed": False, "nativeActionAllowed": False, "productAction": action.endswith("-start")}
        if action == "windows-vm-swtpm-owner-observe":
            if (set(inputs) != {"host", "timeoutSeconds"} or inputs.get("host") != "archlinux" or
                    type(inputs.get("timeoutSeconds")) is not int or not 10 <= inputs["timeoutSeconds"] <= 60):
                return _error("vm_workflow", "swtpm owner observation requires exact Arch host and bounded timeout.")
            try:
                result = _agent_module("windows_vm_swtpm_repair").owner_observe(
                    REPO_ROOT, host=inputs["host"], timeout_seconds=inputs["timeoutSeconds"])
                required = {"host", "state", "censusReason", "censusComplete", "activeSwtpmProcesses", "processes", "nativeActionAllowed"}
                if (not isinstance(result, dict) or set(result) != required or result.get("host") != "archlinux" or
                        result.get("state") not in {"observed", "unknown"} or
                        ((result["state"] == "observed") != result.get("censusComplete")) or
                        (result["censusComplete"] and result.get("censusReason") is not None) or
                        (not result["censusComplete"] and result.get("censusReason") not in {"proc-visibility-incomplete", "process-read-unavailable", "fd-census-incomplete", "census-capacity", "census-unavailable"}) or
                        any(type(result.get(key)) is not bool for key in ("censusComplete", "activeSwtpmProcesses", "nativeActionAllowed")) or
                        not isinstance(result.get("processes"), list) or len(result["processes"]) > 16 or result["nativeActionAllowed"] is not False):
                    raise ValueError("swtpm owner observation response is invalid.")
                for item in result["processes"]:
                    if (not isinstance(item, dict) or set(item) != {"pid", "startTicks", "uid", "relationship"} or
                            type(item.get("pid")) is not int or item["pid"] <= 0 or
                            type(item.get("startTicks")) is not int or item["startTicks"] <= 0 or
                            type(item.get("uid")) is not int or item["uid"] < 0 or
                            item.get("relationship") not in {"task-owned-swtpm-socket", "unattributed-vm-or-socket-path", "no-visible-socket-path"}):
                        raise ValueError("swtpm owner observation process is invalid.")
                return {"tool": "vm_workflow", **result, "ok": result["state"] == "observed",
                        "evidenceClass": "read-only-swtpm-owner-observation", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "host": "archlinux", "state": "unknown", "censusReason": "census-unavailable",
                        "censusComplete": False, "activeSwtpmProcesses": False, "processes": [],
                        "nativeActionAllowed": False, "productAction": False}
        if action == "windows-vm-secureboot-clone-preflight":
            required = {"host", "ownerPid", "ownerStartTicks", "baselineReservationId", "timeoutSeconds"}
            if (set(inputs) != required or inputs.get("host") != "archlinux"
                    or type(inputs.get("ownerPid")) is not int or inputs["ownerPid"] != 3369984
                    or type(inputs.get("ownerStartTicks")) is not int or inputs["ownerStartTicks"] != 45177745
                    or inputs.get("baselineReservationId") != "env-fc3b3308d6a07175d1e4e08330f7f3aa"
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 10 <= inputs["timeoutSeconds"] <= 60):
                return _error("vm_workflow", "Secure Boot clone preflight requires exact Arch source and reservation pins.")
            try:
                result = _agent_module("windows_vm_secureboot_clone").preflight(REPO_ROOT, inputs)
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "blocked",
                        "evidenceClass": "read-only-secureboot-clone-preflight",
                        "nativeActionAllowed": False, "productAction": False}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "windows-vm-media-fingerprint":
            inventory = _agent_module("windows_vm_baseline_inventory")
            if (set(inputs) != {"host", "timeoutSeconds"} or inputs["host"] != "archlinux" or
                    type(inputs["timeoutSeconds"]) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 240):
                return _error("vm_workflow", "Windows media fingerprint requires fixed archlinux host and bounded timeoutSeconds.")
            try:
                result = inventory.media_fingerprint(REPO_ROOT, inputs["host"],
                                                     timeout_seconds=inputs["timeoutSeconds"])
                complete = result.get("mediaFingerprintComplete") is True and result.get("nativeActionAllowed") is False
                return {"tool": "vm_workflow", **result, "ok": complete,
                        "state": "observed" if complete else "unknown",
                        "evidenceClass": "read-only-media-bytes", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-media-fingerprint-unavailable",
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status"}:
            fetch = _agent_module("windows_vm_driver_fetch")
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or not isinstance(inputs["correlationId"], str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    type(inputs["timeoutSeconds"]) is not int or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows driver fetch requires fixed host, canonical correlationId and bounded timeoutSeconds.")
            try:
                method = fetch.start if action.endswith("-start") else fetch.status
                result = method(REPO_ROOT, host=inputs["host"],
                                correlation_id=inputs["correlationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "verified",
                        "evidenceClass": "native-fixture-preparation", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "driver-fetch-outcome-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-disk-probe-start", "windows-vm-disk-probe-status"}:
            probe = _agent_module("windows_vm_fresh_setup")
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or not isinstance(inputs["correlationId"], str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    type(inputs["timeoutSeconds"]) is not int or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows disk probe requires fixed host, canonical correlationId and bounded timeoutSeconds.")
            try:
                method = probe.probe_start if action.endswith("-start") else probe.probe_status
                result = method(REPO_ROOT, host=inputs["host"],
                                correlation_id=inputs["correlationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "verified",
                        "evidenceClass": "native-fixture-disk-probe", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-disk-probe-outcome-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-secureboot-fresh-preflight", "windows-vm-secureboot-fresh-start",
                      "windows-vm-secureboot-fresh-status"}:
            required = {"host", "correlationId", "timeoutSeconds"}
            if action.endswith("-start"):
                required.add("reservationRequest")
            if (set(inputs) != required or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("correlationId"), str)
                    or not _valid_uuid(inputs["correlationId"])
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 30 <= inputs["timeoutSeconds"] <= 300
                    or action.endswith("-start") and not isinstance(inputs.get("reservationRequest"), dict)):
                return _error("vm_workflow", "Secure Boot fresh VM needs fixed host, correlation, timeout and exact start reservation.")
            setup = _agent_module("windows_vm_secureboot_fresh")
            try:
                kwargs = {"host": inputs["host"], "correlation_id": inputs["correlationId"],
                          "timeout_seconds": inputs["timeoutSeconds"]}
                if action.endswith("-start"):
                    result = setup.start(REPO_ROOT, reservation_request=inputs["reservationRequest"], **kwargs)
                elif action.endswith("-status"):
                    result = setup.status(REPO_ROOT, **kwargs)
                else:
                    result = setup.preflight(REPO_ROOT, **kwargs)
                admitted = result.get("state") == ("ready" if action.endswith("-preflight") else "running-observed")
                return {"tool": "vm_workflow", **result, "ok": admitted,
                        "evidenceClass": "native-fixture-preparation" if action.endswith("-start") else "read-only-environment",
                        "nativeActionAllowed": False, "productAction": False,
                        "replayAllowed": False if action.endswith("-start") else result.get("replayAllowed", False)}
            except (ValueError, OSError, KeyError, TypeError) as error:
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "secureboot-fresh-unavailable", "correlationId": inputs["correlationId"],
                        "nativeActionAllowed": False, "replayAllowed": False, "productAction": False}
        if action == "windows-vm-fresh-preflight":
            setup = _agent_module("windows_vm_fresh_setup")
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or not isinstance(inputs["correlationId"], str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    type(inputs["timeoutSeconds"]) is not int or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows fresh preflight requires fixed host, canonical correlationId and bounded timeoutSeconds.")
            try:
                result = setup.preflight(REPO_ROOT, host=inputs["host"],
                                         correlation_id=inputs["correlationId"],
                                         timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "ready",
                        "evidenceClass": "read-only-environment", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-fresh-preflight-unavailable",
                        "correlationId": inputs["correlationId"],
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-optical-attempt2-close-preflight",
                      "windows-vm-optical-attempt2-close-start",
                      "windows-vm-optical-attempt2-close-status"}:
            attempt = _agent_module("windows_vm_optical_boot_attempt2")
            optical = _agent_module("windows_vm_optical_boot")
            closure = inputs.get("closureCorrelationId")
            if (set(inputs) != {"host", "closureCorrelationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or
                    not isinstance(closure, str) or not _valid_uuid(closure) or
                    closure in {optical.FIRST_CORRELATION, optical.FIRST_CLOSURE,
                                optical.SECOND_CORRELATION, optical.VM_CORRELATION} or
                    type(inputs["timeoutSeconds"]) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows optical attempt-2 closure requires fixed Arch host, new canonical closure correlation and bounded timeoutSeconds.")
            try:
                method = {"windows-vm-optical-attempt2-close-preflight": attempt.close_preflight,
                          "windows-vm-optical-attempt2-close-start": attempt.close_start,
                          "windows-vm-optical-attempt2-close-status": attempt.close_status}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                closure_correlation_id=closure,
                                timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == ("ready" if action.endswith("-preflight") else "pre-effect-closed"),
                        "evidenceClass": "read-only-windows-optical-attempt2-close" if not action.endswith("-start") else "native-fixture-optical-attempt2-close",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-optical-attempt2-close-outcome-unavailable",
                        "closureCorrelationId": closure, "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-setup-language-next-preflight", "windows-vm-setup-language-next-start",
                      "windows-vm-setup-language-next-status", "windows-vm-setup-language-next-collect"}:
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "nextCorrelationId", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("nextCorrelationId"), str)
                    or not _valid_uuid(inputs["nextCorrelationId"])
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows Setup language Next requires the fixed Arch host, canonical nextCorrelationId and bounded timeoutSeconds.")
            try:
                setup = _agent_module("windows_vm_setup_language_next")
                method = {"windows-vm-setup-language-next-preflight": setup.preflight,
                          "windows-vm-setup-language-next-start": setup.start,
                          "windows-vm-setup-language-next-status": setup.status,
                          "windows-vm-setup-language-next-collect": setup.collect}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                next_correlation_id=inputs["nextCorrelationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                expected = ("ready" if action.endswith("-preflight") else
                            "collected" if action.endswith("-collect") else "after-observed")
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == expected and result.get("replayAllowed") is False,
                        "evidenceClass": "native-windows-setup-language", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-setup-language-next-outcome-unavailable",
                        "nextCorrelationId": inputs["nextCorrelationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-setup-install-next-preflight", "windows-vm-setup-install-next-start",
                      "windows-vm-setup-install-next-status", "windows-vm-setup-install-next-collect"}:
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "nextCorrelationId", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("nextCorrelationId"), str)
                    or not _valid_uuid(inputs["nextCorrelationId"])
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows checked install option Next needs fixed Arch host, canonical nextCorrelationId and bounded timeoutSeconds.")
            try:
                advance = _agent_module("windows_vm_setup_install_next")
                method = {"windows-vm-setup-install-next-preflight": advance.preflight,
                          "windows-vm-setup-install-next-start": advance.start,
                          "windows-vm-setup-install-next-status": advance.status,
                          "windows-vm-setup-install-next-collect": advance.collect}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                next_correlation_id=inputs["nextCorrelationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                expected = ("ready" if action.endswith("-preflight") else
                            "collected" if action.endswith("-collect") else "after-observed")
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == expected and result.get("replayAllowed") is False,
                        "evidenceClass": "native-windows-install-option-next", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-install-option-next-outcome-unavailable",
                        "nextCorrelationId": inputs["nextCorrelationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-setup-install-ack-preflight", "windows-vm-setup-install-ack-start",
                      "windows-vm-setup-install-ack-status", "windows-vm-setup-install-ack-collect"}:
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "nextCorrelationId", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("nextCorrelationId"), str)
                    or not _valid_uuid(inputs["nextCorrelationId"])
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows install acknowledgment needs fixed Arch host, canonical nextCorrelationId and bounded timeoutSeconds.")
            try:
                acknowledgment = _agent_module("windows_vm_setup_install_ack")
                method = {"windows-vm-setup-install-ack-preflight": acknowledgment.preflight,
                          "windows-vm-setup-install-ack-start": acknowledgment.start,
                          "windows-vm-setup-install-ack-status": acknowledgment.status,
                          "windows-vm-setup-install-ack-collect": acknowledgment.collect}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                next_correlation_id=inputs["nextCorrelationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                expected = ("ready" if action.endswith("-preflight") else
                            "collected" if action.endswith("-collect") else "after-observed")
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == expected and result.get("replayAllowed") is False,
                        "evidenceClass": "native-windows-install-acknowledgment", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-install-acknowledgment-outcome-unavailable",
                        "nextCorrelationId": inputs["nextCorrelationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-setup-install-focus-preflight", "windows-vm-setup-install-focus-start",
                      "windows-vm-setup-install-focus-status", "windows-vm-setup-install-focus-collect"}:
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "nextCorrelationId", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("nextCorrelationId"), str)
                    or not _valid_uuid(inputs["nextCorrelationId"])
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows install focus needs fixed Arch host, canonical nextCorrelationId and bounded timeoutSeconds.")
            try:
                focus = _agent_module("windows_vm_setup_install_focus")
                method = {"windows-vm-setup-install-focus-preflight": focus.preflight,
                          "windows-vm-setup-install-focus-start": focus.start,
                          "windows-vm-setup-install-focus-status": focus.status,
                          "windows-vm-setup-install-focus-collect": focus.collect}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                next_correlation_id=inputs["nextCorrelationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                expected = ("ready" if action.endswith("-preflight") else
                            "collected" if action.endswith("-collect") else "after-observed")
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == expected and result.get("replayAllowed") is False,
                        "evidenceClass": "native-windows-install-focus", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-install-focus-outcome-unavailable",
                        "nextCorrelationId": inputs["nextCorrelationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action == "windows-vm-setup-install-disk-proof":
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows install disk proof needs fixed Arch host and bounded timeoutSeconds.")
            try:
                proof = _agent_module("windows_vm_setup_install_disk_proof")
                result = proof.preflight(REPO_ROOT, host=inputs["host"],
                                         timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == "ready"
                        and result.get("replayAllowed") is False
                        and result.get("nativeActionAllowed") is False,
                        "evidenceClass": "read-only-windows-install-disk-proof",
                        "productAction": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-install-disk-proof-unavailable",
                        "nativeActionAllowed": False, "replayAllowed": False,
                        "productAction": False}
        if action in {"windows-vm-setup-keyboard-next-preflight", "windows-vm-setup-keyboard-next-start",
                      "windows-vm-setup-keyboard-next-status", "windows-vm-setup-keyboard-next-collect"}:
            if (not isinstance(inputs, dict) or set(inputs) != {"host", "nextCorrelationId", "timeoutSeconds"}
                    or inputs.get("host") != "archlinux"
                    or not isinstance(inputs.get("nextCorrelationId"), str)
                    or not _valid_uuid(inputs["nextCorrelationId"])
                    or type(inputs.get("timeoutSeconds")) is not int
                    or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows Setup keyboard Next requires the fixed Arch host, canonical nextCorrelationId and bounded timeoutSeconds.")
            try:
                setup = _agent_module("windows_vm_setup_keyboard_next")
                method = {"windows-vm-setup-keyboard-next-preflight": setup.preflight,
                          "windows-vm-setup-keyboard-next-start": setup.start,
                          "windows-vm-setup-keyboard-next-status": setup.status,
                          "windows-vm-setup-keyboard-next-collect": setup.collect}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                next_correlation_id=inputs["nextCorrelationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                expected = ("ready" if action.endswith("-preflight") else
                            "collected" if action.endswith("-collect") else "after-observed")
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == expected and result.get("replayAllowed") is False,
                        "evidenceClass": "native-windows-setup-keyboard", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-setup-keyboard-next-outcome-unavailable",
                        "nextCorrelationId": inputs["nextCorrelationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-optical-current-screen-preflight", "windows-vm-optical-current-screen-start",
                      "windows-vm-optical-current-screen-status", "windows-vm-optical-current-screen-collect"}:
            current = _agent_module("windows_vm_optical_current_screen")
            optical = _agent_module("windows_vm_optical_boot")
            observation = inputs.get("observationCorrelationId") if isinstance(inputs, dict) else None
            prior = {optical.FIRST_CORRELATION, optical.FIRST_CLOSURE,
                     optical.SECOND_CORRELATION, optical.VM_CORRELATION,
                     current.ATTEMPT_CORRELATION, current.CLOSURE_CORRELATION}
            if (not isinstance(inputs, dict) or
                    set(inputs) != {"host", "observationCorrelationId", "timeoutSeconds"} or
                    inputs.get("host") != "archlinux" or
                    not isinstance(observation, str) or not _valid_uuid(observation) or
                    observation in prior or type(inputs.get("timeoutSeconds")) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows optical current screen requires fixed Arch host, new canonical observation correlation, and bounded timeoutSeconds.")
            try:
                method = {"windows-vm-optical-current-screen-preflight": current.preflight,
                          "windows-vm-optical-current-screen-start": current.start,
                          "windows-vm-optical-current-screen-status": current.status,
                          "windows-vm-optical-current-screen-collect": current.collect}[action]
                result = method(REPO_ROOT, host="archlinux",
                                observation_correlation_id=observation,
                                timeout_seconds=inputs["timeoutSeconds"])
                expected = ("ready" if action.endswith("-preflight") else
                            "collected" if action.endswith("-collect") else "observed")
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == expected and
                              result.get("nativeActionAllowed") is False,
                        "evidenceClass": "read-only-windows-optical-current-screen",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-optical-current-screen-unavailable",
                        "observationCorrelationId": observation,
                        "nativeActionAllowed": False, "replayAllowed": False,
                        "productAction": False}
        if action == "windows-vm-optical-attempt3-frame-collect":
            correlation = "e80d5b29-d44f-4b22-a821-5612304564b5"
            closure = "7cbc014c-3890-422a-891a-a114d7cb779e"
            if (not isinstance(inputs, dict) or
                    set(inputs) != {"host", "correlationId", "closureCorrelationId", "timeoutSeconds"} or
                    inputs.get("host") != "archlinux" or
                    inputs.get("correlationId") != correlation or
                    inputs.get("closureCorrelationId") != closure or
                    type(inputs.get("timeoutSeconds")) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows optical post-frame collection requires fixed Arch host, exact third-attempt and closure correlations, and bounded timeoutSeconds.")
            try:
                result = _agent_module("windows_vm_optical_post_collect").collect(
                    REPO_ROOT, host="archlinux", correlation_id=correlation,
                    closure_correlation_id=closure, timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == "collected" and
                              result.get("nativeActionAllowed") is False,
                        "evidenceClass": "read-only-windows-optical-post-frame",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-optical-post-frame-unavailable",
                        "correlationId": correlation, "closureCorrelationId": closure,
                        "nativeActionAllowed": False, "replayAllowed": False,
                        "productAction": False}
        if action in {"windows-vm-optical-attempt3-preflight", "windows-vm-optical-attempt3-start",
                      "windows-vm-optical-attempt3-status"}:
            attempt = _agent_module("windows_vm_optical_boot_attempt3")
            optical = _agent_module("windows_vm_optical_boot")
            correlation = inputs.get("correlationId")
            closure = inputs.get("closureCorrelationId")
            prior = {optical.FIRST_CORRELATION, optical.FIRST_CLOSURE,
                     optical.SECOND_CORRELATION, optical.VM_CORRELATION}
            if (set(inputs) != {"host", "correlationId", "closureCorrelationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or
                    not isinstance(correlation, str) or not _valid_uuid(correlation) or
                    not isinstance(closure, str) or not _valid_uuid(closure) or
                    correlation in prior or closure in prior or correlation == closure or
                    type(inputs["timeoutSeconds"]) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows optical attempt 3 requires fixed Arch host, distinct new action and second-closure correlations, and bounded timeoutSeconds.")
            try:
                method = {"windows-vm-optical-attempt3-preflight": attempt.preflight,
                          "windows-vm-optical-attempt3-start": attempt.start,
                          "windows-vm-optical-attempt3-status": attempt.status}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                correlation_id=correlation,
                                closure_correlation_id=closure,
                                timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == ("ready" if action.endswith("-preflight") else "post-screen-observed"),
                        "evidenceClass": "read-only-windows-optical-attempt3" if not action.endswith("-start") else "native-fixture-optical-attempt3",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-optical-attempt3-outcome-unavailable",
                        "correlationId": correlation, "closureCorrelationId": closure,
                        "replayAllowed": False, "nativeActionAllowed": False,
                        "productAction": False}
        if action == "windows-vm-optical-attempt2-phase-probe":
            attempt = _agent_module("windows_vm_optical_boot_attempt2")
            if (set(inputs) != {"host", "correlationId", "closureCorrelationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or
                    inputs.get("correlationId") != "98b4f1e0-968c-455b-a85b-d87490f5b256" or
                    inputs.get("closureCorrelationId") != "b76bfd72-2d7b-459a-91da-a063e35c8007" or
                    type(inputs["timeoutSeconds"]) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows optical attempt-2 phase probe requires the exact existing attempt and closure correlations.")
            try:
                result = attempt.phase_probe(REPO_ROOT, host=inputs["host"],
                    correlation_id=inputs["correlationId"],
                    closure_correlation_id=inputs["closureCorrelationId"],
                    timeout_seconds=inputs["timeoutSeconds"])
                probe = result.get("probe")
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == "phase-probed" and
                              isinstance(probe, dict) and probe.get("state") == "ready",
                        "evidenceClass": "read-only-windows-optical-phase",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-optical-phase-probe-unavailable",
                        "correlationId": inputs["correlationId"],
                        "closureCorrelationId": inputs["closureCorrelationId"],
                        "replayAllowed": False, "nativeActionAllowed": False,
                        "productAction": False}
        if action in {"windows-vm-optical-attempt2-preflight", "windows-vm-optical-attempt2-start",
                      "windows-vm-optical-attempt2-status"}:
            attempt = _agent_module("windows_vm_optical_boot_attempt2")
            optical = _agent_module("windows_vm_optical_boot")
            if (set(inputs) != {"host", "correlationId", "closureCorrelationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or
                    not isinstance(inputs["correlationId"], str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    inputs["correlationId"] in {optical.FIRST_CORRELATION, optical.VM_CORRELATION,
                                                "b76bfd72-2d7b-459a-91da-a063e35c8007"} or
                    inputs.get("closureCorrelationId") != "b76bfd72-2d7b-459a-91da-a063e35c8007" or
                    type(inputs["timeoutSeconds"]) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows optical attempt 2 requires fixed Arch host, new action correlation, exact first-attempt closure and bounded timeoutSeconds.")
            try:
                method = {"windows-vm-optical-attempt2-preflight": attempt.preflight,
                          "windows-vm-optical-attempt2-start": attempt.start,
                          "windows-vm-optical-attempt2-status": attempt.status}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                correlation_id=inputs["correlationId"],
                                closure_correlation_id=inputs["closureCorrelationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == ("ready" if action.endswith("-preflight") else "post-screen-observed"),
                        "evidenceClass": "read-only-windows-optical-attempt2" if not action.endswith("-start") else "native-fixture-optical-attempt2",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-optical-attempt2-outcome-unavailable",
                        "correlationId": inputs["correlationId"],
                        "closureCorrelationId": inputs["closureCorrelationId"],
                        "replayAllowed": False, "nativeActionAllowed": False,
                        "productAction": False}
        if action in {"windows-vm-optical-close-preflight", "windows-vm-optical-close-start",
                      "windows-vm-optical-close-status"}:
            optical = _agent_module("windows_vm_optical_boot")
            if (set(inputs) != {"host", "closureCorrelationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or
                    not isinstance(inputs["closureCorrelationId"], str) or
                    not _valid_uuid(inputs["closureCorrelationId"]) or
                    inputs["closureCorrelationId"] in {optical.FIRST_CORRELATION, optical.VM_CORRELATION} or
                    type(inputs["timeoutSeconds"]) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows optical closure requires fixed Arch host, new canonical closureCorrelationId and bounded timeoutSeconds.")
            try:
                method = {"windows-vm-optical-close-preflight": optical.close_preflight,
                          "windows-vm-optical-close-start": optical.close_start,
                          "windows-vm-optical-close-status": optical.close_status}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                closure_correlation_id=inputs["closureCorrelationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == ("ready" if action.endswith("-preflight") else "pre-effect-closed"),
                        "evidenceClass": "read-only-windows-optical-close" if not action.endswith("-start") else "native-fixture-optical-close",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-optical-close-outcome-unavailable",
                        "closureCorrelationId": inputs["closureCorrelationId"],
                        "replayAllowed": False, "nativeActionAllowed": False,
                        "productAction": False}
        if action in {"windows-vm-optical-boot-preflight", "windows-vm-optical-boot-start",
                      "windows-vm-optical-boot-status"}:
            optical = _agent_module("windows_vm_optical_boot")
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or
                    not isinstance(inputs["correlationId"], str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    inputs["correlationId"] == optical.VM_CORRELATION or
                    type(inputs["timeoutSeconds"]) is not int or
                    not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows optical boot requires fixed Arch host, a new canonical correlationId and bounded timeoutSeconds.")
            try:
                method = {"windows-vm-optical-boot-preflight": optical.preflight,
                          "windows-vm-optical-boot-start": optical.start,
                          "windows-vm-optical-boot-status": optical.status}[action]
                result = method(REPO_ROOT, host=inputs["host"],
                                correlation_id=inputs["correlationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") == ("ready" if action.endswith("-preflight") else "post-screen-observed"),
                        "evidenceClass": "read-only-windows-optical-boot" if not action.endswith("-start") else "native-fixture-optical-boot",
                        "productAction": False, "nativeActionAllowed": False,
                        "replayAllowed": False}
            except (ValueError, OSError, KeyError, TypeError, subprocess.TimeoutExpired):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-optical-boot-outcome-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-fresh-screen-start", "windows-vm-fresh-screen-status"}:
            setup = _agent_module("windows_vm_fresh_setup")
            if (set(inputs) != {"host", "correlationId", "timeoutSeconds"} or
                    inputs["host"] != "archlinux" or not isinstance(inputs["correlationId"], str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    type(inputs["timeoutSeconds"]) is not int or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows screen observation requires fixed host, canonical correlationId and bounded timeoutSeconds.")
            try:
                method = setup.screen_start if action.endswith("-start") else setup.screen_status
                result = method(REPO_ROOT, host=inputs["host"],
                                correlation_id=inputs["correlationId"],
                                timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result, "ok": result.get("state") == "observed",
                        "evidenceClass": "native-fixture-screen", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-screen-outcome-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in {"windows-vm-fresh-start", "windows-vm-fresh-status"}:
            setup = _agent_module("windows_vm_fresh_setup")
            required = {"host", "correlationId", "timeoutSeconds"}
            if (set(inputs) != (required | {"reservationRequest"} if action.endswith("-start") else required) or
                    inputs["host"] != "archlinux" or not isinstance(inputs["correlationId"], str) or
                    not _valid_uuid(inputs["correlationId"]) or
                    type(inputs["timeoutSeconds"]) is not int or not 30 <= inputs["timeoutSeconds"] <= 300):
                return _error("vm_workflow", "Windows fresh setup requires fixed host, canonical correlationId, bounded timeoutSeconds and exact reservation request for start.")
            if action.endswith("-start"):
                reservation = inputs["reservationRequest"]
                fields = {"hostAlias", "environment", "operator", "requestedMemoryBytes",
                          "allocationState", "reservationIdentity", "measurement", "headroomBytes"}
                if (not isinstance(reservation, dict) or
                        set(reservation) not in (fields, fields | {"observations"}) or
                        reservation.get("hostAlias") != "archlinux" or
                        reservation.get("environment") != "windows-vm-baseline-20260929" or
                        reservation.get("operator") != "windows-baseline" or
                        reservation.get("requestedMemoryBytes") != 6442450944 or
                        reservation.get("allocationState") != "pending" or
                        not isinstance(reservation.get("reservationIdentity"), dict) or
                        not isinstance(reservation.get("measurement"), dict) or
                        reservation.get("headroomBytes") != 8589934592 or
                        ("observations" in reservation and not isinstance(reservation["observations"], list))):
                    return _error("vm_workflow", "Windows fresh start requires exact pending Arch reservation evidence.")
            try:
                if action.endswith("-start"):
                    result = setup.start(REPO_ROOT, host=inputs["host"],
                                         correlation_id=inputs["correlationId"],
                                         reservation_request=inputs["reservationRequest"],
                                         timeout_seconds=inputs["timeoutSeconds"])
                else:
                    result = setup.status(REPO_ROOT, host=inputs["host"],
                                          correlation_id=inputs["correlationId"],
                                          timeout_seconds=inputs["timeoutSeconds"])
                return {"tool": "vm_workflow", **result,
                        "ok": result.get("state") in {"running-observed", "stopped-observed"},
                        "evidenceClass": "native-fixture-vm-state", "productAction": False}
            except (ValueError, OSError, KeyError, TypeError):
                return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                        "reason": "windows-fresh-setup-outcome-unavailable",
                        "correlationId": inputs["correlationId"], "replayAllowed": False,
                        "nativeActionAllowed": False, "productAction": False}
        if action in ("artifact-register", "artifact-find", "artifact-verify"):
            registry = _agent_module("native_artifact_registry")
            try:
                if action == "artifact-register":
                    result = registry.register_artifact(REPO_ROOT, inputs)
                elif action == "artifact-find":
                    result = registry.find_artifacts(REPO_ROOT, inputs)
                else:
                    result = registry.verify_artifact(REPO_ROOT, inputs.get("artifactId"), inputs.get("locationId"))
                verified = action != "artifact-verify" or result.get("verification") == "verified"
                return {"tool": "vm_workflow", "ok": verified, **result}
            except (ValueError, OSError) as error:
                return _error("vm_workflow", str(error))
        if action in ("bundle-prepare", "bundle-verify"):
            bundle = _agent_module("native_scenario_bundle")
            try:
                if action == "bundle-prepare":
                    result = bundle.prepare_bundle(REPO_ROOT, inputs.get("scenarioId"), inputs.get("outputDirectory"))
                else:
                    result = bundle.verify_bundle(REPO_ROOT, inputs.get("path"), inputs.get("manifestSha256"))
                return {"tool": "vm_workflow", "ok": True, **result}
            except (ValueError, OSError, TypeError) as error:
                return _error("vm_workflow", str(error))
        if action == "inspect-input":
            result = workflow.inspect_input(inputs.get("input", {}), preflight=inputs.get("preflight"))
        elif action == "admit-plan":
            result = workflow.admit_plan(
                inputs.get("measurement", {}),
                requested_memory_bytes=inputs.get("requestedMemoryBytes"),
                headroom_bytes=inputs.get("headroomBytes"),
                reservations=inputs.get("reservations", []),
            )
        else:
            return _error("vm_workflow", "Unknown VM workflow action.")
        return {"tool": "vm_workflow", **result}
    except (workflow.VmWorkflowError, ValueError, TypeError, OSError) as error:
        return _error("vm_workflow", str(error))



def _native_response(tool: str, action: str, result: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Add compact guidance and redacted durable failure evidence to native tools."""
    if tool == "vm_workflow" and action in {"windows-parallel-vm-copy-start", "windows-parallel-vm-copy-status"}:
        enriched = dict(result)
        correlation = enriched.get("correlationId")
        enriched["replayAllowed"] = False
        enriched["nextAction"] = {"kind": "observe-original-copy" if enriched.get("state") != "prepared" else "inspect-prepared-template",
                                  "replayAllowed": False, "requiresFreshEvidence": True}
        if type(correlation) is str and _valid_uuid(correlation) and enriched.get("state") != "prepared":
            enriched["nextAction"]["action"] = {"tool": "vm_workflow", "action": "windows-parallel-vm-copy-status",
                "inputs": {"host": "archlinux", "correlationId": correlation, "timeoutSeconds": 60}}
        return enriched
    guidance = _agent_module("native_next_action")
    enriched = dict(result)
    host = request.get("host") or request.get("hostAlias")
    if isinstance(host, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", host):
        enriched.setdefault("host", host)
    identity = enriched.get("identity") if isinstance(enriched.get("identity"), dict) else {}
    correlation = enriched.get("correlationId") or identity.get("correlationId") or request.get("correlationId")
    if isinstance(correlation, str) and _valid_uuid(correlation):
        enriched.setdefault("correlationId", correlation)
    if str(enriched.get("state", "")).lower() in {"unknown", "submitting"}:
        enriched["replayAllowed"] = False
        phase = enriched.get("failurePhase")
        failure_type = enriched.get("failureType")
        typed_token = lambda value: isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,63}", value)
        if typed_token(phase) and typed_token(failure_type):
            enriched["uncertainty"] = {"phase": phase, "failureType": failure_type}
    enriched["nextAction"] = guidance.next_action(tool, action, enriched)
    if (tool == "vm_workflow" and action == "environment-status" and
            enriched.get("requestedProbesReady") is True and
            enriched.get("state") == "UNKNOWN"):
        enriched["admissionGap"] = {"missingFact": "required environment receipts outside the requested live probes",
                                    "readOnlyAction": None, "nativeActionAllowed": False}
        return enriched
    if tool == "vm_workflow" and action in {
            "acceptance-status", "arch-ai-loop-observe", "arch-qemu-holder-census", "windows-vm-baseline-inventory", "windows-parallel-vm-source-inventory", "windows-parallel-vm-copy-start", "windows-parallel-vm-copy-status", "windows-vm-secureboot-inventory", "windows-vm-virt-firmware-admission", "windows-vm-secureboot-clone-preflight", "vm-preflight-batch",
            "environment-status", "windows-msi-base-pre-effect-status",
            "linux-guest-park-preflight", "linux-guest-park-status",
            "linux-package-fixture-build-preflight", "linux-package-fixture-build-status",
            "linux-package-fixture-build-pre-effect-status",
            "linux-package-fixture-build-terminal-ready-status",
            "linux-deb-arch-guest-prepare-preflight", "linux-deb-arch-guest-prepare-status",
            "linux-deb-arch-acceptance-preflight", "linux-deb-arch-acceptance-status",
            "build-timing-report", "artifact-cache-check", "android-consent-acceptance-preflight",
            "windows-vm-driver-fetch-status", "windows-vm-disk-probe-status",
            "windows-vm-media-fingerprint", "windows-vm-secureboot-fresh-preflight",
            "windows-vm-secureboot-fresh-status", "windows-vm-fresh-preflight",
            "windows-vm-fresh-status", "windows-vm-fresh-screen-status",
            "windows-vm-optical-attempt2-preflight", "windows-vm-optical-attempt2-status",
            "windows-vm-optical-attempt2-phase-probe",
            "windows-vm-optical-attempt2-close-preflight", "windows-vm-optical-attempt2-close-status",
            "windows-vm-optical-attempt3-preflight", "windows-vm-optical-attempt3-status",
            "windows-vm-optical-attempt3-frame-collect",
            "windows-vm-optical-current-screen-preflight", "windows-vm-optical-current-screen-status",
            "windows-vm-optical-current-screen-collect",
            "windows-vm-optical-close-preflight", "windows-vm-optical-close-status",
            "windows-vm-optical-boot-preflight",
            "windows-vm-optical-boot-status", "android-endpoint-admission-status",
            "android-installer-dispatch-status", "android-installer-dispatch-collect",
            "android-installer-callback-status-handoff-ready",
            "android-installer-callback-status-continue",
            "macos-machine-server-stop-status",
            "macos-machine-server-stop-collect"}:
        if action == "acceptance-status" and enriched.get("ok") is True:
            enriched.update(_agent_module("native_response_diagnostics").acceptance_guidance(enriched))
        if enriched.get("ok") is False or str(enriched.get("state", "")).lower() == "unknown":
            enriched.update(_agent_module("native_response_diagnostics").describe(tool, action, result))
        return enriched
    if enriched.get("ok") is not False and str(enriched.get("state", "")).lower() not in {"unknown", "submitting"}:
        return enriched
    recorder = _agent_module("native_failure_evidence")
    details = recorder.bounded_failure_details(action, enriched) if tool == "vm_workflow" else {}
    enriched.update(details)
    diagnostic = _agent_module("native_response_diagnostics").describe(tool, action, enriched)
    enriched.update(diagnostic)
    if details and isinstance(enriched.get("failureSignature"), dict):
        enriched["failureSignature"]["causalRegression"] = details["regressionReference"]
        enriched["failureSignature"]["regressionRequired"] = False
    if tool == "vm_workflow" and action in {"windows-vm-driver-fetch-start", "windows-vm-disk-probe-start",
                                            "windows-vm-fresh-start"}:
        followup = diagnostic.get("admissionGap", {}).get("readOnlyAction")
        if isinstance(followup, dict):
            enriched["nextAction"] = {"kind": "observe-existing-driver-fetch" if action == "windows-vm-driver-fetch-start" else
                                              "observe-existing-windows-vm" if action == "windows-vm-fresh-start" else
                                              "observe-existing-disk-probe",
                                      "reason": "one-shot native fixture outcome needs exact status",
                                      "action": followup, "replayAllowed": False,
                                      "requiresFreshEvidence": True}
    context: dict[str, Any] = {"tool": tool, "action": action}
    safe_token = lambda value: isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value)
    environment = enriched.get("environment") or request.get("environment") or host
    if safe_token(environment):
        context["environmentAlias"] = environment
    if safe_token(correlation):
        context["operationCorrelation"] = correlation
    artifacts = enriched.get("artifactIds") or request.get("artifactIds")
    if isinstance(artifacts, dict) and 0 < len(artifacts) <= 16 and all(safe_token(value) for value in artifacts.values()):
        context["artifactIds"] = list(artifacts.values())
    state = str(enriched.get("state", enriched.get("status", "failure")))
    uncertain = state.lower() in {"unknown", "submitting", "pending", "closing", "close_pending", "owner_unknown", "remote_forward_pending", "local_forward_pending", "recovery_intent_pending"}
    if tool == "vm_workflow" and action in {"windows-vm-driver-fetch-start", "windows-vm-disk-probe-start",
                                            "windows-vm-fresh-start"} and state.lower() in {"partial", "linked-partial", "mismatch", "running-unrecorded-observed"}:
        uncertain = True
    category = enriched.get("reason") or enriched.get("verification") or state
    if not safe_token(category):
        category = "workflow_failure"
    receipt: dict[str, Any] = {"classification": "nativeUNKNOWN" if uncertain else "terminalFailure", "errorCategory": category}
    receipt.update(details)
    if safe_token(state):
        receipt["after"] = {"state": state}
    paths = enriched.get("evidencePaths")
    if isinstance(paths, list) and all(isinstance(path, str) and path.startswith("/") for path in paths):
        receipt["evidencePaths"] = paths[:16]
    try:
        # This fingerprint covers the tool implementation, including uncommitted
        # modules; it does not assert the product package was built from HEAD.
        digest = hashlib.sha256()
        for path in sorted((REPO_ROOT / "agent_tools").glob("*.py")):
            digest.update(path.name.encode()); digest.update(path.read_bytes())
        context["sourceFingerprint"] = digest.hexdigest()
        saved = recorder.record_failure(REPO_ROOT, context, receipt)
        enriched["failureEvidence"] = saved if isinstance(saved, dict) else {"state": "unavailable"}
        evidence_id = enriched["failureEvidence"].get("evidenceId")
        signature = enriched.get("failureSignature")
        if isinstance(evidence_id, str) and safe_token(evidence_id) and isinstance(signature, dict):
            signature["sourceReceiptId"] = evidence_id
    except (ValueError, OSError):
        # Evidence storage must not replace or reclassify the original outcome.
        enriched["failureEvidence"] = {"state": "unavailable"}
    return enriched


def ssh_workflow(action: str = "inventory", host: str | None = None, timeout_seconds: int = 15, identity: dict[str, Any] | None = None, transfer: dict[str, Any] | None = None, device: str | None = None) -> dict[str, Any]:
    """Observe or perform fixed configured SSH fixture actions with durable evidence and safe next steps."""
    result = _ssh_workflow_impl(action, host, timeout_seconds, identity, transfer, device)
    return _native_response("ssh_workflow", action, result, {"host": host, **(transfer or {})})


def vm_workflow(action: str, inputs: dict[str, Any]) -> dict[str, Any]:
    """Manage verified artifacts, reservations, bundles and fixed resumable preflight scenarios."""
    if action in {"source-review-close", "baseline-source-inventory"}:
        # Metadata/source reads must not write native failure evidence on refusal.
        return _vm_workflow_impl(action, inputs)
    if action in {"windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status",
                  "windows-vm-disk-probe-start", "windows-vm-disk-probe-status",
                  "windows-vm-fresh-start", "windows-vm-fresh-status",
                  "windows-vm-optical-boot-start", "windows-vm-optical-close-start",
                  "windows-vm-optical-attempt2-start",
                  "windows-vm-optical-attempt2-close-start", "windows-vm-optical-attempt3-start",
                  "windows-vm-optical-current-screen-start",
                  "linux-package-fixture-build-start", "linux-package-fixture-build-collect",
                  "linux-guest-park-start", "macos-machine-server-stop-start",
                  "android-endpoint-admission-start",
                  "android-endpoint-admission-cleanup", "android-installer-dispatch-start",
                  "android-installer-callback-handoff-ready", "android-installer-callback-continue",
                  "android-installer-abort-prelaunch", "android-installer-reconcile"}:
        try:
            return _native_response("vm_workflow", action, _vm_workflow_impl(action, inputs),
                                    inputs if isinstance(inputs, dict) else {})
        except Exception:
            # A local intent may have been written before any transport or
            # response-handling exception. Never expose a traceback, lose its
            # correlation, or suggest replaying the one-shot download.
            is_optical_close = action in {"windows-vm-optical-close-start",
                                          "windows-vm-optical-attempt2-close-start"}
            is_optical_current = action == "windows-vm-optical-current-screen-start"
            correlation = inputs.get("closureCorrelationId" if is_optical_close else
                                     "observationCorrelationId" if is_optical_current else
                                     "correlationId") if isinstance(inputs, dict) else None
            valid = isinstance(correlation, str) and _valid_uuid(correlation)
            status_action = ("windows-vm-optical-attempt2-close-status" if action == "windows-vm-optical-attempt2-close-start"
                             else "windows-vm-optical-current-screen-status" if is_optical_current
                             else "windows-vm-optical-attempt3-status" if action == "windows-vm-optical-attempt3-start"
                             else "windows-vm-optical-attempt2-status" if action == "windows-vm-optical-attempt2-start"
                             else "windows-vm-optical-close-status" if is_optical_close
                             else "android-endpoint-admission-status" if action.startswith("android-endpoint-admission")
                             else "android-installer-callback-status-handoff-ready" if action == "android-installer-callback-handoff-ready"
                             else "android-installer-callback-status-continue" if action == "android-installer-callback-continue"
                             else "android-installer-dispatch-status" if action.startswith("android-installer-")
                             else "windows-vm-optical-boot-status" if action == "windows-vm-optical-boot-start"
                             else "linux-guest-park-status" if action == "linux-guest-park-start"
                             else "macos-machine-server-stop-status" if action == "macos-machine-server-stop-start"
                             else "linux-package-fixture-build-status" if action.startswith("linux-package-fixture-build")
                             else "windows-vm-driver-fetch-status" if action.startswith("windows-vm-driver-fetch")
                             else "windows-vm-disk-probe-status" if action.startswith("windows-vm-disk-probe")
                             else "windows-vm-fresh-status")
            is_driver = action.startswith("windows-vm-driver-fetch")
            is_fresh = action.startswith("windows-vm-fresh")
            is_optical = action == "windows-vm-optical-boot-start"
            is_optical_attempt2 = action == "windows-vm-optical-attempt2-start"
            is_optical_attempt3 = action == "windows-vm-optical-attempt3-start"
            is_linux_build = action.startswith("linux-package-fixture-build")
            is_guest_park = action == "linux-guest-park-start"
            is_mac_stop = action == "macos-machine-server-stop-start"
            is_android_endpoint = action.startswith("android-endpoint-admission")
            is_android_installer = action.startswith("android-installer-")
            status_inputs = ({"correlationId": correlation} if is_linux_build or is_guest_park or is_mac_stop or is_android_endpoint or is_android_installer else
                             {"host": "archlinux", "observationCorrelationId": correlation,
                              "timeoutSeconds": 120} if is_optical_current else
                             {"host": "archlinux", "closureCorrelationId": correlation,
                              "timeoutSeconds": 120} if is_optical_close else
                             {"host": "archlinux", "correlationId": correlation,
                              "timeoutSeconds": 120}) if valid else None
            if (is_optical_attempt2 or is_optical_attempt3) and status_inputs is not None:
                closure = inputs.get("closureCorrelationId")
                valid_closure = (closure == "b76bfd72-2d7b-459a-91da-a063e35c8007" if is_optical_attempt2 else
                                 isinstance(closure, str) and _valid_uuid(closure) and closure != correlation and
                                 closure not in {"ca76aff1-b67b-47cf-9e82-e61b1fe76ebb",
                                                 "b76bfd72-2d7b-459a-91da-a063e35c8007",
                                                 "98b4f1e0-968c-455b-a85b-d87490f5b256",
                                                 "3d03016b-1848-4626-a7e6-4e2ef44b904f"})
                if valid_closure:
                    status_inputs["closureCorrelationId"] = inputs["closureCorrelationId"]
                else:
                    status_inputs = None
            status_read = ({"tool": "vm_workflow", "action": status_action,
                            "inputs": status_inputs} if status_inputs is not None else None)
            return {"tool": "vm_workflow", "ok": False, "state": "unknown",
                    "reason": "driver-fetch-boundary-unknown" if is_driver else
                              "windows-optical-boot-boundary-unknown" if is_optical else
                              "windows-optical-attempt2-boundary-unknown" if is_optical_attempt2 else
                              "windows-optical-attempt3-boundary-unknown" if is_optical_attempt3 else
                              "windows-optical-current-screen-boundary-unknown" if is_optical_current else
                              "windows-optical-close-boundary-unknown" if is_optical_close else
                              "linux-package-fixture-build-boundary-unknown" if is_linux_build else
                              "linux-guest-park-boundary-unknown" if is_guest_park else
                              "mac-server-stop-boundary-unknown" if is_mac_stop else
                              "android-endpoint-boundary-unknown" if is_android_endpoint else
                              "android-installer-boundary-unknown" if is_android_installer else
                              "windows-fresh-setup-boundary-unknown" if is_fresh else
                              "windows-disk-probe-boundary-unknown",
                    **({"closureCorrelationId" if is_optical_close else
                        "observationCorrelationId" if is_optical_current else
                        "correlationId": correlation} if valid else {}),
                    "replayAllowed": False, "nativeActionAllowed": False,
                    "productAction": False,
                    "nextAction": {"kind": ("observe-existing-driver-fetch" if is_driver else
                                            "observe-existing-optical-boot" if is_optical else
                                            "observe-existing-optical-attempt2" if is_optical_attempt2 else
                                            "observe-existing-optical-attempt3" if is_optical_attempt3 else
                                            "observe-existing-optical-current-screen" if is_optical_current else
                                            "observe-existing-optical-close" if is_optical_close else
                                            "observe-existing-linux-build" if is_linux_build else
                                            "observe-existing-guest-park" if is_guest_park else
                                            "observe-existing-mac-server-stop" if is_mac_stop else
                                            "observe-existing-android-endpoint" if is_android_endpoint else
                                            "observe-existing-android-installer" if is_android_installer else
                                            "observe-existing-windows-vm" if is_fresh else
                                            "observe-existing-disk-probe") if valid else "inspect-evidence",
                                   "reason": "one-shot native fixture outcome is uncertain",
                                   "replayAllowed": False, "requiresFreshEvidence": True,
                                   **({"action": status_read} if status_read else {})}}
    return _native_response("vm_workflow", action, _vm_workflow_impl(action, inputs), inputs if isinstance(inputs, dict) else {})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vpn-control-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("serve")
    ssh_parser = subparsers.add_parser("ssh-workflow")
    ssh_parser.add_argument("action", choices=("connection-channel-prepare", "connection-channel-status", "connection-channel-ensure", "connection-master-status", "gateway-tmux-status-diagnostic", "tmux-disconnect-probe", "gateway-tmux-reconciliation-status", "gateway-tmux-availability", "gateway-tmux-prepare", "gateway-tmux-release", "gateway-tmux-status", "inventory", "probe", "job-status", "fixture-publish", "fixture-status", "android-observe", "connection-recover", "connection-adopt", "connection-session-prepare", "connection-session-status", "connection-session-retire", "connection-session-retirement-status", "connection-session-close", "connection-session-close-status", "connection-nested-orphan-archive", "connection-nested-orphan-archive-status", "android-availability", "apk-publish", "apk-status", "forward-open", "forward-status", "forward-close"))
    ssh_parser.add_argument("--host")
    ssh_parser.add_argument("--device")
    ssh_parser.add_argument("--timeout-seconds", type=int, default=15)
    ssh_parser.add_argument("--identity-file")
    ssh_parser.add_argument("--transfer-file")
    vm_parser = subparsers.add_parser("vm-workflow")
    vm_parser.add_argument("action", choices=("fixture-preflight", "batch-plan", "batch-start", "batch-status", "batch-resume", "batch-collect", "baseline-capture", "baseline-verify", "baseline-restore", "baseline-preflight", "baseline-source-inventory", "matrix-record", "matrix-retract", "matrix-status", "matrix-equivalence-record", "acceptance-status", "vm-preflight-batch", "build-timing-report", "artifact-set-freeze", "artifact-set-verify", "artifact-reuse-check", "artifact-cache-check", "inspect-input", "admit-plan", "artifact-register", "artifact-find", "artifact-verify", "bundle-prepare", "bundle-verify", "environment-status", "environment-reserve", "environment-release", "linux-guest-park-preflight", "linux-guest-park-start", "linux-guest-park-status", "linux-package-fixture-build-preflight", "linux-package-fixture-build-start", "linux-package-fixture-build-status", "linux-package-fixture-build-collect", "linux-package-fixture-build-pre-effect-status", "linux-package-fixture-build-pre-effect-close", "linux-package-fixture-build-terminal-ready-status", "linux-package-fixture-build-terminal-ready-close", "android-api35-large-routing-observe", "android-coldboot-product-api29-observe", "linux-package-tmux-resource-prepare", "linux-package-tmux-availability", "linux-package-tmux-preflight", "linux-package-tmux-start", "linux-package-tmux-status", "linux-package-tmux-collect", "arch-tmux-install-preflight", "arch-tmux-install-start", "arch-tmux-install-status", "linux-deb-arch-guest-prepare-preflight", "linux-deb-arch-guest-prepare-start", "linux-deb-arch-guest-prepare-status", "linux-deb-arch-acceptance-preflight", "linux-deb-arch-acceptance-start", "linux-deb-arch-acceptance-status", "linux-vm-readonly-inventory", "arch-qemu-holder-census", "windows-vm-baseline-inventory", "windows-parallel-vm-source-inventory", "windows-parallel-vm-copy-start", "windows-parallel-vm-copy-status", "windows-vm-secureboot-inventory", "windows-vm-virt-firmware-admission", "windows-vm-secureboot-clone-preflight", "windows-vm-secureboot-fresh-preflight", "windows-vm-secureboot-fresh-start", "windows-vm-secureboot-fresh-status", "windows-vm-media-fingerprint", "windows-vm-driver-fetch-start", "windows-vm-driver-fetch-status", "windows-vm-disk-probe-start", "windows-vm-disk-probe-status", "windows-vm-fresh-preflight", "windows-vm-fresh-start", "windows-vm-fresh-status", "windows-vm-fresh-screen-start", "windows-vm-fresh-screen-status", "windows-vm-optical-boot-preflight", "windows-vm-optical-boot-start", "windows-vm-optical-boot-status", "windows-vm-optical-close-preflight", "windows-vm-optical-close-start", "windows-vm-optical-close-status", "windows-vm-optical-attempt2-preflight", "windows-vm-optical-attempt2-start", "windows-vm-optical-attempt2-status", "windows-vm-optical-attempt2-phase-probe", "windows-vm-optical-attempt2-close-preflight", "windows-vm-optical-attempt2-close-start", "windows-vm-optical-attempt2-close-status", "windows-vm-optical-attempt3-preflight", "windows-vm-optical-attempt3-start", "windows-vm-optical-attempt3-status", "windows-vm-optical-attempt3-frame-collect", "windows-vm-optical-current-screen-preflight", "windows-vm-optical-current-screen-start", "windows-vm-optical-current-screen-status", "windows-vm-optical-current-screen-collect", "windows-vm-setup-language-next-preflight", "windows-vm-setup-language-next-start", "windows-vm-setup-language-next-status", "windows-vm-setup-language-next-collect", "windows-vm-setup-keyboard-next-preflight", "windows-vm-setup-keyboard-next-start", "windows-vm-setup-keyboard-next-status", "windows-vm-setup-keyboard-next-collect", "windows-vm-setup-install-disk-proof", "windows-vm-setup-install-focus-preflight", "windows-vm-setup-install-focus-start", "windows-vm-setup-install-focus-status", "windows-vm-setup-install-focus-collect", "windows-vm-setup-install-ack-preflight", "windows-vm-setup-install-ack-start", "windows-vm-setup-install-ack-status", "windows-vm-setup-install-ack-collect", "windows-vm-setup-install-next-preflight", "windows-vm-setup-install-next-start", "windows-vm-setup-install-next-status", "windows-vm-setup-install-next-collect", "scenario-start", "scenario-status", "scenario-resume", "scenario-collect", "rpm-public-install-start", "rpm-public-install-status", "rpm-public-install-collect", "linux-rpm-fixture-dispatch", "linux-rpm-fixture-status", "linux-rpm-fixture-server-start", "linux-rpm-fixture-server-status", "linux-rpm-fixture-server-collect", "linux-rpm-fixture-server-stop", "linux-rpm-workspace-recovery-status", "linux-rpm-workspace-cleanup-start", "linux-rpm-workspace-cleanup-status", "linux-owner-public-quit-start", "linux-owner-public-quit-status", "linux-owner-public-quit-collect", "linux-rpm-protected-job-observe", "windows-msi-fixture-dispatch", "windows-msi-fixture-status", "windows-msi-fixture-collect", "windows-msi-fixture-failed-log", "windows-fixture-python-preflight", "windows-fixture-stage-start", "windows-fixture-stage-status", "windows-fixture-stage-collect", "windows-fixture-credentials-start", "windows-fixture-credentials-status", "windows-fixture-credentials-collect", "windows-fixture-server-start", "windows-fixture-server-acl-preflight", "windows-fixture-server-status", "windows-fixture-server-collect", "windows-fixture-server-stop-start", "windows-fixture-server-stop-status", "windows-fixture-server-stop-collect", "windows-fixture-credentials-cleanup-start", "windows-fixture-credentials-cleanup-status", "windows-fixture-credentials-cleanup-collect", "windows-fixture-server-abort-start", "windows-fixture-server-abort-status", "windows-fixture-server-abort-collect", "windows-fixture-server-abort-successor-start", "windows-fixture-server-abort-successor-status", "windows-fixture-server-abort-successor-diagnostic", "windows-fixture-server-resume-no-dispatch-start", "windows-fixture-server-post-resource-diagnostic", "windows-fixture-server-probe-events-acl-diagnostic", "windows-fixture-acl-preflight", "windows-fixture-acl-preflight-status", "windows-fixture-credentials-abort-start", "windows-fixture-credentials-abort-status", "windows-fixture-credentials-abort-collect", "windows-fixture-owner-network-start", "windows-fixture-owner-network-status", "windows-fixture-owner-network-collect", "windows-fixture-network-probe-start", "windows-fixture-network-probe-status", "windows-fixture-network-probe-collect", "linux-rpm-base-prepare-preflight", "linux-rpm-base-prepare-start", "linux-rpm-base-prepare-status", "linux-rpm-owner-observe", "rpm-proc-observe", "rpm-proc-observe-privileged", "android-admission-readback", "android-admission-status", "android-admission-preflight", "android-readback-start", "android-readback-status", "android-readback-collect", "android-package-install-start", "android-package-install-status", "android-package-install-collect", "android-package-install-reconcile", "android-package-install-unknown-proof", "android-package-install-unknown-release", "android-cli-stage-start", "android-cli-stage-status", "android-cli-stage-collect", "android-document-acceptance-start", "android-document-acceptance-status", "android-document-acceptance-collect", "android-document-retry-start", "android-document-retry-status", "android-document-retry-collect", "android-document-retry-recovery-start", "android-document-retry-recovery-status", "android-document-retry-recovery-collect", "android-document-retry-recovery-finalize", "android-document-retry-unknown-diagnose", "android-document-retry-unknown-close", "android-obsolete-consent-denial-collect", "android-consent-grant-prompt-collect", "android-consent-grant-acceptance-start", "android-consent-grant-acceptance-diagnose", "android-consent-grant-acceptance-reconcile", "android-consent-grant-acceptance-reconcile-status", "android-consent-grant-acceptance-reconcile-diagnose", "android-consent-grant-acceptance-status", "android-consent-grant-acceptance-collect", "android-vpn-permission-reset-start", "android-vpn-permission-reset-status", "android-vpn-permission-reset-collect", "android-runtime-acceptance-start", "android-runtime-acceptance-status", "android-runtime-acceptance-collect", "android-action-acceptance-start", "android-action-acceptance-status", "android-action-acceptance-collect", "android-api35-remaining-proxy-status", "android-fixture-tls-mint", "android-native-fixture-start", "android-native-fixture-status", "android-native-fixture-stop", "android-native-fixture-collect", "android-endpoint-admission-start", "android-endpoint-admission-status", "android-endpoint-admission-cleanup", "android-endpoint-mount-diagnostic-collect", "android-endpoint-cleanup-readmission", "android-endpoint-cleanup-readmission-status", "android-endpoint-cleanup-readmitted-status", "android-recovered-endpoint-stage-collect", "android-endpoint-cleanup-mount-diagnostic", "android-endpoint-cleanup-readmitted", "android-installer-dispatch-start", "android-installer-dispatch-status", "android-installer-dispatch-collect", "android-installer-callback-handoff-ready", "android-installer-callback-continue", "android-installer-callback-status-handoff-ready", "android-installer-callback-status-continue", "android-installer-abort-prelaunch", "android-installer-reconcile", "android-consent-acceptance-preflight", "android-consent-acceptance-start", "android-consent-acceptance-status", "android-consent-acceptance-collect", "android-document-recovery-start", "android-document-recovery-status", "android-document-recovery-collect", "android-document-recovery-finalize", "android-public-inspect", "windows-msi-preinstall-status", "windows-msi-powershell-preflight", "windows-msi-base-preflight", "windows-msi-base-readiness", "windows-msi-base-start", "windows-msi-base-status", "windows-msi-base-pre-effect-status", "windows-msi-base-pre-effect-close", "windows-msi-owner-observe-preflight", "windows-msi-owner-observe-start", "windows-msi-owner-observe-status", "windows-msi-owner-observe-collect", "windows-msi-owner-quit-preflight", "windows-msi-owner-quit-start", "windows-msi-owner-quit-status", "windows-msi-owner-quit-collect", "windows-msi-target-preflight", "windows-msi-target-readiness", "windows-msi-target-start", "windows-msi-target-status", "windows-msi-public-start", "windows-msi-public-status", "windows-msi-public-collect", "windows-credential-probe-start", "windows-credential-probe-status", "windows-credential-recover-start", "windows-credential-recover-status", "credential-status", "android-proxy-recover", "android-proxy-recovery-status", "macos-installer-recovery-status", "macos-machine-server-stop-start", "macos-machine-server-stop-status", "macos-machine-server-stop-collect", "macos-fixture-guest-stage-start", "macos-fixture-guest-stage-status", "macos-fixture-guest-stage-collect"))
    vm_parser._actions[-1].choices = (*vm_parser._actions[-1].choices,
                                      "source-review-close",
                                      "windows-vm-virt-firmware-install-preflight",
                                      "windows-vm-virt-firmware-install-start",
                                      "windows-vm-virt-firmware-install-status",
                                      "windows-vm-swtpm-repair-preflight",
                                      "windows-vm-swtpm-repair-start",
                                      "windows-vm-swtpm-repair-status",
                                      "windows-vm-swtpm-owner-observe",
                                      "arch-ai-loop-observe",
                                      "windows-msi-base-reconcile",
                                      "windows-fixture-python-inventory-diagnostic",
                                      "windows-fixture-python-download-preflight",
                                      "windows-fixture-python-host-source-observe",
                                      "windows-fixture-python-acquire-start",
                                      "windows-fixture-python-acquire-status",
                                      "windows-fixture-python-acquire-collect",
                                      "windows-fixture-python-acquire-reconcile",
                                      "windows-fixture-python-acquire-failure-detail",
                                      "windows-fixture-python-install-start",
                                      "windows-fixture-python-install-status",
                                      "windows-fixture-python-install-collect",
                                      "windows-fixture-python-install-diagnostic",
                                      "windows-fixture-server-diagnostic",
                                      "windows-fixture-server-static-diagnostic",
                                      "windows-fixture-server-abort-diagnostic",
                                      "windows-fixture-server-second-abort-successor-start",
                                      "windows-fixture-server-second-abort-successor-status",
                                      "windows-fixture-server-second-abort-successor-diagnostic",
                                      "windows-fixture-server-second-abort-recovery-diagnose",
                                      "windows-fixture-server-second-abort-recovery-start",
                                      "windows-fixture-server-second-abort-recovery-status",
                                      "windows-fixture-package-mode-repair-start",
                                      "windows-fixture-package-mode-repair-status",
                                      "windows-fixture-package-mode-repair-collect",
                                      "windows-fixture-package-mode-repair-diagnostic",
                                      "windows-msi-base-terminal-reconcile",
                                      "windows-msi-base-finish-observed",
                                      "windows-msi-base-diagnostic", "windows-msi-base-stage-diagnostic",
                                      "windows-msi-base-transfer-preflight",
                                      "windows-msi-base-transfer-network-admission",
                                      "windows-msi-base-transfer-endpoint-probe",
                                      "windows-msi-base-transfer-endpoint-status",
                                      "windows-msi-base-transfer-endpoint-reconcile",
                                      "windows-msi-http-transfer",
                                      "windows-update-fixture-http-transfer",
                                      "windows-msiexec-service-diagnostic",
                                      "windows-msi-owner-census-preflight",
                                      "windows-msi-owner-census",
                                      "windows-msi-owner-diagnostic",
                                      "windows-msi-owner-liveness",
                                      "windows-msi-stale-lock-recover",
                                      "windows-msi-stale-lock-diagnose",
                                      "windows-msi-stale-lock-reconciliation-status",
                                      "windows-msi-owner-relaunch-launch",
                                      "windows-msi-owner-relaunch-status",
                                      "windows-msi-owner-relaunch-collect",
                                      "windows-msi-owner-relaunch-diagnose",
                                      "windows-msi-owner-relaunch-detail",
                                      "windows-msi-owner-relaunch-endpoint-access",
                                      "windows-msi-owner-public-status-start",
                                      "windows-msi-owner-public-status-status",
                                      "windows-msi-owner-public-status-collect",
                                      "windows-msi-owner-public-status-diagnose",
                                      "windows-msi-owner-public-status-retry-preflight",
                                      "windows-msi-owner-public-status-retry-start",
                                      "windows-msi-owner-public-status-retry-status",
                                      "windows-msi-owner-public-status-retry-collect",
                                      "windows-msi-owner-public-status-retry-diagnose",
                                      "windows-msi-owner-public-status-retry-observe",
                                      "windows-msi-owner-public-status-third-start",
                                      "windows-msi-owner-public-status-third-status",
                                      "windows-msi-owner-public-status-third-collect",
                                      "windows-msi-owner-public-status-third-observe",
                                      "windows-msi-owner-relaunch-quit-start",
                                      "windows-msi-owner-relaunch-quit-status",
                                      "windows-msi-owner-relaunch-quit-collect",
                                      "windows-msi-owner-relaunch-quit-diagnose",
                                      "windows-msi-owner-relaunch-quit-v2-start",
                                      "windows-msi-owner-relaunch-quit-v2-status",
                                      "windows-msi-owner-relaunch-quit-v2-collect",
                                      "windows-msi-owner-relaunch-quit-v2-diagnose",
                                      "windows-msi-owner-relaunch-quit-v2-bootstrap-diagnostic",
                                      "windows-msi-owner-relaunch-quit-v3-start",
                                      "windows-msi-owner-relaunch-quit-v3-status",
                                      "windows-msi-owner-relaunch-quit-v3-collect",
                                      "windows-msi-owner-relaunch-quit-v3-diagnose",
                                      "windows-msi-owner-relaunch-quit-v3-bootstrap-diagnostic",
                                      "windows-msi-owner-relaunch-quit-v3-task-result",
                                      "windows-msi-owner-quit-phase-start",
                                      "windows-msi-owner-quit-phase-status",
                                      "windows-msi-owner-quit-phase-collect",
                                      "windows-msi-owner-relaunch-quit-v4-start",
                                      "windows-msi-owner-relaunch-quit-v4-status",
                                      "windows-msi-owner-relaunch-quit-v4-collect",
                                      "windows-msi-owner-relaunch-quit-v4-diagnose",
                                      "windows-msi-stale-lock-reconcile",
                                      "windows-msi-stale-lock-reconcile-status",
                                      "windows-msi-stale-lock-reconcile-close",
                                      "windows-fixture-stage-diagnostic",
                                      "windows-fixture-stage-recover-7f27",
                                      "windows-fixture-stage-recover-7f27-diagnostic",
                                      "windows-cp117-campaign-rebase",
                                      "windows-cp117-e66-successor-start",
                                      "windows-cp117-e66-successor-status",
                                      "windows-cp117-e66-successor-reconcile",
                                      "windows-cp117-e66-successor-resume-begin",
                                      "windows-cp117-guest-abort-successor-start",
                                      "windows-cp117-guest-abort-successor-status",
                                      "windows-cp117-guest-abort-successor-reconcile",
                                      "windows-cp117-guest-abort-successor-resume-begin",
                                      "windows-cp117-download-abort-successor-start",
                                      "windows-cp117-download-abort-successor-status",
                                      "windows-cp117-download-abort-successor-reconcile",
                                      "windows-cp117-download-abort-successor-resume-close",
                                      "windows-cp117-download-abort-successor-resume-begin",
                                      "windows-cp117-download-abort-current-successor-start",
                                      "windows-cp117-download-abort-current-successor-status",
                                      "windows-cp117-download-abort-current-successor-reconcile",
                                      "windows-cp117-download-abort-current-successor-resume-close",
                                      "windows-cp117-download-abort-current-successor-resume-begin",
                                      "windows-update-fixture-guest-create-abort-status",
                                      "windows-update-fixture-guest-create-abort",
                                      "windows-update-fixture-download-abort-status",
                                      "windows-update-fixture-download-abort",
                                      "windows-update-fixture-download-task-cleanup-status",
                                      "windows-update-fixture-download-task-cleanup",
                                      "windows-update-fixture-download-abort-current-task-cleanup-status",
                                      "windows-update-fixture-download-abort-current-task-cleanup",
                                      "windows-update-fixture-download-abort-current-status",
                                      "windows-update-fixture-download-abort-current",
                                      "windows-cp117-retirement-recovery-preflight",
                                      "windows-cp117-retirement-recovery-parser",
                                      "windows-cp117-retirement-recovery-start",
                                      "windows-cp117-retirement-recovery-status",
                                      "windows-cp117-retirement-recovery-finish",
                                      "windows-cp117-guest-agent-recovery-successor-preflight",
                                      "windows-cp117-guest-agent-recovery-successor-parser",
                                      "windows-cp117-guest-agent-recovery-successor-start",
                                      "windows-cp117-guest-agent-recovery-successor-status",
                                      "windows-cp117-guest-agent-recovery-preflight",
                                      "windows-cp117-guest-agent-recovery-parser",
                                      "windows-cp117-guest-agent-recovery-start",
                                      "windows-cp117-guest-agent-recovery-status",
                                      "windows-cp117-guest-agent-recovery-diagnose",
                                      "windows-cp117-guest-agent-recovery-journal",
                                      "windows-cp117-c32-retained-parser",
                                      "windows-cp117-c32-archive-diagnose",
                                      "windows-cp117-c32-archive-preflight",
                                      "windows-cp117-c32-host-archive-self-test",
                                      "windows-cp117-c32-host-archive-start",
                                      "windows-cp117-c32-host-archive-status",
                                      "windows-cp117-historical-base-archives",
                                      "windows-cp117-source-campaign-reservation-diagnose",
                                      "windows-cp117-source-campaign-preflight",
                                      "windows-cp117-cp95-retained-tasks",
                                      "windows-cp117-cp95-task-retire-preflight",
                                      "windows-cp117-cp95-task-retire-start",
                                      "windows-cp117-cp95-task-retire-status", "windows-cp117-cp95-task-retire-finish", "windows-cp117-cp95-task-retire-tail-start", "windows-cp117-cp95-task-retire-tail-status", "windows-cp117-cp95-task-retire-tail-diagnose", "windows-cp117-cp95-task-retire-tail-close-pre-effect", "windows-cp117-cp95-task-retire-successor-start", "windows-cp117-cp95-task-retire-successor-status", "windows-cp117-cp95-task-retire-successor-admission-diagnose",
                                      "windows-cp117-cp95-task-retire-diagnose", "windows-cp117-cp95-task-retire-finish-diagnose",
                                      "windows-cp117-e848-http-task-retire-preflight",
                                      "windows-cp117-e848-http-task-retire-start",
                                      "windows-cp117-e848-http-task-retire-status",
                                      "windows-cp117-source-pre-effect-status",
                                      "windows-cp117-source-pre-effect-close",
                                      "windows-cp117-source-pre-effect-diagnose",
                                      "windows-cp117-c32-retained-task-retire-preflight",
                                      "windows-cp117-c32-retained-task-retire-start",
                                      "windows-cp117-c32-retained-task-retire-status",
                                      "windows-cp117-e848-http-task",
                                      "windows-cp117-source-campaign-start",
                                      "windows-cp117-source-campaign-status",
                                      "windows-cp117-source-campaign-diagnose",
                                      "windows-cp117-source-campaign-terminal-reconcile",
                                      "windows-cp117-source-campaign-finish",
                                      "windows-cp117-source-campaign-parser",
                                      "windows-cp117-campaign-status",
                                      "windows-cp117-staged-fixture-retire-preflight",
                                      "windows-cp117-staged-fixture-retire-start",
                                      "windows-cp117-staged-fixture-retire-status",
                                      "windows-cp117-staged-fixture-retire-diagnose",
                                      "windows-cp117-staged-fixture-retire-parser",
                                      "windows-cp117-staged-fixture-retire-guard-diagnostic",
                                      "windows-cp117-staged-fixture-retire-boundary",
                                      "windows-cp117-staged-fixture-retire-tree",
                                      "windows-cp117-staged-fixture-retire-locks",
                                      "windows-cp117-campaign-diagnostic",
                                      "windows-update-fixture-phase-status",
                                      "windows-update-fixture-http-stage-extract-diagnostic",
                                      "windows-fixture-credentials-diagnostic",
                                      "windows-fixture-credentials-failure-detail",
                                      "windows-fixture-credentials-provenance-acl-shape",
                                      "windows-fixture-credentials-pre-effect-guard-probe",
                                      "windows-msi-base-start-from-transfer",
                                      "windows-msi-base-unknown-close",
                                      "windows-msi-base-unknown-close-status")
    vm_parser.add_argument("--inputs-file", required=True)
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
    bump.add_argument("--target-version")
    release = subparsers.add_parser("release-workflow")
    release.add_argument("action", choices=("status", "merge-dev", "publish"), default="status")
    visual_flow = subparsers.add_parser("visual-workflow")
    visual_flow.add_argument("action", choices=("start", "status", "complete"))
    visual_flow.add_argument("--target-sha")
    visual_flow.add_argument("--platform", action="append", dest="platforms")
    visual_flow.add_argument("--release", action="store_true")
    visual_flow.add_argument("--post-status", action="store_true")
    visual_verdict = subparsers.add_parser("visual-review")
    visual_verdict.add_argument("target_sha")
    visual_verdict.add_argument("platform")
    visual_verdict.add_argument("scene_id")
    visual_verdict.add_argument("verdict")
    visual_verdict.add_argument("--notes")
    git_parser = subparsers.add_parser("git-workflow")
    git_parser.add_argument("action", choices=("commit", "checkpoint", "push", "checks"))
    git_parser.add_argument("--message")
    git_parser.add_argument("--path", action="append", dest="paths")
    git_parser.add_argument("--sha")
    args = parser.parse_args(argv)

    if args.command == "ssh-workflow":
        identity = None
        transfer = None
        if args.identity_file:
            try:
                identity = json.loads(Path(args.identity_file).read_text(encoding="utf-8"))
                if not isinstance(identity, dict):
                    raise ValueError("identity must be an object")
            except (OSError, ValueError):
                return _json_print(_error("ssh_workflow", "Invalid identity JSON file."))
        if args.transfer_file:
            try:
                transfer = json.loads(Path(args.transfer_file).read_text(encoding="utf-8"))
                if not isinstance(transfer, dict):
                    raise ValueError("transfer must be an object")
            except (OSError, ValueError):
                return _json_print(_error("ssh_workflow", "Invalid transfer JSON file."))
        return _json_print(ssh_workflow(args.action, args.host, args.timeout_seconds, identity, transfer, args.device))
    if args.command == "vm-workflow":
        try:
            inputs = json.loads(Path(args.inputs_file).read_text(encoding="utf-8"))
            if not isinstance(inputs, dict):
                raise ValueError("inputs must be an object")
        except (OSError, ValueError):
            return _json_print(_error("vm_workflow", "Invalid inputs JSON file."))
        return _json_print(vm_workflow(args.action, inputs))

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
        return _json_print(
            version_bump(
                args.summary,
                args.change_type,
                args.dry_run,
                args.force_release,
                args.target_version,
            ),
        )
    if args.command == "release-workflow":
        return _json_print(release_workflow(args.action))
    if args.command == "visual-workflow":
        return _json_print(
            visual_workflow(
                args.action, args.target_sha, args.platforms, args.release, args.post_status,
            ),
        )
    if args.command == "visual-review":
        return _json_print(
            visual_review(args.target_sha, args.platform, args.scene_id, args.verdict, args.notes),
        )
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
    MCP_SERVER.tool()(visual_workflow)
    MCP_SERVER.tool()(visual_review)
    MCP_SERVER.tool()(git_workflow)
    MCP_SERVER.tool()(ssh_workflow)
    MCP_SERVER.tool()(vm_workflow)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
