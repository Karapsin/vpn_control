#!/usr/bin/env python3
"""Track exact-SHA automated visual results and mandatory agent inspection."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "visual-tests" / "scenes.json"
ENVIRONMENTS_PATH = ROOT / "visual-tests" / "environments.json"
SESSION_ROOT = ROOT / ".rag_index" / "visual-review-sessions"
RECEIPT_ROOT = ROOT / ".rag_index" / "visual-review-receipts"
PLATFORMS = ("android", "linux", "windows", "macos")
VERDICTS = ("pass", "product_defect", "expected_change", "infrastructure_failure")


class VisualReviewError(ValueError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise VisualReviewError(f"expected JSON object: {path}")
    return value


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def _canonical_hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _json_hash(path: Path) -> str:
    return _canonical_hash(_read_json(path))


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments], cwd=ROOT, text=True, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise VisualReviewError(completed.stderr.strip() or "git command failed")
    return completed.stdout.strip()


def validate_sha(target_sha: str) -> None:
    if len(target_sha) != 40 or any(char not in "0123456789abcdef" for char in target_sha):
        raise VisualReviewError("target SHA must be 40 lowercase hexadecimal characters")


def normalize_platforms(platforms: list[str], release: bool = False) -> list[str]:
    normalized = list(dict.fromkeys(platforms or list(PLATFORMS)))
    unknown = sorted(set(normalized) - set(PLATFORMS))
    if unknown:
        raise VisualReviewError("unsupported visual platforms: " + ", ".join(unknown))
    if release and set(normalized) != set(PLATFORMS):
        raise VisualReviewError("a release visual review requires android, linux, windows, and macos")
    return [platform for platform in PLATFORMS if platform in normalized]


def scene_inventory(platforms: list[str], manifest_path: Path | None = None) -> dict[str, dict[str, Any]]:
    manifest_path = manifest_path or MANIFEST_PATH
    manifest = _read_json(manifest_path)
    if manifest.get("schema_version") != 1 or not isinstance(manifest.get("scenes"), list):
        raise VisualReviewError("visual scene manifest must use schema_version 1")
    secure = set(manifest.get("capture_contract", {}).get("secure_scene_ids", []))
    inventory: dict[str, dict[str, Any]] = {}
    for raw in manifest["scenes"]:
        if not isinstance(raw, dict):
            raise VisualReviewError("every visual scene must be an object")
        scene_id = raw.get("id")
        scene_platforms = raw.get("platforms")
        if not isinstance(scene_id, str) or not scene_id or not isinstance(scene_platforms, list):
            raise VisualReviewError("every visual scene needs an id and platform list")
        capability = "secure_desktop" if scene_id in secure else (
            "app" if raw.get("geometry_required", True) else "native"
        )
        for platform in platforms:
            if platform not in scene_platforms:
                continue
            key = f"{platform}/{scene_id}"
            if key in inventory:
                raise VisualReviewError(f"duplicate visual scene: {key}")
            inventory[key] = {
                "platform": platform,
                "scene_id": scene_id,
                "capability": capability,
                "automation": "pending",
                "automation_errors": [],
                "review": "pending",
                "review_notes": "",
                "actual": "",
                "actual_sha256": "",
                "contact_sheet": "",
                "contact_sha256": "",
                "geometry": "",
                "geometry_sha256": "",
            }
    if not inventory:
        raise VisualReviewError("no visual scenes matched the requested platforms")
    return inventory


def session_path(target_sha: str) -> Path:
    validate_sha(target_sha)
    return SESSION_ROOT / f"{target_sha}.json"


def receipt_path(target_sha: str) -> Path:
    validate_sha(target_sha)
    return RECEIPT_ROOT / f"{target_sha}.json"


def _load_session(target_sha: str) -> dict[str, Any]:
    path = session_path(target_sha)
    if not path.is_file():
        raise VisualReviewError(f"visual review has not been started for {target_sha}")
    session = _read_json(path)
    if session.get("target_sha") != target_sha:
        raise VisualReviewError("visual review session SHA mismatch")
    return session


def _repository_name() -> str:
    completed = subprocess.run(
        ["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    if completed.returncode != 0 or not completed.stdout.strip():
        raise VisualReviewError(completed.stderr.strip() or "could not resolve GitHub repository")
    return completed.stdout.strip()


def post_commit_status(target_sha: str, state: str, description: str) -> None:
    if state not in {"pending", "success", "failure", "error"}:
        raise VisualReviewError(f"invalid commit status state: {state}")
    environments = _read_json(ENVIRONMENTS_PATH)
    context = str(environments.get("status_context", "vpn-control/agent-visual"))
    repository = _repository_name()
    completed = subprocess.run(
        [
            "gh", "api", "--method", "POST", f"repos/{repository}/statuses/{target_sha}",
            "-f", f"state={state}", "-f", f"context={context}",
            "-f", f"description={description[:140]}",
        ],
        cwd=ROOT, text=True, capture_output=True, check=False,
    )
    if completed.returncode != 0:
        raise VisualReviewError(completed.stderr.strip() or "could not post visual commit status")


def start_review(
    target_sha: str,
    platforms: list[str],
    *,
    release: bool,
    replace: bool = False,
    post_status: bool = False,
) -> dict[str, Any]:
    validate_sha(target_sha)
    normalized = normalize_platforms(platforms, release)
    if _git("rev-parse", "HEAD") != target_sha:
        raise VisualReviewError("visual review target must equal the checked-out HEAD")
    if release and _git("status", "--porcelain"):
        raise VisualReviewError("release visual review requires a clean worktree")
    path = session_path(target_sha)
    if path.exists() and not replace:
        raise VisualReviewError("visual review already exists; use --replace to restart it")
    inventory = scene_inventory(normalized)
    session = {
        "schema_version": 1,
        "target_sha": target_sha,
        "release": release,
        "platforms": normalized,
        "manifest_sha256": _json_hash(MANIFEST_PATH),
        "environments_sha256": _json_hash(ENVIRONMENTS_PATH),
        "created_at_epoch": int(time.time()),
        "updated_at_epoch": int(time.time()),
        "scenes": inventory,
    }
    _write_json(path, session)
    receipt = receipt_path(target_sha)
    if receipt.exists():
        receipt.unlink()
    if post_status and release:
        post_commit_status(target_sha, "pending", f"Agent visual review started: 0/{len(inventory)} scenes")
    return review_status(target_sha)


def ingest_report(target_sha: str, platform: str, report_path: Path, actual_dir: Path) -> dict[str, Any]:
    session = _load_session(target_sha)
    if platform not in session["platforms"]:
        raise VisualReviewError(f"platform is not part of this review: {platform}")
    report = _read_json(report_path)
    if report.get("schema_version") != 1 or report.get("platform") != platform:
        raise VisualReviewError("visual report schema or platform mismatch")
    results = report.get("scenes")
    if not isinstance(results, list):
        raise VisualReviewError("visual report scenes must be a list")
    expected = {
        value["scene_id"]
        for value in session["scenes"].values()
        if value["platform"] == platform
    }
    actual_ids = {item.get("id") for item in results if isinstance(item, dict)}
    if actual_ids != expected:
        missing = sorted(expected - actual_ids)
        unexpected = sorted(str(value) for value in actual_ids - expected)
        raise VisualReviewError(f"report scene mismatch; missing={missing}, unexpected={unexpected}")
    capture_paths = sorted(actual_dir.glob("capture-*.json"))
    if not capture_paths:
        raise VisualReviewError(f"capture provenance is missing for {platform}")
    captured: set[str] = set()
    capture_evidence: list[dict[str, str]] = []
    for capture_path in capture_paths:
        capture = _read_json(capture_path)
        if (
            capture.get("schema_version") != 1
            or capture.get("target_sha") != target_sha
            or capture.get("platform") != platform
            or capture.get("manifest_sha256") != session["manifest_sha256"]
            or not isinstance(capture.get("environment"), dict)
            or capture.get("environment_sha256") != _canonical_hash(capture.get("environment"))
        ):
            raise VisualReviewError(f"capture provenance does not match review: {capture_path}")
        capture_scenes = capture.get("scenes")
        if not isinstance(capture_scenes, dict):
            raise VisualReviewError(f"capture provenance has no scene inventory: {capture_path}")
        duplicate = captured.intersection(str(value) for value in capture_scenes)
        if duplicate:
            raise VisualReviewError("scene appears in multiple capture providers: " + ", ".join(sorted(duplicate)))
        for captured_scene, files in capture_scenes.items():
            if not isinstance(files, dict):
                raise VisualReviewError(f"capture provenance has invalid files: {captured_scene}")
            for kind in ("actual", "geometry"):
                raw_path = str(files.get(kind, ""))
                expected_hash = str(files.get(f"{kind}_sha256", ""))
                if not raw_path:
                    continue
                if Path(raw_path).name != raw_path:
                    raise VisualReviewError(f"capture provenance path is not a file name: {raw_path}")
                path = actual_dir / raw_path
                if not path.is_file() or not expected_hash or _file_hash(path) != expected_hash:
                    raise VisualReviewError(f"captured {kind} changed after stamping: {platform}/{captured_scene}")
        captured.update(str(value) for value in capture_scenes)
        capture_evidence.append({"path": str(capture_path.resolve()), "sha256": _file_hash(capture_path)})
    if captured != expected:
        raise VisualReviewError(
            f"capture provenance scene mismatch; missing={sorted(expected - captured)}, "
            f"unexpected={sorted(captured - expected)}",
        )
    for item in results:
        assert isinstance(item, dict)
        scene_id = str(item["id"])
        key = f"{platform}/{scene_id}"
        entry = session["scenes"][key]
        actual = (actual_dir / f"{scene_id}.png").resolve()
        if not actual.is_file():
            raise VisualReviewError(f"missing actual screenshot: {actual}")
        contact_raw = item.get("contact_sheet")
        contact = Path(str(contact_raw)).resolve() if contact_raw else Path()
        geometry = (actual_dir / f"{scene_id}.geometry.json").resolve()
        entry.update(
            {
                "automation": "pass" if item.get("passed") is True else "fail",
                "automation_errors": [str(value) for value in item.get("errors", [])],
                "actual": str(actual),
                "actual_sha256": _file_hash(actual),
                "contact_sheet": str(contact) if contact.is_file() else "",
                "contact_sha256": _file_hash(contact) if contact.is_file() else "",
                "geometry": str(geometry) if geometry.is_file() else "",
                "geometry_sha256": _file_hash(geometry) if geometry.is_file() else "",
                "review": "pending",
                "review_notes": "",
            },
        )
        entry.pop("reviewed_at_epoch", None)
    session.setdefault("reports", {})[platform] = {
        "path": str(report_path.resolve()),
        "sha256": _file_hash(report_path.resolve()),
    }
    session.setdefault("captures", {})[platform] = capture_evidence
    session["updated_at_epoch"] = int(time.time())
    _write_json(session_path(target_sha), session)
    return review_status(target_sha)


def record_reviews(target_sha: str, reviews: list[dict[str, str]]) -> dict[str, Any]:
    session = _load_session(target_sha)
    if not reviews:
        raise VisualReviewError("at least one scene review is required")
    for review in reviews:
        platform = str(review.get("platform", ""))
        scene_id = str(review.get("scene_id", ""))
        verdict = str(review.get("verdict", ""))
        notes = str(review.get("notes", "")).strip()
        key = f"{platform}/{scene_id}"
        if key not in session["scenes"]:
            raise VisualReviewError(f"scene is not part of this review: {key}")
        if verdict not in VERDICTS:
            raise VisualReviewError(f"invalid visual verdict for {key}: {verdict}")
        entry = session["scenes"][key]
        if not entry.get("actual") or not Path(str(entry["actual"])).is_file():
            raise VisualReviewError(f"cannot review a scene without its screenshot: {key}")
        if verdict != "pass" and not notes:
            raise VisualReviewError(f"non-pass verdict requires notes: {key}")
        entry["review"] = verdict
        entry["review_notes"] = notes
        entry["reviewed_at_epoch"] = int(time.time())
    session["updated_at_epoch"] = int(time.time())
    _write_json(session_path(target_sha), session)
    return review_status(target_sha)


def review_status(target_sha: str) -> dict[str, Any]:
    session = _load_session(target_sha)
    scenes = list(session["scenes"].values())
    batch_size = int(_read_json(MANIFEST_PATH).get("capture_contract", {}).get("review_batch_size", 6))
    pending = [scene for scene in scenes if scene.get("review") == "pending"]
    failed_automation = [
        f"{scene['platform']}/{scene['scene_id']}" for scene in scenes if scene.get("automation") == "fail"
    ]
    blocking_reviews = [
        f"{scene['platform']}/{scene['scene_id']}:{scene.get('review')}"
        for scene in scenes if scene.get("review") not in {"pending", "pass"}
    ]
    next_batch = [
        {
            "platform": scene["platform"],
            "scene_id": scene["scene_id"],
            "actual": scene.get("actual", ""),
            "contact_sheet": scene.get("contact_sheet", ""),
            "automation": scene.get("automation", "pending"),
            "automation_errors": scene.get("automation_errors", []),
        }
        for scene in pending[:batch_size]
    ]
    return {
        "target_sha": target_sha,
        "release": bool(session.get("release")),
        "platforms": session["platforms"],
        "scene_count": len(scenes),
        "automated_pass": sum(scene.get("automation") == "pass" for scene in scenes),
        "automated_fail": len(failed_automation),
        "automated_pending": sum(scene.get("automation") == "pending" for scene in scenes),
        "reviewed_pass": sum(scene.get("review") == "pass" for scene in scenes),
        "review_pending": len(pending),
        "failed_automation": failed_automation,
        "blocking_reviews": blocking_reviews,
        "next_batch": next_batch,
    }


def _verify_session_evidence(session: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected_top_level = (
        (MANIFEST_PATH, str(session.get("manifest_sha256", "")), "scene manifest"),
        (ENVIRONMENTS_PATH, str(session.get("environments_sha256", "")), "environment contract"),
    )
    for path, expected, label in expected_top_level:
        if not path.is_file() or not expected or _json_hash(path) != expected:
            errors.append(f"{label} changed after review start")
    for key, scene in session.get("scenes", {}).items():
        if not isinstance(scene, dict):
            errors.append(f"invalid scene evidence: {key}")
            continue
        for path_key, hash_key, required in (
            ("actual", "actual_sha256", True),
            ("contact_sheet", "contact_sha256", False),
            ("geometry", "geometry_sha256", scene.get("capability") == "app"),
        ):
            raw_path = str(scene.get(path_key, ""))
            expected = str(scene.get(hash_key, ""))
            path = Path(raw_path) if raw_path else Path()
            if required and (not raw_path or not expected):
                errors.append(f"missing {path_key} evidence: {key}")
            elif raw_path and (not path.is_file() or not expected or _file_hash(path) != expected):
                errors.append(f"{path_key} evidence changed after ingestion: {key}")
    for platform, report in session.get("reports", {}).items():
        if not isinstance(report, dict):
            errors.append(f"invalid report evidence: {platform}")
            continue
        path = Path(str(report.get("path", "")))
        expected = str(report.get("sha256", ""))
        if not path.is_file() or not expected or _file_hash(path) != expected:
            errors.append(f"report evidence changed after ingestion: {platform}")
    for platform, captures in session.get("captures", {}).items():
        if not isinstance(captures, list) or not captures:
            errors.append(f"missing capture provenance: {platform}")
            continue
        for capture in captures:
            if not isinstance(capture, dict):
                errors.append(f"invalid capture provenance: {platform}")
                continue
            path = Path(str(capture.get("path", "")))
            expected = str(capture.get("sha256", ""))
            if not path.is_file() or not expected or _file_hash(path) != expected:
                errors.append(f"capture provenance changed after ingestion: {platform}")
    return errors


def complete_review(target_sha: str, *, post_status: bool = False) -> dict[str, Any]:
    session = _load_session(target_sha)
    status = review_status(target_sha)
    blockers: list[str] = []
    if session.get("release") and _git("rev-parse", "HEAD") != target_sha:
        blockers.append("release review target no longer equals the checked-out HEAD")
    if session.get("release") and _git("status", "--porcelain"):
        blockers.append("release review completion requires a clean worktree")
    if session.get("release") and set(session.get("platforms", [])) != set(PLATFORMS):
        blockers.append("release review does not include every supported platform")
    if status["automated_pending"]:
        blockers.append(f"{status['automated_pending']} scenes have no automated result")
    if status["automated_fail"]:
        blockers.append(f"{status['automated_fail']} scenes failed automation")
    if status["review_pending"]:
        blockers.append(f"{status['review_pending']} scenes have not been reviewed by the agent")
    if status["blocking_reviews"]:
        blockers.append(f"{len(status['blocking_reviews'])} agent reviews are blocking")
    blockers.extend(_verify_session_evidence(session))
    if blockers:
        if post_status and session.get("release"):
            post_commit_status(target_sha, "failure", "; ".join(blockers))
        raise VisualReviewError("; ".join(blockers))
    evidence = {
        "schema_version": 1,
        "target_sha": target_sha,
        "release": bool(session.get("release")),
        "platforms": session["platforms"],
        "manifest_sha256": session["manifest_sha256"],
        "environments_sha256": session["environments_sha256"],
        "completed_at_epoch": int(time.time()),
        "reports": session.get("reports", {}),
        "captures": session.get("captures", {}),
        "scenes": session["scenes"],
    }
    digest = _canonical_hash(evidence)
    receipt = {**evidence, "receipt_sha256": digest}
    _write_json(receipt_path(target_sha), receipt)
    if post_status and session.get("release"):
        post_commit_status(
            target_sha,
            "success",
            f"Agent reviewed {status['scene_count']}/{status['scene_count']} scenes; receipt {digest[:16]}",
        )
    return {**status, "receipt": str(receipt_path(target_sha)), "receipt_sha256": digest}


def parse_platforms(values: list[str] | None) -> list[str]:
    if not values:
        return list(PLATFORMS)
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return result


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)

    start = subparsers.add_parser("start")
    start.add_argument("--target-sha", required=True)
    start.add_argument("--platform", action="append")
    start.add_argument("--release", action="store_true")
    start.add_argument("--replace", action="store_true")
    start.add_argument("--post-status", action="store_true")

    ingest = subparsers.add_parser("ingest")
    ingest.add_argument("--target-sha", required=True)
    ingest.add_argument("--platform", required=True, choices=PLATFORMS)
    ingest.add_argument("--report", required=True, type=Path)
    ingest.add_argument("--actual-dir", required=True, type=Path)

    record = subparsers.add_parser("record")
    record.add_argument("--target-sha", required=True)
    record.add_argument("--platform", required=True, choices=PLATFORMS)
    record.add_argument("--scene-id", required=True)
    record.add_argument("--verdict", required=True, choices=VERDICTS)
    record.add_argument("--notes", default="")

    status = subparsers.add_parser("status")
    status.add_argument("--target-sha", required=True)

    complete = subparsers.add_parser("complete")
    complete.add_argument("--target-sha", required=True)
    complete.add_argument("--post-status", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if args.action == "start":
            result = start_review(
                args.target_sha,
                parse_platforms(args.platform),
                release=args.release,
                replace=args.replace,
                post_status=args.post_status,
            )
        elif args.action == "ingest":
            result = ingest_report(args.target_sha, args.platform, args.report, args.actual_dir)
        elif args.action == "record":
            result = record_reviews(
                args.target_sha,
                [{
                    "platform": args.platform,
                    "scene_id": args.scene_id,
                    "verdict": args.verdict,
                    "notes": args.notes,
                }],
            )
        elif args.action == "status":
            result = review_status(args.target_sha)
        else:
            result = complete_review(args.target_sha, post_status=args.post_status)
    except (OSError, json.JSONDecodeError, VisualReviewError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "result": result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
