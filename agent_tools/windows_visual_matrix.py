"""The windows-visual matrix producer: one exact-SHA visual review becomes one matrix-record observation.

No Windows scenario row proves windows-visual (native_scenario_windows.MATRIX_PRODUCERS). Its three scenarios are
proven by the exact-SHA evidence of scripts/visual_platform.py, scripts/visual_regression.py and scripts/visual_review.py:

- scene-capture: every Windows scene of the SHA's own scene manifest captured at that SHA, each in exactly one capture
  provenance, every secure-desktop scene (windows-uac) by a local capture of an owned clone (VISUAL-003), each capture
  provenance registered as a Windows artifact of that SHA;
- geometry-contrast: the comparison report the review ingested passed every scene, against the baseline committed at
  that SHA (the bytes it compared, by Git LFS object ID), geometry and contrast included (VISUAL-004, VISUAL-005);
- agent-verdict: the complete review receipt of that SHA, every Windows scene `pass`, each verdict bound to the very
  screenshot and contact sheet bytes the agent opened (VISUAL-008).

It refuses a missing or extra scene, an unreviewed image or a verdict on other bytes, any non-pass verdict (a
product defect by name), any other SHA in the receipt, manifest, captures or artifacts, a comparison it cannot bind or
whose baseline is not the SHA's, and evidence changed since. It reads Git, the private receipt, the capture and report
files and the artifact registry; it writes only its create-only evidence document, and `register-captures` only
registers the receipt's own capture provenance files. matrix-record re-derives the document before it accepts a passed
windows-visual record (native_acceptance_matrix._visual_rule). The reviewer attestation is the coordinator's.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping

try:
    from . import native_acceptance_matrix as matrix
    from . import native_artifact_registry as registry
except ImportError:  # pragma: no cover - script-style fallback
    import native_acceptance_matrix as matrix  # type: ignore[no-redef]
    import native_artifact_registry as registry  # type: ignore[no-redef]


REQUIREMENT = "windows-visual"
PLATFORM = "windows"
SCHEMA = "vpn-control.windows-visual-evidence"
ARTIFACT_KIND = "visual-capture-provenance"
# The three scenarios and the evidence each one is proven by.
VISUAL_SCENARIOS = {"scene-capture": "capture-provenance", "geometry-contrast": "comparison-report", "agent-verdict": "review-receipt"}
MANIFEST = "visual-tests/scenes.json"
ENVIRONMENTS = "visual-tests/environments.json"
BASELINES = "visual-tests/baselines/" + PLATFORM
RECEIPTS = (".rag_index", "visual-review-receipts")
EVIDENCE = (".rag_index", "native-acceptance-evidence")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_LFS = re.compile(rb"version https://git-lfs\.github\.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize [0-9]+\n\Z")
_MAX_JSON = 16 * 1024 * 1024


class WindowsVisualMatrixError(ValueError):
    """A finite refusal: the evidence cannot prove windows-visual at this SHA."""


def _need(condition: Any, reason: str) -> None:
    if not condition:
        raise WindowsVisualMatrixError(reason)


def _canonical_hash(value: Any) -> str:
    # visual_review's own formula: a receipt digest and the manifest hashes it records.
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _bound_file(raw_path: Any, expected: Any, reason: str) -> Path:
    """An absolute regular file of the evidence whose bytes still hash as recorded."""
    _need(isinstance(raw_path, str) and raw_path and isinstance(expected, str) and _HASH.fullmatch(expected), reason)
    path = Path(raw_path)
    try:
        _need(path.is_absolute() and not path.is_symlink() and path.is_file() and _file_hash(path) == expected, reason)
    except OSError:
        raise WindowsVisualMatrixError(reason) from None
    return path


def _json_file(path: Path, reason: str) -> dict[str, Any]:
    try:
        _need(path.stat().st_size <= _MAX_JSON, reason)
        value = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise WindowsVisualMatrixError(reason) from None
    _need(isinstance(value, dict), reason)
    return value


def _git(root: Path, *arguments: str) -> bytes:
    done = subprocess.run(["git", "-C", str(root), *arguments], capture_output=True, check=False)
    _need(done.returncode == 0, "windows_visual_git_unavailable:" + arguments[0])
    return done.stdout


def _committed(root: Path, sha: str, path: str, reason: str) -> bytes:
    done = subprocess.run(["git", "-C", str(root), "show", sha + ":" + path], capture_output=True, check=False)
    _need(done.returncode == 0, reason)
    return done.stdout


def _baseline_at(root: Path, sha: str, scene_id: str) -> str:
    """The baseline committed at the SHA: its Git LFS object ID, or the blob's own SHA-256 if it is no pointer."""
    blob = _committed(root, sha, BASELINES + "/" + scene_id + ".png", "windows_visual_baseline_missing:" + scene_id)
    pointer = _LFS.fullmatch(blob)
    return pointer.group(1).decode("ascii") if pointer else hashlib.sha256(blob).hexdigest()


def _scenes_at(root: Path, sha: str) -> tuple[str, str, list[dict[str, Any]], set[str]]:
    """The SHA's own manifest and environment hashes, its Windows scenes in order and its secure-desktop scene IDs."""
    try:
        manifest = json.loads(_committed(root, sha, MANIFEST, "windows_visual_manifest_unavailable").decode("utf-8"))
        environments = json.loads(_committed(root, sha, ENVIRONMENTS, "windows_visual_manifest_unavailable").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise WindowsVisualMatrixError("windows_visual_manifest_unavailable") from None
    _need(isinstance(manifest, dict) and manifest.get("schema_version") == 1 and isinstance(manifest.get("scenes"), list),
          "windows_visual_manifest_unavailable")
    scenes = [scene for scene in manifest["scenes"] if isinstance(scene, dict) and PLATFORM in (scene.get("platforms") or [])]
    identifiers = [scene.get("id") for scene in scenes]
    _need(scenes and all(isinstance(item, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,80}", item) for item in identifiers)
          and len(set(identifiers)) == len(identifiers), "windows_visual_manifest_unavailable")
    secure = set((manifest.get("capture_contract") or {}).get("secure_scene_ids") or [])
    return _canonical_hash(manifest), _canonical_hash(environments), scenes, secure


def _receipt(root: Path, sha: str) -> tuple[dict[str, Any], str]:
    path = root.joinpath(*RECEIPTS, sha + ".json")
    _need(path.is_file() and not path.is_symlink(), "windows_visual_receipt_missing")
    receipt = _json_file(path, "windows_visual_receipt_invalid")
    _need(receipt.get("schema_version") == 1, "windows_visual_receipt_invalid")
    _need(receipt.get("target_sha") == sha, "windows_visual_mixed_sha:receipt")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    _need(receipt.get("receipt_sha256") == _canonical_hash(body), "windows_visual_receipt_digest")
    _need(PLATFORM in (receipt.get("platforms") or []), "windows_visual_receipt_without_windows")
    return receipt, _file_hash(path)


def _captures(receipt: Mapping[str, Any], sha: str, manifest_sha256: str, expected: list[str],
              secure: set[str]) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    listed = (receipt.get("captures") or {}).get(PLATFORM)
    _need(isinstance(listed, list) and listed, "windows_visual_capture_missing")
    captures, by_scene = [], {}
    for item in listed:
        _need(isinstance(item, Mapping), "windows_visual_capture_missing")
        path = _bound_file(item.get("path"), item.get("sha256"), "windows_visual_evidence_changed:capture")
        capture = _json_file(path, "windows_visual_capture_invalid")
        _need(capture.get("schema_version") == 1 and capture.get("platform") == PLATFORM, "windows_visual_capture_invalid")
        _need(capture.get("target_sha") == sha, "windows_visual_mixed_sha:capture")
        _need(capture.get("manifest_sha256") == manifest_sha256, "windows_visual_mixed_sha:capture-manifest")
        provider = capture.get("provider")
        _need(provider in ("local", "hosted") and isinstance(capture.get("scenes"), dict), "windows_visual_capture_invalid")
        for scene_id, files in capture["scenes"].items():
            _need(scene_id in expected, "windows_visual_scene_unexpected:" + str(scene_id)[:80])
            _need(scene_id not in by_scene, "windows_visual_scene_duplicate:" + scene_id)
            _need(isinstance(files, Mapping) and files.get("actual") == scene_id + ".png", "windows_visual_capture_invalid")
            by_scene[scene_id] = {"provider": provider, "actualSha256": files.get("actual_sha256"), "folder": path.parent,
                                  "capture": item["sha256"]}
        captures.append({"provider": provider, "sha256": item["sha256"], "scenes": len(capture["scenes"]),
                         "artifactId": "sha256-" + item["sha256"], "path": path})
    for scene_id in expected:
        _need(scene_id in by_scene, "windows_visual_scene_missing:" + scene_id)
        # VISUAL-003: Windows UAC requires a real local client VM; a hosted runner cannot show a secure desktop.
        _need(scene_id not in secure or by_scene[scene_id]["provider"] == "local", "windows_visual_secure_scene_not_owned:" + scene_id)
    return captures, by_scene


def review(root: Path | str, target_sha: str) -> dict[str, Any]:
    """Read only: the windows-visual evidence document of one SHA, or a finite refusal."""
    _need(isinstance(target_sha, str) and _SHA.fullmatch(target_sha), "windows_visual_sha_invalid")
    root = Path(root).resolve()
    _need(_git(root, "rev-parse", "--verify", target_sha + "^{commit}").decode().strip() == target_sha, "windows_visual_sha_unknown")
    manifest_sha256, environments_sha256, scenes, secure = _scenes_at(root, target_sha)
    expected = [str(scene["id"]) for scene in scenes]
    receipt, receipt_file = _receipt(root, target_sha)
    _need(receipt.get("manifest_sha256") == manifest_sha256, "windows_visual_mixed_sha:manifest")
    _need(receipt.get("environments_sha256") == environments_sha256, "windows_visual_mixed_sha:environments")
    entries = {key.split("/", 1)[1]: value for key, value in (receipt.get("scenes") or {}).items()
               if isinstance(key, str) and key.startswith(PLATFORM + "/")}
    for scene_id in expected:
        _need(scene_id in entries, "windows_visual_scene_missing:" + scene_id)
    for scene_id in sorted(set(entries) - set(expected)):
        raise WindowsVisualMatrixError("windows_visual_scene_unexpected:" + scene_id[:80])
    # agent-verdict: a verdict for every scene, on the bytes it names; a product defect blocks by name.
    for scene_id in expected:
        entry = entries[scene_id]
        _need(isinstance(entry, Mapping), "windows_visual_receipt_invalid")
        verdict = entry.get("review")
        _need(verdict != "product_defect", "windows_visual_product_defect:" + scene_id)
        _need(verdict not in (None, "", "pending"), "windows_visual_unreviewed:" + scene_id)
        _need(verdict == "pass", "windows_visual_verdict_" + str(verdict)[:40] + ":" + scene_id)
        _need(type(entry.get("reviewed_at_epoch")) is int and entry.get("actual_sha256")
              and entry.get("reviewed_actual_sha256") == entry["actual_sha256"] and entry.get("contact_sha256")
              and entry.get("reviewed_contact_sha256") == entry["contact_sha256"], "windows_visual_unreviewed:" + scene_id)
        _need(entry.get("automation") == "pass" and not entry.get("automation_errors"), "windows_visual_comparison_failed:" + scene_id)
    captures, captured = _captures(receipt, target_sha, manifest_sha256, expected, secure)
    # geometry-contrast: the report the review ingested, each scene against the baseline committed at the SHA.
    reported = (receipt.get("reports") or {}).get(PLATFORM)
    _need(isinstance(reported, Mapping), "windows_visual_comparison_missing")
    report_path = _bound_file(reported.get("path"), reported.get("sha256"), "windows_visual_evidence_changed:comparison")
    report = _json_file(report_path, "windows_visual_comparison_invalid")
    _need(report.get("schema_version") == 1 and report.get("platform") == PLATFORM and isinstance(report.get("scenes"), list),
          "windows_visual_comparison_invalid")
    results = {item.get("id"): item for item in report["scenes"] if isinstance(item, Mapping)}
    _need(len(results) == len(report["scenes"]), "windows_visual_comparison_invalid")
    for scene_id in expected:
        _need(scene_id in results, "windows_visual_scene_missing:" + scene_id)
    for scene_id in sorted(str(item) for item in set(results) - set(expected)):
        raise WindowsVisualMatrixError("windows_visual_scene_unexpected:" + scene_id[:80])
    _need(report.get("passed") is True, "windows_visual_comparison_failed:report")
    documented = []
    for scene in scenes:
        scene_id = str(scene["id"])
        entry, result, capture = entries[scene_id], results[scene_id], captured[scene_id]
        _need(result.get("passed") is True and result.get("errors") == [], "windows_visual_comparison_failed:" + scene_id)
        _need(isinstance(result.get("baseline_sha256"), str) and _HASH.fullmatch(result["baseline_sha256"])
              and result.get("actual_sha256") == entry["actual_sha256"], "windows_visual_comparison_unbound:" + scene_id)
        _need(result["baseline_sha256"] == _baseline_at(root, target_sha, scene_id), "windows_visual_baseline_stale:" + scene_id)
        # scene-capture: the reviewed image is the captured one, in its capture's own folder, unchanged since.
        actual = _bound_file(entry.get("actual"), entry["actual_sha256"], "windows_visual_evidence_changed:" + scene_id)
        _need(capture["actualSha256"] == entry["actual_sha256"] and actual.parent == capture["folder"]
              and actual.name == scene_id + ".png", "windows_visual_evidence_changed:" + scene_id)
        _bound_file(entry.get("contact_sheet"), entry["contact_sha256"], "windows_visual_evidence_changed:" + scene_id)
        if scene.get("geometry_required", True):
            _bound_file(entry.get("geometry"), entry.get("geometry_sha256"), "windows_visual_evidence_changed:" + scene_id)
        documented.append({"id": scene_id, "capability": entry.get("capability"), "provider": capture["provider"],
                           "capture": capture["capture"], "actualSha256": entry["actual_sha256"],
                           "contactSha256": entry["contact_sha256"], "geometrySha256": entry.get("geometry_sha256") or None,
                           "baselineSha256": result["baseline_sha256"], "verdict": "pass"})
    artifacts = []
    for capture in captures:
        try:
            verified = registry.verify_artifact_readonly(root, capture["artifactId"])
        except (registry.NativeArtifactRegistryError, OSError, ValueError):
            verified = {}
        artifact = verified.get("artifact") if isinstance(verified.get("artifact"), Mapping) else {}
        name = capture["path"].name
        _need(verified.get("verification") == "verified" and artifact.get("platform") == PLATFORM
              and artifact.get("artifactKind") == ARTIFACT_KIND, "windows_visual_capture_unregistered:" + name)
        _need(artifact.get("sourceSha") == target_sha, "windows_visual_mixed_sha:artifact")
        artifacts.append(capture["artifactId"])
    return {"schema": SCHEMA, "schemaVersion": 1, "requirementId": REQUIREMENT, "platform": PLATFORM, "targetSha": target_sha,
            "result": "passed", "scenarios": {name: "passed" for name in VISUAL_SCENARIOS}, "evidenceByScenario": dict(VISUAL_SCENARIOS),
            "manifestSha256": manifest_sha256, "environmentsSha256": environments_sha256,
            "receiptSha256": receipt["receipt_sha256"], "receiptFileSha256": receipt_file,
            "comparison": {"sha256": reported["sha256"], "sceneCount": len(results)},
            "captures": [{key: capture[key] for key in ("provider", "sha256", "scenes", "artifactId")} for capture in captures],
            "immutableArtifactIDs": sorted(artifacts), "scenes": documented}


def _environment(document: Mapping[str, Any]) -> str:
    return "windows-visual-" + "-".join(sorted({capture["provider"] for capture in document["captures"]}))


def verify_document(root: Path | str, document: Any) -> dict[str, Any]:
    """matrix-record's check of a passed windows-visual record: the document re-derives exactly from current evidence."""
    _need(isinstance(document, Mapping) and document.get("schema") == SCHEMA and isinstance(document.get("targetSha"), str),
          "windows_visual_document_invalid")
    derived = review(root, document["targetSha"])
    _need(derived == dict(document), "windows_visual_document_differs")
    return derived


def _write_evidence(root: Path, document: Mapping[str, Any]) -> tuple[str, str]:
    raw = (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    digest = hashlib.sha256(raw).hexdigest()
    name = REQUIREMENT + "-" + digest[:12] + ".json"
    path = root.joinpath(*EVIDENCE, name)
    try:
        if not root.joinpath(".rag_index").exists():
            root.joinpath(".rag_index").mkdir(mode=0o700)
        matrix._private_directory(path.parent)
        if not os.path.lexists(path):
            matrix._exclusive_write(path, raw)  # Create-only: a synced private file linked under its name.
    except (matrix.NativeAcceptanceMatrixError, OSError):
        if not os.path.lexists(path):
            raise WindowsVisualMatrixError("windows_visual_evidence_unavailable") from None
    try:
        same = not path.is_symlink() and _file_hash(path) == digest
    except OSError:
        same = False
    _need(same, "windows_visual_evidence_differs")
    return "/".join((*EVIDENCE, name)), digest


def observation(root: Path | str, target_sha: str, reviewer_attestation: str) -> dict[str, Any]:
    """The matrix-record input for windows-visual at one SHA; it records nothing itself."""
    _need(isinstance(reviewer_attestation, str) and reviewer_attestation.strip() and len(reviewer_attestation) <= 240,
          "windows_visual_attestation_invalid")
    root = Path(root).resolve()
    document = review(root, target_sha)
    try:
        requirements = matrix.load_requirements()
        _need(set(requirements[REQUIREMENT]["requiredScenarios"]) == set(VISUAL_SCENARIOS), "windows_visual_table_differs")
        directory = matrix._existing_directory(root)
        earlier = [] if directory is None else matrix._records_read_only(directory, requirements)
        retracted = set() if directory is None else matrix._read_retractions(directory, requirements)
    except (matrix.NativeAcceptanceMatrixError, OSError):
        raise WindowsVisualMatrixError("windows_visual_ledger_unavailable") from None
    _need(not any(item["requirementId"] == REQUIREMENT and item["originalSourceSHA"] == target_sha and item["result"] == "passed"
                  and item["receiptId"] not in retracted for item in earlier), "windows_visual_already_recorded")
    path, digest = _write_evidence(root, document)
    value = {"requirementId": REQUIREMENT, "platform": PLATFORM, "originalSourceSHA": target_sha,
             "immutableArtifactIDs": document["immutableArtifactIDs"], "evidencePath": path, "evidenceHash": digest,
             "environment": _environment(document), "result": "passed", "scenarioResults": dict(document["scenarios"]),
             "missingEvidence": [], "nextFixedCommand": "none", "reviewerAttestation": reviewer_attestation,
             "evidenceScope": "full-native"}
    try:
        matrix._stored_observation(value, requirements)
        matrix._verify_evidence(root, path, digest)
        matrix._verify_artifacts_readonly(root, value["immutableArtifactIDs"], PLATFORM, target_sha, "full-native")
    except (matrix.NativeAcceptanceMatrixError, OSError, ValueError) as error:
        raise WindowsVisualMatrixError("windows_visual_record_invalid") from error
    return value


def register_captures(root: Path | str, target_sha: str) -> list[dict[str, Any]]:
    """Register each Windows capture provenance file of the SHA's complete receipt as a Windows artifact of that SHA.

    Only files the receipt names, unchanged, whose own target is the SHA. A provenance file hashes every scene file it
    captured, so its registration binds the screenshots, geometry and region evidence to the record's artifacts."""
    _need(isinstance(target_sha, str) and _SHA.fullmatch(target_sha), "windows_visual_sha_invalid")
    root = Path(root).resolve()
    receipt, _ = _receipt(root, target_sha)
    listed = (receipt.get("captures") or {}).get(PLATFORM)
    _need(isinstance(listed, list) and listed, "windows_visual_capture_missing")
    registered = []
    for item in listed:
        _need(isinstance(item, Mapping), "windows_visual_capture_missing")
        path = _bound_file(item.get("path"), item.get("sha256"), "windows_visual_evidence_changed:capture")
        capture = _json_file(path, "windows_visual_capture_invalid")
        _need(capture.get("target_sha") == target_sha and capture.get("platform") == PLATFORM, "windows_visual_mixed_sha:capture")
        try:
            registered.append(registry.register_artifact(root, {
                "platform": PLATFORM, "artifactKind": ARTIFACT_KIND, "localPath": str(path), "sha256": item["sha256"],
                "size": path.stat().st_size, "evidenceClass": "local-verified", "sourceSha": target_sha}))
        except (registry.NativeArtifactRegistryError, OSError) as error:
            raise WindowsVisualMatrixError("windows_visual_capture_register_refused:" + path.name) from error
    return registered


def main(argv: list[str] | None = None) -> int:
    """Closed CLI: review (read only), register-captures, observation (prints the matrix-record input; records nothing)."""
    parser = argparse.ArgumentParser(prog="windows_visual_matrix")
    actions = parser.add_subparsers(dest="action", required=True)
    for name in ("review", "register-captures", "observation"):
        action = actions.add_parser(name)
        action.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
        action.add_argument("--target-sha", required=True)
        if name == "observation":
            action.add_argument("--reviewer-attestation", required=True)
    options = parser.parse_args(argv)
    try:
        if options.action == "review":
            result: Any = review(options.root, options.target_sha)
        elif options.action == "register-captures":
            result = register_captures(options.root, options.target_sha)
        else:
            result = observation(options.root, options.target_sha, options.reviewer_attestation)
    except WindowsVisualMatrixError as error:
        print(json.dumps({"refused": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
