#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("visual_review.py")
SPEC = importlib.util.spec_from_file_location("visual_review", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
visual_review = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = visual_review
SPEC.loader.exec_module(visual_review)


class VisualReviewTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.manifest = self.root / "scenes.json"
        self.environments = self.root / "environments.json"
        self.sessions = self.root / "sessions"
        self.receipts = self.root / "receipts"
        self.manifest.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "capture_contract": {"secure_scene_ids": ["secure"], "review_batch_size": 2},
                    "scenes": [
                        {"id": "app", "platforms": ["android"]},
                        {"id": "native", "platforms": ["linux"], "geometry_required": False},
                        {"id": "secure", "platforms": ["windows"], "geometry_required": False},
                        {"id": "mac", "platforms": ["macos"]},
                    ],
                },
            ),
            encoding="utf-8",
        )
        self.environments.write_text(
            json.dumps({"status_context": "vpn-control/agent-visual"}), encoding="utf-8",
        )
        self.patches = [
            mock.patch.object(visual_review, "ROOT", self.root),
            mock.patch.object(visual_review, "MANIFEST_PATH", self.manifest),
            mock.patch.object(visual_review, "ENVIRONMENTS_PATH", self.environments),
            mock.patch.object(visual_review, "SESSION_ROOT", self.sessions),
            mock.patch.object(visual_review, "RECEIPT_ROOT", self.receipts),
            mock.patch.object(
                visual_review,
                "_git",
                side_effect=lambda *arguments: "" if arguments == ("status", "--porcelain") else "a" * 40,
            ),
        ]
        for patch in self.patches:
            patch.start()

    def tearDown(self) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.temporary.cleanup()

    def _start(self, platforms: list[str] | None = None, release: bool = False) -> str:
        sha = "a" * 40
        visual_review.start_review(sha, platforms or ["android"], release=release)
        return sha

    def _ingest(self, sha: str, platform: str, scene_id: str, passed: bool = True) -> None:
        actual_dir = self.root / f"actual-{platform}"
        report_dir = self.root / f"report-{platform}"
        actual_dir.mkdir(exist_ok=True)
        report_dir.mkdir(exist_ok=True)
        actual = actual_dir / f"{scene_id}.png"
        contact = report_dir / f"{scene_id}.contact.png"
        actual.write_bytes(b"actual")
        contact.write_bytes(b"contact")
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        scene = next(value for value in manifest["scenes"] if value["id"] == scene_id)
        if scene.get("geometry_required", True):
            (actual_dir / f"{scene_id}.geometry.json").write_text(
                json.dumps({"viewport": [1280, 800], "elements": []}),
                encoding="utf-8",
            )
        capture_environment = {"fixture": True}
        capture = {
            "schema_version": 1,
            "platform": platform,
            "provider": "local",
            "target_sha": sha,
            "manifest_sha256": visual_review._json_hash(self.manifest),
            "environment": capture_environment,
            "environment_sha256": visual_review._canonical_hash(capture_environment),
            "scenes": {
                scene_id: {
                    "actual": actual.name,
                    "actual_sha256": visual_review._file_hash(actual),
                },
            },
        }
        (actual_dir / "capture-local.json").write_text(json.dumps(capture), encoding="utf-8")
        report = report_dir / "report.json"
        report.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "platform": platform,
                    "scenes": [
                        {
                            "id": scene_id,
                            "passed": passed,
                            "errors": [] if passed else ["changed pixels"],
                            "contact_sheet": str(contact),
                        },
                    ],
                },
            ),
            encoding="utf-8",
        )
        visual_review.ingest_report(sha, platform, report, actual_dir)

    def test_json_provenance_hash_ignores_line_endings_and_formatting(self) -> None:
        compact = self.root / "compact.json"
        pretty = self.root / "pretty.json"
        compact.write_bytes(b'{"b":2,"a":1}\r\n')
        pretty.write_text('{\n  "a": 1,\n  "b": 2\n}\n', encoding="utf-8")
        self.assertNotEqual(visual_review._file_hash(compact), visual_review._file_hash(pretty))
        self.assertEqual(visual_review._json_hash(compact), visual_review._json_hash(pretty))

    def test_release_review_requires_all_supported_platforms(self) -> None:
        with self.assertRaises(visual_review.VisualReviewError):
            self._start(["android"], release=True)

    def test_receipt_requires_automation_and_agent_pass(self) -> None:
        sha = self._start()
        self._ingest(sha, "android", "app")
        with self.assertRaises(visual_review.VisualReviewError):
            visual_review.complete_review(sha)
        visual_review.record_reviews(
            sha,
            [{"platform": "android", "scene_id": "app", "verdict": "pass", "notes": ""}],
        )
        result = visual_review.complete_review(sha)
        self.assertTrue(Path(result["receipt"]).is_file())
        self.assertEqual(64, len(result["receipt_sha256"]))

    def test_agent_cannot_waive_failed_automation(self) -> None:
        sha = self._start()
        self._ingest(sha, "android", "app", passed=False)
        visual_review.record_reviews(
            sha,
            [{"platform": "android", "scene_id": "app", "verdict": "pass", "notes": "looks acceptable"}],
        )
        with self.assertRaisesRegex(visual_review.VisualReviewError, "failed automation"):
            visual_review.complete_review(sha)

    def test_evidence_changed_after_agent_review_blocks_receipt(self) -> None:
        sha = self._start()
        self._ingest(sha, "android", "app")
        visual_review.record_reviews(
            sha,
            [{"platform": "android", "scene_id": "app", "verdict": "pass", "notes": ""}],
        )
        (self.root / "actual-android" / "app.png").write_bytes(b"changed after review")
        with self.assertRaisesRegex(visual_review.VisualReviewError, "evidence changed"):
            visual_review.complete_review(sha)

    def test_reingest_resets_agent_verdict(self) -> None:
        sha = self._start()
        self._ingest(sha, "android", "app")
        visual_review.record_reviews(
            sha,
            [{"platform": "android", "scene_id": "app", "verdict": "pass", "notes": ""}],
        )
        self._ingest(sha, "android", "app")
        status = visual_review.review_status(sha)
        self.assertEqual(1, status["review_pending"])
        with self.assertRaisesRegex(visual_review.VisualReviewError, "not been reviewed"):
            visual_review.complete_review(sha)

    def test_non_pass_review_requires_reason_and_blocks(self) -> None:
        sha = self._start()
        self._ingest(sha, "android", "app")
        with self.assertRaises(visual_review.VisualReviewError):
            visual_review.record_reviews(
                sha,
                [{"platform": "android", "scene_id": "app", "verdict": "product_defect", "notes": ""}],
            )
        visual_review.record_reviews(
            sha,
            [{
                "platform": "android",
                "scene_id": "app",
                "verdict": "product_defect",
                "notes": "button is clipped",
            }],
        )
        with self.assertRaisesRegex(visual_review.VisualReviewError, "agent reviews are blocking"):
            visual_review.complete_review(sha)

    def test_release_success_posts_receipt_digest_status(self) -> None:
        sha = self._start(list(visual_review.PLATFORMS), release=True)
        for platform, scene in (("android", "app"), ("linux", "native"), ("windows", "secure"), ("macos", "mac")):
            self._ingest(sha, platform, scene)
            visual_review.record_reviews(
                sha,
                [{"platform": platform, "scene_id": scene, "verdict": "pass", "notes": ""}],
            )
        with mock.patch.object(visual_review, "post_commit_status") as post:
            result = visual_review.complete_review(sha, post_status=True)
        post.assert_called_once()
        self.assertEqual("success", post.call_args.args[1])
        self.assertIn(result["receipt_sha256"][:16], post.call_args.args[2])

    def test_release_completion_rechecks_exact_head_and_clean_tree(self) -> None:
        sha = self._start(list(visual_review.PLATFORMS), release=True)
        for platform, scene in (("android", "app"), ("linux", "native"), ("windows", "secure"), ("macos", "mac")):
            self._ingest(sha, platform, scene)
            visual_review.record_reviews(
                sha,
                [{"platform": platform, "scene_id": scene, "verdict": "pass", "notes": ""}],
            )
        with (
            mock.patch.object(
                visual_review,
                "_git",
                side_effect=lambda *arguments: "b" * 40 if arguments == ("rev-parse", "HEAD") else "",
            ),
            self.assertRaisesRegex(visual_review.VisualReviewError, "no longer equals"),
        ):
            visual_review.complete_review(sha)


if __name__ == "__main__":
    unittest.main()
