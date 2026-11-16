"""The windows-visual matrix producer over a real Git commit, the real comparator, the real review and the real ledger.

Each set is made as the visual tools make it: capture provenance stamped as visual_platform stamps it, the comparison by
scripts/visual_regression.py against smudged baselines whose Git LFS pointers are committed at the SHA, the review by
scripts/visual_review.py (start, ingest, a verdict per scene, complete), then the producer and matrix-record. Nothing
reaches a VM, a host or GitHub.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zlib

from agent_tools import native_acceptance_matrix as matrix
from agent_tools import native_artifact_registry as registry
from agent_tools import native_scenario_windows as windows
from agent_tools import windows_visual_matrix as visual

REPOSITORY = Path(__file__).resolve().parents[2]


def _script(name):
    if name == "visual_regression":
        spec = importlib.util.spec_from_file_location("windows_visual_matrix_test_" + name, REPOSITORY / "scripts/visual_regression.py")
    else:
        spec = importlib.util.spec_from_file_location("windows_visual_matrix_test_" + name, REPOSITORY / "scripts/visual_review.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # A dataclass resolves its module by name.
    spec.loader.exec_module(module)
    return module


regression = _script("visual_regression")
REVIEW = "Coordinator opened every Windows screenshot and contact sheet of this SHA."
SCENES = [{"id": "windows-main", "platforms": ["windows", "linux"], "required_elements": ["connect"]},
          {"id": "windows-frame", "platforms": ["windows"], "geometry_required": False},
          {"id": "windows-uac", "platforms": ["windows"], "geometry_required": False},
          {"id": "linux-only", "platforms": ["linux"], "required_elements": ["connect"]}]
WINDOWS = ["windows-main", "windows-frame", "windows-uac"]
GEOMETRY = {"viewport": [16, 16], "elements": [{"id": "connect", "bounds": [0, 0, 16, 16], "interactive": True,
                                                  "label": "Connect", "allow_small": True}]}


def _pointer(raw):
    return ("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n" % (hashlib.sha256(raw).hexdigest(), len(raw))).encode()


def _with_text_chunk(raw):
    """The same pixels in other bytes: an ancillary chunk the decoder skips, so a comparison still passes."""
    payload = b"Comment\x00re-encoded"
    chunk = struct.pack(">I", len(payload)) + b"tEXt" + payload + struct.pack(">I", zlib.crc32(b"tEXt" + payload) & 0xFFFFFFFF)
    return raw[:33] + chunk + raw[33:]


@unittest.skipUnless(os.name == "posix", "the private ledger and registry are POSIX")
class Base(unittest.TestCase):
    hosted = ("windows-main", "windows-frame")
    local = ("windows-uac",)
    stale = False

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name).resolve()
        self.root = self.work / "repository"
        (self.root / "visual-tests").mkdir(parents=True)
        (self.root / ".rag_index").mkdir(mode=0o700)
        self.git("init", "-q")
        manifest = {"schema_version": 1, "capture_contract": {"secure_scene_ids": ["windows-uac"], "review_batch_size": 6},
                    "scenes": SCENES}
        (self.root / "visual-tests/scenes.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        (self.root / "visual-tests/environments.json").write_text(json.dumps({"status_context": "vpn-control/agent-visual"}),
                                                                  encoding="utf-8")
        self.baselines = self.work / "smudged"
        self.images = {}
        for index, scene in enumerate(WINDOWS):
            raw = regression.encode_png(regression.PngImage(16, 16, bytes((8 + index, 17, 31, 255)) * 256))
            self.images[scene] = raw
            pointer = self.root / visual.BASELINES / (scene + ".png")
            pointer.parent.mkdir(parents=True, exist_ok=True)
            pointer.write_bytes(_pointer(raw))
            smudged = self.baselines / "windows" / (scene + ".png")
            smudged.parent.mkdir(parents=True, exist_ok=True)
            # A stale set compares against a baseline other than the SHA's own (same pixels, other bytes).
            smudged.write_bytes(_with_text_chunk(raw) if self.stale and scene == "windows-main" else raw)
        self.git("add", "-A")
        self.git("-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid", "commit", "-q", "-m", "fixture")
        self.sha = self.git("rev-parse", "HEAD")
        self.review_module = _script("visual_review")
        for name, value in (("ROOT", self.root), ("MANIFEST_PATH", self.root / "visual-tests/scenes.json"),
                            ("ENVIRONMENTS_PATH", self.root / "visual-tests/environments.json"),
                            ("SESSION_ROOT", self.root / ".rag_index/visual-review-sessions"),
                            ("RECEIPT_ROOT", self.root / ".rag_index/visual-review-receipts")):
            patcher = mock.patch.object(self.review_module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.actual = self.work / "visual-actual" / "windows"
        self.reports = self.work / "visual-reports"

    def git(self, *arguments):
        return subprocess.run(["git", "-C", str(self.root), *arguments], check=True, capture_output=True, text=True).stdout.strip()

    def capture(self, verdicts=None):
        """Capture, compare, ingest and review every Windows scene; complete the receipt when every verdict is pass."""
        self.actual.mkdir(parents=True)
        for scene in WINDOWS:
            (self.actual / (scene + ".png")).write_bytes(self.images[scene])
        (self.actual / "windows-main.geometry.json").write_text(json.dumps(GEOMETRY), encoding="utf-8")
        for provider, scenes in (("hosted", self.hosted), ("local", self.local)):
            if scenes:
                self.stamp(provider, scenes)
        with contextlib.redirect_stdout(io.StringIO()):
            compared = regression.verify(argparse.Namespace(platform="windows", manifest=self.root / "visual-tests/scenes.json",
                                                            baseline_dir=self.baselines, actual_dir=self.actual, report_dir=self.reports))
        self.assertEqual(0, compared)
        review = self.review_module
        review.start_review(self.sha, ["windows"], release=False)
        review.ingest_report(self.sha, "windows", self.reports / "windows/report.json", self.actual)
        verdicts = verdicts or {}
        review.record_reviews(self.sha, [{"platform": "windows", "scene_id": scene, "verdict": verdicts.get(scene, "pass"),
                                          "notes": "" if verdicts.get(scene, "pass") == "pass" else "seen"} for scene in WINDOWS])
        if not verdicts:
            review.complete_review(self.sha)

    def stamp(self, provider, scenes, sha=None):
        environment = {"canonical_environment": "windows-1280x800", "provider": provider}
        files = {}
        for scene in scenes:
            entry = {"actual": scene + ".png", "actual_sha256": hashlib.sha256((self.actual / (scene + ".png")).read_bytes()).hexdigest()}
            if scene == "windows-main":
                geometry = self.actual / "windows-main.geometry.json"
                entry.update(geometry=geometry.name, geometry_sha256=hashlib.sha256(geometry.read_bytes()).hexdigest())
            files[scene] = entry
        value = {"schema_version": 1, "platform": "windows", "provider": provider, "target_sha": sha or self.sha,
                 "manifest_sha256": self.review_module._json_hash(self.root / "visual-tests/scenes.json"),
                 "environment": environment, "environment_sha256": self.review_module._canonical_hash(environment), "scenes": files}
        (self.actual / ("capture-%s.json" % provider)).write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")

    @property
    def receipt_path(self):
        return self.root.joinpath(*visual.RECEIPTS, self.sha + ".json")

    def rewrite_receipt(self, change):
        receipt = json.loads(self.receipt_path.read_text(encoding="utf-8"))
        change(receipt)
        receipt.pop("receipt_sha256")
        receipt["receipt_sha256"] = self.review_module._canonical_hash(receipt)
        self.receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")

    def rewrite_file(self, path, change, key):
        """Change one bound JSON file and the hash the receipt keeps of it (a hand-made receipt)."""
        value = json.loads(path.read_text(encoding="utf-8"))
        change(value)
        path.write_text(json.dumps(value), encoding="utf-8")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()

        def bind(receipt):
            if key == "report":
                receipt["reports"]["windows"]["sha256"] = digest
            else:
                for item in receipt["captures"]["windows"]:
                    if item["path"] == str(path):
                        item["sha256"] = digest
        self.rewrite_receipt(bind)

    def assert_refused(self, reason, action=None):
        with self.assertRaises(visual.WindowsVisualMatrixError) as caught:
            (action or (lambda: visual.observation(self.root, self.sha, REVIEW)))()
        self.assertEqual(reason, str(caught.exception))
        self.assertFalse(self.root.joinpath(*visual.EVIDENCE).exists(), "nothing is written for a refused set")


class CompleteSetTests(Base):
    def test_a_reviewed_capture_of_every_windows_scene_yields_the_record_matrix_record_accepts(self):
        self.capture()
        registered = visual.register_captures(self.root, self.sha)
        self.assertEqual(2, len(registered))
        observation = visual.observation(self.root, self.sha, REVIEW)
        self.assertEqual(("passed", "full-native", "windows", self.sha, [], "none", "windows-visual-hosted-local"),
                         tuple(observation[key] for key in ("result", "evidenceScope", "platform", "originalSourceSHA",
                                                            "missingEvidence", "nextFixedCommand", "environment")))
        self.assertEqual({"scene-capture": "passed", "geometry-contrast": "passed", "agent-verdict": "passed"},
                         observation["scenarioResults"])
        self.assertEqual(sorted(item["artifactId"] for item in registered), observation["immutableArtifactIDs"])
        document = json.loads((self.root / observation["evidencePath"]).read_bytes())
        self.assertEqual(WINDOWS, [scene["id"] for scene in document["scenes"]], "every Windows scene, and only those")
        self.assertEqual({"windows-main": "hosted", "windows-frame": "hosted", "windows-uac": "local"},
                         {scene["id"]: scene["provider"] for scene in document["scenes"]})
        self.assertEqual({scene: hashlib.sha256(self.images[scene]).hexdigest() for scene in WINDOWS},
                         {scene["id"]: scene["baselineSha256"] for scene in document["scenes"]}, "the SHA's own baselines")
        self.assertNotIn(REVIEW, (self.root / observation["evidencePath"]).read_text(), "the attestation is the coordinator's")
        recorded = matrix.matrix_record(self.root, observation)
        self.assertEqual(("passed", self.sha), (recorded["result"], recorded["originalSourceSHA"]))
        status = next(row for row in matrix.matrix_status(self.root, self.sha)["requirements"] if row["requirementId"] == "windows-visual")
        self.assertEqual("passed", status["status"])
        with self.assertRaisesRegex(visual.WindowsVisualMatrixError, r"\Awindows_visual_already_recorded\Z"):
            visual.observation(self.root, self.sha, REVIEW)

    def test_the_entry_point_prints_the_observation_and_refuses_finitely(self):
        self.capture()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            refused = visual.main(["observation", "--root", str(self.root), "--target-sha", self.sha, "--reviewer-attestation", REVIEW])
        self.assertEqual((1, {"refused": "windows_visual_capture_unregistered:capture-hosted.json"}), (refused, json.loads(err.getvalue())))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, visual.main(["register-captures", "--root", str(self.root), "--target-sha", self.sha]))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, visual.main(["observation", "--root", str(self.root), "--target-sha", self.sha,
                                             "--reviewer-attestation", REVIEW]))
        self.assertEqual("passed", json.loads(out.getvalue())["result"])


class RefusalTests(Base):
    def setUp(self):
        super().setUp()
        self.capture()
        visual.register_captures(self.root, self.sha)

    def test_a_missing_scene_is_refused(self):
        self.rewrite_receipt(lambda receipt: receipt["scenes"].pop("windows/windows-frame"))
        self.assert_refused("windows_visual_scene_missing:windows-frame")

    def test_an_unreviewed_image_is_refused(self):
        def pending(receipt):
            receipt["scenes"]["windows/windows-uac"]["review"] = "pending"
        self.rewrite_receipt(pending)
        self.assert_refused("windows_visual_unreviewed:windows-uac")

    def test_a_verdict_not_bound_to_the_opened_image_is_refused(self):
        # A receipt from a review that never named the bytes it judged, or that judged other bytes.
        for key, value in (("reviewed_actual_sha256", None), ("reviewed_actual_sha256", "0" * 64), ("reviewed_contact_sha256", "0" * 64)):
            with self.subTest(key=key, value=value):
                def unbound(receipt):
                    entry = receipt["scenes"]["windows/windows-main"]
                    entry.pop(key) if value is None else entry.update({key: value})
                saved = self.receipt_path.read_bytes()
                self.rewrite_receipt(unbound)
                self.assert_refused("windows_visual_unreviewed:windows-main")
                self.receipt_path.write_bytes(saved)

    def test_a_product_defect_verdict_is_refused(self):
        def defect(receipt):
            receipt["scenes"]["windows/windows-main"].update(review="product_defect", review_notes="clipped button")
        self.rewrite_receipt(defect)
        self.assert_refused("windows_visual_product_defect:windows-main")

    def test_any_other_non_pass_verdict_is_refused(self):
        def infrastructure(receipt):
            receipt["scenes"]["windows/windows-frame"].update(review="infrastructure_failure", review_notes="black frame")
        self.rewrite_receipt(infrastructure)
        self.assert_refused("windows_visual_verdict_infrastructure_failure:windows-frame")

    def test_mixed_shas_are_refused(self):
        other = "f" * 40
        saved = self.receipt_path.read_bytes()
        self.rewrite_receipt(lambda receipt: receipt.update(target_sha=other))
        self.assert_refused("windows_visual_mixed_sha:receipt")
        self.receipt_path.write_bytes(saved)
        self.rewrite_receipt(lambda receipt: receipt.update(manifest_sha256="0" * 64))
        self.assert_refused("windows_visual_mixed_sha:manifest")
        self.receipt_path.write_bytes(saved)
        self.rewrite_file(self.actual / "capture-local.json", lambda capture: capture.update(target_sha=other), "capture")
        self.assert_refused("windows_visual_mixed_sha:capture")

    def test_an_artifact_of_another_sha_is_refused(self):
        capture = self.actual / "capture-local.json"
        raw = json.loads(capture.read_text(encoding="utf-8"))
        raw["environment"]["note"] = "a second capture of the scene"
        raw["environment_sha256"] = self.review_module._canonical_hash(raw["environment"])
        capture.write_text(json.dumps(raw), encoding="utf-8")
        digest = hashlib.sha256(capture.read_bytes()).hexdigest()
        registry.register_artifact(self.root, {"platform": "windows", "artifactKind": visual.ARTIFACT_KIND, "localPath": str(capture),
                                               "sha256": digest, "size": capture.stat().st_size, "evidenceClass": "local-verified",
                                               "sourceSha": "e" * 40})

        def bind(receipt):
            next(item for item in receipt["captures"]["windows"] if item["path"] == str(capture))["sha256"] = digest
        self.rewrite_receipt(bind)
        self.assert_refused("windows_visual_mixed_sha:artifact")

    def test_a_comparison_without_its_baseline_identity_is_refused(self):
        # A report of the comparator before it bound the bytes it compared cannot show which baseline passed.
        def unbound(report):
            report["scenes"][0].pop("baseline_sha256")
        self.rewrite_file(self.reports / "windows/report.json", unbound, "report")
        self.assert_refused("windows_visual_comparison_unbound:windows-main")

    def test_evidence_changed_after_the_review_is_refused(self):
        (self.actual / "windows-frame.png").write_bytes(self.images["windows-main"])
        self.assert_refused("windows_visual_evidence_changed:windows-frame")

    def test_an_unregistered_capture_is_refused(self):
        with mock.patch.object(visual.registry, "verify_artifact_readonly", side_effect=registry.NativeArtifactRegistryError("absent")):
            self.assert_refused("windows_visual_capture_unregistered:capture-hosted.json")


class StaleBaselineTests(Base):
    stale = True

    def test_a_comparison_against_another_baseline_than_the_shas_is_refused(self):
        self.capture()
        visual.register_captures(self.root, self.sha)
        self.assert_refused("windows_visual_baseline_stale:windows-main")


class SecureSceneTests(Base):
    hosted = tuple(WINDOWS)
    local = ()

    def test_the_uac_scene_must_come_from_an_owned_clone(self):
        self.capture()
        visual.register_captures(self.root, self.sha)
        self.assert_refused("windows_visual_secure_scene_not_owned:windows-uac")


class RecordTests(Base):
    def test_matrix_record_refuses_a_windows_visual_pass_its_producer_did_not_make(self):
        # GAP-VIS: a coordinator-composed record that no code checked for coverage. Any document, here a plain one.
        self.capture()
        artifacts = sorted(item["artifactId"] for item in visual.register_captures(self.root, self.sha))
        evidence = self.root / ".rag_index/hand.json"
        evidence.write_text(json.dumps({"scenes": 58}), encoding="utf-8")
        observation = {"requirementId": "windows-visual", "platform": "windows", "originalSourceSHA": self.sha,
                       "immutableArtifactIDs": artifacts, "evidencePath": ".rag_index/hand.json",
                       "evidenceHash": hashlib.sha256(evidence.read_bytes()).hexdigest(), "environment": "windows-visual-hand",
                       "result": "passed", "scenarioResults": {name: "passed" for name in visual.VISUAL_SCENARIOS},
                       "missingEvidence": [], "nextFixedCommand": "none", "reviewerAttestation": REVIEW, "evidenceScope": "full-native"}
        with self.assertRaisesRegex(matrix.NativeAcceptanceMatrixError, "producer's evidence document"):
            matrix.matrix_record(self.root, observation)

    def test_matrix_record_rederives_the_document_from_current_evidence(self):
        self.capture()
        visual.register_captures(self.root, self.sha)
        observation = visual.observation(self.root, self.sha, REVIEW)
        def defect(receipt):
            receipt["scenes"]["windows/windows-main"].update(review="product_defect", review_notes="clipped button")
        self.rewrite_receipt(defect)
        with self.assertRaisesRegex(matrix.NativeAcceptanceMatrixError, "windows_visual_product_defect:windows-main"):
            matrix.matrix_record(self.root, observation)
        self.assertEqual([], sorted(self.root.joinpath(*matrix.RECEIPTS_RELATIVE.parts).glob("*.json")), "nothing recorded")

    def test_a_record_that_says_more_than_its_document_is_refused(self):
        self.capture()
        visual.register_captures(self.root, self.sha)
        observation = visual.observation(self.root, self.sha, REVIEW)
        with self.assertRaisesRegex(matrix.NativeAcceptanceMatrixError, "differs from its evidence document"):
            matrix.matrix_record(self.root, {**observation, "scenarioResults": {"scene-capture": "passed"}})


class RepositoryTests(unittest.TestCase):
    def test_the_producer_maps_the_requirement_and_the_real_inventory(self):
        requirement = matrix.load_requirements()["windows-visual"]
        self.assertEqual(set(requirement["requiredScenarios"]), set(visual.VISUAL_SCENARIOS))
        self.assertEqual({"windows-visual": "agent_tools/windows_visual_matrix.py"}, windows.MATRIX_PRODUCERS)
        self.assertTrue((REPOSITORY / windows.MATRIX_PRODUCERS["windows-visual"]).is_file())
        # No row proves it, so the row driver's routes (sweep eligibility, the MCP route rule) never claim it.
        self.assertFalse(any(windows.MATRIX_SCENARIOS["windows-visual"].values()))
        manifest = json.loads((REPOSITORY / visual.MANIFEST).read_text(encoding="utf-8"))
        scenes = [scene["id"] for scene in manifest["scenes"] if "windows" in scene["platforms"]]
        secure = set(manifest["capture_contract"]["secure_scene_ids"]) & set(scenes)
        self.assertEqual((58, {"windows-uac"}), (len(scenes), secure), "57 hosted-capable scenes plus the UAC scene of an owned clone")
        for scene in scenes:
            self.assertTrue((REPOSITORY / visual.BASELINES / (scene + ".png")).exists(), scene)

    def test_the_row_driver_names_the_producer_instead_of_an_incomplete_set(self):
        with self.assertRaises(windows.NativeScenarioWindowsError) as caught:
            windows.matrix_observation(REPOSITORY, "windows-visual", ["00000000-0000-4000-8000-000000000000"], REVIEW)
        self.assertEqual("windows_matrix_other_producer:agent_tools/windows_visual_matrix.py", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
