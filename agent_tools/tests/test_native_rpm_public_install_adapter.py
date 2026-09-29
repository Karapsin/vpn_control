from __future__ import annotations

import unittest
import uuid
import json

from agent_tools import native_rpm_public_install_adapter as subject


class Driver:
    def __init__(self): self.calls = []
    def submit(self, intent):
        self.calls.append(("start", intent))
        return {"state": "submitted", "correlationId": intent.correlation_id}
    def status(self, correlation):
        self.calls.append(("status", correlation))
        return {"state": "terminal", "exitCode": 0, "correlationId": correlation}
    def collect(self, correlation):
        self.calls.append(("collect", correlation))
        return {"state": "terminal", "exitCode": 0, "correlationId": correlation, "scenarioEvidence": {
            "correlationId": correlation, "result": "passed", "operationId": "operation-17",
            "protectedJobId": "job-17", "rpmVerifyClean": True, "credentialRestored": True,
            "cleanup": {"state": "complete", "ownerStopped": True, "protectedPreserved": True,
                        "workspaceRemoved": True}}}


class RpmPublicInstallAdapterTest(unittest.TestCase):
    def request(self):
        correlation = str(uuid.uuid4())
        return {"scenarioId": subject.SCENARIO_ID, "host": "fedora", "environment": "owned",
                "bundleHash": "a" * 64, "artifactIds": {"bundleManifest": "sha256-" + "a" * 64,
                "scenarioInput": "sha256-" + "b" * 64, "sourceFixture": "sha256-" + "c" * 64,
                "targetPackage": "sha256-" + "d" * 64}, "credentialHandle": "fixture-auth-17",
                "correlationId": correlation}

    def test_start_binds_exact_artifacts_and_redacts_credential_handle(self):
        driver = Driver(); request = self.request()
        result = subject.RpmPublicInstallAdapter(driver).start(request)
        self.assertEqual("submitted", result["state"])
        intent = driver.calls[0][1]
        self.assertEqual(request["artifactIds"], intent.artifact_ids)
        self.assertNotIn("credentialHandle", intent.public_mapping())

    def test_invalid_source_package_binding_rejects_before_driver(self):
        driver = Driver(); request = self.request(); request["artifactIds"]["targetPackage"] = "sha256-" + "A" * 64
        with self.assertRaises(subject.RpmPublicInstallAdapterError):
            subject.RpmPublicInstallAdapter(driver).start(request)
        self.assertEqual([], driver.calls)

    def test_collection_requires_exact_correlation_and_typed_terminal_recovery(self):
        driver = Driver(); adapter = subject.RpmPublicInstallAdapter(driver); correlation = self.request()["correlationId"]
        self.assertTrue(adapter.collect(correlation)["scenarioEvidence"]["credentialRestored"])
        driver.collect = lambda _correlation: {"state": "terminal", "correlationId": _correlation}
        with self.assertRaisesRegex(subject.RpmPublicInstallAdapterError, "exact terminal"):
            adapter.collect(correlation)

    def test_terminal_pre_operation_failure_collects_without_inventing_job(self):
        driver = Driver(); correlation = self.request()["correlationId"]
        driver.collect = lambda _: {"state": "terminal", "correlationId": correlation, "exitCode": 1,
                                    "scenarioEvidence": None, "failurePhase": "guest-admission"}
        result = subject.RpmPublicInstallAdapter(driver).collect(correlation)
        self.assertEqual("failed", result["scenarioEvidence"]["result"])
        self.assertEqual("guest-admission", result["scenarioEvidence"]["failurePhase"])
        self.assertNotIn("operationId", result["scenarioEvidence"])
        driver.collect = lambda _: {"state": "terminal", "correlationId": correlation,
                                    "exitCode": 1, "scenarioEvidence": None,
                                    "failurePhase": "guest-admission",
                                    "guestAdmissionDiagnostic": "protected-intent-differs",
                                    "guestAdmissionField": "bundleHash",
                                    "privatePath": "/secret"}
        result = subject.RpmPublicInstallAdapter(driver).collect(correlation)
        self.assertEqual("protected-intent-differs", result["guestAdmissionDiagnostic"])
        self.assertEqual("bundleHash", result["guestAdmissionField"])
        self.assertNotIn("privatePath", result)

    def test_terminal_cleanup_failure_exposes_only_fixed_kind(self):
        correlation = self.request()["correlationId"]
        driver = Driver()
        original = driver.collect(correlation)
        original["exitCode"] = 1
        original["scenarioEvidence"]["result"] = "failed"
        original["scenarioEvidence"]["cleanup"]["state"] = "preserved-for-recovery"
        original["scenarioEvidence"]["cleanup"]["workspaceRemoved"] = False
        original["cleanupFailureKind"] = "process-observation-unavailable"
        original["privatePath"] = "/tmp/secret"
        driver.collect = lambda _: original
        result = subject.RpmPublicInstallAdapter(driver).collect(correlation)
        self.assertEqual("process-observation-unavailable", result["cleanupFailureKind"])
        self.assertNotIn("privatePath", result)

    def test_passed_receipt_cannot_claim_unverified_cleanup(self):
        driver = Driver(); correlation = self.request()["correlationId"]
        original = driver.collect(correlation)
        original["scenarioEvidence"]["credentialRestored"] = False
        driver.collect = lambda _: original
        with self.assertRaisesRegex(subject.RpmPublicInstallAdapterError, "verified cleanup"):
            subject.RpmPublicInstallAdapter(driver).collect(correlation)

    def test_passed_collection_requires_integer_zero_exit(self):
        driver = Driver(); correlation = self.request()["correlationId"]
        original = driver.collect(correlation)
        for code in (None, False, True, 1, 130):
            with self.subTest(code=code):
                value = {**original, "exitCode": code}
                driver.collect = lambda _, value=value: value
                with self.assertRaises(subject.RpmPublicInstallAdapterError):
                    subject.RpmPublicInstallAdapter(driver).collect(correlation)

    def test_failed_collection_does_not_forward_untyped_cleanup_data(self):
        driver = Driver(); correlation = self.request()["correlationId"]
        original = driver.collect(correlation)
        original.update(exitCode=1)
        original["scenarioEvidence"].update(result="failed", cleanup={
            "state": "private sentinel", "ownerStopped": {"private": "sentinel"},
            "protectedPreserved": "private sentinel", "workspaceRemoved": []})
        driver.collect = lambda _: original
        result = subject.RpmPublicInstallAdapter(driver).collect(correlation)
        self.assertNotIn("sentinel", json.dumps(result))
        self.assertEqual({"state": "unknown", "ownerStopped": None,
                          "protectedPreserved": None, "workspaceRemoved": None},
                         result["scenarioEvidence"]["cleanup"])

    def test_canonical_input_binds_fixture_target_and_password_preservation(self):
        request = self.request(); intent = subject.RpmPublicInstallIntent.from_mapping(request)
        value = {"schema": subject.INPUT_SCHEMA, "schemaVersion": 1, "scenarioId": subject.SCENARIO_ID,
                 "host": intent.host, "environment": intent.environment, "correlationId": intent.correlation_id,
                 "sourceFixtureSha256": "c" * 64, "targetPackageSha256": "d" * 64,
                 "sourceFingerprint": "e" * 64, "expectedBaseNevra": "vpn-control-2.1.16-1.x86_64",
                 "expectedTargetNevra": "vpn-control-2.1.17-1.x86_64", "expectedDesktopJarSha256": "f" * 64,
                 "expectedBaseVersion": "2.1.16", "expectedTargetVersion": "2.1.17",
                 "fixtureHttpsOrigin": "https://github.com", "productionTrustChanged": False,
                 "preservePasswordBaseline": True}
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        self.assertEqual(value, subject.parse_scenario_input(raw, intent))
        for version in (True, 1.0):
            with self.subTest(schemaVersion=version):
                invalid = {**value, "schemaVersion": version}
                with self.assertRaises(subject.RpmPublicInstallAdapterError):
                    subject.parse_scenario_input((json.dumps(invalid, sort_keys=True, separators=(",", ":")) + "\n").encode(), intent)
        value["targetPackageSha256"] = "a" * 64
        with self.assertRaisesRegex(subject.RpmPublicInstallAdapterError, "artifact digest"):
            subject.parse_scenario_input((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(), intent)


if __name__ == "__main__":
    unittest.main()
