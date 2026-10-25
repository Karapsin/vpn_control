"""Inert candidate evidence tests; no Mac/framework/VM/collector execution."""
import copy
from dataclasses import replace
import unittest
from uuid import uuid4

from agent_tools import readiness
from agent_tools import readiness_tart_macos_idle as idle


class MacIdleReviewTests(unittest.TestCase):
    def setUp(self):
        self.binding = idle.IdleBinding("owned-mac-census", str(uuid4()), str(uuid4()),
                                        502, 42, "darwin:123456:120")
        self.expected = {name: ((1, index+2), (1, index+20))
                         for index, name in enumerate(("guest-jobs", "gui-leases"))}
        observer = {"pid": 42, "uid": 0, "birth": "darwin:123456:120", "executableRole": "verified_probe"}
        self.packet = {"schemaVersion": 1, "machine": self.binding.machine, "boot": self.binding.boot,
                       "observerUid": 0, "first": [dict(observer)], "second": [dict(observer)],
                       "namespaces": {name: {"generation": list(gens[0]), "admissionGeneration": list(gens[1]),
                           "visibilityComplete": True, "jobs": [], "idle": True} for name, gens in self.expected.items()}}
        self.host = {"visibility": frozenset({"reservations", "lifecycle_phases", "operators"}), "blockers": frozenset()}

    def review(self):
        return idle.review(self.packet, self.binding, expected_namespaces=self.expected, host=self.host)

    def process(self, role="unmanaged", pid=55):
        return {"pid": pid, "uid": 502, "birth": "darwin:123457:121", "executableRole": role}

    def terminal(self):
        operation = str(uuid4())
        binding = {"target": self.binding.target, "machine": self.binding.machine,
                   "boot": self.binding.boot, "account": str(self.binding.ordinary_uid)}
        owner = {"pid": 123, "birth": "darwin:123450:321"}
        stream = {"overflow": False, "retainedBytes": 1, "totalBytes": 1, "sha256": "a"*64}
        return {"schemaVersion": 1, "operationId": operation, "state": "terminal", "reason": "correlated_terminal",
                "replayAllowed": False, "binding": binding, "owner": owner,
                "terminal": {"operationId": operation, "generation": str(uuid4()), "binding": dict(binding),
                    "programSha256": "b"*64, "owner": dict(owner), "exitCode": 0, "streamsClosed": True,
                    "stdout": dict(stream), "stderr": dict(stream)}}

    def test_seven_candidate_categories_never_claim_native_idle(self):
        value = self.review()
        self.assertEqual(readiness.IDLE_VISIBILITY, value["candidateVisibility"])
        self.assertEqual(frozenset(), value["candidateBlockers"])
        self.assertEqual(frozenset(), value["missingCategories"])
        self.assertFalse(idle.NATIVE_QUALIFIED)
        self.assertIs(value["nativeQualified"], False); self.assertIs(value["nativeIdle"], False)
        self.assertEqual({"native_producer_unqualified"}, value["reasons"])
        self.assertNotIn("visibility", value, "diagnostic candidates cannot be consumed as a readiness projection")

    def test_unmanaged_service_remains_unknown_even_root_owned(self):
        for uid in (0, 502):
            with self.subTest(uid=uid):
                row = {**self.process(), "uid": uid}
                self.packet["first"].append(row); self.packet["second"].append(dict(row))
                value = self.review()
                self.assertTrue({"running_jobs", "unknown_jobs"} <= value["candidateBlockers"])
                self.assertIn("process_service_activity_unqualified", value["reasons"])
                self.assertIs(value["nativeIdle"], False)
                self.packet["first"].pop(); self.packet["second"].pop()

    def test_transient_protected_and_installer_observations_override_later_role(self):
        self.packet["first"].extend([self.process("protected_runtime", 55), self.process("installer", 56)])
        self.packet["second"].extend([self.process("unmanaged", 55), self.process("unmanaged", 56)])
        value = self.review()
        self.assertTrue({"protected_processes", "installers", "running_jobs", "unknown_jobs"} <= value["candidateBlockers"])
        self.assertTrue({"protected_processes", "installers"} <= value["missingCategories"])
        self.assertIn("process_generation_or_census_changed", value["reasons"])

    def test_observer_requires_exact_root_generation_and_unique_role(self):
        for field, value in (("uid", 502), ("birth", "darwin:123457:120")):
            with self.subTest(field=field):
                original = self.packet["second"][0][field]; self.packet["second"][0][field] = value
                with self.assertRaises(idle.MacIdleError): self.review()
                self.packet["second"][0][field] = original
        self.packet["first"].append(self.process("verified_probe")); self.packet["second"].append(self.process("verified_probe"))
        with self.assertRaisesRegex(idle.MacIdleError, "macos_idle_observer_identity_changed"): self.review()

    def test_target_boot_and_account_binding_is_finite_and_exact(self):
        for field in ("machine", "boot"):
            original = self.packet[field]; self.packet[field] = str(uuid4())
            with self.assertRaisesRegex(idle.MacIdleError, "macos_idle_census_identity_changed"): self.review()
            self.packet[field] = original
        with self.assertRaises(idle.MacIdleError): replace(self.binding, ordinary_uid=True)
        with self.assertRaises(idle.MacIdleError): replace(self.binding, observer_birth="reused")

    def test_missing_host_visibility_and_competing_operator_remain_blockers(self):
        self.host = {"visibility": frozenset({"operators"}), "blockers": frozenset({"operators"})}
        value = self.review()
        self.assertTrue({"reservations", "lifecycle_phases"} <= value["missingCategories"])
        self.assertIn("operators", value["candidateBlockers"])
        self.host = {"visibility": readiness.IDLE_VISIBILITY, "blockers": frozenset()}
        with self.assertRaisesRegex(idle.MacIdleError, "macos_idle_host_projection_invalid"): self.review()

    def test_missing_namespace_never_means_no_jobs(self):
        del self.packet["namespaces"]["gui-leases"]
        value = self.review()
        self.assertIn("unknown_jobs", value["candidateBlockers"])
        self.assertTrue({"running_jobs", "unknown_jobs"} <= value["missingCategories"])
        self.assertIn("namespace_visibility_incomplete", value["reasons"])

    def test_namespace_root_and_admission_generation_changes_refuse(self):
        for field in ("generation", "admissionGeneration"):
            original = self.packet["namespaces"]["guest-jobs"][field]
            self.packet["namespaces"]["guest-jobs"][field] = [99, 99]
            with self.assertRaisesRegex(idle.MacIdleError, "macos_idle_namespace_changed"): self.review()
            self.packet["namespaces"]["guest-jobs"][field] = original

    def test_running_unknown_and_unsubmitted_jobs_block_without_replay(self):
        for state in ("running", "unknown", "unsubmitted"):
            with self.subTest(state=state):
                row = {
                    "schemaVersion": 1, "operationId": str(uuid4()), "state": state,
                    "reason": "original_owner_missing", "replayAllowed": False}
                if state == "running":
                    row.update(binding={"target": self.binding.target, "machine": self.binding.machine,
                                        "boot": self.binding.boot, "account": str(self.binding.ordinary_uid)},
                               owner={"pid": 123, "birth": "darwin:123450:321"})
                self.packet["namespaces"]["guest-jobs"].update(idle=False, jobs=[row])
                result = self.review()
                self.assertIn("running_jobs" if state == "running" else "unknown_jobs", result["candidateBlockers"])
                self.assertNotIn("replayAllowed", result)

    def test_terminal_requires_exact_original_binding_owner_and_closed_streams(self):
        original = self.terminal()
        self.packet["namespaces"]["guest-jobs"]["jobs"] = [original]
        self.assertEqual(frozenset(), self.review()["candidateBlockers"])
        # Collected terminal history keeps its original boot; active/UNKNOWN
        # generations never become terminal just because the guest rebooted.
        original["binding"]["boot"] = original["terminal"]["binding"]["boot"] = str(uuid4())
        self.assertEqual(frozenset(), self.review()["candidateBlockers"])
        mutations = (("streamsClosed", False), ("owner", {"pid": 999, "birth": "darwin:123450:321"}),
                     ("stdout", {**original["terminal"]["stdout"], "overflow": True}),
                     ("stderr", {**original["terminal"]["stderr"], "totalBytes": 2}))
        for field, value in mutations:
            changed = copy.deepcopy(original); changed["terminal"][field] = value
            self.packet["namespaces"]["guest-jobs"]["jobs"] = [changed]
            with self.subTest(field=field), self.assertRaises(idle.MacIdleError): self.review()

    def test_duplicate_operation_and_false_idle_claim_refuse(self):
        row = self.terminal(); self.packet["namespaces"]["guest-jobs"]["jobs"] = [row, copy.deepcopy(row)]
        with self.assertRaisesRegex(idle.MacIdleError, "macos_idle_duplicate_job"): self.review()
        self.packet["namespaces"]["guest-jobs"]["jobs"] = []
        self.packet["namespaces"]["guest-jobs"]["idle"] = False
        with self.assertRaisesRegex(idle.MacIdleError, "macos_idle_namespace_changed"): self.review()

    def test_unexpected_private_fields_never_enter_role_or_error_output(self):
        marker = "PRIVATE-ARGUMENT-OR-PATH-MARKER"
        for field in ("argv", "path", "argvSha256", "argvLength", "knownApple"):
            row = {**self.process(), field: marker}; self.packet["first"].append(row)
            with self.subTest(field=field), self.assertRaises(idle.MacIdleError) as error: self.review()
            self.assertNotIn(marker, str(error.exception))
            self.assertNotIn(field, str(error.exception))
            self.packet["first"].pop()


if __name__ == "__main__": unittest.main()
