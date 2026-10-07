"""Causal finite-output tests for the CP117 source campaign MCP boundary."""
from __future__ import annotations

import unittest

from agent_tools import windows_cp117_source_campaign as campaign
from agent_tools import windows_cp117_source_projection as projection


LEASE = "f18df6cb-2c43-4265-b1ba-4bbadf9b708a"


def flags(product: bool = False) -> dict[str, object]:
    return {"replayAllowed": False, "nativeActionAllowed": False, "productAction": product}


class SourceProjectionTests(unittest.TestCase):
    def test_reservation_blockers_are_finite_and_private_data_rejected(self):
        base={"state":"observed","newIntent":"absent","historical":"present","knownRecordCount":7,**flags()}
        for item,expected in (({"record":"transfer-recovery","phase":"closure-or-absence"},True),
                              ({"record":"private-path","phase":"closure"},False),
                              ({"record":"c32","phase":"unknown","path":"private"},False)):
            value=projection.project("reservation-diagnose",{**base,"blockers":[item]})
            self.assertEqual(expected,value["ok"])
            self.assertNotIn("path",value)

    def test_green_projects_only_fixed_ready_plan(self):
        result = {"state": "ready", "leaseId": LEASE, "sourceSha": campaign._SOURCE,
                  "fixtureReceiptArtifactId": campaign._RECEIPT, "baseMsiArtifactId": campaign._BASE,
                  "targetMsiArtifactId": campaign._TARGET, "retiredLeaseId": campaign._OLD_LEASE,
                  "retiredStageCorrelationId": campaign._OLD_STAGE, "baseInstallRequired": True,
                  "generalBaseRouteAllowed": False, "nextAction": "source-bound-base-install",
                  "sourceBaseInstallInputs": {"host": "archlinux", "correlationId": LEASE,
                                               "sourceSha": campaign._SOURCE,
                                               "fixtureReceiptArtifactId": campaign._RECEIPT,
                                               "baseMsiArtifactId": campaign._BASE,
                                               "targetMsiArtifactId": campaign._TARGET,
                                               "expectedCurrentVersion": campaign._BASE_VERSION}, **flags()}
        self.assertTrue(projection.project("preflight", result)["ok"])
        self.assertEqual("unknown", projection.project("preflight", {**result, "baseInstallRequired": False})["state"])

    def test_start_and_finish_keep_their_real_success_states(self):
        start = projection.project("start", {"state": "submitted", "correlationId": LEASE, **flags(True)})
        finish = projection.project("finish", {"state": "active", "leaseId": LEASE, "replayAllowed": False})
        self.assertTrue(start["ok"]); self.assertTrue(start["productAction"])
        self.assertTrue(finish["ok"]); self.assertFalse(finish["productAction"])
        self.assertEqual("unknown", projection.project("start", {"state": "submitted", "correlationId": LEASE, **flags()})["state"])

    def test_parser_failed_is_observed_but_not_successful(self):
        value = {"state": "failed", "correlationId": LEASE,
                 "checks": ["ps5-parse", "gzip", "embedded-task", "action-hash"], **flags()}
        observed = projection.project("parser", value)
        self.assertEqual("failed", observed["state"]); self.assertFalse(observed["ok"])
        self.assertEqual("unknown", projection.project("parser", {**value, "checks": []})["state"])

    def test_status_and_terminal_cannot_carry_unchecked_fields(self):
        running = projection.project("status", {"state": "running", "correlationId": LEASE, **flags(True)})
        terminal = {"state": "terminal", "correlationId": LEASE, "result": "PASSED", "stage": "READBACK",
                    "exitCode": 0, "sourceSha": campaign._SOURCE, "baseArtifactId": campaign._BASE,
                    "replayAllowed": False}
        self.assertTrue(running["ok"]); self.assertFalse(running["productAction"])
        self.assertTrue(projection.project("terminal-reconcile", terminal)["ok"])
        self.assertTrue(projection.project("status", {**terminal, "nativeActionAllowed": False,
                                                       "productAction": True})["ok"])
        self.assertEqual("unknown", projection.project("status", {**running, "secret": "x"})["state"])
        self.assertEqual("unknown", projection.project("terminal-reconcile", {**terminal, "exitCode": False})["state"])

    def test_diagnose_retains_only_bounded_base_checkpoint(self):
        value = {"state": "diagnosed", "correlationId": LEASE, "binding": "exact",
                 "checkpoint": "qga-protocol", "replayAllowed": False, "nativeActionAllowed": False}
        projected = projection.project("diagnose", value)
        self.assertTrue(projected["ok"]); self.assertFalse(projected["productAction"])
        self.assertEqual("unknown", projection.project("diagnose", {**value, "checkpoint": "private-path"})["state"])

    def test_actual_base_unknown_diagnostic_preserves_finite_missing_fact(self):
        value = projection.base._diagnostic_result(LEASE, "unverified", "qga-protocol")
        observed = projection.project("diagnose", value)
        self.assertEqual("qga-protocol", observed["checkpoint"])
        self.assertEqual("unverified", observed["binding"])
        self.assertFalse(observed["ok"])
        self.assertFalse(observed["productAction"])
        for changed in ({"privatePath": "secret"}, {"checkpoint": "private-path"},
                        {"binding": "exact", "checkpoint": "descriptor"}):
            self.assertNotIn("checkpoint", projection.project("diagnose", {**value, **changed}))

    def test_source_diagnostic_keeps_finite_pre_dispatch_phase(self):
        value = {"state": "observed", "correlationId": LEASE,
                 "phase": "legacy-tasks", **flags()}
        self.assertEqual("legacy-tasks", projection.project("diagnose", value).get("phase"))
        self.assertFalse(projection.project("diagnose", value)["productAction"])
        for change in ({"phase": "private-path"}, {"secret": "x"}, {"productAction": True}):
            self.assertNotIn("phase", projection.project("diagnose", {**value, **change}))

    def test_legacy_task_counts_are_diagnostic_only_and_bounded(self):
        counts = {"legacy": 0, "c32": 1, "recovery": 1, "retirement": 1,
                  "other": 0, "activeInstallerCount": 0}
        value = {"state": "observed", "correlationId": LEASE, "phase": "legacy-tasks",
                 "legacyTaskState": "observed", "legacyTasks": counts, **flags()}
        self.assertEqual(counts, projection.project("diagnose", value).get("legacyTasks"))
        for change in ({"phase": "pre-effect"}, {"legacyTaskState": "reviewed-terminal"},
                       {"legacyTasks": {**counts, "other": True}},
                       {"legacyTasks": {**counts, "c32": 2}},
                       {"legacyTasks": {**counts, "other": 1001}}):
            self.assertNotIn("legacyTasks", projection.project("diagnose", {**value, **change}))

    def test_other_task_identities_are_finite_unique_and_count_matched(self):
        counts = {"legacy": 0, "c32": 1, "recovery": 1, "retirement": 0,
                  "other": 1, "activeInstallerCount": 0}
        item = {"purpose": "fixture-server", "correlationId": LEASE, "taskState": "ready"}
        value = {"state": "observed", "correlationId": LEASE, "phase": "legacy-tasks",
                 "legacyTaskState": "observed", "legacyTasks": counts,
                 "legacyTaskIdentities": [item], "unclassifiedTaskCount": 0, **flags()}
        self.assertEqual([item], projection.project("diagnose", value).get("legacyTaskIdentities"))
        for change in ({"legacyTaskIdentities": [item, item]},
                       {"unclassifiedTaskCount": True},
                       {"unclassifiedTaskCount": 1},
                       {"legacyTaskIdentities": [{**item, "purpose": "arbitrary"}]},
                       {"legacyTaskIdentities": [{**item, "taskState": "terminal"}]},
                       {"legacyTaskIdentities": [{**item, "rawName": "secret"}]}):
            self.assertNotIn("legacyTaskIdentities", projection.project("diagnose", {**value, **change}))

    def test_unknown_correlation_and_fixed_preflight_block_are_retained_without_authorization(self):
        unknown = projection.project("start", {"state": "unknown", "correlationId": LEASE, **flags()})
        self.assertEqual(LEASE, unknown["correlationId"]); self.assertFalse(unknown["ok"])
        blocked = projection.project("preflight", {"state": "blocked", "reason": "base-not-idle", **flags()})
        self.assertEqual("blocked", blocked["state"]); self.assertFalse(blocked["ok"])

    def test_diagnose_retains_bounded_guest_proof_only_at_its_known_checkpoint(self):
        proof = {"task": "absent", "leaf": "absent", "result": "absent", "correlationPowerShell": "absent",
                 "product": "single", "installedVersion": "2.1.19", "installer": "absent"}
        value = {"state": "diagnosed", "correlationId": LEASE, "binding": "exact",
                 "checkpoint": "remote-dispatch-absent", "replayAllowed": False, "nativeActionAllowed": False,
                 "guestProof": proof, "guestProofFailure": "none", "guestProofFailurePhase": "none",
                 "guestProofProjectionReason": "none"}
        self.assertTrue(projection.project("diagnose", value)["ok"])
        self.assertEqual("unknown", projection.project("diagnose", {**value, "privatePath": "x"})["state"])
        self.assertEqual("unknown", projection.project("diagnose", {**value, "guestProofFailurePhase": "private-phase"})["state"])

    def test_red_unhashable_enum_values_fail_closed_at_the_public_boundary(self):
        """Every enum projection rejects untrusted containers without raising."""
        ready_block = {"state": "blocked", "reason": ["base-not-idle"], **flags()}
        parser = {"state": ["passed"], "correlationId": LEASE,
                  "checks": ["ps5-parse", "gzip", "embedded-task", "action-hash"], **flags()}
        observed = {"state": "observed", "correlationId": LEASE, "phase": ["legacy-tasks"], **flags()}
        diagnosed = {"state": "diagnosed", "correlationId": LEASE, "binding": ["exact"],
                     "checkpoint": "qga-protocol", "replayAllowed": False, "nativeActionAllowed": False}
        diagnosed_checkpoint = {**diagnosed, "binding": "exact", "checkpoint": {"qga-protocol": True}}
        proof = {"task": "absent", "leaf": "absent", "result": "absent",
                 "correlationPowerShell": "absent", "product": "absent", "installedVersion": None,
                 "installer": "absent"}
        remote_proof = {"state": "diagnosed", "correlationId": LEASE, "binding": "exact",
                        "checkpoint": "remote-dispatch-absent", "replayAllowed": False,
                        "nativeActionAllowed": False, "guestProof": proof,
                        "guestProofFailure": "none", "guestProofFailurePhase": "none",
                        "guestProofProjectionReason": "none"}
        unknown_diagnostic = {"state": "unknown", "correlationId": LEASE, "binding": ["exact"],
                              "checkpoint": "qga-protocol", "replayAllowed": False,
                              "nativeActionAllowed": False}
        reservation = {"state": "observed", "newIntent": ["absent"], "historical": "present", **flags()}
        cases = (("preflight", ready_block), ("parser", parser), ("diagnose", observed),
                 ("diagnose", diagnosed), ("diagnose", diagnosed_checkpoint),
                 ("diagnose", unknown_diagnostic),
                 *(("diagnose", {**remote_proof, "guestProof": {**proof, field: ["invalid"]}})
                   for field in ("task", "leaf", "result", "correlationPowerShell", "installer", "product")),
                 *(("diagnose", {**remote_proof, field: {"invalid": True}})
                   for field in ("guestProofFailure", "guestProofFailurePhase", "guestProofProjectionReason")),
                 ("reservation-diagnose", reservation),
                 ("reservation-diagnose", {**reservation, "newIntent": "absent", "historical": {"present": True}}),
                 (["diagnose"], {}))
        for action, value in cases:
            with self.subTest(action=action, value=value):
                self.assertEqual(projection.unknown(), projection.project(action, value))


if __name__ == "__main__":
    unittest.main()

class ReservationProjectionTests(unittest.TestCase):
    def test_pre_effect_reservation_block_remains_blocked(self):
        from agent_tools import windows_cp117_source_projection as projection
        value={'state':'blocked','phase':'reservation','correlationId':'67eeeedb-a618-42d5-8e31-821650d16302','replayAllowed':False,'nativeActionAllowed':False,'productAction':False}
        self.assertEqual('blocked',projection.project('start',value)['state'])
    def test_reservation_diagnostic_rejects_unknown_fields(self):
        from agent_tools import windows_cp117_source_projection as projection
        value={'state':'observed','newIntent':'absent','historical':'present','knownRecordCount':7,'replayAllowed':False,'nativeActionAllowed':False,'productAction':False}
        self.assertEqual('observed',projection.project('reservation-diagnose',value)['state'])
        self.assertEqual('unknown',projection.project('reservation-diagnose',{**value,'privatePath':'secret'})['state'])

class Source67ArchiveProjectionTests(unittest.TestCase):
    def test_nine_known_records_with_fixed67_blocker_stays_finite(self):
        value = {"state": "observed", "newIntent": "absent", "historical": "present",
                 "knownRecordCount": 9,
                 "blockers": [{"record": "source-pre-effect", "phase": "verified"}],
                 **flags()}
        projected = projection.project("reservation-diagnose", value)
        self.assertEqual("observed", projected["state"])
        self.assertTrue(projected["ok"])

    def test_all_historical_and_fixed67_blockers_fit_the_closed_union(self):
        blockers = [{"record": "c32", "phase": "unknown"},
                    {"record": "pre-effect", "phase": "closure"},
                    {"record": "transfer-recovery", "phase": "archived"},
                    {"record": "unknown-closure", "phase": "archived"},
                    {"record": "source-pre-effect", "phase": "verified"}]
        value = {"state": "observed", "newIntent": "absent", "historical": "present",
                 "knownRecordCount": 10, "blockers": blockers, **flags()}
        self.assertTrue(projection.project("reservation-diagnose", value)["ok"])
        self.assertEqual("unknown", projection.project("reservation-diagnose", {**value, "knownRecordCount": 11})["state"])

    def test_source67_blocker_is_a_closed_finite_shape(self):
        base = {"state": "observed", "newIntent": "absent", "historical": "present",
                "knownRecordCount": 9, **flags()}
        for blocker in ({"record": "source-pre-effect", "phase": "fresh"},
                        {"record": "source-pre-effect", "phase": "foreign"},
                        {"record": "source-pre-effect", "phase": "verified", "private": "x"},
                        {"record": "foreign", "phase": "verified"}):
            with self.subTest(blocker=blocker):
                projected = projection.project("reservation-diagnose", {**base, "blockers": [blocker]})
                self.assertEqual(blocker["phase"] in {"fresh"}, projected["state"] == "observed")
