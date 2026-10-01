"""Fail-closed tests for the CP117 fixture TLS inventory boundary."""
from __future__ import annotations

import copy
import contextlib
import base64
import gzip
from datetime import datetime, timezone
import hashlib
import io
import json
import os
import re
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import windows_fixture_credentials as credentials
from agent_tools import ssh_transport


LEASE = "11111111-1111-4111-8111-111111111111"
STAGE = "22222222-2222-4222-8222-222222222222"
PROVISION = "33333333-3333-4333-8333-333333333333"
CORR = "44444444-4444-4444-8444-444444444444"
SID = "S-1-5-21-1-2-3-1001"
BINDING = {"leaseId": LEASE, "stageCorrelationId": STAGE, "sourceSha": "a" * 40,
           "sourceFingerprint": "b" * 64, "fixtureReceiptArtifactId": "sha256-" + "c" * 64,
           "baseMsiArtifactId": "sha256-" + "d" * 64,
           "targetMsiArtifactId": "sha256-" + "e" * 64,
           "socketPath": "/owned/cp117.qga", "qemuPid": 123, "startTicks": 456,
           "originalSid": SID, "sessionId": 1, "limited": True}


def acl(path, *, directory=False):
    return {"path": path, "protected": True, "aces": [
        {"sid": sid, "rights": 0x1F01FF, "type": "Allow", "inherited": False,
         "inheritance": 3 if directory else 0, "propagation": 0}
        for sid in ("S-1-5-18", "S-1-5-32-544", SID)]}


def observation():
    paths = credentials._fixed_paths(STAGE)
    return {**BINDING, "schemaVersion": 1, "provisionId": PROVISION,
            "paths": paths, "fileSha256": {"certificate": "1" * 64,
            "privateKey": "2" * 64, "trustStore": "3" * 64},
            "peerCertificateSha256": "4" * 64, "certificateDnsNames": ["github.com"],
            "certificateServerAuth": True, "certificateValidFromUtc": 100,
            "certificateValidUntilUtc": 200, "privateKeyMatchesCertificate": True,
            "trustStoreType": "PKCS12", "trustStoreContainsCertificate": True,
            "trustStoreAlias": "vpn-control-fixture-github",
            "acls": {name: acl(path, directory=name == "directory") for name, path in paths.items()}}


class WindowsFixtureCredentialsTest(unittest.TestCase):
    def test_server_join_selects_only_unaborted_provision_with_same_binding(self):
        old_a = "6161b4ae-3634-4312-ac85-1bacd0001dfa"
        old_b = "791b5235-9ca7-409c-96bc-c341047c7fb4"
        current = "75ed6f9c-ebe6-4f70-ba1a-ab64b8507d16"
        names = (old_a, old_b, current)
        records = {name: {"request": {"host": "archlinux", "leaseId": LEASE,
                                     "stageCorrelationId": STAGE, "correlationId": name},
                          "binding": BINDING} for name in names}
        aborts = {name: {"request": records[name]["request"], "binding": BINDING,
                         "provisionCorrelationId": name} for name in names[:2]}
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary)
            group = root / credentials._GROUP; group.mkdir(parents=True)
            for name in names: (group / (name + ".json")).write_text("{}")
            with patch.object(credentials, "_read_intent", side_effect=lambda _root, name: records[name]), \
                 patch.object(credentials, "_cleanup_intent", side_effect=lambda _root, name, **_kw: aborts.get(name)):
                self.assertEqual(current, credentials._provision_record(root, BINDING)["request"]["correlationId"])

    def test_journal_is_exclusive_private_and_contains_no_key_material(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": {"certificate": "1" * 64,
                  "privateKey": "2" * 64, "trustStore": "3" * 64},
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary)
            credentials._reserve(root, record)
            path = root / credentials._GROUP / (CORR + ".json")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(credentials._read_intent(root, CORR), record)
            self.assertNotIn("PRIVATE KEY", path.read_text())
            with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                credentials._reserve(root, record)

    def test_new_campaign_requires_terminal_closed_prior_journal(self):
        first = {"schemaVersion": 1, "request": {"host": "archlinux", "leaseId": LEASE,
                    "stageCorrelationId": STAGE, "correlationId": CORR}, "binding": BINDING,
                 "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                 "peerCertificateSha256": "4" * 64,
                 "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        new_lease = "55555555-5555-4555-8555-555555555555"
        new_corr = "66666666-6666-4666-8666-666666666666"
        second = copy.deepcopy(first)
        second["request"]["leaseId"] = new_lease
        second["request"]["correlationId"] = new_corr
        second["binding"]["leaseId"] = new_lease
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary)
            credentials._reserve(root, first)
            with patch.object(credentials.lease, "inspect", return_value={"state": "unknown"}):
                with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                    credentials._reserve(root, second)
            with patch.object(credentials.lease, "inspect", return_value={"state": "closed"}):
                credentials._reserve(root, second)
            self.assertEqual(credentials._read_intent(root, CORR), first)
            self.assertEqual(credentials._read_intent(root, new_corr), second)

    def test_new_campaign_admits_only_exact_same_lease_aborted_cleaned_provision(self):
        """A preserved stage lease may remain active after a verified abort."""
        first = {"schemaVersion": 1, "request": {"host": "archlinux", "leaseId": LEASE,
                    "stageCorrelationId": STAGE, "correlationId": CORR}, "binding": BINDING,
                 "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                 "peerCertificateSha256": "4" * 64,
                 "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        new_corr = "66666666-6666-4666-8666-666666666666"
        second = copy.deepcopy(first); second["request"]["correlationId"] = new_corr
        abort = {"schemaVersion": 1, "request": first["request"], "binding": BINDING,
                 "provisionCorrelationId": CORR}
        identity = {"leaseId": LEASE, "host": "archlinux", "environment": "windows-cp117",
                    "operator": "windows-base", "sourceSha": BINDING["sourceSha"],
                    "fixtureReceiptArtifactId": BINDING["fixtureReceiptArtifactId"],
                    "baseMsiArtifactId": BINDING["baseMsiArtifactId"],
                    "targetMsiArtifactId": BINDING["targetMsiArtifactId"],
                    "socketPath": BINDING["socketPath"], "qemuPid": BINDING["qemuPid"],
                    "startTicks": BINDING["startTicks"]}
        receipt = {"schemaVersion": 1, "credentialDirectoryAbsent": True, "taskAbsent": True,
                   "stagePresent": True, "stageCorrelationId": STAGE}
        evidence = hashlib.sha256(json.dumps(receipt, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest()

        def install_campaign(root, *, outcome="failed-cleaned", digest=evidence, active_identity=identity):
            directory, lock = credentials.lease._locked(root)
            os.close(lock)
            active = {"version": 1, "identity": active_identity, "sequence": 4, "state": "active",
                      "role": None, "correlationId": None, "server": "stopped",
                      "credentials": "absent", "lastEvidenceSha256": digest,
                      "lastOutcome": outcome}
            path = directory / "active.json"; path.write_text(json.dumps(active)); os.chmod(path, 0o600)

        for label, outcome, digest, abort_record, active_identity, admitted in (
                ("exact", "failed-cleaned", evidence, abort, identity, True),
                ("wrong-outcome", "succeeded", evidence, abort, identity, False),
                ("wrong-evidence", "failed-cleaned", "0" * 64, abort, identity, False),
                ("missing-abort", "failed-cleaned", evidence, None, identity, False),
                ("wrong-provision", "failed-cleaned", evidence,
                 {**abort, "provisionCorrelationId": PROVISION}, identity, False),
                ("wrong-generation", "failed-cleaned", evidence, abort,
                 {**identity, "startTicks": 999}, False)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = credentials.Path(temporary)
                credentials._reserve(root, first)
                install_campaign(root, outcome=outcome, digest=digest, active_identity=active_identity)
                if abort_record is not None:
                    credentials._reserve_cleanup(root, abort_record, group=credentials._ABORT_GROUP)
                if admitted:
                    credentials._reserve(root, second)
                    self.assertEqual(credentials._read_intent(root, new_corr), second)
                else:
                    with self.assertRaisesRegex(credentials.WindowsFixtureCredentialsError,
                                                "readback or cleanup"):
                        credentials._reserve(root, second)

    def test_abort_history_admits_only_current_held_same_lease_provision(self):
        """A prior completed abort cannot block aborting the next held attempt."""
        old = {"schemaVersion": 1, "request": {"host": "archlinux", "leaseId": LEASE,
               "stageCorrelationId": STAGE, "correlationId": CORR}, "binding": BINDING,
               "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
               "peerCertificateSha256": "4" * 64,
               "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        current_corr = "77777777-7777-4777-8777-777777777777"
        current = copy.deepcopy(old); current["request"]["correlationId"] = current_corr
        old_abort = {"schemaVersion": 1, "request": old["request"], "binding": BINDING,
                     "provisionCorrelationId": CORR}
        current_abort = {"schemaVersion": 1, "request": current["request"], "binding": BINDING,
                         "provisionCorrelationId": current_corr}
        identity = {"leaseId": LEASE, "host": "archlinux", "environment": "windows-cp117",
                    "operator": "windows-base", "sourceSha": BINDING["sourceSha"],
                    "fixtureReceiptArtifactId": BINDING["fixtureReceiptArtifactId"],
                    "baseMsiArtifactId": BINDING["baseMsiArtifactId"],
                    "targetMsiArtifactId": BINDING["targetMsiArtifactId"],
                    "socketPath": BINDING["socketPath"], "qemuPid": BINDING["qemuPid"],
                    "startTicks": BINDING["startTicks"]}
        receipt = {"schemaVersion": 1, "credentialDirectoryAbsent": True, "taskAbsent": True,
                   "stagePresent": True, "stageCorrelationId": STAGE}
        evidence = hashlib.sha256(json.dumps(receipt, sort_keys=True,
                                              separators=(",", ":")).encode()).hexdigest()

        def write_active(root, *, state, role, correlation, digest=evidence, active_identity=identity):
            directory, lock = credentials.lease._locked(root)
            os.close(lock)
            active = {"version": 1, "identity": active_identity, "sequence": 5, "state": state,
                      "role": role, "correlationId": correlation, "server": "stopped",
                      "credentials": "absent", "lastEvidenceSha256": digest,
                      "lastOutcome": "failed-cleaned"}
            path = directory / "active.json"; path.write_text(json.dumps(active)); os.chmod(path, 0o600)

        for label, state, role, correlation, digest, active_identity, admitted in (
                ("exact", "role-active", "credentials", current_corr, evidence, identity, True),
                ("idle", "active", None, None, evidence, identity, False),
                ("wrong-current", "role-active", "credentials", CORR, evidence, identity, False),
                ("wrong-evidence", "role-active", "credentials", current_corr, "0" * 64, identity, False),
                ("wrong-generation", "role-active", "credentials", current_corr, evidence,
                 {**identity, "startTicks": 999}, False)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = credentials.Path(temporary)
                credentials._reserve(root, old)
                write_active(root, state="active", role=None, correlation=None)
                credentials._reserve_cleanup(root, old_abort, group=credentials._ABORT_GROUP)
                credentials._reserve(root, current)
                write_active(root, state=state, role=role, correlation=correlation,
                             digest=digest, active_identity=active_identity)
                if admitted:
                    credentials._reserve_cleanup(root, current_abort, group=credentials._ABORT_GROUP)
                    self.assertEqual(credentials._cleanup_intent(root, current_corr,
                                     group=credentials._ABORT_GROUP), current_abort)
                else:
                    with self.assertRaisesRegex(credentials.WindowsFixtureCredentialsError,
                                                "cleanup needs readback"):
                        credentials._reserve_cleanup(root, current_abort, group=credentials._ABORT_GROUP)

    def test_public_request_rejects_paths_and_secrets(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        self.assertEqual(credentials._request(request), request)
        for extra in ({"privateKey": "secret"}, {"trustStorePath": r"C:\temp\trust.p12"}):
            with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                credentials._request({**request, **extra})

    def test_fixed_credential_sibling_preserves_empty_server_state_contract(self):
        paths = credentials._fixed_paths(STAGE)
        self.assertEqual(paths["directory"],
                         r"C:\Users\vpncp117\AppData\Local\VpnControl\mcp-update-credentials-" + STAGE)
        self.assertNotIn("server-state", repr(paths))
        self.assertIn("EXISTING_CREDENTIALS", credentials._guest_setup_script(paths, SID))
        self.assertIn("Get-ScheduledTask", credentials._guest_cleanup_script(paths, CORR))
        for program in (credentials._REMOTE_START, credentials._REMOTE_STATUS,
                        credentials._REMOTE_CLEANUP_START, credentials._REMOTE_CLEANUP_STATUS):
            compile(program, "remote", "exec")

    def test_system_precreates_and_verifies_provenance_acl_before_limited_owner_task(self):
        """Regression for CP117 result 1 after a limited owner created inherited provenance."""
        paths = credentials._fixed_paths(STAGE)
        finalize = credentials._guest_finalize_script(BINDING, observation(), paths, PROVISION, CORR)
        self.assertIn("[IO.File]::Exists($provenance) -or [IO.Directory]::Exists($provenance)", finalize)
        self.assertIn("[IO.File]::WriteAllBytes($provenance,[byte[]]@())", finalize)
        self.assertIn("Set-PrivateFileAcl $provenance", finalize)
        self.assertIn("throw 'FILE_ACL'", finalize)
        self.assertLess(finalize.index("[IO.File]::WriteAllBytes($provenance,[byte[]]@())"),
                        finalize.index("Register-ScheduledTask -TaskName $task"))
        packed = re.search(r"\$packed=\[Convert\]::FromBase64String\('([^']+)'\)", finalize)
        self.assertIsNotNone(packed)
        owner = gzip.decompress(base64.b64decode(packed.group(1))).decode("utf-16le")
        self.assertIn("Assert-PrivateFileAcl $provenance", owner)
        self.assertLess(owner.index("Assert-PrivateFileAcl $provenance"),
                        owner.index("[IO.File]::WriteAllText($provenance,$json"))
        self.assertNotIn("Set-Acl -LiteralPath $provenance", owner)
        self.assertIn("'provenance.json'", credentials._guest_cleanup_script(paths, CORR))

    def test_every_guest_readback_and_removal_guards_intermediate_ancestors_first(self):
        paths = credentials._fixed_paths(STAGE)
        intermediate = r"C:\Users\vpncp117\AppData"
        guarded_intermediate = (
            "$ancestor=Get-Item -LiteralPath '" + intermediate + "' -Force -ErrorAction Stop\n"
            "if(-not $ancestor.PSIsContainer -or ($ancestor.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0){throw 'UNSAFE_ANCESTOR'}"
        )
        scripts = (
            (credentials._guest_setup_script(paths, SID), "[IO.Directory]::CreateDirectory($root,$security)"),
            (credentials._guest_owner_task_script(BINDING, observation(), paths, PROVISION),
             "Get-Item -LiteralPath $paths[$name]"),
            (credentials._guest_finalize_script(BINDING, observation(), paths, PROVISION, CORR),
             "[IO.Directory]::Exists($root)"),
            (credentials._guest_observe_script(paths, CORR), "Get-FileHash -LiteralPath"),
            (credentials._guest_cleanup_script(paths, CORR), "Unregister-ScheduledTask -TaskName"),
            (credentials._guest_abort_script(paths, CORR, SID), "Get-ScheduledTask -TaskName"),
            (credentials._guest_cleanup_observe_script(paths, CORR, STAGE),
             "$absent=(-not [IO.Directory]::Exists($root)"),
        )
        for script, first_sensitive_operation in scripts:
            with self.subTest(first_sensitive_operation=first_sensitive_operation):
                self.assertIn(guarded_intermediate, script)
                self.assertLess(script.index(guarded_intermediate), script.index(first_sensitive_operation))
                self.assertNotIn("@ANCESTORS@", script)
        abort = credentials._guest_abort_script(paths, CORR, SID)
        self.assertLess(abort.index("$ancestor=Get-Item -LiteralPath '" + paths["directory"] + "'"),
                        abort.index("$item=Get-Item -LiteralPath $root"))
        with self.assertRaises(credentials.WindowsFixtureCredentialsError):
            credentials._guest_fixed_ancestor_guard(r"C:\Users\vpncp117\AppData\Roaming\Elsewhere")

    def test_descriptor_binding_survives_server_start_and_live_roles(self):
        stage_intent = {"leaseId": LEASE, "sourceFingerprint": BINDING["sourceFingerprint"],
                        "request": {name: BINDING[name] for name in ("sourceSha", "fixtureReceiptArtifactId",
                                      "baseMsiArtifactId", "targetMsiArtifactId")}}
        identity = {"leaseId": LEASE, "host": "archlinux", "environment": "windows-cp117",
                    "operator": "windows-base", "sourceSha": BINDING["sourceSha"],
                    "fixtureReceiptArtifactId": BINDING["fixtureReceiptArtifactId"],
                    "baseMsiArtifactId": BINDING["baseMsiArtifactId"],
                    "targetMsiArtifactId": BINDING["targetMsiArtifactId"],
                    "socketPath": BINDING["socketPath"], "qemuPid": BINDING["qemuPid"],
                    "startTicks": BINDING["startTicks"]}
        stage_result = {"state": "staged-not-server-ready", "sourceSha": BINDING["sourceSha"],
                        "targetMsiSha256": BINDING["targetMsiArtifactId"].removeprefix("sha256-")}
        with tempfile.TemporaryDirectory() as temporary:
            with (patch.object(credentials.base, "_descriptor", return_value=(None, None,
                        ("windows-cp117", BINDING["socketPath"], BINDING["qemuPid"],
                         BINDING["startTicks"], SID))),
                  patch.object(credentials.stage, "status", return_value=stage_result),
                  patch.object(credentials.stage, "_read_intent", return_value=stage_intent),
                  patch.object(credentials.lease, "_active") as active,
                  patch.object(credentials.lease, "_remote_confirm", return_value=True),
                  patch.object(credentials.base, "_campaign_remote", return_value=object()),
                  patch.object(credentials.public, "_admit_pair", return_value={
                      "sourceFingerprint": BINDING["sourceFingerprint"]})):
                for role, server_state in (("server-start", "starting"), ("owner-network", "live"),
                                           ("network-probe", "live"), ("target", "live")):
                    active.return_value = {"state": "role-active", "role": role,
                                           "server": server_state, "credentials": "ready",
                                           "identity": identity}
                    self.assertEqual(credentials._binding(credentials.Path(temporary), LEASE, STAGE,
                                      require_credentials="ready"), BINDING)
                active.return_value["identity"] = {**identity, "startTicks": 999}
                with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                    credentials._binding(credentials.Path(temporary), LEASE, STAGE,
                                         require_credentials="ready")

    def test_one_shot_start_journals_before_dispatch_and_never_replays_unknown(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        with tempfile.TemporaryDirectory() as temporary:
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials.base, "_descriptor", return_value=(None, None, None)),
                  patch.object(credentials.base, "_campaign_remote", return_value=object()),
                  patch.object(credentials.lease, "claim_role", return_value={"state": "role-active"}) as claim,
                  patch.object(credentials, "_dispatch", return_value=None) as dispatch):
                self.assertEqual(credentials.start(temporary, request)["state"], "unknown")
                self.assertEqual(credentials.start(temporary, request)["state"], "unknown")
                claim.assert_called_once(); dispatch.assert_called_once()
                record = credentials._read_intent(credentials.Path(temporary), CORR)
                self.assertEqual(record["binding"], BINDING)
                self.assertNotIn("PRIVATE KEY", json.dumps(record))

    def test_fresh_readback_mismatch_cannot_finish_credentials_role(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        provenance = observation()
        fresh = {"schemaVersion": 1, "taskState": "Ready", "taskLastResult": 0,
                 "fileSha256": {**provenance["fileSha256"], "privateKey": "0" * 64},
                 "acls": provenance["acls"],
                 "provenanceAcl": acl(provenance["paths"]["directory"] + r"\provenance.json")}
        raw = json.dumps({"state": "observed", "correlationId": CORR,
                          "provenance": provenance, "fresh": fresh,
                          "provenanceSha256": "f" * 64}).encode()
        with tempfile.TemporaryDirectory() as temporary:
            with (patch.object(credentials.base, "_descriptor", return_value=(None, SimpleNamespace(fixture_transfer_root="/fixed"), None)),
                  patch.object(credentials.transport, "_remote_command", return_value=()),
                  patch.object(credentials.transport, "_run_ssh", return_value=raw)):
                with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                    credentials._remote_observe(credentials.Path(temporary), request, BINDING, record)

    def test_cleanup_requires_terminal_server_and_uses_distinct_role(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        provision = {"request": {**request, "correlationId": PROVISION}}
        with tempfile.TemporaryDirectory() as temporary:
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials, "_provision_record", return_value=provision),
                  patch.object(credentials.lease, "inspect", return_value={"state": "active", "server": "live", "role": None}),
                  patch.object(credentials, "_dispatch_cleanup") as dispatch):
                with self.assertRaisesRegex(credentials.WindowsFixtureCredentialsError, "terminal"):
                    credentials.cleanup_start(temporary, request)
                dispatch.assert_not_called()
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials, "_provision_record", return_value=provision),
                  patch.object(credentials.lease, "inspect", return_value={"state": "active", "server": "stopped", "role": None}),
                  patch.object(credentials.base, "_descriptor", return_value=(None, None, None)),
                  patch.object(credentials.base, "_campaign_remote", return_value=object()),
                  patch.object(credentials.lease, "claim_role", return_value={"state": "role-active"}) as claim,
                  patch.object(credentials, "_dispatch_cleanup", return_value=None) as dispatch):
                self.assertEqual(credentials.cleanup_start(temporary, request)["state"], "unknown")
                self.assertEqual(credentials.cleanup_start(temporary, request)["state"], "unknown")
                self.assertEqual(claim.call_args.args[2], "credentials-cleanup")
                claim.assert_called_once(); dispatch.assert_called_once()

    def test_unknown_partial_provision_can_only_abort_under_held_credentials_role(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        provision = {"schemaVersion": 1, "request": request, "binding": BINDING,
                     "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                     "peerCertificateSha256": "4" * 64,
                     "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary)
            credentials._reserve(root, provision)
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials.lease, "inspect", return_value={"state": "active", "role": None,
                                                                           "server": "stopped"}),
                  patch.object(credentials, "_dispatch_cleanup") as dispatch):
                with self.assertRaisesRegex(credentials.WindowsFixtureCredentialsError, "not held"):
                    credentials.abort_start(root, {"correlationId": CORR})
                dispatch.assert_not_called()
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials.lease, "inspect", return_value={"state": "role-active",
                                                                           "role": "credentials",
                                                                           "server": "stopped"}),
                  patch.object(credentials, "_dispatch_cleanup", return_value=None) as dispatch):
                self.assertEqual(credentials.abort_start(root, {"correlationId": CORR})["state"], "unknown")
                self.assertEqual(credentials.abort_start(root, {"correlationId": CORR})["state"], "unknown")
                dispatch.assert_called_once()
                self.assertTrue(dispatch.call_args.kwargs["abort"])
                abort_script = credentials._guest_abort_script(credentials._fixed_paths(STAGE), CORR, SID)
                self.assertIn("FILE_INVENTORY", abort_script)
                self.assertNotIn("server-state", abort_script)

    def test_ephemeral_material_binds_leaf_key_and_java_trust_without_password(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12
        now = datetime(2026, 9, 29, tzinfo=timezone.utc)
        material = credentials._generate_material(now=now)
        cert = x509.load_pem_x509_certificate(material["certificate"])
        key = serialization.load_pem_private_key(material["privateKey"], password=None)
        trust = pkcs12.load_pkcs12(material["trustStore"], password=None)
        self.assertEqual(cert.public_key(), key.public_key())
        self.assertEqual(trust.additional_certs[0].certificate, cert)
        self.assertEqual(material["peerCertificateSha256"],
                         hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())
        self.assertLess(material["certificateValidFromUtc"], int(now.timestamp()))
        self.assertGreater(material["certificateValidUntilUtc"], int(now.timestamp()))
        self.assertNotIn(b"PRIVATE KEY", material["certificate"] + material["trustStore"])

    def test_valid_fresh_observation_returns_only_bound_private_descriptor(self):
        value = credentials._validate_observation(BINDING, observation(), now=150)
        self.assertEqual(value["peerCertificateSha256"], "4" * 64)
        self.assertEqual(value["trustStoreSha256"], "3" * 64)
        self.assertEqual(value["paths"], credentials._fixed_paths(STAGE))
        self.assertNotIn("privateKey", value)
        self.assertNotIn("password", repr(value).lower())

    def test_exact_guest_source_sid_and_certificate_bindings_are_required(self):
        cases = [("socketPath", "/other/cp117.qga"), ("startTicks", 457),
                 ("originalSid", "S-1-5-21-1-2-3-1002"), ("sourceSha", "0" * 40),
                 ("stageCorrelationId", LEASE), ("trustStoreContainsCertificate", False),
                 ("privateKeyMatchesCertificate", False), ("certificateDnsNames", ["example.com"]),
                 ("certificateValidUntilUtc", 149)]
        for field, changed in cases:
            with self.subTest(field=field):
                value = observation(); value[field] = changed
                with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                    credentials._validate_observation(BINDING, value, now=150)

    def test_path_and_acl_cannot_escape_owner_private_stage_state(self):
        for mutator in (
            lambda v: v["paths"].__setitem__("privateKey", r"C:\other\key.pem"),
            lambda v: v["acls"]["privateKey"].__setitem__("protected", False),
            lambda v: v["acls"]["privateKey"]["aces"][2].__setitem__("sid", "S-1-1-0"),
            lambda v: v["acls"]["trustStore"]["aces"][0].__setitem__("inherited", True),
        ):
            value = copy.deepcopy(observation()); mutator(value)
            with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                credentials._validate_observation(BINDING, value, now=150)

    def test_unintegrated_readback_cannot_promote_static_observation(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(credentials, "_binding", return_value=BINDING):
                with self.assertRaisesRegex(credentials.WindowsFixtureCredentialsError,
                                            "PROVENANCE_READBACK_UNAVAILABLE"):
                    credentials.verified_descriptor(root, LEASE, STAGE)
        for changed in ("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "../other", "", None):
            with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                credentials.verified_descriptor("/unused", LEASE, changed)

    def test_response_loss_diagnostic_is_read_only_and_has_finite_public_result(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        receipt = {"schemaVersion": 1, "directory": "absent", "directoryAcl": "absent",
                   "files": {"certificate": "absent", "privateKey": "absent", "trustStore": "absent"},
                   "provenance": "absent", "provenanceAcl": "absent",
                   "task": {"state": "absent", "lastResult": None}}
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary); credentials._reserve(root, record)
            with (patch.object(credentials, "_binding", return_value=BINDING) as binding,
                  patch.object(credentials, "_remote_diagnostic", return_value=receipt) as remote,
                  patch.object(credentials, "_dispatch", side_effect=AssertionError),
                  patch.object(credentials, "_dispatch_cleanup", side_effect=AssertionError)):
                result = credentials.diagnostic(root, {"correlationId": CORR})
            self.assertEqual(result, {"state": "diagnosed", "correlationId": CORR,
                                      "binding": "exact", "phase": "pre-effect",
                                      "nextReadOnly": "credentials-abort-status", "replayAllowed": False,
                                      "nativeActionAllowed": False, "productAction": False})
            binding.assert_called_once(); remote.assert_called_once()

    def test_response_loss_diagnostic_classifies_terminal_and_partial_receipts(self):
        base_receipt = {"schemaVersion": 1, "directory": "present", "directoryAcl": "verified",
                        "files": {"certificate": "exact", "privateKey": "exact", "trustStore": "exact"},
                        "provenance": "present", "provenanceAcl": "verified",
                        "task": {"state": "Ready", "lastResult": 0}}
        self.assertEqual(credentials._diagnostic_phase(base_receipt),
                         ("ready-uncommitted", "credentials-status"))
        failed = copy.deepcopy(base_receipt); failed["task"]["lastResult"] = 1
        self.assertEqual(credentials._diagnostic_phase(failed),
                         ("terminal-failed", "credentials-abort-status"))
        running = copy.deepcopy(base_receipt); running["task"] = {"state": "Running", "lastResult": 0}
        self.assertEqual(credentials._diagnostic_phase(running),
                         ("task-running", "credential-diagnostic"))
        unsafe = copy.deepcopy(base_receipt); unsafe["files"]["privateKey"] = "unsafe"
        self.assertEqual(credentials._diagnostic_phase(unsafe),
                         ("partial", "credentials-abort-status"))

    def test_terminal_failure_detail_classifies_owner_task_stage_without_file_identity(self):
        failed = {"schemaVersion": 1, "directory": "present", "directoryAcl": "verified",
                  "files": {"certificate": "absent", "privateKey": "absent", "trustStore": "absent"},
                  "provenance": "absent", "provenanceAcl": "absent",
                  "task": {"state": "Ready", "lastResult": 1}}
        self.assertEqual(credentials._terminal_failure_detail(failed), {
            "taskLastResult": 1, "safeStage": "before-file-write", "directory": "present",
            "directoryAcl": "verified", "files": "all-absent", "provenance": "absent",
            "provenanceAcl": "absent"})
        self.assertNotIn("privateKey", credentials._terminal_failure_detail(failed))
        for changed in (
                {**failed, "task": {"state": "Ready", "lastResult": 0}},
                {**failed, "task": {"state": "Running", "lastResult": 1}},
                {**failed, "files": {"certificate": "exact", "privateKey": "exact", "trustStore": "exact",
                                       "key": "secret"}}):
            with self.subTest(changed=changed):
                with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                    credentials._terminal_failure_detail(changed)

    def test_failure_detail_reuses_diagnostic_and_refuses_nonterminal_or_unbound_receipts(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        failed = {"schemaVersion": 1, "directory": "present", "directoryAcl": "verified",
                  "files": {"certificate": "exact", "privateKey": "exact", "trustStore": "exact"},
                  "provenance": "absent", "provenanceAcl": "absent",
                  "task": {"state": "Ready", "lastResult": 7}}
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary); credentials._reserve(root, record)
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials, "_remote_diagnostic", return_value=failed) as remote,
                  patch.object(credentials, "_dispatch", side_effect=AssertionError),
                  patch.object(credentials, "_dispatch_cleanup", side_effect=AssertionError)):
                result = credentials.failure_detail(root, {"correlationId": CORR})
            self.assertEqual(result, {"state": "detailed", "correlationId": CORR, "binding": "exact",
                                      "taskLastResult": 7, "safeStage": "before-provenance",
                                      "directory": "present", "directoryAcl": "verified", "files": "all-exact",
                                      "provenance": "absent", "provenanceAcl": "absent",
                                      "nextReadOnly": "credentials-abort-status", "replayAllowed": False,
                                      "nativeActionAllowed": False, "productAction": False})
            remote.assert_called_once()
            with patch.object(credentials, "_binding", return_value=BINDING), \
                 patch.object(credentials, "_remote_diagnostic", return_value={**failed, "task": {"state": "Ready", "lastResult": 0}}):
                self.assertEqual(credentials.failure_detail(root, {"correlationId": CORR})["state"], "unknown")

    def test_provenance_acl_shape_requires_exact_terminal_acl_failure_and_returns_only_categories(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        failed = {"schemaVersion": 1, "directory": "present", "directoryAcl": "verified",
                  "files": {"certificate": "exact", "privateKey": "exact", "trustStore": "exact"},
                  "provenance": "present", "provenanceAcl": "mismatch",
                  "task": {"state": "Ready", "lastResult": 1}}
        shape = {"schemaVersion": 1, "protected": "protected", "aceCount": "three",
                 "principals": "exact", "rights": "all-allow-full-control",
                 "origin": "all-explicit", "inheritance": "file-only", "propagation": "other"}
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary); credentials._reserve(root, record)
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials, "_remote_diagnostic", return_value=failed),
                  patch.object(credentials, "_remote_provenance_acl_shape", return_value=shape) as observer,
                  patch.object(credentials, "_dispatch", side_effect=AssertionError),
                  patch.object(credentials, "_dispatch_cleanup", side_effect=AssertionError)):
                result = credentials.provenance_acl_shape(root, {"correlationId": CORR})
            observer.assert_called_once()
        self.assertEqual(result, {"state": "classified", "correlationId": CORR, "binding": "exact",
                                  **shape, "nextReadOnly": "credentials-abort-status",
                                  "replayAllowed": False, "nativeActionAllowed": False,
                                  "productAction": False})
        self.assertNotIn("privateKey", result)
        self.assertNotIn("path", result)
        self.assertNotIn("sid", result)

    def test_provenance_acl_shape_fails_closed_for_non_acl_terminal_failure_or_unbound_result(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        failed = {"schemaVersion": 1, "directory": "present", "directoryAcl": "verified",
                  "files": {"certificate": "exact", "privateKey": "exact", "trustStore": "exact"},
                  "provenance": "absent", "provenanceAcl": "absent",
                  "task": {"state": "Ready", "lastResult": 1}}
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary); credentials._reserve(root, record)
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials, "_remote_diagnostic", return_value=failed),
                  patch.object(credentials, "_remote_provenance_acl_shape", side_effect=AssertionError)):
                result = credentials.provenance_acl_shape(root, {"correlationId": CORR})
        self.assertEqual(result["state"], "unknown")

    def test_remote_provenance_acl_shape_accepts_only_bounded_categories(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        shape = {"schemaVersion": 1, "protected": "unprotected", "aceCount": "other",
                 "principals": "unexpected-and-missing", "rights": "contains-other",
                 "origin": "inherited-present", "inheritance": "other", "propagation": "other"}
        raw = json.dumps({"state": "observed", "correlationId": CORR, "receipt": shape}).encode()
        with (patch.object(credentials.base, "_descriptor", return_value=(None,
                    SimpleNamespace(fixture_transfer_root="/fixed"), None)),
              patch.object(credentials.transport, "_remote_command", return_value=()),
              patch.object(credentials.transport, "_run_ssh", return_value=raw) as ssh):
            result = credentials._remote_provenance_acl_shape(credentials.Path("/"), request, BINDING, record)
        self.assertEqual(result, shape)
        self.assertIsNone(ssh.call_args.args[3])
        for poisoned in ({**shape, "path": "C:\\secret"}, {**shape, "principals": "S-1-5-18"}):
            raw = json.dumps({"state": "observed", "correlationId": CORR, "receipt": poisoned}).encode()
            with (patch.object(credentials.base, "_descriptor", return_value=(None,
                        SimpleNamespace(fixture_transfer_root="/fixed"), None)),
                  patch.object(credentials.transport, "_remote_command", return_value=()),
                  patch.object(credentials.transport, "_run_ssh", return_value=raw)):
                with self.assertRaises(credentials.WindowsFixtureCredentialsError):
                    credentials._remote_provenance_acl_shape(credentials.Path("/"), request, BINDING, record)

    def test_generated_provenance_acl_shape_uses_powershell_subexpression_for_hashtable_if(self):
        """Regression for the terminal cleanup script's invalid ``=(if ...)`` form."""
        program = credentials._guest_provenance_acl_shape_script(
            credentials._fixed_paths(STAGE), CORR, observation()["fileSha256"], SID)
        self.assertIn("aceCount=$(if($rules.Count -eq 3){'three'}else{'other'})", program)
        self.assertNotIn("aceCount=(if($rules.Count -eq 3)", program)

    def test_response_loss_diagnostic_preserves_bounded_host_pre_effect_and_failure_facts(self):
        expected = {
            "group-absent": ("host-group-absent", "credentials-abort-status"),
            "journal-absent": ("host-journal-absent", "credentials-abort-status"),
            "binding-mismatch": ("host-binding-mismatch", "credential-diagnostic"),
            "layout-unsafe": ("host-layout-unsafe", "credential-diagnostic"),
            "guest-observer-failed": ("guest-observer-failed", "credential-diagnostic"),
        }
        for host_phase, result in expected.items():
            with self.subTest(host_phase=host_phase):
                self.assertEqual(credentials._diagnostic_phase(
                    {"schemaVersion": 1, "hostPhase": host_phase}), result)
        with self.assertRaises(credentials.WindowsFixtureCredentialsError):
            credentials._diagnostic_phase({"schemaVersion": 1, "hostPhase": "private-key-present"})

    def test_remote_diagnostic_accepts_only_the_bounded_missing_remote_journal_fact(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        raw = json.dumps({"state": "observed", "correlationId": CORR,
                          "receipt": {"schemaVersion": 1, "hostPhase": "journal-absent"}}).encode()
        with (patch.object(credentials.base, "_descriptor", return_value=(None,
                    SimpleNamespace(fixture_transfer_root="/fixed"), None)),
              patch.object(credentials.transport, "_remote_command", return_value=()),
              patch.object(credentials.transport, "_run_ssh", return_value=raw) as ssh):
            receipt = credentials._remote_diagnostic(credentials.Path("/"), request, BINDING, record)
        self.assertEqual(receipt, {"schemaVersion": 1, "hostPhase": "journal-absent"})
        self.assertIsNone(ssh.call_args.args[3])

    def test_generated_remote_diagnostic_reports_absent_group_before_guest_access(self):
        """Execute its real host branch, with only VM liveness stubbed."""
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary); parent = root / "windows-cp117"
            parent.mkdir(mode=0o700); os.chmod(parent, 0o700)
            arguments = [str(root), "windows-cp117", CORR, LEASE, STAGE, "unused.sock",
                         "1", "1", SID, "a" * 40, "b" * 64,
                         "sha256-" + "c" * 64, "sha256-" + "d" * 64, "sha256-" + "e" * 64,
                         PROVISION, "1" * 64, "2" * 64, "3" * 64, "4" * 64, "unused"]
            program = credentials._REMOTE_DIAGNOSTIC.replace(
                "if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()",
                "if env!='windows-cp117':raise ValueError()")
            stream = io.StringIO()
            with patch.object(sys, "argv", ["remote"] + arguments), contextlib.redirect_stdout(stream):
                with self.assertRaises(SystemExit):
                    exec(program, {"__name__": "__main__"})
            self.assertEqual(json.loads(stream.getvalue()), {"state": "observed", "correlationId": CORR,
                             "receipt": {"schemaVersion": 1, "hostPhase": "group-absent"}})

    def test_pre_effect_guard_probe_is_read_only_and_binds_generated_nonsecret_payload_metadata(self):
        request = {"host": "archlinux", "leaseId": LEASE,
                   "stageCorrelationId": STAGE, "correlationId": CORR}
        record = {"schemaVersion": 1, "request": request, "binding": BINDING,
                  "provisionId": PROVISION, "fileSha256": observation()["fileSha256"],
                  "peerCertificateSha256": "4" * 64,
                  "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary); credentials._reserve(root, record)
            with (patch.object(credentials, "_binding", return_value=BINDING),
                  patch.object(credentials, "_remote_pre_effect_guard_probe", return_value="matched") as remote,
                  patch.object(credentials, "_dispatch", side_effect=AssertionError),
                  patch.object(credentials, "_dispatch_cleanup", side_effect=AssertionError)):
                result = credentials.pre_effect_guard_probe(root, {"correlationId": CORR})
        self.assertEqual(result, {"state": "observed", "correlationId": CORR, "binding": "exact",
                                  "localPayload": "metadata-admitted", "remoteRoleGuard": "matched",
                                  "replayAllowed": False, "nativeActionAllowed": False, "productAction": False})
        remote.assert_called_once()

    def test_generated_remote_pre_effect_guard_uses_actual_credentials_role_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary); parent = root / "windows-cp117"
            group = parent / "windows-cp117-campaign"
            group.mkdir(parents=True, mode=0o700)
            for directory in (root, parent, group):
                os.chmod(directory, 0o700)
            lock = group / ".environment.lock"; lock.write_text(""); os.chmod(lock, 0o600)
            identity = {"host": "archlinux", "environment": "windows-cp117", "leaseId": LEASE,
                        "operator": "windows-base", "sourceSha": "a" * 40,
                        "fixtureReceiptArtifactId": "sha256-" + "c" * 64,
                        "baseMsiArtifactId": "sha256-" + "d" * 64,
                        "targetMsiArtifactId": "sha256-" + "e" * 64,
                        "socketPath": "unused.sock", "qemuPid": 1, "startTicks": 1}
            active = {"version": 1, "identity": identity, "sequence": 1, "state": "role-active",
                      "role": "credentials", "correlationId": CORR, "server": "stopped",
                      "credentials": "absent", "lastEvidenceSha256": None, "lastOutcome": None}
            active_path = group / "active.json"; active_path.write_text(json.dumps(active)); os.chmod(active_path, 0o600)
            arguments = [str(root), "windows-cp117", CORR, LEASE, STAGE, "unused.sock", "1", "1", SID,
                         "a" * 40, "b" * 64, "sha256-" + "c" * 64, "sha256-" + "d" * 64,
                         "sha256-" + "e" * 64]
            program = credentials._REMOTE_PRE_EFFECT_GUARD_PROBE.replace(
                "if env!='windows-cp117' or not live(sock,pid,ticks):raise ValueError()",
                "if env!='windows-cp117':raise ValueError()")
            stream = io.StringIO()
            with patch.object(sys, "argv", ["remote"] + arguments), contextlib.redirect_stdout(stream):
                exec(program, {"__name__": "__main__"})
            self.assertEqual(json.loads(stream.getvalue()), {"state": "observed", "correlationId": CORR,
                             "receipt": {"schemaVersion": 1, "guard": "matched"}})

    def test_credential_dispatch_uses_transport_admitted_timeout_and_framed_private_stdin(self):
        """The former 120s timeout is rejected before any SSH transport effect."""
        with tempfile.TemporaryDirectory() as temporary:
            root = credentials.Path(temporary)
            host = ssh_transport.SshHost(alias="archlinux", host="example.invalid", port=22,
                user="tester", identity_file=root / "identity", known_hosts_file=root / "known_hosts")
            config = ssh_transport.SshConfig(root=root, hosts={"archlinux": host})
            with self.assertRaisesRegex(ssh_transport.SshConfigError, "1 and 60"):
                ssh_transport.build_ssh_argv(config, "archlinux", 120)

            request = {"host": "archlinux", "leaseId": LEASE,
                       "stageCorrelationId": STAGE, "correlationId": CORR}
            material = {"certificate": b"certificate-bytes", "privateKey": b"private-key-bytes",
                        "trustStore": b"trust-store-bytes",
                        "fileSha256": {"certificate": hashlib.sha256(b"certificate-bytes").hexdigest(),
                                       "privateKey": hashlib.sha256(b"private-key-bytes").hexdigest(),
                                       "trustStore": hashlib.sha256(b"trust-store-bytes").hexdigest()},
                        "peerCertificateSha256": "4" * 64,
                        "certificateValidFromUtc": 100, "certificateValidUntilUtc": 200}
            captured = {}
            def sent(received_config, received_host, command, payload, timeout):
                captured.update(config=received_config, host=received_host, command=command,
                                payload=payload, timeout=timeout)
                return b'{"state":"submitted"}'
            with (patch.object(credentials.base, "_descriptor", return_value=(config,
                        SimpleNamespace(fixture_transfer_root="/fixed"), None)),
                  patch.object(credentials.transport, "_run_ssh", side_effect=sent)):
                result = credentials._dispatch(root, request, BINDING, material, PROVISION)
            self.assertEqual(result, b'{"state":"submitted"}')
            self.assertEqual(captured["timeout"], 60)
            self.assertEqual(captured["host"], "archlinux")
            self.assertNotIn(b"private-key-bytes", captured["payload"])
            size = int.from_bytes(captured["payload"][:4], "big")
            self.assertEqual(size, len(captured["payload"][4:]))
            framed = json.loads(captured["payload"][4:])
            self.assertEqual(base64.b64decode(framed["files"]["privateKey"]), b"private-key-bytes")
            self.assertNotIn("private-key-bytes", repr(captured["command"]))

    def test_response_loss_diagnostic_rejects_unbounded_or_secret_bearing_receipt(self):
        invalid = {"schemaVersion": 1, "directory": "present", "directoryAcl": "verified",
                   "files": {"certificate": "exact", "privateKey": "exact", "trustStore": "exact"},
                   "provenance": "present", "provenanceAcl": "verified",
                   "task": {"state": "Ready", "lastResult": 0, "key": "secret"}}
        with self.assertRaises(credentials.WindowsFixtureCredentialsError):
            credentials._diagnostic_phase(invalid)
        program = credentials._guest_diagnostic_script(credentials._fixed_paths(STAGE), CORR,
                                                       observation()["fileSha256"], SID)
        self.assertIn("Get-FileHash", program)
        self.assertNotIn("Get-Content", program)
        self.assertNotIn("PRIVATE KEY", program)
        compile(credentials._REMOTE_DIAGNOSTIC, "remote-diagnostic", "exec")
        compile(credentials._REMOTE_PROVENANCE_ACL_SHAPE, "remote-provenance-acl-shape", "exec")
