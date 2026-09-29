"""Fail-closed tests for the CP117 fixture TLS inventory boundary."""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agent_tools import windows_fixture_credentials as credentials


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
                for role, server_state in (("server-start", "starting"), ("target", "live")):
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
