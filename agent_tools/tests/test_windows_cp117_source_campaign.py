"""Causal checks for new-source CP117 campaign admission."""
from __future__ import annotations

import tempfile
import unittest
import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest import mock

from agent_tools import windows_cp117_source_campaign as campaign


LEASE = "f18df6cb-2c43-4265-b1ba-4bbadf9b708a"
DESC = ("windows-cp117", "/qga", 123, 456, "S-1-5-21-1-2-3-1002")
OLD_REQUEST = {"host": "archlinux", "correlationId": campaign._OLD_STAGE,
               "sourceSha": campaign._OLD_SOURCE,
               "fixtureReceiptArtifactId": "sha256-" + "1" * 64,
               "baseMsiArtifactId": "sha256-" + "2" * 64,
               "targetMsiArtifactId": "sha256-" + "3" * 64,
               "expectedCurrentVersion": "2.1.19"}


class SourceCampaignTests(unittest.TestCase):
    def _old_closed(self):
        identity = campaign.base._campaign_identity({**OLD_REQUEST, "correlationId": campaign._OLD_LEASE}, DESC)
        return {"identity": identity, "state": "closed", "role": None, "server": "stopped",
                "credentials": "cleaned", "lastEvidenceSha256": "a" * 64}

    def _pair(self, **changed):
        return {"sourceSha": campaign._SOURCE, "receiptArtifactId": campaign._RECEIPT,
                "baseArtifactId": campaign._BASE, "targetArtifactId": campaign._TARGET,
                "baseVersion": "2.1.19", "targetVersion": "2.2.2", **changed}

    def _idle(self):
        return {"state": "ready", "ready": True, "installedVersion": "2.1.19",
                "productCount": 1, "activeCount": 0, "activeProcesses": []}

    def _retired_root(self, root: Path):
        directory = root / campaign.retirement._DIR
        directory.mkdir(parents=True); directory.chmod(0o700)
        (directory / "receipt.json").write_text('{"leaseId":"e59a7483-4e38-4e7b-b8fa-0d8b2356916a","removed":true,"stageCorrelationId":"e848bed2-5bea-47bc-a85a-6cf17b1fcc6a"}')
        (directory / "receipt.json").chmod(0o600)

    def test_green_requires_fresh_absence_and_returns_explicit_new_base_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._retired_root(root)
            with mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
                 mock.patch.object(campaign.stage, "_read_intent", return_value={"leaseId": campaign._OLD_LEASE, "request": OLD_REQUEST}), \
                 mock.patch.object(campaign.lease, "_locked", return_value=(root, 0)), \
                 mock.patch.object(campaign.os, "close"), \
                 mock.patch.object(campaign.lease, "_active", return_value=None), \
                 mock.patch.object(campaign.lease, "_closed", return_value=self._old_closed()), \
                 mock.patch.object(campaign.lease, "_remote_confirm", return_value=True), \
                 mock.patch.object(campaign.retirement, "diagnose", return_value={"state": "observed", "stage": "absent", "serverTask": "absent", "serverProcess": "absent", "listener": "absent", "credentials": "absent", "runtime": "absent"}), \
                 mock.patch.object(campaign.base, "readiness", return_value=self._idle()), \
                 mock.patch.object(campaign.public, "_admit_pair", return_value=self._pair()), \
                 mock.patch.object(campaign.public, "preinstall_status", return_value={"state": "observed", "jobId": campaign.base._LEGACY_JOB, "phase": "Failed", "code": "RUNTIME_FAILED", "sequence": 3}), \
                 mock.patch.object(campaign.base, "_legacy_task_observation", return_value={"state": "cleaned"}), \
                 mock.patch.object(campaign.base, "_legacy_history_observation", return_value={"state": "clean"}), \
                 mock.patch.object(campaign.lease, "begin") as begin:
                result = campaign.preflight(root, {"host": "archlinux", "leaseId": LEASE})
        self.assertEqual("ready", result["state"])
        self.assertTrue(result["baseInstallRequired"])
        self.assertFalse(result["generalBaseRouteAllowed"])
        self.assertEqual("source-bound-base-install", result["nextAction"])
        self.assertEqual(campaign._SOURCE, result["sourceBaseInstallInputs"]["sourceSha"])
        self.assertEqual("2.1.19", result["sourceBaseInstallInputs"]["expectedCurrentVersion"])
        begin.assert_not_called()

    def test_red_matching_version_never_substitutes_for_fresh_source_absence(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign, "_retirement_terminal", return_value=True), \
             mock.patch.object(campaign, "_fresh_absence", return_value=False), \
             mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(campaign.base, "readiness", return_value=self._idle()) as readiness:
            result = campaign.preflight(Path(directory), {"host": "archlinux", "leaseId": LEASE})
        self.assertEqual({"state": "blocked", "reason": "retirement-not-terminal"}, {"state": result["state"], "reason": result["reason"]})
        readiness.assert_not_called()

    def test_red_old_source_pair_cannot_open_d32_campaign(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign, "_retirement_terminal", return_value=True), \
             mock.patch.object(campaign, "_fresh_absence", return_value=True), \
             mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(campaign.base, "readiness", return_value=self._idle()), \
             mock.patch.object(campaign.public, "_admit_pair", return_value=self._pair(sourceSha=campaign._OLD_SOURCE)):
            result = campaign.preflight(Path(directory), {"host": "archlinux", "leaseId": LEASE})
        self.assertEqual("new-source-pair", result["reason"])

    def test_red_closed_lease_requires_exact_old_identity_and_remote_confirmation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); self._retired_root(root)
            wrong = self._old_closed(); wrong["identity"] = {**wrong["identity"], "sourceSha": campaign._SOURCE}
            with mock.patch.object(campaign.stage, "_read_intent", return_value={"leaseId": campaign._OLD_LEASE, "request": OLD_REQUEST}), \
                 mock.patch.object(campaign.lease, "_locked", return_value=(root, 0)), \
                 mock.patch.object(campaign.os, "close"), mock.patch.object(campaign.lease, "_active", return_value=None), \
                 mock.patch.object(campaign.lease, "_closed", return_value=wrong), mock.patch.object(campaign.lease, "_remote_confirm") as remote:
                self.assertFalse(campaign._retirement_terminal(root, DESC, object(), object()))
        remote.assert_not_called()

    def test_rejects_reused_or_noncanonical_lease(self):
        for lease_id in (campaign._OLD_LEASE, "F18DF6CB-2C43-4265-B1BA-4BBADF9B708A"):
            with self.subTest(lease_id=lease_id):
                with self.assertRaises(campaign.WindowsCp117SourceCampaignError):
                    campaign._request({"host": "archlinux", "leaseId": lease_id})

    def test_transfer_admission_is_fixed_to_d32_and_reuses_only_the_generic_transfer_engine(self):
        inputs = {"host": "archlinux", "correlationId": LEASE, "sourceSha": campaign._SOURCE,
                  "fixtureReceiptArtifactId": campaign._RECEIPT, "baseMsiArtifactId": campaign._BASE,
                  "targetMsiArtifactId": campaign._TARGET, "expectedCurrentVersion": "2.1.19"}
        artifact = Path("/verified/d32-base.msi")
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign, "preflight", return_value={"state": "ready"}) as preflight, \
             mock.patch.object(campaign.public, "_verified_location", return_value=artifact), \
             mock.patch.object(Path, "is_file", return_value=True), mock.patch.object(Path, "is_symlink", return_value=False):
            self.assertEqual(artifact, campaign.transfer_admission(Path(directory), inputs))
        preflight.assert_called_once_with(Path(directory), {"host": "archlinux", "leaseId": LEASE})
        with self.assertRaises(campaign.WindowsCp117SourceCampaignError):
            campaign.transfer_admission(Path.cwd(), {**inputs, "sourceSha": campaign._OLD_SOURCE})

    def test_replacement_task_uninstalls_exact_prior_product_then_checks_workspace_and_d32_hashes(self):
        pair = {"baseArtifactId": campaign._BASE, "baseVersion": "2.1.19", "baseCliSha256": "a" * 64,
                "baseAppJarSha256": "b" * 64, "baseHelperSha256": "c" * 64,
                "baseAppJarName": "desktopApp-2.1.19.jar"}
        source = campaign._replacement_task(LEASE, pair, DESC[4])
        self.assertIn("/x '+$oldCode", source)
        self.assertIn("$none.Count -ne 0", source)
        self.assertIn(".vpn-control-desktop\\workspace.json", source)
        self.assertIn("WORKSPACE", source)
        self.assertIn("PSDrive.Name -cne 'HKCU'", source)
        self.assertIn("InstallLocation.TrimEnd('\\\\').ToLowerInvariant()", source)
        self.assertIn("c:\\users\\vpncp117\\appdata\\local\\vpn-control", source)
        self.assertIn(campaign._BASE.removeprefix("sha256-"), source)

    def test_actual_powershell_task_runtime_census_precedes_uninstall(self):
        """Execute actual emitted task decisions with NO-EFFECT command stubs.

        Windows CI must execute this control. Other hosts may run it with a
        local PowerShell; this measures script ordering, not MSI/OS acceptance.
        """
        interpreter = shutil.which("powershell") or shutil.which("pwsh")
        if interpreter is None:
            if os.name == "nt":
                self.fail("Windows ordering regression requires PowerShell")
            self.skipTest("PowerShell ordering control requires a local interpreter")
        pair = {"baseArtifactId": campaign._BASE, "baseVersion": "2.1.19",
                "baseCliSha256": "a" * 64, "baseAppJarSha256": "b" * 64,
                "baseHelperSha256": "c" * 64, "baseAppJarName": "desktopApp-2.1.19.jar"}
        source = campaign._replacement_task(LEASE, pair, DESC[4])
        # Retain both possible old/new emitted orderings, without rewriting
        # either decision or replacing its guard. Host preflight was idle;
        # the synthetic runtime appears at this actual task-boundary census.
        start = min(source.index("$workspace='"), source.index("$active=@("))
        fragment = source[start:source.index("$stage='INSTALL';P", start)]
        stubs = r'''$ErrorActionPreference='Stop'
$script:InstallerCalls=0
function Test-Path {param($LiteralPath,$PathType) return $false}
function Get-ItemProperty {param([Parameter(ValueFromRemainingArguments=$true)]$Rest) return @()}
function Start-Process {param($FilePath,$ArgumentList,[switch]$PassThru,[switch]$Wait) $script:InstallerCalls++; return [pscustomobject]@{ExitCode=0}}
function Get-CimInstance {param($ClassName) if($fixtureName){return [pscustomobject]@{Name=$fixtureName}}}
$products=@([pscustomobject]@{PSChildName='{11111111-1111-1111-1111-111111111111}';InstallLocation='C:\Users\vpncp117\AppData\Local\vpn-control';PSDrive=[pscustomobject]@{Name='HKCU'}})
'''
        for runtime in ("sing-box.exe", "msiexec.exe", "vpn-control-cli.exe", ""):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as directory:
                script = Path(directory) / "public-order-control.ps1"
                script.write_text(stubs + "$fixtureName='" + runtime + "';$reason=$null\ntry{\n"
                                  + fragment + "\n}catch{$reason=$_.Exception.Message}\n"
                                  + "[pscustomobject]@{calls=$script:InstallerCalls;reason=$reason}|ConvertTo-Json -Compress\n")
                result = subprocess.run([interpreter, "-NoLogo", "-NoProfile", "-NonInteractive",
                                         "-File", str(script)], capture_output=True, text=True, timeout=20,
                                        env={k: v for k, v in os.environ.items() if k != "DYLD_INSERT_LIBRARIES"})
                self.assertEqual(0, result.returncode, result.stderr)
                actual = json.loads(result.stdout)
                self.assertEqual({"calls": 0, "reason": "ACTIVE_PROCESS"} if runtime else
                                 {"calls": 1, "reason": None}, actual)

    def test_replacement_action_hash_is_distinct_from_ordinary_task_and_stable(self):
        pair = {"baseArtifactId": campaign._BASE, "baseVersion": "2.1.19", "baseCliSha256": "a" * 64,
                "baseAppJarSha256": "b" * 64, "baseHelperSha256": "c" * 64,
                "baseAppJarName": "desktopApp-2.1.19.jar"}
        first = campaign._action_sha(LEASE, pair, DESC[4])
        second = campaign._action_sha(LEASE, pair, DESC[4])
        ordinary = campaign.base._terminal_task_arguments_sha(LEASE, {"pair": pair, "request": {"expectedCurrentVersion":"2.1.19"}, "expectedSid": DESC[4]})
        self.assertEqual(first, second)
        self.assertNotEqual(first, ordinary)

    def test_ps5_preflight_contains_exact_replacement_programs_once(self):
        pair = {"baseArtifactId": campaign._BASE, "baseVersion": "2.1.19", "baseCliSha256": "a" * 64,
                "baseAppJarSha256": "b" * 64, "baseHelperSha256": "c" * 64,
                "baseAppJarName": "desktopApp-2.1.19.jar"}
        source = campaign.replacement_powershell_preflight_script(LEASE, pair, DESC[4])
        encoded = __import__("re").findall(r"FromBase64String\('([^']+)'\)", source)
        self.assertEqual(1, len(encoded))
        bootstrap = __import__("gzip").decompress(__import__("base64").b64decode(encoded[0])).decode("utf-16le")
        task_encoded = __import__("re").findall(r"FromBase64String\('([^']+)'\)", bootstrap)
        self.assertEqual(1, len(task_encoded))
        task = __import__("gzip").decompress(__import__("base64").b64decode(task_encoded[0])).decode("utf-16le")
        self.assertEqual(1, task.count("WORKSPACE"))
        self.assertEqual(1, task.count("PRODUCT_IDENTITY"))
        self.assertIn("Parser]::ParseInput", source)
        self.assertLess(len(source.encode("utf-16le")), 30000)

    def test_replacement_bootstrap_rejects_missing_or_duplicate_substitution(self):
        pair = {"baseArtifactId": campaign._BASE, "baseVersion": "2.1.19", "baseCliSha256": "a" * 64,
                "baseAppJarSha256": "b" * 64, "baseHelperSha256": "c" * 64,
                "baseAppJarName": "desktopApp-2.1.19.jar"}
        with mock.patch.object(campaign.base, "_bootstrap", return_value="no embedded task"):
            with self.assertRaises(campaign.WindowsCp117SourceCampaignError):
                campaign._replacement_bootstrap(LEASE, pair, DESC[4])

    def test_parser_uses_actual_admitted_pair_and_stays_read_only(self):
        pair = self._pair(sourceFingerprint="d" * 64, baseCliSha256="a" * 64,
                          baseAppJarSha256="b" * 64, baseHelperSha256="c" * 64,
                          baseAppJarName="desktopApp-2.1.19.jar")
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign, "preflight", return_value={"state":"ready"}), \
             mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(campaign, "_new_pair", return_value=pair), \
             mock.patch.object(campaign.base.windows_credential_probe_ssh, "_run_ssh", return_value='{"state":"passed"}') as run:
            result = campaign.parser(Path(directory), {"host":"archlinux", "leaseId":LEASE})
        self.assertEqual("passed", result["state"])
        self.assertEqual(["ps5-parse","gzip","embedded-task","action-hash"], result["checks"])
        self.assertEqual(30, run.call_args.args[-1])

    def test_parser_ast_check_does_not_depend_on_blocked_installation_preflight(self):
        pair=self._pair(sourceFingerprint='d'*64,baseCliSha256='a'*64,baseAppJarSha256='b'*64,baseHelperSha256='c'*64,baseAppJarName='desktopApp-2.1.19.jar')
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(campaign,'preflight',return_value={'state':'blocked'}) as preflight, mock.patch.object(campaign.base,'_descriptor',return_value=(object(),object(),DESC)), mock.patch.object(campaign,'_new_pair',return_value=pair), mock.patch.object(campaign.base.windows_credential_probe_ssh,'_run_ssh',return_value='{"state":"passed"}') as run:
            self.assertEqual('passed',campaign.parser(Path(directory),{'host':'archlinux','leaseId':LEASE})['state'])
        preflight.assert_not_called();run.assert_called_once()

    def test_parser_invalid_pair_or_generation_rejects_before_transport(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(campaign.base,'_descriptor',return_value=(object(),object(),('wrong','/q',1,2,DESC[4]))),mock.patch.object(campaign,'_new_pair',return_value=None),mock.patch.object(campaign.base.windows_credential_probe_ssh,'_run_ssh') as run:
            self.assertEqual('unknown',campaign.parser(Path(directory),{'host':'archlinux','leaseId':LEASE})['state'])
        run.assert_not_called()

    def test_start_requires_transfer_handoff_before_any_campaign_reservation(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign, "preflight", return_value={"state": "ready"}), \
             mock.patch.object(campaign.base, "_descriptor", return_value=(object(), type("T", (), {"fixture_transfer_root":"/remote"})(), DESC)), \
             mock.patch("agent_tools.windows_msi_http_transfer.ready_for_base", return_value={"state": "unknown"}), \
             mock.patch.object(campaign.base, "_reserve") as reserve:
            result = campaign.start(Path(directory), {"host": "archlinux", "leaseId": LEASE})
        self.assertEqual("unknown", result["state"])
        reserve.assert_not_called()

    def test_red_real_historical_base_reservation_blocks_new_source_before_guest_effect(self):
        """A real base reservation file must remain intact and block preflight."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            record = {"request": {"correlationId": campaign._HISTORICAL_BASE}}
            campaign.base._reserve(root, record)
            ready, reason = campaign._reservation_readiness(root, object(), object(), DESC, LEASE)
            self.assertFalse(ready)
            self.assertEqual("historical-base-unresolved", reason)
            self.assertTrue(campaign.base._intent_path(root, campaign._HISTORICAL_BASE).exists())

    def test_reservation_diagnose_is_local_only_and_never_promotes_c32(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); campaign.base._reserve(root,{"request":{"correlationId":campaign._HISTORICAL_BASE}})
            with mock.patch.object(campaign.base,'_descriptor',return_value=(object(),object(),DESC)),mock.patch('agent_tools.windows_cp117_c32_archive_admission.preflight',return_value={'state':'blocked','phase':'cleanup'}):
                seen=campaign.reservation_diagnose(root,{"host":"archlinux","leaseId":LEASE})
        self.assertEqual("observed",seen["state"])
        self.assertEqual("absent",seen["newIntent"])
        self.assertEqual("present",seen["historical"])

    def test_historical_closure_diagnostic_reports_version_only_after_absence(self):
        corr='45e4514a-c629-4f3b-99bc-aad599640d29'; request={'host':'archlinux','correlationId':corr,'sourceSha':'a'*40,'fixtureReceiptArtifactId':'sha256-'+'a'*64,'baseMsiArtifactId':'sha256-'+'b'*64,'targetMsiArtifactId':'sha256-'+'c'*64,'expectedCurrentVersion':'2.1.17'}; intent={'request':request,'commandSha256':'d'*64}; census={'state':'observed','correlationId':corr,'mutation':'none','remoteStage':'absent','leaf':'absent','task':'absent','result':'absent','correlationPowerShell':'absent','installer':'absent','product':'single','installedVersion':'2.1.19'}
        closed={'identity':campaign.base._campaign_identity(request,DESC),'lastOutcome':'unknown-cleaned'}
        with tempfile.TemporaryDirectory() as d, mock.patch.object(campaign.base,'_unknown_recovery_profile',return_value=(request,'d'*64)),mock.patch.object(campaign.base,'_private_intent',return_value=intent),mock.patch.object(campaign.base,'_unknown_marker_valid',return_value=True),mock.patch.object(campaign.lease,'_locked',return_value=(Path(d),0)),mock.patch.object(campaign.lease,'_active',return_value=None),mock.patch.object(campaign.lease,'_closed',return_value=closed),mock.patch.object(campaign.os,'close'),mock.patch.object(campaign.base,'_unknown_cleanup_observe',side_effect=[census,census]):
            self.assertEqual('installed-version',campaign._historical_closure_phase(Path(d),object(),object(),DESC,corr))

    def test_reservation_diagnostic_uses_authoritative_archive_recognition(self):
        corr='45e4514a-c629-4f3b-99bc-aad599640d29'
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/campaign.base._LOCAL;path.mkdir(parents=True,mode=0o700)
            (path/(corr+'.json')).write_text('{}')
            with mock.patch.object(campaign.base,'_descriptor',return_value=(object(),object(),DESC)),mock.patch.object(campaign.base,'_archived_base_record_names',return_value={corr+'.json',corr+'.unknown-close.json'}),mock.patch.object(campaign.base,'_unknown_closure_archived',return_value=False),mock.patch.object(campaign,'_historical_closure_phase',return_value='installed-version') as diagnosis:
                result=campaign.reservation_diagnose(root,{'host':'archlinux','leaseId':LEASE})
            self.assertNotIn('blockers',result)
            diagnosis.assert_not_called()

    def test_red_reserved_source_run_reports_legacy_job_without_generic_action_observer(self):
        """A post-reservation legacy refusal is a pre-effect fact, not QGA unknown."""
        pair = self._pair(sourceFingerprint="d" * 64, baseCliSha256="a" * 64,
                          baseAppJarSha256="b" * 64, baseHelperSha256="c" * 64,
                          baseAppJarName="desktopApp-2.1.19.jar", baseRuntimeSha256="e" * 64,
                          targetMsiSha256="f" * 64, targetMsiSize=1)
        request = {"host": "archlinux", "correlationId": LEASE, "sourceSha": campaign._SOURCE,
                   "fixtureReceiptArtifactId": campaign._RECEIPT, "baseMsiArtifactId": campaign._BASE,
                   "targetMsiArtifactId": campaign._TARGET, "expectedCurrentVersion": "2.1.19"}
        command = "replacement-bootstrap"
        record = {"request": request, "pair": pair, "environment": DESC[0], "socketPath": DESC[1],
                  "pid": DESC[2], "startTicks": DESC[3], "expectedSid": DESC[4],
                  "commandSha256": __import__("hashlib").sha256(command.encode("utf-16le")).hexdigest(),
                  "leaseId": LEASE}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            campaign.base._reserve(root, record)
            with mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
                 mock.patch.object(campaign.base, "_stage_artifact_readonly", return_value=(pair, 1)), \
                 mock.patch.object(campaign, "_new_pair", return_value=pair), \
                 mock.patch.object(campaign, "_replacement_bootstrap", return_value=command), \
                 mock.patch.object(campaign.public, "preinstall_status", return_value={"state": "observed", "jobId": campaign.base._LEGACY_JOB, "phase": "Running", "code": "RUNTIME_FAILED", "sequence": 3}), \
                 mock.patch.object(campaign.base, "diagnose") as generic, \
                 mock.patch.object(campaign.base, "_legacy_task_observation") as task_census:
                result = campaign.diagnose(root, {"host": "archlinux", "leaseId": LEASE})
        self.assertEqual({"state": "observed", "phase": "legacy-job"},
                         {"state": result["state"], "phase": result["phase"]})
        self.assertNotIn("request", result)
        generic.assert_not_called()
        task_census.assert_not_called()

    def test_green_source_diagnosis_stops_before_legacy_attestation_or_lease_claim(self):
        pair = self._pair(sourceFingerprint="d" * 64, baseCliSha256="a" * 64,
                          baseAppJarSha256="b" * 64, baseHelperSha256="c" * 64,
                          baseAppJarName="desktopApp-2.1.19.jar", baseRuntimeSha256="e" * 64,
                          targetMsiSha256="f" * 64, targetMsiSize=1)
        command = "replacement-bootstrap"
        record = {"request": {"host": "archlinux", "correlationId": LEASE, "sourceSha": campaign._SOURCE,
                               "fixtureReceiptArtifactId": campaign._RECEIPT, "baseMsiArtifactId": campaign._BASE,
                               "targetMsiArtifactId": campaign._TARGET, "expectedCurrentVersion": "2.1.19"},
                  "pair": pair, "environment": DESC[0], "socketPath": DESC[1], "pid": DESC[2],
                  "startTicks": DESC[3], "expectedSid": DESC[4],
                  "commandSha256": __import__("hashlib").sha256(command.encode("utf-16le")).hexdigest(), "leaseId": LEASE}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); campaign.base._reserve(root, record)
            with mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
                 mock.patch.object(campaign.base, "_stage_artifact_readonly", return_value=(pair, 1)), \
                 mock.patch.object(campaign, "_new_pair", return_value=pair), \
                 mock.patch.object(campaign, "_replacement_bootstrap", return_value=command), \
                 mock.patch.object(campaign.public, "preinstall_status", return_value={"state": "observed", "jobId": campaign.base._LEGACY_JOB, "phase": "Failed", "code": "RUNTIME_FAILED", "sequence": 3}), \
                 mock.patch.object(campaign.base, "readiness", return_value={"state": "ready", "activeCount": 0}), \
                 mock.patch.object(campaign.base, "_legacy_task_observation", return_value={"state": "cleaned"}), \
                 mock.patch.object(campaign.base, "_legacy_history_observation", return_value={"state": "clean"}), \
                 mock.patch.object(campaign.lease, "attest_legacy_closed") as attest, \
                 mock.patch.object(campaign.lease, "begin") as begin:
                result = campaign.diagnose(root, {"host": "archlinux", "leaseId": LEASE})
        self.assertEqual("pre-effect", result["phase"])
        attest.assert_not_called()
        begin.assert_not_called()

    def test_red_preflight_blocks_legacy_task_census_before_reserving_source_intent(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign, "_retirement_terminal", return_value=True), \
             mock.patch.object(campaign, "_fresh_absence", return_value=True), \
             mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(campaign.base, "readiness", return_value=self._idle()), \
             mock.patch.object(campaign.public, "_admit_pair", return_value=self._pair()), \
             mock.patch.object(campaign.public, "preinstall_status", return_value={"state": "observed", "jobId": campaign.base._LEGACY_JOB, "phase": "Failed", "code": "RUNTIME_FAILED", "sequence": 3}), \
             mock.patch.object(campaign.base, "_legacy_task_observation", return_value={"state": "blocked"}), \
             mock.patch.object(campaign.base, "_legacy_history_observation") as history:
            result = campaign.preflight(Path(directory), {"host": "archlinux", "leaseId": LEASE})
        self.assertEqual({"state": "blocked", "reason": "legacy-tasks"},
                         {"state": result["state"], "reason": result["reason"]})
        history.assert_not_called()

    def test_legacy_task_diagnosis_reports_only_fixed_bounded_categories(self):
        raw = '{"state":"observed","inventory":{"version":1,"legacy":0,"c32":1,"recovery":1,"retirement":0,"other":0,"activeInstallerCount":0,"identities":[],"unclassifiedTaskCount":0}}'
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(campaign.base, "_remote", return_value=raw) as remote:
            result = campaign._legacy_task_inventory(Path(directory), DESC)
        self.assertEqual({"legacy": 0, "c32": 1, "recovery": 1, "retirement": 0,
                          "other": 0, "activeInstallerCount": 0, "identities": [],
                          "unclassifiedTaskCount": 0}, result)
        self.assertEqual(campaign.base._READINESS, remote.call_args.args[1])
        script = campaign._legacy_task_inventory_script()
        self.assertIn("Parser]::ParseInput", script)
        self.assertIn("VpnControlMcpBase-c32cb108-4d48-407e-9153-40774559ba50", script)
        self.assertIn("VpnControlCp117GuestAgentRecovery-c2c0e5c9-77aa-4bd2-91a1-fb7540aa9f58", script)
        self.assertIn("VpnControlCp117RetirementRecovery-f72ecafe-1890-4e17-a954-1d045dfa0ea3", script)

    def test_red_legacy_task_diagnosis_rejects_bool_or_unbounded_counts(self):
        for changed in ({"legacy": True}, {"other": 1001}):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as directory:
                inventory = {"version": 1, "legacy": 0, "c32": 0, "recovery": 0,
                             "retirement": 0, "other": 0, "activeInstallerCount": 0,
                             "identities": [], "unclassifiedTaskCount": 0, **changed}
                raw = __import__("json").dumps({"state": "observed", "inventory": inventory})
                with mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
                     mock.patch.object(campaign.base, "_remote", return_value=raw):
                    self.assertIsNone(campaign._legacy_task_inventory(Path(directory), DESC))

    def test_diagnose_includes_task_counts_only_for_a_valid_legacy_task_observation(self):
        counts = {"legacy": 0, "c32": 1, "recovery": 1, "retirement": 0,
                  "other": 0, "activeInstallerCount": 0, "identities": [], "unclassifiedTaskCount": 0}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign, "_pre_dispatch_phase", return_value=("legacy-tasks", counts)):
            observed = campaign.diagnose(Path(directory), {"host": "archlinux", "leaseId": LEASE})
        self.assertEqual("observed", observed["legacyTaskState"])
        self.assertEqual({key: value for key, value in counts.items() if key not in {"identities", "unclassifiedTaskCount"}}, observed["legacyTasks"])

    def test_legacy_task_inventory_sanitizes_only_known_prefix_uuid_identities(self):
        identity = {"purpose": "fixture-server", "correlationId": "11111111-1111-4111-8111-111111111111", "taskState": "ready"}
        inventory = {"version": 1, "legacy": 0, "c32": 1, "recovery": 1, "retirement": 0,
                     "other": 1, "activeInstallerCount": 0, "identities": [identity], "unclassifiedTaskCount": 0}
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(campaign.base, "_remote", return_value=__import__("json").dumps({"state": "observed", "inventory": inventory})):
            result = campaign._legacy_task_inventory(Path(directory), DESC)
        self.assertEqual([identity], result["identities"])
        self.assertEqual(0, result["unclassifiedTaskCount"])
        inventory["identities"] = [{**identity, "correlationId": "not-a-uuid"}]
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
             mock.patch.object(campaign.base, "_remote", return_value=__import__("json").dumps({"state": "observed", "inventory": inventory})):
            self.assertIsNone(campaign._legacy_task_inventory(Path(directory), DESC))


class Source67ArchiveReservationTests(unittest.TestCase):
    def test_red_c32_archive_recognition_uses_source67_lease_while_diagnose_uses_prospective_lease(self):
        """Keep the real lease-dependent disagreement visible to the base owner."""
        c32 = campaign._HISTORICAL_BASE
        prospective = "a37d9b94-2e7c-4e2a-94a0-09e8b8170224"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); local = root / campaign.base._LOCAL
            local.mkdir(parents=True, mode=0o700); (local / (c32 + ".json")).write_text("{}")
            calls = []
            def archive_preflight(_root, value):
                calls.append(value["leaseId"])
                return ({"state": "ready", "correlationId": c32, "replayAllowed": False,
                         "nativeActionAllowed": False, "productAction": False}
                        if value["leaseId"] == prospective else {"state": "blocked", "phase": "lease"})
            with mock.patch.object(campaign.base, "_descriptor", return_value=(object(), object(), DESC)), \
                    mock.patch("agent_tools.windows_cp117_c32_archive_admission.preflight", side_effect=archive_preflight):
                campaign.base._archived_base_record_names(root, object(), object(), DESC)
                self.assertEqual(["67eeeedb-a618-42d5-8e31-821650d16302"], calls)
                campaign.reservation_diagnose(root, {"host": "archlinux", "leaseId": prospective})
            self.assertEqual(["67eeeedb-a618-42d5-8e31-821650d16302",
                              "67eeeedb-a618-42d5-8e31-821650d16302", prospective], calls)

    def test_closed_source67_admits_different_lease_and_preserves_original_bytes(self):
        from agent_tools.tests.test_windows_cp117_source_pre_effect_close import source67_archive_fixture
        from agent_tools import windows_cp117_source_pre_effect_close as close
        with source67_archive_fixture() as (root, descriptor, _intent, _marker):
            original = close.base._intent_path(root, close._CORRELATION)
            marker = close._marker(root)
            before = (original.read_bytes(), marker.read_bytes())
            self.assertEqual("closed", close.status(root)["phase"])
            self.assertEqual((True, "ready"), campaign._reservation_readiness(root, object(), object(), descriptor, LEASE))
            self.assertEqual((False, "new-correlation-present"), campaign._reservation_readiness(root, object(), object(), descriptor, close._CORRELATION))
            self.assertEqual(before, (original.read_bytes(), marker.read_bytes()))


    def test_diagnostic_recognizes_fixed_marker_and_explains_unverified_closure(self):
        from agent_tools.tests.test_windows_cp117_source_pre_effect_close import source67_archive_fixture
        from agent_tools import windows_cp117_source_pre_effect_close as close
        with source67_archive_fixture() as (root, _descriptor, _intent, _marker):
            observed = campaign.reservation_diagnose(root, {"host": "archlinux", "leaseId": LEASE})
            self.assertEqual("observed", observed["state"])
            self.assertNotIn("blockers", observed)
            with mock.patch.object(close, "_guest_absent", return_value=None):
                blocked = campaign.reservation_diagnose(root, {"host": "archlinux", "leaseId": LEASE})
            self.assertEqual([{"record": "source-pre-effect", "phase": "fresh"}], blocked["blockers"])
            close._marker(root).unlink()
            blocked = campaign.reservation_diagnose(root, {"host": "archlinux", "leaseId": LEASE})
            self.assertEqual([{"record": "source-pre-effect", "phase": "marker"}], blocked["blockers"])
            # A malformed create-only receipt has the same non-admitted phase;
            # neither condition permits the old consumed intent to be reused.
            from agent_tools.windows_cp117_source_pre_effect_close import _status
            self.assertEqual("verified-absence", _status(root)[0])
            close._marker(root).write_text("{}")
            blocked = campaign.reservation_diagnose(root, {"host": "archlinux", "leaseId": LEASE})
            self.assertEqual([{"record": "source-pre-effect", "phase": "marker"}], blocked["blockers"])


if __name__ == "__main__":
    unittest.main()


class FixedTaskAdmissionBindingTests(unittest.TestCase):
    def test_source_legacy_gate_passes_current_lease_to_fixed_proof_reader(self):
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(campaign.public, "preinstall_status", return_value={
                 "state": "observed", "jobId": campaign.base._LEGACY_JOB, "phase": "Failed",
                 "code": "RUNTIME_FAILED", "sequence": 3}), \
             mock.patch.object(campaign.base, "_legacy_task_observation", return_value={"state": "blocked"}) as reader:
            root = Path(directory)
            self.assertEqual(campaign._legacy_admission_phase(root, DESC, {"state": "ready", "activeCount": 0}, LEASE), "legacy-tasks")
            reader.assert_called_once_with(root, DESC, LEASE)

    def test_diagnostic_inventory_counts_unknown_cp117_tasks(self):
        self.assertIn("^VpnControl(Mcp|Cp117)", campaign._legacy_task_inventory_script())

    def test_diagnostic_full_census_classifies_owned_subfolder_as_unknown(self):
        script = campaign._legacy_task_inventory_script()
        self.assertNotIn("Get-ScheduledTask -TaskPath", script)
        self.assertIn("$_.TaskPath -ceq '\\'", script)
        self.assertIn("$task.TaskPath -cne '\\'", script)

    def test_source_gate_excludes_consumed_unknown_static_retirement(self):
        from agent_tools import windows_cp117_static_tasks_retire as retire
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); journal = root / retire._DIR
            journal.mkdir(parents=True, mode=0o700); (journal / 'intent.json').write_text('{}')
            with mock.patch.object(campaign.public, 'preinstall_status', return_value={
                     'state': 'observed', 'jobId': campaign.base._LEGACY_JOB,
                     'phase': 'Failed', 'code': 'RUNTIME_FAILED', 'sequence': 3}), \
                 mock.patch.object(campaign.base, '_descriptor', return_value=(object(), object(), DESC)), \
                 mock.patch.object(retire, 'status', return_value=retire._result('unknown', 'dispatch')), \
                 mock.patch.object(campaign.base, '_remote') as remote:
                self.assertEqual(campaign._legacy_admission_phase(root, DESC, {'state': 'ready', 'activeCount': 0}, LEASE), 'legacy-tasks')
                remote.assert_not_called()
