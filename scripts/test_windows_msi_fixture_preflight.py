#!/usr/bin/env python3
"""Portable causal regressions for Windows MSI fixture preflight."""

import hashlib
import json
import io
import stat
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_msi_fixture_preflight as subject  # noqa: E402


WIDTH, HEIGHT = 12, 8
TITLE = (1, 1, 5, 2)
ACCOUNT = (2, 3, 8, 4)
PASSWORD = (2, 5, 9, 6)
IDENTITY = subject.PromptIdentity("windows-cp175:589342:520739", "msi-cp175", "uac-cp175-1")


def frame(*, title: bytes, account: bytes = b"A", password: bytes = b"\xff") -> bytes:
    pixels = bytearray(b"\x33\x44\x55" * (WIDTH * HEIGHT))
    for value, rect in ((title, TITLE), (account, ACCOUNT), (password, PASSWORD)):
        x0, y0, x1, y1 = rect
        payload = (value * ((x1 - x0) * (y1 - y0)))[:(x1 - x0) * (y1 - y0)]
        for index, value_byte in enumerate(payload):
            x, y = x0 + index % (x1 - x0), y0 + index // (x1 - x0)
            pixels[(y * WIDTH + x) * 3:(y * WIDTH + x + 1) * 3] = bytes((value_byte,)) * 3
    return f"P6\n{WIDTH} {HEIGHT}\n255\n".encode() + bytes(pixels)


def crop(raw: bytes, rect: tuple[int, int, int, int]) -> bytes:
    header = f"P6\n{WIDTH} {HEIGHT}\n255\n".encode()
    pixels = raw[len(header):]
    x0, y0, x1, y1 = rect
    return b"".join(pixels[(y * WIDTH + x0) * 3:(y * WIDTH + x1) * 3] for y in range(y0, y1))


COMPACT = frame(title=b"C")
EXPANDED = frame(title=b"E")
PROFILE = subject.UacProfile(WIDTH, HEIGHT, TITLE, TITLE, ACCOUNT, PASSWORD,
    hashlib.sha256(crop(COMPACT, TITLE)).hexdigest(),
    hashlib.sha256(crop(EXPANDED, TITLE)).hexdigest(),
    hashlib.sha256(crop(COMPACT, ACCOUNT)).hexdigest(), 0)


class WindowsMsiFixturePreflightTest(unittest.TestCase):
    def test_cp175_old_compact_title_decision_is_red_but_correlated_expansion_is_green(self):
        # CP175 rejected here after More choices re-rasterized only the title.
        self.assertNotEqual(hashlib.sha256(crop(EXPANDED, TITLE)).hexdigest(), PROFILE.compact_title_sha256)
        accepted = subject.match_uac_after_expansion(
            compact_frame=COMPACT, expanded_frame=EXPANDED, expected_identity=IDENTITY,
            compact_identity=IDENTITY, expanded_identity=IDENTITY, profile=PROFILE)
        self.assertEqual("expanded", accepted["phase"])

    def test_expanded_title_cannot_bypass_prior_compact_match_or_prompt_binding(self):
        wrong_compact = frame(title=b"X")
        with self.assertRaisesRegex(subject.FixturePreflightError, "compact UAC app title"):
            subject.match_uac_after_expansion(compact_frame=wrong_compact, expanded_frame=EXPANDED,
                expected_identity=IDENTITY, compact_identity=IDENTITY, expanded_identity=IDENTITY, profile=PROFILE)
        changed = subject.PromptIdentity(IDENTITY.qemu_identity, IDENTITY.operation_id, "other-prompt")
        with self.assertRaisesRegex(subject.FixturePreflightError, "identity"):
            subject.match_uac_after_expansion(compact_frame=COMPACT, expanded_frame=EXPANDED,
                expected_identity=IDENTITY, compact_identity=IDENTITY, expanded_identity=changed, profile=PROFILE)

    def test_account_or_password_change_rejects_before_any_credential_read(self):
        for changed in (frame(title=b"E", account=b"B"), frame(title=b"E", password=b"D")):
            with self.subTest(digest=hashlib.sha256(changed).hexdigest()[:8]):
                with self.assertRaises(subject.FixturePreflightError):
                    subject.match_uac_after_expansion(compact_frame=COMPACT, expanded_frame=changed,
                        expected_identity=IDENTITY, compact_identity=IDENTITY, expanded_identity=IDENTITY, profile=PROFILE)

    def test_cp175_retained_ignored_fixture_reproduces_old_title_rejection_when_present(self):
        evidence = Path(__file__).parents[1] / ".runtime/parity-evidence/checkpoint175/windows-msi"
        ppm, record = evidence / "public-uac-prompt.ppm", evidence / "pixel-regression.json"
        if not (ppm.is_file() and record.is_file()):
            self.skipTest("CP175 ignored fixture is not present")
        metadata = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual([], metadata["titleSearch"]["matches"])
        self.assertEqual([382], metadata["accountSearch"]["matches"])
        self.assertFalse(metadata["privateHandleReadByUacDriver"])
        self.assertEqual(metadata["compactPromptSha256"], hashlib.sha256(ppm.read_bytes()).hexdigest())
        self.assertNotEqual(metadata["compactPromptSha256"], metadata["expandedPromptPpmSha256"])

    def test_cp175_real_profile_checks_title_before_selection_and_selected_account_after_expansion(self):
        evidence = Path(__file__).parents[1] / ".runtime/parity-evidence/checkpoint166/windows"
        compact, expanded = evidence / "cp175-public-uac-poll.ppm", evidence / "cp175-public-install-admin-selected.ppm"
        if not (compact.is_file() and expanded.is_file()):
            self.skipTest("CP175 ignored frames are not present")
        profile = subject.cp175_uac_profile()
        # The compact UAC frame predates account selection: its account crop is
        # deliberately not the approver crop, so admission must not inspect it.
        self.assertNotEqual(hashlib.sha256(subject._crop(compact.read_bytes(), profile.account_rect, profile.width, profile.height)).hexdigest(), profile.account_sha256)
        # CP175's old decision searched the expanded frame at the compact title
        # coordinates and found no match after More choices re-rasterized it.
        self.assertNotEqual(hashlib.sha256(subject._crop(expanded.read_bytes(), profile.compact_title_rect, profile.width, profile.height)).hexdigest(), profile.compact_title_sha256)
        accepted = subject.match_uac_after_expansion(
            compact_frame=compact.read_bytes(), expanded_frame=expanded.read_bytes(),
            expected_identity=IDENTITY, compact_identity=IDENTITY, expanded_identity=IDENTITY,
            profile=profile)
        self.assertEqual("expanded", accepted["phase"])
        receipt = Path(__file__).parents[1] / ".runtime/parity-evidence/checkpoint175/windows-msi/preflight-red-green.json"
        if receipt.is_file():
            recorded = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual(hashlib.sha256(compact.read_bytes()).hexdigest(), recorded["compactFrameSha256"])
            self.assertEqual(hashlib.sha256(expanded.read_bytes()).hexdigest(), recorded["expandedFrameSha256"])
            self.assertEqual(profile.expanded_title_sha256, recorded["green"]["expandedTitleSha256"])
            self.assertFalse(recorded["red"]["oldCompactTitleAtExpandedCoordinates"])

    def test_credential_path_rejects_world_writable_project_ancestor_before_file_use(self):
        # A mocked ancestry reproduces CP175 without relying on host /tmp mode.
        unsafe = Path("/Users/karapsin_de/Nextcloud/projects")
        credential = unsafe / "fixture-credential"
        unsafe_directory = type("Stat", (), {"st_mode": stat.S_IFDIR | 0o777, "st_uid": 1001, "st_size": 0})()
        with mock.patch.object(subject.os, "lstat", return_value=unsafe_directory), \
             mock.patch.object(subject, "_path_ancestors", return_value=[unsafe]):
            with self.assertRaisesRegex(subject.FixturePreflightError, "ancestry"):
                subject.admit_credential_path(credential, owner_uid=1001)

    def test_owner_only_file_and_ancestry_are_admitted_without_reading_secret(self):
        credential = Path("/owner-only/credential")
        owner = 1001
        directory = type("Stat", (), {"st_mode": stat.S_IFDIR | 0o700, "st_uid": owner, "st_size": 0})()
        root = type("Stat", (), {"st_mode": stat.S_IFDIR | 0o755, "st_uid": 0, "st_size": 0})()
        file = type("Stat", (), {"st_mode": stat.S_IFREG | 0o600, "st_uid": owner, "st_size": 6})()
        with mock.patch.object(subject, "_path_ancestors", return_value=[Path("/owner-only"), Path("/")]), \
             mock.patch.object(subject.os, "lstat", side_effect=[directory, root, file]):
            subject.admit_credential_path(credential, owner_uid=owner)
        unsafe_file = type("Stat", (), {"st_mode": stat.S_IFREG | 0o640, "st_uid": owner, "st_size": 6})()
        with mock.patch.object(subject, "_path_ancestors", return_value=[Path("/owner-only"), Path("/")]), \
             mock.patch.object(subject.os, "lstat", side_effect=[directory, root, unsafe_file]):
            with self.assertRaisesRegex(subject.FixturePreflightError, "file"):
                subject.admit_credential_path(credential, owner_uid=owner)

    def test_credential_only_cli_admits_before_any_uac_or_installer_input(self):
        receipt = Path("/owner-only/pre-install-receipt.json")
        with mock.patch.object(sys, "argv", ["preflight", "--credential-only", "--credential-path", "/owner-only/credential", "--receipt", str(receipt)]), \
             mock.patch.object(subject, "admit_credential_path") as credential, \
             mock.patch.object(subject, "match_uac_after_expansion", side_effect=AssertionError("must not inspect UAC")), \
             mock.patch.object(subject, "_write_receipt") as write:
            self.assertEqual(0, subject.main())
        credential.assert_called_once_with(Path("/owner-only/credential"))
        write.assert_called_once_with(receipt, {"phase": "credential-path", "credentialPathAdmitted": "true"})

    def test_credential_admission_without_posix_identity_fails_closed(self):
        no_identity = SimpleNamespace(lstat=mock.Mock())
        with mock.patch.object(subject, "os", no_identity):
            with self.assertRaisesRegex(subject.FixturePreflightError, "POSIX"):
                subject.admit_credential_path(Path("/private/credential"))
        no_identity.lstat.assert_not_called()

    def run_uac_cli(self, compact_observation=None, expanded_observation=None):
        arguments = ["preflight", "--credential-path", "/private/credential",
                     "--compact-frame", "compact.ppm", "--expanded-frame", "expanded.ppm",
                     "--qemu-identity", IDENTITY.qemu_identity,
                     "--operation-id", IDENTITY.operation_id, "--prompt-id", IDENTITY.prompt_id,
                     "--receipt", "/private/receipt.json"]
        if compact_observation is not None:
            arguments += ["--compact-observation", "compact.json"]
        if expanded_observation is not None:
            arguments += ["--expanded-observation", "expanded.json"]
        records = [json.dumps(compact_observation), json.dumps(expanded_observation)]
        with mock.patch.object(sys, "argv", arguments), \
             mock.patch.object(subject, "admit_credential_path"), \
             mock.patch.object(subject, "cp175_uac_profile", return_value=PROFILE), \
             mock.patch.object(Path, "read_bytes", side_effect=[COMPACT, EXPANDED]), \
             mock.patch.object(Path, "read_text", side_effect=records), \
             mock.patch.object(subject, "_write_receipt") as write, \
             redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            try:
                code = subject.main()
            except SystemExit as error:
                code = error.code
        return code, write

    @staticmethod
    def observation(phase, image):
        return {"version": 1, "phase": phase, "frameSha256": hashlib.sha256(image).hexdigest(),
                "qemuIdentity": IDENTITY.qemu_identity, "operationId": IDENTITY.operation_id,
                "promptId": IDENTITY.prompt_id}

    def test_uac_cli_requires_observed_identity_for_both_frames(self):
        code, write = self.run_uac_cli()
        self.assertEqual(2, code)
        write.assert_not_called()

    def test_uac_cli_binds_each_observation_to_its_frame_and_expected_prompt(self):
        compact = self.observation("compact", COMPACT)
        expanded = self.observation("expanded", EXPANDED)
        code, write = self.run_uac_cli(compact, expanded)
        self.assertEqual(0, code)
        self.assertEqual("expanded", write.call_args.args[1]["phase"])
        self.assertEqual(hashlib.sha256(COMPACT).hexdigest(), write.call_args.args[1]["compactFrameSha256"])
        self.assertEqual(hashlib.sha256(EXPANDED).hexdigest(), write.call_args.args[1]["expandedFrameSha256"])
        for field, bad in (("qemuIdentity", "other-guest"), ("operationId", "other-operation"),
                           ("promptId", "other-prompt"), ("frameSha256", "0" * 64),
                           ("phase", "compact"), ("version", True), ("privateInput", "unexpected")):
            with self.subTest(field=field):
                code, write = self.run_uac_cli(compact, {**expanded, field: bad})
                self.assertEqual(2, code)
                write.assert_not_called()


class LaunchPortabilityTest(unittest.TestCase):
    def test_routine_fixture_suite_runs_without_posix_identity_api(self):
        result = subprocess.run(
            [sys.executable, "-c", "import os, runpy, sys; "
             "os.__dict__.pop('getuid', None); "
             "sys.argv = [sys.argv[1], 'WindowsMsiFixturePreflightTest']; "
             "runpy.run_path(sys.argv[0], run_name='__main__')", str(Path(__file__).resolve())],
            cwd=Path(__file__).resolve().parent, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Ran 11 tests", result.stderr)


if __name__ == "__main__":
    unittest.main()
