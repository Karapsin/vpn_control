"""Causal contracts for the fixed Arch ``extra/tmux`` installer."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from agent_tools import arch_tmux_install as installer


CORR = "123e4567-e89b-12d3-a456-426614174000"
SHA = "a" * 40
SECRET = b"test-secret\n"
GENERATION = hashlib.sha256(repr([(path, 1, 2, 3, 4, 5, 0, 0, 2, 0o755) for path in
                                  ("/var/lib/pacman/local", "/var/lib/pacman/sync", "/var/cache/pacman/pkg")]).encode()).hexdigest()


class ArchTmuxInstallTest(unittest.TestCase):
    def _result(self, state: str = "ready") -> dict[str, object]:
        return {"schemaVersion": 1, "host": "archlinux", "correlationId": CORR, "sourceSha": SHA,
                "state": state, "repository": "extra", "package": "tmux", "candidateVersion": "3.5_a-1",
                "installedVersion": None, "lockClear": True, "cachePolicyValid": True,
                "fullGeneration": "b" * 64, "soleTransactionGuard": True,
                "pacmanSignatureVerified": False, "packageIntegrityVerified": False,
                "tmuxPresent": False, "remoteFence": "absent"}

    def test_remote_program_is_fixed_current_candidate_with_guarded_signed_transaction_and_fence(self) -> None:
        program = (installer._REMOTE.replace("__MODE__", repr("start")).replace("__CORR__", repr(CORR))
                   .replace("__SOURCE__", repr(SHA)).replace("__CANDIDATE__", repr("3.5_a-1"))
                   .replace("__GENERATION__", repr(GENERATION)))
        compile(program, "<arch-tmux-install>", "exec")
        self.assertIn("['/usr/bin/pacman','-Si',REPOSITORY+'/'+PACKAGE]", program)
        self.assertIn("['/usr/bin/pacman','-Qkk',PACKAGE]", program)
        self.assertIn("['/usr/bin/sudo','-S','-p',''", program)
        self.assertIn("os.O_EXCL", program)
        self.assertIn("/var/lib/pacman/db.lck", program)
        self.assertIn("pacman-key", program)
        calls: list[list[str]] = []

        def run(argv, **_kwargs):
            calls.append(argv)
            if argv[:3] == ["/usr/bin/pacman", "-Si", "extra/tmux"]:
                return SimpleNamespace(returncode=0, stdout=b"Repository : extra\nName : tmux\nVersion : 3.5_a-1\n")
            if argv[:3] == ["/usr/bin/pacman", "-Q", "tmux"]:
                return SimpleNamespace(returncode=0, stdout=b"tmux 3.5_a-1\n")
            if argv == ["/usr/bin/pacman-conf", "CacheDir"]:
                return SimpleNamespace(returncode=0, stdout=b"/var/cache/pacman/pkg/\n")
            return SimpleNamespace(returncode=0, stdout=b"")

        actual_stat = os.stat
        def lstat(path):
            if str(path) == "/var/lib/pacman/db.lck":
                raise FileNotFoundError()
            if str(path).startswith(home):
                return actual_stat(path)
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                                   st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4,
                                   st_size=5, st_nlink=2)
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {"HOME": home}), \
                mock.patch("subprocess.run", side_effect=run), \
                mock.patch("os.listdir", return_value=[]), \
                mock.patch("os.path.expanduser", side_effect=lambda value: value.replace("~", home, 1)), \
                mock.patch("os.lstat", side_effect=lstat), \
                mock.patch("os.stat", side_effect=lambda path: actual_stat(path) if str(path).startswith(home) else actual_stat(home)), \
                mock.patch("os.path.isfile", return_value=True), mock.patch("os.access", return_value=True), \
                mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(SECRET))), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(SystemExit):
                exec(program, {"__name__": "__main__"})
        response = json.loads(output.getvalue())
        self.assertEqual("verified", response["state"])
        transaction = next(argv for argv in calls if argv[:2] == ["/usr/bin/sudo", "-S"])
        self.assertEqual(transaction[-1], "extra/tmux=3.5_a-1")
        self.assertNotIn("--needed", transaction)
        self.assertNotIn(SECRET.decode().strip(), output.getvalue())

    def test_start_requires_full_readonly_admission_before_credential_or_intent(self) -> None:
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(installer, "preflight", return_value={"safeStartAllowed": False}) as preflight, \
                mock.patch.object(installer.credential_policy, "_read_credential") as credential:
            with self.assertRaisesRegex(ValueError, "preflight"):
                installer.start(root, host="archlinux", correlation_id=CORR, source_sha=SHA)
        preflight.assert_called_once()
        credential.assert_not_called()
        self.assertFalse((Path(root) / ".rag_index" / "arch-tmux-install" / "intent.json").exists())

    def test_generated_remote_treats_real_nul_secret_as_unknown_before_sudo(self) -> None:
        program = (installer._REMOTE.replace("__MODE__", repr("start")).replace("__CORR__", repr(CORR))
                   .replace("__SOURCE__", repr(SHA)).replace("__CANDIDATE__", repr("3.5_a-1"))
                   .replace("__GENERATION__", repr(GENERATION)))
        calls: list[list[str]] = []
        def run(argv, **_kwargs):
            calls.append(argv)
            if argv[:3] == ["/usr/bin/pacman", "-Si", "extra/tmux"]:
                return SimpleNamespace(returncode=0, stdout=b"Repository : extra\nName : tmux\nVersion : 3.5_a-1\n")
            if argv[:3] == ["/usr/bin/pacman", "-Q", "tmux"]:
                return SimpleNamespace(returncode=0, stdout=b"tmux 3.5_a-1\n")
            if argv == ["/usr/bin/pacman-conf", "CacheDir"]:
                return SimpleNamespace(returncode=0, stdout=b"/var/cache/pacman/pkg/\n")
            return SimpleNamespace(returncode=0, stdout=b"")
        fake = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                               st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4, st_size=5, st_nlink=2)
        with tempfile.TemporaryDirectory() as home, mock.patch("subprocess.run", side_effect=run), \
                mock.patch("os.listdir", return_value=[]), \
                mock.patch("os.lstat", side_effect=lambda p: (_ for _ in ()).throw(FileNotFoundError()) if str(p).endswith("db.lck") else os.stat(p) if str(p).startswith(home) else fake), \
                mock.patch("os.stat", return_value=fake), mock.patch("os.path.isfile", return_value=True), \
                mock.patch("os.access", return_value=True), \
                mock.patch("os.path.expanduser", side_effect=lambda value: value.replace("~", home, 1)), \
                mock.patch.object(sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"bad\0secret"))), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            exec(program, {"__name__": "__main__"})
        self.assertEqual("unknown", json.loads(output.getvalue())["state"])
        self.assertFalse(any(argv[:2] == ["/usr/bin/sudo", "-S"] for argv in calls))

    def test_generated_status_rejects_symlink_or_same_byte_fence_replacement(self) -> None:
        program = (installer._REMOTE.replace("__MODE__", repr("status")).replace("__CORR__", repr(CORR))
                   .replace("__SOURCE__", repr(SHA)).replace("__CANDIDATE__", repr("3.5_a-1"))
                   .replace("__GENERATION__", repr(GENERATION)))
        record = {"schemaVersion": 1, "correlationId": CORR, "sourceSha": SHA,
                  "candidateVersion": "3.5_a-1", "generation": GENERATION}
        terminal = record | {"state": "verified", "signature": True}
        def run(argv, **_kwargs):
            if argv[:3] == ["/usr/bin/pacman", "-Si", "extra/tmux"]:
                return SimpleNamespace(returncode=0, stdout=b"Repository : extra\nName : tmux\nVersion : 3.5_a-1\n")
            if argv[:3] == ["/usr/bin/pacman", "-Q", "tmux"]:
                return SimpleNamespace(returncode=0, stdout=b"tmux 3.5_a-1\n")
            if argv == ["/usr/bin/pacman-conf", "CacheDir"]:
                return SimpleNamespace(returncode=0, stdout=b"/var/cache/pacman/pkg/\n")
            return SimpleNamespace(returncode=0, stdout=b"")
        fake = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0,
                               st_dev=1, st_ino=2, st_mtime_ns=3, st_ctime_ns=4, st_size=5, st_nlink=2)
        with tempfile.TemporaryDirectory() as home:
            real_stat = os.stat
            directory = Path(home) / ".local/state/vpn-control/arch-tmux-install"
            directory.mkdir(parents=True, mode=0o700)
            fence = directory / f"{CORR}.json"; target = directory / "target"
            target.write_text(json.dumps(record)); fence.symlink_to(target)
            def lstat(path):
                if str(path).endswith("db.lck"): raise FileNotFoundError()
                return real_stat(path, follow_symlinks=False) if str(path).startswith(home) else fake
            with mock.patch("subprocess.run", side_effect=run), mock.patch("os.listdir", return_value=[]), \
                    mock.patch("os.lstat", side_effect=lstat), mock.patch("os.stat", return_value=fake), \
                    mock.patch("os.path.isfile", return_value=True), mock.patch("os.access", return_value=True), \
                    mock.patch("os.path.expanduser", side_effect=lambda value: value.replace("~", home, 1)), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                exec(program, {"__name__": "__main__"})
            self.assertEqual("unknown", json.loads(output.getvalue())["state"])
            fence.unlink(); fence.write_text(json.dumps(record)); (Path(str(fence) + ".terminal")).write_text(json.dumps(terminal))
            os.chmod(fence, 0o600); os.chmod(Path(str(fence) + ".terminal"), 0o600)
            real_read = os.read; replaced = False
            def replace_after_read(fd, count):
                nonlocal replaced
                data = real_read(fd, count)
                if not replaced:
                    replaced = True; replacement = directory / "replacement"; replacement.write_bytes(data); os.chmod(replacement, 0o600); os.replace(replacement, fence)
                return data
            with mock.patch("subprocess.run", side_effect=run), mock.patch("os.listdir", return_value=[]), \
                    mock.patch("os.lstat", side_effect=lstat), mock.patch("os.stat", return_value=fake), \
                    mock.patch("os.path.isfile", return_value=True), mock.patch("os.access", return_value=True), \
                    mock.patch("os.path.expanduser", side_effect=lambda value: value.replace("~", home, 1)), \
                    mock.patch("os.read", side_effect=replace_after_read), contextlib.redirect_stdout(io.StringIO()) as output:
                exec(program, {"__name__": "__main__"})
            self.assertTrue(replaced)
            self.assertEqual("unknown", json.loads(output.getvalue())["state"])

    def test_start_fences_exact_source_candidate_and_unknown_never_replays(self) -> None:
        admission = self._result()
        public_admission = {key: admission[key] for key in admission if key not in {"schemaVersion"}}
        public_admission.update({"credentialMetadataValid": True, "signaturePolicy": "required-trusted-explicit",
                                 "sourceBinding": "c" * 64, "safeStartAllowed": True})
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(installer, "preflight", return_value=public_admission), \
                mock.patch.object(installer, "_source_binding", return_value="c" * 64), \
                mock.patch.object(installer.credential_policy, "_signature_policy", return_value=True), \
                mock.patch.object(installer.credential_policy, "_read_credential", return_value=SECRET), \
                mock.patch.object(installer, "_remote", side_effect=ValueError("lost response")) as remote:
            result = installer.start(root, host="archlinux", correlation_id=CORR, source_sha=SHA)
            self.assertEqual("unknown", result["state"])
            self.assertFalse(result["replayAllowed"])
            intent = installer._read_intent(installer._journal(root, False), CORR, SHA)
            self.assertEqual("3.5_a-1", intent["candidateVersion"])
            self.assertEqual(SHA, intent["sourceSha"])
            self.assertEqual("c" * 64, intent["sourceBinding"])
            with self.assertRaisesRegex(ValueError, "already exists"):
                installer.start(root, host="archlinux", correlation_id=CORR, source_sha=SHA)
        remote.assert_called_once()

    def test_source_or_helper_config_drift_closes_preflight_and_status_without_ssh(self) -> None:
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(installer, "_source_binding", return_value=None), \
                mock.patch.object(installer.credential_policy, "_credential_metadata", return_value=False), \
                mock.patch.object(installer.credential_policy, "_signature_policy_state", return_value="unavailable"), \
                mock.patch.object(installer, "_remote") as remote:
            result = installer.preflight(root, host="archlinux", correlation_id=CORR, source_sha=SHA)
        self.assertEqual("source-closed", result["state"])
        self.assertFalse(result["safeStartAllowed"])
        remote.assert_not_called()

    def test_status_is_readonly_requires_exact_intent_and_never_reads_credential(self) -> None:
        with tempfile.TemporaryDirectory() as root, \
                mock.patch.object(installer.credential_policy, "_read_credential") as credential:
            absent = installer.status(root, host="archlinux", correlation_id=CORR, source_sha=SHA)
        self.assertEqual("intent-absent", absent["state"])
        self.assertFalse(absent["nativeActionAllowed"])
        credential.assert_not_called()

    def test_validation_rejects_general_host_package_versions_and_invalid_source(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            for kwargs in ({"host": "other"}, {"correlation_id": "bad"}, {"source_sha": "b" * 64}, {"timeout_seconds": True}):
                values = {"host": "archlinux", "correlation_id": CORR, "source_sha": SHA, "timeout_seconds": 60} | kwargs
                with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                    installer.preflight(root, **values)


if __name__ == "__main__":
    unittest.main()
