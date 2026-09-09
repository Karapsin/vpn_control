import json
import hashlib
import os
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import patch
from pathlib import Path

from android_ssh_fixture import (SshdLogGeneration, SshdStartupUnknown, _claim_receipt, _write_claimed_receipt,
                                 start_task_sshd, wait_for_current_authentication)


class FakeProcess:
    def __init__(self, pid=42001):
        self.pid = pid
        self.exit = None
        self.terminated = False

    def poll(self):
        return self.exit

    def terminate(self):
        self.terminated = True
        self.exit = -15


class AndroidSshFixtureTest(unittest.TestCase):
    def test_post_spawn_receipt_failure_retains_live_process(self):
        for failed_write, startup in ((1, True), (2, True), (2, False)):
            with self.subTest(failed_write=failed_write, startup=startup), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                log = root / "fresh.log"
                process = FakeProcess()
                writes = 0

                def spawn(*_args, **_kwargs):
                    if startup:
                        log.write_text("Server listening on 127.0.0.1 port 59022\n")
                    return process

                def publish(*args):
                    nonlocal writes
                    writes += 1
                    if writes == failed_write:
                        raise OSError("Fixture receipt storage unavailable")
                    return _write_claimed_receipt(*args)

                with patch("android_ssh_fixture._write_claimed_receipt", side_effect=publish):
                    with self.assertRaises(SshdStartupUnknown) as caught:
                        start_task_sshd(
                            sshd=root / "sshd", config=root / "config", log_path=log,
                            receipt_path=root / "receipt.json", spawn=spawn, attempts=1, pause=lambda _: None,
                        )
                self.assertIs(caught.exception.generation.process, process)
                self.assertIsInstance(caught.exception.__cause__, OSError)
                self.assertEqual(process.pid, caught.exception.generation.pid)
                self.assertIsNotNone(caught.exception.generation.receipt_identity)
                self.assertFalse(process.terminated)

    def test_stale_prior_run_authentication_never_certifies_current_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "sshd.log"
            log.write_text("Accepted publickey for admin from prior-run\nServer listening on 127.0.0.1\n")
            stat = log.stat()
            offset = log.stat().st_size
            capture = SshdLogGeneration(7, "current", log, (stat.st_dev, stat.st_ino), offset,
                                         hashlib.sha256(log.read_bytes()[:offset]).digest(), FakeProcess())
            self.assertEqual((), capture.current_authentication_lines())

    def test_explicit_log_sink_binds_current_pid_and_observes_only_new_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "fresh.log"
            process = FakeProcess()
            captured = {}

            def spawn(command, **kwargs):
                captured["command"] = command
                captured["kwargs"] = kwargs
                log.write_text("Server listening on 127.0.0.1 port 59022\n")
                return process

            capture = start_task_sshd(
                sshd=root / "sshd", config=root / "sshd_config", log_path=log,
                spawn=spawn, attempts=1, pause=lambda _: None,
            )
            self.assertEqual(42001, capture.pid)
            self.assertTrue(capture.generation)
            self.assertEqual((str(root / "sshd"), "-D", "-E", str(log), "-f", str(root / "sshd_config")),
                             captured["command"])
            self.assertTrue(captured["kwargs"]["start_new_session"])
            if os.name == "posix":
                self.assertEqual(0o600, log.stat().st_mode & 0o777)
            log.write_text(log.read_text() + "Accepted publickey for admin from current-run\n")
            self.assertEqual(("Accepted publickey for admin from current-run",),
                             capture.current_authentication_lines())

    def test_authentication_written_with_startup_record_is_retained(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "fresh.log"

            def spawn(_command, **_kwargs):
                log.write_text("Server listening on 127.0.0.1 port 59022\nAccepted publickey for admin from current-run\n")
                return FakeProcess()

            capture = start_task_sshd(
                sshd=root / "sshd", config=root / "sshd_config", log_path=log,
                spawn=spawn, attempts=1, pause=lambda _: None,
            )
            self.assertEqual(("Accepted publickey for admin from current-run",),
                             capture.current_authentication_lines())

    def test_startup_rejects_replaced_log_even_when_replacement_has_startup_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "fresh.log"

            def spawn(_command, **_kwargs):
                replacement = root / "replacement.log"
                replacement.write_text("Server listening on 127.0.0.1 port stale\n")
                replacement.replace(log)
                return FakeProcess()

            with self.assertRaisesRegex(RuntimeError, "replaced"):
                start_task_sshd(
                    sshd=root / "sshd", config=root / "sshd_config", log_path=log,
                    spawn=spawn, attempts=1, pause=lambda _: None,
                )

    def test_missing_startup_log_is_unknown_and_receipted_without_losing_process(self):
        # Exercise OS/localized text on every host, not only on the Windows runner.
        for message in (None, "No such file or directory", "The system cannot find the file specified", "Datei nicht gefunden"):
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                log = root / "fresh.log"
                process = FakeProcess()

                def spawn(_command, **_kwargs):
                    log.unlink()
                    return process

                failure = (nullcontext() if message is None else
                           patch("android_ssh_fixture._read_current_file", side_effect=FileNotFoundError(2, message)))
                with failure:
                    with self.assertRaises(SshdStartupUnknown) as raised:
                        start_task_sshd(
                            sshd=root / "sshd", config=root / "sshd_config", log_path=log,
                            receipt_path=root / "receipt.json", spawn=spawn, attempts=1, pause=lambda _: None,
                        )
                self.assertIsInstance(raised.exception.__cause__, FileNotFoundError)
                self.assertIs(raised.exception.generation.process, process)
                self.assertEqual("unknown", json.loads((root / "receipt.json").read_text())["readiness"])

    def test_existing_log_is_rejected_before_spawn(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "stale.log"
            log.write_text("Accepted publickey for admin from old-run\n")
            spawned = False

            def spawn(*_args, **_kwargs):
                nonlocal spawned
                spawned = True
                return FakeProcess()

            with self.assertRaisesRegex(ValueError, "fresh"):
                start_task_sshd(
                    sshd=root / "sshd", config=root / "sshd_config", log_path=log,
                    spawn=spawn, attempts=1, pause=lambda _: None,
                )
            self.assertFalse(spawned)

    def test_replaced_log_cannot_supply_current_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "fresh.log"
            log.write_text("Server listening on 127.0.0.1\n")
            stat = log.stat()
            offset = log.stat().st_size
            capture = SshdLogGeneration(7, "current", log, (stat.st_dev, stat.st_ino), offset,
                                         hashlib.sha256(log.read_bytes()[:offset]).digest(), FakeProcess())
            replacement = root / "replacement.log"
            replacement.write_text("Server listening on 127.0.0.1\nAccepted publickey for admin from replacement\n")
            replacement.replace(log)
            with self.assertRaisesRegex(RuntimeError, "replaced"):
                capture.current_authentication_lines()

    def test_same_inode_rewrite_cannot_change_the_startup_prefix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "fresh.log"
            log.write_text("Server listening on 127.0.0.1\n")
            stat = log.stat()
            offset = log.stat().st_size
            capture = SshdLogGeneration(7, "current", log, (stat.st_dev, stat.st_ino), offset,
                                         hashlib.sha256(log.read_bytes()[:offset]).digest(), FakeProcess())
            log.write_text("Server listening on 127.0.0.2\nAccepted publickey for admin from rewrite\n")
            with self.assertRaisesRegex(RuntimeError, "prefix changed"):
                capture.current_authentication_lines()

    def test_missing_current_startup_marker_preserves_spawned_generation_for_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = FakeProcess()
            with self.assertRaisesRegex(SshdStartupUnknown, "startup marker") as raised:
                start_task_sshd(
                    sshd=root / "sshd", config=root / "sshd_config", log_path=root / "fresh.log",
                    receipt_path=root / "receipt.json", spawn=lambda *_args, **_kwargs: process,
                    attempts=1, pause=lambda _: None,
                )
            self.assertFalse(process.terminated)
            self.assertEqual(42001, raised.exception.generation.pid)
            self.assertIsNone(raised.exception.generation.startup_offset)
            receipt = json.loads((root / "receipt.json").read_text())
            self.assertEqual("unknown", receipt["readiness"])
            self.assertEqual(42001, receipt["pid"])

    def test_unknown_startup_receipt_retains_process_and_log_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "fresh.log"
            log.write_text("")
            stat = log.stat()
            generation = SshdLogGeneration(42001, "generation", log, (stat.st_dev, stat.st_ino), None, None, FakeProcess())
            receipt = root / "receipt.json"
            _write_claimed_receipt(_claim_receipt(receipt), generation, "unknown")
            data = json.loads(receipt.read_text())
            self.assertEqual("unknown", data["readiness"])
            self.assertEqual(42001, data["pid"])
            self.assertEqual([stat.st_dev, stat.st_ino], data["logIdentity"])
            self.assertIsNone(data["startupOffset"])
            if os.name == "posix":
                self.assertEqual(0o600, receipt.stat().st_mode & 0o777)

    def test_live_consumer_observes_only_authentication_after_its_startup_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "fresh.log"

            def spawn(_command, **_kwargs):
                log.write_text("Server listening on 127.0.0.1 port 59022\n")
                return FakeProcess()

            capture = start_task_sshd(
                sshd=root / "sshd", config=root / "sshd_config", log_path=log,
                spawn=spawn, attempts=1, pause=lambda _: None,
            )
            pauses = 0

            def pause(_seconds):
                nonlocal pauses
                pauses += 1
                if pauses == 1:
                    log.write_text(log.read_text() + "Accepted publickey for admin from current-run\n")

            self.assertEqual(("Accepted publickey for admin from current-run",),
                             wait_for_current_authentication(capture, attempts=2, pause=pause))

    def test_receipt_is_claimed_before_spawn_and_existing_path_prevents_orphan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipt = root / "receipt.json"
            receipt.write_text("existing")
            spawned = False

            def spawn(*_args, **_kwargs):
                nonlocal spawned
                spawned = True
                return FakeProcess()

            with self.assertRaisesRegex(ValueError, "receipt"):
                start_task_sshd(
                    sshd=root / "sshd", config=root / "sshd_config", log_path=root / "fresh.log",
                    receipt_path=receipt, spawn=spawn, attempts=1, pause=lambda _: None,
                )
            self.assertFalse(spawned)


if __name__ == "__main__":
    unittest.main()
