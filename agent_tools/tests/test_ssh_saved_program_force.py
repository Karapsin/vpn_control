"""Forced saved plans use the existing real local SSH peer and custody.

The separate retained-owner regression proves actual kernel E2BIG recovery.
These focused checks exercise this module's builder and typed exception seam.
"""
import errno
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from agent_tools import ssh_automatic_program as automatic
from agent_tools import ssh_transport as transport
from agent_tools.tests.test_ssh_automatic_program import PeerFixture


@unittest.skipUnless(os.name == "posix", "saved-program custody requires POSIX APIs")
class SavedProgramForceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.peer = PeerFixture(self.root)
        self.config = transport.load_config(self.root)

    def builder(self, command):
        return transport.build_saved_program_argv(self.config, "explicit-peer", 5,
            command=command, ssh_binary=str(self.peer.binary), nested_ssh_binary=str(self.peer.binary))

    def test_small_saved_plan_executes_exact_source_and_arguments_once(self):
        command = ("python3", "-I", "-B", "-c",
                   "import json,sys;print(json.dumps(sys.argv,ensure_ascii=False));raise SystemExit(7)",
                   "space argument", "Ж quote'\\")
        normal = transport.build_ssh_argv(self.config, "explicit-peer", 5, command=command,
                    ssh_binary=str(self.peer.binary), nested_ssh_binary=str(self.peer.binary))
        self.assertIsInstance(normal, list)
        plan = self.builder(command)
        self.assertIsInstance(plan, automatic.PlannedArgv)
        self.assertEqual(tuple(normal), plan.original_argv)
        self.assertEqual(transport.argv_sha256(normal), transport.argv_sha256(plan))
        self.assertLessEqual(automatic.command_bytes(normal), 60000)
        with self.peer.environment(), transport.automatic_submission(plan) as submitted:
            result = subprocess.run(submitted, input=b"", capture_output=True, timeout=10)
        self.assertEqual(7, result.returncode)
        self.assertEqual(["-c", *command[5:]], json.loads(result.stdout))
        self.assertEqual(b"", result.stderr)
        self.assertEqual(2, len(self.peer.events()))
        self.assertTrue(all(event["commandBytes"] <= 60000 and event["maxArgumentBytes"] <= 60000
                            for event in self.peer.events()))
        journal = self.root / ".rag_index/ssh-automatic-program" / plan.correlation
        self.assertEqual(command[4].encode(), (journal / "program.source").read_bytes())
        self.assertTrue((journal / "submission-returned.json").exists())
        with self.peer.environment(), self.assertRaises((FileExistsError, ValueError)):
            with transport.automatic_submission(plan):
                self.fail("A completed saved plan was replayed")
        self.assertEqual(2, len(self.peer.events()))

    def test_force_mode_is_exact_boolean_and_default_small_binding_unchanged(self):
        raw = ["ssh", "host", "true"]
        self.assertIs(raw, automatic.bind(None, None, None, (), None, None, raw))
        for invalid in (1, 0, None, "true", [], {}):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(ValueError, "automatic_force_file_mode"):
                automatic.bind(None, None, None, (), None, None, raw, force_file=invalid)

    def test_forced_builder_keeps_supported_source_and_residual_argument_limits(self):
        for command in (("sh", "-c", "true"),
                        ("python3", "-c", "print('small')", "x" * 60000)):
            with self.subTest(command=command[:2]), self.assertRaises(automatic.AutomaticProgramError):
                self.builder(command)
        self.assertEqual([], self.peer.events())
        self.assertFalse((self.root / ".rag_index/ssh-automatic-program").exists())

    def test_only_inline_popen_boundary_e2big_gets_typed_no_start_proof(self):
        argv = ["fixture-ssh", "host", "command"]
        error = OSError(errno.E2BIG, "actual boundary fixture")
        with mock.patch.object(transport.subprocess, "Popen", side_effect=error) as popen:
            with self.assertRaises(transport.PrelaunchE2Big) as raised:
                transport.popen_ssh(argv, stdout=subprocess.PIPE)
        self.assertEqual(1, popen.call_count)
        self.assertIs(error, raised.exception.__cause__)
        self.assertIs(error, raised.exception.original_error)
        self.assertEqual(errno.E2BIG, raised.exception.errno)
        self.assertEqual(transport.argv_sha256(argv), raised.exception.argv_sha256)
        self.assertIs(False, raised.exception.child_handle_returned)
        self.assertIs(False, raised.exception.executable_started)

    def test_other_inline_popen_errors_keep_original_identity_and_do_not_retry(self):
        for number in (errno.EACCES, errno.ENOENT, errno.EIO):
            error = OSError(number, "boundary fixture")
            with self.subTest(errno=number), mock.patch.object(transport.subprocess, "Popen", side_effect=error) as popen:
                with self.assertRaises(OSError) as raised:
                    transport.popen_ssh(["fixture-ssh", "host", "command"])
                self.assertIs(error, raised.exception)
                self.assertNotIsInstance(raised.exception, transport.PrelaunchE2Big)
                self.assertEqual(1, popen.call_count)

    def test_saved_submission_error_cannot_acquire_inline_no_start_proof(self):
        plan = self.builder(("python3", "-c", "print('source')"))
        error = OSError(errno.E2BIG, "saved submission fixture")
        with self.peer.environment(), mock.patch.object(automatic, "_stage", side_effect=error) as stage:
            with self.assertRaises(OSError) as raised:
                transport.popen_ssh(plan, stdout=subprocess.PIPE)
        self.assertIs(error, raised.exception)
        self.assertNotIsInstance(raised.exception, transport.PrelaunchE2Big)
        self.assertEqual(1, stage.call_count)
        self.assertEqual([], self.peer.events())
        self.assertTrue((self.root / ".rag_index/ssh-automatic-program" / plan.correlation / "unknown.json").exists())


if __name__ == "__main__":
    unittest.main()
