import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from uuid import NAMESPACE_URL, uuid5

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_providers as providers
from agent_tools import readiness_adb_transport as transport


class OwnedAdbTransportTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.root.chmod(0o700)
        self.binding = providers.AndroidBinding("owned", "task-avd", Path("/fixed/adb"),
                                                "task-avd", "emulator-5660", 5038)
        self.host = jobs.current_binding("owned", "actual-test-host")
        self.original = {"pid": 999999999, "birth": "missing", "uid": os.geteuid(), "commandSha256": "0"*64}
        self.owner = transport.OwnedAdbTransport(self.binding, self.original, self.root, self.host, lambda: None)

    def test_dead_original_observation_is_pure_and_foreign_listener_blocks(self):
        with mock.patch.object(self.owner, "_listener", return_value=None):
            self.assertEqual(self.owner.observe(time.monotonic()+5), ("dead", "adb:999999999:missing"))
        self.assertEqual(list(self.root.iterdir()), [])
        with mock.patch.object(self.owner, "_listener", return_value={"pid": 2}):
            with self.assertRaisesRegex(providers.ProviderError, "android_adb_listener_unrecognized"):
                self.owner.observe(time.monotonic()+5)

    def test_original_live_generation_does_not_create_recovery(self):
        original = {"pid": os.getpid(), "birth": jobs._birth(os.getpid()),
                    "uid": os.geteuid(), "commandSha256": "0"*64}
        self.owner.original = original
        with mock.patch.object(self.owner, "_listener", return_value=original), mock.patch.object(jobs, "submit") as submit:
            state, connection = self.owner.observe(time.monotonic()+5)
            self.assertEqual(state, "ready")
            self.owner.recover("1"*64, connection, time.monotonic()+5)
            submit.assert_not_called()

    def test_lost_original_admission_ack_remains_unknown_without_replacement(self):
        self.owner.job_root.mkdir(mode=0o700)
        rid = "2"*64; operation = str(uuid5(NAMESPACE_URL, "android-private-adb:"+rid))
        program = transport.daemon_program(self.owner.job_root, operation, self.host, self.binding)
        jobs._publish(self.root/"adb-generation-000000.json", {"index": 0,"operationId":operation,
             "recoveryId":rid,"programSha256":program.digest,"jobRootGeneration":list(jobs.root_generation(self.owner.job_root))})
        with mock.patch.object(self.owner, "_listener", return_value=None), mock.patch.object(jobs, "submit") as submit:
            with self.assertRaisesRegex(providers.ProviderError, "android_adb_lineage_unknown"):
                self.owner.recover("3"*64, "old", time.monotonic()+5)
            submit.assert_not_called()

    def test_daemon_program_is_snapshotted_and_fixed(self):
        operation = str(uuid5(NAMESPACE_URL,"android-private-adb:"+"4"*64))
        program = transport.daemon_program(self.owner.job_root, operation, self.host, self.binding)
        source = program.source.decode()
        self.assertIn("server", source); self.assertIn("nodaemon", source)
        self.assertNotIn(str(Path(transport.__file__)), source)
        compile(source,"actual-generated-daemon","exec")

    def test_caller_deadline_bounds_listener_process_observation(self):
        limit=time.monotonic()+.1
        def run(argv, **options):
            self.assertGreater(options["timeout"],0)
            self.assertLessEqual(options["timeout"],.1)
            return subprocess.CompletedProcess(argv,1,b"",b"")
        with mock.patch.object(transport.subprocess,"run",side_effect=run):
            self.assertIsNone(self.owner._listener(limit))

    def test_foreign_listener_is_rejected_before_argv_inspection(self):
        calls=[]
        def run(argv,**options):
            calls.append(argv)
            if argv[0]=="lsof":return subprocess.CompletedProcess(argv,0,b"p123\n",b"")
            if argv[-1]=="comm=":return subprocess.CompletedProcess(argv,0,b"/foreign/executable\n",b"")
            self.fail("foreign process argv must never be read or hashed")
        with mock.patch.object(transport.subprocess,"run",side_effect=run),mock.patch.object(jobs,"_birth",return_value="generation"), \
                mock.patch.object(transport,"_executable",return_value=Path("/foreign/executable")):
            with self.assertRaisesRegex(providers.ProviderError,"android_adb_listener_unrecognized"):
                self.owner._listener(time.monotonic()+5)
        self.assertEqual(len(calls),1)

    def test_original_daemon_rewritten_argv0_uses_kernel_executable_identity(self):
        command="adb -L tcp:localhost:5038 fork-server server --reply-fd 4"
        def run(argv,**options):
            replies={"comm=":b"adb\n","uid=":str(os.geteuid()).encode()+b"\n","command=":command.encode()+b"\n"}
            return subprocess.CompletedProcess(argv,0,b"p123\n" if argv[0]=="lsof" else replies[argv[-1]],b"")
        with mock.patch.object(transport.subprocess,"run",side_effect=run),mock.patch.object(jobs,"_birth",return_value="generation"), \
                mock.patch.object(transport,"_executable",return_value=self.binding.adb):
            value=self.owner._listener(time.monotonic()+5)
        self.assertEqual(value,{"pid":123,"birth":"generation","uid":os.geteuid(),"commandSha256":hashlib.sha256(command.encode()).hexdigest()})

    def test_publishing_owner_is_observed_without_second_submission(self):
        with mock.patch.object(self.owner,"observe",side_effect=[("dead","old"),
                providers.ProviderError("android_adb_lineage_unknown"),("ready","new")]), \
                mock.patch.object(self.owner,"_listener",return_value=None), \
                mock.patch.object(jobs,"submit") as submit:
            self.owner.recover("5"*64,"old",time.monotonic()+5)
        self.assertEqual(submit.call_count,1)
        self.assertEqual(len(list(self.root.glob("adb-generation-*.json"))),1)

    def test_client_race_cannot_implicitly_create_daemon(self):
        # A controlled native client reproduces the installed ADB rule: only
        # the numeric-host route refuses daemon startup after listener loss.
        created = self.root/"implicit-daemon"
        executable = self.root/"adb"
        executable.write_text("#!"+sys.executable+"\nimport sys,pathlib\n"
            "if sys.argv[1:3] != ['-H','127.0.0.1']:\n pathlib.Path("+repr(str(created))+").write_text('unowned')\n"
            "sys.exit(1)\n")
        executable.chmod(0o700)
        binding = providers.AndroidBinding("owned","task-avd",executable,"task-avd","emulator-5660",5038)
        backend = providers.AndroidAdbBackend(binding, lambda:"listener-lost-after-guard")
        with self.assertRaisesRegex(providers.ProviderError,"android_transport_unavailable"):
            backend._command(["shell","printf","sentinel"],time.monotonic()+5)
        self.assertFalse(created.exists(), "client created an unowned replacement daemon")


if __name__ == "__main__":
    unittest.main()
