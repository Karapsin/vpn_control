"""Real-process carrier regressions; native lease authority is out of scope."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

from agent_tools import android_component_successor as carrier
from agent_tools import durable_remote_job as durable


@unittest.skipUnless(os.name == "posix", "The original component carrier is POSIX-only")
class ComponentSuccessorTests(unittest.TestCase):
    def test_caller_deadline_preserves_original_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            marker = root / "effects"
            payload = ("import pathlib,time\np=pathlib.Path(" + repr(str(marker)) + ")\n"
                       "with p.open('a') as f:f.write('start\\n');f.flush()\n"
                       "time.sleep(.65)\n"
                       "with p.open('a') as f:f.write('complete\\n');f.flush()\n"
                       "print('complete-original')\n").encode()
            if os.environ.get("VPN_CONTROL_TEST_LEGACY_RECEIVER") == "1":
                # Complete immutable receiver/root beforeimages, with only the
                # documented .2-second timing and local principal/child seams.
                from agent_tools.tests.test_android_component_receiver_timeout import ReceiverTimeout
                before = ReceiverTimeout("test_whole_root_boot_releases_output_after_checked_close")
                before.exercise(before.root_child(payload), payload)
                time.sleep(.7)
                self.assertEqual(marker.read_text().splitlines(), ["start", "complete"])
                return
            jobs = root / "jobs"
            jobs.mkdir(mode=0o700)
            op = str(uuid.uuid4())
            binding = durable.current_binding("component-local-control", "owned-fixture")
            result_dir = jobs / op / "retained"
            source = carrier.program_source(payload, hashlib.sha256(payload).hexdigest(), op, result_dir)
            packet = root / "packet.json"
            packet.write_text(json.dumps({"op": op, "root": str(jobs), "binding": binding.__dict__,
                                          "source": source.decode()}))
            child = ("import json,pathlib,sys;sys.path.insert(0," + repr(str(Path(__file__).resolve().parents[2])) + ");"
                     "from agent_tools import durable_remote_job as d;"
                     "p=json.loads(pathlib.Path(sys.argv[1]).read_text());"
                     "r=pathlib.Path(p['root']);"
                     "d.submit(r,p['op'],d.MachineBinding.from_dict(p['binding']),"
                     "d.Program('android-component-cleanup-successor',p['source'].encode()),generation=d.root_generation(r))")
            process = subprocess.run([sys.executable, "-I", "-B", "-c", child, str(packet)],
                                     capture_output=True, timeout=5)
            self.assertEqual(process.returncode, 0, process.stderr)
            # The submitting client has exited, well before the payload's own
            # work completes. All later reads address this original admission.
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                status = durable.observe(jobs, op, binding, generation=durable.root_generation(jobs))
                if status["state"] == "terminal":
                    break
                time.sleep(.025)
            self.assertEqual(status["state"], "terminal", status)
            status, stdout, stderr = durable.collect(jobs, op, binding, generation=durable.root_generation(jobs))
            self.assertEqual((status["terminal"]["exitCode"], stderr), (0, b""))
            manifest = json.loads(stdout)
            self.assertEqual(marker.read_text().splitlines(), ["start", "complete"])
            # A repeated admission with the same ID observes; it cannot replay.
            durable.submit(jobs, op, binding, durable.Program("android-component-cleanup-successor", source),
                           generation=durable.root_generation(jobs))
            self.assertEqual(marker.read_text().splitlines(), ["start", "complete"])
            header, raw = carrier.read_slice(result_dir, manifest["manifestSha256"], "stdout", 0, 1024)
            self.assertEqual(raw, b"complete-original\n")
            self.assertEqual(header["operationId"], op)

    def test_complete_large_output_is_collected_in_bounded_slices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            size = 8 * 1024 * 1024 + 137
            payload = ("print('x'*" + str(size) + ",end='')").encode()
            if os.environ.get("VPN_CONTROL_TEST_LEGACY_RECEIVER") == "1":
                from agent_tools.tests.test_android_component_receiver_timeout import ReceiverTimeout
                before = ReceiverTimeout("test_complete_child_closes_protocol_without_timeout")
                before.exercise("import sys;sys.stdin.buffer.read();" + payload.decode())
                self.assertLessEqual(len(before.receiver_stdout), 8 * 1024 * 1024)
                return
            op = str(uuid.uuid4())
            result = carrier.execute_retained(payload, hashlib.sha256(payload).hexdigest(), op, root / "retained")
            self.assertLess(len(json.dumps(result)), 16384)
            parts = []
            for offset in range(0, size, carrier.MAX_SLICE_BYTES):
                header, part = carrier.read_slice(root / "retained", result["manifestSha256"], "stdout", offset,
                                                  carrier.MAX_SLICE_BYTES)
                self.assertLessEqual(len(part), carrier.MAX_SLICE_BYTES)
                self.assertLess(len(json.dumps(header)) + len(part), 8 * 1024 * 1024)
                parts.append(part)
            raw = b"".join(parts)
            self.assertEqual(len(raw), size)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), result["streams"]["stdout"]["sha256"])
            self.assertEqual(raw, b"x" * size)
            with self.assertRaisesRegex(ValueError, "successor_slice_invalid"):
                carrier.read_slice(root / "retained", result["manifestSha256"], "stdout", 0, 8 * 1024 * 1024)

    def test_overflow_keeps_partial_evidence_without_complete_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve() / "retained"
            payload = b"print('x'*2048)"
            with self.assertRaisesRegex(ValueError, "successor_observation_overflow"):
                carrier.execute_retained(payload, hashlib.sha256(payload).hexdigest(), str(uuid.uuid4()), directory,
                                         max_bytes=1024)
            self.assertTrue((directory / "intent.json").exists())
            self.assertFalse((directory / "complete.json").exists())

    def test_raw_records_and_manifest_have_the_same_bounded_collection(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve() / "retained"
            payload = b"CARRIER_RECORD_RAW('record',b'original-source-custody');CARRIER_RECORD_PHASE('closing-validation');print('complete')"
            result = carrier.execute_retained(payload, hashlib.sha256(payload).hexdigest(), str(uuid.uuid4()), directory)
            _, raw = carrier.read_slice(directory, result["manifestSha256"], "record-00000", 0, 4096)
            self.assertEqual(raw, b"original-source-custody")
            _, raw = carrier.read_slice(directory, result["manifestSha256"], "manifest", 0, 65536)
            manifest = json.loads(raw)
            self.assertEqual(len(manifest["records"]), 2)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), result["manifestSha256"])

    def test_held_stream_exchange_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve() / "retained"
            payload = b"print('original')"
            result = carrier.execute_retained(payload, hashlib.sha256(payload).hexdigest(), str(uuid.uuid4()), directory)
            stream = directory / "stdout.private"
            original = stream.read_bytes()
            stream.unlink()
            stream.write_bytes(original)
            stream.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "successor_stream_changed"):
                carrier.read_slice(directory, result["manifestSha256"], "stdout", 0, 1024)


if __name__ == "__main__":
    unittest.main()
