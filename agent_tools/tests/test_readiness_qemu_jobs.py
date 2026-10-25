"""Execute the complete fixed guest caller/owner in an isolated real namespace."""
import base64
import ast
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
import os
import plistlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
from uuid import uuid4

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_qemu_jobs as protocol


@unittest.skipUnless(os.name == "posix" and os.geteuid() > 0, "ordinary POSIX account required")
class GuestNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.machine = (Path('/etc/machine-id').read_text().strip() if sys.platform.startswith('linux') else
                        plistlib.loads(subprocess.check_output(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice', '-a'], timeout=3))[0]['IOPlatformUUID'])
        self.root = str(Path(self.temp.name).resolve() / "jobs")
        self.patch = patch.object(protocol, "ROOT", self.root)
        self.patch.start()
        self.darwin_patch = patch.object(protocol, "DARWIN_ROOT", self.root)
        self.darwin_patch.start()
        self.binding = jobs.asdict(jobs.current_binding("fixture", self.machine))

    def tearDown(self):
        self.patch.stop()
        self.darwin_patch.stop()
        self.temp.cleanup()

    def call(self, source, *, good=True):
        argv, payload = protocol.stdin_command(source)
        result = subprocess.run([sys.executable, *argv[1:]], input=payload, capture_output=True, timeout=8)
        if not good:
            self.assertNotEqual(result.returncode, 0)
            return result
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return json.loads(result.stdout)

    def enroll(self):
        return self.call(protocol.enroll_program("fixture", self.machine, os.geteuid()))["namespace"]

    def terminal(self, packet, operation):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            value = self.call(protocol.operation_program(packet, operation, self.binding))
            if value["status"]["state"] == "terminal":
                return value
            time.sleep(.02)
        self.fail("original sentinel did not finish")

    def test_complete_generated_owner_once_retains_streams_counter_and_idle(self):
        packet = self.enroll()
        self.assertTrue(self.call(protocol.observe_program(packet))["idle"])
        operation = str(uuid4())
        source = protocol.operation_program(packet, operation, self.binding, submit=True, count=12, interval_seconds=.02)
        with ThreadPoolExecutor(max_workers=3) as pool:
            list(pool.map(self.call, [source] * 3))
        retained = self.terminal(packet, operation)
        self.assertEqual(base64.b64decode(retained["stdout"]).splitlines(), [str(n).encode() for n in range(12)])
        self.assertEqual(base64.b64decode(retained["stderr"]), b"guest sentinel retained stderr\n")
        self.assertEqual(base64.b64decode(retained["counter"]).splitlines(), [b"execution", *[str(n).encode() for n in range(12)]])
        self.assertEqual(self.call(source), retained)
        self.assertTrue(self.call(protocol.observe_program(packet))["idle"])
        (Path(self.root) / operation / "stdout.bin").write_bytes(b"changed")
        self.call(protocol.observe_program(packet), good=False)

    def test_enrolled_deleted_replaced_and_foreign_namespaces_never_idle(self):
        packet = self.enroll()
        shutil.rmtree(self.root)
        self.call(protocol.observe_program(packet), good=False)
        Path(self.root).mkdir(mode=0o700)
        self.call(protocol.enroll_program("fixture", self.machine, os.geteuid()), good=False)
        self.call(protocol.observe_program(packet), good=False)

    def test_incomplete_admitted_job_and_foreign_files_block_visibility(self):
        packet = self.enroll()
        foreign = Path(self.root) / str(uuid4())
        foreign.mkdir(mode=0o700)
        self.call(protocol.observe_program(packet), good=False)
        foreign.rmdir()
        (Path(self.root) / "unrecognized").write_text("unknown")
        self.call(protocol.observe_program(packet), good=False)

    def test_payload_change_and_wrong_account_rejected_before_namespace_creation(self):
        source = protocol.enroll_program("fixture", self.machine, os.geteuid())
        argv, payload = protocol.stdin_command(source)
        result = subprocess.run([sys.executable, *argv[1:]], input=payload+b"\n", capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(Path(self.root).exists())
        self.call(protocol.enroll_program("fixture", self.machine, os.geteuid()+1), good=False)
        self.assertFalse(Path(self.root).exists())
        self.call(protocol.enroll_program("fixture", "different-machine", os.geteuid()), good=False)
        self.assertFalse(Path(self.root).exists())

    def test_boot_change_cannot_submit_or_replay(self):
        packet = self.enroll()
        wrong = {**self.binding, "boot": "different-boot"}
        operation = str(uuid4())
        self.call(protocol.operation_program(packet, operation, wrong, submit=True), good=False)
        self.assertFalse((Path(self.root) / operation).exists())

    def before(self, group):
        directory = Path(__file__).parent / "fixtures" / group
        path = directory / "readiness_qemu_jobs.py.source"
        raw = path.read_bytes()
        proof = json.loads((directory / "provenance.json").read_bytes())["sha256"]
        self.assertEqual(hashlib.sha256(raw).hexdigest(), proof if type(proof) is str else proof["readiness_qemu_jobs.py"])
        module = types.ModuleType("agent_tools.guest_namespace_before")
        module.__file__ = str(path); module.__package__ = "agent_tools"
        exec(compile(raw, str(path), "exec"), module.__dict__)
        module.ROOT = self.root
        return module

    def test_old_boot_unsubmitted_whole_before_red_current_absence_proof_green(self):
        before = self.before("guest_unsubmitted_boot_before")
        stale = {**self.binding, "boot": str(uuid4())}
        operation = str(uuid4())
        packet = self.call(before.enroll_program("fixture", self.machine, os.geteuid()))["namespace"]
        old = self.call(before.operation_program(packet, operation, stale))
        with self.assertRaises(AssertionError):
            self.assertEqual(old["status"]["state"], "unsubmitted")
        self.assertEqual(old["status"]["reason"], "boot_changed")
        self.assertFalse((Path(self.root) / operation).exists())
        self.root += "-current"
        protocol.ROOT = protocol.DARWIN_ROOT = self.root
        packet = self.enroll()
        current = self.call(protocol.operation_program(packet, operation, stale))
        self.assertEqual(current["status"]["state"], "unsubmitted")
        self.assertFalse(current["admissionConsumed"])
        self.assertEqual(current["unsubmittedProof"]["binding"], self.binding)
        self.assertEqual(current["unsubmittedProof"]["admissionGeneration"], packet["admissionGeneration"])
        self.call(protocol.operation_program(packet, operation, self.binding, submit=True, count=2, interval_seconds=.01))
        self.terminal(packet, operation)
        # Independent admission index preserves uncertainty after jobdir loss.
        shutil.rmtree(Path(self.root) / operation)
        lost = self.call(protocol.operation_program(packet, operation, stale))
        self.assertEqual(lost["status"]["reason"], "original_admission_lost")
        self.assertTrue(lost["admissionConsumed"])
        self.call(protocol.observe_program(packet), good=False)

    def test_actual_concurrent_publication_before_red_current_unknown_once_green(self):
        before = self.before("guest_namespace_publication_before")
        raw = jobs.owner_source()
        needle = b"        job.mkdir(mode=0o700)\n"
        self.assertEqual(raw.count(needle), 1)
        delayed = raw.replace(needle, needle+b"        time.sleep(.3)  # controlled original intent publication window\n")
        for index, module in enumerate((before, protocol)):
            self.root = str(Path(self.temp.name).resolve() / ("publication-"+str(index)))
            module.ROOT = module.DARWIN_ROOT = self.root
            protocol.ROOT = protocol.DARWIN_ROOT = self.root
            with patch.object(jobs, "owner_source", return_value=delayed):
                packet = self.call(module.enroll_program("fixture", self.machine, os.geteuid()))["namespace"]
                operation = str(uuid4())
                source = module.operation_program(packet, operation, self.binding, submit=True, count=3, interval_seconds=.01)
                argv, payload = protocol.stdin_command(source)
                first = subprocess.Popen([sys.executable, *argv[1:]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                first.stdin.write(payload); first.stdin.close(); first.stdin = None
                deadline = time.monotonic()+3
                while not (Path(self.root) / operation).exists() and time.monotonic() < deadline:
                    time.sleep(.005)
                if index == 0:
                    self.call(source, good=False)  # actual whole unfixed caller RED
                else:
                    reply = self.call(source)
                    self.assertTrue(reply["admissionConsumed"])
                stdout, stderr = first.communicate(timeout=5)
                self.assertEqual(first.returncode, 0, stderr.decode())
                self.assertTrue(json.loads(stdout)["admissionConsumed"])
                terminal = self.terminal(packet, operation)
                self.assertEqual(base64.b64decode(terminal["counter"]).splitlines(), [b"execution", b"0", b"1", b"2"])

    def test_actual_atomic_index_publication_before_red_current_clean_once_green(self):
        before = self.before("guest_namespace_index_publication_before")
        raw = jobs.owner_source()
        needle = b"    os.link(temp, path, follow_symlinks=False)\n"
        self.assertEqual(raw.count(needle), 1)
        delayed = raw.replace(needle, b"    if path.parent.name == 'admissions': time.sleep(.25)\n"+needle)
        for index, module in enumerate((before, protocol)):
            self.root = str(Path(self.temp.name).resolve() / ("index-publication-"+str(index)))
            module.ROOT = module.DARWIN_ROOT = self.root
            protocol.ROOT = protocol.DARWIN_ROOT = self.root
            with patch.object(jobs, "owner_source", return_value=delayed):
                packet = self.call(module.enroll_program("fixture", self.machine, os.geteuid()))["namespace"]
                operation = str(uuid4())
                source = module.operation_program(packet, operation, self.binding, submit=True, count=3, interval_seconds=.01)
                with ThreadPoolExecutor(max_workers=2) as pool:
                    list(pool.map(self.call, [source]*2))
                terminal = self.terminal(packet, operation)
                self.assertEqual(base64.b64decode(terminal["counter"]).splitlines(), [b"execution", b"0", b"1", b"2"])
                if index == 0:
                    self.call(module.observe_program(packet), good=False)
                else:
                    self.assertTrue(self.call(module.observe_program(packet))["idle"])

    def test_controlled_boot_change_preserves_submitted_counter_unknown_then_terminal(self):
        # The controlled guest supplies a new boot identity while the actual
        # detached process continues, making accidental replacement observable.
        boot_file = Path(self.temp.name) / "controlled-guest-boot"
        old_boot = str(uuid4()); boot_file.write_text(old_boot)
        raw = jobs.owner_source().decode()
        node = next(node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == "_boot")
        lines = raw.splitlines(keepends=True)
        replacement = "def _boot():\n    return Path("+repr(str(boot_file))+").read_text().strip()\n"
        controlled = ("".join(lines[:node.lineno-1])+replacement+"".join(lines[node.end_lineno:])).encode()
        self.binding = {**self.binding, "boot": old_boot}
        with patch.object(jobs, "owner_source", return_value=controlled):
            packet = self.enroll(); operation = str(uuid4())
            self.call(protocol.operation_program(packet, operation, self.binding, submit=True, count=20, interval_seconds=.03))
            counter = Path(self.root) / operation / "counter.txt"
            deadline = time.monotonic()+3
            while time.monotonic() < deadline:
                if counter.exists() and len(counter.read_text().splitlines()) >= 3:
                    break
                time.sleep(.005)
            boot_file.write_text(str(uuid4()))
            unknown = self.call(protocol.operation_program(packet, operation, self.binding))
            self.assertEqual(unknown["status"]["state"], "unknown")
            self.assertEqual(unknown["status"]["reason"], "boot_changed")
            self.assertTrue(unknown["admissionConsumed"])
            self.assertFalse(self.call(protocol.observe_program(packet))["idle"])
            self.call(protocol.operation_program(packet, operation, self.binding, submit=True), good=False)
            terminal = self.terminal(packet, operation)
            self.assertEqual(base64.b64decode(terminal["counter"]).splitlines(), [b"execution", *[str(n).encode() for n in range(20)]])
            self.assertTrue(self.call(protocol.observe_program(packet))["idle"])


class NamespacePlatformTests(unittest.TestCase):
    def before(self, stem):
        folder = Path(__file__).parent / 'fixtures/guest_namespace_platform_root_before'
        path = folder / (stem + '.py.source')
        expected = {'readiness_qemu_jobs': '5b2910175d4f3324da497f829806b7e5c0d8c09a6b0c4f9a86caffb8a8809ca3',
                    'readiness_guest_jobs': '12c5ff60c03b2c9981f15571028b903b4c98e2ec7ee2231aa0bc0d89e1d3a1af'}[stem]
        raw = path.read_bytes()
        self.assertEqual(expected, hashlib.sha256(raw).hexdigest())
        self.assertEqual(expected, json.loads((folder / 'provenance.json').read_bytes())['sha256'][stem + '.py'])
        module = types.ModuleType('agent_tools.platform_before_' + uuid4().hex)
        module.__file__, module.__package__ = str(path), 'agent_tools'
        exec(compile(raw, str(path), 'exec'), module.__dict__)
        return module

    def packet(self, root):
        return {'schemaVersion': 1, 'root': root, 'generation': [11, 22], 'admissionGeneration': [33, 44],
                'target': 'fixture', 'machine': 'actual-machine', 'actualMachineId': 'actual-machine',
                'account': '1000', 'ownerSourceSha256': hashlib.sha256(jobs.owner_source()).hexdigest()}

    def test_linux_namespace_and_enrollment_parameters_are_unchanged(self):
        original = self.before('readiness_qemu_jobs')
        packet = self.packet('/var/tmp/vc-recovery-jobs')
        self.assertEqual(packet, original._packet(packet))
        self.assertEqual(packet, protocol._packet(packet, guest_platform='linux'))
        def parameters(source):
            return ast.literal_eval(next(n for n in ast.parse(source).body if isinstance(n, ast.Assign)
                                         and isinstance(n.targets[0], ast.Name) and n.targets[0].id == 'PARAMETERS').value)
        self.assertEqual(parameters(original.enroll_program('fixture', 'actual-machine', 1000)),
                         parameters(protocol.enroll_program('fixture', 'actual-machine', 1000)))

    def test_host_packet_requires_exact_finite_provider_platform_root(self):
        for platform, root, foreign in [('linux', protocol.ROOT, protocol.DARWIN_ROOT),
                                        ('darwin', protocol.DARWIN_ROOT, protocol.ROOT)]:
            self.assertEqual(self.packet(root), protocol._packet(self.packet(root), guest_platform=platform))
            with self.assertRaisesRegex(ValueError, 'guest_namespace_packet'):
                protocol._packet(self.packet(foreign), guest_platform=platform)
        for root in ['/tmp/vc-recovery-jobs', '/var/tmp/other', '/private/var/tmp/vc-recovery-jobs/../other', []]:
            with self.assertRaisesRegex(ValueError, 'guest_namespace_packet'):
                protocol._packet(self.packet(root))
        for platform in ['windows', 'darwin-user-selector', [], True]:
            with self.assertRaisesRegex(ValueError, 'guest_namespace_platform'):
                protocol._packet(self.packet(protocol.ROOT), guest_platform=platform)

    def test_whole_original_facade_cross_platform_red_current_provider_guard_green(self):
        from agent_tools import readiness_guest_jobs as facade
        original = self.before('readiness_guest_jobs')
        packet = self.packet(protocol.ROOT)
        executor = types.SimpleNamespace(provider='tart-macos', target='fixture', machine='actual-machine', uid=1000)
        backend = types.SimpleNamespace(load_guest_namespace=lambda: packet)
        with tempfile.TemporaryDirectory() as folder:
            with patch.object(original, '_remote', return_value={'idle': True}) as remote:
                self.assertEqual(packet, original._namespace(Path(folder), executor, backend, enroll=False))
                self.assertEqual(1, remote.call_count)
            with patch.object(facade, '_remote', side_effect=AssertionError('no guest dispatch')) as remote:
                with self.assertRaisesRegex(ValueError, 'guest_namespace_packet'):
                    facade._namespace(Path(folder), executor, backend, enroll=False)
                remote.assert_not_called()

    @unittest.skipUnless(os.name == 'posix' and os.geteuid() > 0, 'ordinary POSIX account required')
    def test_actual_guest_rejects_foreign_platform_before_filesystem_effects(self):
        with tempfile.TemporaryDirectory() as folder:
            linux, darwin = str(Path(folder).resolve() / 'linux'), str(Path(folder).resolve() / 'darwin')
            with patch.object(protocol, 'ROOT', linux), patch.object(protocol, 'DARWIN_ROOT', darwin):
                wrong = darwin if sys.platform.startswith('linux') else linux
                source = protocol.observe_program(self.packet(wrong))
                argv, payload = protocol.stdin_command(source)
                result = subprocess.run([sys.executable, *argv[1:]], input=payload, capture_output=True, timeout=8)
                self.assertNotEqual(0, result.returncode)
                self.assertIn(b'guest_namespace_platform_root', result.stderr)
                self.assertEqual([], list(Path(folder).iterdir()))

    @unittest.skipUnless(sys.platform == 'darwin' and os.geteuid() > 0, 'actual Darwin /var symlink and ordinary account required')
    def test_actual_darwin_symlink_whole_emitted_before_red_current_canonical_green(self):
        original = self.before('readiness_qemu_jobs')
        self.assertTrue(Path('/var').is_symlink())
        self.assertEqual(Path('/private/var'), Path('/var').resolve())
        machine = plistlib.loads(subprocess.check_output(['/usr/sbin/ioreg', '-rd1', '-c', 'IOPlatformExpertDevice', '-a'], timeout=3))[0]['IOPlatformUUID']
        with tempfile.TemporaryDirectory(prefix='vc-job-root-causal-', dir='/private/var/tmp') as folder:
            canonical = Path(folder).resolve()
            alias = Path('/var/tmp') / canonical.name
            original.ROOT = str(alias / 'old')
            def call(source):
                argv, payload = protocol.stdin_command(source)
                return subprocess.run([sys.executable, *argv[1:]], input=payload, capture_output=True, timeout=8)
            red = call(original.enroll_program('fixture', machine, os.geteuid()))
            self.assertNotEqual(0, red.returncode)
            self.assertIn(b'root_invalid', red.stderr)
            self.assertTrue((canonical / 'old').is_dir())
            self.assertEqual([], list((canonical / 'old').iterdir()))
            with patch.object(protocol, 'ROOT', str(alias / 'current')), patch.object(protocol, 'DARWIN_ROOT', str(canonical / 'current')):
                green = call(protocol.enroll_program('fixture', machine, os.geteuid()))
                self.assertEqual(0, green.returncode, green.stderr.decode())
                packet = json.loads(green.stdout)['namespace']
                self.assertEqual(str(canonical / 'current'), packet['root'])
                self.assertEqual(packet, protocol._packet(packet, guest_platform='darwin'))
                self.assertEqual(list(jobs.root_generation(canonical / 'current')), packet['generation'])
                observed = call(protocol.observe_program(packet))
                self.assertEqual(0, observed.returncode, observed.stderr.decode())
                self.assertEqual({'visibilityComplete': True, 'jobs': [], 'idle': True}, json.loads(observed.stdout))


if __name__ == "__main__":
    unittest.main()
