"""Execute every migrated synchronous SSH boundary under real kernel E2BIG.

These are the actual captured dispatch statements, with their original stdin,
stream and timeout semantics. A real socket peer executes the complete generated
program. Native provider scenarios separately exercise each platform's DTOs.
"""
import ast
import errno
import hashlib
import json
import os
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace, ModuleType
from unittest import mock

from agent_tools import ssh_transport as transport
from agent_tools.tests.test_ssh_automatic_program import PeerFixture
from agent_tools import windows_vm_fresh_setup, windows_vm_optical_boot
from agent_tools import windows_vm_secureboot_fresh, windows_msi_base_prepare


@unittest.skipUnless(os.name == "posix", "real POSIX exec admission")
class SynchronousCarrierTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        temporary = tempfile.TemporaryDirectory(prefix="ssh-sync-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.root.chmod(0o700)
        self.peer = PeerFixture(self.root)
        self.peer.hosts["archlinux"] = dict(self.peer.hosts["explicit-peer"])
        self.peer.write_config()
        self.config = transport.load_config(self.root)

    def padding(self):
        remaining = os.sysconf("SC_ARG_MAX") - 20000 - sum(
            len(os.fsencode(k)) + len(os.fsencode(v)) + 2 for k, v in os.environ.items())
        result = {}
        while remaining > 128:
            key = "VC_SYNC_TEST_BUDGET_" + str(len(result))
            value = "E" * min(60000, remaining - len(key) - 2)
            result[key] = value
            remaining -= len(key) + len(value) + 2
        return result

    def statement(self, source, line):
        tree = ast.parse(source)
        candidates = [node for node in ast.walk(tree) if isinstance(node, ast.stmt)
                      and node.lineno <= line <= node.end_lineno]
        return ast.get_source_segment(source, min(candidates, key=lambda n: n.end_lineno - n.lineno))

    def namespace(self, argv, alias):
        stream = tempfile.TemporaryFile()
        stream.write(b"public input")
        stream.seek(0)
        self.addCleanup(stream.close)
        value = {"subprocess": subprocess, "argv": argv, "gateway_argv": argv,
                 "target_argv": argv, "runtime_argv": argv, "timeout": 5,
                 "timeout_seconds": 5, "secret": b"public input", "credential": b"public input",
                 "stream": stream}
        parts = alias.split(".")
        child = transport
        for part in reversed(parts[1:]):
            child = SimpleNamespace(**{part: child})
        value[parts[0]] = child
        return value

    def test_all_reviewed_synchronous_dispatches_actual_red_green(self):
        folder = Path(__file__).parent / "fixtures/ssh_sync_callers"
        manifest = json.loads((folder / "provenance.json").read_bytes())
        checked = 0
        for name, row in manifest.items():
            before = (folder / (name + ".before.source")).read_text()
            self.assertEqual(row["beforeSha256"], hashlib.sha256(before.encode()).hexdigest())
            current = (Path(__file__).parents[1] / name).read_text()
            # Each preserved statement identifies its own real current call;
            # other owners may independently change a different function.
            tree = ast.parse(current)
            current_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                             and isinstance(node.func, ast.Attribute) and node.func.attr == "run_ssh"]
            for index, call in enumerate(row["calls"]):
                with self.subTest(module=name, function=call["function"], dispatch=index):
                    old_statement = self.statement(before, call["line"])
                    wanted = old_statement.replace("subprocess.run", call["transport"] + ".run_ssh", 1)
                    self.assertTrue(any(self.statement(current, node.lineno) == wanted for node in current_calls),
                                    "reviewed dispatch changed without requalification")
                    marker = self.root / (name + "-" + str(index))
                    source = ("PADDING=" + repr("X" * 32000) + "\nfrom pathlib import Path\n"
                              "Path(" + repr(str(marker)) + ").open('a').write('once\\n')\n"
                              "print('{\"sentinel\":1}')\n")
                    argv = transport.build_ssh_argv(self.config, "explicit-peer", 5,
                        command=("python3", "-I", "-B", "-c", "exec(" + repr(source) + ")"),
                        ssh_binary=str(self.peer.binary), nested_ssh_binary=str(self.peer.binary))
                    count = len(self.peer.events())
                    with self.peer.environment(), mock.patch.dict(os.environ, self.padding()):
                        with self.assertRaises(OSError) as failure:
                            exec(compile(old_statement, name + ":before-dispatch", "exec"), self.namespace(argv, call["transport"]))
                        self.assertEqual(errno.E2BIG, failure.exception.errno)
                        self.assertFalse(marker.exists())
                        self.assertEqual(count, len(self.peer.events()))
                        namespace = self.namespace(argv, call["transport"])
                        exec(compile(wanted, name + ":dispatch", "exec"), namespace)
                    self.assertEqual("once\n", marker.read_text())
                    self.assertEqual(count + 2, len(self.peer.events()))
                    completed = [value for value in namespace.values() if isinstance(value, subprocess.CompletedProcess)]
                    self.assertEqual(1, len(completed))
                    self.assertEqual(0, completed[0].returncode)
                    self.assertTrue(all(event["commandBytes"] <= 60000 and event["maxArgumentBytes"] <= 60000
                                        for event in self.peer.events()[count:]))
                    checked += 1
        self.assertEqual(37, checked)

    def test_complete_remote_wrappers_render_dispatch_and_validate_original_result(self):
        folder = Path(__file__).parent / "fixtures/ssh_sync_callers"
        modules = {"windows_vm_fresh_setup": windows_vm_fresh_setup,
                   "windows_vm_optical_boot": windows_vm_optical_boot,
                   "windows_vm_secureboot_fresh": windows_vm_secureboot_fresh,
                   "windows_msi_base_prepare": windows_msi_base_prepare}
        builder = transport.build_ssh_argv
        def fixture_binary(*args, **kwargs):
            if len(args) >= 5:
                return builder(*args, **kwargs)
            return builder(*args, **{**kwargs, "ssh_binary": str(self.peer.binary),
                                    "nested_ssh_binary": str(self.peer.binary)})
        correlation = "c4c8bf81-af85-4265-b9fc-b2bc09242930"
        value = {"schemaVersion": 1, "correlationId": correlation,
                 "state": "unknown", "reason": None, "nativeActionAllowed": False}
        for name, current in modules.items():
            with self.subTest(wrapper=name):
                path = folder / (name + ".py.before.source")
                raw = path.read_bytes()
                old = ModuleType("agent_tools._sync_before_" + name)
                old.__file__, old.__package__ = str(path), "agent_tools"
                with mock.patch.dict(sys.modules, {old.__name__: old}):
                    exec(compile(raw, str(path), "exec"), old.__dict__)
                marker = self.root / ("wrapper-" + name)
                source = ("PADDING=" + repr(hashlib.shake_256(b"public synchronous wrapper fixture").hexdigest(20000)) + "\nfrom pathlib import Path\n"
                          "Path(" + repr(str(marker)) + ").open('a').write('once\\n')\n"
                          "print(" + repr(json.dumps(value, separators=(",", ":"))) + ")\n")
                def invoke(module):
                    if name == "windows_msi_base_prepare":
                        return module._remote(self.config, source, (), None, 5)
                    if name == "windows_vm_secureboot_fresh":
                        with mock.patch.object(module, "HOST", "explicit-peer"), mock.patch.object(module, "_program", return_value=source):
                            return module._remote(self.root, correlation, "status", 5)
                    with mock.patch.object(module, "_program", return_value=source):
                        return module._remote(self.root, "explicit-peer", correlation, "status", 5)
                count = len(self.peer.events())
                with self.peer.environment(), mock.patch.dict(os.environ, self.padding()), \
                        mock.patch.object(transport, "build_ssh_argv", side_effect=fixture_binary):
                    try:
                        red = invoke(old)
                    except OSError as error:
                        self.assertEqual(errno.E2BIG, error.errno)
                    else:
                        self.assertIsNone(red)  # MSI's original finite transport failure.
                    self.assertFalse(marker.exists())
                    self.assertEqual(count, len(self.peer.events()))
                    green = invoke(current)
                if name == "windows_msi_base_prepare":
                    self.assertEqual(value, json.loads(green))
                else:
                    self.assertEqual(value, green)
                self.assertEqual("once\n", marker.read_text())
                self.assertEqual(count + 2, len(self.peer.events()))


if __name__ == "__main__":
    unittest.main()
