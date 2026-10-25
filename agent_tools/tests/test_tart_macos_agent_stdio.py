"""Native launchd failure's real unprivileged filesystem causal boundary.

The complete original public plist/bootstrap and once-only native repair are
retained. The test executes the original plist's stdio contract using actual
kernel permissions, then the repair's unchanged absence/create/record loops.
Only the privileged boundary is mapped to this test account/private parent;
actual launchd KeepAlive and original guest RPC acceptance remain native gates.
"""
import ast
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import sys
import tempfile
import unittest


FIXTURES = Path(__file__).parent / "fixtures"


@unittest.skipUnless(os.name == "posix" and os.geteuid() != 0,
                     "requires actual unprivileged POSIX file permissions")
class AgentStdioCausalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.logs = self.root / "logs"; self.logs.mkdir(mode=0o500)
        self.plist = plistlib.loads((FIXTURES / "tart_macos_agent_stdio.before.plist").read_bytes())
        self.names = tuple(Path(self.plist[key]).name for key in ("StandardErrorPath", "StandardOutPath"))

    def stdio(self):
        """Same configured opens under job UID, before the job can execute."""
        streams = []
        try:
            for name in self.names:
                fd = os.open(self.logs / name, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
                streams.append(os.fdopen(fd, "wb"))
            return subprocess.run([sys.executable, "-I", "-c", "print('ordinary-agent-ready')"],
                                  stdin=subprocess.DEVNULL, stdout=streams[1], stderr=streams[0], timeout=3)
        finally:
            for stream in streams: stream.close()

    def repair(self):
        source = (FIXTURES / "tart_macos_agent_stdio.repair.source").read_text()
        tree = ast.parse(source)
        record = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "record")
        loops = sorted((node for node in ast.walk(tree) if isinstance(node, ast.For)
                        and isinstance(node.target, ast.Name) and node.target.id == "name"
                        and isinstance(node.iter, ast.Name) and node.iter.id == "names"), key=lambda node: node.lineno)
        self.assertEqual(len(loops), 2)
        # Map the target account to the real unprivileged test account. The
        # O_EXCL/no-follow/absence checks, record body and durability calls are
        # executed from the complete native repair source, without mocks.
        class Account(ast.NodeTransformer):
            def visit_Constant(self, node):
                if type(node.value) is int and node.value in {502, 20}:
                    return ast.copy_location(ast.Constant(os.geteuid() if node.value == 502 else os.getegid()), node)
                return node
        module = Account().visit(ast.Module(body=[record, *loops], type_ignores=[]))
        ast.fix_missing_locations(module)
        journal = self.root / "repair-journal"
        if not journal.exists(): journal.mkdir(mode=0o700)
        # This is the privileged repair boundary; the configured daemon UID
        # still has no parent write permission when launchd retries afterward.
        self.logs.chmod(0o700)
        fd = os.open(self.logs, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            scope = {"os": os, "stat": stat, "json": json, "journal": journal,
                     "OPERATION": "controlled-original-repair", "names": self.names, "logfd": fd, "rows": []}
            exec(compile(module, "<original-native-create-only-log-repair>", "exec"), scope)
            return scope["rows"]
        finally:
            os.close(fd); self.logs.chmod(0o500)

    def test_original_plist_missing_stdio_is_red_repair_same_plist_is_green_and_never_replaces(self):
        self.assertEqual(self.plist["UserName"], "toolrecovery")
        self.assertTrue(self.plist["KeepAlive"])
        original = (FIXTURES / "tart_macos_agent_stdio.before.sh").read_text()
        self.assertIn("launchctl bootstrap", original)
        self.assertNotIn("prepare-owned-agent-logs", original)
        with self.assertRaises(PermissionError): self.stdio()
        self.assertEqual(list(self.logs.iterdir()), [])  # job never executes
        rows = self.repair()
        identities = [(row["device"], row["inode"]) for row in rows]
        self.assertEqual(self.stdio().returncode, 0)
        self.assertEqual((self.logs / self.names[1]).read_bytes(), b"ordinary-agent-ready\n")
        for path in self.logs.iterdir():
            info = path.stat()
            self.assertEqual((info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_nlink),
                             (os.geteuid(), os.getegid(), 0o600, 1))
        with self.assertRaisesRegex(RuntimeError, "owned_log_not_proven_absent"): self.repair()
        self.assertEqual(identities, [(path.stat().st_dev, path.stat().st_ino)
                                     for path in (self.logs / name for name in self.names)])

    def test_partial_original_or_symlink_refuses_before_creating_other_log(self):
        self.logs.chmod(0o700)
        outside = self.root / "unrelated"; outside.write_bytes(b"unchanged")
        (self.logs / self.names[0]).symlink_to(outside)
        self.logs.chmod(0o500)
        with self.assertRaisesRegex(RuntimeError, "owned_log_not_proven_absent"): self.repair()
        self.assertFalse((self.logs / self.names[1]).exists())
        self.assertEqual(outside.read_bytes(), b"unchanged")


if __name__ == "__main__": unittest.main()
