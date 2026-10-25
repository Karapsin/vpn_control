"""Complete authenticated diagnostic owners; only the child tool boundary is controlled.

The fixed historical workspace literal is mapped to this test's TemporaryDirectory
at the owner's pathlib import. Neither owner reads .runtime. The actual launched
child is Python emitting fixed public bytes, never clang, sandbox-exec, or ld.
"""
from __future__ import annotations

import builtins
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import types
import unittest

from agent_tools import durable_remote_job as jobs


FIXTURES = Path(__file__).parent / "fixtures" / "clang_driver_plan_retention"
BEFORE_SHA = "9b9715123936d2de2e2ea5b07911fce3e39071cc817d57d4db33daaa720dcaca"
CURRENT_SHA = "05a35fc19c2cc97ee65c65baac2e77b2745249afe22685a97f10fdd1a930331c"
WORKSPACE = "/Users/karapsin_de/projects/vpn_control_tool_recovery/.runtime/tool-recovery/tart-suspend-preparation-134a68b4-4521-467c-a8fc-3d66d69d647c/linker-driver-plan-395a1e0c-8963-4eb7-a6a9-5f64e5cdb76d"


def generation(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


class Forward:
    def __init__(self, original, **changes):
        self.original, self.changes = original, changes

    def __getattr__(self, key):
        return self.changes[key] if key in self.changes else getattr(self.original, key)


@unittest.skipUnless(os.name == "posix", "actual private FD/nonblocking pipe contract requires POSIX")
class DriverPlanRetentionTests(unittest.TestCase):
    def source(self, current):
        name, expected = ("owner.current.source", CURRENT_SHA) if current else ("owner.before.source", BEFORE_SHA)
        provenance = json.loads((FIXTURES / "provenance.json").read_bytes())
        self.assertEqual(set(provenance["sources"]), {"owner.before.source", "owner.current.source"})
        raw = (FIXTURES / name).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), expected)
        self.assertEqual(provenance["sources"][name], expected)
        return raw

    def scenario(self, current, *, linger=False, birth_error=False, start_error=False,
                 selector_error=False, drift=False, overflow=False, preexisting_leaf=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("work", "work/src", "work/bin", "work/tmp", "work/cache", "work/cache/modules"):
                (root / name).mkdir(mode=0o700)
            held_source = root / "held-public-source"
            held_source.write_bytes(b"immutable public source")
            jobs_source = root / "controlled_jobs.py"
            jobs_source.write_text(
                "from agent_tools.durable_remote_job import _boot, _birth as actual_birth\n"
                "import os\n"
                "def _birth(pid):\n"
                + (" if pid != os.getpid(): raise RuntimeError('controlled birth failure')\n" if birth_error else "")
                + " return actual_birth(pid)\n"
            )
            if preexisting_leaf:
                (root / "driver-plan.stdout").symlink_to(held_source)
            descriptors = []
            holds = []
            for path in (held_source, jobs_source):
                fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
                descriptors.append(fd)
                holds.append((path, fd, generation(os.fstat(fd)), hashlib.sha256(path.read_bytes()).hexdigest()))
            inventory = []
            for path in sorted((root / "work").rglob("*")):
                inventory.append({"relative": str(path.relative_to(root / "work")),
                                  "identity": generation(path.lstat())[:5], "fileGeneration": None})
            argv = ["controlled-sandbox-never-executed", "-f", "fixed-profile", "controlled-clang-never-executed", "-###"]
            inputs = {"uid": os.geteuid(), "boot": jobs._boot(), "jobsPath": str(jobs_source),
                      "clangPath": argv[3], "argv": argv, "env": {"PATH": "/usr/bin:/bin"},
                      "profileSha256": "controlled", "directories": [], "aliases": [],
                      "workInventory": inventory}
            children = []
            code = "import os,time\nos.write(1,b'actual-out\\n');os.write(2,b'actual-err\\n')\n"
            if overflow:
                code += "os.write(2,b'x'*70000)\n"
            if drift:
                code += "open(" + repr(str(held_source)) + ",'wb').write(b'changed')\n"
            if linger:
                code += "os.close(1);os.close(2);time.sleep(.4)\n"

            def launch(actual_argv, **kwargs):
                self.assertEqual(actual_argv, argv)
                self.assertTrue(kwargs["close_fds"])
                self.assertNotIn("HOME", kwargs["env"])
                child = subprocess.Popen([sys.executable, "-u", "-c", code], **kwargs)
                children.append(child)
                # The owner's logical 10 seconds is accelerated consistently
                # for both its monotonic clock and its actual wait timeout.
                return Forward(child, wait=lambda timeout: child.wait(timeout=timeout / 80)) if linger else child

            def controlled_open(path, *args, **kwargs):
                if start_error and str(path) == str(root / "driver-plan.started.json"):
                    raise OSError("controlled started publication failure")
                return os.open(path, *args, **kwargs)

            def no_selector():
                raise RuntimeError("controlled selector setup failure")

            started = time.monotonic()
            clock = Forward(time, monotonic=lambda: started + (time.monotonic() - started) * (80 if linger else 1))
            modules = {"pathlib": types.SimpleNamespace(Path=lambda value: root if str(value) == WORKSPACE else Path(value)),
                       "subprocess": Forward(subprocess, Popen=launch), "time": clock,
                       "os": Forward(os, open=controlled_open),
                       "selectors": Forward(selectors, DefaultSelector=no_selector) if selector_error else selectors}

            def controlled_import(name, globals=None, locals=None, fromlist=(), level=0):
                return modules[name] if name in modules else builtins.__import__(name, globals, locals, fromlist, level)

            namespace = {"__name__": "__main__", "__file__": str(FIXTURES / ("owner.current.source" if current else "owner.before.source")),
                         "__builtins__": dict(vars(builtins), __import__=controlled_import),
                         "_PLAN_INPUTS": inputs, "_PLAN_HOLDS": holds}
            error = None
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    exec(compile(self.source(current), namespace["__file__"], "exec"), namespace)
            except Exception as exc:
                error = exc
            finally:
                for child in children:
                    # Every controlled child exits naturally; no kill, signal, or retry.
                    child.wait(timeout=3)
                    for pipe in (child.stdout, child.stderr):
                        if pipe is not None:
                            pipe.close()
                for fd in descriptors:
                    os.close(fd)
            leaves = {}
            for name in ("driver-plan.stdout", "driver-plan.stderr", "driver-plan.capture.jsonl", "driver-plan.terminal.json"):
                path = root / name
                if path.is_file() and not path.is_symlink():
                    leaves[name] = path.read_bytes()
            return error, leaves, len(children)

    def retained(self, leaves):
        self.assertEqual(leaves["driver-plan.stdout"], b"actual-out\n")
        self.assertTrue(leaves["driver-plan.stderr"].startswith(b"actual-err\n"))
        events = [json.loads(line) for line in leaves["driver-plan.capture.jsonl"].splitlines()]
        self.assertEqual(events[-1]["phase"], "capture-final")
        return events[-1]

    def test_actual_closed_streams_live_child_whole_before_red_current_retains(self):
        old_error, old_leaves, _ = self.scenario(False, linger=True)
        self.assertIsInstance(old_error, ValueError)
        self.assertIn("driver_plan_waitpid_unknown", str(old_error))
        self.assertNotIn("driver-plan.stdout", old_leaves)
        error, leaves, count = self.scenario(True, linger=True)
        self.assertIsNotNone(error)
        final = self.retained(leaves)
        self.assertEqual(count, 1)
        self.assertTrue(final["streamsEOF"])
        self.assertFalse(final["directWaitpidCompleted"])
        self.assertEqual(final["fault"]["stage"], "waitpid-timeout")

    def test_birth_failure_whole_before_red_current_finally_drains(self):
        self.assertNotIn("driver-plan.stderr", self.scenario(False, birth_error=True)[1])
        error, leaves, count = self.scenario(True, birth_error=True)
        self.assertIsNotNone(error)
        final = self.retained(leaves)
        self.assertEqual(count, 1)
        self.assertIsNone(final["observedBirth"])
        self.assertTrue(final["directWaitpidCompleted"])

    def test_started_publication_failure_whole_before_red_current_retains(self):
        self.assertNotIn("driver-plan.stderr", self.scenario(False, start_error=True)[1])
        error, leaves, _ = self.scenario(True, start_error=True)
        self.assertIsNotNone(error)
        self.assertTrue(self.retained(leaves)["streamsEOF"])

    def test_selector_setup_failure_whole_before_red_current_has_no_selector_dependency(self):
        self.assertNotIn("driver-plan.stdout", self.scenario(False, selector_error=True)[1])
        error, leaves, count = self.scenario(True, selector_error=True)
        self.assertIsNone(error)
        self.assertEqual(count, 1)
        self.assertEqual(self.retained(leaves)["exitCode"], 0)

    def test_stderr_durable_before_source_drift_refusal(self):
        error, leaves, _ = self.scenario(True, drift=True)
        self.assertIsNotNone(error)
        final = self.retained(leaves)
        self.assertTrue(final["semanticAndSourceGuardsNotYetRun"])
        self.assertIsNone(final["fault"])

    def test_aggregate_stream_cap_and_exclusive_named_leaf(self):
        error, leaves, _ = self.scenario(True, overflow=True)
        self.assertIsNotNone(error)
        self.assertEqual(len(leaves["driver-plan.stdout"]) + len(leaves["driver-plan.stderr"]), 65536)
        error, _, children = self.scenario(True, preexisting_leaf=True)
        self.assertIsNotNone(error)
        self.assertEqual(children, 0)


if __name__ == "__main__":
    unittest.main()
