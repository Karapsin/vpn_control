"""The ordinary owner's two doors for the SSH relay row, with inert peers: no process, handle or Win32 call.

* A public call may take one file the case wrote under the operation root as its whole stdin (``Child``,
  ``Owner.child`` and ``Owner.invoke`` take ``stdin``). Its intent names only the byte count; every other child
  keeps an empty stdin and an unchanged intent.
* A CLI case module of disconnected-cli-config or streaming-client-interrupt may define ``configure_launch``: it runs
  after the static probes and before the one serve, and the owner removes JAVA_TOOL_OPTIONS right after starting
  that serve, as for the responsive document row.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import windows_ordinary_process_owner as process_owner


class StdinChildTests(unittest.TestCase):
    def peers(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory(prefix="owner-stdin-")))
        owner = types.SimpleNamespace(root=root / "operation", children=[], environment={}, events=[], popens=[],
                                      by_path={"held.exe": object()}, parks=[])
        owner.root.mkdir()
        owner.guard = lambda: None
        owner.event = lambda kind, value: owner.events.append((kind, value))
        owner.native = types.SimpleNamespace(birth=lambda handle: "inert-birth")

        def park(reason, error=None):
            owner.parks.append(reason)
            raise RuntimeError(reason)
        owner.park = park
        test = self

        class Popen:
            def __init__(self, argv, **kwargs):
                self.pid, self._handle = 101, 707
                self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
                stdin = kwargs["stdin"]
                test.assertEqual("child-intent", owner.events[-1][0], "custody and intent precede the start")
                owner.popens.append({"stdin": stdin, "bytes": None if stdin is subprocess.DEVNULL else stdin.read(),
                                     "open": None if stdin is subprocess.DEVNULL else not stdin.closed})

            def poll(self):
                return None

        class Thread:
            def __init__(self, **kwargs):
                pass

            def start(self):
                pass

        self.enterContext(mock.patch.object(process_owner.subprocess, "Popen", Popen))
        self.enterContext(mock.patch.object(process_owner.subprocess, "CREATE_NO_WINDOW", 0x8000000, create=True))
        self.enterContext(mock.patch.object(process_owner.subprocess, "CREATE_NEW_CONSOLE", 0x10, create=True))
        self.enterContext(mock.patch.object(process_owner.threading, "Thread", Thread))
        self.enterContext(mock.patch.object(process_owner, "absolute", Path))

        def close_streams():
            for child in owner.children:
                for stream in child.streams.values():
                    stream.close()
        self.addCleanup(close_streams)
        return owner

    def test_a_file_under_the_operation_root_is_the_whole_stdin_and_only_its_size_is_journaled(self):
        owner = self.peers()
        folder = owner.root / "fixture files"
        folder.mkdir()
        path = folder / "key.txt"
        path.write_bytes(b"-----BEGIN OPENSSH PRIVATE KEY-----\nsecret line\n-----END OPENSSH PRIVATE KEY-----\n")
        child = process_owner.Child(owner, "public-cli", ["held.exe", "ssh", "key", "import", "--input", "-"], stdin=str(path))
        self.assertIs(owner.children[0], child)
        self.assertEqual([{"stdin": owner.popens[0]["stdin"], "bytes": path.read_bytes(), "open": True}], owner.popens)
        self.assertTrue(owner.popens[0]["stdin"].closed, "the owner keeps no handle of it once the child holds its own")
        intent = owner.events[0][1]
        self.assertEqual({"child": 0, "label": "public-cli", "argv": ["held.exe", "ssh", "key", "import", "--input", "-"],
                          "consoleCreation": "none", "stdinBytes": len(path.read_bytes())}, intent)
        self.assertNotIn("secret line", json.dumps(owner.events))

    def test_without_stdin_a_child_keeps_an_empty_stdin_and_its_intent_unchanged(self):
        owner = self.peers()
        process_owner.Child(owner, "public-cli", ["held.exe", "status"])
        self.assertIs(subprocess.DEVNULL, owner.popens[0]["stdin"])
        self.assertEqual({"child", "label", "argv", "consoleCreation"}, set(owner.events[0][1]))

    def test_only_a_bounded_regular_single_link_file_under_the_root_is_taken_before_any_custody(self):
        owner = self.peers()
        outside = owner.root.parent / "outside.txt"
        outside.write_bytes(b"x")
        folder = owner.root / "fixture"
        folder.mkdir()
        large = folder / "large.txt"
        large.write_bytes(b"x" * (process_owner.STDIN_MAX_BYTES + 1))
        linked = folder / "linked.txt"
        linked.write_bytes(b"x")
        os.link(linked, folder / "second-name.txt")
        for name, value, reason in (("outside", outside, "stdin-outside-operation-root"), ("root", owner.root, "stdin-outside-operation-root"),
                                    ("directory", folder, "stdin-not-regular-bounded-file"), ("large", large, "stdin-not-regular-bounded-file"),
                                    ("hard-link", linked, "stdin-not-regular-bounded-file"), ("absent", folder / "absent.txt", None)):
            with self.subTest(name=name):
                with self.assertRaises(process_owner.Refused if reason else FileNotFoundError) as caught:
                    process_owner.Child(owner, "public-cli", ["held.exe"], stdin=str(value))
                if reason:
                    self.assertEqual(reason, str(caught.exception))
        self.assertEqual(([], [], []), (owner.children, owner.events, owner.popens))
        with self.assertRaises(process_owner.Refused) as caught:
            process_owner.Child(owner, "console", ["held.exe"], new_console=True, stdin=str(folder / "second-name.txt"))
        self.assertEqual("stdin-console-conflict", str(caught.exception))

    def test_invoke_hands_stdin_to_the_one_public_call_and_nothing_else_changes(self):
        captured = []
        child = types.SimpleNamespace(completed=lambda: "same-inert-child-result")

        def make(label, argv, **kwargs):
            captured.append((label, argv, kwargs))
            return child
        owner = types.SimpleNamespace(request={"cliPath": "held-cli.exe"}, child=make)
        process_owner.Owner.invoke(owner, Path("owned workspace"), "--json", "ssh", "key", "import", "--input", "-", stdin="key.txt")
        process_owner.Owner.invoke(owner, Path("owned workspace"), "--json", "status", timeout=1)
        self.assertEqual([("public-cli", ["held-cli.exe", "--state-dir", "owned workspace", "--json", "ssh", "key", "import", "--input", "-"],
                           {"stdin": "key.txt"}),
                          ("public-cli", ["held-cli.exe", "--state-dir", "owned workspace", "--json", "status"], {})], captured)


def peer_response():
    return subprocess.CompletedProcess([], 0, json.dumps({"schemaVersion": 1, "controllerId": "inert-owner", "requestId": "inert",
                                                          "operationId": None, "configurationRevision": 0, "restartRequired": False,
                                                          "code": "OK", "ok": True, "final": True, "data": {"runtimeRunning": False}}), "")


class LaunchPeer:
    """Records callbacks of Owner.run only: children are declared peers and never processes."""

    def __init__(self, root, action, launch=True, serve_fails=False):
        self.root, self.trace, self.environment = Path(root), [], {"PATH": "inert"}
        self.request = {"action": action, "cliPath": "held-cli.exe", "casesPath": "held-cases.py", "harnessPath": "held-harness.py",
                        "workspace": str(self.root / "workspace"), "productVersion": "2.2.17"}
        self.cases = types.SimpleNamespace(run=lambda *args: self.trace.append(("run",)))
        if launch:
            def configure_launch(owner, workspace):
                self.trace.append(("configure_launch", owner is self, str(workspace)))
                owner.environment["JAVA_TOOL_OPTIONS"] = '"-Djavax.net.ssl.trustStore=held.jks"'
            self.cases.configure_launch = configure_launch
        harness = types.ModuleType("inert-held-harness")
        self.loads = []

        def module(path, name):
            self.loads.append((path, name))
            return self.cases if path == "held-cases.py" else harness
        self.module = module
        peer = self

        class Child:
            def __init__(self, label, argv):
                peer.trace.append(("child", label, "JAVA_TOOL_OPTIONS" in peer.environment))
                if label == "serve" and serve_fails:
                    raise OSError("inert-serve-start")
                self.label, self.argv, self.code = label, argv, None
                self.process = types.SimpleNamespace(poll=lambda: self.code)

            def completed(self):
                self.code = 0
                return subprocess.CompletedProcess(self.argv, 0, "Usage:" if self.label == "help" else "2.2.17", "")

            def wait(self):
                self.code = 0
                return {"exitCode": 0}
        self.child = lambda label, argv: Child(label, argv)

    def guard(self):
        pass

    def event(self, kind, value):
        self.trace.append((kind,))

    def invoke(self, workspace, *argv, **kwargs):
        self.trace.append(("invoke", argv[-1], "JAVA_TOOL_OPTIONS" in self.environment))
        return peer_response()


class LaunchHookTests(unittest.TestCase):
    def run_owner(self, peer):
        with mock.patch.object(process_owner, "absolute", Path):
            return process_owner.Owner.run(peer)

    def test_a_cli_case_module_scopes_jvm_options_to_the_one_serve(self):
        for action in sorted(process_owner.KNOWN_FAILURE_ACTIONS):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as root:
                peer = LaunchPeer(root, action)
                self.assertEqual(0, self.run_owner(peer))
                children = [(row[1], row[2]) for row in peer.trace if row[0] == "child"]
                self.assertEqual([("help", False), ("version", False), ("serve", True)], children)
                launch = [row for row in peer.trace if row[0] == "configure_launch"]
                self.assertEqual([("configure_launch", True, str(Path(root) / "workspace"))], launch)
                self.assertLess(peer.trace.index(("child", "version", False)), peer.trace.index(launch[0]))
                self.assertLess(peer.trace.index(launch[0]), peer.trace.index(("child", "serve", True)))
                self.assertFalse(any(row[2] for row in peer.trace if row[0] == "invoke"), "no later call inherits the options")
                self.assertEqual({"PATH": "inert"}, peer.environment)
                self.assertEqual([("held-cases.py", "_owned_native_" + action.replace("-", "_")), ("held-harness.py",
                                  "_owned_pinned_package_cli_harness")], peer.loads, "the case module is loaded once, before the serve")

    def test_a_module_without_the_hook_runs_as_before(self):
        with tempfile.TemporaryDirectory() as root:
            peer = LaunchPeer(root, "disconnected-cli-config", launch=False)
            self.assertEqual(0, self.run_owner(peer))
            self.assertEqual([("help", False), ("version", False), ("serve", False)],
                             [(row[1], row[2]) for row in peer.trace if row[0] == "child"])
            self.assertEqual({"PATH": "inert"}, peer.environment)

    def test_the_options_leave_the_owner_even_when_the_serve_never_started(self):
        with tempfile.TemporaryDirectory() as root:
            peer = LaunchPeer(root, "disconnected-cli-config", serve_fails=True)
            with self.assertRaisesRegex(OSError, "inert-serve-start"):
                self.run_owner(peer)
            self.assertEqual({"PATH": "inert"}, peer.environment)

    def test_other_actions_never_take_the_hook(self):
        with tempfile.TemporaryDirectory() as root:
            peer = LaunchPeer(root, "fixed-source-mode")
            peer.cases.fixed_full_cases = lambda *args: peer.trace.append(("fixed",))
            self.assertEqual(0, self.run_owner(peer))
            self.assertFalse(any(row[0] == "configure_launch" for row in peer.trace))
            self.assertEqual([("help", False), ("version", False), ("serve", False)],
                             [(row[1], row[2]) for row in peer.trace if row[0] == "child"])


if __name__ == "__main__":
    unittest.main()
