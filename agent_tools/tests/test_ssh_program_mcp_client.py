"""Actual SDK/stdio/retained-relay protocol and authentic client import failure."""
import hashlib
import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).parent / "fixtures/program_mcp_client"


@unittest.skipUnless(os.name == "posix" and importlib.util.find_spec("mcp"), "actual MCP SDK on POSIX")
class ProgramMcpClientTests(unittest.TestCase):
    def controlled_protocol(self, parent, mode, source, *, guest=False, relay_source=None, follow_seconds=15):
        root = parent / (mode + "-" + uuid.uuid4().hex)
        tools = root / "agent_tools"
        tools.mkdir(parents=True)
        (tools / "__init__.py").write_text("")
        fixture = Path(__file__).parent / ("fixtures/program_mcp_source_change/server.source" if mode == "source-change" else
                                         "fixtures/program_guest_mcp_reconnect/server.source" if guest else "fixtures/program_mcp_reconnect/server.source")
        shutil.copyfile(fixture, tools / "mcp_server.py")
        for name in ("ssh_keeper_mcp_relay.py", "ssh_keeper_mcp_delivery.py", "durable_remote_job.py"):
            shutil.copyfile(relay_source if relay_source is not None and name == "ssh_keeper_mcp_relay.py" else ROOT / "agent_tools" / name, tools / name)
        binary = root / ".agent_venv/bin"
        binary.mkdir(parents=True)
        (binary / "python").symlink_to(sys.executable)
        (root / "mode").write_text(mode)
        operation = str(uuid.uuid4())
        request = root / "request.private.json"
        request.write_text(json.dumps({"operationId": operation} if guest == "android" else
                                     {"operationId": operation, "count": 12, "intervalSeconds": .04} if guest else
                                     {"operationId": operation, "program": {"language": "python3", "source": "fixed fixture"}}))
        filename = tools / "ssh_program_mcp_client.py"
        loader = ("from pathlib import Path;import sys;"
                  "filename,source=sys.argv[1:3];sys.argv=[filename,*sys.argv[3:]];"
                  "exec(compile(Path(source).read_bytes(),filename,'exec'),"
                  "{'__name__':'__main__','__file__':filename})")
        args = [sys.executable, "-I", "-B", "-c", loader, str(filename), str(source),
                "--session", "owned", "--server-sha256", hashlib.sha256((tools / "mcp_server.py").read_bytes()).hexdigest(),
                "--output-root", str(root), "--action", "android-program-start" if guest == "android" else "guest-program-start" if guest else "program-start",
                "--fixture" if guest else "--host", "owned-peer",
                "--request-file", str(request), "--follow-seconds", str(follow_seconds)]
        child = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25 + follow_seconds)
        self.assertEqual(b"", child.stderr)
        result = json.loads((root / "owned/client-result.json").read_bytes())
        self.assertTrue((root / "calls").exists(), (root / "owned/sdk.stderr").read_text())
        calls = [json.loads(row) for row in (root / "calls").read_text().splitlines()]
        # Every actual detached sentinel finishes before the fixture is removed.
        import time
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            counter = root / "counter"
            if counter.exists() and len(counter.read_text().splitlines()) == 13:
                break
            time.sleep(.01)
        self.assertTrue((root / "counter").exists(), (root / "owned/sdk.stderr").read_text())
        self.assertEqual(["execution", *map(str, range(12))], (root / "counter").read_text().splitlines())
        self.assertEqual(1, sum(row["action"] == ("android-program-start" if guest == "android" else "guest-program-start" if guest else "program-start") for row in calls))
        self.assertTrue(all(row["operationId"] == operation and row["fixtureId" if guest else "host"] == "owned-peer" for row in calls))
        return child, result, calls, root / "owned", operation

    def test_actual_guest_vm_tool_lost_ack_reconnects_same_fixture_original(self):
        with tempfile.TemporaryDirectory(prefix="guest-program-protocol-loss-") as temporary:
            child, result, calls, directory, operation = self.controlled_protocol(Path(temporary).resolve(), "lost-start",
                ROOT / "agent_tools/ssh_program_mcp_client.py", guest=True)
            self.assertEqual(0, child.returncode)
            self.assertEqual("terminal", result["programState"])
            self.assertEqual(operation, result["operationId"])
            self.assertEqual("owned-peer", result["fixtureId"])
            self.assertEqual(2, result["relayAttempts"])
            self.assertEqual("guest-program-reconcile", calls[1]["action"])
            self.assertEqual("guest-program-collect", calls[-1]["action"])

    def test_actual_android_vm_tool_fixed_spec_lost_ack_reconciles_original(self):
        with tempfile.TemporaryDirectory(prefix="android-program-protocol-loss-") as temporary:
            child, result, calls, directory, operation = self.controlled_protocol(Path(temporary).resolve(), "lost-start",
                ROOT / "agent_tools/ssh_program_mcp_client.py", guest="android")
            self.assertEqual(0, child.returncode)
            self.assertEqual("terminal", result["programState"])
            self.assertEqual(operation, result["operationId"])
            self.assertEqual("owned-peer", result["fixtureId"])
            self.assertEqual(2, result["relayAttempts"])
            self.assertEqual("android-program-reconcile", calls[1]["action"])
            self.assertEqual("android-program-collect", calls[-1]["action"])

    def test_actual_source_change_before_red_current_keeps_kernel_receipt_and_blocks_replay(self):
        fixture = Path(__file__).parent / "fixtures/program_mcp_source_change_before"
        pins = json.loads((fixture / "provenance.json").read_bytes())["sha256"]
        for name in ("ssh_keeper_mcp_relay.py", "ssh_program_mcp_client.py"):
            self.assertEqual(hashlib.sha256((fixture / (name+".source")).read_bytes()).hexdigest(), pins[name])
        with tempfile.TemporaryDirectory(prefix="program-source-change-") as temporary:
            parent = Path(temporary).resolve()
            child, result, calls, directory, operation = self.controlled_protocol(parent, "source-change",
                fixture / "ssh_program_mcp_client.py.source", relay_source=fixture / "ssh_keeper_mcp_relay.py.source")
            self.assertEqual(1, child.returncode)
            self.assertEqual("FileNotFoundError", result["exceptionClass"])
            self.assertFalse((directory / "server-terminal.json").exists())
            with self.assertRaises(AssertionError):
                self.assertTrue(result["originalServerTerminalClosed"])  # actual whole before RED
            child, result, calls, directory, operation = self.controlled_protocol(parent, "source-change",
                ROOT / "agent_tools/ssh_program_mcp_client.py")
            self.assertEqual(1, child.returncode)
            self.assertEqual("program_mcp_server_source_changed", result["reason"])
            self.assertEqual(operation, result["operationId"])
            self.assertEqual(1, result["relayAttempts"])
            terminal = json.loads((directory / "server-terminal.json").read_bytes())
            self.assertTrue(terminal["complete"])
            self.assertFalse(terminal["sourceUnchanged"])
            self.assertEqual(terminal["returnCode"], 0)
            self.assertEqual(result["nextAction"]["kind"], "resolve_blocker")
            self.assertFalse(result["serverExecutionProven"])

    def test_actual_server_loss_whole_before_red_current_reconnect_original_green(self):
        fixture = Path(__file__).parent / "fixtures/program_mcp_reconnect_before"
        before = fixture / "ssh_program_mcp_client.py.source"
        self.assertEqual(json.loads((fixture / "provenance.json").read_bytes())["sha256"], hashlib.sha256(before.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory(prefix="program-protocol-loss-") as temporary:
            parent = Path(temporary).resolve()
            child, result, calls, directory, operation = self.controlled_protocol(parent, "lost-start", before)
            with self.assertRaises(AssertionError):
                self.assertEqual("terminal", result.get("programState"))
            self.assertEqual(1, child.returncode)
            child, result, calls, directory, operation = self.controlled_protocol(parent, "lost-start", ROOT / "agent_tools/ssh_program_mcp_client.py")
            self.assertEqual(0, child.returncode)
            self.assertEqual("terminal", result["programState"])
            self.assertEqual(operation, result["operationId"])
            self.assertEqual(2, result["relayAttempts"])
            self.assertEqual("program-reconcile", calls[1]["action"])
            self.assertTrue((directory / "server-terminal.json").exists())
            self.assertTrue((directory / "relay-recovery-00000001/server-terminal.json").exists())

    def test_follow_deadline_during_call_before_red_closes_relay_green(self):
        fixture = Path(__file__).parent / "fixtures/program_mcp_follow_deadline_before"
        before = fixture / "ssh_program_mcp_client.py.source"
        self.assertEqual(json.loads((fixture / "provenance.json").read_bytes())["sha256"], hashlib.sha256(before.read_bytes()).hexdigest())
        with tempfile.TemporaryDirectory(prefix="program-follow-deadline-") as temporary:
            parent = Path(temporary).resolve()
            # The follow status call is still in flight when the 2 s deadline passes.
            child, result, calls, directory, operation = self.controlled_protocol(parent, "slow-follow", before, follow_seconds=2)
            self.assertEqual("ExceptionGroup", result["exceptionClass"])
            self.assertFalse((directory / "server-terminal.json").exists())
            with self.assertRaises(AssertionError):
                self.assertTrue(result["allRelayAttemptsClosed"])  # actual whole before RED
            child, result, calls, directory, operation = self.controlled_protocol(parent, "slow-follow",
                ROOT / "agent_tools/ssh_program_mcp_client.py", follow_seconds=2)
            self.assertTrue(result["followDeadlineReached"])
            self.assertNotIn("exceptionClass", result)
            self.assertEqual(1, result["relayAttempts"])
            self.assertTrue(result["originalServerTerminalClosed"])
            self.assertTrue(result["allRelayAttemptsClosed"])
            self.assertEqual(result["attemptedToolCalls"], result["returnedToolCalls"])
            self.assertEqual(result["attemptedToolCalls"], result["forwardedToolCalls"])
            self.assertTrue(json.loads((directory / "server-terminal.json").read_bytes())["complete"])
            self.assertEqual(operation, result["operationId"])
            self.assertFalse(result["automaticReplay"])

    def test_actual_terminal_ack_loss_reconciles_and_collects_original(self):
        with tempfile.TemporaryDirectory(prefix="program-terminal-ack-") as temporary:
            child, result, calls, directory, operation = self.controlled_protocol(Path(temporary).resolve(), "lost-terminal", ROOT / "agent_tools/ssh_program_mcp_client.py")
            self.assertEqual(0, child.returncode)
            self.assertEqual("terminal", result["programState"])
            self.assertEqual(2, result["relayAttempts"])
            self.assertEqual("program-collect", calls[-1]["action"])
            self.assertEqual("program-reconcile", json.loads((directory / "relay-attempt-00000001.json").read_bytes())["initialRequest"]["action"])

    def test_actual_repeated_protocol_loss_is_bounded_and_retains_original_identity(self):
        with tempfile.TemporaryDirectory(prefix="program-protocol-bounded-") as temporary:
            child, result, calls, directory, operation = self.controlled_protocol(Path(temporary).resolve(), "always-loss", ROOT / "agent_tools/ssh_program_mcp_client.py")
            self.assertEqual(1, child.returncode)
            self.assertEqual("unknown", result["state"])
            self.assertEqual(operation, result["operationId"])
            self.assertEqual("owned-peer", result["host"])
            self.assertEqual(3, result["relayAttempts"])
            self.assertEqual(["program-start", "program-reconcile", "program-reconcile"], [row["action"] for row in calls])

    def test_actual_typed_blocker_never_opens_replacement_session(self):
        with tempfile.TemporaryDirectory(prefix="program-protocol-blocker-") as temporary:
            child, result, calls, directory, operation = self.controlled_protocol(Path(temporary).resolve(), "typed-blocker", ROOT / "agent_tools/ssh_program_mcp_client.py")
            self.assertEqual(0, child.returncode)
            self.assertEqual("unknown", result["programState"])
            self.assertEqual(1, result["relayAttempts"])
            self.assertEqual(["program-start"], [row["action"] for row in calls])

    def test_protocol_recovery_excludes_cancellation_integrity_and_mixed_errors(self):
        import asyncio
        from agent_tools import ssh_program_mcp_client as client
        self.assertTrue(client.protocol_loss(ConnectionResetError()))
        self.assertTrue(client.protocol_loss(ExceptionGroup("transport", [EOFError(), TimeoutError()])))
        self.assertFalse(client.protocol_loss(asyncio.CancelledError()))
        self.assertFalse(client.protocol_loss(ValueError("source integrity blocker")))
        self.assertFalse(client.protocol_loss(ExceptionGroup("mixed", [EOFError(), ValueError("credential blocker")])))

    def test_native_proxy_target_source_collision_before_red_fixed_socket_green(self):
        import select
        import socket
        import threading
        fixture = Path(__file__).parent / "fixtures/program_proxy_qualification"
        provenance = json.loads((fixture / "provenance.json").read_bytes())
        target = socket.socket()
        target.bind(("127.0.0.1", 0)); target.listen(); target.settimeout(3)
        configured = {"host": "127.0.0.1", "port": target.getsockname()[1]}
        errors = []
        def echo():
            with target.accept()[0] as stream:
                stream.sendall(stream.recv(64))
        responder = threading.Thread(target=echo, daemon=True)
        responder.start()
        try:
            for name in ("before", "fixed"):
                raw = (fixture / (name + ".source")).read_bytes()
                self.assertEqual(provenance[name + "Sha256"], hashlib.sha256(raw).hexdigest())
                tree = ast.parse(raw)
                node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Proxy")
                proxy_code = compile(ast.fix_missing_locations(ast.Module(body=[node], type_ignores=[])), str(fixture / (name + ".source")), "exec")
                scope = {"select": select, "socket": socket, "threading": threading,
                         "source": configured, "configured_target": configured}
                exec(proxy_code, scope)
                proxy = scope["Proxy"]()
                # Exactly the original harness's later sentinel-source binding.
                scope["source"] = "print('sentinel source')"
                try:
                    with mock.patch.object(threading, "excepthook", side_effect=lambda value: errors.append(value.exc_value)):
                        with socket.create_connection(("127.0.0.1", proxy.port), timeout=1) as client:
                            client.settimeout(.3); client.sendall(b"sentinel")
                            if name == "before":
                                with self.assertRaises((TimeoutError, ConnectionResetError)):
                                    self.assertEqual(b"sentinel", client.recv(64))
                            else:
                                self.assertEqual(b"sentinel", client.recv(64))
                finally:
                    proxy.close(); proxy.thread.join(timeout=1)
            self.assertEqual([TypeError], [type(error) for error in errors])
        finally:
            target.close(); responder.join(timeout=1)

    def isolated_root(self, parent):
        # The actual server records refused native outcomes as TEST-001 evidence
        # under its own REPO_ROOT. Copied current source bytes and the same SDK
        # runtime keep client, relay and server authentic; records stay here.
        root = parent / "repository"
        shutil.copytree(ROOT / "agent_tools", root / "agent_tools", ignore=shutil.ignore_patterns("tests", "__pycache__"))
        # The repository interpreter path the client and relay launch is this
        # test's own SDK interpreter: its venv when it has one (a bare symlink
        # would lose the venv), else the interpreter itself (CI has no venv).
        if sys.prefix != sys.base_prefix:
            (root / ".agent_venv").symlink_to(Path(sys.prefix), target_is_directory=True)
        else:
            binary = root / ".agent_venv/bin"
            binary.mkdir(parents=True)
            (binary / "python").symlink_to(sys.executable)
        return root

    def invoke(self, parent, source, label, extra=(), root=ROOT):
        # Preserve the authentic client's module location under root while loading
        # its exact retained bytes. No source statement or protocol is replaced.
        filename = root / "agent_tools/ssh_program_mcp_client.py"
        loader = ("from pathlib import Path;import sys;"
                  "filename,source=sys.argv[1:3];sys.argv=[filename,*sys.argv[3:]];"
                  "exec(compile(Path(source).read_bytes(),filename,'exec'),"
                  "{'__name__':'__main__','__file__':filename})")
        environment = {key: value for key, value in os.environ.items()
                       if key != "PYTHONPATH" and not key.startswith("DYLD_")}
        args = [sys.executable, "-I", "-B", "-c", loader, str(filename), str(source),
                "--session", label, "--server-sha256",
                hashlib.sha256((root / "agent_tools/mcp_server.py").read_bytes()).hexdigest(),
                "--output-root", str(parent), *extra]
        child = subprocess.run(args, cwd=root, env=environment, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45)
        self.assertEqual(b"", child.stderr)
        directory = parent / label
        result = json.loads((directory / "client-result.json").read_bytes())
        self.assertIs(result["sdkCallAttempted"], bool(extra))
        self.assertIs(result["automaticReplay"], False)
        return child, result, directory

    def assert_protocol_ready(self, child, result):
        self.assertEqual(0, child.returncode)
        self.assertEqual("protocol_ready", result["state"])
        self.assertIs(result["originalServerTerminalClosed"], True)
        self.assertEqual(0, result["forwardedToolCalls"])

    def test_original_missing_import_path_is_red_and_whole_fixed_client_is_green(self):
        before = FIXTURE / "before.source"
        raw = before.read_bytes()
        provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
        self.assertEqual(provenance["sourceSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(provenance["sourceBytes"], len(raw))
        with tempfile.TemporaryDirectory(prefix="program-mcp-import-") as temporary:
            parent = Path(temporary).resolve()
            root = self.isolated_root(parent)
            child, result, directory = self.invoke(parent, before, "before", root=root)
            with self.assertRaises(AssertionError):
                self.assert_protocol_ready(child, result)
            self.assertEqual(1, child.returncode)
            self.assertEqual("unknown", result["state"])
            self.assertIn("ModuleNotFoundError: No module named 'agent_tools'",
                          (directory / "sdk.stderr").read_text())
            self.assertFalse((directory / "server-intent.json").exists())
            child, result, directory = self.invoke(parent, ROOT / "agent_tools/ssh_program_mcp_client.py", "after", root=root)
            self.assert_protocol_ready(child, result)
            self.assertTrue((directory / "initialize.json").is_file())
            inventory = json.loads((directory / "tools.json").read_bytes())
            self.assertIn("ssh_workflow", {tool["name"] for tool in inventory["tools"]})
            terminal = json.loads((directory / "server-terminal.json").read_bytes())
            self.assertEqual({"stdout": True, "stderr": True}, terminal["eof"])
            self.assertEqual(0, terminal["delivery"]["toolCallFrameCount"])

    def test_actual_program_route_refuses_unsupported_language_before_dispatch(self):
        operation = str(uuid.uuid4())
        request = {"operationId": operation, "program": {"language": "powershell",
                   "source": "Write-Output unused", "args": [], "cwd": "/", "targetContext": {}}}
        checkout = ROOT / ".rag_index/native-failures"
        listing = lambda: set(os.listdir(checkout)) if checkout.is_dir() else set()
        with tempfile.TemporaryDirectory(prefix="program-mcp-route-") as temporary:
            parent = Path(temporary).resolve()
            root = self.isolated_root(parent)
            path = parent / "request.private.json"
            path.write_text(json.dumps(request)); path.chmod(0o600)
            before = listing()
            child, result, directory = self.invoke(parent, ROOT / "agent_tools/ssh_program_mcp_client.py", "refused",
                ("--action", "program-start", "--host", "explicit-peer", "--request-file", str(path)), root=root)
            self.assertEqual(0, child.returncode)
            self.assertEqual("rpc_returned", result["state"])
            self.assertIs(result["originalServerTerminalClosed"], True)
            self.assertEqual(1, result["forwardedToolCalls"])
            call = json.loads((directory / "call-result.json").read_bytes())["structuredContent"]
            self.assertEqual("refused", call["state"])
            self.assertEqual("program_language_unsupported", call["reason"])
            self.assertEqual(operation, call["operationId"])
            self.assertIs(call["replayAllowed"], False)
            # The typed refusal remains TEST-001 evidence of the temporary
            # repository the actual server ran from, never of the checkout.
            record = root / ".rag_index/native-failures" / (call["failureEvidence"]["evidenceId"] + ".json")
            self.assertEqual(str(record), call["failureEvidence"]["evidencePath"])
            saved = json.loads(record.read_bytes())
            self.assertEqual(["program-start", "explicit-peer", "program_language_unsupported"],
                             [saved["action"], saved["environmentAlias"], saved["errorCategory"]])
            self.assertNotIn(record.name, listing() - before)
            for repository in (root, ROOT):
                self.assertFalse((repository / ".rag_index/ssh-program-execution" / operation).exists())
            terminal = json.loads((directory / "server-terminal.json").read_bytes())
            self.assertEqual({"stdout": True, "stderr": True}, terminal["eof"])
            self.assertEqual(1, terminal["delivery"]["toolCallFrameCount"])
            self.assertEqual(1, terminal["delivery"]["fullyForwardedToolCallFrameCount"])

    def test_follow_actions_bind_original_identity_and_never_replay_start(self):
        from agent_tools import ssh_program_mcp_client as client
        operation=str(uuid.uuid4())
        for kind, action in (("observe_original","program-status"),("reconcile_original","program-reconcile"),("collect_original","program-collect")):
            value={"operationId":operation,"host":"owned-peer","nextAction":{"kind":kind,"action":{"action":"program-start","args":{"host":"foreign","identity":{"operationId":str(uuid.uuid4())}}}}}
            expected=client.request(action,"owned-peer",{"operationId":operation})
            self.assertEqual(expected,client.follow_request("program-start","owned-peer",operation,value))
            self.assertNotEqual("program-start",expected["action"])
        self.assertIsNone(client.follow_request("program-collect","owned-peer",operation,{"operationId":operation,"nextAction":"collect_original"}))
        self.assertIsNone(client.follow_request("program-start","owned-peer",operation,{"operationId":str(uuid.uuid4()),"nextAction":"reconcile_original"}))
        self.assertIsNone(client.follow_request("program-start","owned-peer",operation,{"operationId":operation,"nextAction":"resolve_blocker"}))
        with self.assertRaisesRegex(ValueError,"program_mcp_follow_binding"):
            client.follow_request("program-start","owned-peer",operation,{"operationId":operation,"host":"foreign","nextAction":"observe_original"})

    def test_live_relay_producer_guard_before_red_correct_observer_green(self):
        from agent_tools import ssh_channel_keeper_entry as keeper
        from agent_tools.ssh_keeper_sdk_custody import producer_actor
        fixture=Path(__file__).parent/'fixtures/program_mcp_actor_before'
        raw=(fixture/'qualification.py.source').read_bytes()
        provenance=json.loads((fixture/'provenance.json').read_bytes())
        self.assertEqual(provenance['sha256'],hashlib.sha256(raw).hexdigest())
        tree=ast.parse(raw)
        guards=[node for node in ast.walk(tree) if isinstance(node,ast.Assert)
                and isinstance(node.test,ast.Compare) and isinstance(node.test.left,ast.Call)
                and isinstance(node.test.left.func,ast.Attribute) and node.test.left.func.attr=='actor'
                and isinstance(node.test.left.func.value,ast.Name) and node.test.left.func.value.id=='keeper'
                and any(isinstance(part,ast.Name) and part.id=='server' for part in ast.walk(node.test))]
        self.assertEqual(1,len(guards))
        guard=compile(ast.fix_missing_locations(ast.Module(body=guards,type_ignores=[])),str(fixture/'qualification.py.source'),'exec')
        with tempfile.TemporaryDirectory(prefix='program-relay-actor-') as temporary,tempfile.TemporaryDirectory(prefix='program-relay-root-') as sources:
            directory=Path(temporary).resolve();root=self.isolated_root(Path(sources).resolve())
            environment={key:value for key,value in os.environ.items() if not key.startswith('DYLD_')}
            environment['PYTHONPATH']=str(root)
            expected=hashlib.sha256((root/'agent_tools/mcp_server.py').read_bytes()).hexdigest()
            child=subprocess.Popen([str(root/'.agent_venv/bin/python'),'-B',str(root/'agent_tools/ssh_keeper_mcp_relay.py'),str(directory),expected],
                cwd=root,env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                import time
                deadline=time.monotonic()+10
                while not (directory/'server-intent.json').exists() and time.monotonic()<deadline and child.poll() is None:
                    time.sleep(.01)
                self.assertIsNone(child.poll())
                server=json.loads((directory/'server-intent.json').read_bytes())['serverActor']
                # Execute the exact original guard against the actual live
                # relay/server process, then use its reviewed producer format.
                with self.assertRaises(AssertionError):exec(guard,{'keeper':keeper,'server':server})
                self.assertEqual(server,producer_actor(server['pid']))
            finally:
                child.stdin.close();child.stdin=None
                stdout,stderr=child.communicate(timeout=15)
            self.assertEqual(0,child.returncode,stderr)
            self.assertEqual(b'',stdout)

    def test_actual_program_dispatch_refuses_windows_before_owner_import(self):
        from agent_tools import mcp_server as server
        fixture = Path(__file__).parent / "fixtures/program_coordinator_guard"
        raw = (fixture / "before.route.source").read_bytes()
        provenance = json.loads((fixture / "provenance.json").read_bytes())
        self.assertEqual(provenance["routeSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(provenance["routeBytes"], len(raw))
        actual_os_name = os.name
        class CoordinatorOs:
            name = "nt"
            def __getattr__(self, name):
                return getattr(os, name)
        facade = CoordinatorOs()
        attempted = []
        def refuse_owner_import(name):
            attempted.append(name)
            raise ModuleNotFoundError("native POSIX owner unavailable on this coordinator")
        namespace = dict(vars(server))
        namespace.update(os=facade, _agent_module=refuse_owner_import)
        exec(compile(raw, provenance["originalFile"], "exec", dont_inherit=True), namespace)
        original = namespace["_ssh_workflow_impl"]
        operation = str(uuid.uuid4())
        request = {"operationId": operation, "program": {"language": "python3", "source": "print('unused')",
                   "args": [], "cwd": "/", "targetContext": {}}}
        for action in ("program-start", "program-status", "program-collect"):
            fields = {"transfer": request} if action == "program-start" else {"identity": {"operationId": operation}}
            # Execute the exact complete old dispatcher. It tries the POSIX
            # owner before a platform guard and cannot provide a typed refusal.
            with self.assertRaisesRegex(ModuleNotFoundError, "native POSIX owner unavailable"):
                original(action, host="explicit-peer", **fields)
            self.assertEqual(["ssh_program_execution"], attempted)
            attempted.clear()
            # Scope only this module's os binding; pathlib and the process-wide
            # os module retain their actual platform throughout source guards.
            with mock.patch.object(server, "os", facade), mock.patch.object(server, "_agent_module", side_effect=refuse_owner_import):
                result = server._ssh_workflow_impl(action, host="explicit-peer", **fields)
            self.assertEqual({"tool": "ssh_workflow", "ok": False, "state": "refused",
                "reason": "program_coordinator_unsupported", "host": "explicit-peer", "operationId": operation,
                "nativeActionAllowed": False, "replayAllowed": False}, result)
            self.assertEqual([], attempted)
            self.assertEqual(actual_os_name, os.name)


if __name__ == "__main__":
    unittest.main()
