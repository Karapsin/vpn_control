"""Inert regressions for the fixed privileged terminal census."""
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import ssh_tmux_privileged_terminal_closure as privileged
from agent_tools import ssh_tmux_session as session
from agent_tools import ssh_tmux_closure_census_diagnostic as diagnostic
from agent_tools import ssh_tmux_session_ssh as old


class PrivilegedTerminalCensusTests(unittest.TestCase):
    def value(self):
        return {"state": "complete-root-census", "correlationId": privileged.CORRELATION,
                "hostBootId": "12345678-1234-4123-8123-123456789abc",
                "pane": {"pid": 777, "startTicks": 1}, "originalDeniedPid": 992,
                "originalDeniedStartTicks": 720, "workspaceProof": False,
                "nativeActionAllowed": False, "replayAllowed": False}

    def test_closed_projection_rejects_poisoned_output(self):
        for mutate in (lambda x: x.update(workspaceProof=True),
                       lambda x: x.update(originalDeniedPid=1),
                       lambda x: x.update(hostBootId="not-a-uuid"),
                       lambda x: x.update(extra=True)):
            value = self.value()
            mutate(value)
            with self.assertRaises(ValueError):
                privileged.validate(value)

    def test_diagnostic_entry_validator_accepts_only_strict_complete_carrier_output(self):
        value = self.value()
        self.assertEqual(value, privileged.validate_carrier_diagnostic(value))
        value["workspaceProof"] = True
        with self.assertRaises(ValueError):
            privileged.validate_carrier_diagnostic(value)

    def test_public_observe_diagnostic_reads_a_real_private_complete_capture_and_rejects_poisoned_output(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        job, snapshot, config, transport = object(), {"prepared": "86"}, object(), {"transport": "pin"}
        driver = types.SimpleNamespace(_saved=lambda _: (job, snapshot), _transport=lambda: (config, transport))
        captured = []; values = [self.value(), {**self.value(), "workspaceProof": True}]
        def capture(*_args, **kwargs):
            kwargs["guard"](); captured.append(kwargs)
            capsule = root / ("capsule-" + str(len(captured)))
            capsule.mkdir(mode=0o700)
            value = values[len(captured) - 1]
            stdout_pin = session.write_once(capsule / "stdout", session.canonical(value))
            stderr_pin = session.write_once(capsule / "stderr", b"")
            receipt_pin = session.write_once(capsule / "receipt.json", session.canonical({"stdoutPin": stdout_pin, "stderrPin": stderr_pin}))
            return ({"state": "captured", "receiptPin": receipt_pin}, capsule)
        def read_private(path, maximum=16384, private=True):
            return session.read(Path(path), maximum)
        with mock.patch.object(privileged.credentials, "_read_credential", return_value=b"PRIVATE\n"), \
             mock.patch.object(privileged.adapter, "McpTmuxDriver", return_value=driver), \
             mock.patch.object(privileged.ssh_transport, "connection_host", return_value=types.SimpleNamespace(password=None)), \
             mock.patch.object(privileged.ssh_transport, "build_ssh_argv", return_value=["fixed"]), \
             mock.patch.object(privileged, "_sources", return_value={"fixed": {"sha256": "a" * 64}}), \
             mock.patch.object(privileged.closure.pipe, "_read", side_effect=read_private), \
             mock.patch.object(privileged.adapter, "_capture", side_effect=capture):
            value = privileged.observe_diagnostic(root)
        self.assertEqual("complete-root-census", value["state"])
        self.assertIn("receiptPin", value)
        self.assertEqual(b"PRIVATE\n", captured[0]["payload"])
        with mock.patch.object(privileged.credentials, "_read_credential", return_value=b"PRIVATE\n"), \
             mock.patch.object(privileged.adapter, "McpTmuxDriver", return_value=driver), \
             mock.patch.object(privileged.ssh_transport, "connection_host", return_value=types.SimpleNamespace(password=None)), \
             mock.patch.object(privileged.ssh_transport, "build_ssh_argv", return_value=["fixed"]), \
             mock.patch.object(privileged, "_sources", return_value={"fixed": {"sha256": "a" * 64}}), \
             mock.patch.object(privileged.closure.pipe, "_read", side_effect=read_private), \
             mock.patch.object(privileged.adapter, "_capture", side_effect=capture), self.assertRaises(ValueError):
            privileged.observe_diagnostic(root)

    def test_fixed_program_has_one_inherited_emit_and_no_effect_actions(self):
        source = privileged.program()
        self.assertEqual(1, source.count("print(json.dumps("))
        self.assertIn("os.geteuid()!=0", source)
        self.assertIn("ns['status'](job,source,payload['anchorPin'])", source)
        self.assertNotIn("ns['release']", source)
        self.assertNotIn("ns['start']", source)
        self.assertNotIn("archive", privileged.ROOT_PROGRAM)
        self.assertNotIn("reservation", privileged.ROOT_PROGRAM)

    def test_actual_inherited_owner_prefix_rejects_root_before_status_then_owner_admits(self):
        payload, _code, Paths, Hash, _proxy, output = self._fixture()
        owner = privileged.owner_program()
        with mock.patch("pathlib.Path", Paths.Path), mock.patch.dict(sys.modules, {"hashlib": Hash}), \
             mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))), \
             mock.patch.object(sys, "stdout", output), mock.patch("os.getuid", return_value=0), \
             self.assertRaises(SystemExit) as rejected:
            exec(owner, {})
        self.assertEqual(32, rejected.exception.code)
        admitted = io.StringIO()
        with mock.patch("pathlib.Path", Paths.Path), mock.patch.dict(sys.modules, {"hashlib": Hash}), \
             mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))), \
             mock.patch.object(sys, "stdout", admitted):
            exec(owner, {})
        self.assertEqual("owner-admitted-root-census", json.loads(admitted.getvalue())["state"])

    def _fixture(self, *, live=False, zombie=False, drift=False, source_drift=False,
                 terminal_drift=False, anchor_drift=False, missing_cwd=False, status_exit33=False):
        payload = {"action": "status", "request": old.purpose(privileged.closure.pipe.REQUEST),
                   "stagePin": privileged.closure.pipe.STAGE, "anchorPin": privileged.closure.pipe.ANCHOR}
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        remote = root / "remote"
        job = remote / privileged.CORRELATION
        source = job / "source"
        source.mkdir(parents=True)
        proc = root / "proc"
        (proc / "sys/kernel/random").mkdir(parents=True)
        (proc / "sys/kernel/random/boot_id").write_text("12345678-1234-4123-8123-123456789abc")
        item = proc / "992"
        item.mkdir()
        state = "Z" if zombie else "S"
        fields = [state] + ["0"] * 18 + ["720"] + ["0"] * 3
        (item / "stat").write_text("992 (inert) " + " ".join(fields))
        (item / "status").write_bytes(b"Kthread:\t0\n")
        command = os.fsencode(job / "source") + b"\0" if live else b"inert\0"
        if zombie:
            command = b""
        (item / "cmdline").write_bytes(command)
        if not zombie and not missing_cwd:
            (item / "cwd").symlink_to(root)
        terminal = {"state": "terminal", "correlationId": payload["request"]["correlationId"],
                    "exitCode": 0, "terminalPin": privileged.closure.pipe.TERMINAL,
                    "artifactVerification": "required", "replayAllowed": False}
        tool = """PIN={'generation':[1], 'sha256':'a'*64}
REQ=""" + repr(payload["request"]) + """
STAGE=""" + repr(payload["stagePin"]) + """
ANCHOR=""" + repr(payload["anchorPin"]) + """
TERM=""" + repr(privileged.closure.pipe.TERMINAL) + """
def private_dir(path): return {'private':str(path)}
def read(path,limit=None):
 raw=path.read_bytes()
 if path.name=='stage-ready.json': return raw,STAGE
 if path.name=='tmux-tool.py': return raw,PIN
 return raw,PIN
def source_pin(source,request): return PIN
def status(job,source,anchor): return {'state':'terminal','correlationId':REQ['correlationId'],'exitCode':0,'terminalPin':TERM,'artifactVerification':'required','replayAllowed':False}
def _anchor(job,source,anchor): return {'pane':{'pid':777,'startTicks':1}}
"""
        if source_drift:
            tool = tool.replace("def source_pin(source,request): return PIN",
                                "COUNT=0\ndef source_pin(source,request):\n global COUNT;COUNT+=1;return PIN if COUNT==1 else {'generation':[2],'sha256':'b'*64}")
        if terminal_drift:
            tool = tool.replace("def status(job,source,anchor): return {'state':'terminal'",
                "STATUS_COUNT=0\ndef status(job,source,anchor):\n global STATUS_COUNT;STATUS_COUNT+=1\n if STATUS_COUNT>1:return {'state':'changed'}\n return {'state':'terminal'")
        if anchor_drift:
            tool = tool.replace("def _anchor(job,source,anchor): return {'pane':{'pid':777,'startTicks':1}}",
                "ANCHOR_COUNT=0\ndef _anchor(job,source,anchor):\n global ANCHOR_COUNT;ANCHOR_COUNT+=1\n return {'pane':{'pid':777 if ANCHOR_COUNT==1 else 778,'startTicks':1}}")
        if status_exit33:
            tool = tool.replace("def status(job,source,anchor): return {'state':'terminal'",
                                "def status(job,source,anchor): raise SystemExit(33)\n#")
        tool_path = job / "tmux-tool.py"
        tool_path.write_text(tool)
        tool_path.chmod(0o600)
        ready = {"request": payload["request"], "toolPin": {"generation": [1], "sha256": "a" * 64},
                 "proof": {"source": {"generation": [1], "sha256": "a" * 64},
                           "parent": {"private": str(job.parent)}, "job": {"private": str(job)}}}
        (job / "stage-ready.json").write_text(json.dumps(ready))
        (job / "stage-ready.json").chmod(0o600)
        code = privileged.program()
        if drift:
            code = code.replace("  after=fields(fd)",
                "  (p/'stat').write_bytes((p/'stat').read_bytes().replace(b'720',b'721'))\n  after=fields(fd)")
        local_path = Path
        class Paths:
            @staticmethod
            def Path(path):
                text = str(path)
                if text == "/proc":
                    return proc
                if text.startswith("/proc/"):
                    return proc / text[6:]
                prefix = "/home/kardinal/.vpn-control-linux-package-fixture"
                if text.startswith(prefix):
                    return remote / text[len(prefix):].lstrip("/")
                return local_path(path)
        real_sha = hashlib.sha256
        class Hash:
            @staticmethod
            def sha256(raw):
                if raw == tool.encode():
                    return types.SimpleNamespace(hexdigest=lambda: old.TOOL_SHA)
                return real_sha(raw)
        proxy = types.SimpleNamespace(**vars(os))
        proxy.geteuid = lambda: 0
        proxy.getpid = lambda: 999
        return payload, code, Paths, Hash(), proxy, io.StringIO()

    def _execute(self, fixture, *, expect_exit=None):
        payload, code, Paths, Hash, proxy, output = fixture
        context = (mock.patch("pathlib.Path", Paths.Path), mock.patch.dict(sys.modules, {"hashlib": Hash}),
                   mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))),
                   mock.patch.object(sys, "stdout", output))
        with context[0], context[1], context[2], context[3], mock.patch("os.geteuid", return_value=0):
            if expect_exit is None:
                exec(code, {"os": proxy})
            else:
                with self.assertRaises(SystemExit) as refused:
                    exec(code, {"os": proxy})
                self.assertIn(refused.exception.code, expect_exit)
        return output.getvalue()

    def test_actual_generated_program_root_completes_after_original_eacces_case(self):
        # The old unprivileged observer classifies the measured unreadable cwd;
        # the successor root census reads every row and remains observation-only.
        fixture = self._fixture()
        payload, _code, Paths, Hash, _proxy, denied_output = fixture
        native_readlink = os.readlink
        def denied(path, *args, **kwargs):
            if str(path).endswith("/992/cwd"):
                raise PermissionError(13, "nondumpable")
            return native_readlink(path, *args, **kwargs)
        with mock.patch("pathlib.Path", Paths.Path), mock.patch.dict(sys.modules, {"hashlib": Hash}), \
             mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(json.dumps(payload).encode()))), \
             mock.patch.object(sys, "stdout", denied_output), mock.patch("os.readlink", side_effect=denied):
            exec(diagnostic.remote_program(), {})
        self.assertEqual("process-cwd-error", json.loads(denied_output.getvalue())["phase"])
        output = self._execute(self._fixture())
        rows = output.splitlines()
        self.assertEqual(1, len(rows))
        self.assertEqual("complete-root-census", json.loads(rows[0])["state"])

    def test_actual_generated_program_refuses_live_workspace_zombie_and_pid_drift(self):
        for name, kwargs, codes in (("live", {"live": True}, (37,)),
                                    ("zombie", {"zombie": True}, (36,)),
                                    ("drift", {"drift": True}, (36,)),
                                    ("missing-cwd", {"missing_cwd": True}, (36,))):
            with self.subTest(name=name):
                self.assertEqual("", self._execute(self._fixture(**kwargs), expect_exit=codes))

    def test_actual_generated_program_refuses_inherited_source_tail_drift_before_emit(self):
        self.assertEqual("", self._execute(self._fixture(source_drift=True), expect_exit=(33,)))

    def test_diagnostic_program_classifies_the_actual_silent_inherited_exit_33(self):
        fixture = list(self._fixture(source_drift=True))
        fixture[1] = privileged.diagnostic_program()
        output = self._execute(tuple(fixture))
        value = json.loads(output)
        self.assertEqual("diagnosed-root-census", value["state"])
        self.assertEqual("post-root-source-guard", value["phase"])
        self.assertFalse(value["workspaceProof"])

    def test_diagnostic_program_does_not_mislabel_an_in_census_exit_33_as_pre_dispatch(self):
        fixture = list(self._fixture(status_exit33=True))
        fixture[1] = privileged.diagnostic_program()
        value = json.loads(self._execute(tuple(fixture)))
        self.assertEqual("guard-or-census-before-result", value["phase"])
        self.assertEqual(0, value["pid"])
        self.assertIsNone(value["errno"])

    def test_diagnostic_projection_rejects_unbounded_or_positive_facts(self):
        value = {"state": "diagnosed-root-census", "correlationId": privileged.CORRELATION,
                 "phase": "post-root-source-guard", "pid": 0, "startTicks": 0, "errno": None,
                 "workspaceProof": False, "nativeActionAllowed": False, "replayAllowed": False}
        privileged.validate_diagnostic(value)
        for key, replacement in (("phase", "raw-exception"), ("pid", -1),
                                 ("nativeActionAllowed", True)):
            poisoned = dict(value)
            poisoned[key] = replacement
            with self.assertRaises(ValueError):
                privileged.validate_diagnostic(poisoned)

    def test_actual_generated_program_refuses_terminal_and_anchor_drift_before_emit(self):
        for name, kwargs in (("terminal", {"terminal_drift": True}),
                             ("anchor", {"anchor_drift": True})):
            with self.subTest(name=name):
                self.assertEqual("", self._execute(self._fixture(**kwargs), expect_exit=(32,)))

    def test_wrapper_uses_stdin_only_and_does_not_echo_secret(self):
        calls = []
        fake = types.ModuleType("subprocess")
        fake.PIPE = -1
        fake.DEVNULL = -3
        fake.TimeoutExpired = subprocess.TimeoutExpired
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return types.SimpleNamespace(returncode=0, stdout=b'{"state":"inert"}', stderr=b"")
        fake.run = run
        out = types.SimpleNamespace(buffer=io.BytesIO())
        with mock.patch.dict(sys.modules, {"subprocess": fake}), \
             mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"PRIVATE\n"))), \
             mock.patch.object(sys, "stdout", out):
            exec(privileged.WRAPPER, {})
        argv, kwargs = calls[0]
        self.assertEqual(argv[:7], ["/usr/bin/sudo", "-S", "-p", "", "--", "/usr/bin/python3", "-I"])
        self.assertNotIn("PRIVATE", str(argv))
        self.assertEqual(kwargs["input"], b"PRIVATE\n")
        self.assertEqual(kwargs["stderr"], fake.PIPE)
        self.assertNotIn(b"PRIVATE", out.buffer.getvalue())

    def test_full_wrapper_composition_uses_fixed_payload_literal_after_sudo_consumes_stdin(self):
        remote = privileged.program()
        wrapper = privileged.WRAPPER.replace(repr(privileged.ROOT_PROGRAM), repr(remote))
        calls = []
        fake = types.ModuleType("subprocess")
        fake.PIPE = -1
        fake.TimeoutExpired = subprocess.TimeoutExpired
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            return types.SimpleNamespace(returncode=0, stdout=b"{}", stderr=b"")
        fake.run = run
        out = types.SimpleNamespace(buffer=io.BytesIO())
        with mock.patch.dict(sys.modules, {"subprocess": fake}), \
             mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"secret\n"))), \
             mock.patch.object(sys, "stdout", out):
            exec(wrapper, {})
        argv, kwargs = calls[0]
        embedded = ast.literal_eval(ast.parse(argv[-1], mode="eval").body.args[0])
        self.assertEqual(kwargs["input"], b"secret\n")
        self.assertNotIn("sys.stdin.buffer.read(16385)", embedded)
        self.assertIn("payload={'action': 'status'", embedded)
        compile(embedded, "<composed-root-program>", "exec")

    def test_actual_wrapper_to_sudo_to_generated_root_prefix_works_with_password_only_stdin(self):
        _payload, _code, Paths, Hash, _proxy, _output = self._fixture()
        remote = privileged.program()
        wrapper = privileged.WRAPPER.replace(repr(privileged.ROOT_PROGRAM), repr(remote))
        fake = types.ModuleType("subprocess")
        fake.PIPE = -1
        fake.TimeoutExpired = subprocess.TimeoutExpired
        observed = []
        def run(argv, **kwargs):
            observed.append(kwargs["input"])
            embedded = ast.literal_eval(ast.parse(argv[-1], mode="eval").body.args[0])
            inner = io.StringIO()
            with contextlib.redirect_stdout(inner):
                exec(embedded, {})
            return types.SimpleNamespace(returncode=0, stdout=inner.getvalue().encode(), stderr=b"")
        fake.run = run
        outer = types.SimpleNamespace(buffer=io.BytesIO())
        with mock.patch("pathlib.Path", Paths.Path), mock.patch.dict(sys.modules, {"hashlib": Hash, "subprocess": fake}), \
             mock.patch("os.geteuid", return_value=0), \
             mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"PRIVATE\n"))), \
             mock.patch.object(sys, "stdout", outer):
            exec(wrapper, {})
        self.assertEqual([b"PRIVATE\n"], observed)
        self.assertEqual("complete-root-census", json.loads(outer.buffer.getvalue())["state"])

    def test_actual_carrier_runs_owner_root_owner_and_refuses_closing_anchor_drift(self):
        for name, closing_drift in (("stable", False), ("closing-drift", True)):
            with self.subTest(name=name):
                _payload, _code, Paths, Hash, _proxy, _output = self._fixture()
                carrier = privileged.carrier_program()
                fake = types.ModuleType("subprocess")
                fake.PIPE = -1
                fake.TimeoutExpired = subprocess.TimeoutExpired
                calls = []
                owner_calls = [0]
                def run(argv, **kwargs):
                    calls.append((argv, kwargs))
                    embedded = ast.literal_eval(ast.parse(argv[-1], mode="eval").body.args[0])
                    output = io.StringIO()
                    if argv[0] == "/usr/bin/sudo":
                        with contextlib.redirect_stdout(output), mock.patch("os.geteuid", return_value=0):
                            exec(embedded, {})
                    else:
                        with contextlib.redirect_stdout(output):
                            exec(embedded, {})
                        owner_calls[0] += 1
                        if closing_drift and owner_calls[0] == 2:
                            value = json.loads(output.getvalue())
                            value["pane"] = {"pid": 778, "startTicks": 1}
                            output = io.StringIO()
                            print(json.dumps(value, sort_keys=True, separators=(",", ":")), file=output)
                    return types.SimpleNamespace(returncode=0, stdout=output.getvalue().encode(), stderr=b"")
                fake.run = run
                outer = types.SimpleNamespace(buffer=io.BytesIO())
                with mock.patch("pathlib.Path", Paths.Path), mock.patch.dict(sys.modules, {"hashlib": Hash, "subprocess": fake}), \
                     mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"PRIVATE\n"))), \
                     mock.patch.object(sys, "stdout", outer):
                    if closing_drift:
                        with self.assertRaises(SystemExit) as refused:
                            exec(carrier, {})
                        self.assertEqual(34, refused.exception.code)
                    else:
                        exec(carrier, {})
                self.assertEqual(2, owner_calls[0])
                self.assertEqual(1, sum(1 for argv, _ in calls if argv[0] == "/usr/bin/sudo"))
                if not closing_drift:
                    self.assertEqual("complete-root-census", json.loads(outer.buffer.getvalue())["state"])

    def test_actual_carrier_projects_measured_root_child_exit_with_empty_stdout(self):
        _payload, _code, Paths, Hash, _proxy, _output = self._fixture()
        carrier = privileged.carrier_program()
        fake = types.ModuleType("subprocess")
        fake.PIPE = -1
        fake.TimeoutExpired = subprocess.TimeoutExpired
        def run(argv, **kwargs):
            if argv[0] == "/usr/bin/sudo":
                return types.SimpleNamespace(returncode=36, stdout=b"", stderr=b"")
            embedded = ast.literal_eval(ast.parse(argv[-1], mode="eval").body.args[0])
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exec(embedded, {})
            return types.SimpleNamespace(returncode=0, stdout=output.getvalue().encode(), stderr=b"")
        fake.run = run
        class Stream:
            def __init__(self): self.buffer = io.BytesIO()
            def write(self, text): self.buffer.write(text.encode()); return len(text)
            def flush(self): pass
        outer = Stream()
        errors = Stream()
        with mock.patch("pathlib.Path", Paths.Path), mock.patch.dict(sys.modules, {"hashlib": Hash, "subprocess": fake}), \
             mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"PRIVATE\n"))), \
             mock.patch.object(sys, "stdout", outer), mock.patch.object(sys, "stderr", errors):
            with self.assertRaises(SystemExit) as stopped:
                exec(carrier, {})
        self.assertEqual(0, stopped.exception.code)
        value = json.loads(outer.buffer.getvalue())
        self.assertEqual({"state": "root-census-failed", "correlationId": privileged.CORRELATION,
                          "phase": "proc-observation-unknown", "childExit": 36, "errno": None,
                          "workspaceProof": False, "nativeActionAllowed": False, "replayAllowed": False}, value)
        privileged.validate_carrier_diagnostic(value)

    def test_actual_root_census_reports_pid_substep_and_measured_cwd_errno(self):
        _payload, _code, Paths, _Hash, _proxy, _output = self._fixture()
        facts = {"state": "owner-admitted-root-census", "correlationId": privileged.CORRELATION,
                 "terminal": privileged.closure.pipe.TERMINAL, "pane": {"pid": 777, "startTicks": 1},
                 "replayAllowed": False, "nativeActionAllowed": False, "workspaceProof": False}
        code = privileged.ROOT_CENSUS.replace("FIXED_CORRELATION", repr(privileged.CORRELATION)).replace("OWNER_FACT", repr(facts))
        out = io.StringIO()
        native_readlink = os.readlink
        def denied(path, *args, **kwargs):
            if path == "cwd":
                raise PermissionError(13, "denied")
            return native_readlink(path, *args, **kwargs)
        with mock.patch("pathlib.Path", Paths.Path), mock.patch("os.geteuid", return_value=0), \
             mock.patch("os.readlink", side_effect=denied), contextlib.redirect_stdout(out), \
             self.assertRaises(SystemExit) as stopped:
            exec(code, {})
        self.assertEqual(0, stopped.exception.code)
        value = json.loads(out.getvalue())
        self.assertEqual(("root-census-proc-failed", "proc-io", 992, 720, "EACCES"),
                         (value["state"], value["substep"], value["pid"], value["startTicks"], value["errno"]))
        privileged.validate_carrier_diagnostic(value)

    def test_actual_root_census_allows_only_a_fully_proven_zombie_row(self):
        _payload, _code, Paths, _Hash, _proxy, _output = self._fixture(zombie=True)
        item = Paths.Path("/proc/992")
        (item / "fd").mkdir()
        (item / "maps").write_bytes(b"")
        facts = {"state": "owner-admitted-root-census", "correlationId": privileged.CORRELATION,
                 "terminal": privileged.closure.pipe.TERMINAL, "pane": {"pid": 777, "startTicks": 1},
                 "replayAllowed": False, "nativeActionAllowed": False, "workspaceProof": False}
        code = privileged.ROOT_CENSUS.replace("FIXED_CORRELATION", repr(privileged.CORRELATION)).replace("OWNER_FACT", repr(facts))
        output = io.StringIO()
        with mock.patch("pathlib.Path", Paths.Path), mock.patch("os.geteuid", return_value=0), contextlib.redirect_stdout(output):
            exec(code, {})
        self.assertEqual("complete-root-census", json.loads(output.getvalue())["state"])
        (item / "fd" / "occupied").write_bytes(b"x")
        refused = io.StringIO()
        with mock.patch("pathlib.Path", Paths.Path), mock.patch("os.geteuid", return_value=0), contextlib.redirect_stdout(refused), \
             self.assertRaises(SystemExit) as stopped:
            exec(code, {})
        self.assertEqual(0, stopped.exception.code)
        self.assertEqual("zombie-resources", json.loads(refused.getvalue())["substep"])
        (item / "fd" / "occupied").unlink()
        marker = "   child=os.open('fd',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)"
        second = code.rfind(marker)
        post_maps = code[:second] + "   (pathlib.Path('/proc/992')/'maps').write_bytes(b'changed')\n" + code[second:]
        refused = io.StringIO()
        with mock.patch("pathlib.Path", Paths.Path), mock.patch("os.geteuid", return_value=0), contextlib.redirect_stdout(refused), \
             self.assertRaises(SystemExit) as stopped:
            exec(post_maps, {})
        self.assertEqual(0, stopped.exception.code)
        self.assertEqual("zombie-postcheck", json.loads(refused.getvalue())["substep"])

    def test_wrapper_keeps_bounded_failure_stderr_for_the_private_transport_capsule(self):
        fake = types.ModuleType("subprocess")
        fake.PIPE = -1
        fake.TimeoutExpired = subprocess.TimeoutExpired
        fake.run = lambda *args, **kwargs: types.SimpleNamespace(returncode=1, stdout=b"", stderr=b"sudo denied")
        stdout = types.SimpleNamespace(buffer=io.BytesIO())
        stderr = types.SimpleNamespace(buffer=io.BytesIO())
        with mock.patch.dict(sys.modules, {"subprocess": fake}), \
             mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(b"PRIVATE\n"))), \
             mock.patch.object(sys, "stdout", stdout), mock.patch.object(sys, "stderr", stderr), \
             self.assertRaises(SystemExit) as refused:
            exec(privileged.WRAPPER, {})
        self.assertEqual(33, refused.exception.code)
        self.assertEqual(b"sudo denied", stderr.buffer.getvalue())
        self.assertNotIn(b"PRIVATE", stderr.buffer.getvalue())

    def test_observe_routes_secret_and_bounded_raw_capture_through_the_private_adapter(self):
        job, snapshot, config, transport = object(), {"saved": "pin"}, object(), {"transport": "pin"}
        captured = []
        driver = types.SimpleNamespace(_saved=lambda _: (job, snapshot), _transport=lambda: (config, transport))
        def capture(*_args, **kwargs):
            kwargs["guard"]()
            captured.append(kwargs)
            return ({"state": "unknown", "receiptPin": {"sha256": "a" * 64}}, Path("/inert"))
        with mock.patch.object(privileged.credentials, "_read_credential", return_value=b"PRIVATE\n"), \
             mock.patch.object(privileged.adapter, "McpTmuxDriver", return_value=driver), \
             mock.patch.object(privileged.ssh_transport, "connection_host", return_value=types.SimpleNamespace(password=None)), \
             mock.patch.object(privileged.ssh_transport, "build_ssh_argv", return_value=["fixed"]), \
             mock.patch.object(privileged.diagnostic, "_sources", return_value={"fixed": {"sha256": "a" * 64}}), \
             mock.patch.object(privileged.adapter, "_capture", side_effect=capture), \
             self.assertRaises(ValueError):
            privileged.observe(Path(self.tempdir()))
        self.assertEqual(b"PRIVATE\n", captured[0]["payload"])

    def test_current_prepared_adapter_replaces_only_retired_legacy_saved_admission(self):
        """Run both real inherited _saved methods over the same prepared record."""
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        job = Path(tmp.name) / privileged.CORRELATION
        job.mkdir(mode=0o700)
        request = privileged.closure.pipe.REQUEST
        prepared = {"request": request, "prepared": "current-86"}
        retired = {"request": request, "prepared": "retired-legacy"}
        session.write_once(job / "tmux-adapter-intent.json", session.canonical(prepared))
        legacy = object.__new__(old.TmuxArchDriver)
        legacy._job = lambda _: job
        legacy._snapshot = lambda _: retired
        current = object.__new__(privileged.adapter.McpTmuxDriver)
        current._job = lambda _: job
        current._snapshot = lambda _: prepared
        with self.assertRaisesRegex(ValueError, "admission_changed"):
            old.TmuxArchDriver._saved(legacy, request)
        self.assertEqual((job, prepared), privileged.adapter.McpTmuxDriver._saved(current, request))
        config, transport = object(), {"transport": "pin"}
        driver = types.SimpleNamespace(_saved=lambda _: (job, prepared), _transport=lambda: (config, transport))
        calls = []
        def capture(*_args, **kwargs):
            kwargs["guard"]()
            calls.append(kwargs)
            return ({"state": "unknown", "receiptPin": {"sha256": "a" * 64}}, Path("/inert"))
        with mock.patch.object(privileged.credentials, "_read_credential", return_value=b"PRIVATE\n"), \
             mock.patch.object(privileged.adapter, "McpTmuxDriver", return_value=driver), \
             mock.patch.object(privileged.ssh_transport, "connection_host", return_value=types.SimpleNamespace(password=None)), \
             mock.patch.object(privileged.ssh_transport, "build_ssh_argv", return_value=["fixed"]), \
             mock.patch.object(privileged, "_sources", return_value={"fixed": {"sha256": "a" * 64}}), \
             mock.patch.object(privileged.adapter, "_capture", side_effect=capture), \
             self.assertRaises(ValueError):
            privileged.observe(Path(self.tempdir()))
        self.assertEqual("status", calls[0]["authority"]["phase"])
        self.assertEqual(prepared, calls[0]["authority"]["snapshot"])

    def test_public_diagnostic_entry_uses_its_own_closed_factory_and_rejects_factory_drift(self):
        job, snapshot, config, transport = object(), {"prepared": "86"}, object(), {"transport": "pin"}
        driver = types.SimpleNamespace(_saved=lambda _: (job, snapshot), _transport=lambda: (config, transport))
        def capture(*_args, **kwargs):
            kwargs["guard"]()
            return ({"state": "unknown", "receiptPin": {"sha256": "a" * 64}}, Path("/inert"))
        common = [mock.patch.object(privileged.credentials, "_read_credential", return_value=b"PRIVATE\n"),
                  mock.patch.object(privileged.adapter, "McpTmuxDriver", return_value=driver),
                  mock.patch.object(privileged.ssh_transport, "connection_host", return_value=types.SimpleNamespace(password=None)),
                  mock.patch.object(privileged.ssh_transport, "build_ssh_argv", return_value=["fixed"]),
                  mock.patch.object(privileged, "_sources", return_value={"fixed": {"sha256": "a" * 64}}),
                  mock.patch.object(privileged.adapter, "_capture", side_effect=capture)]
        with common[0], common[1], common[2], common[3], common[4], common[5], self.assertRaises(ValueError):
            privileged.observe_diagnostic(Path(self.tempdir()))
        original = privileged.diagnostic_program
        values = [original(), original() + "\n# changed"]
        with mock.patch.object(privileged, "diagnostic_program", side_effect=values), \
             mock.patch.object(privileged.credentials, "_read_credential", return_value=b"PRIVATE\n"), \
             mock.patch.object(privileged.adapter, "McpTmuxDriver", return_value=driver), \
             mock.patch.object(privileged.ssh_transport, "connection_host", return_value=types.SimpleNamespace(password=None)), \
             mock.patch.object(privileged.ssh_transport, "build_ssh_argv", return_value=["fixed"]), \
             mock.patch.object(privileged, "_sources", return_value={"fixed": {"sha256": "a" * 64}}), \
             mock.patch.object(privileged.adapter, "_capture", side_effect=capture), self.assertRaises(ValueError):
            privileged.observe_diagnostic(Path(self.tempdir()))

    def tempdir(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return tmp.name


if __name__ == "__main__":
    unittest.main()
