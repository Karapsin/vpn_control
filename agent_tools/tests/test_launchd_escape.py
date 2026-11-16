"""Opted-in local checks leave the background-priority tmux tree on macOS; nothing else does.

Whole-before RED/GREEN against the preserved unfixed sources in fixtures/launchd_escape:
the bf8d2da2 relay (`launchctl submit`) and its `_run` selection. Portable tests drive the
real relays against a fake `launchctl`; the macOS tests use the real launchd.
"""
from __future__ import annotations

import ast
import functools
import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import resource
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
import uuid

from agent_tools import managed_agent_check as owned

ROOT = Path(owned.__file__).resolve().parents[1]
RELAY = ROOT / "agent_tools" / "launchd_escape.py"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "launchd_escape"
CMD = [sys.executable, "scripts/test_visual_regression.py"]
PRIVATE = [sys.executable, str(ROOT / "agent_tools/agent_test_runner.py"),
           "--plan-file", str(ROOT / ".rag_index/agent-test-runs" / "0a1b2c3d-0000-4000-8000-00000000abcd.plan.json"),
           "--report-dir", str(ROOT / ".rag_index/agent-test-runs" / "0a1b2c3d-0000-4000-8000-00000000abcd")]


def preserved(name: str) -> Path:
    path = FIXTURE / name
    row = json.loads((FIXTURE / "provenance.json").read_text())["files"][name]
    if hashlib.sha256(path.read_bytes()).hexdigest() != row["sha256"]:
        raise ValueError(f"preserved source changed: {name}")
    return path


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path, loader=importlib.machinery.SourceFileLoader(name, str(path)))
    module = sys.modules[name] = importlib.util.module_from_spec(spec)  # dataclasses resolve their module
    spec.loader.exec_module(module)
    return module


def wrap(command=CMD, **kw):
    kw.setdefault("environ", {})
    kw.setdefault("which", lambda name: "/bin/" + name)
    kw.setdefault("root", ROOT)
    return owned.background_escape(command, **kw)


def literal(node):
    """Evaluate a literal argv/command table from mcp_server source; sys.executable stays symbolic."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Attribute) and ast.unparse(node) == "sys.executable":
        return sys.executable
    if isinstance(node, (ast.List, ast.Tuple)):
        return [literal(item) for item in node.elts]
    if isinstance(node, ast.Dict):
        return {literal(key): literal(value) for key, value in zip(node.keys, node.values)}
    if isinstance(node, ast.JoinedStr):
        return "<formatted>"
    return "<dynamic>"


SERVER = ast.parse((ROOT / "agent_tools/mcp_server.py").read_bytes())


def server_assignment(name):
    for node in SERVER.body:
        targets = [node.target] if isinstance(node, ast.AnnAssign) else getattr(node, "targets", [])
        if any(getattr(target, "id", None) == name for target in targets):
            return literal(node.value)
    raise KeyError(name)


# Native, guest, SSH, VM, release and remote actions, the visual review CLI and the SSH keeper child.
NEVER_ESCAPED = [
    [sys.executable, "scripts/visual_review.py", "capture", "--sha", "0" * 40],
    [sys.executable, "scripts/visual_review.py", "record"],
    # ssh_channel_keeper_entry.child_argv shape (_run timeout 1845).
    [sys.executable, "-I", "-B", "-c", "<bootstrap>", "<payload>", str(ROOT), uuid.uuid4().hex, "a" * 64, "b" * 64],
    ["ssh", "-o", "BatchMode=yes", "vm-host", "true"],
    ["./agent_tools/mcp_tool.sh", "ssh-workflow", "--action", "connection-channel-keep"],
    ["./agent_tools/mcp_tool.sh", "vm-workflow", "--action", "scenario-start"],
    [sys.executable, "agent_tools/windows_scenario_host_job.py", "submit"],
    [sys.executable, "agent_tools/native_scenario_bundle.py"],
    ["tart", "run", "macos-guest"],
    ["virsh", "start", "win11"],
    ["./scripts/package_windows_desktop_vm.sh"],
    ["./scripts/package_linux_desktop.sh"],
    ["./scripts/check_release_hygiene.sh"],
    ["./gradlew", ":app:assembleRelease"],
    ["./gradlew", "--continue", ":desktopApp:test"],
    ["git", "push", "origin", "dev"],
    ["gh", "workflow", "run", "release-publish.yml", "--ref", "main"],
    ["gh", "workflow", "run", "vpn-integration.yml", "--ref", "main", "-f", "profile=all"],
    [sys.executable, "-m", "unittest", "agent_tools.tests.test_ssh_tmux_session"],
    [sys.executable, "scripts/test_visual_regression.py", "--extra"],
    ["/other/python", "scripts/test_visual_regression.py"],
    [*PRIVATE[:3], "/tmp/x.plan.json", *PRIVATE[4:]],
]


class SelectionTests(unittest.TestCase):
    def test_opted_in_checks_get_the_relay_with_their_bound(self):
        for command in (CMD, [sys.executable, "scripts/check_ui_theme.py"], ["./scripts/check_localization.py"],
                        ["./scripts/status_catalog_tool.py", "check"], PRIVATE):
            self.assertEqual([sys.executable, str(RELAY), "relay", "--bound", "3000", "--", *command],
                             wrap(command, platform="darwin", bound=3000))
        self.assertEqual(["py", str(RELAY), "relay", "--", *PRIVATE], wrap(PRIVATE, platform="darwin", python="py"))
        self.assertEqual(["py", str(RELAY), "relay", "--bound", "2", "--", *PRIVATE],
                         wrap(PRIVATE, platform="darwin", python="py", bound=1.5))

    def test_noop_elsewhere_and_when_disabled(self):
        for platform in ("linux", "win32"):
            self.assertEqual(wrap(platform=platform), CMD)
        self.assertEqual(wrap(platform="darwin", environ={owned.BACKGROUND_ESCAPE_DISABLE: "0"}), CMD)
        self.assertEqual(wrap(platform="darwin", environ={owned.BACKGROUND_ESCAPE_MARKER: "1"}), CMD)
        self.assertEqual(wrap(platform="darwin", which=lambda name: None), CMD)
        self.assertEqual(wrap(platform="darwin", relay=RELAY.with_name("missing.py")), CMD)

    def test_native_guest_ssh_vm_release_and_remote_commands_are_never_escaped(self):
        for command in NEVER_ESCAPED:
            for bound in (None, 120, 1800, 1845, 3000):
                self.assertEqual(command, wrap(command, platform="darwin", bound=bound), command)

    def test_every_literal_mcp_run_command_and_unlisted_check_runs_directly(self):
        calls = [literal(node.args[0]) for node in ast.walk(SERVER)
                 if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_run"
                 and node.args and isinstance(node.args[0], ast.List)]
        self.assertGreater(len(calls), 30)
        checks = [*server_assignment("PREPUSH_COMMANDS"),
                  *(command for commands in server_assignment("FOCUSED_COMMANDS").values() for command in commands)]
        escaped = {tuple(command) for command in calls + checks if wrap(command, platform="darwin", bound=3000) != command}
        allowlisted = ({(sys.executable, script) for script in owned.BACKGROUND_ESCAPE_PYTHON_SCRIPTS}
                       | set(owned.BACKGROUND_ESCAPE_COMMANDS))
        self.assertEqual({(sys.executable, "scripts/check_ui_theme.py"), (sys.executable, "scripts/test_visual_regression.py"),
                          ("./scripts/check_localization.py",), ("./scripts/status_catalog_tool.py", "check")},
                         allowlisted)
        # Only the named allowlist escapes, and every entry is a local check-plan command.
        self.assertEqual(allowlisted, escaped)
        self.assertLessEqual(allowlisted, set(map(tuple, checks)))

    def test_run_selects_by_argv_never_by_timeout(self):
        run = next(node for node in SERVER.body if isinstance(node, ast.FunctionDef) and node.name == "_run")
        calls = [node for node in ast.walk(run) if isinstance(node, ast.Call)
                 and ast.unparse(node.func) == "managed_agent_check.background_escape"]
        self.assertEqual(1, len(calls))
        statement = next(node for node in run.body if calls[0] in ast.walk(node))
        self.assertIsInstance(statement, ast.Assign, "unconditional: background_escape alone decides")
        self.assertEqual({"root", "bound"}, {keyword.arg for keyword in calls[0].keywords})


class RunSelectionRedGreenTests(unittest.TestCase):
    """The exact `_run` of bf8d2da2 escaped every command bounded at 30 minutes or more."""

    def drive(self, server: Path, check: Path, command, timeout):
        source = ast.parse(server.read_bytes()).body
        chosen = [node for node in source if isinstance(node, ast.FunctionDef)
                  and node.name in {"_run", "_display", "_bounded", "_failure_log_excerpt"}
                  or isinstance(node, ast.Assign) and len(node.targets) == 1
                  and getattr(node.targets[0], "id", None) in {"MAX_OUTPUT_CHARS", "HEAVY_COMMAND_SECONDS"}]
        launched = []

        class Popen:
            def __init__(self, argv, **_):
                launched.append(list(argv))
                self.returncode = 0

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def communicate(self, timeout=None):
                return "", ""

        module = load(check, f"managed_agent_check_{check.stem.replace('.', '_')}")
        shim = types.SimpleNamespace(background_escape=functools.partial(
            module.background_escape, platform="darwin", environ={}, which=lambda name: "/bin/launchctl",
            relay=RELAY))
        namespace = {
            "os": os, "re": __import__("re"), "shlex": __import__("shlex"), "Any": object, "REPO_ROOT": ROOT,
            "subprocess": types.SimpleNamespace(Popen=Popen, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE,
                                                CompletedProcess=subprocess.CompletedProcess,
                                                TimeoutExpired=subprocess.TimeoutExpired),
            "local_build_environment": types.SimpleNamespace(apply=lambda root, env: env,
                                                             LocalBuildEnvironmentError=ValueError),
            "check_output_retention": types.SimpleNamespace(RetentionError=ValueError),
            "managed_agent_check": shim,
        }
        exec(compile(ast.Module(chosen, []), str(server), "exec"), namespace)
        namespace["_run"](command, timeout=timeout)
        return launched[0]

    def test_unfixed_run_escaped_visual_review_keeper_and_gradle_RED_current_runs_them_directly_GREEN(self):
        before = (preserved("mcp_server.bf8d2da2.before.source"), preserved("managed_agent_check.bf8d2da2.before.source"))
        current = (ROOT / "agent_tools/mcp_server.py", ROOT / "agent_tools/managed_agent_check.py")
        cases = [(NEVER_ESCAPED[0], 30 * 60), (NEVER_ESCAPED[2], 1845),
                 (["./gradlew", "--continue", ":desktopApp:test"], 50 * 60)]
        for command, timeout in cases:
            self.assertEqual([sys.executable, str(RELAY), "relay", "--", *command],
                             self.drive(*before, command, timeout))  # RED
            self.assertEqual(command, self.drive(*current, command, timeout))  # GREEN
        self.assertEqual([sys.executable, str(RELAY), "relay", "--bound", "3000", "--", *CMD],
                         self.drive(*current, CMD, 50 * 60))


@unittest.skipUnless(os.name == "posix", "the job script is bash")
class RestartedJobTests(unittest.TestCase):
    """A second start of job.sh never reruns the command; a lost first run reports 137."""

    def starts(self, module, lose=False) -> tuple[int, str, str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "job"
            directory.mkdir()
            command = ["/bin/sh", "-c", f"echo run >> {root / 'runs'}; echo out; echo err >&2"]
            script = directory / "job.sh"
            script.write_text(module._script(command, temporary, {}, directory, "vpncontrol.test.absent", os.getpid()))
            first = subprocess.run(["/bin/bash", str(script)], timeout=60)
            self.assertEqual(0, first.returncode)
            self.assertEqual("0", (directory / "rc").read_text().strip())
            if lose:
                (directory / "rc").unlink()  # the first run was killed before it wrote its status
            # A launchd restart, before the relay has read the outputs.
            subprocess.run(["/bin/bash", str(script)], timeout=60)
            rc = (directory / "rc").read_text().strip() if (directory / "rc").exists() else ""
            return (len((root / "runs").read_text().splitlines()), (directory / "out").read_text(),
                    (directory / "err").read_text(), rc)

    def test_restart_reruns_and_truncates_RED_current_runs_once_GREEN(self):
        runs, out, err, _ = self.starts(load(preserved("launchd_escape.before.source"), "launchd_escape_before"))
        self.assertEqual(2, runs)  # RED: the command ran again
        self.assertEqual((2, "out\n", "err\n"), (runs, out, err))  # its second start replaced the first outputs
        current = load(RELAY, "launchd_escape_current")
        self.assertEqual((1, "out\n", "err\n", "0"), self.starts(current))

    def test_restart_after_a_lost_status_left_none_RED_current_writes_137_GREEN(self):
        before = load(preserved("launchd_escape.bf8d2da2.before.source"), "launchd_escape_bf8d2da2")
        self.assertEqual((1, "out\n", "err\n", ""), self.starts(before, lose=True))  # RED
        self.assertEqual((1, "out\n", "err\n", "137"), self.starts(load(RELAY, "launchd_escape_current"), lose=True))


FAKE_LAUNCHCTL = r'''#!{python}
import os, plistlib, signal, subprocess, sys
from pathlib import Path
STATE = Path({state!r})
MODE = (STATE / "mode").read_text().strip()
# What launchd itself would hand a job: never the caller's environment.
LAUNCHD = {{"PATH": "/usr/bin:/bin", "SSH_AUTH_SOCK": "/launchd/leak", "XPC_SERVICE_NAME": "leak", "XPC_FLAGS": "0x0"}}
args = sys.argv[1:]
with open(STATE / "log", "a") as log:
    log.write(" ".join(args) + "\n")
removed = set((STATE / "removed").read_text().split()) if (STATE / "removed").exists() else set()
def pid():
    try:
        return int((STATE / "pid").read_text())
    except (OSError, ValueError):
        return None
def alive():
    value = pid()
    if value is None:
        return False
    try:
        os.kill(value, 0)
    except ProcessLookupError:
        return False
    return subprocess.run(["ps", "-o", "stat=", "-p", str(value)], capture_output=True, text=True).stdout.strip()[:1] not in ("Z", "")
def start(argv):
    if MODE == "fail":
        sys.exit(5)
    if MODE == "fail-after-start":
        subprocess.run(argv, env=LAUNCHD, stdin=subprocess.DEVNULL)
        sys.exit(5)
    child = subprocess.Popen(argv, env=LAUNCHD, start_new_session=True, stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (STATE / "pid").write_text(str(child.pid))
    sys.exit(0)
def remove(label):
    with open(STATE / "removed", "a") as handle:
        handle.write(label + "\n")
    if alive() and label == (STATE / "label").read_text().strip():
        os.kill(pid(), signal.SIGTERM)
if args[0] == "bootstrap":
    data = Path(args[2]).read_bytes()
    (STATE / "plist").write_bytes(data)
    job = plistlib.loads(data)
    (STATE / "label").write_text(job["Label"])
    start(job["ProgramArguments"])
elif args[0] == "submit":
    (STATE / "label").write_text(args[2])
    start(args[4:])
elif args[0] == "list" and len(args) == 1:
    sys.stdout.write((STATE / "list").read_text() if (STATE / "list").exists() else "")
elif args[0] == "list":
    sys.exit(113 if args[1] in removed else 0)
elif args[0] == "print":
    if args[1].rsplit("/", 1)[-1] in removed:
        sys.exit(113)
    print("state = " + ("running" if alive() else "not running"))
elif args[0] == "kill" and alive():
    os.kill(pid(), getattr(signal, args[1]))
elif args[0] in ("bootout", "remove"):
    remove(args[1].rsplit("/", 1)[-1])
'''


@unittest.skipUnless(os.name == "posix", "the job script is bash")
class FakeLaunchdTests(unittest.TestCase):
    """The real relays against a fake `launchctl` that runs the job the way launchd would."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.state = self.root / "state"
        self.state.mkdir()
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "launchctl"
        fake.write_text(FAKE_LAUNCHCTL.format(python=sys.executable, state=str(self.state)))
        fake.chmod(0o755)
        self.env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(self.root), "LAUNCHD_ESCAPE_PROBE": "a b'c",
                    "TMPDIR": str(self.root)}
        self.runs = self.root / "runs"

    def mode(self, value):
        (self.state / "mode").write_text(value)

    def relay(self, source: Path, *argv):
        return [sys.executable, str(source), "relay", "--", *argv]

    def log(self):
        return (self.state / "log").read_text() if (self.state / "log").exists() else ""

    def run_relay(self, source, *argv, timeout=60):
        return subprocess.run(self.relay(source, *argv), cwd=self.root, env=self.env, capture_output=True,
                              text=True, timeout=timeout)

    def counted(self, code=3):
        return ["/bin/sh", "-c", f"echo run >> {self.runs}; echo out; exit {code}"]

    def test_failed_bootstrap_after_the_job_started_ran_twice_RED_runs_once_GREEN(self):
        self.mode("fail-after-start")
        before = self.run_relay(preserved("launchd_escape.bf8d2da2.before.source"), *self.counted())
        self.assertEqual((3, 2), (before.returncode, len(self.runs.read_text().splitlines())))  # RED: job and direct
        self.runs.unlink()
        done = self.run_relay(RELAY, *self.counted())
        self.assertEqual((3, "out\n", 1), (done.returncode, done.stdout, len(self.runs.read_text().splitlines())))

    def test_bootstrap_failing_before_the_job_started_runs_directly_once(self):
        self.mode("fail")
        done = self.run_relay(RELAY, *self.counted(4))
        self.assertEqual((4, "out\n", 1), (done.returncode, done.stdout, len(self.runs.read_text().splitlines())))
        self.assertIn("bootout gui/", self.log())

    def test_lost_exit_status_hung_RED_returns_137_quickly_GREEN(self):
        self.mode("background")
        lose = ["/bin/sh", "-c", "echo out; kill -KILL $PPID"]
        process = subprocess.Popen(self.relay(preserved("launchd_escape.bf8d2da2.before.source"), *lose),
                                   cwd=self.root, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaises(subprocess.TimeoutExpired):  # RED: waits for the outer timeout
                process.wait(timeout=12)
        finally:
            process.terminate()
            process.wait(timeout=60)
        for name in ("pid", "removed", "log"):
            (self.state / name).unlink(missing_ok=True)
        began = time.monotonic()
        done = self.run_relay(RELAY, *lose)
        self.assertEqual((137, "out\n"), (done.returncode, done.stdout))
        self.assertIn("ended without an exit status", done.stderr)
        self.assertLess(time.monotonic() - began, 10)

    def test_sigkilled_relay_left_its_job_RED_job_stops_and_removes_itself_GREEN(self):
        self.mode("background")
        for source, expect_removal in ((preserved("launchd_escape.bf8d2da2.before.source"), False), (RELAY, True)):
            for name in ("pid", "removed", "log", "label"):
                (self.state / name).unlink(missing_ok=True)
            marker = self.root / f"term-{expect_removal}"
            command = ["/bin/sh", "-c", f"trap 'echo term > {marker}; exit 0' TERM; while :; do sleep 0.2; done"]
            process = subprocess.Popen(self.relay(source, *command), cwd=self.root, env=self.env,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + 20
            while not (self.state / "label").exists() and time.monotonic() < deadline:
                time.sleep(0.1)
            time.sleep(1)
            process.kill()
            process.wait(timeout=10)
            label = (self.state / "label").read_text().strip()
            def removals():
                return [line for line in self.log().splitlines()
                        if line.split()[:1] in (["bootout"], ["remove"]) and label in line]
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and not marker.exists():
                time.sleep(0.2)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not removals():
                time.sleep(0.2)
            self.assertTrue(marker.exists(), "the job's watchdog stops the command")
            self.assertEqual(expect_removal, bool(removals()), (source, self.log()))

    def test_job_gets_exactly_the_caller_environment_and_soft_limits(self):
        for source, leaked in ((preserved("launchd_escape.bf8d2da2.before.source"), True), (RELAY, False)):
            self.mode("background")
            dump = self.root / f"env-{leaked}"
            done = self.run_relay(source, "/bin/sh", "-c", f'/usr/bin/env > {dump}; pwd -P')
            self.assertEqual((0, f"{self.root}\n"), (done.returncode, done.stdout))
            env = dict(line.split("=", 1) for line in dump.read_text().splitlines() if "=" in line)
            self.assertEqual(leaked, "SSH_AUTH_SOCK" in env or "XPC_SERVICE_NAME" in env)  # RED / GREEN
            self.assertEqual("a b'c", env["LAUNCHD_ESCAPE_PROBE"])
        job = plistlib.loads((self.state / "plist").read_bytes())
        soft = {key: min(resource.getrlimit(getattr(resource, name))[0], 0x7FFFFFFFFFFFFFFF)
                for key, name in (("NumberOfFiles", "RLIMIT_NOFILE"), ("NumberOfProcesses", "RLIMIT_NPROC"),
                                  ("Core", "RLIMIT_CORE"), ("Stack", "RLIMIT_STACK"))}
        self.assertEqual((soft, False, True, ["/usr/bin/env", "-i"]),
                         (job["SoftResourceLimits"], job["KeepAlive"], job["RunAtLoad"], job["ProgramArguments"][:2]))
        self.assertGreater(job["ExitTimeOut"], 0)
        self.assertTrue(set(env) - {"PWD", "SHLVL", "_", "OLDPWD"}
                        <= set(self.env) | {owned.BACKGROUND_ESCAPE_MARKER, "LC_CTYPE", "__CF_USER_TEXT_ENCODING"},
                        sorted(env))

    def test_startup_sweep_removes_labels_past_their_bound_or_relay(self):
        self.mode("background")
        now, live, dead = int(time.time()), os.getpid(), 2 ** 22 + 12345
        labels = {"expired": f"vpncontrol.check.{now - 5}.{live}.0123abcd",
                  "orphaned": f"vpncontrol.check.{now + 3600}.{dead}.0123abcd",
                  "current": f"vpncontrol.check.{now + 3600}.{live}.0123abcd",
                  "legacy-orphaned": f"vpncontrol.check.{dead}.89abcdef",
                  "legacy-live": f"vpncontrol.check.{live}.89abcdef",
                  "unrelated": "com.example.agent"}
        (self.state / "list").write_text("".join(f"-\t0\t{label}\n" for label in labels.values()))
        for source, swept in ((preserved("launchd_escape.bf8d2da2.before.source"), False), (RELAY, True)):
            (self.state / "log").unlink(missing_ok=True)
            self.assertEqual(0, self.run_relay(source, "/bin/sh", "-c", "exit 0").returncode)
            expected = {f"bootout gui/{os.getuid()}/{labels['expired']}", f"bootout gui/{os.getuid()}/{labels['orphaned']}",
                        f"remove {labels['legacy-orphaned']}"}
            deadline = time.monotonic() + 10
            while swept and not expected <= set(self.log().splitlines()) and time.monotonic() < deadline:
                time.sleep(0.1)
            lines = set(self.log().splitlines())
            self.assertEqual(swept, expected <= lines)  # RED: the unfixed relay never swept
            for kept in ("current", "legacy-live", "unrelated"):
                self.assertFalse(any(labels[kept] in line for line in lines), kept)


def labels() -> list[str]:
    listed = subprocess.run(["launchctl", "list"], capture_output=True, text=True).stdout
    return [line.split()[-1] for line in listed.splitlines() if line.split() and "vpncontrol.check." in line.split()[-1]]


@unittest.skipUnless(sys.platform == "darwin", "launchd relay is macOS only")
class RealLaunchdTests(unittest.TestCase):
    def run_relay(self, *argv, source=RELAY, **kw):
        bound = ["--bound", "120"] if source == RELAY else []  # the unfixed relay had no bound
        return subprocess.run([sys.executable, str(source), "relay", *bound, "--", *argv],
                              capture_output=True, text=True, timeout=120, **kw)

    def mine(self, pid):
        return [label for label in labels() if f".{pid}." in label]

    def test_status_streams_cwd_exact_environment_and_limits(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith(("SSH_", "XPC_"))}
        env["LAUNCHD_ESCAPE_PROBE"] = "a b'c\nline"
        with tempfile.TemporaryDirectory() as temporary:
            dump = Path(temporary) / "env"
            script = (f'printf "%s\\n" "$LAUNCHD_ESCAPE_PROBE"; pwd -P; ulimit -n; ulimit -u; ulimit -c; ulimit -s; '
                      f'/usr/bin/env -0 > {dump}; echo e >&2; exit 7')
            done = self.run_relay("/bin/sh", "-c", script, env=env, cwd="/usr")
            seen = dict(item.split("=", 1) for item in dump.read_text().split("\0") if "=" in item)
        lines = done.stdout.splitlines()
        self.assertEqual((7, ["a b'c", "line", "/usr"], "e\n"), (done.returncode, lines[:3], done.stderr))
        limits = [resource.getrlimit(name)[0] for name in (resource.RLIMIT_NOFILE, resource.RLIMIT_NPROC)]
        core, stack = (resource.getrlimit(name)[0] for name in (resource.RLIMIT_CORE, resource.RLIMIT_STACK))
        expected = [*map(str, limits), "unlimited" if core == resource.RLIM_INFINITY else str(core // 512),
                    "unlimited" if stack == resource.RLIM_INFINITY else str(stack // 1024)]
        self.assertEqual(expected, lines[3:7])
        self.assertFalse({key for key in seen if key.startswith(("SSH_", "XPC_"))})
        self.assertEqual({key: value for key, value in env.items() if key not in ("PWD", "SHLVL", "_", "OLDPWD")},
                         {key: seen[key] for key in env if key in seen and key not in ("PWD", "SHLVL", "_", "OLDPWD")})

    def test_unfixed_relay_gave_launchd_limits_and_environment_RED(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith(("SSH_", "XPC_"))}
        done = self.run_relay("/bin/sh", "-c", "ulimit -n; /usr/bin/env", env=env,
                              source=preserved("launchd_escape.bf8d2da2.before.source"))
        lines = done.stdout.splitlines()
        if resource.getrlimit(resource.RLIMIT_NOFILE)[0] != 256:
            self.assertEqual("256", lines[0])  # launchd's default soft nofile
        self.assertTrue(any(line.startswith(("SSH_AUTH_SOCK=", "XPC_SERVICE_NAME=")) for line in lines[1:]))

    def test_job_is_outside_background_priority_inheritance(self):
        done = self.run_relay("/bin/sh", "-c", "ps -o ppid= -p $$; ps -o pri= -p $$")
        parent, priority = done.stdout.split()
        self.assertNotEqual(parent, str(os.getpid()))
        self.assertGreaterEqual(int(priority), 20)

    def test_long_command_keeps_its_complete_output_and_runs_once(self):
        # Longer than launchd's 10 s throttle: a KeepAlive job would have been restarted when it ended.
        with tempfile.TemporaryDirectory() as temporary:
            runs = Path(temporary) / "runs"
            done = self.run_relay("/bin/sh", "-c", f"echo run >> {runs}; sleep 11; echo out-end; echo err-end >&2")
            time.sleep(12)
            self.assertEqual((0, "out-end\n", "err-end\n", 1),
                             (done.returncode, done.stdout, done.stderr, len(runs.read_text().splitlines())))

    def test_lost_exit_status_returns_137_quickly_and_leaves_no_label(self):
        began = time.monotonic()
        done = self.run_relay("/bin/sh", "-c", "echo out; kill -KILL $PPID")
        self.assertEqual((137, "out\n"), (done.returncode, done.stdout))
        self.assertLess(time.monotonic() - began, 10)

    def test_no_label_or_process_remains_after_exit_sigterm_or_sigkill(self):
        for how in ("exit", signal.SIGTERM, signal.SIGKILL):
            tag = f"{os.getpid() % 1000}{uuid.uuid4().int % 100000}"
            argv = ["/bin/sh", "-c", f"echo begin; exec /bin/sleep {tag}" if how != "exit" else "echo begin"]
            process = subprocess.Popen([sys.executable, str(RELAY), "relay", "--bound", "120", "--", *argv],
                                       stdout=subprocess.PIPE)
            self.assertEqual(b"begin\n", process.stdout.readline())
            if how != "exit":
                self.assertEqual(1, len(self.mine(process.pid)))
                process.send_signal(how)
            process.wait(timeout=60)
            process.stdout.close()
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and (self.mine(process.pid) or (
                    how != "exit" and subprocess.run(["pgrep", "-f", f"sleep {tag}$"]).returncode == 0)):
                time.sleep(0.5)
            self.assertEqual([], self.mine(process.pid), how)
            if how != "exit":
                self.assertNotEqual(0, subprocess.run(["pgrep", "-f", f"sleep {tag}$"]).returncode, how)


if __name__ == "__main__":
    unittest.main()
