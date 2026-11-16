"""Heavy checks leave the background-priority tmux tree on macOS and are untouched elsewhere."""
from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

from agent_tools import managed_agent_check as owned

RELAY = Path(owned.__file__).resolve().with_name("launchd_escape.py")
CMD = ["/bin/echo", "x"]


def wrap(**kw):
    kw.setdefault("environ", {})
    kw.setdefault("which", lambda name: "/bin/" + name)
    return owned.background_escape(CMD, **kw)


class WrapTests(unittest.TestCase):
    def test_macos_prefixes_relay(self):
        self.assertEqual(wrap(platform="darwin", python="py"), ["py", str(RELAY), "relay", "--", *CMD])

    def test_noop_elsewhere_and_when_disabled(self):
        for platform in ("linux", "win32"):
            self.assertEqual(wrap(platform=platform), CMD)
        self.assertEqual(wrap(platform="darwin", environ={owned.BACKGROUND_ESCAPE_DISABLE: "0"}), CMD)
        self.assertEqual(wrap(platform="darwin", environ={owned.BACKGROUND_ESCAPE_MARKER: "1"}), CMD)
        self.assertEqual(wrap(platform="darwin", which=lambda name: None), CMD)
        self.assertEqual(wrap(platform="darwin", relay=RELAY.with_name("missing.py")), CMD)

    def test_input_not_mutated(self):
        original = list(CMD)
        wrap(platform="darwin")
        self.assertEqual(CMD, original)


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "launchd_escape"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path, loader=importlib.machinery.SourceFileLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def before_relay():
    raw = (FIXTURE / "launchd_escape.before.source").read_bytes()
    if hashlib.sha256(raw).hexdigest() != json.loads((FIXTURE / "provenance.json").read_text())["sha256"]:
        raise ValueError("preserved relay source changed")
    return load(FIXTURE / "launchd_escape.before.source", "launchd_escape_before")


@unittest.skipUnless(os.name == "posix", "the job script is bash")
class RestartedJobTests(unittest.TestCase):
    """`launchctl submit` restarts job.sh after every exit until the relay removes the label."""

    def starts(self, module) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "job"
            directory.mkdir()
            command = ["/bin/sh", "-c", f"echo run >> {root / 'runs'}; echo out; echo err >&2"]
            script = directory / "job.sh"
            script.write_text(module._script(command, temporary, {}, directory, "label", os.getpid()))
            first = subprocess.run(["/bin/bash", str(script)], timeout=60)
            self.assertEqual(0, first.returncode)
            self.assertEqual("0", (directory / "rc").read_text().strip())
            # launchd's restart, before the relay has read the outputs.
            subprocess.run(["/bin/bash", str(script)], timeout=60)
            return (len((root / "runs").read_text().splitlines()), (directory / "out").read_text(),
                    (directory / "err").read_text())

    def test_restart_reruns_and_truncates_RED_current_runs_once_GREEN(self):
        runs, out, err = self.starts(before_relay())
        self.assertEqual(2, runs)  # RED: the command ran again
        self.assertEqual((2, "out\n", "err\n"), (runs, out, err))  # its second start replaced the first outputs
        current = load(RELAY, "launchd_escape_current")
        self.assertEqual((1, "out\n", "err\n"), self.starts(current))


@unittest.skipUnless(sys.platform == "darwin", "launchd relay is macOS only")
class RelayTests(unittest.TestCase):
    def run_relay(self, *argv, **kw):
        return subprocess.run([sys.executable, str(RELAY), "relay", "--", *argv],
                              capture_output=True, text=True, timeout=60, **kw)

    def test_status_streams_cwd_and_env(self):
        env = dict(os.environ, LAUNCHD_ESCAPE_PROBE="a b'c")
        done = self.run_relay("/bin/sh", "-c", 'echo "$LAUNCHD_ESCAPE_PROBE"; pwd -P; echo e >&2; exit 7',
                              env=env, cwd="/usr")
        self.assertEqual((done.returncode, done.stdout.split("\n")[:2], done.stderr), (7, ["a b'c", "/usr"], "e\n"))

    def test_job_is_outside_background_priority_inheritance(self):
        done = self.run_relay("/bin/sh", "-c", "ps -o ppid= -p $$")
        self.assertNotEqual(done.stdout.strip(), str(os.getpid()))

    def test_long_command_keeps_its_complete_output_and_runs_once(self):
        # Longer than launchd's 10 s throttle, so launchd restarts job.sh as soon as it ends.
        with tempfile.TemporaryDirectory() as temporary:
            runs = Path(temporary) / "runs"
            done = self.run_relay("/bin/sh", "-c", f"echo run >> {runs}; sleep 11; echo out-end; echo err-end >&2")
            time.sleep(12)
            self.assertEqual((0, "out-end\n", "err-end\n", 1),
                             (done.returncode, done.stdout, done.stderr, len(runs.read_text().splitlines())))

    def test_sigterm_stops_job(self):
        process = subprocess.Popen([sys.executable, str(RELAY), "relay", "--", "/bin/sleep", "97531"])
        time.sleep(3)
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=60), 143)
        time.sleep(1)
        self.assertNotEqual(subprocess.run(["pgrep", "-f", "sleep 97531"], capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
