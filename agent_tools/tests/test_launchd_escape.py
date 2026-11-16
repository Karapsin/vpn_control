"""Heavy checks leave the background-priority tmux tree on macOS and are untouched elsewhere."""
from __future__ import annotations

import os
from pathlib import Path
import signal
import subprocess
import sys
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

    def test_sigterm_stops_job(self):
        process = subprocess.Popen([sys.executable, str(RELAY), "relay", "--", "/bin/sleep", "97531"])
        time.sleep(3)
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(timeout=60), 143)
        time.sleep(1)
        self.assertNotEqual(subprocess.run(["pgrep", "-f", "sleep 97531"], capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
