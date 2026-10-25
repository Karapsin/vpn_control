"""Local guest harness bound tolerates a slow child launch on a directory-bound host.

On an Active Directory bound Mac the wrong guestUser subtest's absent-account
lookup took 10.03 s before it was negatively cached, just past run_guest's old
10 s child bound. Here only the interpreter that the unchanged run_guest launches
is replaced, by an owned wrapper that sleeps past that bound and then execs the
real interpreter with the same arguments and stdin. The guest then refuses a
wrong UID of the existing current account, so no directory lookup is involved.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock
from uuid import uuid4

from agent_tools.tests import test_macos_fixture_stage as current


BEFORE = Path(__file__).parent / "fixtures/macos_fixture_stage_child_bound/test_macos_fixture_stage.py.before.source"
PROVENANCE = Path(__file__).parent / "fixtures/macos_fixture_stage_child_bound/provenance.json"
BEFORE_SHA256 = "2a9c6cf0e86e5d5b6274c75a6418d3b743711db417c7c1570f0162daa2c18870"
ORIGINAL = "test_wrong_actual_account_uid_home_and_boot_refuse_before_fixture_mutation"
OLD_BOUND_SECONDS = 10
# Fixed stand-in for the measured 10.03 s lookup, with a margin past the old bound.
DELAY_SECONDS = OLD_BOUND_SECONDS + 1


def slow_interpreter(directory, real):
    """Record each launch, sleep, then become the real interpreter in the same process."""
    code = ("import os,sys,time\n"
            "with open(sys.argv[1],'a') as record:record.write(str(os.getpid())+'\\n')\n"
            "time.sleep(float(sys.argv[2]));os.execv(sys.argv[3],sys.argv[3:])\n")
    wrapper = directory / "python"
    words = (real, "-I", "-c", code, str(directory / "launches"), str(DELAY_SECONDS), real)
    wrapper.write_text("#!/bin/sh\nexec " + " ".join(map(shlex.quote, words)) + ' "$@"\n')
    wrapper.chmod(0o700)
    return wrapper


@unittest.skipUnless(os.name == "posix", "owned /bin/sh interpreter wrapper")
class GuestChildBoundTests(unittest.TestCase):
    def before(self):
        provenance = json.loads(PROVENANCE.read_bytes())
        raw = BEFORE.read_bytes()
        self.assertEqual((BEFORE_SHA256, len(raw), False),
                         (provenance["sourceSha256"], provenance["sourceBytes"], provenance["nativeFailureClaimed"]))
        self.assertEqual(BEFORE_SHA256, hashlib.sha256(raw).hexdigest())
        self.assertEqual(current.__name__ + ".LocalMacosGuestProgramTests." + ORIGINAL, provenance["originalFailureTestId"])
        module = types.ModuleType("_macos_fixture_stage_child_bound_before_" + uuid4().hex)
        module.__file__ = current.__file__
        exec(compile(raw, str(BEFORE), "exec", dont_inherit=True), module.__dict__)
        return module

    def refused_inputs(self):
        # The original guestUid subtest: the existing current account resolves
        # locally, so the guest's refusal never waits for a directory service.
        import pwd
        account = pwd.getpwuid(os.getuid())
        home = Path(account.pw_dir).resolve()
        value = current.request()
        value["correlationId"] = str(uuid4())
        value["environmentContext"].update(guestUser=account.pw_name, guestUid=os.getuid() + 1, guestHome=str(home))
        value["guestRoot"] = str(home / (".mcp-fixture-stage-test-" + uuid4().hex))
        return value

    def test_unfixed_bound_times_out_on_slow_child_and_fixed_bound_returns_guest_refusal(self):
        unfixed = self.before().LocalMacosGuestProgramTests(ORIGINAL)
        fixed = current.LocalMacosGuestProgramTests(ORIGINAL)
        value = self.refused_inputs()
        with tempfile.TemporaryDirectory(prefix="vct-child-bound-") as temporary:
            wrapper = slow_interpreter(Path(temporary), sys.executable)
            # Both actual run_guest methods launch the wrapper at once: one delay, not two.
            with mock.patch.object(sys, "executable", str(wrapper)), ThreadPoolExecutor(1) as pool:
                old = pool.submit(unfixed.run_guest, value)
                started = time.monotonic()
                result = fixed.run_guest(value)
                elapsed = time.monotonic() - started
                with self.assertRaises(subprocess.TimeoutExpired) as timed_out:
                    old.result()
            self.assertEqual(2, len((Path(temporary) / "launches").read_text().splitlines()))
        self.assertEqual((str(wrapper), OLD_BOUND_SECONDS), (timed_out.exception.cmd[0], timed_out.exception.timeout))
        self.assertGreaterEqual(elapsed, DELAY_SECONDS)
        self.assertNotEqual(0, result.returncode)
        self.assertIn(b"stage_guest_identity_changed", result.stderr)
        self.assertFalse(os.path.lexists(value["guestRoot"]))


if __name__ == "__main__":
    unittest.main()
