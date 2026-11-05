"""Untrusted prior-operation source must refuse before opening a credential.

The transport is the existing real Unix-socket fixture. The launch-absence
observer is the explicit controlled seam; canonical producer/source admission,
the historical source mismatch and credential file IO all remain real.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock
import uuid

from agent_tools import readiness_windows_login as login
from agent_tools import readiness_windows_login_continuation as continuation
from agent_tools.tests import test_readiness_windows_login as login_tests


FIXTURE = Path(__file__).parent / "fixtures/windows_login_history_before_secret"


@contextmanager
def before_module():
    raw = (FIXTURE / "before.source").read_bytes()
    if hashlib.sha256(raw).hexdigest() != json.loads((FIXTURE / "provenance.json").read_bytes())["sourceSha256"]:
        raise AssertionError("login admission-order beforeimage changed")
    name = "agent_tools._windows_login_history_before_" + uuid.uuid4().hex
    module = types.ModuleType(name)
    module.__package__ = "agent_tools"
    module.__file__ = str(FIXTURE / "before.source")
    sys.modules[name] = module
    try:
        exec(compile(raw, module.__file__, "exec"), vars(module))
        yield module
    finally:
        sys.modules.pop(name, None)


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "credential/source custody uses POSIX nofollow files")
class WindowsLoginHistoryBeforeSecretTests(unittest.TestCase):
    implementation = login

    def setUp(self):
        self.fixture = login_tests.ProtectedDispatchRetryTests("runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.backend = self.fixture.backend
        self.secret = self.fixture.private
        self.root = self.fixture.root
        operation = str(uuid.uuid4())
        directory = self.root / ".runtime/readiness-windows-login" / operation
        directory.parent.mkdir(mode=0o700, parents=True)
        directory.mkdir(mode=0o700)
        source = b"print('untrusted prior caller')\n"
        identity = {"operationId": operation, "binding": self.backend.binding,
                    "expectedSid": self.backend.expected_sid, "profile": {},
                    "expected": {"boot": self.fixture.facts["boot"]}}
        for name, value in (("credential.intent.json", json.dumps({"identity": identity,
                             "callerSha256": hashlib.sha256(source).hexdigest(), "replayAllowed": False}).encode()),
                            ("login-submit-original.py", source)):
            path = directory / name
            path.write_bytes(value)
            path.chmod(0o600)

    def invoke(self, *, missing_secret=False, status_only=False):
        secret_identity = (self.secret.stat().st_dev, self.secret.stat().st_ino)
        original_open = os.open
        opens = []

        def opened(*args, **kwargs):
            descriptor = original_open(*args, **kwargs)
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == secret_identity:
                opens.append(descriptor)
            return descriptor

        module = self.implementation
        with mock.patch.object(continuation, "login", module), mock.patch.object(
                continuation, "observe_launch_absence", return_value={"controlled": "readonly launch absence"}), mock.patch.object(os, "open", opened):
            if status_only:
                value = module.execute(self.backend, str(uuid.uuid4()), {}, {"boot": self.fixture.facts["boot"]},
                                       "", time.monotonic() + 30, status_only=True)
                return value, opens
            with self.assertRaisesRegex(ValueError, "windows_login_prior_source_untrusted"):
                module.execute(self.backend, str(uuid.uuid4()), {}, {"boot": self.fixture.facts["boot"]},
                               str(self.secret.with_name("missing.secret") if missing_secret else self.secret),
                               time.monotonic() + 30)
        return None, opens

    def test_untrusted_prior_source_refuses_before_real_secret_file_open(self):
        _, opens = self.invoke()
        self.assertEqual([], opens, "credential file was opened before prior-source admission")

    def test_missing_secret_does_not_hide_the_prior_source_refusal(self):
        _, opens = self.invoke(missing_secret=True)
        self.assertEqual([], opens)

    def test_original_status_without_submission_opens_no_secret(self):
        value, opens = self.invoke(status_only=True)
        self.assertEqual("original_submission_unknown", value["reason"])
        self.assertEqual([], opens)

    def test_whole_before_reproduces_the_same_positive_failure(self):
        case = type(self)("test_untrusted_prior_source_refuses_before_real_secret_file_open")
        result = unittest.TestResult()
        with before_module() as before:
            case.implementation = before
            case.run(result)
        self.assertEqual(1, result.testsRun)
        self.assertEqual([], result.errors)
        self.assertEqual(1, len(result.failures))
        self.assertIn("credential file was opened before prior-source admission", result.failures[0][1])


if __name__ == "__main__":
    unittest.main()
