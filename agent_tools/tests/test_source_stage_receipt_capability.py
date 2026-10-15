"""Unsupported source-receipt readers refuse before accessing local records."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid

from agent_tools import ssh_source_file_stage_direct as subject


def preserved_source():
    directory = Path(__file__).parent / "fixtures/source_stage_receipt_capability"
    path = directory / "before.source"
    metadata = json.loads((directory / "provenance.json").read_bytes())
    if hashlib.sha256(path.read_bytes()).hexdigest() != metadata["sourceSha256"]:
        raise AssertionError("Unfixed capability source changed")
    name = "agent_tools._stage_receipt_before_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_loader(name, loader=None, origin=str(path))
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    finally:
        sys.modules.pop(name, None)
    return module


class SourceReceiptCapabilityTests(unittest.TestCase):
    correlation = "8e" * 16

    def assert_unsupported(self, result):
        self.assertNotIn("escapedError", result, result)
        self.assertEqual("unknown", result["state"])
        self.assertEqual("unsupported_coordinator", result["reason"])
        self.assertEqual(self.correlation, result["correlationId"])
        for name in ("sourceExecuted", "nativeActionAllowed", "replayAllowed", "remoteReadiness"):
            self.assertFalse(result[name], name)

    def test_unsupported_reader_is_finite_before_any_filesystem_access(self):
        with mock.patch.object(subject.direct, "coordinator_capable", return_value=False), \
                mock.patch.object(subject.os, "open", side_effect=AssertionError("receipt filesystem read")) as opened:
            result = subject.retained_receipt("/nonexistent-public-root", self.correlation, host="fresh-target")
        self.assert_unsupported(result)
        opened.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "causal absent-POSIX-API replay uses an owned POSIX record")
    def test_absent_posix_apis_are_finite_in_an_isolated_os_namespace(self):
        for missing, value in self.missing_api_case(subject).items():
            with self.subTest(missing=missing):
                self.assert_unsupported(value)

    def missing_api_case(self, implementation):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            directory = root / ".rag_index/ssh-source-file-stage" / self.correlation
            directory.mkdir(parents=True, mode=0o700)
            intent = directory / "intent.json"
            intent.write_text("{}\n")
            intent.chmod(0o600)
            results = {}
            for missing in ("O_NOFOLLOW", "getuid"):
                namespace = types.SimpleNamespace(**{key: value for key, value in vars(os).items() if key != missing})
                with mock.patch.object(implementation, "os", namespace), \
                        mock.patch.object(implementation.direct, "os", namespace):
                    try:
                        value = implementation.retained_receipt(root, self.correlation, host="fresh-target")
                    except AttributeError as error:
                        value = {"escapedError": str(error)}
                results[missing] = value
            return results

    @unittest.skipUnless(os.name == "posix", "causal absent-POSIX-API replay uses an owned POSIX record")
    def test_preserved_source_leaks_both_missing_api_failures_and_fix_refuses(self):
        before = self.missing_api_case(preserved_source())
        for missing, value in before.items():
            self.assertIn(missing, value["escapedError"])
        after = self.missing_api_case(subject)
        for value in after.values():
            self.assert_unsupported(value)


if __name__ == "__main__":
    unittest.main()
