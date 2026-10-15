"""A stage-only publisher never submits a profile on the wrong SSH hop."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock
import uuid

from agent_tools import ssh_source_file_stage_direct as subject


FIXTURE = Path(__file__).parent / "fixtures/source_stage_route_depth"


def preserved_source():
    path = FIXTURE / "before.source"
    metadata = json.loads((FIXTURE / "provenance.json").read_bytes())
    if hashlib.sha256(path.read_bytes()).hexdigest() != metadata["sourceSha256"]:
        raise AssertionError("Unfixed route-depth source changed")
    name = "agent_tools._stage_route_depth_before_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_loader(name, loader=None, origin=str(path))
    module = importlib.util.module_from_spec(spec)
    module.__file__ = str(path)
    sys.modules[name] = module
    try:
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    finally:
        sys.modules.pop(name, None)
    return module


@unittest.skipUnless(os.name == "posix", "owned POSIX source and inert child fixture")
class StageRouteDepthTests(unittest.TestCase):
    retained_evidence = None

    def exercise(self, implementation, depth, alias="fresh-target"):
        import pwd
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            (root / ".runtime").mkdir(mode=0o700)
            (root / ".rag_index").mkdir(mode=0o700)
            key = root / "public-fixture-key"
            known = root / "public-fixture-known-hosts"
            for path in (key, known):
                path.write_bytes(b"PUBLIC_INERT_BYTES\n")
                path.chmod(0o600)
            user = pwd.getpwuid(os.getuid()).pw_name

            def host(transport="direct", gateway=None):
                value = {"host": "192.0.2.1", "port": 22, "user": user,
                         "identityFile": str(key), "knownHostsFile": str(known),
                         "transport": transport}
                if gateway is not None:
                    value.update(gateway=gateway, remoteHostAlias="explicit-peer",
                                 remoteConfigFile="/srv/owned/explicit-peer.conf",
                                 password="PUBLIC_INERT_PASSPHRASE")
                return value

            hosts = {"fresh-relay": host()}
            if depth == 1:
                hosts[alias] = host()
            elif depth == 2:
                hosts[alias] = host("nested", "fresh-relay")
            elif depth == 3:
                hosts["fresh-middle"] = host("nested", "fresh-relay")
                hosts[alias] = host("nested", "fresh-middle")
            elif depth != 0:
                raise AssertionError(depth)
            config = root / ".vm-hosts.local.json"
            config.write_text(json.dumps({"schemaVersion": 1, "hosts": hosts}))
            config.chmod(0o600)
            caller = root / ".runtime/complete-caller.py"
            caller.write_bytes(b"raise RuntimeError('caller must never execute')\n")
            caller.chmod(0o600)
            correlation = uuid.uuid4().hex
            marker = root / "inert-transport-accepted.json"
            boundary = root / "inert-transport.py"
            boundary.write_text(
                "import json,sys\nfrom pathlib import Path\n"
                "Path(sys.argv[1]).write_text(json.dumps({'accepted':True,'endpoint':sys.argv[-2]}))\n"
                "sys.stdin.buffer.read()\nprint('{}',flush=True)\n"
            )
            # Only the OS/network boundary is replaced. Real configuration,
            # route/source custody, framing, journal and child collection run.
            error = result = None
            with mock.patch.object(
                implementation.direct, "outer_prefix",
                return_value=([sys.executable, str(boundary), str(marker)], "explicit-outer-peer"),
            ):
                try:
                    result = implementation.publish(
                        root, alias, str(caller),
                        hashlib.sha256(caller.read_bytes()).hexdigest(), correlation,
                    )
                except (ValueError, KeyError) as caught:
                    error = str(caught)
            journal = root / ".rag_index/ssh-source-file-stage"
            if self.retained_evidence is not None:
                shutil.copytree(root, Path(self.retained_evidence) / correlation)
            return {"error": error, "result": result,
                    "journalCreated": journal.exists(), "transportSubmitted": marker.exists(),
                    "transport": json.loads(marker.read_bytes()) if marker.exists() else None}

    def assert_pre_effect_refusal(self, value, reason=None):
        self.assertIsNotNone(value["error"], value)
        if reason is not None:
            self.assertEqual(reason, value["error"], value)
        self.assertFalse(value["journalCreated"], value)
        self.assertFalse(value["transportSubmitted"], value)

    def test_three_hop_refuses_before_any_journal_or_transport(self):
        self.assert_pre_effect_refusal(self.exercise(subject, 3), "source_stage_route")

    def test_missing_and_one_hop_refuse_before_any_journal_or_transport(self):
        for depth in (0, 1):
            with self.subTest(depth=depth):
                self.assert_pre_effect_refusal(self.exercise(subject, depth))

    def test_arbitrary_explicit_two_hop_aliases_reach_only_the_owned_inert_boundary(self):
        for alias in ("rebuilt-lab", "independent-peer-2"):
            with self.subTest(alias=alias):
                value = self.exercise(subject, 2, alias)
                self.assertIsNone(value["error"], value)
                self.assertTrue(value["journalCreated"], value)
                self.assertTrue(value["transportSubmitted"], value)
                self.assertEqual("explicit-outer-peer", value["transport"]["endpoint"])
                # The boundary intentionally supplies no successful receipt.
                self.assertEqual("unknown", value["result"]["state"])
                self.assertEqual("source_stage_gateway_receipt", value["result"]["reason"])

    def test_preserved_unfixed_source_really_submits_the_wrong_hop(self):
        value = self.exercise(preserved_source(), 3)
        self.assertIsNone(value["error"], value)
        self.assertTrue(value["journalCreated"], value)
        self.assertTrue(value["transportSubmitted"], value)
        self.assertEqual("explicit-outer-peer", value["transport"]["endpoint"])
        self.assertEqual("unknown", value["result"]["state"])
        with self.assertRaises(AssertionError):
            self.assert_pre_effect_refusal(value)


if __name__ == "__main__":
    unittest.main()
