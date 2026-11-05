"""Actual local harness beforeimages: missing bindings and cached repo imports."""
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

import agent_tools
from agent_tools import android_local_custody as custody

FIXTURES = Path(__file__).parent / "fixtures/android_local_custody"
QUALIFIER_SHA = "c4912f4c4282d8e9a61fdf5acca7233c89448b720227fa32fa47c1a859a4b672"
ADAPTER_SHA = "1831b5105fd23f45cd047c1cd46af6e427129b7b9089c3f1a9749b211468f955"


def before(name, digest):
    provenance = json.loads((FIXTURES / "provenance.json").read_text())
    raw = (FIXTURES / name).read_bytes()
    if (hashlib.sha256(raw).hexdigest() != digest
            or provenance["files"][name]["sha256"] != digest
            or provenance["files"][name]["bytes"] != len(raw)
            or provenance["files"][name]["wholeFile"] is not True):
        raise AssertionError("authentic whole beforeimage changed")
    return raw


class LocalAdapterBindingsTests(unittest.TestCase):
    def prepared(self):
        raw = before("qualifier.before.source", QUALIFIER_SHA)
        if os.environ.get("VPN_CONTROL_TEST_LEGACY_LOCAL_BINDINGS") == "1":
            return raw
        return custody.local_adapter_source(raw, QUALIFIER_SHA)

    def namespace(self, raw):
        # Execute the actual renderer's local prelude. Native transport and
        # private files are environmental seams, not replacement guard code.
        tree = ast.parse(raw)
        selected = [node for node in tree.body
                    if ((isinstance(node, ast.FunctionDef) and node.name == "_pin")
                        or (isinstance(node, ast.Import) and
                            [item.name for item in node.names] == ["pathlib"]))]
        namespace = {"os": os}
        exec(compile(ast.Module(body=selected, type_ignores=[]), "actual-local-prelude", "exec"), namespace)
        return tree, namespace

    @unittest.skipUnless(os.name == "posix", "native local FD custody requires POSIX")
    def test_actual_qualifier_local_fd_guard_has_a_bound_pin(self):
        tree, namespace = self.namespace(self.prepared())
        block = next(node for node in tree.body if isinstance(node, ast.Try)
                     and node.body and isinstance(node.body[0], ast.Assign)
                     and any(isinstance(target, ast.Name) and target.id == "pin"
                             for target in node.body[0].targets))
        # This is the real failed entrypoint, unchanged, including its actual
        # named/held inode and owner checks. Only the owned lock path/FD varies.
        body = ast.Module(body=block.body[:2], type_ignores=[])
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "lock"
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_RDONLY, 0o600)
            try:
                namespace.update(fd=fd, lock=lock)
                exec(compile(body, "actual-local-fd-entrypoint", "exec"), namespace)
                self.assertEqual(namespace["pin"][:2], [os.fstat(fd).st_dev, os.fstat(fd).st_ino])
            finally:
                os.close(fd)

    def test_actual_qualifier_path_entrypoint_has_local_pathlib(self):
        tree, namespace = self.namespace(self.prepared())
        statement = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                         and any(isinstance(target, ast.Name) and target.id == "lease"
                                 for target in node.targets))
        namespace["local"] = types.SimpleNamespace(QUALIFIED_LEASE="/owned/control/lease")
        exec(compile(ast.Module(body=[statement], type_ignores=[]), "actual-local-path-entrypoint", "exec"), namespace)
        self.assertEqual(namespace["lease"], Path("/owned/control/lease"))

    def test_another_missing_global_refuses_before_native_execution(self):
        raw = before("qualifier.before.source", QUALIFIER_SHA).replace(
            b"lease=pathlib.Path(local.QUALIFIED_LEASE)",
            b"lease=unbound_namespace.Path(local.QUALIFIED_LEASE)")
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), QUALIFIER_SHA)
        with self.assertRaisesRegex(ValueError, "local_custody_unbound_globals:unbound_namespace"):
            custody.local_adapter_source(raw, hashlib.sha256(raw).hexdigest())

    def test_future_import_stays_in_its_valid_preamble(self):
        raw = b'"""owned adapter"""\nfrom __future__ import annotations\nvalue: Missing = 3\n'
        prepared = custody.local_adapter_source(raw, hashlib.sha256(raw).hexdigest())
        namespace = {}
        exec(compile(prepared, "owned-future-adapter", "exec"), namespace)
        self.assertEqual(namespace["value"], 3)


class CapturedLocalImportTests(unittest.TestCase):
    def snapshots(self, adapter, continuity=b"identity='captured'\n"):
        root = Path(__file__).parents[1]
        raw = {"continuity": continuity,
               "retirement": (root / "android_installer_failed_check_retirement.py").read_bytes(),
               "bundle": (root / "android_installer_component_bundle.py").read_bytes(),
               "adapter": adapter}
        return {role: {"source": value, "sha256": hashlib.sha256(value).hexdigest()}
                for role, value in raw.items()}

    def actual_import_entrypoint(self):
        raw = before("adapter.before.source", ADAPTER_SHA)
        tree = ast.parse(raw)
        nodes = [node for node in tree.body if isinstance(node, ast.ImportFrom)
                 and node.module == "agent_tools"]
        self.assertEqual(len(nodes), 3)
        return ("\n".join(ast.get_source_segment(raw.decode(), node) for node in nodes)
                + "\nobserved=continuity.identity\n").encode()

    def test_actual_adapter_import_uses_verified_bytes_over_cached_module(self):
        adapter = self.actual_import_entrypoint()
        stale = types.ModuleType("agent_tools.android_component_continuity")
        stale.identity = "stale-cached-module"
        with mock.patch.dict(sys.modules, {stale.__name__: stale}), \
                mock.patch.object(agent_tools, "android_component_continuity", stale, create=True):
            if os.environ.get("VPN_CONTROL_TEST_LEGACY_LOCAL_IMPORT") == "1":
                namespace = {}
                exec(compile(adapter, "actual-unfixed-import-entrypoint", "exec"), namespace)
                observed = namespace["observed"]
            else:
                module, proof = custody.load_local_adapter(self.snapshots(adapter), Path.cwd() / "owned-adapter.py")
                observed = module.observed
                self.assertFalse(proof["namedRepositoryImportsUsed"])
                self.assertFalse(proof["bytecodeCacheUsed"])
                self.assertIs(agent_tools.android_component_continuity, stale)
            self.assertEqual(observed, "captured")

    def test_changed_helper_bytes_refuse_before_the_adapter_runs(self):
        snapshots = self.snapshots(b"raise AssertionError('adapter ran')\n")
        snapshots["continuity"]["source"] = b"identity='exchanged'\n"
        with self.assertRaisesRegex(ValueError, "local_custody_source_changed"):
            custody.load_local_adapter(snapshots, Path.cwd() / "owned-adapter.py")

    def test_unexpected_repository_import_never_falls_back_to_live_modules(self):
        snapshots = self.snapshots(b"from agent_tools import ssh_transport\n")
        with self.assertRaisesRegex(ValueError, "local_custody_repository_import_refused"):
            custody.load_local_adapter(snapshots, Path.cwd() / "owned-adapter.py")

    def test_generated_primitive_resolves_only_the_captured_validator(self):
        root = Path(__file__).parents[1]
        continuity = (root / "android_component_continuity.py").read_bytes()
        adapter = (b"from agent_tools import android_component_continuity as continuity\n"
                   b"from agent_tools import android_installer_failed_check_retirement as retirement\n")
        module, _ = custody.load_local_adapter(self.snapshots(adapter, continuity), Path.cwd() / "owned-adapter.py")
        primitive = module.retirement.release_component_fenced
        captured_import = primitive.__globals__["__builtins__"]["__import__"]
        selected = captured_import("agent_tools.android_component_continuity", fromlist=("validate_relocated_lease_receipt",))
        self.assertIs(selected, module.continuity)
        self.assertIs(selected.validate_relocated_lease_receipt.__globals__, selected.__dict__)


if __name__ == "__main__":
    unittest.main()
