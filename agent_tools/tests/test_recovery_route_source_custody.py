"""Physical cached-recovery counterfactuals through complete public servers.

The fixture adapters only write an inert local marker. No credential, device,
SSH connection, VM, reservation or native product operation is used.
"""
from __future__ import annotations

from contextlib import contextmanager
import ast
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import py_compile
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock
import uuid


SOURCE_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).with_name("fixtures") / "cached_recovery_source"
CORRELATION = "00000000-0000-0000-0000-000000000001"
ADAPTERS = {
    "android_proxy_recovery": ("AndroidProxyRecoveryError", (
        "recover_owned_stale_proxy", "observe_recovery")),
    "windows_credential_recovery_ssh": ("WindowsCredentialRecoveryError", (
        "start", "status", "credential_status")),
    "windows_credential_probe_ssh": ("WindowsCredentialProbeSshError", (
        "start", "status")),
}
ROUTES = (
    ("android_proxy_recovery", "android-proxy-recover", {
        "host": "owned", "device": "api29", "expectedPort": 12345,
        "correlationId": CORRELATION}),
    ("android_proxy_recovery", "android-proxy-recovery-status", {
        "host": "owned", "device": "api29", "identity": {}}),
    ("windows_credential_recovery_ssh", "windows-credential-recover-start", {
        "host": "owned", "environment": "owned-vm", "correlationId": CORRELATION}),
    ("windows_credential_recovery_ssh", "windows-credential-recover-status", {
        "host": "owned", "correlationId": CORRELATION}),
    ("windows_credential_recovery_ssh", "credential-status", {
        "host": "owned", "correlationId": CORRELATION, "handle": "owned-handle"}),
    ("windows_credential_probe_ssh", "windows-credential-probe-start", {
        "host": "owned", "environment": "owned-vm", "correlationId": CORRELATION}),
    ("windows_credential_probe_ssh", "windows-credential-probe-status", {
        "host": "owned", "correlationId": CORRELATION}),
)


def _source(*, historical=False):
    # The override runs the identical assertion against the complete preserved
    # unfixed owner. Routine checks also exercise exact preserved import lines.
    path = Path(os.environ.get("VPN_RECOVERY_ROUTE_SOURCE", SOURCE_ROOT / "mcp_server.py"))
    raw = path.read_bytes()
    if historical:
        before_raw = (FIXTURE / "before.json").read_bytes()
        provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
        if hashlib.sha256(before_raw).hexdigest() != provenance["fragmentSha256"]:
            raise ValueError("preserved_recovery_imports_changed")
        text = raw.decode()
        for name, original in json.loads(before_raw).items():
            variable = original.strip().split(" = ", 1)[0]
            fixed = f'            {variable} = _agent_module("{name}")\n'
            if text.count(fixed) != 1:
                raise ValueError("current_recovery_import_not_unique")
            text = text.replace(fixed, original)
        raw = text.encode()
    return raw


def _request(request):
    # The exact preserved unfixed owner predates explicit new-start
    # environments and refuses that field; omit only it there, so the
    # override still reaches the causal cached-policy effect.
    provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
    if hashlib.sha256(_source()).hexdigest() == provenance["sourceSha256"]:
        return {key: value for key, value in request.items() if key != "environment"}
    return dict(request)


@contextmanager
def _physical_server(*, historical=False):
    with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
        root = Path(temporary).resolve()
        root.chmod(0o700)
        directory = root / "agent_tools"
        directory.mkdir(mode=0o700)
        raw = _source(historical=historical)
        captured = {
            node.args[0].value + ".py"
            for node in ast.walk(ast.parse(raw))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == "_captured_core" and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        }
        needed = captured | {
            "affected_agent_tests.py", "affected_agent_test_dependencies.json",
            "agent_test_runner.py", "native_review_source_closure.py",
            "tool_action_policy.py", "tool_action_policy.json",
        }
        for name in needed:
            shutil.copyfile(SOURCE_ROOT / name, directory / name)
        (directory / "mcp_server.py").write_bytes(raw)
        # Every route keeps its real mandatory classification. Like these
        # adapters, readiness admission is inert here: no SSH connection.
        (directory / "readiness_vm_dispatch.py").write_text(
            "from contextlib import nullcontext\n"
            "def admitted_dispatch(*args,**kwargs):return nullcontext()\n")
        helper = directory / "inert_recovery_policy.py"
        helper.write_text("VALUE='OLDER'\n")
        py_compile.compile(str(helper), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
        for name, (error, methods) in ADAPTERS.items():
            body = (
                "from pathlib import Path\n"
                "from . import inert_recovery_policy as policy\n"
                f"class {error}(ValueError):pass\n"
                "def observe(*args,**kwargs):\n"
                " root=Path(__file__).parent.parent\n"
                " (root/'effect').write_text(policy.VALUE)\n"
                " if (root/'drift').exists():\n"
                "  path=Path(policy.__file__)\n"
                "  path.write_bytes(path.read_bytes()+b'\\n# changed during call\\n')\n"
                " return {'state':'submitted','available':True,'observedPolicy':policy.VALUE}\n"
                # Inert explicit-environment check that new starts run first.
                "def _admit_environment(*args,**kwargs):return None\n"
            )
            body += "\n".join(f"{method}=observe" for method in methods) + "\n"
            (directory / (name + ".py")).write_text(body)
        package_name = "_physical_recovery_" + uuid.uuid4().hex
        package = types.ModuleType(package_name)
        package.__path__ = [str(directory)]
        sys.modules[package_name] = package
        public = None
        try:
            spec = importlib.util.spec_from_file_location(
                package_name + ".mcp_server", directory / "mcp_server.py")
            public = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = public
            spec.loader.exec_module(public)
            for name in ADAPTERS:
                importlib.import_module(package_name + "." + name)
            # Enrichment is orthogonal to captured dispatch; keep the physical
            # source implementation and its opening/closing guards unchanged.
            with mock.patch.object(public, "_native_response",
                                   side_effect=lambda tool, action, result, request: result):
                yield public, root, helper
        finally:
            for name in list(sys.modules):
                if (name == package_name or name.startswith(package_name + ".")
                        or public is not None and (name.startswith(
                            "_vpn_core_" + str(public._MCP_BOOT_TIME_NS) + "_") or
                            name == "_vpn_native_core_" + str(public._MCP_BOOT_TIME_NS) or
                            name.startswith("_vpn_native_core_" + str(public._MCP_BOOT_TIME_NS) + "."))):
                    sys.modules.pop(name, None)


def _replace_policy(helper):
    previous = helper.stat()
    helper.write_text("VALUE='NEWER'\n")
    os.utime(helper, ns=(previous.st_atime_ns, previous.st_mtime_ns))


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"),
                     "Physical POSIX source-custody fixture")
class RecoveryRouteSourceTests(unittest.TestCase):
    def test_every_public_recovery_route_ignores_cached_policy_and_valid_old_pyc(self):
        with _physical_server() as (public, root, helper):
            _replace_policy(helper)
            for module, action, request in ROUTES:
                with self.subTest(module=module, action=action):
                    result = public.vm_workflow(action, _request(request))
                    self.assertEqual("NEWER", result.get("observedPolicy"), result)
                    self.assertEqual("NEWER", (root / "effect").read_text())

    def test_preserved_import_statements_reproduce_old_policy_effect(self):
        with _physical_server(historical=True) as (public, root, helper):
            _replace_policy(helper)
            for module, action, request in ROUTES:
                with self.subTest(module=module, action=action):
                    result = public.vm_workflow(action, dict(request))
                    self.assertEqual("OLDER", result.get("observedPolicy"), result)
                    self.assertEqual("OLDER", (root / "effect").read_text())

    def test_each_recovery_adapter_closing_drift_stays_unknown_and_nonreplayable(self):
        for module in ADAPTERS:
            route = next(row for row in ROUTES if row[0] == module)
            with self.subTest(module=module), _physical_server() as (public, root, helper):
                (root / "drift").touch()
                result = public.vm_workflow(route[1], _request(route[2]))
                self.assertTrue((root / "effect").exists())
                self.assertEqual("unknown", result.get("state"), result)
                self.assertEqual("native_source_closure_unavailable", result.get("reason"))
                self.assertIs(False, result.get("replayAllowed"))
                self.assertIs(False, result.get("nativeActionAllowed"))


if __name__ == "__main__":
    unittest.main()
