"""Complete MCP entry source bootstrap ignores owned stale interpreter caches.

All execution belongs to separate temporary physical packages and isolated child
interpreters. The portable compiler-profile control changes one nested valid line
table only. Actual cross-patch compiler validation remains separate native proof.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import types
import unittest


TOOLS = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).with_name("fixtures") / "mcp_source_bootstrap"
BEFORE_SHA = "9ba5cb86a41efcc0b60e26dbe85b6fbbf5217de2c0c72716a01e29ae18df0725"


def before_entry():
    raw = (FIXTURE / "mcp_server.before.source").read_bytes()
    provenance = json.loads((FIXTURE / "provenance.json").read_bytes())
    if (len(raw) != 662451 or hashlib.sha256(raw).hexdigest() != BEFORE_SHA
            or provenance["sourceSha256"] != BEFORE_SHA or provenance["sourceBytes"] != len(raw)
            or provenance["sourcePath"] != "agent_tools/mcp_server.py"
            or provenance["sourceCommit"] != "c68058eb64f8452207bf2091bd2950e5a06231da"):
        raise AssertionError("Complete original MCP entry source changed")
    return raw


def metadata_profile(code, raw, filename):
    """Preserve all executable fields; replace only valid nested line metadata."""
    name = "_bootstrap_source"
    node = next(item for item in ast.parse(raw).body if isinstance(item, ast.FunctionDef) and item.name == name)
    lines = raw.splitlines(keepends=True)
    lines.insert(node.body[0].lineno - 1, b"\n")
    alternate = compile(b"".join(lines), filename, "exec", dont_inherit=True)
    original_nested = next(item for item in code.co_consts if isinstance(item, types.CodeType) and item.co_name == name)
    alternate_nested = next(item for item in alternate.co_consts if isinstance(item, types.CodeType) and item.co_name == name)
    if original_nested.co_code != alternate_nested.co_code or original_nested.co_linetable == alternate_nested.co_linetable:
        raise AssertionError("Compiler-profile fixture did not isolate line metadata")
    variant = original_nested.replace(co_linetable=alternate_nested.co_linetable)
    for field in ("co_code", "co_consts", "co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals",
                  "co_stacksize", "co_flags", "co_names", "co_varnames", "co_freevars", "co_cellvars"):
        if getattr(variant, field) != getattr(original_nested, field):
            raise AssertionError("Compiler-profile fixture changed executable field " + field)
    return code.replace(co_consts=tuple(variant if item is original_nested else item for item in code.co_consts))


def source_names(entry):
    captured = {
        call.args[0].value + ".py"
        for call in ast.walk(ast.parse(entry))
        if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "_captured_core"
        and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)
    }
    return captured | {
        "affected_agent_tests.py", "affected_agent_test_dependencies.json", "agent_test_runner.py",
        "native_review_source_closure.py", "source_module_loader.py", "windows_source_custody.py",
        "tool_action_policy.py", "tool_action_policy.json",
    }


STUB = b'''import builtins
from pathlib import Path
from . import inert_bootstrap_policy as policy
class SshConfigError(ValueError):pass
def inventory(root):
 builtins._bootstrap_inventory_calls.append(policy.VALUE)
 if builtins._bootstrap_drift:
  path=Path(policy.__file__);path.write_bytes(path.read_bytes()+b'\\n# changed during request\\n')
 return ('inert-source-backed-host',)
'''


CHILD = r'''import builtins,hashlib,importlib,json,subprocess,sys,types
from pathlib import Path
root=Path(sys.argv[1]);scenario=sys.argv[2];sys.path.insert(0,str(root))
builtins._bootstrap_inventory_calls=[];builtins._bootstrap_drift=scenario=='closing-drift'
record={'scenario':scenario,'inventoryCalls':[],'error':None,'nativeEffects':0}
poison_calls=[];effect_calls=[]
def forbidden_effect(*args,**kwargs):
 effect_calls.append('subprocess');raise AssertionError('unexpected_native_process_submission')
def poisoned(*args,**kwargs):
 poison_calls.append('adopted');raise AssertionError('canonical_cached_loader_adopted')
if scenario=='poison':
 poison=types.ModuleType('agent_tools.source_module_loader');poison.__file__=str(root/'agent_tools/source_module_loader.py');poison.adapter=poisoned;poison.request_scope=poisoned
 sys.modules[poison.__name__]=poison
 backend=types.ModuleType('agent_tools.windows_source_custody');backend.__file__=str(root/'agent_tools/windows_source_custody.py');backend.WindowsHeld=poisoned
 sys.modules[backend.__name__]=backend
try:
 public=importlib.import_module('agent_tools.mcp_server')
 for name in ('Popen','run','check_call','check_output','call'):setattr(subprocess,name,forbidden_effect)
 boot=getattr(public,'_SOURCE_MODULE_LOADER',None)
 record['privateLoaderName']=getattr(boot,'__name__',None)
 record['privateLoaderPath']=getattr(boot,'__file__',None)
 record['privateLoaderPackage']=getattr(boot,'__package__',None)
 record['loaderPhysicalSha256']=hashlib.sha256((root/'agent_tools/source_module_loader.py').read_bytes()).hexdigest()
 record['canonicalCacheIsPrivateLoader']=sys.modules.get('agent_tools.source_module_loader') is boot and boot is not None
 record['backendCaptured']=bool(boot is not None and getattr(sys.modules.get(boot.__package__),'windows_source_custody',None) is not None)
 if scenario=='loader-drift':
  path=root/'agent_tools/source_module_loader.py';path.write_bytes(path.read_bytes()+b'\n# changed after entry boot\n')
 before={name for name in sys.modules if name.startswith('_vpn_source_')}
 record['result']=public._ssh_workflow_impl(action='inventory')
 record['requestNamespacesCleaned']=before=={name for name in sys.modules if name.startswith('_vpn_source_')}
 if scenario=='twice':
  record['secondResult']=public._ssh_workflow_impl(action='inventory')
  record['requestNamespacesCleaned']=record['requestNamespacesCleaned'] and before=={name for name in sys.modules if name.startswith('_vpn_source_')}
  record['sameBootLoader']=getattr(public,'_SOURCE_MODULE_LOADER',None) is boot
except BaseException as error:
 record['error']={'type':type(error).__name__,'message':str(error)}
record['inventoryCalls']=builtins._bootstrap_inventory_calls
record['poisonCalls']=poison_calls
record['nativeEffects']=len(effect_calls)
record['loadedOwnedSources']=all(str(root) in str(getattr(module,'__file__','')) for name,module in sys.modules.items() if name in ('agent_tools.mcp_server','agent_tools.source_module_loader'))
print(json.dumps(record,sort_keys=True))
'''


class McpSourceBootstrapTests(unittest.TestCase):
    entry_source = TOOLS / "mcp_server.py"
    retained_evidence = None

    def exercise(self, *, original=False, stale_pyc=True, scenario="inventory"):
        raw = before_entry() if original else Path(self.entry_source).read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            directory = root / "agent_tools"
            directory.mkdir()
            (directory / "__init__.py").write_bytes(b"")
            for name in source_names(raw):
                shutil.copyfile(TOOLS / name, directory / name)
            (directory / "mcp_server.py").write_bytes(raw)
            (directory / "ssh_transport.py").write_bytes(STUB)
            (directory / "inert_bootstrap_policy.py").write_bytes(b"VALUE='FRESH_SOURCE'\n")
            loader = directory / "source_module_loader.py"
            loader_raw = loader.read_bytes()
            optimization = sys.flags.optimize
            tag = sys.implementation.cache_tag + (".opt-" + str(optimization) if optimization else "")
            cache = loader.parent / "__pycache__" / (loader.stem + "." + tag + ".pyc")
            source_stat = loader.stat()
            payload = None
            if stale_pyc:
                code = metadata_profile(compile(loader_raw, str(loader), "exec", dont_inherit=True), loader_raw, str(loader))
                header = importlib.util.MAGIC_NUMBER + struct.pack("<III", 0, int(loader.stat().st_mtime) & 0xffffffff, len(loader_raw) & 0xffffffff)
                payload = header + marshal.dumps(code)
                cache.parent.mkdir(exist_ok=True)
                cache.write_bytes(payload)
            child = root / "owned_bootstrap_child.py"
            child.write_text(CHILD)
            optimization_flags = ["-O"] if optimization == 1 else ["-OO"] if optimization == 2 else []
            result = subprocess.run([sys.executable, "-I", "-B", *optimization_flags, str(child), str(root), scenario],
                                    cwd=root, capture_output=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stderr.decode("utf-8", "replace"))
            self.assertEqual(b"", result.stderr)
            record = json.loads(result.stdout)
            record["entrySha256"] = hashlib.sha256(raw).hexdigest()
            record["loaderSourceSha256"] = hashlib.sha256(loader_raw).hexdigest()
            record["sourceBytesUnchanged"] = loader.read_bytes() == loader_raw
            record["pycBytesUnchanged"] = payload is None or cache.read_bytes() == payload
            record["sameTagTimestampValid"] = (payload is not None and payload[:4] == importlib.util.MAGIC_NUMBER
                and payload[4:8] == b"\0" * 4
                and payload[8:12] == struct.pack("<I", int(source_stat.st_mtime) & 0xffffffff)
                and payload[12:16] == struct.pack("<I", len(loader_raw) & 0xffffffff))
            record["cacheTag"] = sys.implementation.cache_tag
            if self.retained_evidence is not None:
                target = Path(self.retained_evidence) / (("before" if original else "current") + "-" + scenario)
                shutil.copytree(root, target)
                (target / "result.json").write_text(json.dumps(record, indent=2) + "\n")
            return record

    def assert_fresh_inventory(self, record, calls=1):
        self.assertIsNone(record["error"], record)
        self.assertEqual({"ok": True, "tool": "ssh_workflow", "hosts": ["inert-source-backed-host"]}, record["result"])
        self.assertEqual(["FRESH_SOURCE"] * calls, record["inventoryCalls"])
        self.assertEqual(0, record["nativeEffects"])
        self.assertEqual([], record["poisonCalls"])
        self.assertTrue(record["loadedOwnedSources"], record)
        self.assertTrue(record["requestNamespacesCleaned"], record)
        self.assertTrue(record["sourceBytesUnchanged"], record)
        self.assertTrue(record["pycBytesUnchanged"], record)
        self.assertTrue(record["privateLoaderName"].startswith("_vpn_native_core_"), record)
        self.assertFalse(record["canonicalCacheIsPrivateLoader"], record)

    def test_registered_inventory_uses_fresh_held_loader_bytes(self):
        record = self.exercise()
        self.assertTrue(record["sameTagTimestampValid"], record)
        self.assert_fresh_inventory(record)

    def test_complete_original_entry_reproduces_canonical_loader_cache_failure(self):
        record = self.exercise(original=True)
        with self.assertRaises(AssertionError):
            self.assert_fresh_inventory(record)
        self.assertEqual({"type": "ValueError", "message": "Loaded adapter loader differs from its source"}, record["error"])
        self.assertEqual([], record["inventoryCalls"])
        self.assertTrue(record["sourceBytesUnchanged"])
        self.assertTrue(record["pycBytesUnchanged"])

    def test_canonical_loader_and_backend_cache_poison_are_not_adopted(self):
        self.assert_fresh_inventory(self.exercise(scenario="poison"))

    def test_boot_loader_change_refuses_without_hot_reload(self):
        record = self.exercise(scenario="loader-drift")
        self.assertIsNone(record["error"], record)
        self.assertEqual("unknown", record["result"].get("state"), record)
        self.assertEqual("native_source_closure_unavailable", record["result"].get("reason"), record)
        self.assertIs(False, record["result"].get("nativeActionAllowed"), record)
        self.assertIs(False, record["result"].get("replayAllowed"), record)
        self.assertEqual([], record["inventoryCalls"])
        self.assertEqual(0, record["nativeEffects"])

    def test_request_source_closing_refuses_and_cleans_namespace(self):
        record = self.exercise(scenario="closing-drift")
        self.assertIsNone(record["error"], record)
        self.assertEqual("unknown", record["result"].get("state"), record)
        self.assertEqual("native_source_closure_unavailable", record["result"].get("reason"), record)
        self.assertIs(False, record["result"].get("nativeActionAllowed"), record)
        self.assertIs(False, record["result"].get("replayAllowed"), record)
        self.assertEqual(["FRESH_SOURCE"], record["inventoryCalls"])
        self.assertTrue(record["requestNamespacesCleaned"], record)
        self.assertEqual(0, record["nativeEffects"])

    def test_each_request_closes_its_namespace_and_reuses_captured_boot_loader(self):
        record = self.exercise(scenario="twice")
        self.assert_fresh_inventory(record, calls=2)
        self.assertEqual(record["result"], record["secondResult"])
        self.assertTrue(record["sameBootLoader"])

    def test_portable_nt_bootstrap_keeps_backend_and_loader_in_same_private_package(self):
        raw = Path(self.entry_source).read_bytes()
        node = next(item for item in ast.parse(raw).body if isinstance(item, ast.FunctionDef) and item.name == "_captured_native_sources")
        calls = []
        modules = {}
        def capture(name, *, package):
            calls.append((name, package))
            value = types.SimpleNamespace(__name__=package + "." + name, __package__=package)
            modules[value.__name__] = value
            return value
        namespace = {"os": types.SimpleNamespace(name="nt"), "types": types,
                     "sys": types.SimpleNamespace(modules=modules), "_MCP_BOOT_TIME_NS": 123456789,
                     "_captured_core": capture}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(self.entry_source), "exec"), namespace)
        loader = namespace["_captured_native_sources"]()
        self.assertEqual([("windows_source_custody", "_vpn_native_core_123456789"),
                          ("source_module_loader", "_vpn_native_core_123456789")], calls)
        package = modules["_vpn_native_core_123456789"]
        self.assertEqual([], package.__path__)
        self.assertIs(package.source_module_loader, loader)
        self.assertEqual(loader.__package__, package.windows_source_custody.__package__)

    @unittest.skipUnless(os.name == "nt", "Actual Windows source-custody backend requires Windows")
    def test_native_windows_entry_captures_actual_backend_source(self):
        record = self.exercise(scenario="poison")
        self.assert_fresh_inventory(record)
        self.assertTrue(record["backendCaptured"], record)


if __name__ == "__main__":
    unittest.main()
