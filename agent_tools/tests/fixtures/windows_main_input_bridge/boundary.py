"""Finite authentic test-source boundary; never a guest/input admission peer.

Only top-level filesystem roles in the preserved test helpers are relocated.
Every original function/class AST is unchanged. Complete before/current bodies
execute under their original causal oracle; latest V3 uses actual agent modules.
"""
from __future__ import annotations

import ast
import atexit
import builtins
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCE_ROLES = {
    "main": "agent_tools/windows_main_input_bridge.py",
    "observer": "agent_tools/windows_main_secure_observer.py",
    "backend": "agent_tools/windows_main_input_observer_backend.py",
    "pending": "agent_tools/windows_pending_installer_join.py",
}
SELECTORS = (
    "VPN_MAIN_INPUT_BRIDGE_BEFORE", "VPN_MAIN_INPUT_PARTIAL_BEFORE",
    "VPN_MAIN_INPUT_PRIVATE_UNKNOWN_BEFORE", "VPN_MAIN_INPUT_FRAME_BEFORE",
    "VPN_MAIN_INPUT_OBSERVER_BEFORE", "VPN_MAIN_INPUT_CAPTURE_BEFORE",
    "VPN_MAIN_INPUT_REVIEW_BEFORE", "VPN_MAIN_INPUT_OBSERVER_REVIEW_BEFORE",
    "VPN_MAIN_INPUT_GUID_BEFORE", "VPN_MAIN_INPUT_GUID_OBSERVER_BEFORE",
)
# name, historical helper stage, actual unchanged method, before role/path,
# original fixture selector, precise original diagnostic, requires PowerShell.
CASES = (
    ("source-helper-import", "v1", "test_source_helper_boundary_uses_explicit_fixed_planner", "main", "v1/initial-main.before.source", "VPN_MAIN_INPUT_BRIDGE_BEFORE", "ModuleNotFoundError", False),
    ("canonical-envelope-budget", "v1", "test_current_actual_canonical_producer_keeps_both_limits", "observer", "v1/canonical-observer.before.source", "VPN_MAIN_INPUT_OBSERVER_BEFORE", "transfer_windows_transport_bytes", False),
    ("partial-qmp-custody", "v1", "test_partial_qmp_reply_is_retained_and_same_original_can_finish_without_resend", "main", "v1/partial-main.before.source", "VPN_MAIN_INPUT_PARTIAL_BEFORE", "AssertionError", False),
    ("parent-capture-scope", "v1", "test_real_powershell_parent_capture_uses_own_scope", "observer", "v1/capture-observer.before.source", "VPN_MAIN_INPUT_CAPTURE_BEFORE", "pending-identity-security", True),
    ("powershell-finite-guard", "v1", "test_real_powershell_native_guard_refusal_preserves_finite_code", "observer", "v1/capture-observer.before.source", "VPN_MAIN_INPUT_CAPTURE_BEFORE", "throw$c", True),
    ("private-qmp-unknown-lock", "v1", "test_private_qmp_unknown_locks_shared_peer_before_another_sequence", "main", "v1/private-main.before.source", "VPN_MAIN_INPUT_PRIVATE_UNKNOWN_BEFORE", "False is not true", False),
    ("frame-conversion-custody", "v1", "test_actual_ppm_conversion_rejects_changed_original_frame", "main", "v1/frame-main.before.source", "VPN_MAIN_INPUT_FRAME_BEFORE", "Refused not raised", False),
    ("fixed-lifetime-root", "v2", "test_fixed_intent_root_cannot_be_reset_by_second_private_folder", "main", "v1/main.current.source", "VPN_MAIN_INPUT_REVIEW_BEFORE", "Refused not raised", False),
    ("system-consent-sid", "v2", "test_strict_consent_requires_actual_system_sid", "main", "v1/main.current.source", "VPN_MAIN_INPUT_REVIEW_BEFORE", "Refused not raised", False),
    ("selected-account-validator", "v2", "test_visible_admin_label_is_not_selected_account_authority", "main", "v1/main.current.source", "VPN_MAIN_INPUT_REVIEW_BEFORE", "Refused not raised", False),
    ("selected-account-powershell", "v2", "test_real_powershell_providerless_account_label_refuses", "observer", "v1/observer.current.source", "VPN_MAIN_INPUT_OBSERVER_REVIEW_BEFORE", "2 != 0", True),
    ("native-guid-whole-bridge", "v3", "test_wrong_bridge_machine_guid_cannot_rekey_unknown_input", "main", "v2/main.current.source", "VPN_MAIN_INPUT_GUID_BEFORE", "2 != 1", False),
    ("native-guid-powershell-emitter", "v3", "test_real_powershell_result_emits_registry_guid_not_expected_guid", "observer", "v2/observer.current.source", "VPN_MAIN_INPUT_GUID_OBSERVER_BEFORE", "KeyError: 'machineGuid'", True),
)
POWERSHELL_METHODS = (
    "test_parser_actual_when_explicitly_available",
    "test_actual_powershell_literal_bytes_match_child_and_native_hashes",
    "test_real_powershell_parent_capture_uses_own_scope",
    "test_real_powershell_native_guard_refusal_preserves_finite_code",
    "test_real_powershell_result_emits_registry_guid_not_expected_guid",
    "test_real_powershell_providerless_account_label_refuses",
    "test_real_powershell_selection_provider_binds_same_password_subtree",
)
RUNS = []


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def powershell():
    return (os.environ.get("VPN_CONTROL_TEST_POWERSHELL")
            or (shutil.which("powershell.exe") if os.name == "nt" else None)
            or shutil.which("pwsh"))


def posix_capable():
    return os.name == "posix" and all(hasattr(os, name) for name in
        ("getuid", "O_NOFOLLOW", "O_DIRECTORY", "pread", "fchmod"))


def provenance():
    value = json.loads((HERE / "provenance.json").read_bytes())
    assert value["schemaVersion"] == 1
    for relative, pin in value["fixtures"].items():
        raw = (HERE / relative).read_bytes()
        assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], relative
    for relative, pin in value["metadata"].items():
        raw = (HERE / relative).read_bytes()
        assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], relative
        assert json.loads(raw)["schemaVersion"] == 1, relative
    for relative, pin in {**value["production"], **value["baselineInputs"]}.items():
        raw = (ROOT / relative).read_bytes()
        assert len(raw) == pin["bytes"] and sha(raw) == pin["sha256"], relative
    return value


def stage_roles(stage):
    if stage not in {"v1", "v2", "v3"}:
        raise ValueError("finite-input-helper-stage")
    return {
        "main": ROOT / SOURCE_ROLES["main"] if stage == "v3" else HERE / stage / "main.current.source",
        "observer": ROOT / SOURCE_ROLES["observer"] if stage == "v3" else HERE / stage / "observer.current.source",
        "backend": ROOT / SOURCE_ROLES["backend"],
        "pending": ROOT / SOURCE_ROLES["pending"],
    }


def render_controls(stage, before_case=None):
    provenance()
    roles = stage_roles(stage)
    if before_case is not None:
        assert before_case in CASES and before_case[1] == stage
        roles[before_case[3]] = HERE / before_case[4]
    original = (HERE / stage / "controls.source").read_text()
    source = original.replace("HERE = Path(__file__).resolve().parent", "HERE = Path(" + repr(str(HERE / stage)) + ")", 1)
    start = source.index('b_source = HERE / "main_input_bridge.py"')
    stop = source.index('b = load("private_main_input_bridge_controls", b_source)', start)
    source = source[:start] + "b_source = Path(" + repr(str(roles["main"])) + ")\ns_source = Path(" + repr(str(roles["observer"])) + ")\n" + source[stop:]
    for old, role in (("canonical_observer_backend.py", "backend"), ("pending_join.py", "pending")):
        token = 'HERE / "' + old + '"'
        assert source.count(token) == 1
        source = source.replace(token, "Path(" + repr(str(roles[role])) + ")", 1)
    # The only remapping is top-level filesystem data. Every actual control,
    # setUp, fixture class and function body is the original complete AST.
    functions = lambda raw: [ast.dump(node, include_attributes=False) for node in ast.parse(raw).body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    assert functions(source) == functions(original), "original-control-body-drift"
    return source, roles


def clean_environment(selector=None):
    result = dict(os.environ)
    for name in (*SELECTORS, "PYTHONPATH", "DYLD_INSERT_LIBRARIES"):
        result.pop(name, None)
    result.update(PYTHONDONTWRITEBYTECODE="1", POWERSHELL_UPDATECHECK="Off", POWERSHELL_TELEMETRY_OPTOUT="1")
    runtime = powershell()
    if runtime is not None:
        result["VPN_CONTROL_TEST_POWERSHELL"] = runtime
    if selector is not None:
        assert selector in SELECTORS
        result[selector] = "1"
    return result


def load_current_controls():
    source, roles = render_controls("v3")
    temporary = tempfile.TemporaryDirectory(prefix="windows-main-input-current-")
    atexit.register(temporary.cleanup)
    path = Path(temporary.name) / "mapped_controls.py"
    path.write_text(source)
    name = "_windows_main_input_whole_current_" + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    environment = clean_environment()
    class DeclaredHelperOs:
        environ = environment
        def __getattr__(self, key):
            return getattr(os, key)
    normal_import = builtins.__import__
    def import_peer(import_name, *args, **kwargs):
        return DeclaredHelperOs() if import_name == "os" else normal_import(import_name, *args, **kwargs)
    module.__dict__["__builtins__"] = dict(vars(builtins), __import__=import_peer)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    module._whole_mapped_source_sha256 = sha(source.encode())
    module._whole_original_source_sha256 = sha((HERE / "v3/controls.source").read_bytes())
    module._declared_roles = {key: str(value) for key, value in roles.items()}
    return module


def run_pair(name):
    case = next((item for item in CASES if item[0] == name), None)
    if case is None:
        raise ValueError("finite-input-causal-case")
    if not posix_capable():
        raise RuntimeError("declared-posix-fixture-capability-required")
    if case[7] and powershell() is None:
        raise RuntimeError("declared-powershell-fixture-capability-required")
    results = []
    with tempfile.TemporaryDirectory(prefix="windows-main-input-causal-") as directory:
        root = Path(directory)
        for label, before, expected in (("RED", case, 1), ("GREEN", None, 0)):
            source, roles = render_controls(case[1], before)
            script = root / (label + ".py")
            script.write_text(source)
            result = subprocess.run([sys.executable, "-B", str(script), "BridgeControls." + case[2]],
                cwd=root, env=clean_environment(case[5] if before else None), capture_output=True, timeout=45)
            text = (result.stdout + result.stderr).decode("utf-8", errors="replace")
            assert result.returncode == expected, (name, label, result.returncode, text)
            assert "Ran 1 test" in text and "skipped=" not in text, (name, label, text)
            if before:
                assert case[6] in text, (name, "wrong-causal-failure", text)
            results.append({"case": name, "stage": case[1], "method": case[2], "phase": label,
                "returnCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                "mappedHelperSha256": sha(source.encode()),
                "sourceRoles": {key: {"path": str(value), "sha256": sha(value.read_bytes())} for key, value in roles.items()},
                "completeOriginalControlBodies": True, "nativeOrNetworkActions": False})
    RUNS.extend(results)
    return results
