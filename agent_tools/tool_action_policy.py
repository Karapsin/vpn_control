"""Explicit, immutable readiness policies and a fail-closed exposure audit.

Policy lookup does not connect, probe, select a target, or repair anything. The
coordinator must apply the existing historical/ownership fences before readiness
and retain the original operation's observation route after uncertain dispatch.
"""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass, field, replace
import json
import os
import sys
import hashlib
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

MANIFEST_PATH = Path(__file__).with_name("tool_action_policy.json")
SOURCE_PATH = Path(__file__).absolute()
_EXECUTING_CODE = sys._getframe().f_code
try:
    from .source_module_loader import _bootstrap_source
except ImportError:  # supported standalone CLI entrypoint
    sys.path.insert(0, str(SOURCE_PATH.parent.parent))
    from agent_tools.source_module_loader import _bootstrap_source
REQUIREMENTS = frozenset(("transport", "guest", "guest_agent", "ordinary_session", "interactive_desktop"))
RECOVERIES = frozenset(("reconnect", "start", "resume", "wake_display", "login", "reboot"))
TEST_STATES = frozenset(("default", "disconnected", "locked", "signed_out", "sleeping", "paused", "suspended", "stopped"))
PROVIDER_POLICY_ACTIONS = MappingProxyType({
    ("vm_workflow", "readiness-lease-acquire"): frozenset((
        "android-emulator", "raw-qemu-windows", "libvirt-windows", "tart-macos")),
})


class ActionPolicyError(ValueError):
    """An exposed action has no reviewed readiness authority."""


@dataclass(frozen=True)
class ProviderPolicy:
    requirements: frozenset[str]
    permitted_recoveries: frozenset[str]
    classification: str


@dataclass(frozen=True)
class ActionPolicy:
    surface: str
    action: str
    requirements: frozenset[str]
    permitted_recoveries: frozenset[str]
    expected_test_state: str
    observation_route: str
    classification: str
    provider_policies: Mapping[str, ProviderPolicy] = field(default_factory=lambda: MappingProxyType({}), hash=False)


def _capture(path: Path):
    """Use existing cross-platform source custody; JSON receives identical guards."""
    try:
        with _bootstrap_source(Path(path).absolute()) as (raw, guard):
            info = Path(path).lstat()
            generation = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                          info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
            guard()
            return raw, generation, hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, TypeError, AttributeError):
        raise ActionPolicyError("policy_source_custody_failed") from None


def _guard_loaded_catalog():
    for path, expected in ((SOURCE_PATH, _SOURCE_PIN), (MANIFEST_PATH, _MANIFEST_PIN)):
        raw, generation, digest = _capture(path)
        if (generation, digest) != expected:
            raise ActionPolicyError("loaded_policy_changed")


def load_catalog(path: Path = MANIFEST_PATH) -> Mapping[tuple[str, str], ActionPolicy]:
    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ActionPolicyError("duplicate_policy_key")
            result[key] = value
        return result
    try:
        raw, _, _ = _capture(path)
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise ActionPolicyError("invalid_policy_document") from None
    try:
        return _parse_catalog(document)
    except ActionPolicyError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError):
        raise ActionPolicyError("invalid_policy_document") from None


def _parse_catalog(document) -> Mapping[tuple[str, str], ActionPolicy]:
    if type(document) is not dict or set(document) != {"schemaVersion", "groups"} or document["schemaVersion"] != 1:
        raise ActionPolicyError("unsupported_policy_schema")
    result = {}
    for group in document["groups"]:
        fields = {"surface", "classification", "requirements", "permittedRecoveries", "expectedTestState", "actions"}
        if set(group) not in (fields, fields | {"providerPolicies"}):
            raise ActionPolicyError("invalid_policy_group")
        requirements = frozenset(group["requirements"])
        recoveries = frozenset(group["permittedRecoveries"])
        if not requirements <= REQUIREMENTS or not recoveries <= RECOVERIES or group["expectedTestState"] not in TEST_STATES:
            raise ActionPolicyError("invalid_policy_capability")
        if not requirements and recoveries:
            raise ActionPolicyError("recovery_without_requirement")
        if group["classification"] in {"local_metadata", "local_observation", "readiness_observation", "retired", "recovery_primitive", "intentional_phase"} and recoveries:
            raise ActionPolicyError("protected_policy_has_recovery")
        if group["classification"] == "remote_observation" and (requirements != {"transport"} or not recoveries <= {"reconnect"}):
            raise ActionPolicyError("remote_observation_may_not_wake_guest")
        for action, route in group["actions"].items():
            key = group["surface"], action
            if key in result or not all(type(value) is str and value for value in (*key, route, group["classification"])):
                raise ActionPolicyError("duplicate_or_invalid_policy")
            variants = _provider_policies(group, key, requirements, recoveries)
            result[key] = ActionPolicy(*key, requirements, recoveries, group["expectedTestState"], route, group["classification"], variants)
    return MappingProxyType(result)


def _provider_policies(group, key, requirements, recoveries):
    if "providerPolicies" not in group:
        return MappingProxyType({})
    rows = group["providerPolicies"]
    if (key not in PROVIDER_POLICY_ACTIONS or len(group["actions"]) != 1 or
            group["classification"] != "interactive_submission" or group["expectedTestState"] != "default" or
            type(rows) is not dict or set(rows) != PROVIDER_POLICY_ACTIONS[key]):
        raise ActionPolicyError("invalid_provider_policy_scope")
    result = {}
    for provider, row in rows.items():
        if type(row) is not dict or set(row) != {"classification", "requirements", "permittedRecoveries"}:
            raise ActionPolicyError("invalid_provider_policy")
        for field_name in ("requirements", "permittedRecoveries"):
            values = row[field_name]
            if type(values) is not list or any(type(value) is not str for value in values) or len(values) != len(set(values)):
                raise ActionPolicyError("invalid_provider_policy")
        required, permitted = frozenset(row["requirements"]), frozenset(row["permittedRecoveries"])
        classification = row["classification"]
        if not required or not required <= requirements or not permitted <= recoveries:
            raise ActionPolicyError("provider_policy_escalation")
        if classification == "interactive_submission":
            valid = "interactive_desktop" in required
        elif classification == "background_submission":
            valid = required <= {"transport", "guest", "guest_agent"} and not permitted & {"wake_display", "login"}
        else:
            valid = False
        if not valid:
            raise ActionPolicyError("invalid_provider_policy_classification")
        result[provider] = ProviderPolicy(required, permitted, classification)
    return MappingProxyType(result)


_SOURCE_BYTES, _SOURCE_GENERATION, _SOURCE_SHA256 = _capture(SOURCE_PATH)
if _EXECUTING_CODE != compile(_SOURCE_BYTES, __file__, "exec", dont_inherit=True, optimize=sys.flags.optimize):
    raise ActionPolicyError("executing_policy_source_mismatch")
_SOURCE_PIN = (_SOURCE_GENERATION, _SOURCE_SHA256)
_MANIFEST_BYTES, _MANIFEST_GENERATION, MANIFEST_SHA256 = _capture(MANIFEST_PATH)
_MANIFEST_PIN = (_MANIFEST_GENERATION, MANIFEST_SHA256)
CATALOG = load_catalog()
_guard_loaded_catalog()


def action_policy(surface: str, action: str, *, provider: str | None = None) -> ActionPolicy:
    """Inspect base authority, or select an explicitly classified actual provider.

    Context-free base policies are conservative inspection/audit declarations.
    Provider-sensitive execution must select its authenticated fixture lane.
    """
    _guard_loaded_catalog()
    try:
        policy = CATALOG[surface, action]
    except (KeyError, TypeError):
        raise ActionPolicyError("unclassified_tool_action") from None
    if provider is None:
        return policy
    if type(provider) is not str or provider not in policy.provider_policies:
        raise ActionPolicyError("unclassified_tool_provider")
    selected = policy.provider_policies[provider]
    return replace(policy, requirements=selected.requirements,
                   permitted_recoveries=selected.permitted_recoveries,
                   classification=selected.classification, provider_policies=MappingProxyType({}))


def _strings(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        result = set()
        for child in node.elts:
            if isinstance(child, ast.Starred):
                continue
            result.update(_strings(child))
        return result
    return set()


def _dispatch_actions(tree: ast.Module, function_names: set[str]) -> set[str]:
    result = set()
    for function in tree.body:
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) or function.name not in function_names:
            continue
        for node in ast.walk(function):
            if not isinstance(node, ast.Compare):
                continue
            if isinstance(node.left, ast.Name) and node.left.id == "action":
                for operator, operand in zip(node.ops, node.comparators):
                    if isinstance(operator, (ast.Eq, ast.NotEq)) or (isinstance(operator, (ast.In, ast.NotIn)) and isinstance(operand, (ast.List, ast.Tuple, ast.Set))):
                        result.update(_strings(operand))
            elif len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)) and isinstance(node.comparators[0], ast.Name) and node.comparators[0].id == "action":
                result.update(_strings(node.left))
    return result


def _workflow_cli_actions(tree: ast.Module, parser_name: str) -> set[str]:
    result = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == parser_name
                and node.func.attr == "add_argument" and node.args and _strings(node.args[0]) == {"action"}):
            for keyword in node.keywords:
                if keyword.arg == "choices":
                    result.update(_strings(keyword.value))
        # The finite VM CLI choices are extended after its initial declaration.
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if (isinstance(target, ast.Attribute) and target.attr == "choices"
                        and any(isinstance(child, ast.Name) and child.id == parser_name for child in ast.walk(target))):
                    result.update(_strings(node.value))
    return result


def _script_actions(tree: ast.Module) -> set[str]:
    """Read finite argparse declarations, including literal for-loop actions."""
    result = set()
    constants = {target.id: value.value for value in tree.body
                 if isinstance(value, ast.Assign)
                 for target in value.targets if isinstance(target, ast.Name)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "add_parser" and node.args:
            result.update(_strings(node.args[0]))
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument" and node.args
                and _strings(node.args[0]) == {"--action"}):
            choices = next((keyword.value for keyword in node.keywords if keyword.arg == "choices"), None)
            if isinstance(choices, ast.Name):
                choices = constants.get(choices.id)
            actions = _strings(choices) if choices is not None else set()
            if not actions:
                raise ActionPolicyError("unbounded_direct_action_choices")
            result.update(actions)
            required = next((keyword.value for keyword in node.keywords if keyword.arg == "required"), None)
            if not isinstance(required, ast.Constant) or required.value is not True:
                result.add("run")
        if isinstance(node, ast.For) and isinstance(node.target, ast.Name):
            if any(isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                   and child.func.attr == "add_parser" and child.args
                   and isinstance(child.args[0], ast.Name) and child.args[0].id == node.target.id
                   for statement in node.body for child in ast.walk(statement)):
                result.update(_strings(node.iter))
    return result


# The supported direct-entrypoint boundary is deliberately finite. Adding a new
# action in any of these scripts requires an explicit catalog review. Other
# native scenario fixtures are dispatched through their classified VM action.
DIRECT_SCRIPTS = MappingProxyType({
    "visual_platform": "scripts/visual_platform.py",
    "visual_target": "scripts/visual_target.py",
    "visual_review": "scripts/visual_review.py",
    "capture_visual_macos_tart": "scripts/capture_visual_macos_tart.py",
    "capture_visual_windows_qemu": "scripts/capture_visual_windows_qemu.py",
    "macos_vm_resource_monitor": "scripts/macos_vm_resource_monitor.py",
    "android_installer_lifecycle": "scripts/android_installer_lifecycle.py",
    "capture_visual_android": "scripts/capture_visual_android.sh",
    "capture_visual_desktop": "scripts/capture_visual_desktop.sh",
    "capture_visual_desktop_windows": "scripts/capture_visual_desktop.ps1",
    "bootstrap_windows_visual_vm": "scripts/bootstrap_windows_visual_vm.sh",
    "start_windows_visual_vm": "scripts/start_windows_visual_vm.sh",
    "mark_windows_visual_vm_ready": "scripts/mark_windows_visual_vm_ready.sh",
    "prepare_linux_install_vm": "scripts/prepare_linux_install_vm.py",
    "ssh_program_mcp_client": "agent_tools/ssh_program_mcp_client.py",
    "readiness_entrypoints": "agent_tools/readiness_entrypoints.py",
    "readiness_adb_dispatch": "agent_tools/readiness_adb_dispatch.py",
})
# These option modes have different readiness authority than the default capture.
DIRECT_OPTION_ACTIONS = MappingProxyType({
    "capture_visual_windows_qemu": MappingProxyType({"--probe": "probe", "--send-key": "input", "--type-text": "input"}),
})


def _registered_tools(tree: ast.Module) -> Mapping[str, str]:
    result = {}
    for node in ast.walk(tree):
        if (not isinstance(node, ast.Call) or not isinstance(node.func, ast.Call)
                or not isinstance(node.func.func, ast.Attribute) or node.func.func.attr != "tool"
                or not isinstance(node.func.func.value, ast.Name) or node.func.func.value.id != "MCP_SERVER"):
            continue
        if len(node.args) != 1 or not isinstance(node.args[0], ast.Name):
            raise ActionPolicyError("unbounded_tool_registration")
        public_name = node.args[0].id
        for keyword in node.func.keywords:
            if keyword.arg == "name":
                if not isinstance(keyword.value, ast.Constant) or type(keyword.value.value) is not str:
                    raise ActionPolicyError("unbounded_tool_registration")
                public_name = keyword.value.value
        if public_name in result:
            raise ActionPolicyError("duplicate_tool_registration")
        result[public_name] = node.args[0].id
    return MappingProxyType(result)


def _literal_actions(node, bindings):
    if isinstance(node, ast.Name):
        values = bindings.get(node.id, ())
        if len(values) != 1:
            return None
        return _literal_actions(values[0], {})
    if isinstance(node, ast.Constant) and type(node.value) is str:
        return frozenset({node.value})
    if isinstance(node, (ast.Set, ast.Tuple, ast.List)):
        values = [_literal_actions(item, {}) for item in node.elts]
        if all(value is not None for value in values):
            return frozenset().union(*values)
    if isinstance(node, ast.Dict) and all(isinstance(key, ast.Constant) and type(key.value) is str for key in node.keys):
        return frozenset(key.value for key in node.keys)
    return None


def _action_bindings(function):
    result = {}
    for node in ast.walk(function):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    result.setdefault(target.id, []).append(node.value)
    return result


def _finite_condition(node, bindings):
    if isinstance(node, ast.Compare) and isinstance(node.left, ast.Name) and node.left.id == "action" and len(node.ops) == 1:
        if isinstance(node.ops[0], (ast.Eq, ast.In)):
            return _literal_actions(node.comparators[0], bindings)
    if isinstance(node, ast.BoolOp):
        bounds = [_finite_condition(value, bindings) for value in node.values]
        if isinstance(node.op, ast.And):
            known = [bound for bound in bounds if bound is not None]
            return frozenset.intersection(*known) if known else None
        if isinstance(node.op, ast.Or) and all(bound is not None for bound in bounds):
            return frozenset().union(*bounds)
    return None


def _finite_dictionary_join(node):
    """A prefix may select a branch only if its first work is a finite join.

    Literal table -> table.get(action) -> immediate return for missing routes.
    Unknown names cannot reach an adapter, and every table key enters inventory.
    """
    if not isinstance(node, ast.If) or len(node.body) < 3:
        return None
    table, join, guard = node.body[:3]
    if (not isinstance(table, ast.Assign) or len(table.targets) != 1
            or not isinstance(table.targets[0], ast.Name) or not isinstance(table.value, ast.Dict)):
        return None
    try:
        ast.literal_eval(table.value)  # Table construction itself has no effects.
    except (ValueError, TypeError):
        return None
    keys = _literal_actions(table.value, {})
    if keys is None or (not isinstance(join, ast.Assign) or len(join.targets) != 1
            or not isinstance(join.targets[0], ast.Name) or not isinstance(join.value, ast.Call)):
        return None
    lookup = join.value
    if (not isinstance(lookup.func, ast.Attribute) or lookup.func.attr != "get"
            or not isinstance(lookup.func.value, ast.Name) or lookup.func.value.id != table.targets[0].id
            or len(lookup.args) != 1 or lookup.keywords or not isinstance(lookup.args[0], ast.Name)
            or lookup.args[0].id != "action"):
        return None
    expected = ast.parse(f"if {join.targets[0].id} is None:\n return None").body[0].test
    if (not isinstance(guard, ast.If) or ast.dump(guard.test) != ast.dump(expected)
            or guard.orelse or len(guard.body) != 1 or not isinstance(guard.body[0], ast.Return)):
        return None
    return keys


def _historical_refusal_gate(node):
    # Explicit existing refusal-only fence. It never selects an adapter or
    # forwards a prefix-derived operation, so it cannot expose new actions.
    if not isinstance(node, ast.If):
        return False
    template = ast.parse("retired = windows_vm_setup_policy.refusal(action, inputs)\nif retired is not None:\n return retired").body
    if [ast.dump(statement) for statement in node.body] != [ast.dump(statement) for statement in template]:
        return False
    test = ast.parse("action.startswith('windows-')", mode="eval").body
    fixed = ast.parse("surface == 'vm' and action.startswith('windows-')", mode="eval").body
    return ast.dump(node.test) in {ast.dump(test), ast.dump(fixed)}


def _audit_dynamic_routes(tree):
    """Reject unbounded string routing even if no new literal action exists."""
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    functions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and any(argument.arg == "action" for argument in node.args.args)}
    bindings = {name: _action_bindings(function) for name, function in functions.items()}
    joins = {node: keys for function in functions.values() for node in ast.walk(function)
             if (keys := _finite_dictionary_join(node)) is not None}
    inherited = {}
    public_implementations = set(_registered_tools(tree).values())
    def action_dependent(node, scope, seen=frozenset()):
        for value in ast.walk(node):
            if not isinstance(value, ast.Name):
                continue
            if value.id == "action":
                return True
            if value.id not in seen and any(action_dependent(assigned, scope, seen | {value.id})
                                            for assigned in scope.get(value.id, ())):
                return True
        return False
    def dominance(node, function):
        bound = inherited.get(function.name)
        child, parent = node, parents.get(node)
        while parent is not None and parent is not function:
            candidate = None
            if isinstance(parent, ast.If):
                if child in parent.body:
                    candidate = _finite_condition(parent.test, bindings[function.name])
                if candidate is None and (child is parent.test or child in parent.body):
                    candidate = joins.get(parent)
            if candidate is not None:
                bound = candidate if bound is None else bound & candidate
            child, parent = parent, parents.get(parent)
        return bound
    # Internal helpers inherit only the finite intersection proven at every
    # actual source callsite, including non-first action parameters.
    for _ in range(len(functions)):
        changed = False
        for name, function in functions.items():
            if name in public_implementations:
                continue  # External callers are not bounded by internal callsites.
            position = next(index for index, argument in enumerate(function.args.args) if argument.arg == "action")
            bounds = []
            for caller in functions.values():
                for call in ast.walk(caller):
                    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != name:
                        continue
                    argument = (call.args[position] if len(call.args) > position else
                                next((keyword.value for keyword in call.keywords if keyword.arg == "action"), None))
                    if isinstance(argument, ast.Name) and argument.id == "action":
                        bounds.append(dominance(call, caller))
                    else:
                        bounds.append(_literal_actions(argument, bindings[caller.name]))
            if bounds and all(bound is not None for bound in bounds):
                value = frozenset().union(*bounds)
                if inherited.get(name) != value:
                    inherited[name] = value; changed = True
        if not changed:
            break
    for function in functions.values():
        for node in ast.walk(function):
            # A stored predicate (predicate = action.startswith) is routing
            # authority too; it cannot evade the bound by postponing its call.
            dynamic = isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "action"
            if isinstance(node, ast.Call) and not dynamic:
                if ((isinstance(node.func, ast.Name) and node.func.id in {"_agent_module", "getattr"})
                        or isinstance(node.func, ast.Attribute) and node.func.attr in {"import_module", "__import__"}):
                    dynamic = any(action_dependent(argument, bindings[function.name]) for argument in node.args)
            if not dynamic or dominance(node, function) is not None:
                continue
            owner = node
            while owner in parents and not isinstance(owner, ast.If):
                owner = parents[owner]
            if _historical_refusal_gate(owner):
                continue
            raise ActionPolicyError("unbounded_dynamic_action_route:" + function.name)
    return MappingProxyType({name: frozenset().union(*(joins[node] for node in ast.walk(function) if node in joins))
                             for name, function in functions.items()})


def exposed_actions(root: Path) -> Mapping[str, frozenset[str]]:
    """Inspect source without importing tools or running native entrypoints."""
    tree = ast.parse((root / "agent_tools/mcp_server.py").read_text(encoding="utf-8"))
    joined_actions = _audit_dynamic_routes(tree)
    result = {
        "ssh_workflow": _dispatch_actions(tree, {"ssh_workflow", "_ssh_workflow_impl", "_ssh_channel_workflow", "_ssh_channel_keeper_workflow", "_ssh_direct_channel_workflow"}) | _workflow_cli_actions(tree, "ssh_parser") | set(joined_actions.get("_ssh_workflow_impl", ())) | set(joined_actions.get("ssh_workflow", ())),
        "vm_workflow": _dispatch_actions(tree, {"vm_workflow", "_vm_workflow_impl", "_vm_workflow_dispatch"}) | _workflow_cli_actions(tree, "vm_parser") | set(joined_actions.get("_vm_workflow_impl", ())) | set(joined_actions.get("_vm_workflow_dispatch", ())) | set(joined_actions.get("vm_workflow", ())),
        "visual_workflow": _dispatch_actions(tree, {"visual_workflow"}),
    }
    definitions = {node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    for surface, implementation in _registered_tools(tree).items():
        if surface in result:
            continue
        function = definitions.get(implementation)
        if function is None:
            raise ActionPolicyError("registered_tool_definition_missing")
        if any(argument.arg == "action" for argument in function.args.args):
            actions = _dispatch_actions(tree, {implementation}) | set(joined_actions.get(implementation, ()))
            if not actions:
                raise ActionPolicyError("unbounded_tool_action_surface")
            result.setdefault(surface, set()).update(actions)
        else:
            result[surface] = {"call"}
    for surface, relative in DIRECT_SCRIPTS.items():
        source = (root / relative).read_text(encoding="utf-8")
        actions = set()
        if relative.endswith(".py"):
            script_tree = ast.parse(source)
            actions = _script_actions(script_tree)
            options = {next(iter(_strings(node.args[0])), "") for node in ast.walk(script_tree)
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                       and node.func.attr == "add_argument" and node.args}
            for option, action in DIRECT_OPTION_ACTIONS.get(surface, {}).items():
                if option not in options:
                    raise ActionPolicyError("direct_option_contract_changed")
                actions.add(action)
        # Shell/PowerShell and reviewed single-operation parsers have no
        # positional subcommand. Option-specific actions supplement default run.
        if not relative.endswith(".py") or not _script_actions(script_tree):
            actions.add("run")
        result.setdefault(surface, set()).update(actions)
    return MappingProxyType({surface: frozenset(actions) for surface, actions in result.items()})


def audit_action_catalog(root: Path, catalog: Mapping[tuple[str, str], ActionPolicy] = CATALOG) -> dict[str, object]:
    _guard_loaded_catalog()
    exposed = {(surface, action) for surface, actions in exposed_actions(root).items() for action in actions}
    classified = set(catalog)
    missing, stale = exposed - classified, classified - exposed
    if missing or stale:
        details = {"missing": sorted("%s:%s" % key for key in missing), "stale": sorted("%s:%s" % key for key in stale)}
        raise ActionPolicyError("action_policy_audit_failed:" + json.dumps(details, sort_keys=True))
    for key, providers in PROVIDER_POLICY_ACTIONS.items():
        if set(catalog[key].provider_policies) != providers:
            raise ActionPolicyError("action_provider_policy_audit_failed:" + ":".join(key))
    return {"ok": True, "actionCount": len(exposed), "surfaceCount": len({key[0] for key in exposed})}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        print(json.dumps(audit_action_catalog(args.root), sort_keys=True))
    except (ActionPolicyError, OSError, SyntaxError) as error:
        print(json.dumps({"ok": False, "reason": str(error)}, sort_keys=True))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
