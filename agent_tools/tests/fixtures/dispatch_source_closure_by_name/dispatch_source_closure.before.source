#!/usr/bin/env python3
"""Computed source closure of every native dispatch action in readiness_vm_dispatch.json.

An action's closure is every top-level agent_tools module that its entry modules
reach through:
  * an import statement (module level or inside a function), absolute or relative;
  * a sibling source named by `Path(...).with_name("<module>.py")` or by the
    literal path "agent_tools/<module>.py" (a shipped or read source, such as a
    guest worker, a packet body or a reviewed helper);
  * a module-level `_INSTANCE_SOURCES` tuple of module names (sources shipped to
    a lab host).

CI requires each declared closure to equal this computation, so the runtime
committed-source rule (readiness_vm_dispatch) checks exactly what can run, and
requires every fixed-host proof to name a symbol of a closure module that holds
(host-constant) or compares with (validated-host) the row's host literal.
Usage: python3 -m agent_tools.dispatch_source_closure [--check | --write]
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent
CATALOG = TOOLS / "readiness_vm_dispatch.json"
_REGISTRIES = frozenset({"_INSTANCE_SOURCES"})


def modules(tools=TOOLS):
    return frozenset(path.stem for path in Path(tools).glob("*.py"))


def direct_sources(name, tools=TOOLS, known=None):
    """Top-level agent_tools modules that one module imports, reads or ships."""
    known = modules(tools) if known is None else known
    tree = ast.parse((Path(tools) / (name + ".py")).read_bytes(), filename=name + ".py")
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if (node.level == 1 and not node.module) or (node.level == 0 and node.module == "agent_tools"):
                found.update(alias.name for alias in node.names)
            elif node.level == 1:
                found.add(node.module.split(".")[0])
            elif node.level == 0 and node.module and node.module.startswith("agent_tools."):
                found.add(node.module.split(".")[1])
        elif isinstance(node, ast.Import):
            found.update(alias.name.split(".")[1] for alias in node.names if alias.name.startswith("agent_tools."))
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.startswith("agent_tools/")
              and node.value.endswith(".py") and node.value.count("/") == 1):
            found.add(node.value[len("agent_tools/"):-3])
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "with_name"
              and len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)
              and node.args[0].value.endswith(".py")):
            found.add(node.args[0].value[:-3])
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id in _REGISTRIES for t in node.targets):
            value = ast.literal_eval(node.value)
            found.update(item for item in value if isinstance(item, str))
    return (found & known) - {name}


def closure(entries, tools=TOOLS, known=None, cache=None):
    known = modules(tools) if known is None else known
    cache = {} if cache is None else cache
    seen, pending = set(), [name for name in entries if name in known]
    while pending:
        name = pending.pop()
        if name in seen:
            continue
        seen.add(name)
        if name not in cache:
            cache[name] = direct_sources(name, tools, known)
        pending.extend(cache[name])
    return sorted(seen)


_PARSED = {}  # (tools, module, size, mtime_ns) -> direct sources; one parse per process


def computed(catalog=None, tools=TOOLS):
    catalog = json.loads(CATALOG.read_bytes()) if catalog is None else catalog
    known = modules(tools)
    cache = _Cache(Path(tools))
    return {action: closure(row["modules"], tools, known, cache) for action, row in catalog["actions"].items()}


def mismatches(catalog=None, tools=TOOLS):
    catalog = json.loads(CATALOG.read_bytes()) if catalog is None else catalog
    expected = computed(catalog, tools)
    return {action: {"missing": sorted(set(expected[action]) - set(row["closure"])),
                     "extra": sorted(set(row["closure"]) - set(expected[action]))}
            for action, row in catalog["actions"].items() if sorted(row["closure"]) != expected[action]}


class _Cache(dict):
    """Direct sources keyed by the file's size and mtime, shared across calls."""

    def __init__(self, tools):
        super().__init__()
        self.tools = tools

    def _key(self, name):
        info = (self.tools / (name + ".py")).stat()
        return (str(self.tools), name, info.st_size, info.st_mtime_ns)

    def __contains__(self, name):
        return self._key(name) in _PARSED

    def __getitem__(self, name):
        return _PARSED[self._key(name)]

    def __setitem__(self, name, value):
        _PARSED[self._key(name)] = value


def _symbol(tree, dotted):
    """The module-level assignment or the (nested) def/class that `dotted` names."""
    body, node = tree.body, None
    for part in dotted.split("."):
        node = next((item for item in body if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                     and item.name == part), None)
        if node is None and body is tree.body and "." not in dotted:
            node = next((item for item in body if isinstance(item, ast.Assign)
                         and any(isinstance(t, ast.Name) and t.id == part for t in item.targets)), None)
        if node is None:
            return None
        body = getattr(node, "body", [])
    return node


def proof_problems(catalog=None, tools=TOOLS):
    """A fixed-host proof names a symbol of a closure module that holds the row's host literal.

    host-constant: a module-level assignment of exactly that string.
    validated-host: a def or class whose body compares with that string.
    """
    catalog = json.loads(CATALOG.read_bytes()) if catalog is None else catalog
    problems, trees = {}, {}
    for action, row in catalog["actions"].items():
        if row["kind"] != "fixed_host":
            continue
        proof, host = row["proof"], row["host"]
        if proof["module"] not in row["closure"]:
            problems[action] = "proof_module_outside_closure"
            continue
        if proof["module"] not in trees:
            trees[proof["module"]] = ast.parse((Path(tools) / (proof["module"] + ".py")).read_bytes())
        node = _symbol(trees[proof["module"]], proof["symbol"])
        if node is None:
            problems[action] = "proof_symbol_missing"
        elif proof["kind"] == "host-constant":
            if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and node.value.value == host):
                problems[action] = "proof_symbol_not_host_constant"
        elif proof["kind"] == "validated-host":
            compared = any(isinstance(item, ast.Compare) and any(
                isinstance(side, ast.Constant) and side.value == host for side in (item.left, *item.comparators))
                for item in ast.walk(node))
            if isinstance(node, ast.Assign) or not compared:
                problems[action] = "proof_symbol_does_not_validate_host"
        else:
            problems[action] = "proof_kind_unknown"
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", action="store_true", help="rewrite every declared closure to the computed one")
    args = parser.parse_args(argv)
    catalog = json.loads(CATALOG.read_bytes())
    if args.write:
        for action, value in computed(catalog).items():
            catalog["actions"][action]["closure"] = value
        CATALOG.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"ok": True, "actions": len(catalog["actions"])}))
        return 0
    found, proofs = mismatches(catalog), proof_problems(catalog)
    print(json.dumps({"ok": not found and not proofs, "mismatches": found, "proofProblems": proofs}, indent=2))
    return 1 if found or proofs else 0


if __name__ == "__main__":
    sys.exit(main())
