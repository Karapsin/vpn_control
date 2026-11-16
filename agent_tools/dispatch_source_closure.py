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
committed-source rule (readiness_vm_dispatch) checks exactly what can run.
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


def computed(catalog=None, tools=TOOLS):
    catalog = json.loads(CATALOG.read_bytes()) if catalog is None else catalog
    known, cache = modules(tools), {}
    return {action: closure(row["modules"], tools, known, cache) for action, row in catalog["actions"].items()}


def mismatches(catalog=None, tools=TOOLS):
    catalog = json.loads(CATALOG.read_bytes()) if catalog is None else catalog
    expected = computed(catalog, tools)
    return {action: {"missing": sorted(set(expected[action]) - set(row["closure"])),
                     "extra": sorted(set(row["closure"]) - set(expected[action]))}
            for action, row in catalog["actions"].items() if sorted(row["closure"]) != expected[action]}


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
    found = mismatches(catalog)
    print(json.dumps({"ok": not found, "mismatches": found}, indent=2))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
