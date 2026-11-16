#!/usr/bin/env python3
"""Computed source closure of every native dispatch action in readiness_vm_dispatch.json.

A closure is a sorted list of repository-relative files. From an action's entry
modules it follows, through every agent_tools Python file it reaches (top level
or in a subpackage such as windows_system_collector/):
  * an import statement (module level or inside a function), absolute or relative;
  * a module loaded by name: a string argument of a loader call (`_agent_module`,
    `importlib.import_module`, `_module`, `SourceSession(...)`, `.load`, `.adapter`,
    `_source_pin`), directly, in an f-string tail (`f"{__package__}.name"`) or
    through a module-level name assigned a string, and every name of a by-name
    registry (`_INSTANCE_SOURCES`, `_VM_NATIVE_ADAPTERS`, `_PROFILE_MODULES`);
  * a file named by a literal: `Path(...).with_name("<file>")`, a sibling file
    name such as "tool_action_policy.json", a path relative to agent_tools such
    as "windows_public_updater/update_cases.py", a repository path under
    agent_tools/ or scripts/ (the scenario bundle table ships these to the guest:
    .py, .ps1, .ps1.template, .cs, .source), or a subpackage directory name,
    which names all of its files;
  * the module's own resource named by `.with_suffix("<suffix>")`
    (readiness_vm_dispatch.json).
Non-Python files and scripts/ files are leaves. Tests, fixtures, caches and
Markdown are never members.

CI requires each declared closure to equal this computation, so the runtime
committed-source rule (readiness_vm_dispatch) checks exactly what can run, and
requires every fixed-host proof to name a symbol of a closure module that holds
(host-constant) or compares with (validated-host) the row's host literal.
Usage: python3 -m agent_tools.dispatch_source_closure [--check | --write]
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys

TOOLS = Path(__file__).resolve().parent
CATALOG = TOOLS / "readiness_vm_dispatch.json"
_PREFIX = "agent_tools/"
# Literal repository paths that a tool runs, reads or ships (the bundle table's agent_tools/ and scripts/ entries).
_LITERAL_ROOTS = ("agent_tools/", "scripts/")
_SKIPPED_DIRECTORIES = frozenset({"tests", "__pycache__"})
# By-name module registries: every string they hold is a module loaded by name.
REGISTRIES = frozenset({"_INSTANCE_SOURCES", "_VM_NATIVE_ADAPTERS", "_PROFILE_MODULES"})
# Calls whose string arguments name a module to load (agent_tools.<name>, .<name> or <name>).
LOADERS = frozenset({"_agent_module", "import_module", "_module", "load", "adapter", "SourceSession", "_source_pin"})


def module_path(name):
    """Repository path of the agent_tools file of `name` (top-level module stem or a known relative path)."""
    return _PREFIX + name + ".py"


def _member(relative):
    parts = relative.split("/")
    return (not any(part in _SKIPPED_DIRECTORIES or part.startswith(".") for part in parts)
            and not relative.endswith((".md", ".pyc")))


def files(tools=TOOLS):
    """Every agent_tools file a closure may hold: repository paths, without tests, caches or Markdown."""
    tools = Path(tools)
    found = set()
    for directory, names, leaves in os.walk(tools):
        names[:] = sorted(name for name in names if name not in _SKIPPED_DIRECTORIES and not name.startswith("."))
        for leaf in leaves:
            relative = os.path.relpath(os.path.join(directory, leaf), tools).replace(os.sep, "/")
            if _member(relative):
                found.add(_PREFIX + relative)
    return frozenset(found)


def modules(tools=TOOLS):
    """Top-level module stems (the names readiness_vm_dispatch.json lists as entry modules)."""
    return frozenset(path.stem for path in Path(tools).glob("*.py"))


class Scan:
    """One walk of a parsed module: what the closure rules read from it."""

    __slots__ = ("imports", "strings", "loaded", "with_name", "with_suffix")

    def __init__(self, tree):
        self.imports, self.strings, self.with_name, self.with_suffix = [], set(), set(), set()
        assigned, loader_arguments, registries = {}, [], set()
        for node in ast.walk(tree):
            kind = type(node)
            if kind is ast.Constant:
                if type(node.value) is str and 0 < len(node.value) <= 256:
                    self.strings.add(node.value)
            elif kind is ast.Import or kind is ast.ImportFrom:
                self.imports.append(node)
            elif kind is ast.Assign:
                for target in node.targets:
                    if type(target) is ast.Name:
                        if type(node.value) is ast.Constant and type(node.value.value) is str:
                            assigned.setdefault(target.id, set()).add(node.value.value)
                        if target.id in REGISTRIES:
                            registries.add(node.value)
            elif kind is ast.Call:
                function = node.func
                name = function.id if type(function) is ast.Name else function.attr if type(function) is ast.Attribute else None
                if name in LOADERS:
                    loader_arguments.extend([*node.args, *(keyword.value for keyword in node.keywords)])
                if (type(function) is ast.Attribute and name in ("with_name", "with_suffix") and len(node.args) == 1
                        and type(node.args[0]) is ast.Constant and type(node.args[0].value) is str):
                    (self.with_name if name == "with_name" else self.with_suffix).add(node.args[0].value)
        raw = set()
        for value in registries:
            raw.update(_strings(value))
        for argument in loader_arguments:
            raw.update(_strings(argument))
            if type(argument) is ast.Name:
                raw.update(assigned.get(argument.id, ()))
        self.loaded = set()
        for value in raw:
            value = (value[len("agent_tools."):] if value.startswith("agent_tools.") else value).lstrip(".")
            if value and len(value) <= 160 and all(part.isidentifier() for part in value.split(".")):
                self.loaded.add(value)


def _strings(node):
    return [item.value for item in ast.walk(node) if type(item) is ast.Constant and type(item.value) is str]


def by_name_loads(tree):
    """Module names one parsed module loads by name: dotted, without an `agent_tools.` or leading `.` prefix."""
    return Scan(tree).loaded


def _resolve_module(dotted, known):
    """agent_tools path of a dotted module name, or of its longest existing prefix."""
    parts = dotted.split(".")
    for end in range(len(parts), 0, -1):
        for candidate in (_PREFIX + "/".join(parts[:end]) + ".py", _PREFIX + "/".join(parts[:end]) + "/__init__.py"):
            if candidate in known:
                return candidate
    return None


def _imports(scan, path, known):
    """agent_tools paths one module imports, package or script style."""
    package = path[len(_PREFIX):].split("/")[:-1]
    found = set()
    for node in scan.imports:
        names = []
        if type(node) is ast.ImportFrom:
            module = node.module.split(".") if node.module else []
            if node.level:
                base = package[:len(package) - (node.level - 1)] if node.level > 1 else package
                names = [".".join([*base, *module, alias.name]) for alias in node.names] + [".".join([*base, *module])]
            elif module and module[0] == "agent_tools":
                names = [".".join([*module[1:], alias.name]) for alias in node.names] + [".".join(module[1:])]
            elif module:
                # Script-style sibling import (`import native_artifact_registry`), as the MCP fallbacks do.
                names = [".".join([*package, *module]), ".".join(module)]
        else:
            for alias in node.names:
                parts = alias.name.split(".")
                names.append(".".join(parts[1:]) if parts[0] == "agent_tools" else ".".join([*package, *parts]))
                if parts[0] != "agent_tools" and package:
                    names.append(alias.name)
        for name in names:
            if name:
                resolved = _resolve_module(name, known)
                if resolved is not None:
                    found.add(resolved)
    return found


def _subpackages(known):
    return frozenset(item.split("/")[1] for item in known if item.count("/") >= 2)


def _literals(scan, path, known, root, subpackages):
    """Files a module names by literal or resource rule."""
    directory = path.rsplit("/", 1)[0] + "/"
    found = {directory + value for value in scan.with_name if directory + value in known}
    found.update(path[:-3] + value for value in scan.with_suffix if path[:-3] + value in known)
    for value in scan.strings:
        if "\n" in value or ".." in value.split("/"):
            continue
        value = value.rstrip("/")
        for candidate in (directory + value, _PREFIX + value, value):
            if candidate in known:
                found.add(candidate)
        if value.startswith(_LITERAL_ROOTS) and not value.startswith(_PREFIX) and _member(value) \
                and (Path(root) / value).is_file():
            found.add(value)
        if value in subpackages:
            found.update(item for item in known if item.startswith(_PREFIX + value + "/"))
    return found


def direct_sources(path, tools=TOOLS, known=None, subpackages=None):
    """Repository paths one closure member reaches directly. Only agent_tools Python files have edges."""
    known = files(tools) if known is None else known
    if not (path.startswith(_PREFIX) and path.endswith(".py")):
        return set()
    tools = Path(tools)
    scan = Scan(ast.parse((tools / path[len(_PREFIX):]).read_bytes(), filename=path))
    found = _imports(scan, path, known) | _literals(scan, path, known, tools.parent,
                                                    _subpackages(known) if subpackages is None else subpackages)
    found.update(resolved for resolved in (_resolve_module(name, known) for name in scan.loaded) if resolved)
    return found - {path}


def closure(entries, tools=TOOLS, known=None, cache=None):
    """Sorted repository paths reachable from entry module names."""
    known = files(tools) if known is None else known
    cache = {} if cache is None else cache
    subpackages = _subpackages(known)
    seen, pending = set(), [module_path(name) for name in entries if module_path(name) in known]
    while pending:
        path = pending.pop()
        if path in seen:
            continue
        seen.add(path)
        if path not in cache:
            cache[path] = direct_sources(path, tools, known, subpackages)
        pending.extend(cache[path])
    return sorted(seen)


_PARSED = {}  # (tools, path, size, mtime_ns) -> direct sources; one parse per process


def declared(catalog):
    """{action: closure list}: a row's closure is a list or the id of a shared list in catalog["closures"]."""
    shared = catalog.get("closures", {})
    return {action: list(shared[row["closure"]] if type(row["closure"]) is str else row["closure"])
            for action, row in catalog["actions"].items()}


def closure_id(paths):
    """The id of a shared closure: derived from its members, so equal closures share one list."""
    return "closure-" + hashlib.sha256(json.dumps(sorted(paths)).encode()).hexdigest()[:16]


def write(catalog, tools=TOOLS):
    """The catalog with every closure recomputed, each distinct list stored once under closures."""
    shared = {}
    for action, value in computed(catalog, tools).items():
        identity = closure_id(value)
        shared[identity] = value
        catalog["actions"][action]["closure"] = identity
    return {"schemaVersion": catalog["schemaVersion"], "closures": dict(sorted(shared.items())),
            "actions": catalog["actions"]}


def computed(catalog=None, tools=TOOLS):
    catalog = json.loads(CATALOG.read_bytes()) if catalog is None else catalog
    known = files(tools)
    cache = _Cache(Path(tools))
    return {action: closure(row["modules"], tools, known, cache) for action, row in catalog["actions"].items()}


def mismatches(catalog=None, tools=TOOLS):
    catalog = json.loads(CATALOG.read_bytes()) if catalog is None else catalog
    expected, lists = computed(catalog, tools), declared(catalog)
    found = {action: {"missing": sorted(set(expected[action]) - set(lists[action])),
                      "extra": sorted(set(lists[action]) - set(expected[action]))}
             for action in catalog["actions"] if sorted(lists[action]) != expected[action]}
    shared = catalog.get("closures", {})
    for identity, value in shared.items():
        if identity != closure_id(value) or value != sorted(value):
            found["closures:" + identity] = {"missing": [], "extra": ["unsorted or misnamed shared closure"]}
    return found


class _Cache(dict):
    """Direct sources keyed by the file's size and mtime, shared across calls; each file is stat'ed once per use."""

    def __init__(self, tools):
        super().__init__()
        self.tools, self.keys = tools, {}

    def _key(self, path):
        if path not in self.keys:
            if not path.endswith(".py") or not path.startswith(_PREFIX):
                self.keys[path] = None
            else:
                info = (self.tools / path[len(_PREFIX):]).stat()
                self.keys[path] = (str(self.tools), path, info.st_size, info.st_mtime_ns)
        return self.keys[path]

    def __contains__(self, path):
        key = self._key(path)
        return key is None or key in _PARSED

    def __getitem__(self, path):
        key = self._key(path)
        return set() if key is None else _PARSED[key]

    def __setitem__(self, path, value):
        key = self._key(path)
        if key is not None:
            _PARSED[key] = value


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
    problems, trees, lists = {}, {}, declared(catalog)
    for action, row in catalog["actions"].items():
        if row["kind"] != "fixed_host":
            continue
        proof, host = row["proof"], row["host"]
        if module_path(proof["module"]) not in lists[action]:
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
        catalog = write(catalog)
        CATALOG.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"ok": True, "actions": len(catalog["actions"])}))
        return 0
    found, proofs = mismatches(catalog), proof_problems(catalog)
    print(json.dumps({"ok": not found and not proofs, "mismatches": found, "proofProblems": proofs}, indent=2))
    return 1 if found or proofs else 0


if __name__ == "__main__":
    sys.exit(main())
