#!/usr/bin/env python3
"""Select agent unittest modules from Git and their transitive local dependencies.

No test module is imported during planning. Literal file/module references cover
source readers, hash-pinned helpers and fixtures as well as normal imports.
Unbounded local dynamic dispatch is conservatively connected to its package;
unresolved dynamic imports and changed agent files without consumers refuse.
"""
from __future__ import annotations
import argparse
import ast
from dataclasses import dataclass
import json
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import uuid
import stat
import io


# Reviewed opaque loaders: changes to their exact source require renewed mapping.
# Package scopes cover custom import hooks; finite loaders use explicit files.
LOADED_SELECTOR_SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
DEPENDENCY_MANIFEST = Path(__file__).with_name("affected_agent_test_dependencies.json")
_DEPENDENCY_MANIFEST_BYTES = DEPENDENCY_MANIFEST.read_bytes()
LOADED_DEPENDENCY_MANIFEST_SHA256 = hashlib.sha256(_DEPENDENCY_MANIFEST_BYTES).hexdigest()
_DECLARATIONS = json.loads(_DEPENDENCY_MANIFEST_BYTES)
if _DECLARATIONS.get("schemaVersion") != 1:
    raise RuntimeError("Unsupported agent dependency manifest")
REVIEWED_DYNAMIC_DEPENDENCIES = _DECLARATIONS["loaders"]
REVIEWED_NON_PYTHON_RESOURCES = _DECLARATIONS["nonPythonResources"]


class SelectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Selection:
    baseline: str
    changed: tuple[str, ...]
    modules: tuple[str, ...]
    total_modules: int

    def as_dict(self):
        return {"baseline": self.baseline, "changedPaths": list(self.changed),
                "modules": list(self.modules), "selectedModuleCount": len(self.modules),
                "totalModuleCount": self.total_modules}

    def commands(self, python: str):
        modules = list(self.modules)
        gate = "agent_tools.tests.test_ssh_connection_session_close"
        result = []
        if gate in modules:
            result.append([python, "-m", "unittest", gate])
            modules.remove(gate)
        if modules:
            result.append([python, "-m", "unittest", *modules])
        return result


def git(root, *args):
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True)
    if result.returncode:
        raise SelectionError("Git selection failed: " + " ".join(args))
    return result.stdout


def baseline_for(root, baseline=None):
    if baseline is None:
        baseline = os.environ.get("AGENT_TEST_BASELINE") or None
    if baseline is None:
        event = os.environ.get("GITHUB_EVENT_NAME")
        if event:
            try:
                data = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
                if event == "push":
                    baseline = data["before"]
                elif event == "pull_request":
                    baseline = git(root, "merge-base", data["pull_request"]["base"]["sha"], "HEAD").decode().strip()
                else:
                    raise SelectionError("CI event has no comparison baseline; pass --baseline or --audit")
            except (OSError, KeyError, ValueError) as error:
                raise SelectionError("CI comparison baseline is unavailable") from error
        else:
            baseline = git(root, "merge-base", "origin/dev", "HEAD").decode().strip()
    if not baseline or set(baseline) == {"0"}:
        raise SelectionError("Comparison baseline is missing; use an explicit baseline or intentional --audit")
    return git(root, "rev-parse", "--verify", baseline + "^{commit}").decode().strip()


def changed_paths(root, baseline):
    # --no-renames deliberately retains both old and new names. NUL delimiters
    # preserve whitespace; diff includes committed, index and worktree changes.
    changed = set(git(root, "diff", "--name-only", "--no-renames", "-z", baseline, "--").decode().split("\0"))
    changed.update(git(root, "ls-files", "--others", "--exclude-standard", "-z").decode().split("\0"))
    return changed - {""}


VERSION_ONLY_METADATA = {"gradle.properties"}
PROSE_FILES = {"README.md", "AGENTS.md", "agent_tools/README.md"}


def is_document(path):
    # Product version-only metadata is intentionally covered by product/release
    # checks. Markdown/RST under tool data or fixtures remains executable input.
    if path in VERSION_ONLY_METADATA:
        return True
    return path.endswith((".md", ".rst")) and (path in PROSE_FILES or path.startswith(("docs/", "agent_docs/")))


def potentially_agent_input(path):
    return path.startswith(("agent_tools/", "scripts/", ".github/workflows/")) or path in {".github/required-workflows.json", ".codex/config.toml"}


def is_python_source(path):
    return path.endswith((".py", ".source", ".py.gz"))


def read_source(path, raw):
    if path.endswith(".py.gz"):
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                raw = stream.read(16 * 1024 * 1024 + 1)
        except (OSError, EOFError) as error:
            raise SelectionError("Invalid compressed Python source: " + path) from error
    if len(raw) > 16 * 1024 * 1024:
        raise SelectionError("Python dependency source exceeds analysis limit: " + path)
    try:
        return raw.decode("utf-8")
    except UnicodeError as error:
        raise SelectionError("Python dependency source is not UTF-8: " + path) from error


def dependencies(path, source, inventory):
    """Conservative local dependency edges, with unresolved loading refusal."""
    if REVIEWED_NON_PYTHON_RESOURCES.get(path) == hashlib.sha256(source.encode()).hexdigest():
        return set()
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError) as error:
        raise SelectionError("Cannot analyze Python source: " + path) from error
    edges = set()
    def unknown(message):
        declaration = REVIEWED_DYNAMIC_DEPENDENCIES.get(path)
        if declaration and hashlib.sha256(source.encode()).hexdigest() in declaration["sourceSha256"]:
            scopes = []
            for scope in declaration["scopes"]:
                if scope.startswith("@"):
                    kind, constant = scope[1:].split(":", 1)
                    definitions = [n.value for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign)) and any(isinstance(t, ast.Name) and t.id == constant for t in (n.targets if isinstance(n, ast.Assign) else [n.target]))]
                    if kind not in {"files", "modules"} or len(definitions) != 1:
                        raise SelectionError("Declared source registry is unavailable: " + path)
                    try:
                        values = ast.literal_eval(definitions[0])
                    except (ValueError, TypeError) as error:
                        raise SelectionError("Declared source registry is not literal: " + path) from error
                    if not isinstance(values, (tuple, list)) or not all(isinstance(v, str) for v in values):
                        raise SelectionError("Declared source registry has invalid entries: " + path)
                    for value in values:
                        if kind == "modules":
                            scopes.append("agent_tools/" + value + ".py")
                        else:
                            scopes.append(value if "/" in value else "agent_tools/" + value)
                else:
                    scopes.append(scope)
            for scope in scopes:
                if scope.endswith("/*.py"):
                    parent = scope[:-5]
                    edges.update(p for p in inventory if str(PurePosixPath(p).parent) == parent and p.endswith(".py"))
                elif scope.endswith("/"):
                    edges.update(p for p in inventory if p.startswith(scope))
                elif scope in inventory:
                    edges.add(scope)
                else:
                    raise SelectionError("Declared dependency is unavailable: " + scope)
            return
        error = SelectionError(message + path)
        error.dependencies = set(edges)
        raise error
    for parent in PurePosixPath(path).parents:
        init = str(parent / "__init__.py")
        if init in inventory and init != path:
            edges.add(init)
    module_paths = {p[:-3].replace("/", "."): p for p in inventory if p.endswith(".py")}
    tokens = set(re.findall(r"[A-Za-z0-9_./-]+", source))
    strings = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    # Embedded scripts, filename lists, path joins and fixture roots are real
    # dependencies. Index names once per file rather than comparing every string
    # against every repository path.
    aliases, module_aliases, directories = {}, {}, {}
    for candidate in inventory:
        if candidate == path or is_document(candidate):
            continue
        item = PurePosixPath(candidate)
        for alias in (candidate, item.name):
            aliases.setdefault(alias, set()).add(candidate)
        if item.suffix == ".py":
            for alias in (item.stem, candidate[:-3].replace("/", ".")):
                module_aliases.setdefault(alias, set()).add(candidate)
        for start in range(1, len(item.parts)):
            aliases.setdefault("/".join(item.parts[start:]), set()).add(candidate)
        for directory in item.parents:
            if str(directory) != ".":
                directories.setdefault(str(directory), set()).add(candidate)
    for token in tokens:
        edges.update(aliases.get(token.removeprefix("./"), ()))

    assignments = {}
    import_bindings = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    assignments.setdefault(target.id, []).append(node.value)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                import_bindings[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.Import):
            for alias in node.names:
                import_bindings[alias.asname or alias.name] = alias.name
    def expression_literals(node, seen=None):
        seen = set() if seen is None else seen
        values = []
        if node is None:
            return values
        for part in ast.walk(node):
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                values.append(part.value)
            elif isinstance(part, ast.Name) and part.id in import_bindings:
                values.append(import_bindings[part.id])
            elif isinstance(part, ast.Name) and part.id not in seen:
                for value in assignments.get(part.id, ()):
                    values.extend(expression_literals(value, seen | {part.id}))
        return values
    def import_bounds(node, seen=frozenset()):
        # Every alternative must resolve; a known branch cannot authenticate an
        # unrelated parameter. __package__ is the fixed local loader context.
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}, set()
        if isinstance(node, ast.Name):
            if node.id == "__package__":
                return {"agent_tools", str(PurePosixPath(path).parent).replace("/", ".")}, set()
            if node.id in seen or node.id not in assignments:
                return None
            results = [import_bounds(value, seen | {node.id}) for value in assignments[node.id]]
            if any(result is None for result in results):
                return None
            return set().union(*(r[0] for r in results)), set().union(*(r[1] for r in results))
        if isinstance(node, ast.IfExp):
            results = [import_bounds(node.body, seen), import_bounds(node.orelse, seen)]
            if any(result is None for result in results):
                return None
            return results[0][0] | results[1][0], results[0][1] | results[1][1]
        if isinstance(node, ast.BoolOp):
            results = [import_bounds(value, seen) for value in node.values]
            if any(result is None for result in results):
                return None
            return set().union(*(r[0] for r in results)), set().union(*(r[1] for r in results))
        if isinstance(node, ast.JoinedStr):
            values = [part.value if isinstance(part, ast.FormattedValue) else part for part in node.values]
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            values = [node.left, node.right]
        else:
            return None
        prefixes, packages = {""}, set()
        for value in values:
            result = import_bounds(value, seen)
            if result is None:
                if prefixes and all(prefix.startswith("agent_tools.") for prefix in prefixes):
                    return set(), {"agent_tools"}
                return None
            if result[1]:
                packages.update(result[1]); continue
            prefixes = {prefix + suffix for prefix in prefixes for suffix in result[0]}
        return prefixes, packages

    # Directory names alone (including command data and write destinations)
    # are not source reads. Only actual readonly directory operations and the
    # source argument of copying/loading add a directory's finite children.
    def repository_path_context(expression, seen=frozenset()):
        for part in ast.walk(expression):
            if isinstance(part, ast.Name) and part.id not in seen:
                if part.id == "__file__":
                    return True
                if any(repository_path_context(value, seen | {part.id}) for value in assignments.get(part.id, ())):
                    return True
            if isinstance(part, ast.Call) and bounded_source_path(part, {}):
                constructor = isinstance(part.func, ast.Name) and part.func.id in path_constructors or isinstance(part.func, ast.Attribute) and part.func.attr == "Path" and isinstance(part.func.value, ast.Name) and part.func.value.id in pathlib_namespaces
                if constructor:
                    return True
        return False
    def directory_inputs(expression):
        found = set()
        for literal in expression_literals(expression):
            directory = literal.strip("/")
            if len(directory) < 3:
                continue
            for full, resources in directories.items():
                if "/" not in directory and directory not in {"agent_tools", "scripts", "fixtures"} and not repository_path_context(expression):
                    continue
                if full == directory or full.endswith("/" + directory):
                    found.update(resources)
        return found
    def literal_value(node, seen=frozenset()):
        if isinstance(node, ast.Name) and node.id not in seen and len(assignments.get(node.id, ())) == 1:
            return literal_value(assignments[node.id][0], seen | {node.id})
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, (ast.Tuple, ast.List)):
            return tuple(literal_value(value, seen) for value in node.elts)
        if isinstance(node, ast.Dict):
            return {literal_value(key, seen): literal_value(value, seen) for key, value in zip(node.keys, node.values)}
        raise ValueError("not a literal registry")
    source_loops = [node for node in ast.walk(tree) if isinstance(node, ast.For)]
    def reader_loop_bindings(reader):
        bindings = {}
        def bind(target, value):
            if isinstance(target, ast.Name) and isinstance(value, str):
                bindings.setdefault(target.id, set()).add(value)
            elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, (tuple, list)) and len(target.elts) == len(value):
                for item, component in zip(target.elts, value):
                    bind(item, component)
        for loop in source_loops:
            if not loop.lineno <= reader.lineno <= loop.end_lineno:
                continue
            try:
                if isinstance(loop.iter, ast.Call) and isinstance(loop.iter.func, ast.Attribute) and loop.iter.func.attr == "items" and not loop.iter.args and not loop.iter.keywords:
                    registry = literal_value(loop.iter.func.value)
                    values = registry.items() if isinstance(registry, dict) else ()
                else:
                    values = literal_value(loop.iter)
                if isinstance(values, (str, bytes, dict)):
                    continue
                for value in values:
                    bind(loop.target, value)
            except (ValueError, TypeError):
                continue
        return bindings
    path_constructors = {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module == "pathlib" for alias in node.names if alias.name == "Path"}
    pathlib_namespaces = {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names if alias.name == "pathlib"}
    def bounded_source_path(node, bindings, seen=frozenset()):
        if isinstance(node, ast.Constant):
            return isinstance(node.value, (str, int))
        if isinstance(node, ast.Name):
            if node.id == "__file__" or node.id in bindings:
                return True
            if node.id in seen or node.id not in assignments:
                return False
            return all(bounded_source_path(value, bindings, seen | {node.id}) for value in assignments[node.id])
        if isinstance(node, ast.Attribute):
            if node.attr == "__file__" and isinstance(node.value, ast.Name) and node.value.id in import_bindings:
                return bool(module_aliases.get(import_bindings[node.value.id]))
            return node.attr in {"parent", "parents", "name", "stem", "suffix"} and bounded_source_path(node.value, bindings, seen)
        if isinstance(node, ast.Subscript):
            return bounded_source_path(node.value, bindings, seen) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, int)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Div, ast.Add)):
            return bounded_source_path(node.left, bindings, seen) and bounded_source_path(node.right, bindings, seen)
        if isinstance(node, ast.IfExp):
            return bounded_source_path(node.body, bindings, seen) and bounded_source_path(node.orelse, bindings, seen)
        if isinstance(node, ast.Call):
            constructor = isinstance(node.func, ast.Name) and node.func.id in path_constructors or isinstance(node.func, ast.Attribute) and node.func.attr == "Path" and isinstance(node.func.value, ast.Name) and node.func.value.id in pathlib_namespaces
            if constructor:
                return all(bounded_source_path(value, bindings, seen) for value in node.args) and not node.keywords
            if isinstance(node.func, ast.Attribute) and node.func.attr in {"resolve", "absolute", "with_name", "with_suffix", "joinpath"}:
                return bounded_source_path(node.func.value, bindings, seen) and all(bounded_source_path(value, bindings, seen) for value in node.args) and not node.keywords
        return False
    for reader in ast.walk(tree):
        if not isinstance(reader, ast.Call):
            continue
        call = reader.func.attr if isinstance(reader.func, ast.Attribute) else getattr(reader.func, "id", "")
        call = import_bindings.get(call, call).split(".")[-1]
        if call in {"walk", "listdir"}:
            owner = reader.func.value if isinstance(reader.func, ast.Attribute) else None
            qualified_os = isinstance(owner, ast.Name) and import_bindings.get(owner.id) == "os"
            imported_os = isinstance(reader.func, ast.Name) and any(isinstance(node, ast.ImportFrom) and node.module == "os" and any((alias.asname or alias.name) == reader.func.id and alias.name == call for alias in node.names) for node in ast.walk(tree))
            if not qualified_os and not imported_os:
                continue
        expression = None
        directory_read = call in {"glob", "rglob", "iterdir", "listdir", "walk", "copytree"}
        if isinstance(reader.func, ast.Attribute) and call in {"read_text", "read_bytes", "glob", "rglob", "iterdir", "open"}:
            expression = reader.func.value
        elif call in {"copytree", "listdir", "walk", "open"} and reader.args:
            expression = reader.args[0]
        if expression is None:
            continue
        if call == "open":
            mode = next((keyword.value for keyword in reader.keywords if keyword.arg == "mode"), reader.args[0] if isinstance(reader.func, ast.Attribute) and reader.args else reader.args[1] if len(reader.args) > 1 else None)
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(character in mode.value for character in "wax"):
                continue
        resources = directory_inputs(expression)
        loop_bindings = reader_loop_bindings(reader)
        for values in loop_bindings.values():
            for value in values:
                edges.update(aliases.get(value, ()))
        def unbounded_suffix(node):
            if bounded_source_path(node, loop_bindings):
                return False
            names = [part for part in ast.walk(node) if isinstance(part, ast.Name)]
            return any(part.id not in loop_bindings and import_bounds(part) is None for part in names)
        dynamic = any(isinstance(n, ast.FormattedValue) and unbounded_suffix(n.value) or isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Div, ast.Add)) and not isinstance(n.right, ast.Constant) and unbounded_suffix(n.right) for n in ast.walk(expression))
        raw_name_suffix = isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div) and isinstance(expression.right, ast.Name) and not bounded_source_path(expression.right, loop_bindings)
        if raw_name_suffix and repository_path_context(expression):
            unknown("Unbounded absolute source-read suffix: ")
        known_input = resources or any(aliases.get(value) for value in expression_literals(expression))
        if known_input and any(isinstance(part, (ast.IfExp, ast.BoolOp)) and import_bounds(part) is None for part in ast.walk(expression)):
            unknown("Unbounded source-read alternative: ")
        elif resources and (directory_read or dynamic):
            if not bounded_source_path(expression, loop_bindings) or path in REVIEWED_DYNAMIC_DEPENDENCIES:
                unknown("Unbounded or reviewed source directory reader: ")
            else:
                edges.update(resources)
    for node in ast.walk(tree):
        names = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            parent = PurePosixPath(path).parent
            if node.level:
                for _ in range(node.level - 1):
                    parent = parent.parent
                base = str(parent).replace("/", ".") + ("." + node.module if node.module else "")
            else:
                base = node.module or ""
            names = [base] + [base + "." + a.name for a in node.names]
        for name in names:
            if name == "mcp" or name.startswith("mcp."):
                edges.add("agent_tools/requirements-mcp.txt")
            if name in module_paths:
                edges.add(module_paths[name])
            if name + ".__init__" in module_paths:
                edges.add(module_paths[name + ".__init__"])
            if "." not in name:
                local = str(PurePosixPath(path).parent / (name + ".py"))
                edges.update({local} if local in inventory else module_aliases.get(name, ()))
        if not isinstance(node, ast.Call):
            continue
        call = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        if call not in {"import_module", "__import__", "spec_from_file_location"}:
            continue
        argument = node.args[1] if call == "spec_from_file_location" and len(node.args) > 1 else (node.args[0] if node.args else None)
        literals = expression_literals(argument)
        for literal in literals:
            edges.update(module_aliases.get(literal.strip("."), ()))
            if literal.startswith("."):
                edges.update(module_aliases.get(literal[1:], ()))
        if call == "spec_from_file_location":
            # Generic source loaders bind all literal source/fixture candidates
            # in the same file. No such candidates means mapping is unknown.
            bindings = reader_loop_bindings(node)
            for values in bindings.values():
                for value in values:
                    edges.update(aliases.get(value, ()))
            if isinstance(argument, ast.Constant):
                edges.update(directories.get(argument.value, ()))
            alternatives = [part for part in ast.walk(argument) if isinstance(part, (ast.IfExp, ast.BoolOp))] if argument is not None else []
            bounded_alternatives = all((bound := import_bounds(part)) is not None and not bound[1] and all(aliases.get(value) or module_aliases.get(value.strip(".")) or directories.get(value.strip("/")) for value in bound[0]) for part in alternatives)
            if not bounded_source_path(argument, bindings) or not bounded_alternatives or not any(aliases.get(s) or module_aliases.get(s.strip(".")) or directories.get(s.strip("/")) for s in literals):
                unknown("Unresolved source loader: ")
        else:
            bounded = import_bounds(argument)
            if bounded is None:
                unknown("Unresolved dynamic import at line " + str(node.lineno) + ": ")
                continue
            modules, packages = bounded
            if packages:
                if path in REVIEWED_DYNAMIC_DEPENDENCIES:
                    unknown("Reviewed local dispatcher changed: ")
                else:
                    edges.update(p for p in inventory if p.startswith("agent_tools/") and p.endswith(".py"))
            for module in modules:
                if module_paths.get(module) == path:
                    continue
                if module.split(".")[0] in sys.stdlib_module_names:
                    continue
                if module == "mcp" or module.startswith("mcp."):
                    edges.add("agent_tools/requirements-mcp.txt"); continue
                resolved = module_aliases.get(module.strip("."), set())
                if resolved:
                    edges.update(resolved)
                else:
                    unknown("Unresolved dynamic import at line " + str(node.lineno) + ": ")
    return edges


def select_from_sources(sources, changed, baseline="inert", existing_tests=None):
    inventory = set(sources)
    tests = sorted(p for p in inventory if p.startswith("agent_tools/tests/test_") and p.endswith(".py") and sources[p] is not None and (existing_tests is None or p in existing_tests))
    changed = set(changed)
    relevant = {p for p in changed if not is_document(p) and potentially_agent_input(p)}
    if not relevant:
        return Selection(baseline, tuple(sorted(changed)), (), len(tests))
    graph, errors = {}, {}
    for path, text in sources.items():
        if is_python_source(path) and text is not None:
            graph[path] = set()
            for version in (text if isinstance(text, tuple) else (text,)):
                try:
                    graph[path].update(dependencies(path, version, inventory))
                except SelectionError as error:
                    errors[path] = error
                    graph[path].update(getattr(error, "dependencies", set()))
    # Script inputs are the finite source dependencies of production tools or
    # real imported test helpers. Product files cannot enroll agent suites merely
    # because a test reads their text.
    owned = set()
    for owner in graph:
        if owner.startswith("agent_tools/") and not owner.startswith("agent_tools/tests/"):
            pending = [owner]
            while pending:
                dependency = pending.pop()
                if dependency in owned:
                    continue
                owned.add(dependency); pending.extend(graph.get(dependency, ()))
        elif owner.startswith("agent_tools/tests/"):
            text = sources[owner]
            for version in (text if isinstance(text, tuple) else (text,)):
                try:
                    tree = ast.parse(version)
                except (SyntaxError, TypeError):
                    continue
                for node in ast.walk(tree):
                    base = node.module if isinstance(node, ast.ImportFrom) else None
                    if base and base.startswith("scripts"):
                        names = [base] + [base + "." + alias.name for alias in node.names]
                    elif isinstance(node, ast.Import):
                        names = [alias.name for alias in node.names if alias.name.startswith("scripts.")]
                    else:
                        names = []
                    for name in names:
                        candidate = name.replace(".", "/") + ".py"
                        if candidate in inventory:
                            owned.add(candidate)
    relevant = {p for p in relevant if not p.startswith("scripts/") or p in owned}
    if not relevant:
        return Selection(baseline, tuple(sorted(changed)), (), len(tests))
    if errors and any(p.startswith("agent_tools/") or is_python_source(p) for p in relevant):
        raise errors[sorted(errors)[0]]
    selected = []
    consumed = set()
    for test in tests:
        reachable, pending = set(), [test]
        while pending:
            path = pending.pop()
            if path in reachable:
                continue
            reachable.add(path)
            pending.extend(graph.get(path, ()))
        if reachable & relevant:
            for path in sorted(reachable & set(errors)):
                raise errors[path]
            selected.append(test)
            consumed.update(reachable & relevant)
    unmapped = {p for p in relevant if p.startswith("agent_tools/") and p not in consumed and not p.startswith("agent_tools/tests/test_")}
    if unmapped:
        raise SelectionError("Changed agent dependency has no known consumers: " + ", ".join(sorted(unmapped)))
    return Selection(baseline, tuple(sorted(changed)), tuple(p[:-3].replace("/", ".") for p in selected), len(tests))


def select(root, baseline=None, audit=False):
    root = Path(root)
    baseline = git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip() if audit and baseline is None else baseline_for(root, baseline)
    changed = changed_paths(root, baseline)
    current = set(git(root, "ls-files", "-z").decode().split("\0")) - {""}
    current.update(set(git(root, "ls-files", "--others", "--exclude-standard", "-z").decode().split("\0")) - {""})
    previous = set(git(root, "ls-tree", "-r", "--name-only", "-z", baseline).decode().split("\0")) - {""}
    if audit or not any(not is_document(p) and potentially_agent_input(p) for p in changed):
        modules = tuple(sorted(p[:-3].replace("/", ".") for p in current if p.startswith("agent_tools/tests/test_") and p.endswith(".py") and (root / p).is_file()))
        return Selection(baseline, tuple(sorted(changed)), modules if audit else (), len(modules))
    sources = {}
    for path in current | previous:
        target = root / path
        sources[path] = read_source(path, target.read_bytes()) if target.is_file() and is_python_source(path) else None
    # Old imports/resources must survive removed edges and deleted source files.
    for path in changed & previous:
        if is_python_source(path):
            old = read_source(path, git(root, "show", baseline + ":" + path))
            if sources[path] is None:
                sources[path] = old
            else:
                sources[path] = (sources[path], old)
    return select_from_sources(sources, changed, baseline, {p for p in current if (root / p).is_file()})


def snapshot(root):
    """Same path/mode/content fingerprint as the managed prepush receipt."""
    names = set(git(root, "ls-files", "-z").decode().split("\0"))
    names.update(git(root, "ls-files", "--others", "--exclude-standard", "-z").decode().split("\0"))
    digest = hashlib.sha256()
    for name in sorted(names - {""}):
        path = Path(root) / name
        if path.is_file():
            digest.update(name.encode("utf-8", errors="surrogateescape")); digest.update(b"\0")
            digest.update(str(path.stat().st_mode & 0o777).encode("ascii")); digest.update(b"\0")
            digest.update(path.read_bytes()); digest.update(b"\0")
    return digest.hexdigest()


def serial_command(root, command, fingerprint):
    result = [command[0], str(Path(root).resolve() / "agent_tools/agent_test_runner.py"),
              "--serial-stdout", "--source-fingerprint", fingerprint]
    for name in command[3:]:
        result.extend(["--test-id", name])
    return result


def prepare_run(root, command, fingerprint):
    """Reserve a private retained plan only after planning/source gates pass."""
    gate = "agent_tools.tests.test_ssh_connection_session_close"
    if len(command) < 4 or command[1:3] != ["-m", "unittest"] or command[3:] == [gate]:
        return list(command)
    if os.name != "posix":
        return serial_command(root, command, fingerprint)
    root = Path(root).resolve()
    parent = root / ".rag_index" / "agent-test-runs"
    for ancestor in [parent, *parent.parents]:
        if ancestor.exists() and stat.S_ISLNK(ancestor.lstat().st_mode):
            raise SelectionError("Agent test report path cannot contain symlinks")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise SelectionError("Agent test report parent must be private and owned")
    token = str(uuid.uuid4())
    plan = parent / (token + ".plan.json")
    value = {"schemaVersion": 1, "sourceFingerprint": fingerprint, "modules": command[3:], "maxWorkers": 2}
    fd = os.open(plan, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    return [command[0], str(root / "agent_tools/agent_test_runner.py"), "--plan-file", str(plan), "--report-dir", str(parent / token)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--baseline")
    parser.add_argument("--audit", action="store_true", help="Intentional full suite audit")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--include", nargs="+", help="Run only these existing CI test IDs when their agent module is affected; explicit script IDs remain product checks")
    args = parser.parse_args(argv)
    try:
        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != LOADED_SELECTOR_SOURCE_SHA256 or hashlib.sha256(DEPENDENCY_MANIFEST.read_bytes()).hexdigest() != LOADED_DEPENDENCY_MANIFEST_SHA256:
            raise SelectionError("Agent test selector or dependency metadata changed after loading")
        fingerprint = snapshot(args.root) if args.run else None
        selection = select(args.root, args.baseline, args.audit)
    except SelectionError as error:
        print(json.dumps({"ok": False, "selectionError": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(selection.as_dict(), indent=2), flush=True)
    if args.run:
        commands = selection.commands(sys.executable)
        if args.include is not None:
            ids = [name for name in args.include if name.startswith("scripts.") or any(name == module or name.startswith(module + ".") for module in selection.modules)]
            print(json.dumps({"selectedTestIds": ids, "selectedTestIdCount": len(ids)}), flush=True)
            commands = [[sys.executable, "-m", "unittest", *ids]] if ids else []
        if snapshot(args.root) != fingerprint:
            print("Repository changed after selection; regenerate the test plan", file=sys.stderr)
            return 2
        for command in commands:
            if args.include is None:
                command = prepare_run(args.root, command, fingerprint)
            else:
                command = serial_command(args.root, command, fingerprint)
            result = subprocess.run(command, cwd=args.root)
            if result.returncode:
                return result.returncode
        if snapshot(args.root) != fingerprint:
            print("Repository changed during selected tests; no valid completed check", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
