#!/usr/bin/env python3
"""Select agent unittest modules from Git and their transitive local dependencies.

No test module is imported during planning. The graph joins precise static edges
(imports, literal module loads, literal repository paths and declared scopes)
with the per-test footprints CI records. Local selection is precise, not
complete: CI runs the complete agent suite on every agent-input change.
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
from types import MappingProxyType


# Declared extra edges for sources whose loads no static rule can see. A
# declaration is keyed by path only: CI runs the complete agent suite on any
# agent-input change, so local selection may be precise rather than complete.
LOADED_SELECTOR_SOURCE_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
DEPENDENCY_MANIFEST = Path(__file__).with_name("affected_agent_test_dependencies.json")
_DEPENDENCY_MANIFEST_BYTES = DEPENDENCY_MANIFEST.read_bytes()
LOADED_DEPENDENCY_MANIFEST_SHA256 = hashlib.sha256(_DEPENDENCY_MANIFEST_BYTES).hexdigest()
_DECLARATIONS = json.loads(_DEPENDENCY_MANIFEST_BYTES)
if _DECLARATIONS.get("schemaVersion") != 2 or set(_DECLARATIONS) != {"schemaVersion", "loaders"}:
    raise RuntimeError("Unsupported agent dependency manifest")
REVIEWED_DYNAMIC_DEPENDENCIES = _DECLARATIONS["loaders"]
# Whole-tree scopes and server adapter registries connect one file to hundreds
# of others. Footprints record what each test actually loads instead.
HUB_SCOPES = frozenset({"agent_tools/", "scripts/", "@modules:_VM_NATIVE_ADAPTERS", "@files:_KEEPER_ROLES"})
# Recorded per-test footprints (agent_test_footprints.py), fetched from CI.
FOOTPRINT_CACHE = Path(".rag_index") / "agent-test-footprints.json"


class SelectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class Selection:
    baseline: str
    changed: tuple[str, ...]
    modules: tuple[str, ...]
    total_modules: int
    footprint_commit: str | None = None
    unconsumed: tuple[str, ...] = ()

    def as_dict(self):
        return {"baseline": self.baseline, "changedPaths": list(self.changed),
                "modules": list(self.modules), "selectedModuleCount": len(self.modules),
                "totalModuleCount": self.total_modules, "footprintCommit": self.footprint_commit,
                "unconsumedPaths": list(self.unconsumed)}

    def commands(self, python: str, *, max_modules_per_command: int | None = None):
        if max_modules_per_command is not None and (type(max_modules_per_command) is not int
                                                    or not 1 <= max_modules_per_command <= 2000):
            raise SelectionError("Invalid managed test batch size")
        modules = list(self.modules)
        gate = "agent_tools.tests.test_ssh_connection_session_close"
        result = []
        if gate in modules:
            result.append([python, "-m", "unittest", gate])
            modules.remove(gate)
        if modules:
            size = max_modules_per_command or len(modules)
            for start in range(0, len(modules), size):
                result.append([python, "-m", "unittest", *modules[start:start + size]])
        return result


# Hosted Fast Checks runs this many explicit agent shards, each its own job and
# receipt. The managed local stage keeps two halves of the same sorted
# alternating partition; with an even hosted count each half is exactly the
# union of the hosted shards whose index has its parity.
CI_SHARD_COUNT = 6


def shard_selection(selection, index, count):
    """Partition the complete already-validated plan, never dependency discovery."""
    if (type(index) is not int or type(count) is not int or count not in (2, CI_SHARD_COUNT)
            or not 0 <= index < count):
        raise SelectionError("Shards require count 2 (managed halves) or %d (hosted CI) and an index below it"
                             % CI_SHARD_COUNT)
    modules = tuple(sorted(selection.modules))
    if len(modules) != len(set(modules)):
        raise SelectionError("Duplicate global test module")
    return Selection(selection.baseline, selection.changed, modules[index::count], selection.total_modules)


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
                data = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
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
PROSE_FILES = {"README.md", "AGENTS.md", "CLAUDE.md", "agent_tools/README.md"}
# Tracked client configuration outside agent_tools/ that tests must consume.
ROOT_AGENT_CONFIG = {".mcp.json", ".claude/settings.json"}


def is_document(path):
    # Product version-only metadata is intentionally covered by product/release
    # checks. Markdown/RST under tool data or fixtures remains executable input.
    if path in VERSION_ONLY_METADATA:
        return True
    return path.endswith((".md", ".rst")) and (path in PROSE_FILES or path.startswith(("docs/", "agent_docs/")))


def potentially_agent_input(path):
    return path.startswith(("agent_tools/", "scripts/", ".github/workflows/")) or path in {".github/required-workflows.json", ".codex/config.toml", ".gitattributes", *ROOT_AGENT_CONFIG}


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


_LITERAL_FANOUT = 64


def _inventory_indexes(inventory):
    """Exact path indexes; a bare file name never names a file by itself."""
    module_paths = {p[:-3].replace("/", "."): p for p in inventory if p.endswith(".py")}
    paths, directories, fixtures = {}, {}, {}
    for candidate in inventory:
        if is_document(candidate):
            continue
        parts = PurePosixPath(candidate).parts
        # A literal names a file by its full path or by a tail of two or more
        # parts, and a directory the same way; a bare file name names nothing.
        for start in range(0, len(parts) - 1):
            paths.setdefault("/".join(parts[start:]), set()).add(candidate)
        for end in range(1, len(parts)):
            for start in range(0, end):
                if start == 0 or end - start >= 2:
                    directories.setdefault("/".join(parts[start:end]), set()).add(candidate)
        if candidate.startswith("agent_tools/tests/fixtures/") and len(parts) > 4:
            fixtures.setdefault(parts[3], set()).add(candidate)
    top_level = {}
    for candidate in inventory:
        if candidate.endswith(".py") and candidate.count("/") == 1 and candidate.startswith(("agent_tools/", "scripts/")):
            top_level.setdefault(PurePosixPath(candidate).name, set()).add(candidate)
    freeze = lambda entries: MappingProxyType({key: frozenset(values) for key, values in entries.items()})
    return (MappingProxyType(module_paths), freeze(paths), freeze(directories), freeze(fixtures),
            MappingProxyType({name: next(iter(values)) for name, values in top_level.items() if len(values) == 1}))


def _analysis(path, source):
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError):
        return None
    return tree, tuple(ast.walk(tree))


def dependencies(path, source, inventory):
    """Precise static edges: imports, literal module loads and literal repository paths."""
    return _dependencies(path, source, inventory, _inventory_indexes(inventory))


def _declared(path, tree, inventory):
    declaration = REVIEWED_DYNAMIC_DEPENDENCIES.get(path)
    edges = set()
    if not declaration:
        return edges
    for scope in declaration["scopes"]:
        if scope in HUB_SCOPES:
            continue
        if scope.startswith("@"):
            kind, constant = scope[1:].split(":", 1)
            definitions = [] if tree is None else [
                n.value for n in tree.body if isinstance(n, (ast.Assign, ast.AnnAssign))
                and any(isinstance(t, ast.Name) and t.id == constant for t in (n.targets if isinstance(n, ast.Assign) else [n.target]))]
            try:
                values = ast.literal_eval(definitions[0]) if len(definitions) == 1 else ()
            except (ValueError, TypeError):
                values = ()
            for value in values if isinstance(values, (tuple, list)) else ():
                if isinstance(value, str):
                    candidate = "agent_tools/" + value + ".py" if kind == "modules" else value if "/" in value else "agent_tools/" + value
                    if candidate in inventory:
                        edges.add(candidate)
        elif scope.endswith("/*.py"):
            parent = scope[:-5]
            edges.update(p for p in inventory if str(PurePosixPath(p).parent) == parent and p.endswith(".py"))
        elif scope.endswith("/"):
            edges.update(p for p in inventory if p.startswith(scope))
        elif scope in inventory:
            edges.add(scope)
    return edges


def _package_literal(literal, files, inventory):
    """Whether a directory literal names a Python package rather than data."""
    for path in files:
        index = ("/" + path).find("/" + literal + "/")
        if index >= 0 and path[:index + len(literal)] + "/__init__.py" in inventory:
            return True
    return False


def _dependencies(path, source, inventory, indexes, analysis=None):
    module_paths, paths, directories, fixtures, top_level = indexes
    analysis = analysis if analysis is not None else _analysis(path, source)
    tree, nodes = analysis if analysis is not None else (None, ())
    edges = _declared(path, tree, inventory)
    for parent in PurePosixPath(path).parents:
        init = str(parent / "__init__.py")
        if init in inventory and init != path:
            edges.add(init)
    directory = PurePosixPath(path).parent
    is_test = path.startswith(("agent_tools/tests/", "scripts/test_", "scripts/testdata/"))

    def module(name):
        if name == "mcp" or name.startswith("mcp."):
            edges.add("agent_tools/requirements-mcp.txt")
        for candidate in (name, name + ".__init__"):
            if candidate in module_paths:
                edges.add(module_paths[candidate])
        if name and "." not in name:
            # Bare imports resolve the way the repository's sys.path entries do.
            for candidate in (str(directory / (name + ".py")), "agent_tools/" + name + ".py", "scripts/" + name + ".py"):
                if candidate in inventory:
                    edges.add(candidate)
                    break

    # A production module's import inside a function runs only when that code
    # runs; CI footprints record the lazy imports tests actually exercise.
    lazy = set()
    if not is_test:
        for outer in nodes:
            if isinstance(outer, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                lazy.update(id(inner) for inner in ast.walk(outer) if isinstance(inner, (ast.Import, ast.ImportFrom, ast.Call)))
    for node in nodes:
        if id(node) in lazy:
            continue
        if isinstance(node, ast.Import):
            for alias in node.names:
                module(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parent = directory
                for _ in range(node.level - 1):
                    parent = parent.parent
                base = ".".join(part for part in (str(parent).replace("/", "."), node.module or "") if part)
            else:
                base = node.module or ""
            module(base)
            for alias in node.names:
                module(base + "." + alias.name if base else alias.name)
        elif isinstance(node, ast.Call):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            literals = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            if name in {"import_module", "__import__"}:
                for literal in literals[:1]:
                    module(literal.strip("."))
        elif is_test and isinstance(node, ast.Constant) and isinstance(node.value, str) and len(node.value) <= 512:
            # Tests and their fixtures name the files they read. A production
            # source registry (shipped closures, reviewed roles) is not a test
            # dependency of every importer; recorded footprints cover its reads.
            literal = node.value.strip().removeprefix("./").strip("/")
            if not literal or "\n" in literal:
                continue
            if "/" in literal:
                # A package or fixtures root is not a resource; recorded
                # footprints name the files a test actually reads under it.
                folder = directories.get(literal, ())
                if folder and _package_literal(literal, folder, inventory):
                    # Packages are linked by their imports, not by their names.
                    folder = ()
                for found in (paths.get(literal, ()), folder):
                    if len(found) <= _LITERAL_FANOUT:
                        edges.update(found)
            elif literal in inventory:
                edges.add(literal)
            elif literal.endswith(".py") and literal in top_level:
                edges.add(top_level[literal])
            elif literal in fixtures and ("_" in literal or "-" in literal):
                edges.update(fixtures[literal])
    edges.discard(path)
    return edges


def load_footprints(root):
    """Recorded edges from the newest fetched CI footprint table, or None."""
    try:
        value = json.loads((Path(root) / FOOTPRINT_CACHE).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (not isinstance(value, dict) or value.get("schemaVersion") != 1 or not isinstance(value.get("edges"), dict)
            or not isinstance(value.get("directories", {}), dict)):
        return None
    return value


@dataclass(frozen=True)
class Graph:
    """Forward edges of one inventory; build once, query for any change set."""
    inventory: frozenset
    edges: MappingProxyType
    owned_scripts: frozenset
    footprint_commit: str | None
    listings: MappingProxyType = MappingProxyType({})

    def reverse(self):
        reverse = {}
        for owner, dependencies_ in self.edges.items():
            for dependency in dependencies_:
                reverse.setdefault(dependency, set()).add(owner)
        return reverse


def build_graph(sources, footprints=None):
    inventory = set(sources)
    graph, script_inputs = {}, {}
    indexes = _inventory_indexes(inventory)
    for path, text in sources.items():
        if is_python_source(path) and text is not None:
            graph[path] = set()
            for version in (text if isinstance(text, tuple) else (text,)):
                analysis = _analysis(path, version)
                if analysis is not None and path.startswith("agent_tools/tests/"):
                    imported = script_inputs.setdefault(path, set())
                    for node in analysis[1]:
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
                                imported.add(candidate)
                graph[path].update(_dependencies(path, version, inventory, indexes, analysis))
        elif path in REVIEWED_DYNAMIC_DEPENDENCIES:
            graph.setdefault(path, set()).update(_declared(path, None, inventory))
    # Recorded footprints add what each test and module actually opened, listed
    # or compiled; a listed directory covers its current children.
    for owner, files in (footprints or {}).get("edges", {}).items():
        if owner in inventory and isinstance(files, list):
            graph.setdefault(owner, set()).update(p for p in files if p in inventory and p != owner)
    # A listed directory depends on its names, not on its files' bytes: only an
    # added or removed child selects the lister.
    listings = {}
    for owner, folders in (footprints or {}).get("directories", {}).items():
        if owner in inventory and isinstance(folders, list):
            for folder in folders:
                if isinstance(folder, str) and folder:
                    listings.setdefault(folder.rstrip("/"), set()).add(owner)
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
            owned.update(script_inputs.get(owner, ()))
    return Graph(frozenset(inventory), MappingProxyType({k: frozenset(v) for k, v in graph.items()}), frozenset(owned),
                 footprints.get("sourceCommit") if footprints else None,
                 MappingProxyType({k: frozenset(v) for k, v in listings.items()}))


def select_from_graph(graph, tests, changed, baseline="inert", reverse=None, structural=frozenset()):
    """structural: the changed paths that were added or removed."""
    changed = set(changed)
    relevant = {p for p in changed if not is_document(p) and potentially_agent_input(p)}
    relevant = {p for p in relevant if not p.startswith("scripts/") or p in graph.owned_scripts}
    if not relevant:
        return Selection(baseline, tuple(sorted(changed)), (), len(tests), footprint_commit=graph.footprint_commit)
    reverse = graph.reverse() if reverse is None else reverse
    listers = {owner for p in relevant & set(structural) for owner in graph.listings.get(str(PurePosixPath(p).parent), ())}
    affected, pending = set(), list(relevant | listers)
    while pending:
        path = pending.pop()
        if path in affected:
            continue
        affected.add(path)
        pending.extend(reverse.get(path, ()))
    selected = [test for test in tests if test in affected]
    reachable, pending = set(), list(selected)
    while pending:
        path = pending.pop()
        if path in reachable:
            continue
        reachable.add(path)
        pending.extend(graph.edges.get(path, ()))
    # A changed agent file no selected test reaches is reported, not refused:
    # CI runs the complete suite on every agent-input change (TEST-004).
    unconsumed = tuple(sorted(p for p in relevant - reachable
                              if (p.startswith("agent_tools/") or p in ROOT_AGENT_CONFIG) and not p.startswith("agent_tools/tests/test_")))
    return Selection(baseline, tuple(sorted(changed)), tuple(p[:-3].replace("/", ".") for p in selected), len(tests),
                     footprint_commit=graph.footprint_commit, unconsumed=unconsumed)


def test_paths(sources, existing_tests=None):
    return sorted(p for p in sources if p.startswith("agent_tools/tests/test_") and p.endswith(".py") and sources[p] is not None
                  and (existing_tests is None or p in existing_tests))


def select_from_sources(sources, changed, baseline="inert", existing_tests=None, footprints=None, structural=frozenset()):
    tests = test_paths(sources, existing_tests)
    if not any(not is_document(p) and potentially_agent_input(p) for p in changed):
        return Selection(baseline, tuple(sorted(set(changed))), (), len(tests),
                         footprint_commit=footprints.get("sourceCommit") if footprints else None)
    return select_from_graph(build_graph(sources, footprints), tests, changed, baseline, structural=structural)


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
    existing = {p for p in current if (root / p).is_file()}
    return select_from_sources(sources, changed, baseline, existing, footprints=load_footprints(root),
                               structural=frozenset(changed - (existing & previous)))


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


def prepare_run(root, command, fingerprint, changed=None):
    """Reserve a private retained plan only after planning/source gates pass.

    `changed` is the selection's changed path set; with it, TEST-001 RED halves
    whose test, beforeimage and closure are unchanged are skipped and recorded
    (agent_tools/tests/red_gate.py). None runs every RED half.
    """
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
    if changed is not None:
        value["changedPaths"] = sorted(changed)
    fd = os.open(plan, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    return [command[0], str(root / "agent_tools/agent_test_runner.py"), "--plan-file", str(plan), "--report-dir", str(parent / token)]


def test_interpreter(root):
    """Use the same prepared runtime as MCP; CI may use its prepared system Python."""
    root=Path(root).resolve()
    for relative in (".agent_venv/bin/python",".agent_venv/Scripts/python.exe"):
        candidate=root/relative
        if candidate.is_file() and os.access(candidate,os.X_OK):return str(candidate)
    return sys.executable


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--baseline")
    parser.add_argument("--audit", action="store_true", help="Intentional full suite audit")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--include", nargs="+", help="Run only these existing CI test IDs when their agent module is affected; explicit script IDs remain product checks")
    parser.add_argument("--shard-index", type=int, help="Explicit hosted CI bucket, 0 to %d" % (CI_SHARD_COUNT - 1))
    parser.add_argument("--shard-count", type=int, help="Explicit hosted CI bucket count, currently %d" % CI_SHARD_COUNT)
    parser.add_argument("--ci-evidence-dir", type=Path, help="New public CI evidence directory; requires explicit shard and --run")
    args = parser.parse_args(argv)
    sharded = args.shard_index is not None or args.shard_count is not None
    if sharded and (args.shard_index not in range(CI_SHARD_COUNT) or args.shard_count != CI_SHARD_COUNT
                    or args.include is not None):
        parser.error("Both shard arguments require count %d, an index from 0 to %d, and no --include"
                     % (CI_SHARD_COUNT, CI_SHARD_COUNT - 1))
    if args.ci_evidence_dir is not None and (not sharded or not args.run):
        parser.error("Public CI evidence requires explicit shards and --run")
    try:
        if hashlib.sha256(Path(__file__).read_bytes()).hexdigest() != LOADED_SELECTOR_SOURCE_SHA256 or hashlib.sha256(DEPENDENCY_MANIFEST.read_bytes()).hexdigest() != LOADED_DEPENDENCY_MANIFEST_SHA256:
            raise SelectionError("Agent test selector or dependency metadata changed after loading")
        fingerprint = snapshot(args.root) if args.run else None
        selection = select(args.root, args.baseline, args.audit)
    except SelectionError as error:
        print(json.dumps({"ok": False, "selectionError": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps(selection.as_dict(), indent=2), flush=True)
    global_selection = selection
    if sharded:
        selection = shard_selection(selection, args.shard_index, args.shard_count)
        print(json.dumps({"shardIndex": args.shard_index, "shardCount": args.shard_count,
                          "assignedModules": list(selection.modules)}, sort_keys=True), flush=True)
    if args.run:
        evidence = None
        if args.ci_evidence_dir is not None:
            # The explicit CI branch alone needs the public projector. Existing
            # MCP/default/include dispatch and copied-source closures stay exact.
            if __package__:
                from .agent_ci_evidence import Evidence, plan_value
            else:
                from agent_ci_evidence import Evidence, plan_value
            try:
                head = git(args.root, "rev-parse", "HEAD").decode().strip()
                public_plan = plan_value(baseline=selection.baseline, head=head, fingerprint=fingerprint,
                                         modules=list(global_selection.modules), index=args.shard_index,
                                         run_id=os.environ.get("GITHUB_RUN_ID", "local"),
                                         attempt=os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
                evidence = Evidence(args.ci_evidence_dir, public_plan)
            except (OSError, ValueError, KeyError, TypeError):
                print("Public CI evidence admission refused", file=sys.stderr)
                return 2
        python = test_interpreter(args.root)
        commands = selection.commands(python)
        if args.include is not None:
            ids = [name for name in args.include if name.startswith("scripts.") or any(name == module or name.startswith(module + ".") for module in selection.modules)]
            print(json.dumps({"selectedTestIds": ids, "selectedTestIdCount": len(ids)}), flush=True)
            commands = [[python, "-m", "unittest", *ids]] if ids else []
        if snapshot(args.root) != fingerprint:
            print("Repository changed after selection; regenerate the test plan", file=sys.stderr)
            if evidence is not None:
                evidence.finish(2, False)
            return 2
        for command in commands:
            modules = list(command[3:])
            if args.include is None:
                # An explicit audit without a baseline re-proves every RED half.
                red_changed = None if args.audit and args.baseline is None else global_selection.changed
                command = prepare_run(args.root, command, fingerprint, red_changed)
            else:
                command = serial_command(args.root, command, fingerprint)
            if evidence is None:
                # Selected tests never read this selector's own stdin stream.
                code = subprocess.run(command, cwd=args.root, stdin=subprocess.DEVNULL).returncode
            else:
                report_dir = Path(command[command.index("--report-dir") + 1]) if "--report-dir" in command else None
                try:
                    code = evidence.run(command, args.root, modules, report_dir)
                except (OSError, ValueError, KeyError, TypeError):
                    print("Public CI evidence collection failed", file=sys.stderr)
                    code = 2
            if code:
                if evidence is not None:
                    evidence.finish(code, snapshot(args.root) == fingerprint)
                return code
        unchanged = snapshot(args.root) == fingerprint
        if evidence is not None and not evidence.finish(0, unchanged):
            return 2
        if not unchanged:
            print("Repository changed during selected tests; no valid completed check", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
