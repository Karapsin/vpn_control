"""TEST-001 RED halves run when their proof could have changed (S10).

A RED half re-proves that a regression fails on preserved unfixed source. Its
result can change only when the test, its beforeimage, or code the test imports
changes. The agent test runner passes the changed repository paths of the
current comparison in AGENT_TEST_CHANGED_PATHS_FILE (a JSON list).

red_required(test, *beforeimages) is True when:
  * no changed set is given (plain unittest, explicit audits, serial CI), or
  * the test module, any named beforeimage, or any file in the test module's
    closure is in the changed set. The closure follows static imports of
    agent_tools and agent_tools.tests modules (module and function level) and,
    when a CI footprint table is cached (agent_test_footprints), every file the
    test module and those modules were recorded reading, compiling or importing.

Every decision is recorded with the digests that justify it in
AGENT_TEST_RED_RECORD (JSON lines), so a skipped RED half names the unchanged
test, beforeimage and closure bytes of the RED proof it relies on.
"""
from __future__ import annotations

import ast
import functools
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
CHANGED_ENV = "AGENT_TEST_CHANGED_PATHS_FILE"
RECORD_ENV = "AGENT_TEST_RED_RECORD"


@functools.lru_cache(maxsize=None)
def _changed(source):
    if not source:
        return None
    value = json.loads(Path(source).read_text(encoding="utf-8"))
    if type(value) is not list or any(type(item) is not str for item in value):
        raise ValueError("Invalid changed path list")
    return frozenset(value)


def changed_paths():
    """The changed repository paths, or None when every RED half must run."""
    return _changed(os.environ.get(CHANGED_ENV, ""))


def _module_path(name):
    if name != "agent_tools" and not name.startswith("agent_tools."):
        return None
    relative = name.replace(".", "/")
    for candidate in (relative + ".py", relative + "/__init__.py"):
        if (ROOT / candidate).is_file():
            return candidate
    return None


@functools.lru_cache(maxsize=None)
def _imports(path):
    package = path[:-3].replace("/", ".").rsplit(".", 1)[0]
    if path.endswith("/__init__.py"):
        package = path[:-len("/__init__.py")].replace("/", ".")
    found = set()
    for node in ast.walk(ast.parse((ROOT / path).read_bytes(), filename=path)):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package.split(".")
                base = base[:len(base) - node.level + 1]
                module = ".".join(base + ([node.module] if node.module else []))
            else:
                module = node.module or ""
            names = [module] + [module + "." + alias.name for alias in node.names]
        else:
            continue
        for name in names:
            target = _module_path(name)
            if target is not None and target != path:
                found.add(target)
    return frozenset(found)


@functools.lru_cache(maxsize=None)
def _footprints():
    try:
        value = json.loads((ROOT / ".rag_index" / "agent-test-footprints.json").read_text(encoding="utf-8"))
        edges = value["edges"]
        return {owner: frozenset(paths) for owner, paths in edges.items()}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


@functools.lru_cache(maxsize=None)
def closure(path):
    """`path` and every repository file it imports or was recorded using, transitively."""
    recorded = _footprints()
    seen, pending = set(), [path]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current.endswith(".py") and (ROOT / current).is_file():
            pending.extend(_imports(current))
        pending.extend(recorded.get(current, ()))
    return frozenset(seen)


def _relative(path):
    path = Path(path).resolve()
    return path.relative_to(ROOT).as_posix()


def _digest(relative):
    target = ROOT / relative
    return hashlib.sha256(target.read_bytes()).hexdigest() if target.is_file() else None


def red_required(test, *beforeimages):
    """Whether this test's RED half must run now; records the decision."""
    module = sys.modules[type(test).__module__]
    source = _relative(module.__file__)
    images = tuple(sorted(_relative(path) for path in beforeimages))
    changed = changed_paths()
    if changed is None:
        required, reason = True, "no-changed-set"
    elif source in changed or changed.intersection(images):
        required, reason = True, "test-or-beforeimage-changed"
    elif changed & closure(source):
        required, reason = True, "imported-module-changed"
    else:
        required, reason = False, "unchanged"
    _record(test, source, images, required, reason)
    return required


def _record(test, source, images, required, reason):
    target = os.environ.get(RECORD_ENV)
    if not target:
        return
    entry = {"schemaVersion": 1, "test": test.id(), "red": "ran" if required else "skipped", "reason": reason,
             "testSource": {source: _digest(source)}, "beforeimages": {path: _digest(path) for path in images},
             "closureSha256": hashlib.sha256("".join(
                 "%s %s\n" % (path, _digest(path)) for path in sorted(closure(source))).encode()).hexdigest()}
    with open(target, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")
