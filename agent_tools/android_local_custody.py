"""Closed local imports for the fixed Android original-lease custody adapter.

These are internal preparation helpers, not a public source execution API.
The native caller supplies held, authenticated snapshots and retains their
identities through the local effect. No named import or bytecode cache supplies
the continuity validator, bundle readers, retirement primitive or local adapter.
"""
from __future__ import annotations

import ast
import builtins
import hashlib
import re
from pathlib import Path
import symtable
import types

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_ROLES = frozenset(("continuity", "retirement", "bundle", "adapter"))
_LOCAL_PRELUDE = '''import pathlib
def _pin(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]
'''


def _need(condition, reason):
    if not condition:
        raise ValueError(reason)


def _verified(raw: bytes, expected_sha256: str) -> bytes:
    _need(type(raw) is bytes and 0 < len(raw) <= 8 * 1024 ** 2
          and type(expected_sha256) is str and _SHA.fullmatch(expected_sha256)
          and hashlib.sha256(raw).hexdigest() == expected_sha256,
          "local_custody_source_changed")
    compile(raw, "captured-local-custody-source", "exec", dont_inherit=True)
    return raw


def _bound(source: bytes) -> None:
    """Check this adapter's assembled namespace before its first native call."""
    table = symtable.symtable(source, "captured-local-custody-adapter", "exec")
    referenced_names = {node.id for node in ast.walk(ast.parse(source))
                        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)}
    declared = {symbol.get_name() for symbol in table.get_symbols()
                if symbol.is_assigned() or symbol.is_imported() or symbol.is_namespace()}
    available = declared | set(dir(builtins)) | {"__name__", "__file__", "__builtins__"}
    missing = set()

    def inspect(scope):
        for symbol in scope.get_symbols():
            if (symbol.is_referenced() and symbol.is_global()
                    and symbol.get_name() in referenced_names
                    and symbol.get_name() not in available):
                missing.add(symbol.get_name())
        for child in scope.get_children():
            inspect(child)

    inspect(table)
    _need(not missing, "local_custody_unbound_globals:" + ",".join(sorted(missing)))


def local_adapter_source(source: bytes, expected_sha256: str) -> bytes:
    """Bind the actual local FD9/Path names, then refuse other missing globals.

    The remote protected header defines its own _pin inside a string. That does
    not bind the caller's local namespace. The explicit local prelude is part of
    the returned reviewed source, retaining the complete original adapter bytes.
    """
    original = _verified(source, expected_sha256)
    tree = ast.parse(original)
    # A future import must remain ahead of executable statements. Keep the
    # original module docstring/future preamble without changing function bytes.
    insertion = 0
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant) and isinstance(tree.body[0].value.value, str):
        insertion = tree.body[0].end_lineno
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            insertion = node.end_lineno
    lines = original.splitlines(keepends=True)
    prepared = (b"".join(lines[:insertion]) + b"\n" + _LOCAL_PRELUDE.encode()
                + b"\n" + b"".join(lines[insertion:]))
    _bound(prepared)
    compile(prepared, "captured-local-custody-adapter", "exec", dont_inherit=True)
    return prepared


def _retirement_definitions(raw: bytes, expected_sha256: str) -> bytes:
    """Call the real factories from one authenticated whole source snapshot."""
    text = _verified(raw, expected_sha256).decode("utf-8", "strict")
    tree = ast.parse(text)
    definitions = []
    for name in ("component_admission_source", "component_release_source"):
        nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name == name]
        _need(len(nodes) == 1 and not nodes[0].decorator_list,
              "local_custody_retirement_factory_changed")
        definitions.append(ast.get_source_segment(text, nodes[0]))
    namespace = {"ast": ast, "hashlib": hashlib, "_SHA": _SHA}
    exec(compile("\n\n".join(definitions), "captured-retirement-factories", "exec",
                 dont_inherit=True), namespace)
    return namespace["component_release_source"](raw, expected_sha256).encode()


def load_local_adapter(snapshots: dict, adapter_path: Path | str):
    """Execute captured helpers and resolve only the three fixed repo imports.

    The adapter's stdlib imports keep normal Python behavior. Repository imports
    return the exact in-memory modules below, including the continuity import
    executed later by release_component_fenced. Cached canonical modules and
    .pyc files cannot become execution authority. This grants no lease release.
    """
    _need(type(snapshots) is dict and set(snapshots) == _ROLES,
          "local_custody_snapshot_scope_invalid")
    source = {}
    pins = {}
    for role, snapshot in snapshots.items():
        _need(type(snapshot) is dict and set(snapshot) == {"source", "sha256"},
              "local_custody_snapshot_invalid")
        source[role] = _verified(snapshot["source"], snapshot["sha256"])
        pins[role] = snapshot["sha256"]
    path = Path(adapter_path)
    _need(path.is_absolute() and ".." not in path.parts,
          "local_custody_adapter_path_invalid")
    closed_retirement = _retirement_definitions(source["retirement"], pins["retirement"])
    prepared_adapter = local_adapter_source(source["adapter"], pins["adapter"])
    modules = {}
    original_import = builtins.__import__
    names = {"android_component_continuity": "continuity",
             "android_installer_failed_check_retirement": "retirement",
             "android_installer_component_bundle": "bundle"}

    def captured_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "agent_tools" and level == 0:
            _need(bool(fromlist) and all(item in names and names[item] in modules
                                        for item in fromlist),
                  "local_custody_repository_import_refused")
            return types.SimpleNamespace(**{item: modules[names[item]] for item in fromlist})
        if name.startswith("agent_tools.") or level:
            suffix = name.removeprefix("agent_tools.")
            _need(level == 0 and suffix in names and names[suffix] in modules
                  and bool(fromlist) and all(hasattr(modules[names[suffix]], item)
                                           for item in fromlist),
                  "local_custody_repository_import_refused")
            return modules[names[suffix]]
        return original_import(name, globals, locals, fromlist, level)

    safe_builtins = dict(vars(builtins), __import__=captured_import)
    for role, raw in (("continuity", source["continuity"]),
                      ("bundle", source["bundle"]),
                      ("retirement", closed_retirement),
                      ("adapter", prepared_adapter)):
        module = types.ModuleType("captured_android_local_" + role)
        module.__file__ = str(path if role == "adapter" else path.with_name(role + ".captured.py"))
        module.__dict__["__builtins__"] = safe_builtins
        exec(compile(raw, module.__file__, "exec", dont_inherit=True), module.__dict__)
        modules[role] = module
    provenance = {"schema": 1, "kind": "android-local-captured-source-custody",
                  "sources": pins,
                  "retirementDefinitionsSha256": hashlib.sha256(closed_retirement).hexdigest(),
                  "preparedAdapterSha256": hashlib.sha256(prepared_adapter).hexdigest(),
                  "localPreludeSha256": hashlib.sha256(_LOCAL_PRELUDE.encode()).hexdigest(),
                  "namedRepositoryImportsUsed": False, "bytecodeCacheUsed": False,
                  "releaseGranted": False, "replayAllowed": False}
    return modules["adapter"], provenance
