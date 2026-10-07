"""Load exact historical code for inert tests; never dispatch native entry points."""
import ast
import builtins
import hashlib
import inspect
from pathlib import Path
import types


class _NoNativeLocking(types.ModuleType):
    """A declared test seam: every optional POSIX API access is forbidden."""
    def __getattr__(self, name):
        raise RuntimeError('historical_native_locking_forbidden')


def _inert_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == 'fcntl' and level == 0:
        # Scope is this historical namespace only: no sys.modules/global patch.
        # Pure source factories work on Windows; no historical lock claim can.
        return _NoNativeLocking('fcntl')
    return builtins.__import__(name, globals, locals, fromlist, level)


def verify(module, path, sha256):
    path = Path(path).resolve()
    raw = path.read_bytes()
    if module.__file__ != str(path) or hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError('historical_source_binding_changed')
    for node in ast.parse(raw).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function = inspect.unwrap(getattr(module, node.name))
            if (not isinstance(function, types.FunctionType)
                    or function.__globals__ is not module.__dict__
                    or function.__code__.co_filename != str(path)):
                raise ValueError('historical_function_binding_changed')
    return module


def load(path, sha256):
    path = Path(path).resolve()
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha256:
        raise ValueError('historical_source_binding_changed')
    module = types.ModuleType('agent_tools._inert_history_' + sha256)
    module.__package__ = 'agent_tools'
    module.__file__ = str(path)
    module.__dict__['__builtins__'] = {**vars(builtins), '__import__': _inert_import}
    exec(compile(raw, str(path), 'exec', dont_inherit=True), module.__dict__)
    return verify(module, path, sha256)
