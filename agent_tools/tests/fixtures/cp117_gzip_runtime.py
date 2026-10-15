"""Scoped gzip runtime compatibility for exact historical CP117 fixture code.

These modules are outside the supported MCP adapter closure. Their original
source and rendered-source pins stay intact. Only testcase-owned module views
receive the Python 3.13+ gzip OS byte; the stdlib and current MCP views do not.
"""
from contextlib import ExitStack, contextmanager
import gzip
import hashlib
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch


SOURCE_HASHES = {
    'windows_cp117_secure_input_observe.py': '836d2d13dea8604d8d9f3c409db7d15fde349ceb0ecade06ce704a3a2693f590',
    'windows_cp117_secure_input_tuple_observe.py': 'a763bec79923cd09a450f5b635c6c61a059c1fa3f488eb14cff35f687bfd04bc',
    'windows_cp117_secure_input_geometry_observe.py': '9f9efa88a58588d67afbf52f68ca201b11575aa1edf744941f1c42894f1cddcf',
    'windows_cp117_secure_input_descendants_observe.py': '571bc5a22dcdcdb11e49e6572a50b123339a8b6b39e6f8e154e960583f0f306b',
    'windows_cp117_windowless_candidate_observe.py': '554416b9f6ba89da838aadb32f33f1b1b6428c8e577edd421e5e56e7db1c83ed',
    'windows_cp117_windowless_edit_observe.py': '584b2dab158f95ffee3c95def3d6e33b3c2d2d5701af95885d7f7e1b2914eed1',
    'windows_cp117_windowless_gui_login.py': 'afaa1184bc10f9358d57238e2d6d736de2435c0f7b2553a7aaf7343efe9ae7a8',
    'windows_cp117_windowless_provider_login.py': '3447001b51cb4df248e4566135bba568c5e3e090a9a9744d4ba3eafc4e9a8c12',
    'provider_f54029cf.source': 'f54029cf3259011d71df93c51f15b3c2b7a886470008427cf85c8e127c567a72',
}
_LINKS = ('m', 'original', 'role', 'geometry', 'windowless', 'original_semantic',
          'secure', 'fixture', 'provider')


def canonical_gzip(data, compresslevel=9, *, mtime=0):
    """Keep level 9/mtime 0 gzip bytes, changing only RFC 1952's OS metadata."""
    if type(data) is not bytes or compresslevel != 9 or type(compresslevel) is not int or type(mtime) is not int or mtime != 0:
        raise ValueError('historical_gzip_runtime_arguments')
    raw = gzip.compress(data, compresslevel=9, mtime=0)
    if len(raw) < 18 or raw[:8] != b'\x1f\x8b\x08\x00\x00\x00\x00\x00' or raw[8] != 2:
        raise ValueError('historical_gzip_runtime_header')
    return raw[:9] + b'\xff' + raw[10:]


class HistoricalGzipView:
    """A fixture namespace dependency, never a replacement for stdlib gzip."""
    compress = staticmethod(canonical_gzip)
    decompress = staticmethod(gzip.decompress)
    GzipFile = gzip.GzipFile


def historical_gzip_view():
    return HistoricalGzipView()


def _targets(roots):
    pending = list(roots)
    seen = set()
    result = []
    while pending:
        module = pending.pop()
        if not isinstance(module, types.ModuleType) or id(module) in seen:
            continue
        seen.add(id(module))
        if len(seen) > 128:
            raise ValueError('historical_gzip_runtime_scope')
        namespace = vars(module)
        path = namespace.get('__file__')
        if isinstance(path, str) and Path(path).name in SOURCE_HASHES:
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != SOURCE_HASHES[Path(path).name]:
                raise ValueError('historical_gzip_runtime_source_changed')
            current = namespace.get('gzip')
            if current is not gzip and not isinstance(current, HistoricalGzipView):
                raise ValueError('historical_gzip_runtime_dependency_changed')
            result.append(module)
        pending.extend(namespace.get(name) for name in _LINKS)
    return result


@contextmanager
def historical_gzip_context(*actual_fixture_modules):
    """Attach only to supplied, source-verified historical module objects.

    No module is imported or found through a canonical module cache here. The
    caller installs its historical graph first, then supplies that actual graph.
    Nested and failed contexts restore every original dependency reference.
    """
    with ExitStack() as stack:
        for module in _targets(actual_fixture_modules):
            stack.enter_context(patch.object(module, 'gzip', historical_gzip_view()))
        yield


def _case_modules(case):
    method = getattr(case, case._testMethodName)
    namespaces = [getattr(method, '__globals__', {})]
    owner = sys.modules.get(type(case).__module__)
    if isinstance(owner, types.ModuleType):
        namespaces.append(vars(owner))
    return tuple(namespace.get(name) for namespace in namespaces for name in _LINKS)


class HistoricalGzipTestCase(unittest.TestCase):
    """Scope existing globals, then actual fixture replacements after setUp."""
    def run(self, result=None):
        with ExitStack() as stack:
            self._historical_gzip_stack = stack
            try:
                return super().run(result)
            finally:
                del self._historical_gzip_stack

    def _callSetUp(self):
        self._historical_gzip_stack.enter_context(historical_gzip_context(*_case_modules(self)))
        super()._callSetUp()
        self._historical_gzip_stack.enter_context(historical_gzip_context(*_case_modules(self)))

    def _callTestMethod(self, method):
        with historical_gzip_context(*_case_modules(self)):
            return super()._callTestMethod(method)
