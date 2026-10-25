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
    'windows_cp117_secure_input_observe.py': '032dd9225f3ea79dfe31aebbd1e039977c228d1f93507c9446a3682c6bc49dbc',
    'windows_cp117_secure_input_tuple_observe.py': 'fb8d6b3f2bdaab3b97039e784c04fd555d2b0710f1018f935953900f370b4522',
    'windows_cp117_secure_input_geometry_observe.py': '832746a0a990dc42b6e82f799d52dbab42b8424c1be4fab54da171af522f32c7',
    'windows_cp117_secure_input_descendants_observe.py': 'c11d73f56e89219c64ae820e9986fea33a7749479101c7bc8bd8913e043e8d70',
    'windows_cp117_windowless_candidate_observe.py': '2909daf02f73c2ac3622a16156743d5be3d3d869fe7e297fef26d39acd10df9f',
    'windows_cp117_windowless_edit_observe.py': '73414896403937d5040a0132e5d407483287c922b1a0b96b387d058661d3e9f3',
    'windows_cp117_windowless_gui_login.py': 'afd3a4a99f82b861bc83e227f842486a84f0b7ed8a8d332e3bb248ecc67bb822',
    'windows_cp117_windowless_provider_login.py': 'c6415d2856248cc967ca4f1278143390f53b3b832e11b22c753ef417dc4372a3',
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
