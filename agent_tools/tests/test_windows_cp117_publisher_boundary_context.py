"""Synthetic publisher observations bind to their actual inert action descriptor."""
import ast
import base64
import gzip
import hashlib
import json
from pathlib import Path
import textwrap
import types
import unittest

from agent_tools.tests import test_windows_cp117_server_read_binding as boundary


FIXTURE = Path(__file__).with_name('fixtures') / 'windows_cp117_publisher_boundary'
METHOD = 'test_actual_native_failure_projection_lost_inner_stage_and_closed_successor_factory'
FRAGMENT_SHA = '86cbb8440a5dc0e34f5172db40428412cb7e4c7dcf6bff176db8ac4538f2974b'
NATIVE_SHA = '6577a0d62f8bf6425d112e5f4c42efe3a54d22b4cb70f09544992b37e02b6a35'


def native_capture():
    raw = gzip.decompress(base64.b64decode(boundary.PUBLISHER_READ_NATIVE_GZIP, validate=True))
    if hashlib.sha256(raw).hexdigest() != NATIVE_SHA:
        raise AssertionError('Original publisher capture changed')
    return json.loads(raw)


def original_method():
    path = FIXTURE / 'publisher_boundary.before.fragment'
    raw = path.read_bytes()
    provenance = json.loads((FIXTURE / 'provenance.json').read_bytes())
    if (len(raw) != 2406 or hashlib.sha256(raw).hexdigest() != FRAGMENT_SHA
            or provenance['fragmentBytes'] != len(raw) or provenance['fragmentSha256'] != FRAGMENT_SHA
            or provenance['sourcePath'] != 'agent_tools/tests/test_windows_cp117_server_read_binding.py'
            or provenance['sourceCommit'] != 'c68058eb64f8452207bf2091bd2950e5a06231da'
            or provenance['className'] != 'PublisherBoundaryTests' or provenance['methodName'] != METHOD
            or provenance['captureJsonSha256'] != NATIVE_SHA or provenance['nativeExecution'] is not False):
        raise AssertionError('Original publisher method provenance changed')
    native_capture()
    tree = ast.parse(textwrap.dedent(raw.decode()), filename=str(path))
    if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef) or tree.body[0].name != METHOD:
        raise AssertionError('Original publisher method shape changed')
    namespace = dict(vars(boundary))
    exec(compile(tree, str(path), 'exec', dont_inherit=True), namespace)
    return namespace[METHOD]


def os3_gzip_view(observations):
    """A valid alternate gzip OS byte in one explicit inert factory namespace."""
    compress = gzip.compress
    view = types.SimpleNamespace(**vars(gzip))
    def profiled(data, *args, **kwargs):
        original = compress(data, *args, **kwargs)
        if len(original) < 18 or original[:3] != b'\x1f\x8b\x08':
            raise AssertionError('Owned gzip header is not valid')
        result = original[:9] + b'\x03' + original[10:]
        if result[:9] != original[:9] or result[10:] != original[10:] or gzip.decompress(result) != data:
            raise AssertionError('Owned gzip profile changed payload or trailer')
        observations.append({'inputSha256': hashlib.sha256(data).hexdigest(),
                             'originalSha256': hashlib.sha256(original).hexdigest(),
                             'profiledSha256': hashlib.sha256(result).hexdigest(),
                             'originalOsByte': original[9], 'profiledOsByte': result[9]})
        return result
    view.compress = profiled
    return view


def profiled_boundary_case(method, observations):
    case = boundary.PublisherBoundaryTests(METHOD)
    original_factory = case.factory
    native_action = native_capture()['task']['actionSha256']
    def factory(path):
        namespace = original_factory(path)
        case.assertIs(gzip, namespace['gzip'])
        namespace['gzip'] = os3_gzip_view(observations)
        actual = hashlib.sha256(namespace['publisher_action']().encode()).hexdigest()
        case.assertNotEqual(native_action, actual)
        observations.append({'nativeActionSha256': native_action, 'actualActionSha256': actual})
        return namespace
    case.factory = factory
    setattr(case, METHOD, types.MethodType(method, case))
    return case


class PublisherBoundaryContextTests(unittest.TestCase):
    def test_exact_old_synthetic_observation_red_current_action_binding_green(self):
        original_compress = gzip.compress
        original_decompress = gzip.decompress
        original_capture = boundary.PUBLISHER_READ_NATIVE_GZIP
        outcomes = []
        for label, method in [('before', original_method()),
                              ('current', getattr(boundary.PublisherBoundaryTests, METHOD))]:
            observations = []
            case = profiled_boundary_case(method, observations)
            result = unittest.TestSuite([case]).run(unittest.TestResult())
            self.assertEqual(1, result.testsRun)
            self.assertFalse(result.failures, result.failures)
            self.assertFalse(result.skipped)
            self.assertTrue(observations, {'errors': result.errors, 'failures': result.failures})
            if label == 'before':
                self.assertEqual(1, len(result.errors))
                self.assertIn('ValueError: publisher-read-schema', result.errors[0][1])
            else:
                self.assertFalse(result.errors, result.errors)
            self.assertIs(original_compress, gzip.compress)
            self.assertIs(original_decompress, gzip.decompress)
            self.assertEqual(original_capture, boundary.PUBLISHER_READ_NATIVE_GZIP)
            native_capture()
            outcomes.append({'source': label, 'errors': len(result.errors), 'observations': observations})
        print(json.dumps({'publisherBoundarySyntheticAction': outcomes,
                          'nativeExecution': False, 'stdlibUnchanged': True}, sort_keys=True), flush=True)

    def test_explicit_gzip_profile_keeps_complete_payload_and_stdlib(self):
        observations = []
        original_compress = gzip.compress
        raw = b'OWNED INERT PUBLISHER PROGRAM\n' * 17
        ordinary = original_compress(raw, mtime=0)
        alternate = os3_gzip_view(observations).compress(raw, mtime=0)
        self.assertEqual(ordinary[:9], alternate[:9])
        self.assertEqual(ordinary[10:], alternate[10:])
        self.assertEqual(3, alternate[9])
        self.assertEqual(raw, gzip.decompress(alternate))
        self.assertIs(original_compress, gzip.compress)
        self.assertEqual(1, len(observations))


if __name__ == '__main__':
    unittest.main()
