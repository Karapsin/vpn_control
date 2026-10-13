import ast
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from agent_tools import android_original_host_wire as wire

D = Path(__file__).resolve().parent
BEFORE = os.environ.get('VPN_CONTROL_DURABLE_JSON_BEFORE') == '1'

def existing_producer():
    source = (D.parent / 'android_admission_readback.py').read_text(encoding='utf-8')
    tree = ast.parse(source)
    value = next(n.value for n in tree.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == '_ASYNC_SUBMIT' for t in n.targets))
    program = ast.literal_eval(value)
    return next(n for n in ast.parse(program).body
                if isinstance(n, ast.FunctionDef) and n.name == 'durable')

def parse(raw):
    if not BEFORE:
        return wire.decode_durable_json_record(raw)
    # Exact expression from the preserved a1e5 native collector beforeimage.
    source = (D / 'fixtures/android_durable_identity_before.source').read_bytes()
    namespace = {'base64': base64, '_strict_json': wire._strict_json,
                 'first': {'job': {'identity.json': {'base64': base64.b64encode(raw).decode()}}}}
    exec(compile(source, '<preserved-actual-identity-consumer>', 'exec'), namespace)
    return namespace['identity']

class DurableJSON(unittest.TestCase):
    def test_actual_existing_producer_payload_and_consumer(self):
        function = existing_producer()
        payload = next(n.value for n in ast.walk(function) if isinstance(n, ast.Assign)
                       and any(isinstance(t, ast.Name) and t.id == 'payload' for t in n.targets))
        value = {'pid': 2617469, 'startTicks': 91305563}
        raw = eval(compile(ast.Expression(payload), '<actual-private-producer-payload>', 'eval'),
                   {'value': value, 'json': json})
        self.assertEqual(parse(raw), value)

    def test_missing_lf_refuses(self):
        with self.assertRaises(ValueError):
            parse(b'{"pid":2617469,"startTicks":91305563}')

    def test_extra_lf_and_other_trailing_bytes_refuse(self):
        for raw in (b'{}\n\n', b'{} \n', b'{}x\n', b'{}\r\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse(raw)

    def test_duplicate_keys_refuse(self):
        with self.assertRaises(ValueError):
            parse(b'{"pid":1,"pid":2}\n')

    def test_nonfinite_refuses(self):
        for raw in (b'{"value":NaN}\n', b'{"value":Infinity}\n', b'{"value":1e9999}\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse(raw)

    @unittest.skipIf(BEFORE, 'fixed decoder type/bound controls')
    def test_record_bound_and_type_refuse(self):
        oversized = b'{"v":"' + b'x' * (16385 - 9) + b'"}\n'
        self.assertEqual(len(oversized), 16385)
        for raw in (b'', oversized, '{}\n', bytearray(b'{}\n'), True):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(ValueError):
                parse(raw)

    @unittest.skipIf(BEFORE, 'fixed decoder positive boundary')
    def test_exact_record_bound_valid_json_is_accepted(self):
        raw = b'{"v":"' + b'x' * (16384 - 9) + b'"}\n'
        self.assertEqual(len(raw), 16384)
        self.assertEqual(parse(raw), {'v': 'x' * (16384 - 9)})

    @unittest.skipUnless(os.name == 'posix', 'existing async directory fsync producer is POSIX')
    def test_actual_existing_producer_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            job = Path(temporary)
            namespace = {'job': job, 'json': json, 'os': os}
            exec(compile(ast.Module(body=[existing_producer()], type_ignores=[]),
                         '<actual-existing-async-durable-file>', 'exec'), namespace)
            value = {'pid': 2617469, 'startTicks': 91305563}
            namespace['durable']('identity.json', value)
            self.assertEqual(parse((job / 'identity.json').read_bytes()), value)

if __name__ == '__main__':
    unittest.main()
