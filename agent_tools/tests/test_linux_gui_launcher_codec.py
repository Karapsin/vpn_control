"""Actual outer receiver encoder; stop before the first SOURCE exec/native effect."""
import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'agent_tools/native_owner_gui_lifecycle_ssh.py'
FIXTURE = ROOT / 'agent_tools/tests/fixtures/linux_gui_source_custody'


def literals():
    tree = ast.parse(SOURCE.read_bytes())
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in ('_RECEIVER', '_LAUNCHER'):
                    values[target.id] = ast.literal_eval(node.value)
    return values


def emit(capsule):
    values = literals()
    tree = ast.parse(values['_RECEIVER'])
    block = next(node.body for node in tree.body if isinstance(node, ast.Try) and any(isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'custody' for t in n.targets) for n in tree.body[:tree.body.index(node)]))
    start = next(i for i, n in enumerate(block) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in ('raw', 'encoded') for t in n.targets))
    stop = next(i for i, n in enumerate(block) if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'argv' for t in n.targets))
    def bad(reason): raise ValueError(reason)
    namespace = dict(base64=base64, hashlib=hashlib, json=json, zlib=zlib, capsule=capsule, intent={}, _LAUNCHER_SOURCE=values['_LAUNCHER'], bad=bad)
    exec(compile(ast.Module(body=block[start:stop], type_ignores=[]), 'actual-outer-encoder', 'exec'), namespace)
    return namespace['command']


def decode_before_exec(command):
    tree = ast.parse(command)
    stop = next(i for i,n in enumerate(tree.body) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Name) and n.value.func.id=='exec')
    namespace = {}
    exec(compile(ast.Module(body=tree.body[:stop],type_ignores=[]), 'outer-decode-before-source-exec', 'exec'), namespace)
    return namespace


class LauncherCodecTests(unittest.TestCase):
    def capsule(self): return json.loads((FIXTURE / 'normal-capsule.source').read_bytes())

    def test_actual_normal_six_role_capsule_fits_unchanged_bound(self):
        command = emit(self.capsule())
        self.assertLess(len(command.encode()), 65536)
        self.assertEqual(decode_before_exec(command)['_ORIGINAL_CAPSULE'], self.capsule())

    def test_every_body_and_canonical_seal_preserved(self):
        original = self.capsule()
        result = decode_before_exec(emit(original))
        self.assertEqual(result['raw'], (json.dumps(original, sort_keys=True, separators=(',', ':'))+'\n').encode())
        for before, after in zip(original['inputs'],result['_ORIGINAL_CAPSULE']['inputs']):
            self.assertEqual(base64.b64decode(before['body']),base64.b64decode(after['body']))

    def test_changed_wire_rejected_before_source_exec(self):
        command = emit(self.capsule())
        tree = ast.parse(command)
        payload = next(n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='b64decode' and n.args and isinstance(n.args[0],ast.Constant))
        wire = json.loads(zlib.decompress(base64.b64decode(payload.args[0].value)))
        wire['inputs'][0]['body'] += '\n# altered'
        payload.args[0].value = base64.b64encode(zlib.compress(json.dumps(wire,sort_keys=True,separators=(',',':')).encode())).decode()
        with self.assertRaises(AssertionError): decode_before_exec(ast.unparse(tree))

    def test_binary_source_refused_before_native_effect(self):
        capsule = copy.deepcopy(self.capsule());capsule['inputs'][0]['body']=base64.b64encode(b'\xff').decode()
        with self.assertRaises(UnicodeDecodeError): emit(capsule)


if __name__ == '__main__': unittest.main()
