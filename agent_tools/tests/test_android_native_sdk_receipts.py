"""Replay actual native receipts through the exact acceptance-harness validator.

Only local completed child processes are created. No fixture/SSH/ADB invocation
or remote admission is run when selecting the preserved function from its AST.
"""
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

FIXTURES = Path(__file__).parent / 'fixtures' / 'android_adb_jobs'


def authenticated(name, section):
    provenance = json.loads((FIXTURES / 'sdk_harness.provenance.json').read_bytes())
    raw = (FIXTURES / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != provenance[section][name]:
        raise AssertionError('Preserved native evidence changed')
    return raw


def validator(name):
    source = FIXTURES / name
    tree = ast.parse(authenticated(name, 'sourceSha256'), filename=str(source))
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'finish_client']
    if len(nodes) != 1:
        raise AssertionError('Preserved native validator is missing')
    namespace = {'json': json}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), 'exec'), namespace)
    return namespace['finish_client']


def run_completed(function, receipt):
    # Replay the byte-for-byte retained native SDK result through a real local
    # process, including wait/exit handling in the complete original validator.
    authenticated(receipt.name, 'receiptSha256')
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / 'native-result.json'
        with output.open('wb') as stream:
            child = subprocess.Popen([sys.executable, '-c',
                'import os,sys;os.write(1,open(sys.argv[1],"rb").read())', str(receipt)],
                stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.PIPE)
            child.wait(timeout=5)
        try:
            return function(child, [], output)
        finally:
            child.stderr.close()


class NativeSdkReceiptTests(unittest.TestCase):
    def test_native_healthy_delivery_does_not_claim_execution_from_forwarding(self):
        receipt = FIXTURES / 'sdk_healthy.native.json'
        with self.assertRaises(AssertionError):
            run_completed(validator('sdk_flag.before.source'), receipt)
        value = run_completed(validator('sdk_harness.fixed.source'), receipt)
        self.assertIs(False, value['serverExecutionProven'])
        self.assertEqual('complete', value['nextAction']['kind'])
        self.assertTrue(value['allRelayAttemptsClosed'])

    def test_native_lost_ack_has_fewer_returned_calls_without_replaying_start(self):
        receipt = FIXTURES / 'sdk_server.native.json'
        with self.assertRaises(AssertionError):
            run_completed(validator('sdk_counts.before.source'), receipt)
        value = run_completed(validator('sdk_harness.fixed.source'), receipt)
        self.assertLess(value['returnedToolCalls'], value['forwardedToolCalls'])
        self.assertFalse(value['automaticReplay'])
        self.assertEqual(2, value['relayAttempts'])
        self.assertEqual('terminal', value['programState'])

    def test_fresh_native_client_retains_same_original_complete_result(self):
        value = run_completed(validator('sdk_harness.fixed.source'), FIXTURES / 'sdk_client.native.json')
        self.assertEqual('1cbef06d-8001-5d2b-8387-0201bfb7c714', value['operationId'])
        self.assertTrue(value['originalServerTerminalClosed'])
        self.assertFalse(value['automaticReplay'])


if __name__ == '__main__':
    unittest.main()
