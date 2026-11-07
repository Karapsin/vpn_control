"""Portable Read-Rows cause witness from authenticated complete MSI body recipes.

The live getter returns the complete original body with only two [void] casts.
This finite witness executes its entire Read-Rows function with declared method,
record and release peers in real PowerShell. It does not execute Windows guards,
open an MSI, or qualify actual COM returns. Native metadata GREEN remains required.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).parent
BEFORE_BODY_SHA = '4eab4f008f2d23a87196f9893e8b35df96646201d852c6638448ba7523732de8'
CURRENT_BODY_SHA = '8b912c9c61edbaa39d52004fc467bc4595272f46a4226c1ed33d08add76a4618'
FUNCTION_PINS = {'before': 'b273dcb9a038c9a36d1cafbb522af113ded658f9c5c6ddee0589c42a082dca90',
                 'after': '1336676c8124c7098ef02515ca54e9e3c2a779751883c5ed5d967f385cbfe543'}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _function(complete_body, label):
    start = complete_body.index(b'function Read-Rows(')
    end = complete_body.index(b'function Read-Optional(', start)
    whole_function = complete_body[start:end]
    if _sha(whole_function) != FUNCTION_PINS[label]:
        raise ValueError('msi_metadata_rows_complete_function_pin')
    return whole_function


def run_rows_pair(before, current, directory, powershell):
    if _sha(before) != BEFORE_BODY_SHA or _sha(current) != CURRENT_BODY_SHA:
        raise ValueError('msi_metadata_rows_complete_body_pin')
    provenance = json.loads((HERE / 'provenance.json').read_bytes())
    fixtures = {}
    for record in provenance['files']:
        raw = (HERE / record['path']).read_bytes()
        if len(raw) != record['bytes'] or _sha(raw) != record['sha256']:
            raise ValueError('msi_metadata_rows_fixture_pin')
        fixtures[record['path']] = raw
    shapes = {'zero': [], 'one': [['Property']],
              'multiple': [['Property'], ['Directory'], ['Component']],
              'one-null-field': [[None]]}
    returns = (('void', 'void'), ('null', 'void'), ('void', 'null'),
               ('null', 'null'), ('zero', 'void'), ('void', 'zero'), ('integer', 'string'))
    cases = [{'name': shape + '--execute-' + execute + '--close-' + close,
              'rows': rows, 'execute': execute, 'close': close}
             for shape, rows in shapes.items() for execute, close in returns]
    encoded_cases = base64.b64encode(json.dumps(cases, separators=(',', ':')).encode()).decode()
    results = {}
    for label, source in (('before', before), ('after', current)):
        target = Path(directory) / label
        target.mkdir(mode=0o700)
        whole_function = _function(source, label)
        staged = {'complete-body.ps1.template': source, 'Read-Rows.complete.ps1': whole_function,
                  'declared-view-record-release-peers.cs': fixtures['declared-view-record-release-peers.cs.source'],
                  'rows-oracle.ps1': fixtures['rows-oracle.ps1.source']}
        for name, raw in staged.items():
            (target / name).write_bytes(raw)
        environment = os.environ.copy()
        environment.update(POWERSHELL_UPDATECHECK='Off', POWERSHELL_TELEMETRY_OPTOUT='1',
            PSModuleAnalysisCachePath=str(target / 'module-analysis-cache'),
            FUNCTION_SOURCE=str(target / 'Read-Rows.complete.ps1'), CASE_LIST_JSON=encoded_cases)
        process = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-File', str(target / 'rows-oracle.ps1')],
            cwd=target, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=False)
        (target / 'stdout.bin').write_bytes(process.stdout)
        (target / 'stderr.bin').write_bytes(process.stderr)
        value = json.loads(process.stdout.decode('utf-8-sig'))
        expected_failures = 24 if label == 'before' else 0
        if process.stderr or process.returncode != (1 if expected_failures else 0):
            raise AssertionError(('msi_metadata_rows_process', label, process.returncode, process.stderr))
        if len(value['cases']) != 28 or value['oracleFailures'] != expected_failures:
            raise AssertionError(('msi_metadata_rows_case_inventory', label, value))
        for declared, observed in zip(cases, value['cases']):
            expected_ok = label == 'after' or (declared['execute'], declared['close']) == ('void', 'void')
            if observed['case'] != declared['name'] or observed['ok'] is not expected_ok:
                raise AssertionError(('msi_metadata_rows_positive_oracle', label, declared, observed))
            closing = observed['closing']
            count = len(declared['rows'])
            releases = {'record-' + str(index): 1 for index in range(count)}
            releases['view'] = 1
            if (closing['executeCalls'] != 1 or closing['closeCalls'] != 1
                    or closing['releases'] != releases or closing['fetchCalls'] != count + 1
                    or closing['fieldCalls'] != count or closing['aggregateRows'] != count
                    or observed['releaseType'] != 'DeclaredMarshal'):
                raise AssertionError(('msi_metadata_rows_release_closing', label, declared, closing))
            if not expected_ok and 'null' in (declared['execute'], declared['close']):
                if observed['error']['fullyQualifiedErrorId'] != 'NullArray':
                    raise AssertionError(('msi_metadata_rows_actual_null_failure', observed))
        unchanged = all((target / name).read_bytes() == raw for name, raw in staged.items())
        if not unchanged:
            raise AssertionError('msi_metadata_rows_source_changed')
        result = {'exitCode': process.returncode, 'matrix': value,
            'stdoutBytes': len(process.stdout), 'stderrBytes': len(process.stderr),
            'stdoutSha256': _sha(process.stdout), 'stderrSha256': _sha(process.stderr),
            'completeBodySha256': _sha(source), 'completeFunctionSha256': _sha(whole_function),
            'sourcesUnchanged': unchanged, 'naturalExit': True, 'streamsEof': True,
            'portableCauseWitness': True, 'actualMsiComAbiQualified': False,
            'windowsBootstrapGuardsExecuted': False, 'nativeOrNetworkActions': False}
        (target / 'process-receipt.json').write_text(json.dumps(result, indent=2) + '\n')
        results[label] = result
    return results
