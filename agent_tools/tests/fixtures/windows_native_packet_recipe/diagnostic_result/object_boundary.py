"""Complete diagnostic body with a declared own-child CIM boundary.

The real PowerShell runtime executes all body statements and the producer's
actual property-assignment boundary. Bootstrap Windows identity guards are not
executed here; the original complete native scenario remains required.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import uuid

HERE = Path(__file__).parent
BEFORE_BODY_SHA = 'b076b5caacbeebc04e2b78e2ba27de5e026d6c04bf9666ea231eacf7ca5c2359'
PRODUCER_SHA = '2938a7c6c25d23adc9683ced126fe2d3c0a88614dab59a7b134a624d6f8b0ee8'
BEFORE_BOUND_SHA = 'faf20e55a28888257ee3005b84f5ca1cdb5f5c1ec44c702060dd35fbbe0a815a'


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def generated_assignment(whole_producer, native_draft, guest_context):
    if _sha(whole_producer) != PRODUCER_SHA:
        raise ValueError('diagnostic_object_complete_producer_pin')
    name = '_diagnostic_object_complete_producer_' + uuid.uuid4().hex
    module = types.ModuleType(name)
    module.__file__ = '<complete-authenticated-artifact-producer>'
    sys.modules[name] = module
    try:
        exec(compile(whole_producer, module.__file__, 'exec'), module.__dict__)
        assert module._boot_bound.__globals__ is module.__dict__
        bound = module._boot_bound(native_draft.decode('utf-8-sig'), guest_context)
    finally:
        sys.modules.pop(name, None)
    if _sha(bound.encode('utf-8-sig')) != BEFORE_BOUND_SHA:
        raise ValueError('diagnostic_object_actual_native_bound_join')
    lines = bound.splitlines()
    selected = [index for index, line in enumerate(lines) if line.startswith('$r.bootstrapOpening=')]
    if len(selected) != 1 or lines[selected[0] + 1] != '[pscustomobject]$r':
        raise ValueError('diagnostic_object_actual_assignment_boundary')
    return ('\n'.join(lines[selected[0]:selected[0] + 2]) + '\n').encode('utf-8-sig')


def run_diagnostic_object_pair(before, current, whole_producer, native_draft,
                               guest_context, directory, powershell):
    if _sha(before) != BEFORE_BODY_SHA:
        raise ValueError('diagnostic_object_authentic_before_pin')
    assignment = generated_assignment(whole_producer, native_draft, guest_context)
    directory = Path(directory)
    results = {}
    for label, source in (('before', before), ('after', current)):
        target = directory / label
        target.mkdir(mode=0o700)
        body = target / 'complete-body.ps1'
        assignment_path = target / 'actual-generated-assignments.ps1'
        body.write_bytes(source)
        assignment_path.write_bytes(assignment)
        runner = target / 'object-boundary.ps1'
        runner_source = (HERE / 'object-boundary.ps1.source').read_bytes()
        runner.write_bytes(runner_source)
        environment = os.environ.copy()
        environment.update(POWERSHELL_UPDATECHECK='Off', POWERSHELL_TELEMETRY_OPTOUT='1',
                           PSModuleAnalysisCachePath=str(target / 'module-analysis-cache'))
        process = subprocess.run([str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive',
            '-ExecutionPolicy', 'Bypass', '-File', str(runner),
            '-BodyPath', str(body), '-AssignmentPath', str(assignment_path)],
            cwd=target, env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60, check=False)
        for name, data in (('stdout.bin', process.stdout), ('stderr.bin', process.stderr)):
            (target / name).write_bytes(data)
        unchanged = (body.read_bytes() == source and assignment_path.read_bytes() == assignment
                     and runner.read_bytes() == runner_source)
        results[label] = {'exitCode': process.returncode, 'stdoutBytes': len(process.stdout),
            'stderrBytes': len(process.stderr), 'stdoutSha256': _sha(process.stdout),
            'stderrSha256': _sha(process.stderr), 'stderr': process.stderr.decode('utf-8-sig'),
            'result': json.loads(process.stdout.decode('utf-8-sig')) if process.returncode == 0 else None,
            'completeBodySha256': _sha(source), 'actualGeneratedAssignmentSha256': _sha(assignment),
            'sourcesUnchanged': unchanged, 'naturalExit': True,
            'bootstrapGuardsExecuted': False, 'declaredCimPeerOnlyOwnChild': True}
        (target / 'process-receipt.json').write_text(json.dumps(results[label], indent=2) + '\n')
    return results
