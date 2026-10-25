"""Whole-before RED/GREEN: managed check/test children never inherit stdin.

The unfixed MCP check launcher (`_run`), unittest-runner worker Popen and
selector run loop let every child inherit the launching process's stdin: the
MCP stdio JSON-RPC stream, an interactive terminal or a sweep's piped input. A
selected test whose fixture peer read stdin to EOF then blocked on, or consumed,
that stream. Each real seam runs in a fresh parent whose stdin is a pipe holding
only sentinel bytes; an inert generated probe test records what it read. No
network, VM, SSH or host tool is involved.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / 'agent_tools'
FIXTURES = Path(__file__).parent / 'fixtures/runner_stdin_isolation'
BEFORE = {'mcp_server.py': 'mcp_server.before.source',
          'agent_test_runner.py': 'agent_test_runner.before.source',
          'affected_agent_tests.py': 'affected_agent_tests.before.source'}
# The selector dispatches its fixed first safety-gate command verbatim, so the
# inert probe takes that module name inside each private generated root.
GATE = 'agent_tools.tests.test_ssh_connection_session_close'
SENTINEL = b'{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"run_checks"}}\n'
PROBE = ('import sys,unittest\nfrom pathlib import Path\nclass Probe(unittest.TestCase):\n'
         ' def test_reads_stdin(self):Path(%r).write_bytes(sys.stdin.buffer.read())\n')
# Library seams need their own parent process. Only Git planning is replaced
# around the selector's actual main() loop; the MCP launcher is the exact `_run`
# source with its own output helpers and the real checkout environment helper.
DRIVER = r'''import ast,importlib.util,json,os,re,shlex,subprocess,sys
from pathlib import Path
from typing import Any
from unittest import mock
seam,source,root,repository,gate=sys.argv[1],Path(sys.argv[2]),Path(sys.argv[3]),sys.argv[4],sys.argv[5]
if seam=='selector':
    spec=importlib.util.spec_from_file_location('stdin_isolation_selector',source)
    selector=sys.modules[spec.name]=importlib.util.module_from_spec(spec);spec.loader.exec_module(selector)
    plan=selector.Selection('0'*40,(),(gate,),1)
    with mock.patch.object(selector,'snapshot',return_value='a'*64),mock.patch.object(selector,'select',return_value=plan):
        value={'code':selector.main(['--root',str(root),'--run'])}
else:
    sys.path.insert(0,repository)
    from agent_tools import check_output_retention,local_build_environment
    names={'_run','_display','_bounded','_failure_log_excerpt'}
    chosen=[node for node in ast.parse(source.read_bytes()).body if isinstance(node,ast.FunctionDef) and node.name in names
            or isinstance(node,ast.Assign) and [getattr(t,'id',None) for t in node.targets]==['MAX_OUTPUT_CHARS']]
    assert len(chosen)==len(names)+1,'exact MCP launcher source required'
    ns={'os':os,'re':re,'shlex':shlex,'subprocess':subprocess,'Any':Any,'REPO_ROOT':root,
        'local_build_environment':local_build_environment,'check_output_retention':check_output_retention}
    exec(compile(ast.Module(chosen,[]),str(source),'exec'),ns)
    result=ns['_run']([sys.executable,'-B','-m','unittest',gate],timeout=60)
    value={'ok':result['ok'],'returncode':result['returncode']}
print('DRIVER '+json.dumps(value),flush=True)
'''


@unittest.skipUnless(os.name == 'posix', 'POSIX pipes, private runner reports and worker sessions')
class RunnerStdinIsolationTests(unittest.TestCase):
    def generated(self, name, before, *helpers):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        (root / 'agent_tools/tests').mkdir(parents=True)
        (root / 'tools').mkdir()
        for package in ('agent_tools', 'agent_tools/tests'):
            (root / package / '__init__.py').write_text('')
        (root / (GATE.replace('.', '/') + '.py')).write_text(PROBE % str(root / 'stdin-read.bin'))
        provenance = json.loads((FIXTURES / 'provenance.json').read_bytes())['files']
        for current, frozen in BEFORE.items():  # Finite literal source registry.
            if current == name:
                raw = (FIXTURES / frozen).read_bytes() if before else (TOOLS / current).read_bytes()
                if before:
                    self.assertEqual(('agent_tools/' + current, provenance[frozen]['sha256']),
                                     (provenance[frozen]['path'], hashlib.sha256(raw).hexdigest()))
                (root / 'tools' / current).write_bytes(raw)
        for helper in helpers:
            shutil.copyfile(TOOLS / helper, root / 'tools' / helper)
        return root

    def launch(self, root, argv):
        env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'}
        env.pop('DYLD_INSERT_LIBRARIES', None)
        # The launching parent's stdin holds only SENTINEL, then EOF: a child
        # can consume it but never block. This test keeps the same read end.
        read, write = os.pipe()
        try:
            os.write(write, SENTINEL)
        finally:
            os.close(write)
        try:
            result = subprocess.run(argv, cwd=root, env=env, stdin=read, capture_output=True, timeout=120)
            left = b''.join(iter(lambda: os.read(read, 65536), b''))
        finally:
            os.close(read)
        record = root / 'stdin-read.bin'
        self.assertTrue(record.is_file(), result.stdout.decode(errors='replace') + result.stderr.decode(errors='replace'))
        return result, left, record.read_bytes()

    def runner(self, before):
        # The actual coordinator CLI that the selector's prepared runs execute.
        root = self.generated('agent_test_runner.py', before, 'agent_test_session_observer.py')
        plan = root / 'tools/plan.json'
        plan.write_text(json.dumps({'schemaVersion': 1, 'sourceFingerprint': 'a' * 64, 'modules': [GATE], 'maxWorkers': 1}))
        (root / 'reports').mkdir(mode=0o700)
        result, left, read = self.launch(root, [sys.executable, '-B', str(root / 'tools/agent_test_runner.py'),
                                                '--plan-file', str(plan), '--report-dir', str(root / 'reports/run')])
        report = json.loads((root / 'reports/run/report.json').read_bytes())
        self.assertEqual((0, 'complete', 1), (result.returncode, report['state'], report['counts']['testsRun']),
                         result.stderr.decode(errors='replace'))
        return left, read

    def driver(self, seam, name, before, *helpers):
        root = self.generated(name, before, *helpers)
        result, left, read = self.launch(root, [sys.executable, '-I', '-B', '-c', DRIVER, seam,
                                                str(root / 'tools' / name), str(root), str(ROOT), GATE])
        lines = [line[7:] for line in result.stdout.decode().splitlines() if line.startswith('DRIVER ')]
        self.assertEqual((0, 1), (result.returncode, len(lines)), result.stderr.decode(errors='replace'))
        return json.loads(lines[0]), left, read

    def selector(self, before):
        value, left, read = self.driver('selector', 'affected_agent_tests.py', before, 'affected_agent_test_dependencies.json')
        self.assertEqual({'code': 0}, value)
        return left, read

    def server(self, before):
        value, left, read = self.driver('server', 'mcp_server.py', before)
        self.assertEqual({'ok': True, 'returncode': 0}, value)
        return left, read

    def assert_isolated(self, seam):
        for before in (True, False):
            with self.subTest(seam=seam, before=before):
                left, read = getattr(self, seam)(before)
                # RED: the inert child read the parent's stream, which is lost.
                # GREEN: the child saw immediate EOF; the parent's bytes remain.
                self.assertEqual((SENTINEL, b'') if before else (b'', SENTINEL), (read, left))

    def test_whole_before_runner_worker_consumed_parent_stdin_current_worker_gets_eof(self):
        self.assert_isolated('runner')

    def test_whole_before_selector_run_consumed_parent_stdin_current_child_gets_eof(self):
        self.assert_isolated('selector')

    def test_whole_before_mcp_check_launcher_consumed_stdio_current_child_gets_eof(self):
        self.assert_isolated('server')


if __name__ == '__main__':
    unittest.main()
