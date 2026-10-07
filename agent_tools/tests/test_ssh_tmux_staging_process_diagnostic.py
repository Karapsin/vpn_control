"""Actual generated source scan diagnostic tests with inert /proc fixtures."""
import contextlib
import io
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock
from agent_tools import ssh_tmux_staging_process_diagnostic as diagnostic
from agent_tools import ssh_tmux_source_staging_recovery as recovery
from agent_tools import ssh_tmux_session_ssh as old
from agent_tools import ssh_tmux_session as session

ID='b8b987ec-a4cc-4f6f-8c32-41c70a60f8e0'


class DiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.job=self.root/recovery.OLD_CORRELATION;self.job.mkdir(mode=0o700)
        session.write_once(self.job/'stage-intent.json',session.canonical(old.purpose(recovery.OLD_REQUEST)))
        self.proc=self.root/'proc';self.proc.mkdir()
        self.entry=self.proc/'101010';self.entry.mkdir()
        fields=['S']+['1']*18+['888']+['1']*3
        (self.entry/'stat').write_text('101010 (test) '+' '.join(fields))
        (self.entry/'cmdline').write_bytes(b'inert\0')
        (self.entry/'cwd').symlink_to(self.root)

    def source(self,program):
        return program.replace(old.REMOTE_ROOT,str(self.root)).replace("pathlib.Path('/proc').iterdir()",f"pathlib.Path({str(self.proc)!r}).iterdir()").replace("pathlib.Path('/proc',str(pid))",f"pathlib.Path({str(self.proc)!r},str(pid))")

    def execute(self,source,*,original=False):
        payload={'request':old.purpose(recovery.OLD_REQUEST)}
        if not original:payload['diagnosticId']=ID
        output=io.StringIO()
        with mock.patch('sys.stdin',types.SimpleNamespace(buffer=io.BytesIO(session.canonical(payload)))),contextlib.redirect_stdout(output):
            try:exec(compile(source,'<inert-diagnostic>','exec'),{})
            except SystemExit as error:
                if original:raise
                self.assertEqual(error.code,0)
        return None if not output.getvalue() else __import__('json').loads(output.getvalue())

    def test_actual_original_error_loses_reason_vs_diagnostic(self):
        (self.entry/'cwd').unlink()
        with self.assertRaises(SystemExit) as error:self.execute(self.source(recovery.PROOF),original=True)
        self.assertEqual(error.exception.code,36)
        result=self.execute(self.source(diagnostic.PROGRAM));diagnostic.validate_result(result,ID)
        self.assertEqual(result['rejection']['phase'],'cwd');self.assertEqual(result['rejection']['errno'],2)
        self.assertEqual(result['rejection']['directoryState'],'present')
        self.assertIs(result['admissionAllowed'],False)
        self.assertNotIn('command',str(result));self.assertNotIn(str(self.root),str(result))

    def test_actual_permission_gap_never_normalized_to_absence(self):
        native_readlink=os.readlink
        def deny(path,*a,**k):
            if Path(path)==self.entry/'cwd':raise PermissionError(13,'private secret argv')
            return native_readlink(path,*a,**k)
        with mock.patch('os.readlink',side_effect=deny):result=self.execute(self.source(diagnostic.PROGRAM))
        self.assertEqual(result['rejection']['errno'],13);self.assertEqual(result['rejection']['directoryState'],'present')
        self.assertNotIn('secret',str(result));diagnostic.validate_result(result,ID)

    def test_actual_vanished_process_is_diagnostic_only(self):
        source=self.source(diagnostic.PROGRAM).replace("phase='cmdline'", "phase='cmdline'\n   import shutil;shutil.rmtree(p)")
        result=self.execute(source);diagnostic.validate_result(result,ID)
        self.assertEqual(result['rejection']['directoryState'],'absent');self.assertIs(result['admissionAllowed'],False)

    def test_actual_pid_reuse_and_caps_distinguished(self):
        source=self.source(diagnostic.PROGRAM).replace("phase='stat-after'", "phase='stat-after'\n   (p/'stat').write_bytes(before.replace(b'888',b'999'))")
        result=self.execute(source);self.assertEqual(result['rejection']['phase'],'pid-generation')
        (self.entry/'cmdline').write_bytes(b'x'*65537)
        result=self.execute(self.source(diagnostic.PROGRAM));self.assertEqual(result['rejection']['phase'],'proc-cap')

    def test_success_cannot_become_usable_recovery_proof(self):
        result=self.execute(self.source(diagnostic.PROGRAM));diagnostic.validate_result(result,ID)
        self.assertIsNone(result['rejection']);self.assertIs(result['admissionAllowed'],False)
        with self.assertRaises(old.AdapterError):recovery._valid_remote(result)
        self.assertNotIn('proof',result)

    def test_matching_live_job_never_promotes_admission(self):
        (self.entry/'cmdline').write_bytes(b'git\0'+os.fsencode(self.job/'source')+b'\0')
        result=self.execute(self.source(diagnostic.PROGRAM));self.assertEqual(result['rejection']['phase'],'matching-job-process')
        self.assertEqual(result['rejection']['exitCode'],37)
        self.assertIs(result['admissionAllowed'],False)

    def test_foreign_effects_still_refuse_before_scan(self):
        (self.job/'tmux-worker.py').write_bytes(b'foreign')
        with self.assertRaises(AssertionError):self.execute(self.source(diagnostic.PROGRAM))
        self.assertEqual((self.job/'tmux-worker.py').read_bytes(),b'foreign')

    def test_exact_program_whitelist_and_false_bool(self):
        with self.assertRaises(old.AdapterError):diagnostic.command('print(1)')
        self.assertNotIn('\n',diagnostic.command(diagnostic.PROGRAM)[-1]);self.assertLess(len(diagnostic.command(diagnostic.PROGRAM)[-1]),30000)
        result=self.execute(self.source(diagnostic.PROGRAM));result['admissionAllowed']=0
        with self.assertRaises(old.AdapterError):diagnostic.validate_result(result,ID)


if __name__=='__main__':unittest.main()
