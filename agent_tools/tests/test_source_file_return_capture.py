"""Actual child streams prove separate bounded file-return output budgets."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from agent_tools import ssh_source_file_stage_direct as stage
from agent_tools import windows_vm_deploy as deploy
from agent_tools import android_qualified_cli_observation as original


@unittest.skipUnless(os.name=='posix','protected local pipe fixture')
class FileReturnCaptureTests(unittest.TestCase):
    def test_default_stays_bounded_file_return_retains_complete_stdout_and_natural_exit(self):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve()) as temporary:
            root=Path(temporary);source=root/'producer.py'
            source.write_text("import json,sys\nsys.stdin.buffer.read()\nprint(json.dumps({'bytes':'x'*(128*1024)}))\n")
            ordinary=root/'ordinary';ordinary.mkdir();large=root/'large';large.mkdir()
            with self.assertRaisesRegex(ValueError,'unverified'):stage._run(ordinary,[sys.executable,'-I',str(source)],b'{}','native')
            truncated=json.loads((ordinary/'native-terminal.json').read_bytes())
            self.assertTrue(truncated['complete']);self.assertTrue(truncated['overflow']);self.assertEqual(0,truncated['returnCode'])
            value=stage._run(large,[sys.executable,'-I',str(source)],b'{}','native',file_output=True)
            self.assertEqual(128*1024,len(value['bytes']))
            terminal=json.loads((large/'native-terminal.json').read_bytes())
            self.assertTrue(terminal['complete']);self.assertFalse(terminal['overflow']);self.assertEqual(0,terminal['returnCode'])
            self.assertEqual(terminal['counts']['stdout'],(large/'native-stdout.private').stat().st_size)
            self.assertEqual(65536,original.OUTER_CAP)
    def test_invalid_budgets_refuse_before_child_and_gateway_only_changes_output_budget(self):
        with mock.patch.object(stage.subprocess,'Popen',side_effect=AssertionError('must not launch')):
            for invalid in (True,0,2**30):
                with self.assertRaises(ValueError):stage.FileCapture([],capture_limit=invalid)
        receipt={'path':'/tmp/vpn-control-windows-caller-'+'a'*32+'/caller.py','sha256':'ab'*32,'bytes':123,'principal':'fixture'}
        for mode,expected in ((False,4096),(True,5242880)):
            namespace={};exec(compile(deploy.gateway_program(receipt,file_output=mode),'complete saved gateway','exec'),namespace)
            self.assertEqual(expected,namespace['CAP']);self.assertLess(len(namespace['COMMAND'].encode()),60000)


if __name__=='__main__':unittest.main()
