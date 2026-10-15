"""Standalone selector CLI uses the prepared environment, real child execution."""
import contextlib,io,os,shutil,sys,tempfile,types,unittest
from pathlib import Path
from unittest import mock
from agent_tools import affected_agent_tests as subject

@unittest.skipUnless(os.name=='posix','POSIX executable wrapper fixture')
class PreparedInterpreterTests(unittest.TestCase):
    def test_complete_cli_runs_selected_test_in_prepared_runtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);scripts=root/'scripts';scripts.mkdir();(scripts/'__init__.py').write_text('')
            (scripts/'test_environment.py').write_text("import os,unittest\nclass T(unittest.TestCase):\n def test_environment(self):self.assertEqual('prepared',os.environ.get('VC_TEST_ENVIRONMENT'))\n")
            binary=root/'.agent_venv/bin/python';binary.parent.mkdir(parents=True)
            binary.write_text('#!'+sys.executable+'\nimport os,sys\nos.environ["VC_TEST_ENVIRONMENT"]="prepared"\nos.execv(sys.executable,[sys.executable,*sys.argv[1:]])\n');binary.chmod(0o700)
            selected=types.SimpleNamespace(modules=[],as_dict=lambda:{'modules':[]},commands=lambda python:[])
            with mock.patch.object(subject,'select',return_value=selected),mock.patch.object(subject,'snapshot',return_value='a'*64),mock.patch.object(subject,'serial_command',side_effect=lambda root,command,fingerprint:command),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0,subject.main(['--root',str(root),'--run','--include','scripts.test_environment']))

if __name__=='__main__':unittest.main()
