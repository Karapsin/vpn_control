"""Exercise the actual fixed fixture driver with inert native-command seams."""
import io
import os
from pathlib import Path, PureWindowsPath
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scripts import test_jpackage_launcher as launcher
from agent_tools import linux_package_fixture_build as fixture
REQUEST={'sourceSha':'60e925b21274d5502517562c8d9375b24881464f',
 'baseVersion':'2.2.6','targetVersion':'2.2.7',
 'correlationId':'55bb5555-5555-4555-8555-555555555555'}

class FixtureLauncherPreflightTest(unittest.TestCase):
 def driver(self,stderr):
  with tempfile.TemporaryDirectory() as temp:
   job=Path(temp);jdk=job/'jdk';source=job/'source'
   runtime=source/'desktopApp/src/main/resources/bin/linux-amd64/sing-box'
   runtime.parent.mkdir(parents=True);runtime.write_bytes(b'inert-runtime')
   for name in ('java','javac','jar','jpackage'):
    exe=jdk/'bin'/name;exe.parent.mkdir(parents=True,exist_ok=True);exe.touch()
   calls=[];effects=[]
   def native(command,**kwargs):
    if PureWindowsPath(command[0]).name == 'java':return subprocess.CompletedProcess(command,0,'','openjdk version "17.0.20.1"')
    if PureWindowsPath(command[0]).name == 'jpackage':
     output=Path(command[command.index('--dest')+1])/'launcher-preflight/bin/launcher-preflight'
     output.parent.mkdir(parents=True);output.touch()
    if PureWindowsPath(command[0]).name == 'launcher-preflight':return subprocess.CompletedProcess(command,0,'JPACKAGE_LAUNCHER_OK\n',stderr)
    return subprocess.CompletedProcess(command,0,'','')
   def run_build(argv,cwd,log,timeout):
    calls.append(argv)
    if 'scripts/test_jpackage_launcher.py' in argv:
     try:launcher.run_preflight(Path(argv[-1]),runner=native)
     except launcher.LauncherPreflightError:raise fixture.LinuxPackageFixtureBuildError('Fixed Linux package build failed')
    else:effects.append(argv)
   with patch.dict(os.environ,{'JAVA_HOME':str(jdk)}), \
     patch.object(fixture,'_run_build',side_effect=run_build), \
     patch.object(fixture.subprocess,'run',return_value=subprocess.CompletedProcess([],0,REQUEST['sourceSha']+'\n','')), \
     patch.object(fixture,'_verify_built',return_value=[]), \
     patch.object(fixture,'_timing_inventory',return_value=[]), \
     patch.object(fixture.sys,'stdout',SimpleNamespace(buffer=io.BytesIO())), \
     patch.object(launcher.sys,'platform','linux'):
    error=None
    try:fixture._remote_run(job,REQUEST)
    except fixture.LinuxPackageFixtureBuildError as exc:error=exc
   return calls,effects,error
 def test_abort_on_stderr_stops_before_runtime_and_package_build(self):
  calls,effects,error=self.driver('pure virtual method called\nterminate called without an active exception\n')
  self.assertIsNotNone(error,'actual driver admitted the measured dirty launcher')
  self.assertEqual([],effects,'runtime/package effects ran before strict launcher admission')
  self.assertEqual(1,len(calls))
 def test_clean_launcher_retains_both_fixed_families(self):
  calls,effects,error=self.driver('')
  self.assertIsNone(error);self.assertEqual(6,len(calls));self.assertEqual(5,len(effects))
  self.assertEqual('scripts/test_jpackage_launcher.py',calls[0][1]);self.assertEqual(['default','arch'],[a[a.index('--timing-pipeline-id')+1].split('-')[-1] for a in effects if '--timing-pipeline-id' in a])
 def test_inert_native_command_names_accept_both_platform_spellings(self):
  for name in ('java','jpackage','launcher-preflight'):
   self.assertEqual(name,PureWindowsPath('C:/JDK/bin/'+name).name)
   self.assertEqual(name,PureWindowsPath('/tmp/JDK/bin/'+name).name)
 def test_java_home_precedes_path(self):
  with tempfile.TemporaryDirectory() as temp:
   home=Path(temp);(home/'bin').mkdir();(home/'bin/java').touch()
   with patch.dict(os.environ,{'JAVA_HOME':str(home)}),patch.object(fixture.shutil,'which',side_effect=AssertionError('PATH consulted')):
    self.assertEqual(home.resolve(),fixture._launcher_jdk())
 def test_path_jvm_resolves_the_same_jdk(self):
  with tempfile.TemporaryDirectory() as temp:
   home=Path(temp);(home/'bin').mkdir();(home/'bin/java').touch()
   with patch.dict(os.environ,{'JAVA_HOME':''}),patch.object(fixture.shutil,'which',return_value=str(home/'bin/java')):
    self.assertEqual(home.resolve(),fixture._launcher_jdk())
 def test_missing_path_jvm_refuses(self):
  with patch.dict(os.environ,{'JAVA_HOME':''}),patch.object(fixture.shutil,'which',return_value=None):
   with self.assertRaises(fixture.LinuxPackageFixtureBuildError):fixture._launcher_jdk()
 def test_missing_home_refuses_without_build(self):
  with patch.dict(os.environ,{'JAVA_HOME':'/nonexistent-parity-jdk-5d718884'}):
   with self.assertRaises(FileNotFoundError):fixture._launcher_jdk()

if __name__=='__main__':unittest.main()
