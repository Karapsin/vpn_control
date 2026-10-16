"""Actual PowerShell setup/installer boundary counterfactual; no native MSI claim."""
import ast
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from agent_tools import windows_vm_unattend as setup
from agent_tools.tests.fixtures.windows_powershell_environment import windows_powershell_environment


@unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'native Windows PowerShell 5.1')
class SetupPhaseTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.folder=Path(__file__).parent/'fixtures/setup_msi_phase'
        metadata=json.loads((self.folder/'provenance.json').read_bytes())
        row=next(x for x in metadata['sources'] if x['source']=='windows_vm_unattend.py')
        raw=(self.folder/row['file']).read_bytes();self.assertEqual(row['sha256'],hashlib.sha256(raw).hexdigest())
        tree=ast.parse(raw)
        before=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and
                    any(isinstance(t,ast.Name) and t.id=='INITIALIZE' for t in n.targets))
        self.scripts={}
        for name,text in (('before',before),('initialize',setup.INITIALIZE),('install',setup.INSTALL_AGENT)):
            path=self.root/(name+'.ps1');path.write_text(text,encoding='utf-8-sig');self.scripts[name]=str(path)
        self.sequence=0

    def run_case(self,mode,root=None,harness=None):
        self.sequence+=1
        root=root or self.root/('case-'+str(self.sequence));root.mkdir(exist_ok=True)
        request=self.root/('request-'+str(self.sequence)+'.json')
        request.write_text(json.dumps({'mode':mode,'root':str(root),**self.scripts}),encoding='utf8')
        result=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',
                               str(harness or self.folder/'native_harness.ps1'),'-RequestFile',str(request)],
                              capture_output=True,timeout=30, env=windows_powershell_environment('powershell.exe', os.environ))
        return result,root

    def value(self,result):
        self.assertEqual(0,result.returncode,result.stderr.decode('utf8','replace'))
        return json.loads(result.stdout.decode('utf-8-sig').strip().splitlines()[-1])

    def test_preserved_specialize_invokes_installer_early_fixed_stages_only_system_task(self):
        before=self.value(self.run_case('beforeEarly')[0])
        after=self.value(self.run_case('fixedEarly')[0])
        self.assertEqual('MSI_BEFORE_SETUP_COMPLETE',before['outcome']);self.assertEqual(1,before['msiCalls'])
        self.assertEqual('completed',after['outcome']);self.assertEqual(0,after['msiCalls'])
        self.assertEqual(1,after['taskCalls'])

    def test_deferred_install_waits_for_setup_and_an_uncertain_install_is_not_replayed(self):
        success=self.value(self.run_case('fixedReady')[0])
        self.assertEqual('completed',success['outcome']);self.assertEqual(1,success['msiCalls'])
        self.assertGreater(success['sleeps'],0)
        result,root=self.run_case('fixedUnknown');unknown=self.value(result)
        self.assertEqual('GUEST_AGENT_INSTALL_UNKNOWN',unknown['outcome'])
        intent=root/'VpnControlFixture/agent-install-intent.json';saved=intent.read_bytes()
        calls=(root/'installer-calls.txt').read_bytes()
        retry,_=self.run_case('retry',root)
        self.assertEqual(74,retry.returncode)
        self.assertEqual(saved,intent.read_bytes());self.assertEqual(calls,(root/'installer-calls.txt').read_bytes())

    def test_actual_parent_before_loses_terminal_code_fixed_held_handle_retains_it(self):
        folder=Path(__file__).parent/'fixtures/setup_process_capture'
        provenance=json.loads((folder/'provenance.json').read_bytes())
        for filename,expected in (('before.ps1',None),('after.ps1',0)):
            with self.subTest(filename=filename):
                raw=(folder/filename).read_bytes()
                self.assertEqual(provenance[filename.split('.')[0]+'Sha256'],hashlib.sha256(raw).hexdigest())
                # setUp already owns before.ps1 as a script file. Each parent
                # control gets a disjoint directory without adopting that file.
                root=self.root/('parent-case-'+filename);root.mkdir()
                for role,path in self.scripts.items():(root/(role+'.ps1')).write_bytes(Path(path).read_bytes())
                (root/'harness.ps1').write_bytes((self.folder/'native_harness.ps1').read_bytes())
                runner=root/'parent.ps1'
                runner.write_text('''param([string]$RequestFile)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$data=Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
$root=$data.root
. $data.parentSource
$capture=Run-Case 'beforeEarly' (Join-Path $root 'case-root')
[Console]::WriteLine((@{code=$capture.code;outcome=$capture.value.outcome;msiCalls=$capture.value.msiCalls} | ConvertTo-Json -Compress))
''',encoding='utf-8-sig')
                request=root/'request.json';request.write_text(json.dumps({'root':str(root),'parentSource':str(folder/filename)}),encoding='utf8')
                result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(runner),'-RequestFile',str(request)],capture_output=True,timeout=30, env=windows_powershell_environment('powershell.exe', os.environ))
                value=self.value(result)
                self.assertEqual(expected,value['code']);self.assertEqual('MSI_BEFORE_SETUP_COMPLETE',value['outcome']);self.assertEqual(1,value['msiCalls'])

    def test_preserved_harness_masks_exit_fixed_propagates_without_installer_replay(self):
        folder=Path(__file__).parent/'fixtures/setup_child_exit';before=folder/'before.ps1'
        self.assertEqual(json.loads((folder/'provenance.json').read_bytes())['sourceSha256'],hashlib.sha256(before.read_bytes()).hexdigest())
        result,root=self.run_case('fixedUnknown');self.assertEqual('GUEST_AGENT_INSTALL_UNKNOWN',self.value(result)['outcome'])
        intent=root/'VpnControlFixture/agent-install-intent.json';calls=root/'installer-calls.txt'
        original=intent.read_bytes(),calls.read_bytes()
        old,_=self.run_case('retry',root,harness=before)
        self.assertEqual(0,old.returncode);self.assertEqual(0,self.value(old)['msiCalls'])
        fixed,_=self.run_case('retry',root)
        self.assertEqual(74,fixed.returncode);self.assertEqual(original,(intent.read_bytes(),calls.read_bytes()))


if __name__=='__main__':unittest.main()
