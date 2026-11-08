"""Incomplete Windows work visibility can never authorize a guest reboot."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from agent_tools import readiness_windows_idle as idle
from agent_tools.tests.test_readiness_windows_guest import facts,MACHINE,SID

BOOT='2026-10-20T09:37:35.5000000Z'
ROOT='12345678:0000000000000042:0000000000000001'


def observation():
    return {'schemaVersion':1,'sessionFacts':facts(),
            'leaseFacts':{'schemaVersion':1,'machine':MACHINE,'boot':BOOT,'rootGeneration':ROOT,
                          'visibilityComplete':True,'blockers':[],'terminalCount':1},
            'jobFacts':{'schemaVersion':1,'machine':MACHINE,'boot':BOOT,'rootGeneration':None,
                        'admissionGeneration':None,'visibilityComplete':True,'blockers':[],'terminalCount':0},
            'processes':[{'pid':4,'name':'System','session':0,'knownSystem':True,'self':False}],
            'lifecycle':{'setupComplete':True,'fixtureTaskDisabled':True,'installerAbsent':True},
            'blockers':[],'visibilityComplete':True}


class WindowsIdleTests(unittest.TestCase):
    def check(self,value):return idle.validate(value,MACHINE,BOOT,'recovery',SID,ROOT)

    def test_only_complete_current_native_inventory_has_no_blockers(self):
        value=self.check(observation())
        self.assertTrue(value['visibilityComplete']);self.assertEqual(frozenset(),value['blockers'])

    def test_active_unknown_lease_or_missing_visibility_blocks(self):
        for missing in ['guest','leases','unknownlease','jobs','unknownjob','operator','unknownprocess','installer']:
            value=observation()
            if missing=='guest':value['visibilityComplete']=False
            elif missing=='leases':value['leaseFacts']['visibilityComplete']=False;value['leaseFacts']['blockers']=[{'operationId':None,'reason':'lease_inventory_unavailable'}]
            elif missing=='unknownlease':value['leaseFacts']['blockers']=[{'operationId':MACHINE,'reason':'lease_original_work_not_terminal'}]
            elif missing=='jobs':value['jobFacts']['visibilityComplete']=False;value['jobFacts']['blockers']=[{'operationId':None,'reason':'job_inventory_unavailable'}]
            elif missing=='unknownjob':value['jobFacts']['blockers']=[{'operationId':MACHINE,'reason':'job_original_work_not_terminal'}]
            elif missing=='operator':value['sessionFacts']['sessions'].append({'Id':3,'Name':'RDP-Tcp#0','State':0})
            elif missing=='unknownprocess':value['processes'][0]['knownSystem']=False
            else:value['lifecycle']['installerAbsent']=False
            with self.subTest(case=missing):self.assertTrue(self.check(value)['blockers'])

    def test_foreign_epoch_and_malformed_census_are_refused(self):
        value=observation();value['sessionFacts']['boot']='2026-10-20T10:37:35.5000000Z'
        with self.assertRaisesRegex(ValueError,'windows_idle_epoch'):self.check(value)
        for field,bad in [('pid',True),('session',True),('self',1),('name','private\ninput')]:
            value=observation();value['processes'][0][field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):self.check(value)

    def test_generator_has_readonly_boundaries_and_no_input_channel(self):
        source=idle.powershell_source(MACHINE,BOOT,'recovery',SID,ROOT)
        self.assertEqual(1,source.count('[Console]::WriteLine'))
        self.assertIn('Win32_Process',source);self.assertIn('VpnControlFixtureInitialize',source)
        for command in ['guest-shutdown','Restart-Computer','Set-ItemProperty','SendKeys','SendInput']:
            self.assertNotIn(command,source)
        for bad in [None,'operator\ncommand']:
            with self.assertRaises(ValueError):idle.powershell_source(MACHINE,BOOT,bad,SID,ROOT)


FIXTURE=Path(__file__).parent/'fixtures/windows_product_allowance'
PROTECTED=r"'^(sing-box|vpn.?control|wireguard|openvpn|tailscale)(\.exe)?$'"


def before_observe():
    raw=(FIXTURE/'idle.before.source').read_bytes()
    if hashlib.sha256(raw).hexdigest()!=json.loads((FIXTURE/'provenance.json').read_bytes())['sources']['idle.before.source']['sha256']:
        raise AssertionError('idle beforeimage changed')
    return next(ast.literal_eval(n.value) for n in ast.parse(raw).body if isinstance(n,ast.Assign) and getattr(n.targets[0],'id','')=='_OBSERVE')


def protected_line(source):
    lines=[line for line in source.splitlines() if PROTECTED in line]
    if len(lines)!=1:raise AssertionError('one protected-process line')
    return lines[0]


class ProductAllowanceTests(unittest.TestCase):
    """A passed preboot row's declared product may run through readiness-reboot; nothing else may."""
    def test_before_the_census_blocked_every_running_product_and_now_only_an_undeclared_one(self):
        before=protected_line(before_observe())
        # A source guard only. The reproducer runs the census decision itself: CensusDecisionTests, where PowerShell exists.
        self.assertEqual(" if($name -match "+PROTECTED+"){$blockers.Add('protected_processes')}",before)
        for name in ('vpn-control.exe','sing-box.exe'):self.assertRegex(name,PROTECTED.strip("'"))
        current=protected_line(idle._OBSERVE)
        self.assertEqual(" if(-not $declared -and $name -match "+PROTECTED+"){$blockers.Add('protected_processes')}",current)
        declared=[line for line in idle._OBSERVE.splitlines() if line.lstrip().startswith('$declared=')]
        self.assertEqual([" $declared=[bool]($identity -and -not $known -and -not $self -and (Test-DeclaredProduct $p $native))"],declared)
        self.assertNotIn('Test-DeclaredProduct',before_observe())

    def test_only_the_two_product_images_can_ever_be_declared(self):
        self.assertIn("$ProductNames=@('vpn-control.exe','sing-box.exe')",idle.ALLOWANCE)
        self.assertEqual(1,idle.ALLOWANCE.count('$ProductNames=@('))
        for name in ('consent.exe','vpn-control-cli.exe','python','powershell','msiexec'):self.assertNotIn(name,idle.ALLOWANCE.lower())

    def test_the_allowance_only_reads_and_any_failure_grants_nothing(self):
        for command in ('Set-','Remove-','New-Item','Out-File','WriteAll','Move-','Copy-','Start-Process','Stop-Process','Rename-','.Run(','Invoke-Expression'):
            self.assertNotIn(command,idle.ALLOWANCE)
        self.assertIn("}catch{return $a}",idle.ALLOWANCE)
        self.assertIn("}catch{continue}}",idle.ALLOWANCE)
        self.assertIn("}catch{return $false}}",idle.ALLOWANCE)
        self.assertNotIn('[Console]::WriteLine',idle.ALLOWANCE)

    def test_every_declared_fact_is_checked_live(self):
        for fact in ('$v.machine -cne $machine','$v.bootFileTimeUtc -cne $boot','$v.ordinarySid -cne $account','$v.sessionId -ne $console',
                     "-ceq 'S-1-5-18'",'Get-FileHash -LiteralPath $n.image -Algorithm SHA256','GetOwnerSid','$pp -ne [UInt32]$r.parentPid',
                     "Name='Schedule'","\\System32\\svchost.exe",'[UInt64]$pn.birth -ge [UInt64]$n.birth','$v.operationId -cne $f.Name.Substring(23)'):
            self.assertIn(fact,idle.ALLOWANCE)

    def test_the_job_writes_exactly_what_the_census_reads(self):
        from agent_tools import windows_scenario_host_job as job
        self.assertEqual(job.ALLOWANCE_SCHEMA,'vpn-control.windows-product-allowance')
        self.assertIn("'"+job.ALLOWANCE_SCHEMA+"'",idle.ALLOWANCE)
        self.assertIn("'"+job.ALLOWANCE_LEAF+"'",idle.ALLOWANCE)
        self.assertEqual(len('VpnControlOrdinaryTask-'),23)
        self.assertTrue(job.WORKSPACE_PREFIX.endswith('\\VpnControlOrdinaryTask-'))
        for name in ('schema','schemaVersion','operationId','machine','bootFileTimeUtc','ordinarySid','sessionId','processes'):
            self.assertIn('$v.'+name,idle.ALLOWANCE)
        for name in ('pid','parentPid','creationFileTime','image','sha256'):
            self.assertIn('$r.'+name,idle.ALLOWANCE)

    def test_the_census_with_the_allowance_stays_one_ascii_read_only_program(self):
        source=idle.powershell_source(MACHINE,BOOT,'recovery',SID,ROOT)
        source.encode('ascii');self.assertEqual(1,source.count('[Console]::WriteLine'))
        self.assertLess(source.index('Read-ProductAllowance $Machine'),source.index('$rows=@(foreach($p in $processes){'))

    def test_the_census_decision_harness_runs_the_real_observe_on_both_sources(self):
        # What CensusDecisionTests hands Windows PowerShell; composing it needs no PowerShell.
        for observe,allowance in ((idle._OBSERVE,idle.ALLOWANCE),(before_observe(),'')):
            with tempfile.TemporaryDirectory()as directory:
                program=census_program(directory,observe,allowance).read_bytes().decode('ascii')
                self.assertEqual((2,1 if allowance else 0),(program.count(observe),program.count(allowance) if allowance else 0))
                self.assertLess(program.index('function Test-SystemOwned($x) { $true }'),program.index(observe))


ALLOWANCE_HARNESS=r"""
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;
public sealed class AllowanceStubFacts {public UInt32 pid;public string image="";public string birth="";public int birthError=0;}
public static class RecoveryProcessIdentity {
 public static Dictionary<UInt32,AllowanceStubFacts> Rows=new Dictionary<UInt32,AllowanceStubFacts>();
 public static AllowanceStubFacts Read(UInt32 id){return Rows[id];}
}
'@
$script:Owner=$Account;$script:Schedule=40;$script:Failed=New-Object 'System.Collections.Generic.List[string]'
function Invoke-CimMethod { @{ReturnValue=0;Sid=$script:Owner} }
function Get-CimInstance { @(@{ProcessId=$script:Schedule}) }
function Test-SystemOwned($x) { $true }
function New-Facts([UInt32]$id,[string]$image,[string]$birth){$row=New-Object AllowanceStubFacts;$row.pid=$id;$row.image=$image;$row.birth=$birth;[RecoveryProcessIdentity]::Rows[$id]=$row;return $row}
function Expect([bool]$actual,[bool]$wanted,[string]$label){if($actual -ne $wanted){$script:Failed.Add($label)}}
$RecoveryRoleProcessMap=@{}
function Add-Row([UInt32]$id,[string]$name,[UInt32]$parent,[UInt32]$session){$p=@{ProcessId=$id;Name=$name;ParentProcessId=$parent;SessionId=$session};$RecoveryRoleProcessMap[$id]=$p;return $p}
$null=Add-Row 40 'svchost.exe' 4 0;$null=New-Facts 40 ($env:SystemRoot+'\System32\svchost.exe') '1000'
$null=Add-Row 41 'python.exe' 40 2;$null=New-Facts 41 'C:\Users\fixtureuser\AppData\Local\Programs\Python\Python313\python.exe' '1100'
$ProductAllowance=Read-ProductAllowance $Machine $Account 2 $Boot
Expect ($ProductAllowance.Count -eq 3) $true 'DECLARATION_UNREAD'
$root=Add-Row 50 'vpn-control.exe' 40 2;$rootFacts=New-Facts 50 $Image '2000'
$jvm=Add-Row 51 'vpn-control.exe' 50 2;$jvmFacts=New-Facts 51 $Image '2001'
Expect (Test-DeclaredProduct $root $rootFacts) $true 'ROOT_REFUSED'
Expect (Test-DeclaredProduct $jvm $jvmFacts) $true 'JVM_REFUSED'
$other=Add-Row 52 'vpn-control.exe' 40 2;Expect (Test-DeclaredProduct $other (New-Facts 52 $Image '2002')) $false 'UNDECLARED_ALLOWED'
$child=Add-Row 53 'vpn-control.exe' 41 2;Expect (Test-DeclaredProduct $child (New-Facts 53 $Image '2003')) $false 'DECLARED_OWNER_CHILD_ALLOWED'
$consent=Add-Row 54 'consent.exe' 40 2;Expect (Test-DeclaredProduct $consent (New-Facts 54 $Image '2004')) $false 'CONSENT_ALLOWED'
$script:Owner='S-1-5-21-9-9-9-1001';Expect (Test-DeclaredProduct $root $rootFacts) $false 'WRONG_SID_ALLOWED';$script:Owner=$Account
$root.SessionId=3;Expect (Test-DeclaredProduct $root $rootFacts) $false 'WRONG_SESSION_ALLOWED';$root.SessionId=2
[IO.File]::WriteAllBytes($Image,[Text.Encoding]::ASCII.GetBytes('changed'));Expect (Test-DeclaredProduct $root $rootFacts) $false 'WRONG_HASH_ALLOWED'
[IO.File]::WriteAllBytes($Image,[Text.Encoding]::ASCII.GetBytes('product'))
$script:Schedule=99;Expect (Test-DeclaredProduct $root $rootFacts) $false 'ROOT_WITHOUT_SCHEDULER_ALLOWED';$script:Schedule=40
function Test-SystemOwned($x) { $false }
Expect ((Read-ProductAllowance $Machine $Account 2 $Boot).Count -eq 0) $true 'FOREIGN_OWNER_READ'
function Test-SystemOwned($x) { $true }
Expect ((Read-ProductAllowance $Machine $Account 2 '2026-10-21T09:37:35.5000000Z').Count -eq 0) $true 'STALE_BOOT_READ'
Expect ((Read-ProductAllowance $Machine 'S-1-5-21-9-9-9-1001' 2 $Boot).Count -eq 0) $true 'OTHER_ACCOUNT_READ'
[Console]::WriteLine((@{failed=@($script:Failed)}|ConvertTo-Json -Compress))
"""


CENSUS_HARNESS=r"""
$ErrorActionPreference='Stop'
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;
public sealed class CensusStubFacts {public UInt32 pid;public string image="";public string birth="";public int birthError=0;}
public static class RecoveryProcessIdentity {
 public static Dictionary<UInt32,CensusStubFacts> Rows=new Dictionary<UInt32,CensusStubFacts>();
 public static CensusStubFacts Read(UInt32 id){return Rows[id];}
 public static bool Image(CensusStubFacts f,string name,string cimBirth){return f.image.Length>0&&String.Equals(System.IO.Path.GetFileName(f.image),name,StringComparison.OrdinalIgnoreCase);}
 public static bool Kernel(CensusStubFacts f,string name,UInt32 parent,UInt32 session,string cimBirth){return false;}
}
'@
$script:Census=@()
function Get-CimInstance {[CmdletBinding()]param([Parameter(Position=0)][string]$ClassName,[string]$Filter)
 if($ClassName -eq 'Win32_Service'){return [pscustomobject]@{ProcessId=40}};return $script:Census}
function Invoke-CimMethod {[CmdletBinding()]param($InputObject,[string]$MethodName) [pscustomobject]@{ReturnValue=0;Sid=$Account}}
function Test-RecoveryExtraRole { $false }
function Get-ItemProperty { [pscustomobject]@{SystemSetupInProgress=0;OOBEInProgress=0} }
function Get-ScheduledTask { [pscustomobject]@{State='Disabled'} }
function Test-Path { $false }
function Add-Process([UInt32]$id,[string]$name,[UInt32]$parent,[UInt32]$session,[string]$image,[string]$birth){
 $f=New-Object CensusStubFacts;$f.pid=$id;$f.image=$image;$f.birth=$birth;[RecoveryProcessIdentity]::Rows[$id]=$f
 $script:Census+=,([pscustomobject]@{ProcessId=$id;Name=$name;ParentProcessId=$parent;SessionId=$session;CreationDate=$null})}
"""
# The Task Scheduler service, then the declared GUI launcher, its JVM and the runtime under it.
CENSUS_WORLD=r"""
function Test-SystemOwned($x) { $true }
Add-Process 40 'svchost.exe' 4 0 ($env:SystemRoot+'\System32\svchost.exe') '1000'
Add-Process 50 'vpn-control.exe' 40 2 $Gui '2000'
Add-Process 51 'vpn-control.exe' 50 2 $Gui '2001'
Add-Process 52 'sing-box.exe' 51 2 $Runtime '2002'
"""


def census_program(directory,observe,allowance):
    """One ASCII program: the declaration as a passed preboot publishes it, stubs for the OS facts, then _OBSERVE twice."""
    data=Path(directory);operation='33333333-4444-4555-8666-777777777778'
    folder=data/('VpnControlOrdinaryTask-'+operation);folder.mkdir()
    gui=data/'vpn-control.exe';gui.write_bytes(b'product');runtime=data/'sing-box.exe';runtime.write_bytes(b'runtime')
    from datetime import datetime,timezone
    delta=datetime(2026,10,20,9,37,35,500000,tzinfo=timezone.utc)-datetime(1601,1,1,tzinfo=timezone.utc)
    rows=[(50,40,'2000',gui,b'product'),(51,50,'2001',gui,b'product'),(52,51,'2002',runtime,b'runtime')]
    declaration={'schema':'vpn-control.windows-product-allowance','schemaVersion':1,'operationId':operation,'machine':MACHINE,
                 'bootFileTimeUtc':str((delta.days*86400+delta.seconds)*10**7+delta.microseconds*10),'ordinarySid':SID,'sessionId':2,
                 'processes':[{'pid':pid,'parentPid':parent,'creationFileTime':birth,'image':str(image),'sha256':hashlib.sha256(raw).hexdigest()}
                              for pid,parent,birth,image,raw in rows]}
    (folder/'product-allowance.json').write_bytes((json.dumps(declaration)+'\n').encode())
    literal=lambda value:"'"+str(value).replace("'","''")+"'"
    prelude=("$env:ProgramData="+literal(directory)+";$Machine="+literal(MACHINE)+";$Account="+literal(SID)+";$Boot="+literal(BOOT)
             +";$Gui="+literal(gui)+";$Runtime="+literal(runtime)+";$leaseFacts=@{};$jobFacts=@{}"
             +";$sessionFacts=[pscustomobject]@{machine=$Machine;boot=$Boot;expectedSid=$Account;ordinary=$true;console=2}\n")
    program=prelude+CENSUS_HARNESS+allowance+CENSUS_WORLD+observe+"\nAdd-Process 53 'vpn-control.exe' 40 2 $Gui '2003'\n"+observe
    path=data/'census.ps1';path.write_bytes(program.encode('ascii'))
    return path


def census_decisions(observe,allowance):
    """The census's own row decision over declared stub facts: the declared app alone, then beside an undeclared one."""
    with tempfile.TemporaryDirectory()as directory:
        path=census_program(directory,observe,allowance)
        result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,timeout=120)
    if result.returncode!=0:raise RuntimeError((result.stdout+result.stderr).decode(errors='replace'))
    return [json.loads(line) for line in result.stdout.decode().splitlines() if line.strip()]


def check_declared_product_passes(case,observe,allowance):
    """The regression: the declared app adds neither protected_processes nor unknown_jobs; an undeclared one adds both."""
    declared,undeclared=census_decisions(observe,allowance)
    known=lambda value:{row['pid']:row['knownSystem'] for row in value['processes']}
    case.assertEqual({40:True,50:True,51:True,52:True},known(declared))
    case.assertEqual(set(),{'protected_processes','unknown_jobs'}&set(declared['blockers']))
    case.assertEqual({40:True,50:True,51:True,52:True,53:False},known(undeclared))
    case.assertEqual({'protected_processes','unknown_jobs'},{'protected_processes','unknown_jobs'}&set(undeclared['blockers']))


@unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'The census row decision runs in Windows PowerShell')
class CensusDecisionTests(unittest.TestCase):
    """The census's own _OBSERVE decides each row; only the OS facts it reads are declared stubs."""
    def test_a_declared_product_passes_the_census_and_an_undeclared_one_still_blocks(self):
        check_declared_product_passes(self,idle._OBSERVE,getattr(idle,'ALLOWANCE',''))

    def test_the_unfixed_census_fails_the_same_regression(self):
        # RED kept in the suite: the before-image blocked the declared app by its name alone.
        with self.assertRaises(AssertionError):
            check_declared_product_passes(self,before_observe(),'')


@unittest.skipUnless(os.name=='nt' and shutil.which('powershell.exe'),'Actual Windows PowerShell allowance decisions')
class NativeAllowanceTests(unittest.TestCase):
    def test_the_declared_app_is_allowed_and_every_control_still_blocks(self):
        with tempfile.TemporaryDirectory()as directory:
            data=Path(directory);operation='33333333-4444-4555-8666-777777777778'
            folder=data/('VpnControlOrdinaryTask-'+operation);folder.mkdir()
            image=data/'vpn-control.exe';image.write_bytes(b'product')
            digest=hashlib.sha256(b'product').hexdigest()
            boot='2026-10-20T09:37:35.5000000Z'
            from datetime import datetime,timezone
            delta=datetime(2026,10,20,9,37,35,500000,tzinfo=timezone.utc)-datetime(1601,1,1,tzinfo=timezone.utc)
            filetime=str((delta.days*86400+delta.seconds)*10**7+delta.microseconds*10)
            declaration={'schema':'vpn-control.windows-product-allowance','schemaVersion':1,'operationId':operation,'machine':MACHINE,
                         'bootFileTimeUtc':filetime,'ordinarySid':SID,'sessionId':2,
                         'processes':[{'pid':50,'parentPid':40,'creationFileTime':'2000','image':str(image),'sha256':digest},
                                      {'pid':51,'parentPid':50,'creationFileTime':'2001','image':str(image),'sha256':digest},
                                      # Declared, yet its parent is the owner's python: never the scheduler's start.
                                      {'pid':53,'parentPid':41,'creationFileTime':'2003','image':str(image),'sha256':digest}]}
            (folder/'product-allowance.json').write_bytes((json.dumps(declaration)+'\n').encode())
            literal=lambda value:"'"+str(value).replace("'","''")+"'"
            prelude=("$env:ProgramData="+literal(directory)+";$Machine="+literal(MACHINE)+";$Account="+literal(SID)+";$Boot="+literal(boot)
                     +";$Image="+literal(image)+";$sessionFacts=@{console=2}\n")
            path=data/'allowance.ps1';path.write_text(prelude+idle.ALLOWANCE+ALLOWANCE_HARNESS,encoding='utf-8')
            result=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(path)],capture_output=True,timeout=120)
        self.assertEqual(0,result.returncode,(result.stdout+result.stderr).decode(errors='replace'))
        failed=json.loads(result.stdout)['failed']
        self.assertEqual([],[] if failed is None else [failed] if type(failed) is str else failed)


if __name__=='__main__':unittest.main()
