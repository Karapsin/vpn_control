"""Fast inert regressions for the fixed retained downloader observer."""
from __future__ import annotations

import base64
import copy
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from agent_tools import windows_cp117_e848_http_task as task


NONCE = 'A'*32


def proof():
    return {'state':'observed','taskState':'Ready',
            'execute':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'arguments':'-NoProfile -NonInteractive -EncodedCommand '+base64.b64encode(task._script(43210,NONCE).encode('utf-16le')).decode(),
            'workingDirectory':'','principalSid':task._GENERATION[4],
            'logonType':'Interactive','runLevel':'Limited','triggerCount':0,'executionTimeLimit':'PT5M',
            'lastRunTicks':638500000000000000,'nowTicks':638600000000000000,'lastTaskResult':0,
            'correlationProcess':'absent','installer':'absent'}


@unittest.skipUnless(task.history._supported(), 'POSIX private journal locking required')
class RetainedHttpTaskTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        rag=self.root/'.rag_index';rag.mkdir(mode=0o700)
        self.record={'routeNonce':NONCE};self.closed={'state':'closed','identity':{'leaseId':task._LEASE}}
        self.records={relative:{'retained':relative} for relative in task._RECORD_SHA}
        self.records['windows-update-fixture-http-stage/'+task._CORR+'.json']=self.record
        self.records['windows-cp117-campaign/'+task._LEASE+'.closed.json']=self.closed
        for relative,value in self.records.items():
            p=rag/relative;p.parent.mkdir(mode=0o700,exist_ok=True);p.write_text(json.dumps(value));p.chmod(0o600)
        self.campaign=self.root/task.base.campaign_lease._DIR
        p=self.campaign/'.environment.lock';p.write_bytes(b'');p.chmod(0o600)
        patch=mock.patch.object(task,'_RECORD_SHA',{k:task.history._digest(v) for k,v in self.records.items()})
        patch.start();self.addCleanup(patch.stop)
        self.descriptor=mock.patch.object(task.base,'_descriptor',return_value=(None,SimpleNamespace(fixture_transfer_root='/inert'),task._GENERATION))
        self.descriptor.start();self.addCleanup(self.descriptor.stop)

    def observe(self, first=None, second=None):
        first=proof() if first is None else first
        second=copy.deepcopy(first) if second is None else second
        with mock.patch.object(task.base,'_remote',return_value=json.dumps({'state':'observed','proofs':[first,second]})) as remote:
            result=task.observe(self.root,{})
        return result,remote

    def test_good_terminal_is_read_only_and_public_has_no_private_metadata(self):
        before={p:p.read_bytes() for p in (self.root/'.rag_index').rglob('*') if p.is_file()}
        observed,remote=self.observe()
        self.assertEqual(observed,{'state':'ready','phase':'verified','proof':'terminal-success',**task._FLAGS})
        self.assertEqual(before,{p:p.read_bytes() for p in before})
        self.assertNotIn('EncodedCommand',json.dumps(observed));self.assertNotIn(NONCE,json.dumps(observed))
        self.assertEqual(remote.call_count,1)
        dispatched=base64.b64decode(remote.call_args.args[2][-1]).decode('utf-16le')
        self.assertEqual(dispatched,task._PS)
        for mutation in ('Unregister-ScheduledTask','Start-ScheduledTask','Register-ScheduledTask','Remove-Item','Stop-Process'):
            self.assertNotIn(mutation,dispatched)

    def test_wrong_action_nonce_port_and_unbounded_arguments_reject(self):
        original=task._script(43210,NONCE)
        cases=[(original+';Get-Date','task-action'),
               (original.replace(NONCE,'B'*32),'task-action'),
               (original.replace('$port=43210;','$port=65536;'),'task-port'),
               (original.replace('$port=43210;','$port=04321;'),'task-port'),
               (original.replace('$port=43210;','$port=43210;$port=43210;'),'task-port'),
               (original.replace('$port=43210;','$port=43210+1;'),'task-port')]
        for script,phase in cases:
            with self.subTest(phase=phase,script_len=len(script)):
                p=proof();p['arguments']='-NoProfile -NonInteractive -EncodedCommand '+base64.b64encode(script.encode('utf-16le')).decode()
                observed,_=self.observe(p);self.assertEqual(observed['phase'],phase);self.assertEqual(observed['proof'],'unverified')
        for field,value in [('execute','powershell.exe'),('arguments','A'*12001)]:
            p=proof();p[field]=value;self.assertEqual(self.observe(p)[0]['phase'],'task-action')

    def test_principal_settings_terminal_and_process_guards(self):
        cases=[('principalSid','S-1-5-18','task-principal'),('taskState','Running','task-state'),
               ('taskState','Queued','task-state'),('runLevel','Highest','task-settings'),
               ('logonType','ServiceAccount','task-settings'),('triggerCount',1,'task-trigger'),
               ('triggerCount',False,'task-trigger'),('workingDirectory','C:\\foreign','task-settings'),
               ('executionTimeLimit','PT1H','task-execution-limit'),('lastRunTicks',0,'task-terminal'),
               ('lastRunTicks',638700000000000000,'task-terminal'),('lastTaskResult',1,'task-terminal'),
               ('lastTaskResult',False,'task-terminal'),('correlationProcess','ambiguous','process'),
               ('correlationProcess','present','process'),('installer','present','installer')]
        for field,value,phase in cases:
            with self.subTest(field=field,value=value):
                p=proof();p[field]=value;observed,_=self.observe(p)
                self.assertEqual(observed['phase'],phase);self.assertNotEqual(observed['state'],'ready')
        p=proof();p['foreign']=True;self.assertEqual(self.observe(p)[0]['phase'],'remote-output-shape')
        second=proof();second['lastRunTicks']+=1;self.assertEqual(self.observe(second=second)[0]['phase'],'remote-recheck')

    def test_missing_changed_or_unsafe_history_never_queries_guest(self):
        p=self.root/'.rag_index/windows-cp117-staged-fixture-retire/receipt.json'
        original=p.read_bytes()
        for kind in ('missing','changed','public','symlink'):
            with self.subTest(kind=kind):
                if p.exists() or p.is_symlink():p.unlink()
                if kind=='changed':p.write_text('{}');p.chmod(0o600)
                elif kind=='public':p.write_bytes(original);p.chmod(0o644)
                elif kind=='symlink':p.symlink_to(self.root/'.rag_index/windows-cp117-retirement-recovery/guest-terminal.json')
                with mock.patch.object(task.base,'_remote') as remote:
                    self.assertEqual(task.observe(self.root,{})['phase'],'local-history');remote.assert_not_called()
        p.unlink();p.write_bytes(original);p.chmod(0o600)
        lock=self.campaign/'.environment.lock';lock.unlink()
        with mock.patch.object(task.base,'_remote') as remote:
            self.assertEqual(task.observe(self.root,{})['phase'],'local-history');remote.assert_not_called()

    def test_local_active_and_foreign_generation_fail_before_remote(self):
        active=self.campaign/'active.json'
        for value in ('{}','not-json','{"identity":{"leaseId":"foreign"}}'):
            active.write_text(value);active.chmod(0o600)
            with mock.patch.object(task.base,'_remote') as remote:
                self.assertEqual(task.observe(self.root,{})['phase'],'local-active');remote.assert_not_called()
        active.unlink()
        with mock.patch.object(task.base,'_descriptor',return_value=(None,None,(*task._GENERATION[:2],123,520739,task._GENERATION[4]))),mock.patch.object(task.base,'_remote') as remote:
            self.assertEqual(task.observe(self.root,{})['phase'],'generation');remote.assert_not_called()
        with mock.patch.object(task.history,'_supported',return_value=False):
            self.assertEqual(task.observe(self.root,{})['phase'],'platform')
        for value in ({'port':1},{'correlationId':task._CORR},[],None):
            with self.assertRaises(ValueError):task.observe(self.root,value)

    def test_scheduler_null_trigger_normalization_is_the_actual_dispatch_fragment(self):
        p=proof();p['triggerCount']=1
        self.assertEqual(self.observe(p)[0]['phase'],'task-trigger')
        fragment=task._trigger_count_powershell()
        self.assertIn(fragment,task._PS)
        self.assertIn('triggerCount=$triggerCount;',task._PS)
        self.assertNotIn('triggerCount=@($task.Triggers).Count;',task._PS)
        p=proof();p['executionTimeLimit']='PT1H'
        self.assertEqual(self.observe(p)[0]['phase'],'task-execution-limit')

    def test_process_census_dispatch_uses_encoded_payload_and_excludes_only_self(self):
        body=task._process_census_powershell()
        self.assertIn(body,task._PS)
        self.assertIn("$processState='ambiguous'",body)
        self.assertIn('FromBase64String',body)
        self.assertIn('$process.ProcessId -eq $PID',body)

    def test_windows_process_census_encoded_opaque_foreign_and_self(self):
        powershell=shutil.which('powershell.exe')
        if powershell is None:self.skipTest('requires Windows PowerShell; inert no process census calls')
        body=task._process_census_powershell()
        script=r'''$corr='@CORR@';$body='@BODY@'
function Census([string]$name,[string]$line,[bool]$self){$processId=if($self){$PID}else{$PID+1};$all=@([pscustomobject]@{ProcessId=$processId;Name=$name;CommandLine=$line});Invoke-Expression $body;$processState}
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Output '"+$corr+"'"))
[Console]::Out.WriteLine(('raw='+(Census 'powershell.exe' ('powershell.exe -Command '+$corr) $false)))
[Console]::Out.WriteLine(('encoded='+(Census 'powershell.exe' ('powershell.exe -EncodedCommand '+$encoded) $false)))
[Console]::Out.WriteLine(('encoded-quoted='+(Census 'powershell.exe' ('powershell.exe -ec "'+$encoded+'"') $false)))
[Console]::Out.WriteLine(('opaque='+(Census 'powershell.exe' $null $false)))
[Console]::Out.WriteLine(('foreign='+(Census 'powershell.exe' 'powershell.exe -Command Get-Date' $false)))
[Console]::Out.WriteLine(('self='+(Census 'powershell.exe' ('powershell.exe -EncodedCommand '+$encoded) $true)))
[Console]::Out.WriteLine(('invalid='+(Census 'powershell.exe' 'powershell.exe -EncodedCommand !!!!' $false)))
[Console]::Out.WriteLine(('other='+(Census 'cmd.exe' 'cmd.exe /c exit' $false)))
'''.replace('@CORR@',task._CORR).replace('@BODY@',body.replace("'","''"))
        result=subprocess.run([powershell,'-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,check=True,timeout=15)
        self.assertEqual(['raw=present','encoded=present','encoded-quoted=present','opaque=ambiguous','foreign=ambiguous','self=absent','invalid=ambiguous','other=absent'],result.stdout.splitlines())

    def test_windows_exact_trigger_fragment_empty_null_real_mixed_and_duplicate(self):
        powershell=shutil.which('powershell.exe')
        if powershell is None:self.skipTest('requires Windows PowerShell; inert no Scheduler calls')
        fixed=task._trigger_count_powershell()
        old='$triggerCount=@($task.Triggers).Count'
        script=r'''function Count([object[]]$items,[string]$body){$task=[pscustomobject]@{Triggers=$items};Invoke-Expression $body;$triggerCount}
$old='@OLD@';$fixed='@FIXED@'
[Console]::Out.WriteLine(('old-null='+(Count -items ([object[]]@($null)) -body $old)))
[Console]::Out.WriteLine(('fixed-empty='+(Count -items ([object[]]@()) -body $fixed)))
[Console]::Out.WriteLine(('fixed-null='+(Count -items ([object[]]@($null)) -body $fixed)))
[Console]::Out.WriteLine(('fixed-real='+(Count -items ([object[]]@([pscustomobject]@{x=1})) -body $fixed)))
[Console]::Out.WriteLine(('fixed-mixed='+(Count -items ([object[]]@($null,[pscustomobject]@{x=1})) -body $fixed)))
[Console]::Out.WriteLine(('fixed-duplicate='+(Count -items ([object[]]@($null,$null)) -body $fixed)))
'''.replace('@OLD@',old.replace("'","''")).replace('@FIXED@',fixed.replace("'","''"))
        result=subprocess.run([powershell,'-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,check=True,timeout=15)
        self.assertEqual(['old-null=1','fixed-empty=0','fixed-null=0','fixed-real=1','fixed-mixed=2','fixed-duplicate=2'],result.stdout.splitlines())

    def test_foreign_owner_and_missing_platform_apis_fail_closed(self):
        with mock.patch.object(task.history.os,'getuid',return_value=os.getuid()+1),mock.patch.object(task.base,'_remote') as remote:
            self.assertEqual(task.observe(self.root,{})['phase'],'local-history');remote.assert_not_called()
        code="""import builtins,os
original=builtins.__import__
def nofcntl(name,*a,**k):
 if name=='fcntl':raise ImportError('unavailable')
 return original(name,*a,**k)
builtins.__import__=nofcntl;os.getuid=None
from agent_tools import windows_cp117_e848_http_task as observer
assert observer.observe('.',{})=={'state':'blocked','phase':'platform','proof':'unverified','replayAllowed':False,'nativeActionAllowed':False,'productAction':False}
"""
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def run_remote(self, mode='good'):
        # Production remote program with inert QGA stubs and private temp trees.
        # Every filesystem path is beneath TemporaryDirectory; no socket is used.
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name)
        campaign=root/'windows-cp117/windows-cp117-campaign'
        group=root/'windows-cp117/windows-update-fixture-http-stage'
        for p in (root/'windows-cp117',campaign,group):p.mkdir(mode=0o700,exist_ok=True)
        lock=campaign/'.environment.lock';lock.write_bytes(b'');lock.chmod(0o600)
        closed=campaign/(task._LEASE+'.closed.json');closed.write_text(json.dumps(self.closed));closed.chmod(0o600)
        if mode in ('active','active-malformed','active-foreign'):
            p=campaign/'active.json';p.write_text({'active':'{}','active-malformed':'not-json','active-foreign':'{"identity":{"leaseId":"foreign"}}'}[mode]);p.chmod(0o600)
        if mode=='lock-mode':lock.chmod(0o644)
        if mode=='lock-missing':lock.unlink()
        if mode=='stage':(group/task._CORR).mkdir(mode=0o700)
        encoded=base64.b64encode(task._PS.encode('utf-16le')).decode()
        envelope={'exited':True,'exitcode':0,'out-data':base64.b64encode(json.dumps(proof()).encode()).decode(),'out-truncated':False,'err-truncated':False}
        progress=b'#< CLIXML\r\n<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04"><Obj S="progress" RefId="0"><MS><S N="Activity">Loading</S></MS></Obj></Objs>'
        if mode=='progress':envelope['err-data']=base64.b64encode(progress).decode()
        if mode=='stderr-error':envelope['err-data']=base64.b64encode(progress.replace(b'S="progress"',b'S="Error"')).decode()
        if mode=='truncated':envelope['out-truncated']=True
        if mode=='bom':envelope['out-data']=base64.b64encode(b'\xef\xbb\xbf'+json.dumps(proof()).encode()).decode()
        if mode=='bad-bom':envelope['out-data']=base64.b64encode(b'\xff\xfeA').decode()
        if mode=='bad-encoding':envelope['out-data']=base64.b64encode(b'\x80').decode()
        if mode=='bad-json':envelope['out-data']=base64.b64encode(b'not JSON').decode()
        if mode=='extra':envelope['extra']='foreign'
        header=r'''import os,stat,sys,json,hashlib,base64,re,gzip
calls=0;livecalls=0
def decode(raw):
 if raw.startswith(b'\xff\xfe'):return raw.decode('utf-16')
 return raw.decode('utf-8-sig')
def live(sock,pid,ticks):
 global livecalls
 livecalls+=1
 return not (MODE=='generation' and livecalls>2)
def call(sock,action,args):
 global calls
 if action=='guest-exec':
  calls+=1
  program=base64.b64decode(args['arg'][-1]).decode('utf-16le')
  if calls==1:
   packed=re.search(r"FromBase64String\('([^']+)'\)",program).group(1)
   assert gzip.decompress(base64.b64decode(packed))==base64.b64decode(EXPECTED)
   assert 'Parser]::ParseInput' in program and 'Invoke-Expression' not in program
  else:assert args['arg'][-1]==EXPECTED
  return {'pid':calls}
 if args['pid']==1:
  return {'exited':True,'exitcode':(1 if MODE=='parser' else 0),'out-data':base64.b64encode(json.dumps({'version':1,'code':('FAILED' if MODE=='parser' else 'OK')}).encode()).decode()}
 return ENVELOPE
'''
        header='MODE='+repr(mode)+'\nEXPECTED='+repr(encoded)+'\nENVELOPE='+repr(envelope)+'\n'+header
        args=[str(root),*task._remote_arguments(task._GENERATION,self.closed),encoded]
        completed=subprocess.run([sys.executable,'-c',header+task._REMOTE_BODY,*args],capture_output=True,text=True,timeout=10)
        self.assertEqual(completed.returncode,0,completed.stderr)
        return json.loads(completed.stdout)

    def test_production_remote_two_censuses_and_exact_parser(self):
        for mode in ('good','progress','bom'):
            with self.subTest(mode=mode):
                value=self.run_remote(mode);self.assertEqual(value['state'],'observed');self.assertEqual(len(value['proofs']),2)
        for mode,phase in [('parser','parser'),('active','active'),('active-malformed','active'),('active-foreign','active'),('lock-mode','lock'),('lock-missing','lock'),('stage','stage'),('generation','generation'),
                           ('stderr-error','output-stderr-error'),('truncated','output-truncated'),
                           ('bad-json','output-json'),('bad-bom','output-bom'),('bad-encoding','output-encoding'),('extra','output-envelope')]:
            with self.subTest(mode=mode):self.assertEqual(self.run_remote(mode),{'state':'unknown','phase':phase})

    def test_unknown_and_extra_transport_never_publish_secret_or_ready(self):
        for value in (None,'not-json',json.dumps({'state':'observed','proofs':[proof()]}),
                      json.dumps({'state':'observed','proofs':[proof(),proof()],'raw':NONCE}),
                      json.dumps({'state':'unknown','phase':'foreign-secret'})):
            with mock.patch.object(task.base,'_remote',return_value=value):
                observed=task.observe(self.root,{})
                self.assertNotEqual(observed['state'],'ready');self.assertEqual(observed['proof'],'unverified')
                self.assertIn(observed['phase'],task._PHASES);self.assertNotIn(NONCE,json.dumps(observed))


if __name__=='__main__':unittest.main()
