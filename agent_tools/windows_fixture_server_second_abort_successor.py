"""Finish one exact CP117 abort after a lost terminal response.

This is intentionally a *proof successor*: it never submits another cleanup
command.  The original abort may already have removed the exact failed task
before its QGA child returned a nonzero result.  A fresh SYSTEM observation of
that task, its matching interpreter process, and the fixture listener is the
only fact that can release the still-held server-start role.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping

from . import windows_cp117_lease as lease
from . import windows_msi_base_prepare as base
from . import windows_update_fixture_server as server


class WindowsFixtureServerSecondAbortSuccessorError(ValueError):
    pass


_SERVER = "316e6189-5be0-4ea0-bca1-a3905816d815"
_ABORT = "c701e8af-dcab-4573-9059-f436b9916a08"
_CONSUMED = "bd0e2b0a-6d9d-4bc7-9f0f-352a9b045d5c"
_RECOVERY = "6a4a50cf-b75f-4ef5-a1fe-37b04c7cf0b9"
_DIR = ".rag_index/windows-fixture-server-second-abort-successor"
_RECOVERY_DIR = ".rag_index/windows-fixture-server-second-abort-recovery"
_UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")
_UNKNOWN = {"state": "unknown", "replayAllowed": False,
            "nativeActionAllowed": False, "productAction": False}


# This QGA program has no mutation branch.  It first binds the result to the
# original abort journal, then asks SYSTEM for the exact task/process/listener
# census.  It deliberately returns only finite classifications, never command
# lines, paths, SIDs, or fixture URLs.
_REMOTE = base._QGA + r'''import base64,json,os,re,stat,sys,time
root,server_corr,abort_corr,sock,pid,ticks,python_path,args64=sys.argv[1:]
def out(v):print(json.dumps(v,sort_keys=True,separators=(',',':')))
def regular(path,limit):
 i=os.lstat(path)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=limit:raise ValueError()
 with open(path,encoding='utf-8') as stream:return json.load(stream)
def run(ps):
 global phase
 phase='powershell-launch';encoded=base64.b64encode(ps.encode('utf-16le')).decode();child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 phase='powershell-status'
 for _ in range(120):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:return result
  if result.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 raise ValueError()
phase='binding'
try:
 if not live(sock,pid,ticks) or not python_path or not base64.b64decode(args64,validate=True) or any(not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',x) for x in (server_corr,abort_corr)):raise ValueError()
 phase='journal'
 job=os.path.join(root,'windows-cp117','windows-update-fixture-server',server_corr);cleanup=os.path.join(job,'cleanup-'+abort_corr)
 for path in (job,cleanup):
  info=os.lstat(path)
  if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError()
 binding=regular(os.path.join(cleanup,'binding.json'),16384);dispatch=regular(os.path.join(cleanup,'dispatch.json'),16384)
 if binding.get('serverCorrelationId')!=server_corr or binding.get('cleanupCorrelationId')!=abort_corr or binding.get('socketPath')!=sock or binding.get('qemuPid')!=int(pid) or binding.get('startTicks')!=int(ticks) or binding.get('dispatchMode')!='dispatched' or set(dispatch)!={'pid'} or type(dispatch['pid']) is not int or dispatch['pid']<=0:raise ValueError()
 phase='abort-child-status'
 try:old=call(sock,'guest-exec-status',{'pid':dispatch['pid']})
 except ValueError:old=None
 if old is None:abort_child='expired'
 else:
  if old.get('exited') is False:out({'state':'observed','abortChild':'running','task':'unknown','process':'unknown','listener':'unknown'});raise SystemExit(0)
  if old.get('exited') is not True or type(old.get('exitcode')) is not int or old.get('exitcode')==0:raise ValueError()
  abort_child='terminal-nonzero'
 task='VpnControlMcpFixtureServer-'+server_corr
 ps="$ErrorActionPreference='Stop';$n='"+task+"';$python='"+python_path.replace("'","''")+"';$args=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('"+args64+"'));$t=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $n});$ts=if($t.Count -eq 0){'absent'}elseif($t.Count -ne 1){'ambiguous'}elseif($t[0].State -eq 'Ready'){'ready'}elseif($t[0].State -eq 'Disabled'){'disabled'}elseif($t[0].State -eq 'Running'){'running'}else{'other'};$p=@(Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $python -and $_.CommandLine -like ('*'+$args)});$l=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -in @($p|ForEach-Object {[int]$_.ProcessId})});$r=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$'});[Console]::Out.WriteLine((@{taskState=$ts;process=if($p.Count -eq 0){'absent'}else{'present'};listener=if($l.Count -eq 0){'absent'}else{'present'};runtime=if($r.Count -eq 0){'off'}else{'on'}}|ConvertTo-Json -Compress))"
 phase='census-launch';result=run(ps);phase='census-result'
 if result.get('exitcode')!=0 or result.get('out-truncated',False) is not False or result.get('err-truncated',False) is not False:raise ValueError()
 census=json.loads(decode(base64.b64decode(result['out-data'],validate=True)))
 if not isinstance(census,dict) or set(census)!={'taskState','process','listener','runtime'} or census['taskState'] not in ('absent','ready','disabled','running','other','ambiguous') or census['process'] not in ('absent','present') or census['listener'] not in ('absent','present') or census['runtime'] not in ('off','on'):raise ValueError()
 out({'state':'observed','abortChild':abort_child,**census})
except SystemExit:raise
except Exception:out({'state':'diagnosed','phase':phase})
'''

# The only mutation in this module.  It is guarded by the same exact abort
# journal and performs one Task Scheduler unregister.  Its guest terminal is
# durable before it reports, and every later call is a fresh absence verifier.
_REMOTE_UNREGISTER = base._QGA + r'''import base64,json,os,re,stat,sys,time
root,server_corr,abort_corr,next_corr,sock,pid,ticks,sid,python_path,args64=sys.argv[1:]
def out(v):print(json.dumps(v,sort_keys=True,separators=(',',':')))
def save(path,v):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as f:json.dump(v,f,sort_keys=True,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
 parent=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parent);os.close(parent)
def regular(path,limit):
 i=os.lstat(path)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=limit:raise ValueError()
 with open(path,encoding='utf-8') as f:return json.load(f)
def run(ps):
 encoded=base64.b64encode(ps.encode('utf-16le')).decode();child=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',encoded],'capture-output':True})['pid']
 if type(child) is not int or child<=0:raise ValueError()
 for _ in range(120):
  result=call(sock,'guest-exec-status',{'pid':child})
  if result.get('exited') is True:return result
  if result.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 raise ValueError()
try:
 if not live(sock,pid,ticks) or any(not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',x) for x in (server_corr,abort_corr,next_corr)) or not base64.b64decode(args64,validate=True):raise ValueError()
 job=os.path.join(root,'windows-cp117','windows-update-fixture-server',server_corr);old=os.path.join(job,'cleanup-'+abort_corr)
 for p in (job,old):
  i=os.lstat(p)
  if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
 old_binding=regular(os.path.join(old,'binding.json'),16384);old_dispatch=regular(os.path.join(old,'dispatch.json'),16384)
 if old_binding.get('serverCorrelationId')!=server_corr or old_binding.get('cleanupCorrelationId')!=abort_corr or old_binding.get('socketPath')!=sock or old_binding.get('qemuPid')!=int(pid) or old_binding.get('startTicks')!=int(ticks) or old_binding.get('dispatchMode')!='dispatched' or set(old_dispatch)!={'pid'} or type(old_dispatch['pid']) is not int or old_dispatch['pid']<=0:raise ValueError()
 group=os.path.join(job,'second-abort-successor-'+next_corr);binding=os.path.join(group,'binding.json');terminal=os.path.join(group,'terminal.json')
 expected={'serverCorrelationId':server_corr,'abortCleanupCorrelationId':abort_corr,'successorCorrelationId':next_corr,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'originalSid':sid}
 if os.path.exists(binding):
  i=os.lstat(binding)
  if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or stat.S_IMODE(i.st_mode)!=0o600:raise ValueError()
  with open(binding,encoding='utf-8') as f:
   if json.load(f)!=expected:raise ValueError()
  if not os.path.exists(terminal):raise ValueError()
 else:
  os.mkdir(group,0o700);save(binding,expected)
 task='VpnControlMcpFixtureServer-'+server_corr
 args=base64.b64decode(args64,validate=True).decode().replace("'","''");py=python_path.replace("'","''");owner=sid.replace("'","''")
 verify="$ErrorActionPreference='Stop';$n='"+task+"';$py='"+py+"';$a='"+args+"';$t=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $n});$p=@(Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $py -and $_.CommandLine -like ('*'+$a)});$l=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -in @($p|ForEach-Object {[int]$_.ProcessId})});$r=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$'});if($t.Count -ne 0 -or $p.Count -ne 0 -or $l.Count -ne 0 -or $r.Count -ne 0){exit 9}"
 if os.path.exists(terminal):
  result=run(verify)
  if result.get('exitcode')!=0:raise ValueError()
  out({'state':'cleaned'});raise SystemExit(0)
 action="$ErrorActionPreference='Stop';$n='"+task+"';$py='"+py+"';$a='"+args+"';$sid='"+owner+"';$t=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $n});$p=@(Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $py -and $_.CommandLine -like ('*'+$a)});$l=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -in @($p|ForEach-Object {[int]$_.ProcessId})});$r=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$'});$ac=@($t[0].Actions);if($t.Count -ne 1 -or $t[0].State -notin @('Ready','Disabled') -or $t[0].Principal.UserId -cne $sid -or $ac.Count -ne 1 -or $ac[0].Execute -cne $py -or $ac[0].Arguments -cne $a -or $p.Count -ne 0 -or $l.Count -ne 0 -or $r.Count -ne 0){throw 'PRECONDITION'};Unregister-ScheduledTask -TaskPath '\\' -TaskName $n -Confirm:$false -ErrorAction Stop;"
 result=run(action)
 if result.get('exitcode')!=0:raise ValueError()
 result=run(verify)
 if result.get('exitcode')!=0:raise ValueError()
 save(terminal,{'taskAbsent':True,'processAbsent':True,'listenerAbsent':True,'runtimeOff':True})
 out({'state':'cleaned'})
except SystemExit:raise
except Exception:out({'state':'unknown'})
'''

_REMOTE_UNREGISTER_DIAGNOSTIC = base._QGA + r'''import base64,json,os,stat,sys,time
root,server_corr,abort_corr,next_corr,sock,pid,ticks,sid,python_path,args64=sys.argv[1:]
def out(v):print(json.dumps(v,sort_keys=True,separators=(',',':')))
def kind(path):
 try:i=os.lstat(path)
 except FileNotFoundError:return 'absent'
 return 'present' if stat.S_ISREG(i.st_mode) and not stat.S_ISLNK(i.st_mode) and i.st_uid==os.geteuid() and stat.S_IMODE(i.st_mode)==0o600 else 'mismatch'
def run(ps):
 e=base64.b64encode(ps.encode('utf-16le')).decode();c=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',e],'capture-output':True})['pid']
 for _ in range(120):
  r=call(sock,'guest-exec-status',{'pid':c})
  if r.get('exited') is True:return r
  if r.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 raise ValueError()
phase='journal'
try:
 if not live(sock,pid,ticks):raise ValueError()
 group=os.path.join(root,'windows-cp117','windows-update-fixture-server',server_corr,'second-abort-successor-'+next_corr)
 binding=kind(os.path.join(group,'binding.json'));terminal=kind(os.path.join(group,'terminal.json'))
 phase='powershell-launch';task='VpnControlMcpFixtureServer-'+server_corr;py=python_path.replace("'","''");args=base64.b64decode(args64,validate=True).decode().replace("'","''");owner=sid.replace("'","''")
 ps="$ErrorActionPreference='Stop';$n='"+task+"';$py='"+py+"';$a='"+args+"';$sid='"+owner+"';$account='VPNMSIX64\vpncp117';$t=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $n});$p=@(Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $py -and $_.CommandLine -like ('*'+$a)});$l=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -in @($p|ForEach-Object {[int]$_.ProcessId})});$r=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$'});$a0=@();if($t.Count -eq 1){$a0=@($t[0].Actions)};$ts=if($t.Count -eq 0){'absent'}elseif($t.Count -ne 1){'ambiguous'}else{$sv=[int]$t[0].State;if($sv -eq 3){'ready'}elseif($sv -eq 1){'disabled'}elseif($sv -eq 4){'running'}else{'other'}};$pm=if($t.Count -ne 1){'not-applicable'}elseif($t[0].Principal.UserId -ceq $account){'expected-username'}elseif($t[0].Principal.UserId -ceq $sid){'expected-sid'}else{'foreign'};$psid=if($t.Count -ne 1){'not-applicable'}else{try{$u=[string]$t[0].Principal.UserId;$actual=if($u -match '^S-1-'){([Security.Principal.SecurityIdentifier]::new($u)).Value}else{([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value};if($actual -ceq $sid){'resolved-sid-match'}else{'mismatch'}}catch{'unavailable'}};$ac=if($t.Count -ne 1){'not-applicable'}elseif($a0.Count -eq 0){'zero'}elseif($a0.Count -eq 1){'one'}elseif($a0.Count -eq 2){'two'}else{'three-or-more'};$fp={param($x)if($x.Execute -ceq $py -and $x.Arguments -ceq $a){'expected'}else{'other'}};$f0=if($a0.Count -ge 1){& $fp $a0[0]}else{'not-applicable'};$f1=if($a0.Count -ge 2){& $fp $a0[1]}else{'not-applicable'};$more=if($a0.Count -le 2){'none'}elseif(@($a0|Select-Object -Skip 2|ForEach-Object {& $fp $_}|Where-Object {$_ -eq 'other'}).Count -eq 0){'all-expected'}else{'contains-other'};$lt=if($t.Count -ne 1){'not-applicable'}elseif($t[0].Principal.LogonType.ToString() -ceq 'Interactive'){'expected'}else{'other'};$rl=if($t.Count -ne 1){'not-applicable'}elseif($t[0].Principal.RunLevel.ToString() -ceq 'Limited'){'expected'}else{'other'};[Console]::Out.WriteLine((@{taskState=$ts;principal=$pm;principalSid=$psid;actionCount=$ac;action0Fingerprint=$f0;action1Fingerprint=$f1;additionalActions=$more;logonType=$lt;runLevel=$rl;process=if($p.Count -eq 0){'absent'}else{'present'};listener=if($l.Count -eq 0){'absent'}else{'present'};runtime=if($r.Count -eq 0){'off'}else{'on'}}|ConvertTo-Json -Compress))"
 r=run(ps);phase='powershell-status'
 if r.get('exitcode')!=0 or r.get('out-truncated',False) is not False:raise ValueError()
 v=json.loads(decode(base64.b64decode(r['out-data'],validate=True)))
 if not isinstance(v,dict) or set(v)!={'taskState','principal','principalSid','actionCount','action0Fingerprint','action1Fingerprint','additionalActions','logonType','runLevel','process','listener','runtime'} or v.get('taskState') not in {'absent','ready','disabled','running','other','ambiguous'} or v.get('principal') not in {'expected-username','expected-sid','foreign','not-applicable'} or v.get('principalSid') not in {'resolved-sid-match','mismatch','unavailable','not-applicable'} or v.get('actionCount') not in {'zero','one','two','three-or-more','not-applicable'} or v.get('action0Fingerprint') not in {'expected','other','not-applicable'} or v.get('action1Fingerprint') not in {'expected','other','not-applicable'} or v.get('additionalActions') not in {'none','all-expected','contains-other'} or v.get('logonType') not in {'expected','other','not-applicable'} or v.get('runLevel') not in {'expected','other','not-applicable'} or v.get('process') not in {'absent','present'} or v.get('listener') not in {'absent','present'} or v.get('runtime') not in {'off','on'}:raise ValueError()
 out({'state':'observed','journalBinding':binding,'journalTerminal':terminal,**v})
except Exception:out({'state':'diagnosed','phase':phase})
'''

# A fresh, fixed recovery is deliberately separate from the consumed bd0e...
# attempt.  It records its local intent before remote submission, then records
# a guest binding before its one Task Scheduler mutation.
_REMOTE_RECOVERY = base._QGA + r'''import base64,json,os,re,stat,sys,time
root,server_corr,old_corr,recovery_corr,sock,pid,ticks,sid,python_path,args64=sys.argv[1:]
def out(v):print(json.dumps(v,sort_keys=True,separators=(',',':')))
def regular(path,limit):
 i=os.lstat(path)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=limit:raise ValueError()
 with open(path,encoding='utf-8') as f:return json.load(f)
def save(path,v):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600)
 with os.fdopen(fd,'w',encoding='utf-8') as f:json.dump(v,f,sort_keys=True,separators=(',',':'));f.write('\n');f.flush();os.fsync(f.fileno())
 parent=os.open(os.path.dirname(path),os.O_RDONLY|getattr(os,'O_DIRECTORY',0));os.fsync(parent);os.close(parent)
def run(ps):
 e=base64.b64encode(ps.encode('utf-16le')).decode();c=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',e],'capture-output':True})['pid']
 if type(c) is not int or c<=0:raise ValueError()
 for _ in range(120):
  r=call(sock,'guest-exec-status',{'pid':c})
  if r.get('exited') is True:return r
  if r.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 raise ValueError()
try:
 if not live(sock,pid,ticks) or any(not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',x) for x in (server_corr,old_corr,recovery_corr)) or not base64.b64decode(args64,validate=True):raise ValueError()
 job=os.path.join(root,'windows-cp117','windows-update-fixture-server',server_corr);old=os.path.join(job,'second-abort-successor-'+old_corr);group=os.path.join(job,'second-abort-recovery-'+recovery_corr)
 for d in (job,old):
  i=os.lstat(d)
  if not stat.S_ISDIR(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o700:raise ValueError()
 old_binding=regular(os.path.join(old,'binding.json'),16384)
 if set(old_binding)!={'serverCorrelationId','abortCleanupCorrelationId','successorCorrelationId','socketPath','qemuPid','startTicks','originalSid'} or old_binding.get('serverCorrelationId')!=server_corr or old_binding.get('successorCorrelationId')!=old_corr or old_binding.get('socketPath')!=sock or old_binding.get('qemuPid')!=int(pid) or old_binding.get('startTicks')!=int(ticks) or old_binding.get('originalSid')!=sid or os.path.exists(os.path.join(old,'terminal.json')):raise ValueError()
 expected={'serverCorrelationId':server_corr,'consumedSuccessorCorrelationId':old_corr,'recoveryCorrelationId':recovery_corr,'socketPath':sock,'qemuPid':int(pid),'startTicks':int(ticks),'originalSid':sid}
 binding=os.path.join(group,'binding.json');terminal=os.path.join(group,'terminal.json')
 if os.path.exists(binding):
  if regular(binding,16384)!=expected or os.path.exists(terminal):raise ValueError()
  out({'state':'unknown'});raise SystemExit(0)
 os.mkdir(group,0o700);save(binding,expected)
 task='VpnControlMcpFixtureServer-'+server_corr;args=base64.b64decode(args64,validate=True).decode().replace("'","''");py=python_path.replace("'","''");owner=sid.replace("'","''")
 ps="$ErrorActionPreference='Stop';$n='"+task+"';$py='"+py+"';$a='"+args+"';$sid='"+owner+"';$t=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $n});$ac=@();if($t.Count -eq 1){$ac=@($t[0].Actions)};$u=if($t.Count -eq 1){[string]$t[0].Principal.UserId}else{''};try{$actual=if($u -match '^S-1-'){([Security.Principal.SecurityIdentifier]::new($u)).Value}else{([Security.Principal.NTAccount]::new($u)).Translate([Security.Principal.SecurityIdentifier]).Value}}catch{$actual=''};$p=@(Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $py -and $_.CommandLine -like ('*'+$a)});$l=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -in @($p|ForEach-Object {[int]$_.ProcessId})});$r=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$'});if($t.Count -ne 1 -or [int]$t[0].State -notin @(3,1) -or $actual -cne $sid -or $t[0].Principal.LogonType.ToString() -cne 'Interactive' -or $t[0].Principal.RunLevel.ToString() -cne 'Limited' -or $ac.Count -ne 1 -or $ac[0].Execute -cne $py -or $ac[0].Arguments -cne $a -or $p.Count -ne 0 -or $l.Count -ne 0 -or $r.Count -ne 0){throw 'PRECONDITION'};Unregister-ScheduledTask -TaskPath '\\' -TaskName $n -Confirm:$false -ErrorAction Stop;$gone=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $n});if($gone.Count -ne 0){throw 'PRESENT'}"
 if run(ps).get('exitcode')!=0:raise ValueError()
 save(terminal,{'taskAbsent':True,'processAbsent':True,'listenerAbsent':True,'runtimeOff':True});out({'state':'cleaned'})
except SystemExit:raise
except Exception:out({'state':'unknown'})
'''

_REMOTE_RECOVERY_STATUS = base._QGA + r'''import base64,json,os,stat,sys,time
root,server_corr,old_corr,recovery_corr,sock,pid,ticks,sid,python_path,args64=sys.argv[1:]
def out(v):print(json.dumps(v,sort_keys=True,separators=(',',':')))
def regular(path,limit):
 i=os.lstat(path)
 if not stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode) or i.st_uid!=os.geteuid() or stat.S_IMODE(i.st_mode)!=0o600 or not 0<i.st_size<=limit:raise ValueError()
 with open(path,encoding='utf-8') as f:return json.load(f)
def run(ps):
 e=base64.b64encode(ps.encode('utf-16le')).decode();c=call(sock,'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',e],'capture-output':True})['pid']
 if type(c) is not int or c<=0:raise ValueError()
 for _ in range(120):
  r=call(sock,'guest-exec-status',{'pid':c})
  if r.get('exited') is True:return r
  if r.get('exited') is not False:raise ValueError()
  time.sleep(.25)
 raise ValueError()
try:
 if not live(sock,pid,ticks):raise ValueError()
 job=os.path.join(root,'windows-cp117','windows-update-fixture-server',server_corr);old=os.path.join(job,'second-abort-successor-'+old_corr);group=os.path.join(job,'second-abort-recovery-'+recovery_corr)
 old_binding=regular(os.path.join(old,'binding.json'),16384)
 if os.path.exists(os.path.join(old,'terminal.json')) or set(old_binding)!={'serverCorrelationId','abortCleanupCorrelationId','successorCorrelationId','socketPath','qemuPid','startTicks','originalSid'} or old_binding.get('serverCorrelationId')!=server_corr or old_binding.get('successorCorrelationId')!=old_corr or old_binding.get('socketPath')!=sock or old_binding.get('qemuPid')!=int(pid) or old_binding.get('startTicks')!=int(ticks) or old_binding.get('originalSid')!=sid:raise ValueError()
 b=regular(os.path.join(group,'binding.json'),16384);t=regular(os.path.join(group,'terminal.json'),1024)
 if set(b)!={'serverCorrelationId','consumedSuccessorCorrelationId','recoveryCorrelationId','socketPath','qemuPid','startTicks','originalSid'} or b.get('serverCorrelationId')!=server_corr or b.get('consumedSuccessorCorrelationId')!=old_corr or b.get('recoveryCorrelationId')!=recovery_corr or b.get('socketPath')!=sock or b.get('qemuPid')!=int(pid) or b.get('startTicks')!=int(ticks) or b.get('originalSid')!=sid or t!={'taskAbsent':True,'processAbsent':True,'listenerAbsent':True,'runtimeOff':True}:raise ValueError()
 task='VpnControlMcpFixtureServer-'+server_corr;args=base64.b64decode(args64,validate=True).decode().replace("'","''");py=python_path.replace("'","''")
 ps="$ErrorActionPreference='Stop';$n='"+task+"';$py='"+py+"';$a='"+args+"';$t=@(Get-ScheduledTask -TaskPath '\\' -ErrorAction Stop|Where-Object {$_.TaskName -ceq $n});$p=@(Get-CimInstance Win32_Process -Filter \"Name = 'python.exe'\" -ErrorAction Stop|Where-Object {$_.ExecutablePath -ceq $py -and $_.CommandLine -like ('*'+$a)});$l=@(Get-NetTCPConnection -State Listen -ErrorAction Stop|Where-Object {$_.LocalAddress -eq '127.0.0.1' -and $_.OwningProcess -in @($p|ForEach-Object {[int]$_.ProcessId})});$r=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.Name -match '^(vpn-control|vpn-control-cli|msiexec|consent|sing-box)\\.exe$'});if($t.Count -ne 0 -or $p.Count -ne 0 -or $l.Count -ne 0 -or $r.Count -ne 0){exit 9}"
 if run(ps).get('exitcode')!=0:raise ValueError()
 out({'state':'cleaned'})
except Exception:out({'state':'unknown'})
'''


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    if not isinstance(value, Mapping) or set(value) != {"successorCorrelationId"}:
        raise WindowsFixtureServerSecondAbortSuccessorError("Exact successor correlation is required.")
    value = value.get("successorCorrelationId")
    if not isinstance(value, str) or not _UUID.fullmatch(value) or value in {_SERVER, _ABORT}:
        raise WindowsFixtureServerSecondAbortSuccessorError("Successor correlation is invalid.")
    return {"successorCorrelationId": value}


def _path(root: Path, correlation: str) -> Path:
    return root / _DIR / (correlation + ".json")


def _read(root: Path, correlation: str) -> dict[str, Any] | None:
    try:
        fd = os.open(_path(root, correlation), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096:
            raise WindowsFixtureServerSecondAbortSuccessorError("Successor journal is unsafe.")
        value = json.load(stream)
    return value if isinstance(value, dict) else None


def _reserve(root: Path, record: Mapping[str, Any]) -> bool:
    directory = root / _DIR
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise WindowsFixtureServerSecondAbortSuccessorError("Successor journal directory is unsafe.")
    correlation = record["request"]["successorCorrelationId"]
    prior = _read(root, correlation)
    if prior is not None:
        if prior != dict(record):
            raise WindowsFixtureServerSecondAbortSuccessorError("Successor journal changed.")
        return False
    raw = (json.dumps(dict(record), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(_path(root, correlation), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return True


def _admission(root: Path) -> tuple[Any, Any, tuple[Any, ...], dict[str, str], dict[str, Any]]:
    intent = server._read_intent(root, _SERVER)
    abort = server._read_cleanup_intent(root, _ABORT)
    if intent is None or abort is None or abort.get("mode") != "abort":
        raise WindowsFixtureServerSecondAbortSuccessorError("Exact original abort is unavailable.")
    request = server._request(intent.get("request", {}))
    cleanup = server._cleanup_request(abort.get("request", {}))
    if request["serverCorrelationId"] != _SERVER or cleanup != {"leaseId": request["leaseId"], "serverCorrelationId": _SERVER, "cleanupCorrelationId": _ABORT} or abort.get("serverRequest") != request:
        raise WindowsFixtureServerSecondAbortSuccessorError("Original abort binding changed.")
    config, target, descriptor = base._descriptor(root)
    env, socket, pid, ticks, sid = descriptor
    if (abort.get("schemaVersion") != 1 or abort.get("environment") != "windows-cp117"
            or any(abort.get(k) != v for k, v in (("socketPath", socket), ("qemuPid", pid),
                                                   ("startTicks", ticks), ("originalSid", sid)))):
        raise WindowsFixtureServerSecondAbortSuccessorError("Guest generation changed.")
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
        identity = base._campaign_identity({**request, "correlationId": request["leaseId"]}, descriptor)
        if not isinstance(current, Mapping) or current.get("identity") != identity or current.get("state") != "role-active" or current.get("role") != "server-start" or current.get("correlationId") != _SERVER or current.get("server") != "starting" or current.get("credentials") != "ready":
            raise WindowsFixtureServerSecondAbortSuccessorError("Exact server-start role is not held.")
        if not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None):
            raise WindowsFixtureServerSecondAbortSuccessorError("Remote server-start role is not held.")
    finally:
        os.close(lock)
    return config, target, descriptor, request, abort


def _observe(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...], request: Mapping[str, str]) -> dict[str, Any] | None:
    try:
        intent = server._read_intent(root, _SERVER)
        if not isinstance(intent, Mapping) or not isinstance(intent.get("pythonPath"), str):
            return None
        tls = server._private_tls_descriptor(root, request)
        arguments = server._launch_arguments(request, tls)
        raw = base._remote(config, _REMOTE, (str(target.fixture_transfer_root), _SERVER, _ABORT, descriptor[1], str(descriptor[2]), str(descriptor[3]), intent["pythonPath"], base64.b64encode(arguments.encode()).decode("ascii")), None, 60)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        return None
    return result if isinstance(result, dict) else None


def _unregister(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...], request: Mapping[str, str], correlation: str) -> dict[str, Any] | None:
    try:
        intent = server._read_intent(root, _SERVER)
        if not isinstance(intent, Mapping) or not isinstance(intent.get("pythonPath"), str):
            return None
        arguments = server._launch_arguments(request, server._private_tls_descriptor(root, request))
        raw = base._remote(config, _REMOTE_UNREGISTER, (str(target.fixture_transfer_root), _SERVER, _ABORT,
                           correlation, descriptor[1], str(descriptor[2]), str(descriptor[3]), descriptor[4],
                           intent["pythonPath"], base64.b64encode(arguments.encode()).decode("ascii")), None, 60)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        return None
    return result if isinstance(result, dict) else None


def _unregister_diagnose(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...], request: Mapping[str, str], correlation: str) -> dict[str, Any] | None:
    try:
        intent = server._read_intent(root, _SERVER)
        if not isinstance(intent, Mapping) or not isinstance(intent.get("pythonPath"), str): return None
        arguments = server._launch_arguments(request, server._private_tls_descriptor(root, request))
        raw = base._remote(config, _REMOTE_UNREGISTER_DIAGNOSTIC, (str(target.fixture_transfer_root), _SERVER, _ABORT, correlation, descriptor[1], str(descriptor[2]), str(descriptor[3]), descriptor[4], intent["pythonPath"], base64.b64encode(arguments.encode()).decode("ascii")), None, 60)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError): return None
    return result if isinstance(result, dict) else None


def _unknown(correlation: str) -> dict[str, Any]:
    return {**_UNKNOWN, "successorCorrelationId": correlation}


def _proof(value: Mapping[str, Any]) -> bool:
    return (isinstance(value, Mapping) and value.get("abortChild") in {"terminal-nonzero", "expired"}
            and value == {"state": "observed", "abortChild": value["abortChild"], "taskState": "absent",
                          "process": "absent", "listener": "absent", "runtime": "off"})


def _digest(record: Mapping[str, Any], descriptor: tuple[Any, ...]) -> str:
    return hashlib.sha256(json.dumps({"record": record, "guest": descriptor[1:]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _completed(root: Path, request: Mapping[str, str], record: Mapping[str, Any]) -> str | None:
    """Reconcile only an already-finished local role; it never observes or acts."""
    config, target, descriptor = base._descriptor(root)
    digest = _digest(record, descriptor)
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
    finally:
        os.close(lock)
    expected = base._campaign_identity({**request, "correlationId": request["leaseId"]}, descriptor)
    if (not isinstance(current, Mapping) or current.get("identity") != expected
            or current.get("state") != "active" or current.get("role") is not None
            or current.get("server") != "stopped" or current.get("lastOutcome") != "failed-cleaned"
            or current.get("lastEvidenceSha256") != digest
            or not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None)):
        return None
    return digest


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    request = _request(value); correlation = request["successorCorrelationId"]
    try:
        path = Path(root).resolve(strict=True)
        config, target, descriptor, server_request, _abort = _admission(path)
        record = {"version": 1, "request": request, "serverCorrelationId": _SERVER,
                  "abortCleanupCorrelationId": _ABORT, "serverRequest": server_request,
                  "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}}
        if not _reserve(path, record):
            return _unknown(correlation)
        observed = _observe(path, config, target, descriptor, server_request)
        if not (isinstance(observed, Mapping) and observed.get("abortChild") in {"expired", "terminal-nonzero"}
                and observed.get("taskState") in {"ready", "disabled"} and observed.get("process") == "absent"
                and observed.get("listener") == "absent" and observed.get("runtime") == "off"):
            return _unknown(correlation)
        result = _unregister(path, config, target, descriptor, server_request, correlation)
        return ({"state": "submitted", "successorCorrelationId": correlation, "replayAllowed": False,
                 "nativeActionAllowed": False, "productAction": False}
                if result == {"state": "cleaned"} else _unknown(correlation))
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerSecondAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return _unknown(correlation)


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    request = _request(value); correlation = request["successorCorrelationId"]
    try:
        path = Path(root).resolve(strict=True)
        saved = _read(path, correlation)
        if isinstance(saved, Mapping) and saved.get("request") == request and saved.get("serverCorrelationId") == _SERVER and isinstance(saved.get("serverRequest"), Mapping):
            saved_request = server._request(saved["serverRequest"])
            try:
                digest = _completed(path, saved_request, saved)
            except (OSError, ValueError, KeyError, TypeError, lease.Cp117LeaseError,
                    base.WindowsMsiBasePrepareError):
                digest = None
            if digest is not None:
                return {"state": "cleaned", "successorCorrelationId": correlation, "cleanupReceiptSha256": digest, "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        config, target, descriptor, server_request, _abort = _admission(path)
        record = {"version": 1, "request": request, "serverCorrelationId": _SERVER,
                  "abortCleanupCorrelationId": _ABORT, "serverRequest": server_request,
                  "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}}
        if _read(path, correlation) != record:
            return _unknown(correlation)
        observed = _observe(path, config, target, descriptor, server_request)
        if not _proof(observed):
            return _unknown(correlation)
        digest = _digest(record, descriptor)
        finished = lease.finish_role(path, server_request["leaseId"], "server-start", _SERVER, digest, "failed-cleaned", base._campaign_remote(config, target))
        if finished.get("state") != "active":
            return _unknown(correlation)
        return {"state": "cleaned", "successorCorrelationId": correlation, "cleanupReceiptSha256": digest, "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerSecondAbortSuccessorError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return _unknown(correlation)


def _recovery_request(value: Mapping[str, Any]) -> dict[str, str]:
    if value != {"recoveryCorrelationId": _RECOVERY}:
        raise WindowsFixtureServerSecondAbortSuccessorError("Exact recovery correlation is required.")
    return {"recoveryCorrelationId": _RECOVERY}


def _recovery_path(root: Path) -> Path:
    return root / _RECOVERY_DIR / (_RECOVERY + ".json")


def _recovery_read(root: Path) -> dict[str, Any] | None:
    try:
        fd = os.open(_recovery_path(root), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= 4096):
            raise WindowsFixtureServerSecondAbortSuccessorError("Recovery journal is unsafe.")
        value = json.load(stream)
    return value if isinstance(value, dict) else None


def _recovery_reserve(root: Path, record: Mapping[str, Any]) -> bool:
    directory = root / _RECOVERY_DIR
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or directory.is_symlink() or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise WindowsFixtureServerSecondAbortSuccessorError("Recovery journal directory is unsafe.")
    prior = _recovery_read(root)
    if prior is not None:
        if prior != dict(record):
            raise WindowsFixtureServerSecondAbortSuccessorError("Recovery journal changed.")
        return False
    raw = (json.dumps(dict(record), sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(_recovery_path(root), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    return True


def _recovery_admission(root: Path) -> tuple[Any, Any, tuple[Any, ...], dict[str, str], dict[str, Any]]:
    config, target, descriptor, request, abort = _admission(root)
    consumed = _read(root, _CONSUMED)
    if (not isinstance(consumed, Mapping) or consumed.get("version") != 1
            or consumed.get("request") != {"successorCorrelationId": _CONSUMED}
            or consumed.get("serverCorrelationId") != _SERVER or consumed.get("serverRequest") != request
            or consumed.get("abortCleanupCorrelationId") != _ABORT
            or consumed.get("guestGeneration") != {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}):
        raise WindowsFixtureServerSecondAbortSuccessorError("Consumed successor binding changed.")
    return config, target, descriptor, request, dict(consumed)


def _recovery_record(request: Mapping[str, str], descriptor: tuple[Any, ...], consumed: Mapping[str, Any]) -> dict[str, Any]:
    return {"version": 1, "recoveryCorrelationId": _RECOVERY, "consumedSuccessorCorrelationId": _CONSUMED,
            "serverCorrelationId": _SERVER, "abortCleanupCorrelationId": _ABORT, "serverRequest": dict(request),
            "consumedRecordSha256": hashlib.sha256(json.dumps(dict(consumed), sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            "guestGeneration": {"socketPath": descriptor[1], "qemuPid": descriptor[2], "startTicks": descriptor[3]}}


def _recovery_unknown() -> dict[str, Any]:
    return {**_UNKNOWN, "recoveryCorrelationId": _RECOVERY}


def _recovery_remote(root: Path, config: Any, target: Any, descriptor: tuple[Any, ...], request: Mapping[str, str], program: str) -> dict[str, Any] | None:
    try:
        intent = server._read_intent(root, _SERVER)
        if not isinstance(intent, Mapping) or not isinstance(intent.get("pythonPath"), str): return None
        arguments = server._launch_arguments(request, server._private_tls_descriptor(root, request))
        values = (str(target.fixture_transfer_root), _SERVER, _CONSUMED, _RECOVERY, descriptor[1], str(descriptor[2]),
                  str(descriptor[3]), descriptor[4], intent["pythonPath"], base64.b64encode(arguments.encode()).decode("ascii"))
        raw = base._remote(config, program, values, None, 60)
        result = json.loads(raw) if raw is not None else None
    except (OSError, ValueError, TypeError, base.WindowsMsiBasePrepareError):
        return None
    return result if isinstance(result, dict) else None


def resume_start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _recovery_request(value)
    try:
        path = Path(root).resolve(strict=True)
        config, target, descriptor, request, consumed = _recovery_admission(path)
        record = _recovery_record(request, descriptor, consumed)
        if not _recovery_reserve(path, record):
            return _recovery_unknown()
        result = _recovery_remote(path, config, target, descriptor, request, _REMOTE_RECOVERY)
        if result != {"state": "cleaned"}:
            return _recovery_unknown()
        return {"state": "submitted", "recoveryCorrelationId": _RECOVERY, "replayAllowed": False,
                "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerSecondAbortSuccessorError,
            lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return _recovery_unknown()


def _recovery_completed(root: Path) -> str | None:
    """Reconcile a completed recovery without another guest observation or action."""
    record = _recovery_read(root)
    if not isinstance(record, Mapping) or record.get("recoveryCorrelationId") != _RECOVERY:
        return None
    config, target, descriptor = base._descriptor(root)
    digest = _digest(record, descriptor)
    directory, lock = lease._locked(root)
    try:
        current = lease._active(directory)
    finally:
        os.close(lock)
    request = record.get("serverRequest")
    if not isinstance(request, Mapping):
        return None
    expected = base._campaign_identity({**request, "correlationId": request.get("leaseId")}, descriptor)
    if (not isinstance(current, Mapping) or current.get("identity") != expected or current.get("state") != "active"
            or current.get("role") is not None or current.get("server") != "stopped"
            or current.get("lastOutcome") != "failed-cleaned" or current.get("lastEvidenceSha256") != digest
            or not lease._remote_confirm(base._campaign_remote(config, target), "status", current, None)):
        return None
    return digest


def resume_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _recovery_request(value)
    try:
        path = Path(root).resolve(strict=True)
        try:
            completed = _recovery_completed(path)
        except (OSError, ValueError, KeyError, TypeError, lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
            completed = None
        if completed is not None:
            return {"state": "cleaned", "recoveryCorrelationId": _RECOVERY, "cleanupReceiptSha256": completed,
                    "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
        config, target, descriptor, request, consumed = _recovery_admission(path)
        record = _recovery_record(request, descriptor, consumed)
        if _recovery_read(path) != record:
            return _recovery_unknown()
        if _recovery_remote(path, config, target, descriptor, request, _REMOTE_RECOVERY_STATUS) != {"state": "cleaned"}:
            return _recovery_unknown()
        digest = _digest(record, descriptor)
        finished = lease.finish_role(path, request["leaseId"], "server-start", _SERVER, digest, "failed-cleaned", base._campaign_remote(config, target))
        if finished.get("state") != "active":
            return _recovery_unknown()
        return {"state": "cleaned", "recoveryCorrelationId": _RECOVERY, "cleanupReceiptSha256": digest,
                "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerSecondAbortSuccessorError,
            lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return _recovery_unknown()


def resume_diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _recovery_request(value)
    observed = diagnose(root, {"successorCorrelationId": _CONSUMED})
    observed.pop("successorCorrelationId", None)
    return {**observed, "recoveryCorrelationId": _RECOVERY}


def _action_shape_valid(value: Mapping[str, Any]) -> bool:
    """Reject a scalar-coercion result that cannot describe its action count."""
    count = value.get("actionCount")
    first, second, extra = (value.get("action0Fingerprint"), value.get("action1Fingerprint"),
                            value.get("additionalActions"))
    known = {"expected", "other"}
    if count in {"zero", "not-applicable"}:
        return first == second == "not-applicable" and extra == "none"
    if count == "one":
        return first in known and second == "not-applicable" and extra == "none"
    if count == "two":
        return first in known and second in known and extra == "none"
    if count == "three-or-more":
        return first in known and second in known and extra in {"all-expected", "contains-other"}
    return False


def diagnose(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    request = _request(value); correlation = request["successorCorrelationId"]
    flags = {"successorCorrelationId": correlation, "replayAllowed": False, "nativeActionAllowed": False, "productAction": False}
    try:
        path = Path(root).resolve(strict=True)
        config, target, descriptor, server_request, _abort = _admission(path)
    except (OSError, ValueError, KeyError, TypeError, WindowsFixtureServerSecondAbortSuccessorError,
            lease.Cp117LeaseError, base.WindowsMsiBasePrepareError):
        return {"state": "diagnosed", "phase": "admission", **flags}
    successor = _unregister_diagnose(path, config, target, descriptor, server_request, correlation)
    diagnostic_fields = {"state", "journalBinding", "journalTerminal", "taskState", "principal", "principalSid",
                         "actionCount", "action0Fingerprint", "action1Fingerprint", "additionalActions",
                         "logonType", "runLevel", "process", "listener", "runtime"}
    if (isinstance(successor, dict) and set(successor) == diagnostic_fields
            and successor.get("state") == "observed"
            and successor.get("journalBinding") in {"absent", "present", "mismatch"}
            and successor.get("journalTerminal") in {"absent", "present", "mismatch"}
            and successor.get("taskState") in {"absent", "ready", "disabled", "running", "other", "ambiguous"}
            and successor.get("principal") in {"expected-username", "expected-sid", "foreign", "not-applicable"}
            and successor.get("principalSid") in {"resolved-sid-match", "mismatch", "unavailable", "not-applicable"}
            and successor.get("actionCount") in {"zero", "one", "two", "three-or-more", "not-applicable"}
            and successor.get("action0Fingerprint") in {"expected", "other", "not-applicable"}
            and successor.get("action1Fingerprint") in {"expected", "other", "not-applicable"}
            and successor.get("additionalActions") in {"none", "all-expected", "contains-other"}
            and successor.get("logonType") in {"expected", "other", "not-applicable"}
            and successor.get("runLevel") in {"expected", "other", "not-applicable"}
            and successor.get("process") in {"absent", "present"}
            and successor.get("listener") in {"absent", "present"}
            and successor.get("runtime") in {"off", "on"}
            and _action_shape_valid(successor)):
        return {**successor, **flags}
    observed = _observe(path, config, target, descriptor, server_request)
    if (isinstance(observed, dict) and set(observed) == {"state", "abortChild", "taskState", "process", "listener", "runtime"}
            and observed.get("state") == "observed" and observed.get("abortChild") in {"running", "terminal-nonzero", "expired"}
            and observed.get("taskState") in {"absent", "ready", "disabled", "running", "other", "ambiguous"}
            and observed.get("process") in {"absent", "present"} and observed.get("listener") in {"absent", "present"}
            and observed.get("runtime") in {"off", "on"}):
        return {**observed, **flags}
    phases = {"binding", "journal", "abort-child-status", "powershell-launch",
              "powershell-status", "census-result"}
    if isinstance(observed, dict) and observed.get("state") == "diagnosed" and observed.get("phase") in phases and set(observed) == {"state", "phase"}:
        return {**observed, **flags}
    return {"state": "diagnosed", "phase": "remote-observation", **flags}


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "start": return start(root, inputs)
    if action == "status": return status(root, inputs)
    if action == "diagnostic": return diagnose(root, inputs)
    if action == "resume_start": return resume_start(root, inputs)
    if action == "resume_status": return resume_status(root, inputs)
    if action == "resume_diagnose": return resume_diagnose(root, inputs)
    raise WindowsFixtureServerSecondAbortSuccessorError("Unknown second abort successor action.")
