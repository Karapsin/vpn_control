"""Fixed read-only account/session facts for the recovered CP117 guest."""
import base64
import json

BODY=r'''$ErrorActionPreference='Stop'
try {
 $sid='S-1-5-21-2404255130-2183793310-3766671872-1002'
 $account=@(Get-CimInstance Win32_UserAccount -Filter "Name='vpncp117' AND LocalAccount=TRUE")
 if($account.Count -gt 1){throw 'ACCOUNT_BOUND'}
 $accounts=@($account|ForEach-Object {[pscustomobject]@{expectedSid=($_.SID -ceq $sid);expectedName=($_.Name -ceq 'vpncp117');disabled=[bool]$_.Disabled;lockedOut=[bool]$_.Lockout;localAccount=[bool]$_.LocalAccount}})
 $processes=@(Get-CimInstance Win32_Process|Where-Object {$_.Name -match '^(explorer|LogonUI|winlogon)\.exe$'})
 if($processes.Count -gt 16){throw 'SESSION_BOUND'}
 $rows=@($processes|ForEach-Object {
  $p=$_;$owner=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
  [pscustomobject]@{kind=$p.Name.ToLowerInvariant().Replace('.exe','');pid=[int]$p.ProcessId;parentPid=[int]$p.ParentProcessId;sessionId=[int]$p.SessionId;startedAtUtc=$p.CreationDate.ToUniversalTime().ToString('o');ownerKnown=($owner.ReturnValue -eq 0);expectedUser=($owner.ReturnValue -eq 0 -and $owner.Sid -ceq $sid)}
 })
 [Console]::Out.WriteLine(([pscustomobject]@{version=1;accountCount=$accounts.Count;accounts=$accounts;processCount=$rows.Count;processes=$rows}|ConvertTo-Json -Depth 5 -Compress))
}catch{[Console]::Out.WriteLine('{"version":1,"code":"UNKNOWN"}');exit 1}
'''

def parse_terminal(value,nonce,sha,pid):
    if value.get('exited')is not True:return None
    if value.get('out-truncated')or value.get('err-truncated'):raise ValueError('guest-truncated')
    raw=base64.b64decode(value.get('out-data',''),validate=True)
    if len(raw)>32768:raise ValueError('guest-output-cap')
    first,sep,body=raw.partition(b'\n')
    if not sep or first.rstrip(b'\r')!=('CP117-READ %s %s %d'%(nonce,sha,pid)).encode():return None
    if value.get('exitcode')!=0:raise ValueError('guest-exit')
    result=json.loads(body)
    if set(result)!={'version','accountCount','accounts','processCount','processes'}or result['version']!=1:raise ValueError('session-schema')
    for count,rows,bound in(('accountCount','accounts',1),('processCount','processes',16)):
        if type(result[count])is not int or not 0<=result[count]<=bound or not isinstance(result[rows],list)or len(result[rows])!=result[count]:raise ValueError('session-bound')
    for row in result['accounts']:
        if set(row)!={'expectedSid','expectedName','disabled','lockedOut','localAccount'}or any(type(v)is not bool for v in row.values()):raise ValueError('account-schema')
    for row in result['processes']:
        if set(row)!={'kind','pid','parentPid','sessionId','startedAtUtc','ownerKnown','expectedUser'}or row['kind']not in('explorer','logonui','winlogon'):raise ValueError('session-process-schema')
        if any(type(row[k])is not int or row[k]<0 for k in('pid','parentPid','sessionId'))or row['pid']<=0 or not isinstance(row['startedAtUtc'],str)or not row['startedAtUtc']or any(type(row[k])is not bool for k in('ownerKnown','expectedUser')):raise ValueError('session-process-schema')
        if row['expectedUser']and not row['ownerKnown']:raise ValueError('session-owner-schema')
    return result
