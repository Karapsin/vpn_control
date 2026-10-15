"""Fixed read-only setup qualification; exact guest acknowledgements never replay."""
import json,re,uuid

READ_SETUP='$ErrorActionPreference=\'Stop\'\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\nif([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne \'S-1-5-18\'){throw \'FIXTURE_SYSTEM_REQUIRED\'}\n$os=Get-CimInstance Win32_OperatingSystem\n$computer=Get-CimInstance Win32_ComputerSystem\n$version=Get-ItemProperty -LiteralPath \'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\'\n$state=Get-ItemProperty -LiteralPath \'HKLM:\\SYSTEM\\Setup\'\n$image=Get-ItemProperty -LiteralPath \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State\'\n$user=Get-LocalUser -Name $ExpectedUser\n$admin=Get-LocalUser -Name $ExpectedAdministrator\n$admins=@(Get-LocalGroupMember -SID \'S-1-5-32-544\' | ForEach-Object {$_.SID.Value})\n$users=@(Get-LocalGroupMember -SID \'S-1-5-32-545\' | ForEach-Object {$_.SID.Value})\n$profile=Get-CimInstance Win32_UserProfile -Filter ("SID=\'"+$user.SID.Value+"\'")\n$service=Get-CimInstance Win32_Service -Filter "Name=\'qemu-ga\'"\n$task=Get-ScheduledTask -TaskName \'VpnControlFixtureInitialize\'\n$taskInfo=Get-ScheduledTaskInfo -TaskName \'VpnControlFixtureInitialize\'\n$logs=Join-Path $env:ProgramData \'VpnControlFixture\'\n$ready=$null\nif(Test-Path -LiteralPath (Join-Path $logs \'ready.json\')){$ready=Get-Content -LiteralPath (Join-Path $logs \'ready.json\') -Raw | ConvertFrom-Json}\n$result=[ordered]@{\n nonce=$OperationId\n fixturePrincipal=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value\n os=[ordered]@{caption=$os.Caption;version=$os.Version;bootTime=$os.LastBootUpTime.ToUniversalTime().ToString(\'o\');productName=$version.ProductName;editionId=$version.EditionID;displayVersion=$version.DisplayVersion;build=$version.CurrentBuildNumber;ubr=$version.UBR;locale=(Get-WinSystemLocale).Name}\n computer=[ordered]@{name=$computer.Name;loggedOn=$computer.UserName;partOfDomain=$computer.PartOfDomain}\n user=[ordered]@{name=$user.Name;sid=$user.SID.Value;enabled=$user.Enabled;isAdministrator=($admins -contains $user.SID.Value);isUsersMember=($users -contains $user.SID.Value);profileRoot=$profile.LocalPath}\n administrator=[ordered]@{name=$admin.Name;sid=$admin.SID.Value;enabled=$admin.Enabled;isAdministrator=($admins -contains $admin.SID.Value)}\n setup=[ordered]@{systemSetupInProgress=$state.SystemSetupInProgress;oobeInProgress=$state.OOBEInProgress;imageState=$image.ImageState;taskState=[string]$task.State;taskResult=$taskInfo.LastTaskResult;ready=$ready}\n guestAgent=[ordered]@{state=$service.State;startMode=$service.StartMode;path=$service.PathName;pid=$service.ProcessId}\n}\n[Console]::WriteLine(($result | ConvertTo-Json -Depth 8 -Compress))\n'

def quiet_source(body):
    if type(body)is not str or not 0<len(body.encode('utf8'))<=65536:raise ValueError('guest_powershell_bound')
    return "$ProgressPreference='SilentlyContinue'\n"+body


def powershell_source(setup,operation_id):
    from .windows_vm_unattend import parse_setup
    setup=parse_setup(setup)
    if type(operation_id)is not str or str(uuid.UUID(operation_id))!=operation_id:raise ValueError("qualification_identity")
    return quiet_source("$ExpectedUser="+repr(setup["user"])+"\n$ExpectedAdministrator="+repr(setup["administrator"])+"\n$OperationId="+repr(operation_id)+"\n"+READ_SETUP)


def validate_setup_result(value,operation_id,setup):
    if (type(value)is not dict or set(value)!={'nonce','fixturePrincipal','os','computer','user','administrator','setup','guestAgent'}
            or value['nonce']!=operation_id or value['fixturePrincipal']!='S-1-5-18'
            or len(json.dumps(value))>16384):raise ValueError('instance_qualification_result')
    fields={'os':{'caption','version','bootTime','productName','editionId','displayVersion','build','ubr','locale'},
            'computer':{'name','loggedOn','partOfDomain'},'user':{'name','sid','enabled','isAdministrator','isUsersMember','profileRoot'},
            'administrator':{'name','sid','enabled','isAdministrator'},
            'setup':{'systemSetupInProgress','oobeInProgress','imageState','taskState','taskResult','ready'},
            'guestAgent':{'state','startMode','path','pid'}}
    if any(type(value[k])is not dict or set(value[k])!=wanted for k,wanted in fields.items()):raise ValueError('instance_qualification_fields')
    for role in ('user','administrator'):
        item=value[role]
        if (item['name']!=setup[role] or type(item['sid'])is not str or re.fullmatch('S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+',item['sid'])is None
                or any(type(item[k])is not bool for k in ('enabled','isAdministrator'))):raise ValueError('instance_qualification_account')
    if type(value['user']['isUsersMember'])is not bool:raise ValueError('instance_qualification_account')
    return value


def qualify_instance(spec,setup,operation_id,status_only,root,read,save,process,owns,instance_intent,closing,observed,script_source=None):
    import base64,hashlib,json,os,re,time
    global wire,partial_wire,QGA_PEER_PID,QGA_GUARD
    prefix='qualification-'+operation_id
    def require(value,reason):
        if not value:raise ValueError(reason)
    def guard_epoch():
        with open('/proc/sys/kernel/random/boot_id') as stream:boot=stream.read(128).strip()
        require(boot==CONTEXT['hostBootId'],'instance_host_epoch')
        instance_intent();closing()
    before=observed();guard_epoch()
    require(before['guestAgentReady'],'instance_guest_not_ready')
    script=PS_SCRIPT if script_source is None else script_source;digest=hashlib.sha256(script.encode()).hexdigest()
    if not status_only:
        save(prefix+'.intent.json',{'operationId':operation_id,'powerShellSha256':digest,'readOnly':True,'before':before})
        save(prefix+'.ps1',script.encode())
    intent=read(prefix+'.intent.json')
    require(intent['operationId']==operation_id and intent['readOnly']is True,'instance_qualification_intent')
    wire=partial_wire=-1
    try:
        # Every collection gets its own wire logs. No read can overwrite or
        # resubmit an original acknowledgement, even after source updates.
        suffix=os.urandom(12).hex()
        wire=os.open(root/(prefix+'.'+suffix+'.wire'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        partial_wire=os.open(root/(prefix+'.'+suffix+'.partial-wire'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        row=read('qemu-started.json');QGA_PEER_PID=row['pid'];process(row);owns(row['pid'],root/'qga.sock',True);named=os.lstat(root/'qga.sock')
        def rpc_guard():
            process(row);require(os.lstat(root/'qga.sock').st_ino==named.st_ino,'instance_qga_changed');guard_epoch()
        QGA_GUARD=rpc_guard
        if not status_only:
            require(intent['powerShellSha256']==digest,'instance_qualification_source')
            ack=call(str(root/'qga.sock'),'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',base64.b64encode(script.encode('utf-16le')).decode()],'capture-output':True})
            require(type(ack)is dict and set(ack)=={'pid'} and type(ack['pid'])is int and ack['pid']>0,'instance_guest_exec_ack')
            save(prefix+'.ack.json',{'operationId':operation_id,'ack':ack,'replayAllowed':False})
        receipt=read(prefix+'.ack.json');require(receipt['operationId']==operation_id and receipt['replayAllowed']is False,'instance_guest_exec_ack')
        if os.path.lexists(root/(prefix+'.terminal.json')):terminal=read(prefix+'.terminal.json')
        else:
            deadline=time.monotonic()+25
            while True:
                terminal=call(str(root/'qga.sock'),'guest-exec-status',receipt['ack'],_deadline=deadline)
                if terminal.get('exited')is True:break
                if time.monotonic()>=deadline:
                    guard_epoch();return {'state':'qualification-pending','operationId':operation_id,'productReady':False}
                time.sleep(.2)
            save(prefix+'.terminal.json',terminal)
        out=base64.b64decode(terminal.get('out-data',''),validate=True);err=base64.b64decode(terminal.get('err-data',''),validate=True)
        require(terminal.get('exitcode')==0 and terminal.get('exited')is True and not terminal.get('out-truncated',False) and not terminal.get('err-truncated',False) and not err and len(out)<=16384,'instance_guest_admission_output')
        result=validate_setup_result(json.loads(out.decode('utf-8-sig')),operation_id,setup)
        media=read('installer-image.json') if os.path.lexists(root/'installer-image.json') else None
        image_matches=bool(media is not None and media['installerSha256']==spec['assets']['installer']['sha256']
                           and media['image']['name']==setup['imageName'] and media['image']['editionId']==result['os']['editionId']
                           and result['os']['locale']==setup['locale'])
        ready=result['setup']['ready'];user=result['user'];admin=result['administrator']
        setup_ready=bool(image_matches and before['ordinarySessionObserved'] and type(ready)is dict and ready.get('state')=='ready' and ready.get('installerExit')in (0,3010)
                         and result['setup']['systemSetupInProgress']==0 and result['setup']['oobeInProgress']==0
                         and result['setup']['imageState']=='IMAGE_STATE_COMPLETE' and user['enabled'] and not user['isAdministrator']
                         and user['isUsersMember'] and admin['enabled'] and admin['isAdministrator'] and result['guestAgent']['state']=='Running')
        process(row);guard_epoch()
        return {'state':'setup-observed','operationId':operation_id,'setupReady':setup_ready,'imageMatchesRequest':image_matches,
                'result':result,'productReady':False}
    finally:
        for fd in (wire,partial_wire):
            if fd>=0:os.close(fd)


SECURE_SETUP=r'''$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){throw 'FIXTURE_SYSTEM_REQUIRED'}
$state=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
if($state.SystemSetupInProgress -ne 0 -or $state.OOBEInProgress -ne 0){throw 'FIXTURE_SETUP_INCOMPLETE'}
$data=[Console]::In.ReadToEnd() | ConvertFrom-Json
if($data.operationId -cne $OperationId -or $data.password -cnotmatch '^[A-Za-z0-9!_-]{24,64}$'){throw 'FIXTURE_SECRET_INPUT'}
$password=ConvertTo-SecureString -String $data.password -AsPlainText -Force
try{Set-LocalUser -Name $ExpectedAdministrator -Password $password}finally{$password.Dispose()}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class FixtureLogon {
 [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]
 public static extern bool LogonUser(string user,string domain,string password,int type,int provider,out IntPtr token);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr token);
}
'@
$token=[IntPtr]::Zero
try {
 if(-not [FixtureLogon]::LogonUser($ExpectedAdministrator,$env:COMPUTERNAME,$data.password,3,0,[ref]$token)){throw 'FIXTURE_PASSWORD_VERIFY'}
} finally {if($token -ne [IntPtr]::Zero){[void][FixtureLogon]::CloseHandle($token)};$data.password=$null;$data=$null}
$key='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty -LiteralPath $key -Name AutoAdminLogon -Value '0'
foreach($name in @('DefaultPassword','AutoLogonCount')){
 if((Get-ItemProperty -LiteralPath $key).PSObject.Properties.Name -contains $name){Remove-ItemProperty -LiteralPath $key -Name $name}
}
$caches=@((Join-Path $env:WINDIR 'Panther\unattend.xml'),(Join-Path $env:WINDIR 'Panther\autounattend.xml'),(Join-Path $env:WINDIR 'Panther\Unattend\unattend.xml'),(Join-Path $env:WINDIR 'System32\Sysprep\unattend.xml'))
foreach($path in $caches){if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}}
Disable-ScheduledTask -TaskName 'VpnControlFixtureInitialize' | Out-Null
$winlogon=Get-ItemProperty -LiteralPath $key
if($winlogon.AutoAdminLogon -ne '0' -or $winlogon.PSObject.Properties.Name -contains 'DefaultPassword' -or $winlogon.PSObject.Properties.Name -contains 'AutoLogonCount'){throw 'FIXTURE_AUTOLOGON_REMAINS'}
if(@($caches | Where-Object {Test-Path -LiteralPath $_}).Count -ne 0){throw 'FIXTURE_SETUP_CACHE_REMAINS'}
if((Get-ScheduledTask -TaskName 'VpnControlFixtureInitialize').State -ne 'Disabled'){throw 'FIXTURE_TASK_REMAINS'}
[Console]::WriteLine((@{nonce=$OperationId;principal='S-1-5-18';passwordVerified=$true;automaticLogonDisabled=$true;setupCachesRemoved=$true;setupTaskDisabled=$true} | ConvertTo-Json -Compress))
'''


def secure_source(setup,operation_id):
    # Reuse the exact validated, literal account/nonce bindings; no credentials
    # enter argv or executable source. QGA supplies them only through stdin.
    source=powershell_source(setup,operation_id)
    return source[:source.index(READ_SETUP)]+SECURE_SETUP


def secure_instance(spec,setup,operation_id,status_only,root,read,save,process,owns,instance_intent,closing,observed,qmp):
    import base64,hashlib,json,os,re,stat,sys,time,uuid
    global wire,partial_wire,QGA_PEER_PID,QGA_GUARD
    def require(value,reason):
        if not value:raise ValueError(reason)
    def guard_epoch():
        with open('/proc/sys/kernel/random/boot_id')as stream:boot=stream.read(128).strip()
        require(boot==CONTEXT['hostBootId'],'instance_host_epoch');instance_intent();closing()
    if not status_only:
        check_id=str(uuid.uuid5(uuid.UUID(operation_id),'secure-setup-admission'))
        check=qualify_instance(spec,setup,check_id,False,root,read,save,process,owns,instance_intent,closing,observed,SECURE_CHECK_SCRIPT)
        require(check['state']=='setup-observed' and check['setupReady']is True,'instance_secure_admission')
        # A separate immutable intent fences every credential/media effect.
        save('secure-intent.json',{'operationId':operation_id,'powerShellSha256':hashlib.sha256(SECURE_SCRIPT.encode()).hexdigest(),'qualificationId':check_id})
        blocks=qmp('query-block');seed=[b for b in blocks if b.get('device')=='seed']
        require(len(seed)==1 and seed[0].get('inserted',{}).get('file')==str(root/'seed.iso'),'instance_seed_identity')
        qmp('eject',{'device':'seed','force':True})
        seed=[b for b in qmp('query-block')if b.get('device')=='seed']
        require(len(seed)==1 and 'inserted'not in seed[0],'instance_seed_eject_unknown')
        save('secure-media-ejected.json',{'operationId':operation_id,'seedEmpty':True})
    intent=read('secure-intent.json');require(intent['operationId']==operation_id,'instance_secure_identity')
    ejected=read('secure-media-ejected.json');require(ejected=={'operationId':operation_id,'seedEmpty':True},'instance_seed_eject_unknown')
    guard_epoch();row=read('qemu-started.json');process(row);owns(row['pid'],root/'qga.sock',True);named=os.lstat(root/'qga.sock')
    wire=partial_wire=-1
    try:
        suffix=os.urandom(12).hex()
        wire=os.open(root/('secure-'+suffix+'.wire'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        partial_wire=os.open(root/('secure-'+suffix+'.partial-wire'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        QGA_PEER_PID=row['pid']
        def guard():
            process(row);require(os.lstat(root/'qga.sock').st_ino==named.st_ino,'instance_qga_changed');guard_epoch()
        QGA_GUARD=guard
        if not status_only:
            payload=json.loads(sys.stdin.buffer.read(4097));require(type(payload)is dict and set(payload)=={'password'},'instance_secure_payload')
            require(type(payload['password'])is str and re.fullmatch('[A-Za-z0-9!_-]{24,64}',payload['password'])is not None,'instance_secure_payload')
            payload['operationId']=operation_id
            save('secure.ps1',SECURE_SCRIPT.encode())
            ack=call(str(root/'qga.sock'),'guest-exec',{'path':'powershell.exe','arg':['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-EncodedCommand',base64.b64encode(SECURE_SCRIPT.encode('utf-16le')).decode()],
                    'input-data':base64.b64encode(json.dumps(payload).encode()).decode(),'capture-output':True})
            payload.clear()
            require(type(ack)is dict and set(ack)=={'pid'} and type(ack['pid'])is int and ack['pid']>0,'instance_guest_exec_ack')
            save('secure-ack.json',{'operationId':operation_id,'ack':ack,'replayAllowed':False})
        receipt=read('secure-ack.json');require(receipt['operationId']==operation_id and receipt['replayAllowed']is False,'instance_guest_exec_ack')
        if os.path.lexists(root/'secure-terminal.json'):terminal=read('secure-terminal.json')
        else:
            deadline=time.monotonic()+25
            while True:
                terminal=call(str(root/'qga.sock'),'guest-exec-status',receipt['ack'],_deadline=deadline)
                if terminal.get('exited')is True:break
                if time.monotonic()>=deadline:
                    guard();return {'state':'secure-pending','operationId':operation_id,'productReady':False}
                time.sleep(.2)
            save('secure-terminal.json',terminal)
        out=base64.b64decode(terminal.get('out-data',''),validate=True);err=base64.b64decode(terminal.get('err-data',''),validate=True)
        require(terminal.get('exited')is True and terminal.get('exitcode')==0 and not terminal.get('out-truncated',False) and not terminal.get('err-truncated',False) and not err and len(out)<=4096,'instance_secure_output')
        result=json.loads(out.decode('utf-8-sig'))
        require(result=={'nonce':operation_id,'principal':'S-1-5-18','passwordVerified':True,'automaticLogonDisabled':True,'setupCachesRemoved':True,'setupTaskDisabled':True},'instance_secure_result')
        # Cleanup may resume only after a retained terminal proves the one
        # credential operation succeeded. Never resubmit guest-exec or eject.
        seed=[b for b in qmp('query-block')if b.get('device')=='seed']
        require(len(seed)==1 and 'inserted'not in seed[0],'instance_seed_eject_unknown');guard()
        paths=[root/'seed.iso',root/'seed/Autounattend.xml',root/'seed/initialize.ps1',root/'seed/install-agent.ps1']
        for path in paths:
            if not os.path.lexists(path):continue
            info=os.lstat(path)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o600 and info.st_nlink==1,'instance_seed_cleanup_identity')
            guard();os.unlink(path)
        if os.path.lexists(root/'seed'):
            info=os.lstat(root/'seed');require(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700,'instance_seed_cleanup_identity')
            guard();os.rmdir(root/'seed')
        guard();return {'state':'secured-observed','operationId':operation_id,'setupSecured':True,'productReady':False}
    finally:
        for fd in (wire,partial_wire):
            if fd>=0:os.close(fd)
