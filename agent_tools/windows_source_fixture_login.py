"""Private existing-source account boundary for the two fixed owned guests.

No login runs on import. Passwords and secret-derived key requests remain only
in memory and the positively identified guest's private QMP socket channel.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import stat
import time

from . import windows_parallel_vm_launch as launch

SOURCE_ROOT=Path('/home/kardinal/vpn-control-windows-native-20260907')
SOURCE_PARENT=[66307,31893507,16832,1000,1000]
CREDENTIAL_GENERATION=[66307,31893835,33152,1000,1000,1,75,1788737169010323133,1788737169010323133]
ACCOUNT='parityagent'
SID='S-1-5-21-606332539-4179368406-55829832-1000'
QEMU_PID=3726886
QEMU_TICKS=21863571


class PrivateLoginUnknown(ValueError):
    """Finite public code only; no private channel bytes or exception text."""


def private_source_credential(path=SOURCE_ROOT/'credentials.json'):
    """Fixed owner-private file; never compute a digest of its contents."""
    launch.need(path==SOURCE_ROOT/'credentials.json','source-login-credential-path')
    launch.need(launch.inventory.parent_identity(SOURCE_ROOT.lstat())==SOURCE_PARENT,'source-login-parent')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        launch.need(launch.inventory.generation(before)==CREDENTIAL_GENERATION
            and stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode)==0o600
            and before.st_uid==1000 and before.st_nlink==1,'source-login-credential-shape')
        raw=os.read(fd,4097);launch.need(len(raw)==75,'source-login-credential-size')
        try:value=json.loads(raw)
        except BaseException:raise PrivateLoginUnknown('private-input-unsupported') from None
        launch.need(type(value) is dict and set(value) in ({'username','password'},{'user','password'},{'accountName','password'}),
            'source-login-credential-schema')
        names=[v for k,v in value.items() if k in ('username','user','accountName')]
        launch.need(names==[ACCOUNT] and type(value['password']) is str,'source-login-account')
        try:secret=value['password'].encode('ascii')
        except BaseException:raise PrivateLoginUnknown('private-input-unsupported') from None
        launch.need(0<len(secret)<=64 and all(33<=v<=126 for v in secret),'source-login-password-shape')
        launch.need(launch.inventory.generation(os.fstat(fd))==CREDENTIAL_GENERATION
            ==launch.inventory.generation(path.lstat())
            and launch.inventory.parent_identity(SOURCE_ROOT.lstat())==SOURCE_PARENT,'source-login-credential-closing')
        return secret
    finally:os.close(fd)


def private_key_requests(secret):
    """Pure fixed US keyboard encoding; never describe unsupported bytes."""
    if type(secret) is not bytes or not 0<len(secret)<=64:
        raise PrivateLoginUnknown('private-input-unsupported')
    shifted={'!':'1','@':'2','#':'3','$':'4','%':'5','^':'6','&':'7','*':'8','(':'9',')':'0',
        '_':'minus','+':'equal','{':'bracket_left','}':'bracket_right','|':'backslash',
        ':':'semicolon','"':'apostrophe','<':'comma','>':'dot','?':'slash','~':'grave_accent'}
    plain={'-':'minus','=':'equal','[':'bracket_left',']':'bracket_right','\\':'backslash',
        ';':'semicolon',"'":'apostrophe',',':'comma','.':'dot','/':'slash','`':'grave_accent'}
    requests=[]
    for byte in secret:
        char=chr(byte);shift=False
        if 'A'<=char<='Z':key=char.lower();shift=True
        elif 'a'<=char<='z' or '0'<=char<='9':key=char
        elif char in plain:key=plain[char]
        elif char in shifted:key=shifted[char];shift=True
        else:raise PrivateLoginUnknown('private-input-unsupported')
        keys=([{'type':'qcode','data':'shift'}] if shift else [])+[{'type':'qcode','data':key}]
        requests.append({'keys':keys,'hold-time':80})
    return requests


def private_qmp_command(connection, command, arguments, token, deadline):
    """Private request and sanitized bounded reply; no response journal/hashes.

    A QMP refusal can echo request content, so neither raw reply nor its error
    description may escape this boundary. No logger or receipt callback exists.
    """
    if command not in ('send-key','qmp_capabilities') or type(token) is not str or not re.fullmatch('[a-z0-9-]{1,96}',token):
        raise PrivateLoginUnknown('private-request-unsupported')
    request={'execute':command,'id':token}
    if arguments is not None:request['arguments']=arguments
    try:
        connection.sendall(json.dumps(request,separators=(',',':')).encode()+b'\n')
        for _ in range(16):
            raw=bytearray()
            while not raw.endswith(b'\n'):
                remaining=deadline-time.monotonic()
                if remaining<=0:raise PrivateLoginUnknown('private-reply-unknown')
                connection.settimeout(remaining)
                chunk=connection.recv(1)
                if not chunk:raise PrivateLoginUnknown('private-reply-unknown')
                raw.extend(chunk)
                if len(raw)>4096:raise PrivateLoginUnknown('private-reply-unknown')
            reply=json.loads(raw)
            if type(reply) is not dict:raise PrivateLoginUnknown('private-reply-unknown')
            if reply.get('id')==token:
                if set(reply)!={'return','id'} or type(reply['return']) is not dict:
                    raise PrivateLoginUnknown('private-reply-unknown')
                return True
            if 'event' not in reply:raise PrivateLoginUnknown('private-reply-unknown')
        raise PrivateLoginUnknown('private-reply-unknown')
    except PrivateLoginUnknown:raise
    except BaseException:
        raise PrivateLoginUnknown('private-reply-unknown') from None


def private_receipt_name(index):
    if type(index) is not int or not 0<=index<=128:
        raise PrivateLoginUnknown('private-receipt-unsupported')
    value=index+1;letters=''
    while value:
        value,remainder=divmod(value-1,26);letters=chr(97+remainder)+letters
    return 'private-'+letters+'.json'


def perform_private_login(connection, secret, correlation, guard, publish):
    """One private sequence; callbacks receive no secret or derived keycodes."""
    requests=private_key_requests(secret)
    publish({'phase':'private-entry-intent','replayAllowed':False})
    try:
        for index,arguments in enumerate(requests):
            guard()
            private_qmp_command(connection,'send-key',arguments,
                correlation+'-private-'+str(index),time.monotonic()+3)
            publish({'phase':'private-acknowledged','index':index,'replayAllowed':False})
            time.sleep(.1)
        guard()
        private_qmp_command(connection,'send-key',{'keys':[{'type':'qcode','data':'ret'}],'hold-time':80},
            correlation+'-submit',time.monotonic()+3)
        publish({'phase':'private-submit-acknowledged','replayAllowed':False})
        guard()
        return {'state':'login-submitted','replayAllowed':False,'interactiveSessionVerified':False}
    except BaseException:
        publish({'phase':'private-entry-unknown','replayAllowed':False})
        raise PrivateLoginUnknown('private-entry-unknown') from None
    finally:
        secret=None;requests=None


def login_program(prepared, observed, identity, correlation, *, slot="secondary"):
    """Two fixed source/account/field targets; never a path or PID selector."""
    import inspect
    import uuid
    launch.need(type(slot) is str and slot in ("secondary","tertiary"),"source-login-target")
    target={"secondary":(QEMU_PID,QEMU_TICKS,"vm-r-a85c4b4f",
                "09e6fad22ba0972293fd489c60163259e7401d6725328fc8212919dc3a7dbefa"),
            "tertiary":(3847348,22216504,"vm-r-e7e110ff",
                "9bed1ae596597faf24cdf97d7225bdd89cfd737149a92751add910c6d1afc6c3")}[slot]
    prepared,observed,identity=json.loads(json.dumps([prepared,observed,identity],sort_keys=True))
    launch.need(str(uuid.UUID(correlation))==correlation and type(identity) is dict
        and type(identity.get('pid')) is int and identity['pid']==target[0]
        and type(identity.get('startTicks')) is int and identity['startTicks']==target[1]
        and type(identity.get('uid')) is int and identity['uid']==1000,'source-login-identity')
    header=launch.launch_program(prepared,observed,correlation).split('\nrun=None\n',1)[0]
    header+='import base64\n'
    header+='launch=SimpleNamespace(need=need,inventory=inventory)\n'
    for name in ('SOURCE_ROOT','SOURCE_PARENT','CREDENTIAL_GENERATION','ACCOUNT','SID','QEMU_PID','QEMU_TICKS'):
        value=globals()[name]
        header+=name+'='+("Path("+repr(str(value))+")" if isinstance(value,Path) else repr(value))+'\n'
    for function in (PrivateLoginUnknown,private_source_credential,private_key_requests,private_qmp_command,private_receipt_name,perform_private_login):
        header+=inspect.getsource(function)+'\n'
    header+='ROW='+repr(identity)+'\nCORRELATION='+repr(correlation)+'\n'
    header+='SLOT='+repr(slot)+'\nSTATE_NAME='+repr(target[2])+'\nFIELD_SHA='+repr(target[3])+'\n'
    header+=r'''
value={'state':'unknown','reason':'source-login-preentry','credentialEntrySubmitted':False,'productAcceptance':False,'replayAllowed':False}
fd=None;secret=None
try:
 need(os.geteuid()==0,'source-login-privilege');observed_process(Path('/proc'),ROW)
 guest=fixed_guest(SLOT);state=guest.root/STATE_NAME
 need(stat.S_ISDIR(state.lstat().st_mode) and state.lstat().st_uid==1000 and stat.S_IMODE(state.lstat().st_mode)==0o700,'source-login-state')
 journal=Path('/home/kardinal/vpn-control-windows-parallel-vm-template-20261005')/('source-login-'+CORRELATION)
 parentfd=os.open(journal.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);parentpin=parent_identity(os.fstat(parentfd))
 need(parentpin==parent_identity(journal.parent.lstat()) and parentpin[3:5]==[0,1000] and stat.S_IMODE(parentpin[2])==0o750,'source-login-journal-parent')
 journal.mkdir(mode=0o700);os.fsync(parentfd);fd=os.open(journal,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);journalpin=parent_identity(os.fstat(fd))
 qga_client=AccessClient(str(state/'qga.sock'),timeout_seconds=3).bind({'rootFd':fd},guest,ROW)
 account_script=r"$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$u=Get-LocalUser -Name parityagent;$p=Get-ItemProperty -LiteralPath 'Registry::HKEY_USERS\.DEFAULT\Keyboard Layout\Preload';[ordered]@{account=$u.Name;fullName=$u.FullName;sid=$u.SID.Value;enabled=$u.Enabled;loginKeyboard=$p.'1'}|ConvertTo-Json -Compress"
 created=qga_client._exchange('guest-exec',{'path':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe','arg':['-NoProfile','-NonInteractive','-EncodedCommand',base64.b64encode(account_script.encode('utf-16le')).decode()],'capture-output':True})
 need(type(created) is dict and set(created)=={'pid'} and type(created['pid']) is int and created['pid']>0,'source-login-account-pid')
 prepare.record_at(fd,'account-started.json',created);value['originalAccountProbePid']=created['pid'];deadline=time.monotonic()+30
 while True:
  result=qga_client.guest_exec_status(created['pid'])
  if result.get('exited') is True:break
  need(time.monotonic()<deadline,'source-login-account-deadline');time.sleep(.2)
 need(result.get('exitcode')==0 and result.get('out-truncated') is not True,'source-login-account-exit')
 raw=base64.b64decode(result.get('out-data',''),validate=True);need(0<len(raw)<=4096,'source-login-account-output')
 account=json.loads(raw)
 need(type(account) is dict and set(account)=={'account','fullName','sid','enabled','loginKeyboard'}
  and type(account['enabled']) is bool and account['enabled'] is True
  and all(type(account[key]) is str for key in ('account','fullName','sid','loginKeyboard'))
  and account=={'account':ACCOUNT,'fullName':'Parity test user','sid':SID,'enabled':True,'loginKeyboard':'00000409'},'source-login-account-current')
 prepare.record_at(fd,'account-admitted.json',account);observed_process(Path('/proc'),ROW)
 # Account probing is complete; continue its immutable journal sequence.
 framer=AccessClient('fixed-qmp',max_response_bytes=4096).bind({'rootFd':fd},guest,ROW)
 framer.frames=qga_client.frames
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
  connection.settimeout(3);connection.connect(str(state/'qmp.sock'));peer=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(peer[:2]==(ROW['pid'],1000),'source-login-peer')
  def receive():return json.loads(framer._read_qmp_response(connection,time.monotonic()+3))
  need('QMP' in receive(),'source-login-greeting')
  def public_command(name,args=None):
   token=CORRELATION+'-'+name;request={'execute':name,'id':token}
   if args is not None:request['arguments']=args
   connection.sendall(json.dumps(request).encode()+b'\n')
   for _ in range(16):
    answer=receive()
    if answer.get('id')==token:need('return' in answer,'source-login-public-refusal');return answer
   raise ValueError('source-login-public-response')
  public_command('qmp_capabilities');need(public_command('query-status')['return']['status']=='running','source-login-running')
  screen=state/('admit-'+CORRELATION[:8]+'.png');need(not os.path.lexists(screen),'source-login-screen-existing')
  public_command('screendump',{'filename':str(screen),'format':'png'})
  imagefd=os.open(screen,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:pin=file_hash(imagefd,1048576)
  finally:os.close(imagefd)
  need(pin['generation']==generation(screen.lstat()) and pin['generation'][3:6]==[1000,1000,1]
   and pin['sha256']==FIELD_SHA,'source-login-current-field')
  secret=private_source_credential()
  prepare.record_at(fd,'admission.json',{'originalPid':ROW['pid'],'startTicks':ROW['startTicks'],'guest':SLOT,'account':ACCOUNT,'sid':SID,
   'sourceCredentialGeneration':CREDENTIAL_GENERATION,'emptyField':pin,'loginKeyboard':'00000409','capsLockWarningAbsent':True,
   'credentialReset':False,'replayAllowed':False})
  index=[0]
  def publish(metadata):
   prepare.record_at(fd,private_receipt_name(index[0]),metadata);index[0]+=1
  def guard():
   observed_process(Path('/proc'),ROW)
   need(parentpin==parent_identity(os.fstat(parentfd))==parent_identity(journal.parent.lstat()) and journalpin==parent_identity(os.fstat(fd))==parent_identity(journal.lstat()),'source-login-journal-closing')
   need(generation((SOURCE_ROOT/'credentials.json').lstat())==CREDENTIAL_GENERATION
    and parent_identity(SOURCE_ROOT.lstat())==SOURCE_PARENT,'source-login-input-generation')
  value['credentialEntrySubmitted']=True
  submitted=perform_private_login(connection,secret,CORRELATION,guard,publish)
  secret=None
  observed_process(Path('/proc'),ROW)
  value={**submitted,'correlationId':CORRELATION,'credentialEntrySubmitted':True,'productAcceptance':False}
 prepare.record_at(fd,'result.json',value)
except BaseException as error:
 value['reason']='source-login-unknown-after-submission' if value['credentialEntrySubmitted'] else 'source-login-preentry-refused'
 value['errorType']=type(error).__name__
 if fd is not None:
  try:prepare.record_at(fd,'unknown.json',value)
  except BaseException:pass
finally:
 secret=None
 if fd is not None:os.close(fd)
 if 'parentfd' in globals():os.close(parentfd)
print(json.dumps(value,sort_keys=True),flush=True)
'''
    compile(header,'fixed source fixture private login','exec')
    return header
