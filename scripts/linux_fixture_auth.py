#!/usr/bin/env python3
"""Private OS-authentication input for the disposable Linux fixture guest."""
from __future__ import annotations
import json, os, secrets, stat, subprocess, sys
from pathlib import Path

FIXTURE_ACCOUNT = "vpnfixture"
PURPOSE = "linux-public-install-polkit-auth"
OWNED_GUEST_CONFIRMATION = "I_CONFIRM_VPNFIXTURE_DISPOSABLE_GUEST"
_CREDENTIAL, _RECEIPT, _BASELINE, _MAX = "credential", "receipt.json", "baseline.json", 16384
class FixtureAuthError(RuntimeError): pass
def _need(ok, message):
    if not ok: raise FixtureAuthError(message)
def _default_account(name):
    import pwd  # unavailable on Windows: import only after the Linux gate
    return pwd.getpwnam(name)
def _account(lookup, platform, geteuid):
    _need(platform.startswith("linux"), "Linux fixture authentication requires Linux")
    geteuid = getattr(os, "geteuid", lambda: -1) if geteuid is None else geteuid
    item=lookup(FIXTURE_ACCOUNT); uid=getattr(item,"pw_uid",None)
    _need(getattr(item,"pw_name",FIXTURE_ACCOUNT)==FIXTURE_ACCOUNT and type(uid) is int and uid>0, "Fixture account identity is unsafe")
    _need(geteuid()==uid and geteuid()!=0, "Fixture authentication must run as the non-root vpnfixture account")
    return item
def _parts(path):
    path=Path(path); _need(path.is_absolute() and ".." not in path.parts and len(path.parts)>1, "Credential directory must be absolute and lexical")
    return path.parts[1:]
def _parent(path, uid):
    flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0); fd=os.open("/",flags)
    try:
        parts=_parts(path)
        for part in parts[:-1]:
            child=os.open(part,flags,dir_fd=fd); os.close(fd); fd=child
        info=os.fstat(fd); _need(stat.S_ISDIR(info.st_mode) and info.st_uid==uid and not stat.S_IMODE(info.st_mode)&0o022, "Credential directory parent identity or mode is unsafe")
        return fd,parts[-1],info.st_dev
    except Exception: os.close(fd); raise
def _dir(parent,name,uid,device):
    fd=os.open(name,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0),dir_fd=parent)
    try:
        info=os.fstat(fd); _need(stat.S_ISDIR(info.st_mode) and info.st_uid==uid and stat.S_IMODE(info.st_mode)==0o700 and info.st_dev==device, "Fixture credential directory identity or mode is unsafe")
        return fd,info
    except Exception: os.close(fd); raise
def _read(fd,name,uid,device):
    try: child=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=fd)
    except OSError: raise FixtureAuthError("Fixture credential file is unsafe") from None
    try:
        info=os.fstat(child); _need(stat.S_ISREG(info.st_mode) and info.st_uid==uid and stat.S_IMODE(info.st_mode)==0o600 and info.st_dev==device and info.st_size<=_MAX, "Fixture credential file identity or mode is unsafe")
        value=os.read(child,_MAX+1); _need(len(value)<=_MAX,"Fixture credential file is too large"); return value,info
    finally: os.close(child)
def _write(fd,name,value,uid,device):
    child=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600,dir_fd=fd)
    try:
        os.fchmod(child,0o600); _write_all(child,value); os.fsync(child); info=os.fstat(child)
        _need(stat.S_ISREG(info.st_mode) and info.st_uid==uid and stat.S_IMODE(info.st_mode)==0o600 and info.st_dev==device, "Fixture credential file identity or mode is unsafe")
        return info
    finally: os.close(child)
def _replace(fd,name,value,uid,device):
    try: child=os.open(name,os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=fd)
    except OSError: raise FixtureAuthError("Fixture credential file is unsafe") from None
    try:
        info=os.fstat(child); _need(stat.S_ISREG(info.st_mode) and info.st_uid==uid and stat.S_IMODE(info.st_mode)==0o600 and info.st_dev==device, "Fixture credential file identity or mode is unsafe")
        os.ftruncate(child,0); _write_all(child,value); os.fsync(child)
    finally: os.close(child)
def _write_all(fd,value):
    pending=memoryview(value)
    while pending:
        try: count=os.write(fd,pending)
        except OSError: raise FixtureAuthError("Fixture credential file write failed") from None
        _need(type(count) is int and count>0 and count<=len(pending), "Fixture credential file write was partial")
        pending=pending[count:]
def _run(argv,runner,**kwargs):
    try: return runner(argv,text=True,capture_output=True,check=False,**kwargs)
    except Exception: raise FixtureAuthError("Fixture account command failed") from None
def _locked(runner):
    result=_run(["passwd","--status",FIXTURE_ACCOUNT],runner); fields=getattr(result,"stdout","").strip().split()
    _need(getattr(result,"returncode",1)==0 and len(fields)>=2 and fields[0]==FIXTURE_ACCOUNT and fields[1]=="L", "Fixture account must have a locked-only password baseline")
def _shadow(runner):
    result=_run(["sudo","-n","getent","shadow",FIXTURE_ACCOUNT],runner)
    _need(getattr(result,"returncode",1)==0, "Fixture password baseline is unavailable")
    raw=getattr(result,"stdout","")
    _need(isinstance(raw,str) and raw.endswith("\n") and raw.count("\n")==1, "Fixture password baseline is unsafe")
    fields=raw[:-1].split(":")
    _need(len(fields)==9 and fields[0]==FIXTURE_ACCOUNT and fields[1] and all("\x00" not in value and "\r" not in value and "\n" not in value for value in fields), "Fixture password baseline is unsafe")
    _need(all(value=="" or value.isdecimal() for value in fields[2:]), "Fixture password baseline is unsafe")
    return fields
def _private_baseline(fd,uid,device):
    raw,_=_read(fd,_BASELINE,uid,device)
    try: baseline=json.loads(raw.decode())
    except (ValueError,UnicodeDecodeError): raise FixtureAuthError("Fixture password baseline is unreadable") from None
    _need(set(baseline)=={"original","post"} and all(isinstance(value,list) and len(value)==9 for value in baseline.values()), "Fixture password baseline is unsafe")
    for fields in baseline.values():
        _need(fields[0]==FIXTURE_ACCOUNT and fields[1] and all(isinstance(value,str) and "\x00" not in value and "\r" not in value and "\n" not in value for value in fields) and all(value=="" or value.isdecimal() for value in fields[2:]), "Fixture password baseline is unsafe")
    return baseline
def _validate(directory,correlation,purpose,uid):
    _need(isinstance(correlation,str) and correlation and "/" not in correlation and "\0" not in correlation,"Fixture correlation is unsafe"); _need(purpose==PURPOSE,"Fixture credential purpose is unsafe")
    parent,name,device=_parent(directory,uid)
    try: fd,_=_dir(parent,name,uid,device)
    finally: os.close(parent)
    try:
        raw,_=_read(fd,_RECEIPT,uid,device); credential,info=_read(fd,_CREDENTIAL,uid,device)
        try: receipt=json.loads(raw.decode())
        except (ValueError,UnicodeDecodeError): raise FixtureAuthError("Fixture credential receipt is unreadable") from None
        required={"account","correlation","credentialPath","credentialPathInode","purpose","uid"}
        _need(set(receipt) in (required,required|{"preservesExistingPassword"}) and receipt["account"]==FIXTURE_ACCOUNT and receipt["uid"]==uid and receipt["correlation"]==correlation and receipt["purpose"]==PURPOSE and receipt["credentialPath"]==str(Path(directory)/_CREDENTIAL) and receipt["credentialPathInode"]==info.st_ino and ("preservesExistingPassword" not in receipt or receipt["preservesExistingPassword"] is True),"Fixture credential receipt identity is unsafe")
        return receipt,credential
    finally: os.close(fd)
def prepare(*,credential_dir,correlation,purpose,guest_confirmation,runner=subprocess.run,account_lookup=_default_account,password_factory=None,platform=sys.platform,geteuid=None,preserve_existing_password=False):
    _need(guest_confirmation==OWNED_GUEST_CONFIRMATION,"Disposable vpnfixture guest confirmation is required"); account=_account(account_lookup,platform,geteuid); _need(purpose==PURPOSE,"Fixture credential purpose is unsafe")
    baseline=None
    if preserve_existing_password is True:
        status=_run(["passwd","--status",FIXTURE_ACCOUNT],runner); fields=getattr(status,"stdout","").strip().split()
        _need(getattr(status,"returncode",1)==0 and len(fields)>=2 and fields[0]==FIXTURE_ACCOUNT and fields[1]=="P", "Fixture account must have a password baseline for preservation")
        baseline=_shadow(runner)
    else:
        _need(preserve_existing_password is False,"Existing-password preservation must be explicitly enabled"); _locked(runner)
    parent,name,device=_parent(credential_dir,account.pw_uid)
    try:
        try: os.mkdir(name,0o700,dir_fd=parent)
        except FileExistsError: raise FixtureAuthError("Credential directory already exists; refusing overwrite") from None
        fd,_=_dir(parent,name,account.pw_uid,device)
    finally: os.close(parent)
    try:
        password=(password_factory or (lambda:secrets.token_urlsafe(32)))(); _need(isinstance(password,str) and password and "\n" not in password and "\r" not in password and ":" not in password,"Generated fixture password is unsafe")
        info=_write(fd,_CREDENTIAL,(password+"\n").encode(),account.pw_uid,device); receipt={"account":FIXTURE_ACCOUNT,"correlation":correlation,"credentialPath":str(Path(credential_dir)/_CREDENTIAL),"credentialPathInode":info.st_ino,"purpose":PURPOSE,"uid":account.pw_uid}
        if baseline is not None: receipt["preservesExistingPassword"]=True
        _write(fd,_RECEIPT,(json.dumps(receipt,sort_keys=True)+"\n").encode(),account.pw_uid,device)
        if baseline is not None: _write(fd,_BASELINE,(json.dumps({"original":baseline,"post":[]},sort_keys=True)+"\n").encode(),account.pw_uid,device)
        changed=_run(["sudo","-n","chpasswd"],runner,input=FIXTURE_ACCOUNT+":"+password+"\n"); _need(getattr(changed,"returncode",1)==0,"Fixture OS password setup failed")
        if baseline is not None:
            post=_shadow(runner); _replace(fd,_BASELINE,(json.dumps({"original":baseline,"post":post},sort_keys=True)+"\n").encode(),account.pw_uid,device)
        return receipt
    finally: os.close(fd)
def status(*,credential_dir,correlation,purpose,account_lookup=_default_account,platform=sys.platform,geteuid=None):
    account=_account(account_lookup,platform,geteuid); receipt,_=_validate(credential_dir,correlation,purpose,account.pw_uid); return receipt.copy()
def read_credential_after_prompt(*,credential_dir,correlation,purpose,prompt_confirmed,account_lookup=_default_account,platform=sys.platform,geteuid=None):
    _need(prompt_confirmed is True,"Credential may be read only after prompt confirmation"); account=_account(account_lookup,platform,geteuid); _,raw=_validate(credential_dir,correlation,purpose,account.pw_uid)
    try: value=raw.decode()
    except UnicodeDecodeError: raise FixtureAuthError("Fixture credential is unsafe") from None
    _need(value.endswith("\n") and value.count("\n")==1 and value[:-1],"Fixture credential is unsafe"); return value[:-1]
def restore(*,credential_dir,correlation,terminal_receipt,terminal_validator,runner=subprocess.run,account_lookup=_default_account,platform=sys.platform,geteuid=None):
    _need(callable(terminal_validator) and terminal_validator(terminal_receipt,correlation) is True,"Fixture terminal correlation is unknown; preserving credential files")
    account=_account(account_lookup,platform,geteuid); receipt,_=_validate(credential_dir,correlation,PURPOSE,account.pw_uid)
    baseline=None
    if receipt.get("preservesExistingPassword") is True:
        parent,name,device=_parent(credential_dir,account.pw_uid)
        try: fd,_=_dir(parent,name,account.pw_uid,device)
        finally: os.close(parent)
        try: baseline=_private_baseline(fd,account.pw_uid,device)
        finally: os.close(fd)
        _need(baseline["post"],"Fixture password setup state is unknown; preserving credential files")
        _need(_shadow(runner)==baseline["post"],"Fixture account changed concurrently; preserving credential files")
        restored=_run(["sudo","-n","chpasswd","-e"],runner,input=FIXTURE_ACCOUNT+":"+baseline["original"][1]+"\n"); _need(getattr(restored,"returncode",1)==0,"Fixture password restoration failed")
        last_change=baseline["original"][2] or "-1"
        aged=_run(["sudo","-n","chage","-d",last_change,FIXTURE_ACCOUNT],runner); _need(getattr(aged,"returncode",1)==0,"Fixture password aging restoration failed")
        _need(_shadow(runner)==baseline["original"],"Fixture password restoration verification failed")
    else:
        locked=_run(["sudo","-n","passwd","--lock","--",FIXTURE_ACCOUNT],runner); _need(getattr(locked,"returncode",1)==0,"Fixture account lock restoration failed"); _locked(runner)
    parent,name,device=_parent(credential_dir,account.pw_uid)
    try: fd,_=_dir(parent,name,account.pw_uid,device)
    finally: os.close(parent)
    try:
        _read(fd,_CREDENTIAL,account.pw_uid,device); _read(fd,_RECEIPT,account.pw_uid,device)
        if baseline is not None: _read(fd,_BASELINE,account.pw_uid,device); os.unlink(_BASELINE,dir_fd=fd)
        os.unlink(_CREDENTIAL,dir_fd=fd); os.unlink(_RECEIPT,dir_fd=fd)
    finally: os.close(fd)
    parent,name,_=_parent(credential_dir,account.pw_uid)
    try: os.rmdir(name,dir_fd=parent)
    finally: os.close(parent)
    return {"account":FIXTURE_ACCOUNT,"correlation":receipt["correlation"],"restored":True}
