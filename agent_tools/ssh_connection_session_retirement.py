"""Retire only positively dead, previously completed local SSH master history.

No signals, SSH check, guest command, or configuration write is available. The
original journal lock coordinates session owners; rename excludes overwrite,
but does not claim an atomic CAS against unrelated external filesystem writers.
"""
from __future__ import annotations

import ctypes
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

from . import ssh_connection_session as session
from .private_inventory_lock import Directory

_ORIGINAL_SOURCE = 'dba4466d09aff57787cb008edcd044bc1cb4c3a22f4325c6a41efebe230a0720'
_FILES = {'intent.json','child.json','anchor.json','ready.json','launch.json','startup.json','launch.stderr.private','lock'}
_HASH = re.compile(r'[0-9a-f]{64}')


def _unknown(host):
    return {'state':'unknown','host':host,'replayAllowed':False}


def _paths(root,host,receipt):
    if not isinstance(host,str) or not session.transport._ALIAS_RE.fullmatch(host) or not isinstance(receipt,str) or not _HASH.fullmatch(receipt):
        raise ValueError('invalid retirement binding')
    root=Path(root).resolve(strict=True)
    group=root/session._DIR
    leaf=session._sha((str(root)+'\0'+host).encode())[:24]
    prefix=leaf+'.retire-dead-'+receipt
    return root,group,group/leaf,group/(leaf+'-retired-dead-'+receipt),group/(prefix+'.intent.json'),group/(prefix+'.terminal.json')


def _stderr(journal,guard):
    name='launch.stderr.private';guard.check()
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=guard.journal_fd)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1
                or stat.S_IMODE(info.st_mode)!=0o600 or not 0<=info.st_size<=4096):raise ValueError('unsafe diagnostic')
        fp=session._fp(info);raw=os.read(fd,4097)
        if len(raw)!=info.st_size or session._fp(os.fstat(fd))!=fp or session._fp(os.stat(name,dir_fd=guard.journal_fd,follow_symlinks=False))!=fp:
            raise ValueError('diagnostic changed')
        guard.check()
        return {'bytes':len(raw),'pin':{'sha256':session._sha(raw),'fingerprint':fp}}
    finally:os.close(fd)


def _history(journal,guard):
    guard.check()
    if set(os.listdir(guard.journal_fd))!=_FILES:raise ValueError('unsupported journal history')
    value={}
    for name in sorted(_FILES-{'launch.stderr.private','lock'}):
        content,pin=guard.read(journal/name);value[name]={'value':content,'pin':pin}
    value['launch.stderr.private']=_stderr(journal,guard)
    guard.check()
    return value


def _validate(history,receipt):
    intent=history['intent.json']['value'];child=history['child.json']['value'];ready=history['ready.json']['value']
    if set(intent)!={'version','authority','socketPath','parentIdentity'} or type(intent['version'])is not int or intent['version']!=1:raise ValueError('intent format')
    if session._sha(session._json(history['ready.json']['pin']))!=receipt:raise ValueError('ready receipt changed')
    if set(child)!={'intentSha256','pid'} or type(child['pid'])is not int or not 0<child['pid']<=2147483647 or child['intentSha256']!=session._sha(session._json(intent)):raise ValueError('child binding')
    if history['anchor.json']['value']!={'intentPin':history['intent.json']['pin'],'childPin':history['child.json']['pin'],'parentIdentity':intent['parentIdentity']}:raise ValueError('anchor binding')
    expected={'version','intentSha256','childPin','intentPin','anchorPin','socketFingerprint','master','authoritySha256'}
    if (set(ready)!=expected or type(ready['version'])is not int or ready['version']!=1 or ready['intentSha256']!=child['intentSha256']
            or ready['childPin']!=history['child.json']['pin'] or ready['intentPin']!=history['intent.json']['pin']
            or ready['anchorPin']!=history['anchor.json']['pin'] or ready['authoritySha256']!=session._sha(session._json(intent['authority']))):raise ValueError('ready history binding')
    master=ready['master']
    if not isinstance(master,dict) or set(master)!={'pid','generationSha256'} or type(master['pid'])is not int or master['pid']!=child['pid'] or not isinstance(master['generationSha256'],str) or not _HASH.fullmatch(master['generationSha256']):raise ValueError('master identity')
    fp=ready['socketFingerprint']
    if not isinstance(fp,list) or len(fp)!=8 or any(type(x)is not int for x in fp) or not stat.S_ISSOCK(fp[2]) or fp[3]!=os.getuid() or fp[4]!=1 or fp[2]&0o077:raise ValueError('original socket proof')
    path=Path(intent['socketPath'])
    if not path.is_absolute() or path.name!='m' or len(os.fsencode(path))>=90 or path.parent.parent!=Path(tempfile.gettempdir()).resolve():raise ValueError('socket provenance')
    startup=history['startup.json']['value'];diagnostic=history['launch.stderr.private']
    if (set(startup)!={'version','exitCode','elapsedMs','stderrBytes','stderrSha256','stderrFingerprint'} or type(startup['version'])is not int or startup['version']!=1
            or type(startup['elapsedMs'])is not int or startup['elapsedMs']<0
            or startup['exitCode'] is not None and type(startup['exitCode'])is not int
            or not isinstance(startup['stderrSha256'],str) or not _HASH.fullmatch(startup['stderrSha256'])
            or type(startup['stderrBytes'])is not int or not 0<=startup['stderrBytes']<=4096
            or not isinstance(startup['stderrFingerprint'],list) or len(startup['stderrFingerprint'])!=8
            or startup['stderrFingerprint'][:5]!=diagnostic['pin']['fingerprint'][:5]):raise ValueError('diagnostic provenance')
    return intent,child['pid'],path


def _absent(pid,path,parent_identity):
    if session._directory(path.parent)!=parent_identity:raise ValueError('socket parent changed')
    if os.path.lexists(path):raise ValueError('socket is present')
    result=subprocess.run(['/bin/ps','-p',str(pid),'-o','pid='],stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=3,check=False)
    # No /proc assumption; live/reused PID, permissions/errors and ambiguous
    # output never constitute positive death, regardless of old PID identity.
    if result.returncode!=1 or result.stdout!=b'' or result.stderr!=b'':raise ValueError('PID absence unproven')
    if session._directory(path.parent)!=parent_identity or os.path.lexists(path):raise ValueError('socket absence changed')
    return {'pid':pid,'pidAbsent':True,'socketAbsent':True,'observer':'ps-p-exit1-empty'}


def _rename_no_replace(parent_fd,source,destination):
    libc=ctypes.CDLL(None,use_errno=True)
    if sys.platform=='darwin':
        function=libc.renameatx_np;flags=4  # Darwin SDK RENAME_EXCL.
    elif sys.platform.startswith('linux'):
        function=libc.renameat2;flags=1  # Linux RENAME_NOREPLACE.
    else:raise ValueError('exclusive rename unsupported')
    function.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
    function.restype=ctypes.c_int
    if function(parent_fd,os.fsencode(source),parent_fd,os.fsencode(destination),flags)!=0:
        raise OSError(ctypes.get_errno(),'exclusive archive rename failed')


def _helper_pin():
    raw,fp=session._bytes(Path(__file__),False)
    return {'sha256':session._sha(raw),'fingerprint':fp}


def _group_read(directory,path):
    directory.guard();value=session._read(path,directory.fd);directory.guard();return value


def _group_create(directory,path,value):
    directory.guard();session._create(path,value,directory.fd);directory.guard()
    stored,pin=_group_read(directory,path)
    if stored!=value or pin['sha256']!=session._sha(session._json(value)):
        raise ValueError('created retirement bytes changed')
    return stored,pin


def _status(root,host,receipt,group,archive,intent_path,terminal_path):
    with Directory(group) as directory:
        intent,intent_pin=_group_read(directory,intent_path)
        if (intent.get('version')!=1 or intent.get('root')!=str(root) or intent.get('host')!=host
                or intent.get('receiptSha256')!=receipt or intent.get('archive')!=archive.name):raise ValueError('retirement intent binding')
        if not os.path.lexists(terminal_path):return _unknown(host)
        terminal,_=_group_read(directory,terminal_path)
        if terminal!={'version':1,'state':'retired','retirementIntentPin':intent_pin,'archive':archive.name,'historySha256':session._sha(session._json(intent['history']))}:raise ValueError('terminal binding')
        # Historical status never probes a new PID or authorizes another rename.
        if session._fp(os.lstat(archive/'lock'))!=intent['sessionLockFingerprint']:
            raise ValueError('archived lock generation changed')
        guard=session._JournalGuard(root,archive)
        try:
            if session._directory(archive)!=intent['journalIdentity'] or _history(archive,guard)!=intent['history']:raise ValueError('archive history changed')
            _validate(intent['history'],receipt);directory.guard();guard.check()
        finally:guard.close()
        return {'state':'retired','host':host,'receiptSha256':receipt,'replayAllowed':False}


def status(root,host,receipt_sha256):
    try:
        root,group,_,archive,intent_path,terminal_path=_paths(root,host,receipt_sha256)
        return _status(root,host,receipt_sha256,group,archive,intent_path,terminal_path)
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError):return _unknown(host)


def retire(root,host,receipt_sha256):
    """Archive one exact completed, positively dead session; consumed is status-only."""
    try:
        root,group,journal,archive,intent_path,terminal_path=_paths(root,host,receipt_sha256)
        if os.path.lexists(intent_path):return _status(root,host,receipt_sha256,group,archive,intent_path,terminal_path)
        if os.path.lexists(terminal_path) or os.path.lexists(archive):return _unknown(host)
        if session._source()!=_ORIGINAL_SOURCE:raise ValueError('original helper changed')
        session._journal(root,host,False)
        info=os.lstat(journal/'lock')
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600:raise ValueError('unsafe session lock')
        fd=os.open(journal/'lock',os.O_RDONLY|os.O_NOFOLLOW);guard=None
        try:
            if session._fp(os.fstat(fd))!=session._fp(info):raise ValueError('session lock changed')
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            guard=session._JournalGuard(root,journal,fd,session._fp(info))
            with Directory(group) as directory:
                history=_history(journal,guard);intent,pid,path=_validate(history,receipt_sha256)
                config,outer,authority=guard.snapshot(root,host)
                if authority!=intent['authority']:raise ValueError('source authority changed')
                if history['launch.json']['value']!={'version':1,'argvSha256':session._sha(session._json(session._launch_argv(config,outer,path))),'diagnosticLimit':4096}:raise ValueError('launch provenance')
                guard.fence=(journal/'intent.json',intent,history['intent.json']['pin'])
                guard.authority=(root,host,authority);guard.socket_parent=(path,intent['parentIdentity']);guard.require_socket_absent=True
                helper=_helper_pin();journal_identity=session._directory(journal)
                observation=_absent(pid,path,intent['parentIdentity'])
                guard.check()
                if _history(journal,guard)!=history:raise ValueError('history changed')
                if os.path.lexists(intent_path) or os.path.lexists(terminal_path) or os.path.lexists(archive):raise ValueError('retirement already reserved')
                value={'version':1,'state':'pending','root':str(root),'host':host,'receiptSha256':receipt_sha256,
                       'archive':archive.name,'journalIdentity':journal_identity,'history':history,'helperPin':helper,
                       'sessionLockFingerprint':session._fp(info),'absence':observation}
                created=_group_create(directory,intent_path,value)
                stored,retirement_pin=_group_read(directory,intent_path)
                if stored!=value or (stored,retirement_pin)!=created:raise ValueError('retirement intent changed')
                _absent(pid,path,intent['parentIdentity'])
                if _history(journal,guard)!=history or _helper_pin()!=helper:raise ValueError('history or helper changed')
                if _group_read(directory,intent_path)!=(value,retirement_pin):raise ValueError('consumed retirement changed')
                if os.path.lexists(terminal_path) or os.path.lexists(archive):raise ValueError('archive collision')
                directory.guard();guard.check()
                _rename_no_replace(directory.fd,journal.name,archive.name)
                os.fsync(directory.fd)
                guard.close();guard=session._JournalGuard(root,archive,fd,session._fp(info))
                guard.authority=(root,host,authority);guard.socket_parent=(path,intent['parentIdentity']);guard.require_socket_absent=True
                if session._directory(archive)!=journal_identity or _history(archive,guard)!=history:raise ValueError('archived history changed')
                _absent(pid,path,intent['parentIdentity']);guard.check()
                if _group_read(directory,intent_path)!=(value,retirement_pin):raise ValueError('retirement intent changed after rename')
                terminal={'version':1,'state':'retired','retirementIntentPin':retirement_pin,'archive':archive.name,'historySha256':session._sha(session._json(history))}
                terminal_created=_group_create(directory,terminal_path,terminal)
                if _group_read(directory,terminal_path)!=terminal_created:raise ValueError('terminal changed')
                guard.check();directory.guard()
                return {'state':'retired','host':host,'receiptSha256':receipt_sha256,'replayAllowed':False}
        finally:
            if guard is not None:guard.close()
            os.close(fd)
    except (OSError,ValueError,TypeError,KeyError,AttributeError,subprocess.SubprocessError):return _unknown(host)
