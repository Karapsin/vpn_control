"""Fixed ordinary GET diagnosis of protected Mac service-source shapes.

No privilege installation, lifecycle, input, command runner or idle admission.
Source labels/paths/argv/account names and native errors stay private memory.
The independent volume result is retained even when Catalog construction fails.
"""
from __future__ import annotations

import ctypes as C
import os
from pathlib import Path
import plistlib
import stat
import sys
from uuid import UUID
if os.name == 'posix':
    import pwd
else:
    pwd = None

_EXECUTING_CODE = sys._getframe().f_code
_FILES = ('tart_macos_probe.py','tart_macos_service_census.py','tart_macos_catalog_diagnostics.py')
_REASONS = frozenset({'macos_root_volume_unavailable','macos_root_policy_unavailable',
    'macos_system_source_volume_unqualified','macos_service_source_directory_unqualified',
    'macos_service_source_overflow','macos_service_source_unqualified','macos_service_source_changed',
    'macos_service_source_invalid','macos_service_source_account_unavailable'})
_SHAPES = ('protected_read_unavailable','plist_invalid','dictionary_invalid','label_invalid',
    'duplicate_label_same_domain','duplicate_label_cross_domain','arguments_missing',
    'arguments_empty','arguments_invalid','program_missing','program_invalid',
    'program_inferred','bundle_program_present','source_account_unavailable')


class CatalogDiagnosticUnavailable(ValueError):pass


def need(value):
    if not value:raise CatalogDiagnosticUnavailable('macos_catalog_diagnostic_unavailable')


def _reason(error, service):
    if (type(error) is service.ServiceUnavailable and len(error.args)==1
            and type(error.args[0]) is str and error.args[0] in _REASONS):return error.args[0]
    return 'native_or_source_unavailable'


def shape(value, origin, labels, counts):
    """Only fixed schema counts escape; no content fingerprints or values."""
    need(origin in {'system_daemon','system_agent'})
    if type(value) is not dict:
        counts['dictionary_invalid']+=1;return
    label=value.get('Label')
    if type(label) is not str or not label:counts['label_invalid']+=1
    else:
        if (origin,label) in labels:counts['duplicate_label_same_domain']+=1
        other='system_agent' if origin=='system_daemon' else 'system_daemon'
        if (other,label) in labels:counts['duplicate_label_cross_domain']+=1
        labels.add((origin,label))
    arguments=value.get('ProgramArguments');program=value.get('Program')
    if 'BundleProgram' in value:counts['bundle_program_present']+=1
    if arguments is None:
        counts['arguments_missing']+=1
        if program is None:counts['program_missing']+=1
    elif type(arguments) is not list or any(type(item) is not str for item in arguments):
        counts['arguments_invalid']+=1
    elif not arguments:counts['arguments_empty']+=1
    elif program is None:
        program=arguments[0];counts['program_inferred']+=1
    if program is not None and (type(program) is not str or not program.startswith('/')):
        counts['program_invalid']+=1
    username=value.get('UserName')
    if username is not None:
        try:
            if type(username) is not str or pwd is None:raise KeyError()
            pwd.getpwnam(username)
        except (KeyError,TypeError):counts['source_account_unavailable']+=1


def scan(volume, service):
    need(type(volume) is service.Volume and volume.source_eligible)
    reader=service.Catalog.__new__(service.Catalog);reader.volume=volume
    counts={name:0 for name in _SHAPES};labels=set();total=0;stable=True
    for name,origin in service.Catalog._DIRECTORIES:
        directory=Path(name);before=directory.lstat()
        need(stat.S_ISDIR(before.st_mode) and before.st_uid==0 and not before.st_mode&0o022
             and before.st_dev==volume.device)
        files=list(directory.iterdir());need(len(files)<=service.MAX_SERVICES)
        for path in files:
            if path.suffix!='.plist':continue
            total+=1
            try:raw,_=reader._read(path)
            except Exception:
                counts['protected_read_unavailable']+=1;continue
            try:value=plistlib.loads(raw)
            except Exception:
                counts['plist_invalid']+=1;continue
            shape(value,origin,labels,counts)
        stable=service.generation(directory.lstat())==service.generation(before) and stable
    return {'state':'observed','directorySnapshotStable':stable,'sourceFileCount':total,'shapeCounts':counts}


def inspect(native, service, uid):
    """Independent stages: catalog failure never erases real volume evidence."""
    volume=None
    try:
        volume=native.volume();need(type(volume) is service.Volume)
        volume_fact={'state':'observed',**volume.public()}
    except Exception as error:
        volume=None;volume_fact={'state':'unavailable','reason':_reason(error,service)}
    catalog_fact={'state':'not_attempted','reason':'volume_unavailable'}
    shapes={'state':'not_attempted','reason':'source_volume_unqualified'}
    if volume is not None:
        try:
            catalog=service.Catalog(volume,uid)
            catalog_fact={'state':'observed','sourceCount':len(catalog.sources),'stable':catalog.stable()}
        except Exception as error:catalog_fact={'state':'unavailable','reason':_reason(error,service)}
        if volume.source_eligible:
            try:shapes=scan(volume,service)
            except Exception:shapes={'state':'unavailable','reason':'protected_source_scan_unavailable'}
    return {'volume':volume_fact,'catalog':catalog_fact,'sourceShapes':shapes}


def _inputs(machine,boot,uid,principal,agent):
    try:valid=type(machine) is str and str(UUID(machine))==machine and type(boot) is str and str(UUID(boot))==boot
    except (ValueError,TypeError,AttributeError):valid=False
    need(valid and type(uid) is int and uid>=501 and type(principal) is str and principal
         and type(agent) is tuple and len(agent)==5 and all(type(item) is int for item in agent)
         and agent[0]>0 and agent[1]==uid and agent[2]==1 and agent[3]>0 and 0<=agent[4]<1000000)


def collect(base,native,service,bsd,*,machine,boot,uid,principal,agent):
    _inputs(machine,boot,uid,principal,agent)
    def target():
        need(pwd is not None and os.geteuid()==uid and pwd.getpwuid(uid).pw_name==principal
             and base.machine()==machine and base.boot()[0]==boot and os.getppid()==agent[0])
        row=bsd()
        need(base.proc.proc_pidinfo(agent[0],3,0,C.byref(row),C.sizeof(row))==C.sizeof(row)
             and (row.pid,row.uid,row.ppid,row.start_seconds,row.start_microseconds)==agent)
    target();result=inspect(native,service,uid);target()
    return {'schemaVersion':1,'state':'diagnostic','machine':machine,'boot':boot,'uid':uid,
            'nativeQualified':False,'idleAuthority':False,**result}


def source(*,machine,boot,uid,principal,agent):
    _inputs(machine,boot,uid,principal,agent)
    need(os.name=='posix' and hasattr(os,'O_NOFOLLOW'));captured={}
    for name in _FILES:
        path=Path(__file__).with_name(name);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<before.st_size<=262144)
            raw=os.read(fd,before.st_size+1);after=os.fstat(fd)
            fields=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
            need(len(raw)==before.st_size and all(getattr(before,key)==getattr(after,key) for key in fields));captured[name]=raw
        finally:os.close(fd)
    need(_EXECUTING_CODE==compile(captured[_FILES[-1]],__file__,'exec',dont_inherit=True))
    config=dict(machine=machine,boot=boot,uid=uid,principal=principal,agent=agent)
    text='import json,sys,types\n_modules=[]\n'
    for name in _FILES:
        text+='_m=types.ModuleType('+repr('_fixed_catalog_'+name[:-3])+');sys.modules[_m.__name__]=_m\n'
        text+='exec(compile('+repr(captured[name])+','+repr('<fixed-'+name+'>')+',"exec"),_m.__dict__)\n_modules.append(_m)\n'
    text+=('try:\n _modules[2].need(sys.platform=="darwin" and len(sys.argv)==1)\n'
        ' import signal;signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(60)\n'
        ' _base=_modules[0].Native();_native=_modules[1].NativeServices(_base,None)\n'
        ' _result=_modules[2].collect(_base,_native,_modules[1],_modules[0]._Bsd,**'+repr(config)+')\n'
        'except Exception:\n _result={"state":"blocked","reason":"macos_catalog_diagnostic_unavailable"}\n'
        'print(json.dumps(_result,sort_keys=True))\nraise SystemExit(0 if _result.get("state")=="diagnostic" else 3)\n')
    need(len(text)<=262144);return text.encode('utf-8')
