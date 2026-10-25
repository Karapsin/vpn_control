"""Inert versioned zero-argument Mac root collector installer input.

No public tool imports this file. Installation/source and native qualification
remain mandatory. User-domain dictionaries cross only root-owned private pipes;
the final report contains finite roles and kernel identities, never argv/env or
unexpected paths, labels, digests, lengths, or exception text.
"""
from __future__ import annotations
import ctypes as C
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import stat
import subprocess
import sys
from uuid import UUID

_EXECUTING_CODE=sys._getframe().f_code
_FILES=('tart_macos_probe.py','tart_macos_idle_collector.py','tart_macos_service_census.py',
        'tart_macos_network_census.py','tart_macos_idle_helper.py')


class HelperUnavailable(ValueError):pass


def need(value,reason='macos_idle_helper_unavailable'):
    if not value:raise HelperUnavailable(reason)


def generation(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_uid,info.st_gid,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def config(value):
    need(type(value)is dict and set(value)=={'machine','qualificationOriginBoot','ordinaryUid','ordinaryPrincipal','python','pythonSha256','agentSha256','agentPlistSha256','helper'})
    need(type(value['machine'])is str and str(UUID(value['machine']))==value['machine']
         and type(value['qualificationOriginBoot'])is str and str(UUID(value['qualificationOriginBoot']))==value['qualificationOriginBoot']
         and type(value['ordinaryUid'])is int and value['ordinaryUid']>=501
         and type(value['ordinaryPrincipal'])is str and value['ordinaryPrincipal']
         and type(value['pythonSha256'])is str and re.fullmatch(r'[0-9a-f]{64}',value['pythonSha256'])
         and all(type(value[key])is str and re.fullmatch(r'[0-9a-f]{64}',value[key])for key in ('agentSha256','agentPlistSha256'))
         and type(value['python'])is str and re.fullmatch(r'/usr/local/libexec/vpn-tool-recovery-cont-[0-9a-f]+/python/bin/python3\.12',value['python'])
         and type(value['helper'])is str and re.fullmatch(r'/usr/local/libexec/vpn-tool-recovery-idle-[0-9a-f-]{36}/main\.py',value['helper']))
    return value


def caller_source(value):
    value=config(value)
    return ('import subprocess,sys\n'
        'if len(sys.argv)!=1:raise SystemExit(3)\n'
        'try:\n r=subprocess.run(["/usr/bin/sudo","-n",'+repr(value['helper'])+'],stdin=subprocess.DEVNULL,'
        'stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=60)\n'
        'except Exception:raise SystemExit(3) from None\n'
        'if r.returncode or not 0<len(r.stdout)<=2097152:raise SystemExit(3)\n'
        'sys.stdout.buffer.write(r.stdout)\n').encode()


def ordinary_source(value):
    value=config(value)
    return ('import runpy;runpy.run_path('+repr(str(PurePosixPath(value['helper']).with_name('caller.py')))+',run_name="__main__")\n').encode()


def _ordinary_arguments(value):
    raw=ordinary_source({key:item for key,item in value.items()if key not in {'invocationBoot'}})
    gate=("import hashlib,sys;raw=sys.stdin.buffer.read(262145);"
          "assert len(raw)=="+str(len(raw))+" and hashlib.sha256(raw).hexdigest()=="+
          repr(hashlib.sha256(raw).hexdigest())+", 'guest_source_changed';"
          "exec(compile(raw,'<registered-guest-job>','exec'),{'__name__':'__main__'})")
    return (os.fsencode(value['python']),b'-I',b'-B',b'-c',gate.encode())


def protected_file(path,*,maximum,expected_sha=None):
    need(os.name=='posix'and hasattr(os,'O_NOFOLLOW'))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode)and before.st_uid==0 and not before.st_mode&0o022
             and 0<before.st_size<=maximum)
        data=os.read(fd,before.st_size+1)
        need(len(data)==before.st_size and generation(os.fstat(fd))==generation(before))
        if expected_sha is not None:need(hashlib.sha256(data).hexdigest()==expected_sha)
        return data,generation(before)
    finally:os.close(fd)


def protected_parents(path):
    for parent in reversed(Path(path).parents):
        info=parent.lstat()
        need(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and not info.st_mode&0o022)


def source_guard(value):
    """Actual immutable installed helper and qualified interpreter, not DTO flags."""
    need(str(Path(globals()['__outer_file__']))==value['helper'])
    path=Path(value['helper']);parent=path.parent
    need(parent.resolve(strict=True)==parent)
    protected_parents(path)
    before=parent.lstat()
    need(stat.S_ISDIR(before.st_mode)and before.st_uid==0 and not before.st_mode&0o022)
    raw,identity=protected_file(path,maximum=524288)
    need(identity[2]&0o555==0o555)
    need(globals()['__outer_code__']==compile(raw,str(path),'exec',dont_inherit=True))
    caller,_=protected_file(path.with_name('caller.py'),maximum=16384)
    need(caller==caller_source(value))
    original=Path(value['python']);protected_parents(original)
    info=original.lstat();need(info.st_uid==0 and (stat.S_ISREG(info.st_mode)or stat.S_ISLNK(info.st_mode)))
    executable=original.resolve(strict=True);protected_parents(executable)
    need(executable.is_relative_to(original.parent.parent.parent))
    protected_file(executable,maximum=64*1024*1024,expected_sha=value['pythonSha256'])
    need(generation(parent.lstat())==generation(before))
    return identity,executable


def _target(base,value):
    import pwd
    need(base.machine()==value['machine']and base.boot()[0]==value['invocationBoot']
         and pwd.getpwuid(value['ordinaryUid']).pw_name==value['ordinaryPrincipal'])


def child_domain(base,processes,native,value,executable):
    """Only the root collector's own dropped-UID child may emit private rows."""
    need(os.geteuid()>=501)
    for number in (0,1):
        info=os.fstat(number);need(stat.S_ISFIFO(info.st_mode)and info.st_uid==0)
    parent=processes.process(os.getppid());need(parent[1]==0)
    buffer=C.create_string_buffer(4096)
    need(0<base.proc.proc_pidpath(parent[0],buffer,len(buffer))<len(buffer)
         and os.fsdecode(buffer.value)==str(executable))
    _target(base,value)
    domain=native.domain('caller_user');need(domain.uid==os.geteuid())
    need(processes.process(parent[0])==parent);_target(base,value)
    return {'schemaVersion':1,'machine':value['machine'],'boot':value['invocationBoot'],'uid':domain.uid,'rows':domain.rows}


def user_domain(uid,value):
    """Fixed self executable only. No command, source, environment or path input."""
    need(os.geteuid()==0 and type(uid)is int and uid>=501)
    import pwd
    account=pwd.getpwuid(uid)
    argv=[value['python'],'-I','-B',value['helper']]
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        user=uid,group=account.pw_gid,extra_groups=[],close_fds=True,
        env={'PATH':'/usr/bin:/bin','LANG':'C','HOME':account.pw_dir})
    try:stdout,stderr=process.communicate(b'',timeout=20)
    except subprocess.TimeoutExpired:
        # Only this newly created synchronous diagnostic child is owned here.
        process.kill();process.communicate();raise HelperUnavailable('macos_user_domain_unavailable')from None
    need(process.returncode==0 and not stderr and 0<len(stdout)<=4*1024*1024,'macos_user_domain_unavailable')
    expected=value
    try:value=plistlib.loads(stdout)
    except (ValueError,TypeError):raise HelperUnavailable('macos_user_domain_unavailable')from None
    need(type(value)is dict and set(value)=={'schemaVersion','machine','boot','uid','rows'}and type(value['schemaVersion'])is int
         and value['schemaVersion']==1 and value['uid']==uid and value['machine']==expected['machine']
         and value['boot']==expected['invocationBoot'] and type(value['rows'])is list,'macos_user_domain_unavailable')
    return value['rows'] # Private memory only, not a receipt or final output.


def source_owned_chain(base,processes,native,domains,value,executable):
    """Exact public source and kernel actors of this one current observation."""
    actor=processes.process(os.getpid());sudo=processes.process(actor[2]);caller=processes.process(sudo[2]);agent=processes.process(caller[2])
    need(actor[1]==sudo[1]==0 and caller[1]==agent[1]==value['ordinaryUid']and agent[2]==1)
    need(len({row[0]for row in (actor,sudo,caller,agent)})==4)
    def exact(row,program,arguments):
        before=native.image(row);actual,argv=native.argv(row)
        need(actual==os.fsencode(str(program))and argv==arguments and any(before)and native.image(row)==before)
        return before
    exact(actor,executable,(os.fsencode(value['python']),b'-IB',os.fsencode(value['helper'])))
    exact(caller,executable,_ordinary_arguments(value))
    sudo_path=Path('/usr/bin/sudo');protected_parents(sudo_path)
    volume=native.volume();info=sudo_path.stat()
    need(volume.source_eligible and info.st_uid==0 and info.st_dev==volume.device and not info.st_mode&0o022)
    exact(sudo,sudo_path,(b'/usr/bin/sudo',b'-n',os.fsencode(value['helper'])))
    need(processes.code(sudo)=='apple_valid')
    prefix=Path(value['python']).parent.parent.parent;binary=prefix/'tart-guest-agent'
    protected_parents(binary);protected_file(binary,maximum=64*1024*1024,expected_sha=value['agentSha256'])
    exact(agent,binary,(os.fsencode(str(binary)),b'--run-rpc'))
    path=Path('/Library/LaunchDaemons/com.vpn-control.tool-recovery.agent.plist');protected_parents(path)
    raw,_=protected_file(path,maximum=65536,expected_sha=value['agentPlistSha256'])
    plist=plistlib.loads(raw)
    need(type(plist)is dict and plist.get('Label')=='com.vpn-control.tool-recovery.agent'
         and plist.get('UserName')==value['ordinaryPrincipal']
         and plist.get('ProgramArguments')==[str(binary),'--run-rpc'])
    rows=[row for domain in domains if domain.kind=='system'and domain.uid==0 for row in domain.rows
          if row.get('Label')==plist['Label']]
    need(len(rows)==1 and type(rows[0].get('PID'))is int and rows[0]['PID']==agent[0])
    if 'ProgramArguments'in rows[0]:need(rows[0]['ProgramArguments']==plist['ProgramArguments'])
    for row in (actor,sudo,caller,agent):need(processes.process(row[0])==row)
    return (sudo,caller,agent)


def collect(base,processes,native,service,network,value,executable):
    need(os.geteuid()==0);_target(base,value)
    protected_network=network.NativeNetwork(base);network_before=protected_network.snapshot();_target(base,value)
    first=processes.snapshot();images={pid:native.image(actor)for pid,(actor,_)in first.items()};observer=processes.process(os.getpid())
    need(observer[1]==0 and first.get(observer[0],(None,None))[0]==observer)
    domains=[native.domain('system')]
    users={actor[1]for actor,_ in first.values()if actor[1]>=501}
    need(value['ordinaryUid']in users and len(users)<=4)
    for uid in sorted(users):domains.append(service.Domain('caller_user',uid,user_domain(uid,value)))
    chain=source_owned_chain(base,processes,native,domains,value,executable)
    need(all(first.get(actor[0])==(actor,'unmanaged')for actor in chain))
    excluded={actor[0]for actor in chain}
    filtered={pid:row for pid,row in first.items()if pid not in excluded}
    observed=[service.Domain(domain.kind,domain.uid,[row for row in domain.rows if row.get('PID')not in excluded])for domain in domains]
    volume=native.volume();catalog=service.Catalog(volume,value['ordinaryUid'])
    report=service.review(filtered,observed,catalog,native,ordinary_uid=value['ordinaryUid'],observer=observer)
    second=processes.snapshot();_target(base,value)
    network_report=network.review(network_before,protected_network.snapshot());_target(base,value)
    stable=first==second
    if stable:stable=all(native.image(actor)==images[pid]for pid,(actor,_)in second.items())
    need(source_owned_chain(base,processes,native,[native.domain('system')],value,executable)==chain)
    return {'schemaVersion':1,'machine':value['machine'],'boot':value['invocationBoot'],'ordinaryUid':value['ordinaryUid'],
        'observerUid':0,'state':'diagnostic','nativeQualified':False,'idleAuthority':False,
        'processIdentityComplete':stable,'serviceEvidence':report,'networkEvidence':network_report,'volume':volume.public(),
        'sourceOwnedControlChain':[{'pid':row[0],'uid':row[1],'birth':f'darwin:{row[3]}:{row[4]}','role':role}
            for row,role in zip(chain,('current_sudo_bridge','current_ordinary_observer','qualified_guest_agent'))],
        'missingEvidence':['durable_namespaces','host_reservations_lifecycle_operators',
                           'known_service_purpose_and_activity_applicability','protected_network_provider_source_join']}


def main():
    private=os.geteuid()!=0
    try:
        need(sys.platform=='darwin'and len(sys.argv)==1)
        import signal
        signal.signal(signal.SIGALRM,signal.SIG_DFL);signal.alarm(15 if private else 45)
        stored=config(globals()['__configuration__']);identity,executable=source_guard(stored);value=stored
        modules=globals()['__modules__'];probe,census,service,network=modules
        base=probe.Native();value={**value,'invocationBoot':base.boot()[0]};_target(base,value)
        processes=census.Native(base);native=service.NativeServices(base,processes)
        if private:
            result=child_domain(base,processes,native,value,executable)
            need(source_guard(stored)==(identity,executable))
            output=plistlib.dumps(result,fmt=plistlib.FMT_BINARY)
            need(0<len(output)<=4*1024*1024);sys.stdout.buffer.write(output);return 0
        result=collect(base,processes,native,service,network,value,executable)
        need(source_guard(stored)==(identity,executable))
        output=json.dumps(result,sort_keys=True).encode();need(len(output)<=2*1024*1024)
        sys.stdout.buffer.write(output+b'\n');return 0
    except Exception:
        # Native data, unknown paths/argv and child errors are never rendered.
        if not private:sys.stdout.write('{"state":"blocked","reason":"macos_idle_helper_unavailable"}\n')
        return 3


def helper_source(value):
    """Pure installer input; caller must qualify/install under protected admin flow."""
    value=config(value)
    need(os.name=='posix'and hasattr(os,'O_NOFOLLOW'))
    captured={}
    for name in _FILES:
        path=Path(__file__).with_name(name);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=262144)
            raw=os.read(fd,before.st_size+1)
            need(len(raw)==before.st_size and generation(os.fstat(fd))==generation(before));captured[name]=raw
        finally:os.close(fd)
    need(_EXECUTING_CODE==compile(captured[_FILES[-1]],__file__,'exec',dont_inherit=True))
    text='#!'+value['python']+' -IB\nimport sys,types\n_outer_code=sys._getframe().f_code\n_modules=[]\n'
    for name in _FILES:
        text+='_m=types.ModuleType('+repr('_fixed_idle_'+name[:-3])+');sys.modules[_m.__name__]=_m\n'
        text+='exec(compile('+repr(captured[name])+','+repr('<fixed-'+name+'>')+',"exec"),_m.__dict__)\n'
        text+='_modules.append(_m)\n'
    text+='_modules[1].__dict__["__bsd_class__"]=_modules[0]._Bsd\n'
    text+='_modules[4].__dict__.update(__configuration__='+repr(value)+',__modules__=_modules[:4],__outer_file__=__file__,__outer_code__=_outer_code)\n'
    text+='raise SystemExit(_modules[4].main())\n'
    result=text.encode();need(len(result)<=524288);return result
