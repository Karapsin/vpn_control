"""Read-only proof for transient kernel workers and the inert init console.

Unmanaged user shells are never a process-name exemption. The sole console
exception requires the fixed init service, controlling terminal, public argv,
zero CPU, and a one-byte blocking read from that same console.
"""
import re
from . import readiness_providers as providers


def _need(value):
    if not value:
        raise providers.ProviderError('android_idle_work_active')


def _status(raw, pid, uid):
    values={}
    for line in raw.splitlines():
        key,sep,value=line.partition(':')
        if key in {'Pid','PPid','Uid','Kthread','State'}:
            _need(sep and key not in values);values[key]=value.strip()
    _need(set(values)=={'Pid','PPid','Uid','Kthread','State'} and values['Pid']==str(pid)
          and values['Uid'].split()==[str(uid)]*4 and values['Kthread'] in {'0','1'})
    return values


def _console_stat(raw,pid):
    prefix,sep,tail=raw.rpartition(') ')
    _need(sep and prefix==str(pid)+' (sh')
    fields=tail.split();_need(len(fields)>=20)
    _need(fields[0]=='S' and fields[1]=='1' and all(fields[i]==str(pid) for i in (2,3,5))
          and fields[4].isdigit() and int(fields[4])>0 and fields[11]==fields[12]=='0'
          and fields[19].isdigit() and int(fields[19])>0)
    return tuple(fields[i] for i in (0,1,2,3,4,5,11,12,19))


def idle_names(raw,baseline,command,deadline):
    """Return names with only independently proven idle system roles removed."""
    names=raw.strip().splitlines()
    _need(names and names[0].strip()=='NAME')
    unknown=set(line.strip() for line in names[1:])-set(baseline)-{'ps'}
    if not unknown:return raw
    _need(all(name=='sh' or name.startswith('[') and name.endswith(']') for name in unknown))
    def get(args):return command(args,deadline)[0].replace('\r','')
    snapshot=get(['shell','ps','-A','-o','PID,UID,S,NAME']).strip().splitlines()
    _need(snapshot and snapshot[0].split()==['PID','UID','S','NAME'] and len(snapshot)<=4096)
    result=['NAME'];seen=set();consoles=0
    for line in snapshot[1:]:
        row=line.split(None,3)
        _need(len(row)==4 and row[0].isdigit() and row[1].isdigit() and len(row[2])==1)
        pid,uid=int(row[0]),int(row[1]);name=row[3]
        _need(pid>0 and pid not in seen);seen.add(pid)
        if name in baseline or name=='ps':result.append(name);continue
        _need(name=='sh' or uid==0 and name.startswith('[') and name.endswith(']'))
        status=_status(get(['shell','cat','/proc/'+str(pid)+'/status']),pid,uid)
        if name!='sh':
            _need(uid==0 and status['Kthread']=='1');continue
        consoles+=1
        _need(consoles==1 and uid==2000 and status['Kthread']=='0' and status['PPid']=='1')
        before=_console_stat(get(['shell','cat','/proc/'+str(pid)+'/stat']),pid)
        _need(get(['shell','getprop','init.svc.console']).strip()=='running')
        init=get(['shell','cat','/system/etc/init/hw/init.rc'])
        blocks=re.findall(r'(?m)^service console [^\n]*(?:\n[ \t]+[^\n]*)*',init)
        expected=('service console /system/bin/sh','class core','console','disabled','user shell',
                  'group shell log readproc','seclabel u:r:shell:s0','setenv HOSTNAME console','shutdown critical')
        _need(len(blocks)==1 and tuple(line.strip() for line in blocks[0].splitlines())==expected)
        _need(get(['shell','readlink','/proc/'+str(pid)+'/exe']).strip()=='/system/bin/sh')
        _need(get(['shell','cat','/proc/'+str(pid)+'/cmdline']) in ('/system/bin/sh\0','sh\0'))
        for fd in ('0','1','2'):
            _need(get(['shell','readlink','/proc/'+str(pid)+'/fd/'+fd]).strip()=='/dev/console')
        architecture=get(['shell','uname','-m']).strip()
        read_call={'aarch64':63,'x86_64':0,'armv7l':3}.get(architecture)
        syscall=get(['shell','cat','/proc/'+str(pid)+'/syscall']).split()
        try:
            valid=(read_call is not None and len(syscall)==9 and syscall[0]==str(read_call)
                   and int(syscall[1],0)==0 and int(syscall[3],0)==1)
        except (ValueError,TypeError):
            valid=False
        _need(valid)
        _need(_console_stat(get(['shell','cat','/proc/'+str(pid)+'/stat']),pid)==before)
    return '\n'.join(result)+'\n'
