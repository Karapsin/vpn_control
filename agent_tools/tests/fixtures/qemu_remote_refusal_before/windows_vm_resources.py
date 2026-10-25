"""Finite Linux/KVM resource producer for argument-driven Windows deployment."""
import ast
from . import native_host_observation as host
from . import ssh_tmux_resource_admission as admission

def _main():
    try:
        if os.geteuid()!=0:raise ValueError('resource_privilege')
        boot,vms=census();first,physical,swap=memory();time.sleep(.1)
        last,physical2,swap2=memory();boot2,vms2=census()
        if first is None or last is None or physical!=physical2 or boot!=boot2 or vms!=vms2:raise ValueError('resource_changed')
        uid=os.environ.get('SUDO_UID','')
        if re.fullmatch('[0-9]{1,10}',uid)is None or not 0<=int(uid)<2**32:raise ValueError('resource_principal')
        parent=os.path.dirname(SPEC['root']);fds=[]
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);fds.append(fd)
            for part in parent.split('/')[1:]:
                fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);fds.append(fd)
            info=os.fstat(fd)
            if info.st_uid!=int(uid) or info.st_mode&0o022:
                if not (info.st_uid==0 and info.st_mode&stat_module.S_ISVTX):raise ValueError('resource_parent')
            disk=os.fstatvfs(fd)
            if (info.st_dev,info.st_ino)!=(os.lstat(parent).st_dev,os.lstat(parent).st_ino):raise ValueError('resource_parent_changed')
        finally:
            for fd in reversed(fds):os.close(fd)
        value={'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':MODE,'state':'resources-observed','reason':None,
               'hostBootId':boot,'vms':vms,'physicalMemoryBytes':physical,'swapUsedBytes':swap2,'samples':[first,last],
               'freeDiskBytes':disk.f_bavail*disk.f_frsize,'inventoryComplete':True,'nativeActionAllowed':False,'replayAllowed':False}
    except (OSError,ValueError,TypeError,IndexError,KeyError):
        value={'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':MODE,'state':'blocked','reason':'resource_observation_unknown','nativeActionAllowed':False,'replayAllowed':False}
    print(json.dumps(value,separators=(',',':')))

def definitions():
    def selected(source,names):
        tree=ast.parse(source)
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
        if {n.name for n in nodes}!=set(names):raise ValueError('resource_definition_changed')
        return '\n'.join(ast.get_source_segment(source,n) for n in nodes)
    return 'import os,json,re,hashlib,time,stat as stat_module\n'+selected(host._REMOTE_PROGRAM,('memory','parse_memory','stat','kernel_thread','terminal_zombie'))+'\n'+selected(admission._REMOTE,('proc_visible','census'))+'\n'


def measurement(value):
    """Validate observed facts; the reservation planner separately admits capacity."""
    import re,uuid
    keys={'schemaVersion','deploymentId','mode','state','reason','hostBootId','vms','physicalMemoryBytes','swapUsedBytes','samples','freeDiskBytes','inventoryComplete','nativeActionAllowed','replayAllowed'}
    if type(value)is not dict or set(value)!=keys or value['inventoryComplete']is not True or value['reason']is not None:raise ValueError('resource_response')
    if type(value['hostBootId'])is not str or str(uuid.UUID(value['hostBootId']))!=value['hostBootId']:raise ValueError('resource_boot')
    if any(type(value[k])is not int or value[k]<0 for k in ('physicalMemoryBytes','swapUsedBytes','freeDiskBytes')) or value['physicalMemoryBytes']<=0:raise ValueError('resource_sizes')
    rows=value['vms'];pids=set()
    if type(rows)is not list or len(rows)>128:raise ValueError('resource_process_capacity')
    for row in rows:
        if type(row)is not dict or set(row)!={'pid','startTicks','sessionId','uid','commandSha256','executableGeneration','configuredMemoryBytes'}:raise ValueError('resource_process_fields')
        if any(type(row[k])is not int or row[k]<=0 for k in ('pid','startTicks','sessionId','configuredMemoryBytes')) or row['pid']in pids:raise ValueError('resource_process_identity')
        if type(row['uid'])is not int or not 0<=row['uid']<2**32 or type(row['commandSha256'])is not str or re.fullmatch('[0-9a-f]{64}',row['commandSha256'])is None:raise ValueError('resource_process_identity')
        generation=row['executableGeneration']
        if type(generation)is not list or len(generation)!=9 or any(type(x)is not int or x<0 for x in generation):raise ValueError('resource_executable_identity')
        pids.add(row['pid'])
    samples=value['samples']
    if type(samples)is not list or len(samples)!=2:raise ValueError('resource_samples')
    for sample in samples:
        if type(sample)is not dict or set(sample)!={'observedAtUnixMs','availableMemoryBytes','psi','psiSomeAvg10','psiFullAvg10','vmstat'}:raise ValueError('resource_sample_fields')
        if any(type(sample[k])is not int or sample[k]<0 for k in ('observedAtUnixMs','availableMemoryBytes')):raise ValueError('resource_sample_sizes')
        import math
        if any(type(sample[k])not in (int,float) or not math.isfinite(sample[k]) or sample[k]<0 for k in ('psiSomeAvg10','psiFullAvg10')):raise ValueError('resource_pressure')
        expected='normal' if sample['psiFullAvg10']==0 and sample['psiSomeAvg10']<=1 else 'warning'
        if sample['psi']!=expected or type(sample['vmstat'])is not dict or set(sample['vmstat'])!={'pswpin','pswpout','oomKill'} or any(type(x)is not int or x<0 for x in sample['vmstat'].values()):raise ValueError('resource_pressure')
    return {'platform':'linux','physicalMemoryBytes':value['physicalMemoryBytes'],'runningConfiguredMemoryBytes':sum(r['configuredMemoryBytes'] for r in rows),'availableMemoryBytes':samples[-1]['availableMemoryBytes'],'swapUsedBytes':value['swapUsedBytes'],'pressure':samples[-1]['psi'],'samples':samples}


def mcp_measurement(value,deployment_id):
    """Validate the explicit MCP envelope before reading its strict native DTO.

    UI guidance is separate metadata. This conversion grants no host action or
    freshness claim; admission still needs current source-bound observations.
    """
    import uuid
    if type(deployment_id)is not str or str(uuid.UUID(deployment_id))!=deployment_id:raise ValueError('resource_deployment')
    envelope={'tool','ok','productAction','evidenceClass'}
    if (type(value)is not dict or not envelope.issubset(value) or value['tool']!='vm_workflow' or value['ok']is not True
            or value['productAction']is not False or value['evidenceClass']!='read-only-deployment-resources'
            or type(value.get('schemaVersion'))is not int or value['schemaVersion']!=1 or value.get('deploymentId')!=deployment_id
            or value.get('mode')!='host-resources' or value.get('state')!='resources-observed'
            or value.get('nativeActionAllowed')is not False or value.get('replayAllowed')is not False):raise ValueError('resource_mcp_envelope')
    return measurement({key:item for key,item in value.items() if key not in envelope|{'nextAction'}})
