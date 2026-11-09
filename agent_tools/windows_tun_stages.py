"""Finite ordinary active-A/pending-B TUN stages on the Windows scenario route.

The product's original async job stays retained. This module cannot press UAC keys:
the closed windows-uac-decision action answers the vpn-broker prompt, and every input
here comes from the row's own job plan and context stage, never from a caller. The
decision it waits for is that action's one decision for this operation. A grant also
needs the TUN SYSTEM collector's ready and off records; the direct sampler runs only
between them. The closing census shows the row left no broker, scoped runtime, private
stage or TUN route behind. From the request until the operation settles (a denial, a
known end or a grant's exact off) a failure parks the owner; a final refusal of the
request itself, with nothing changed, is a known end.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import socket
import uuid

VARIANTS = frozenset({'restart-grant','restart-deny','find-best-grant','find-best-deny'})
FIELDS = frozenset({'schemaVersion','variant','pendingLocation','runtimeConfigPath','guiPath',
    'installedAdmissionArtifactId','ordinaryContextArtifactId','expectedApprovingAdminSid',
    'uacDecisionId','programData','collectorSourceSha256'})
SAMPLER_FIELDS = frozenset({'samplerPath','samplerInputPath'})  # A grant's direct sampler and its input
BROKER_LEAF = 'vpn-control-vpn-broker.exe'  # DesktopWindowsVpnHelperAdmission's packaged helper
STAGE_PREFIX = 'vpn-control-vpn-'  # The broker's private stage under ProgramData
TUN_SUBNET = ('172.19.250.0', 30)  # DesktopProxyConfigFactory's generated TUN address
# ControlCode's final refusals and their exits: the owner admitted no operation, or ended it before it replied.
# Its transport codes (exit 2) and an answer from no or another controller leave the request's outcome open.
REFUSED_EXITS = {**dict.fromkeys(('INVALID_ARGUMENT','NOT_FOUND','AMBIGUOUS_LOCATION','READ_ONLY_SOURCE','BUSY','CONFLICT',
    'UNSUPPORTED','INTERACTION_REQUIRED','PERMISSION_DENIED','PERSISTENCE_FAILED','RUNTIME_FAILED'),1),'CANCELLED':130}


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def decision_id(operation):
    """windows_uac_decision.decision_id: the one decision a scenario operation may have."""
    return str(uuid.uuid5(uuid.UUID(operation),'windows-uac-decision'))


def settled(lease):
    """The row's own operation is final and nothing of it can still run elevated: a denial, a known end, or a grant
    after its exact off. Until then any failure parks the owner; once settled, a failure closes as a known one."""
    return lease['finished'] is True and (lease['inputs']['variant'].endswith('deny') or 'knownEnd' in lease
                                          or lease.get('offFinished') is True)


def tun_routes(subnet=TUN_SUBNET):
    """IPv4 routes and addresses on the generated TUN subnet, from the IP helper tables a standard user reads."""
    import ctypes
    network,bits=subnet;base=int.from_bytes(socket.inet_aton(network),'big');mask=(0xffffffff<<(32-bits))&0xffffffff
    found=set()
    # MIB_IPFORWARDROW: destination at 0, next hop at 12, 56 bytes; MIB_IPADDRROW: address at 0, 24 bytes.
    for name,width,columns in (('GetIpForwardTable',56,(0,12)),('GetIpAddrTable',24,(0,))):
        function=getattr(ctypes.windll.iphlpapi,name);size=ctypes.c_ulong(0)
        require(function(None,ctypes.byref(size),False) in (0,122),'tun-route-table-size')
        for _ in range(4):  # The table may grow between two calls.
            buffer=ctypes.create_string_buffer(size.value+4096);size=ctypes.c_ulong(len(buffer))
            code=function(buffer,ctypes.byref(size),False)
            if code!=122:break
        require(code==0,'tun-route-table-read')
        raw=buffer.raw;count=int.from_bytes(raw[:4],'little')
        require(4+count*width<=len(raw),'tun-route-table-bound')
        for row in range(count):
            for column in columns:
                at=4+row*width+column
                if int.from_bytes(raw[at:at+4],'big')&mask==base:found.add((name,socket.inet_ntoa(raw[at:at+4])))
    return sorted(found)


def census(inputs, observer, exclude=()):
    """What a TUN row could leave behind, as the ordinary user sees it. Reads only."""
    rows=observer.WindowsNative().processes()
    return {'brokers':sorted(row['pid'] for row in rows if row['name'].casefold()==BROKER_LEAF),
            'runtimes':sorted(row['pid'] for row in rows if row['name'].casefold()=='sing-box.exe' and row['pid'] not in exclude),
            'stages':sorted(name for name in os.listdir(inputs['programData']) if name.casefold().startswith(STAGE_PREFIX)),
            'routes':[list(row) for row in tun_routes()]}


def kept(state, inputs, before, pending, initial, status, cases, observer):
    """Active A and its config bytes as before, pending B still selected in VPN mode, owner and runtime unelevated."""
    require(all(status['data'][key]==before['data'][key] for key in
        ('runtimeRunning','activeLocationId','activeMode','runtimeId','runtimeStartedAt'))
        and status['restartRequired'] is True and status['data']['configuredMode']=='vpn'
        and status['data']['selectedLocationId']==pending['data']['selectedLocationId']
        and cases.config_bytes(inputs['runtimeConfigPath'])=={key:initial[key] for key in ('sizeBytes','sha256')},
        'uac-denial-lost-active-a-or-pending-b')
    native=observer.WindowsNative()
    cases.exact_actor(native,state['actors']['owner'],elevated=False)
    cases.exact_actor(native,state['actors']['runtime'],elevated=False)


def unscoped(inputs, observer, state, baseline):
    """Nothing scoped started: no broker, no TUN route, and no runtime or private stage the baseline did not hold."""
    found=census(inputs,observer,exclude=(state['actors']['runtime']['pid'],))
    require(found['brokers']==[] and found['routes']==[] and set(found['runtimes'])<=set(baseline['runtimes'])
            and found['stages']==baseline['stages'],'scoped-tun-unexpected-terminal-scoped-state')
    return found


def refused(owner, state, inputs, runtime, cases, observer, operation, children, known):
    """The request's own reply, when a failed check found a final refusal from this controller.

    A refusal is a known end only with A, pending B and the census as before: no operation is open, so the row
    closes like any known failure. Any other reply (lost, partial, transport, another controller's) returns, and
    the original failure parks the owner.
    """
    if len(children)!=1 or tuple(children[0].argv[-5:])!=('--json','--controller-id',state['identity'],'--async',operation):
        return
    reply=children[0].completed()
    try:
        body=json.loads(reply.stdout)
    except ValueError:
        return
    if not (reply.stderr=='' and type(body) is dict and body.get('schemaVersion')==1 and body.get('controllerId')==state['identity']
            and body.get('final') is True and body.get('ok') is False and type(body.get('code')) is str
            and reply.returncode==REFUSED_EXITS.get(body['code'])):
        return
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    kept(state,inputs,known['before'],known['pending'],known['initial'],status,cases,observer)
    found=unscoped(inputs,observer,state,known['baseline'])
    owner.event('scoped-tun-request-refused-known',{'variant':inputs['variant'],'reply':body,'status':status,
        'census':found,'knownFailure':True,'replayAllowed':False})
    owner.tun_operation_requested=False  # No operation is open: the driver closes the row as a known failure.
    raise AssertionError('scoped-tun-request-refused')


def begin(owner, state, inputs, runtime, cases, observer):
    grant=type(inputs) is dict and str(inputs.get('variant')).endswith('grant')
    require(type(inputs) is dict and set(inputs)==FIELDS|(SAMPLER_FIELDS if grant else set()) and inputs['schemaVersion']==1
            and inputs['variant'] in VARIANTS and all(inputs[key] is not None for key in inputs),
            'scoped-tun-native-inputs-pending')
    require(not grant or all(str(Path(inputs[key])).casefold() in owner.by_path for key in SAMPLER_FIELDS),
            'scoped-tun-held-sampler')
    require(inputs['pendingLocation']=='Owned B' and str(Path(inputs['guiPath'])).casefold() in owner.by_path
            and inputs['expectedApprovingAdminSid']!=owner.request['context']['ordinarySid'],
            'scoped-tun-fixed-pending-location-admin-role')
    require(inputs['uacDecisionId']==decision_id(owner.request['operationId']),'scoped-tun-route-decision')
    require(os.name=='nt' and Path(inputs['programData'])==Path(os.environ['ProgramData']),
            'scoped-tun-current-programdata-context')
    # Before any change: no broker and no TUN route exist, and these are the stages and runtimes not of this row.
    baseline=census(inputs,observer,exclude=(state['actors']['runtime']['pid'],))
    require(baseline['brokers']==[] and baseline['routes']==[],'scoped-tun-clean-before-row')
    before = runtime.result(owner,state['workspace'],state['identity'],'status')
    require(before['data']['runtimeRunning'] is True and before['data']['activeMode']=='proxy-only'
            and before['restartRequired'] is False, 'scoped-tun-active-proxy-a')
    config=cases.LiveConfig(owner,state['workspace'],inputs['runtimeConfigPath'])
    actual={k:before['data'][k] for k in ('activeLocationId','activeMode','runtimeId','runtimeStartedAt')}
    for tail in (('locations','select','Owned B'),('settings','set','mode','vpn')):
        status=runtime.result(owner,state['workspace'],state['identity'],'status')
        runtime.result(owner,state['workspace'],state['identity'],'--if-revision',str(status['configurationRevision']),*tail)
        pending=runtime.result(owner,state['workspace'],state['identity'],'status')
        require(all(pending['data'][key]==value for key,value in actual.items()) and config.snapshot()==config.initial,
                'pending-b-mutated-active-a')
    require(pending['restartRequired'] is True and pending['data']['configuredMode']=='vpn'
            and pending['data']['selectedLocationId']!=before['data']['activeLocationId'],
            'scoped-tun-pending-b-not-established')
    # Intentional product restart may replace its config. Preserve the actual
    # beforeimage and release this stable-window observer BEFORE mutation.
    raw=Path(inputs['runtimeConfigPath']).read_bytes()
    require(len(raw)<=32768 and hashlib.sha256(raw).hexdigest()==config.initial['sha256'],
            'owned-small-proxy-config-beforeimage')
    runtime.publish(owner,owner.root/'tun-active-a-beforeimage.json',raw)
    config.close()
    # From here on the product may hold an open operation, a prompt or a broker: any failure parks the owner,
    # unless the request's own reply proves it final and nothing changed.
    owner.tun_operation_requested=True
    operation='find-best' if inputs['variant'].startswith('find-best') else 'restart'
    asked=len(owner.children)
    try:
        accepted=runtime.result(owner,state['workspace'],state['identity'],'--async',operation,
                                final=False,codes=('ACCEPTED',))
    except AssertionError:
        refused(owner,state,inputs,runtime,cases,observer,operation,owner.children[asked:],
                {'before':before,'pending':pending,'initial':config.initial,'baseline':baseline})
        raise
    require(type(accepted['operationId']) is str and str(uuid.UUID(accepted['operationId']))==accepted['operationId']
            and str(uuid.UUID(accepted['requestId']))==accepted['requestId'], 'scoped-tun-original-accepted-job')
    lease={'state':state,'inputs':inputs,'before':before,'pending':pending,'accepted':accepted,
           'activeConfig':config,'baseline':baseline,'finished':False}
    if not hasattr(owner,'tun_operation_leases'):owner.tun_operation_leases=[]
    owner.tun_operation_leases.append(lease)
    # windows-uac-decision's census reads this event's variant and expectedApprovingAdminSid; it is published once.
    owner.event('scoped-tun-awaiting-current-input', {'accepted':accepted,'variant':inputs['variant'],
        'ordinarySid':owner.request['context']['ordinarySid'],
        'ordinarySessionId':owner.request['context']['ordinarySessionId'],
        'expectedApprovingAdminSid':inputs['expectedApprovingAdminSid'],
        'uacDecisionId':inputs['uacDecisionId'],
        'ownerActor':state['actors']['owner'],'originalServeChild':state['serve'].ordinal,
        'inputNotPerformedByThisAdapter':True,'replayAllowed':False})
    return lease


def read_native_record(owner, lease, file_record, receipts, expected_stage):
    """Read a create-only machine-protected record from the actual SYS collector."""
    require(type(file_record) is dict and set(file_record)=={'path','sha256','sizeBytes'}
            and type(file_record['sizeBytes']) is int and 0<file_record['sizeBytes']<=262144,
            'scoped-tun-native-record-bound')
    expected=receipts.canonical_path(lease['inputs']['programData']) / ('tun-evidence-'+owner.request['operationId']) / (expected_stage+'.json')
    require(receipts.canonical_path(file_record['path'])==expected, 'scoped-tun-exact-machine-record-destination')
    observation=receipts.FileObservation(owner,file_record['path'])
    try:
        receipts.machine_security(observation.opening['security'],False)
        raw=observation.read(262144)
        require(len(raw)==file_record['sizeBytes'] and hashlib.sha256(raw).hexdigest()==file_record['sha256'],
                'scoped-tun-native-record-generation')
        value=json.loads(raw)
    finally:observation.close()
    require(value['schemaVersion']==1 and value['stage']==expected_stage
            and value['ordinaryTaskOperationId']==owner.request['operationId']
            and value['productOperationId']==lease['accepted']['operationId']
            and value['originRequestId']==lease['accepted']['requestId']
            and value['controllerId']==lease['state']['identity']
            and value['context']['bootIdentifier']==owner.request['context']['bootIdentifier']
            and value['context']['ordinarySid']==owner.request['context']['ordinarySid']
            and value['context']['approvingAdminSid']==lease['inputs']['expectedApprovingAdminSid']
            and type(value['context']['ordinarySessionId']) is int
            and value['context']['ordinarySessionId']==owner.request['context']['ordinarySessionId']
            and receipts.canonical_path(value['context']['workspace'])
                ==receipts.canonical_path(owner.request['workspace'])
                ==receipts.canonical_path(str(lease['state']['workspace']))
            and receipts.canonical_path(value['context']['programData'])
                ==receipts.canonical_path(lease['inputs']['programData'])
            and value['collectorSourceSha256']==lease['inputs']['collectorSourceSha256']
            and value['sourceSha']==owner.request['sourceSha'],
            'scoped-tun-protected-native-operation-join')
    return value


def finish(owner, lease, runtime, cases, observer, native_record=None, receipts=None):
    require(lease in owner.tun_operation_leases and not lease['finished'],'scoped-tun-finish-once')
    state=lease['state'];denied=lease['inputs']['variant'].endswith('deny')
    # The default wait parks at 120 s, about as long as a prompt lives, so it must outlast the prompt.
    # Every final code the stages know is read; one this variant does not expect is known only as checked below.
    terminal=runtime.finish_operation(owner,state,lease['accepted'],
        {'OK','RUNTIME_FAILED','CANCELLED','PERMISSION_DENIED'},seconds=300)
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    # An expired prompt reaches a grant as the product's own CANCELLED: the same unchanged A, a known failure.
    cancelled=not denied and terminal['code']=='CANCELLED'
    unexpected=terminal['code'] not in ({'CANCELLED','PERMISSION_DENIED'} if denied else {'OK','CANCELLED'})
    if denied or cancelled or unexpected:
        kept(state,lease['inputs'],lease['before'],lease['pending'],lease['activeConfig'].initial,status,cases,observer)
        if unexpected:
            # A refused preparation, say, before any prompt: known only with A intact and nothing scoped started.
            found=unscoped(lease['inputs'],observer,state,lease['baseline'])
            lease.update(finished=True,knownEnd=terminal['code'])
            owner.event('scoped-tun-unexpected-terminal-known',{'variant':lease['inputs']['variant'],'terminal':terminal,
                'status':status,'census':found,'knownFailure':True,'replayAllowed':False})
            return {'terminal':terminal,'status':status,'nativeRecord':None,'knownFailure':terminal['code']}
    else:
        require(native_record is not None and receipts is not None,'actual-tun-native-file-required')
        native_record=read_native_record(owner,lease,native_record,receipts,'ready')
        require(native_record['stage']=='ready'
                and native_record['productOperationId']==lease['accepted']['operationId'],
                'actual-machine-protected-tun-ready-observation-required')
        require(status['data']['runtimeRunning'] is True and status['data']['activeMode']=='vpn'
                and status['data']['activeLocationId']==status['data']['selectedLocationId']
                and status['restartRequired'] is False
                and native_record['observations']['configuration']['sha256']!=lease['activeConfig'].initial['sha256'],
                'scoped-tun-actual-commit-result')
        lease['nativeReady']=native_record  # The TUN is up: only now may the direct sampler run.
    lease['finished']=True
    if cancelled:
        lease['knownEnd']=terminal['code']  # No TUN came up: the grant closes by its census, with no off of its own.
        owner.event('scoped-tun-grant-cancelled-known',{'variant':lease['inputs']['variant'],'terminal':terminal,
            'status':status,'knownFailure':True,'replayAllowed':False})
        return {'terminal':terminal,'status':status,'nativeRecord':None,'cancelled':True}
    owner.event('scoped-tun-public-outcome',{'variant':lease['inputs']['variant'],'terminal':terminal,
        'status':status,'nativeRecord':native_record,'uacInputOriginStillRequired':True,
        'trafficAndExactOffStillRequired':not denied,'privilegedFaultRecoveryProven':False})
    return {'terminal':terminal,'status':status,'nativeRecord':native_record}


def begin_off(owner,lease,runtime):
    require(lease in owner.tun_operation_leases and lease['finished']
            and lease['inputs']['variant'].endswith('grant') and not lease.get('offRequested'),
            'scoped-tun-explicit-off-once')
    lease['offRequested']=True
    state=lease['state']
    # Product owns retirement of the exact elevated child; no process kill.
    terminal=runtime.result(owner,state['workspace'],state['identity'],'off')
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    require(status['data']['runtimeRunning'] is False,'scoped-tun-public-off-runtime-still-running')
    lease['offTerminal']=terminal
    owner.event('scoped-tun-awaiting-exact-off-observation',{'accepted':lease['accepted'],
        'offTerminal':terminal,'status':status,'originalNativeCustodyMustBeRetained':True})
    return terminal


def finish_off(owner,lease,file_record,receipts):
    require(lease.get('offRequested') and not lease.get('offFinished'),'scoped-tun-original-off-stage')
    record=read_native_record(owner,lease,file_record,receipts,'off')
    rows=record['originalProcesses']
    require(len(rows)==2 and {row['role'] for row in rows}=={'helperActor','runtimeActor'}
            and all(row['originalHandleSignaled'] is True and row['times']['creationFileTime']==row['creationFileTime']
                    for row in rows), 'scoped-tun-original-process-handles-not-proven-terminal')
    lease['offFinished']=True
    owner.event('scoped-tun-exact-off-observed',{'offTerminal':lease['offTerminal'],'record':record,
        'noBroadProcessStop':True,'originalOwnerCleanupStillRequired':True})
    return record


def traffic(owner, lease):
    """The direct sampler through this row's own TUN: after its ready record proved the TUN up, before its off.

    Outside that window the benchmark address would leave the guest, so nothing else starts it.
    """
    require(lease in owner.tun_operation_leases and lease['finished'] and lease.get('nativeReady') is not None
            and not lease.get('offRequested') and not lease['inputs']['variant'].endswith('deny'),
            'scoped-tun-direct-traffic-window')
    inputs=lease['inputs']
    raw=owner.by_path[str(Path(inputs['samplerInputPath'])).casefold()].digest(True,4096)
    require(json.loads(raw)['expectedBodyHex']==lease['state']['inputs']['fixtureBody'].encode().hex(),
            'scoped-tun-sampler-owned-upstream-body')
    child=owner.child('scoped-tun-direct-traffic',[owner.request['pythonRuntime']['interpreterPath'],'-I','-B',
        inputs['samplerPath'],'--input',inputs['samplerInputPath']])
    output=child.completed()
    rows=[json.loads(line) for line in output.stdout.splitlines()]
    require(output.returncode==0 and output.stderr=='' and len(rows)>=2
            and rows[-1]=={'kind':'terminal','sampleCount':len(rows)-1,'allSamplesSucceeded':True}
            and all(row.get('kind')=='sample' and row.get('succeeded') is True for row in rows[:-1]),
            'scoped-tun-direct-traffic')
    owner.event('scoped-tun-direct-traffic-observed',{'child':child.ordinal,'samples':len(rows)-1,
        'target':'198.18.0.1:80','socksStep':False,'replayAllowed':False})
    return rows


def closing(owner, lease, observer):
    """Read after the public off: no broker, no runtime this row started, no new private stage, no TUN route.

    Once per settled lease: a denial, a known end such as a cancelled grant, or a grant after its exact off.
    """
    require(lease in owner.tun_operation_leases and settled(lease) and not lease.get('closed'),'scoped-tun-closing-once')
    found=census(lease['inputs'],observer)
    baseline=lease['baseline']
    require(found['brokers']==[] and found['routes']==[] and set(found['runtimes'])<=set(baseline['runtimes'])
            and found['stages']==baseline['stages'],'scoped-tun-scoped-state-left-behind')
    lease['closed']=True
    owner.event('scoped-tun-closing-census',{'baseline':baseline,'closing':found,'replayAllowed':False})
    return found
