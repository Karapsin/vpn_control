"""Finite ordinary active-A/pending-B TUN stages on the Windows scenario route.

The product's original async job stays retained. This module cannot press UAC keys:
the closed windows-uac-decision action answers the vpn-broker prompt, and every input
here comes from the row's own job plan and context stage, never from a caller. The
decision it waits for is that action's one decision for this operation. A grant also
needs the TUN SYSTEM collector's ready and off records, which the dedicated driver hands
over (finish asks for ready only once the product's own operation ended OK); the direct
sampler runs only between them. The closing census shows the row left no broker, scoped
runtime, private stage or TUN route behind. From the request until the operation settles
(a denial, a known end or a grant's exact off) a failure parks the owner; a final refusal
of the request itself, with nothing changed, is a known end.

The configuration and fault variants first add their own location from the documents the proxy rows' branch cases
make (windows_runtime_branch_cases), so each is the TUN half of a proxy row. A configuration grant compares the runtime
config the ordinary user reads in its ready window with the bytes SYSTEM read for its ready record. A preparation
failure in VPN mode raises no prompt and must leave A, pending B and the census as they were; a commit-readiness
failure after an approval must bring A back as a new unelevated runtime with nothing scoped left. Neither asks a
collector: no TUN comes up.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import socket
import uuid

# The reserved cases (windows_tun_reserved_cases) restart into their own pending location: resources-grant and ssh-grant
# are grants with the collector and sampler; stage-squat is approved but its broker refuses, so no TUN comes up.
RESERVED_VARIANTS = frozenset({'resources-grant','ssh-grant','stage-squat'})
VARIANTS = frozenset({'restart-grant','restart-deny','find-best-grant','find-best-deny',
    'generated-grant','custom-grant','large-grant','vpn-prepare-failure','vpn-commit-failure'})|RESERVED_VARIANTS
# Approved variants whose TUN SYSTEM collector proves the broker and its runtime from the ready record to the off record.
GRANTS = frozenset({'restart-grant','find-best-grant','generated-grant','custom-grant','large-grant','resources-grant','ssh-grant'})
# Grants whose runtime config is the product's generated VPN config, with its TUN inbound: only through that TUN may the
# direct sampler run. A CUSTOM document in VPN mode keeps its own inbounds and these define no TUN, so the sampler's
# benchmark address would leave the guest: custom-grant and large-grant never sample.
SAMPLED = frozenset({'restart-grant','find-best-grant','generated-grant','resources-grant','ssh-grant'})
# Each configuration or fault variant's own location, added from a document before it is selected.
CONFIGS = {'generated-grant':'Owned generated','custom-grant':'Owned CUSTOM','large-grant':'Owned large CUSTOM'}
FAULTS = {'vpn-prepare-failure':'Owned prepare failure','vpn-commit-failure':'Owned commit failure'}
PENDING = {**dict.fromkeys(('restart-grant','restart-deny','find-best-grant','find-best-deny','ssh-grant'),'Owned B'),
    **dict.fromkeys(('resources-grant','stage-squat'),'Owned resources'),**CONFIGS,**FAULTS}
# windows_runtime_branch_cases.custom_config's kind for each CUSTOM document.
DOCUMENT_KIND = {'custom-grant':'custom','large-grant':'large','vpn-prepare-failure':'prepare-failure',
    'vpn-commit-failure':'commit-readiness-failure'}
# The product checks a config before it asks for the broker (DesktopProxyRuntimeManager.buildLaunch, sing-box check):
# a preparation failure raises no prompt, so nothing is answered and no decision awaits it.
PROMPTLESS = frozenset({'vpn-prepare-failure'})
CONFIG_BYTES = 8*1024*1024  # windows_runtime_branch_cases.MAX_CONFIG
INLINE_LIMIT = 60000  # The large document must exceed the inline limit, as the proxy row's does.
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
                                          or 'faultRecovered' in lease or 'conflictEnd' in lease or lease.get('offFinished') is True)


def guest_filetime():
    """The guest's UTC system time as a FILETIME (100 ns since 1601): the clock GetProcessTimes stamps an exit with."""
    import ctypes
    value=ctypes.c_ulonglong(0)
    ctypes.windll.kernel32.GetSystemTimePreciseAsFileTime(ctypes.byref(value))
    require(value.value>0,'scoped-tun-guest-clock')
    return value.value


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


def document(owner, state, variant, branches):
    """A configuration or fault variant's own location document, published as the proxy rows' branch cases publish
    theirs: the same generated SOCKS document or CUSTOM config, held open read-only until the row's off."""
    port=state['ready']['advertisedSocksPort'];name=PENDING[variant];original=None
    if variant=='generated-grant':
        value={'type':'socks','remarks':name,'server':'127.0.0.1','server_port':port}
    else:
        original=branches.custom_config(port,DOCUMENT_KIND[variant]);value=branches.profile_document(original,name)
    raw=branches.encoded(value)
    require(variant!='large-grant' or len(raw)>INLINE_LIMIT,'large-fixture-must-exceed-inline-limit')
    path,_=branches.publish_fixture(owner,'owned-tun-profile-'+variant+'.json',raw)
    return {'name':name,'path':str(path),'original':original,'sizeBytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def capture_refused(owner, state, inputs, runtime, cases, observer, reserved, known):
    """resources-grant, before its own request: a config the ordinary capture refuses ends in the product's UNSUPPORTED
    with A as before, the refused location pending, and no broker, stage, route or correlation journal: before any prompt.

    From this request until that is shown a failure parks, as for the row's own request; then nothing is open."""
    for tail in (('locations','select',reserved.REFUSED),('settings','set','mode','vpn')):
        status=runtime.result(owner,state['workspace'],state['identity'],'status')
        runtime.result(owner,state['workspace'],state['identity'],'--if-revision',str(status['configurationRevision']),*tail)
    pending=runtime.result(owner,state['workspace'],state['identity'],'status')
    require(pending['restartRequired'] is True and pending['data']['configuredMode']=='vpn'
            and pending['data']['selectedLocationId']!=known['before']['data']['activeLocationId'],
            'scoped-tun-refused-pending-not-established')
    owner.tun_operation_requested=True
    accepted=runtime.result(owner,state['workspace'],state['identity'],'--async','restart',final=False,codes=('ACCEPTED',))
    body=reserved.terminal(state,accepted,{'UNSUPPORTED'})
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    kept(state,inputs,known['before'],pending,known['initial'],status,cases,observer)
    found=unscoped(inputs,observer,state,known['baseline'])
    require(reserved.journals(state['workspace'])=={},'scoped-tun-refused-capture-left-a-journal')
    owner.tun_operation_requested=False  # Nothing is open: the refusal ended before any prompt or broker.
    owner.event('scoped-tun-capture-refused-before-prompt',{'variant':inputs['variant'],'terminal':body,'status':status,
        'census':found,'journals':0,'replayAllowed':False})
    return body


def begin(owner, state, inputs, runtime, cases, observer, branches=None, reserved=None):
    variant=inputs.get('variant') if type(inputs) is dict else None
    sampled=variant in SAMPLED
    require(type(inputs) is dict and set(inputs)==FIELDS|(SAMPLER_FIELDS if sampled else set()) and inputs['schemaVersion']==1
            and inputs['variant'] in VARIANTS and all(inputs[key] is not None for key in inputs),
            'scoped-tun-native-inputs-pending')
    require((branches is not None)==(variant in CONFIGS or variant in FAULTS),'scoped-tun-variant-document-cases')
    require(not sampled or all(str(Path(inputs[key])).casefold() in owner.by_path for key in SAMPLER_FIELDS),
            'scoped-tun-held-sampler')
    require(inputs['pendingLocation']==PENDING[variant] and str(Path(inputs['guiPath'])).casefold() in owner.by_path
            and inputs['expectedApprovingAdminSid']!=owner.request['context']['ordinarySid'],
            'scoped-tun-fixed-pending-location-admin-role')
    require(inputs['uacDecisionId']==decision_id(owner.request['operationId']),'scoped-tun-route-decision')
    require((reserved is not None)==(inputs['variant'] in RESERVED_VARIANTS)
            and (reserved is None or reserved.variant==inputs['variant'] and reserved.pending==inputs['pendingLocation']),
            'scoped-tun-reserved-case-binding')
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
    if reserved is not None:
        # The reserved case's own pending location (and SSH route); nothing restarts here.
        require(reserved.prepare(state,runtime)==inputs['pendingLocation'],'scoped-tun-reserved-pending-location')
        require(config.snapshot()==config.initial,'pending-b-mutated-active-a')
        if inputs['variant']=='resources-grant':
            capture_refused(owner,state,inputs,runtime,cases,observer,reserved,
                            {'before':before,'initial':config.initial,'baseline':baseline})
    added=None if branches is None else document(owner,state,variant,branches)
    tails=(('locations','select',PENDING[variant]),('settings','set','mode','vpn'))
    if added is not None:
        tails=(('locations','add','--input',added['path']),)+tails
    for tail in tails:
        status=runtime.result(owner,state['workspace'],state['identity'],'status')
        runtime.result(owner,state['workspace'],state['identity'],'--if-revision',str(status['configurationRevision']),*tail)
        pending=runtime.result(owner,state['workspace'],state['identity'],'status')
        require(all(pending['data'][key]==value for key,value in actual.items()) and config.snapshot()==config.initial,
                'pending-b-mutated-active-a')
    require(pending['restartRequired'] is True and pending['data']['configuredMode']=='vpn'
            and pending['data']['selectedLocationId']!=before['data']['activeLocationId'],
            'scoped-tun-pending-b-not-established')
    if variant in CONFIGS:
        # The location reads back as the document that made it, before anything is asked of the broker.
        shown=json.loads(runtime.result(owner,state['workspace'],state['identity'],'locations','show',PENDING[variant])['data']['configuration'])
        require(shown==added['original'] if added['original'] is not None else
                shown.get('server')=='127.0.0.1' and shown.get('server_port')==state['ready']['advertisedSocksPort'],
                'scoped-tun-configuration-public-readback')
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
           'activeConfig':config,'baseline':baseline,'finished':False,**({} if added is None else {'document':added})}
    if not hasattr(owner,'tun_operation_leases'):owner.tun_operation_leases=[]
    owner.tun_operation_leases.append(lease)
    if variant in PROMPTLESS:
        # No prompt follows: windows-uac-decision has no row for it and nothing waits on one.
        owner.event('scoped-tun-request-accepted',{'accepted':accepted,'variant':variant,'document':added,
            'promptExpected':False,'replayAllowed':False})
        return lease
    if reserved is not None:
        # Before the decision may answer: a mutable job's correlation journal, and a squat row's folder at its stage.
        lease['reserved']=reserved
        lease['beforeDecision']=reserved.before_prompt(state)
    # windows-uac-decision's census reads this event's variant and expectedApprovingAdminSid; it is published once.
    owner.event('scoped-tun-awaiting-current-input', {'accepted':accepted,'variant':inputs['variant'],
        'ordinarySid':owner.request['context']['ordinarySid'],
        'ordinarySessionId':owner.request['context']['ordinarySessionId'],
        'expectedApprovingAdminSid':inputs['expectedApprovingAdminSid'],
        'uacDecisionId':inputs['uacDecisionId'],
        'ownerActor':state['actors']['owner'],'originalServeChild':state['serve'].ordinal,
        'inputNotPerformedByThisAdapter':True,'replayAllowed':False,**({} if added is None else {'document':added})})
    return lease


def read_native_record(owner, lease, file_record, receipts, expected_stage):
    """Read a create-only machine-protected record from the actual SYS collector.

    Its source is the product source the row runs: the lifecycle inputs' own, which the dedicated driver keeps on the
    lease. The ordinary worker request carries none; an owner request that does binds the same way.
    """
    require(type(file_record) is dict and set(file_record)=={'path','sha256','sizeBytes'}
            and type(file_record['sizeBytes']) is int and 0<file_record['sizeBytes']<=262144,
            'scoped-tun-native-record-bound')
    source=lease['sourceSha'] if 'sourceSha' in lease else owner.request['sourceSha']
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
            and value['sourceSha']==source,
            'scoped-tun-protected-native-operation-join')
    return value


def denials(variant):
    """The public codes a denial of this variant's prompt ends its operation with.

    Esc ends the prompt with ERROR_CANCELLED (DesktopWindowsVpnBroker: 1223 is CANCELLED), and a restart that ends it
    otherwise unelevated may say PERMISSION_DENIED. Find Best ends at its first CANCELLED start, restoring A
    (DesktopFindBestService); any other failed start makes it try its next candidate, which raises a prompt of its own,
    so for Find Best no other code is the denial of this prompt.
    """
    return {'CANCELLED'} if variant.startswith('find-best') else {'CANCELLED','PERMISSION_DENIED'}


def find_best_selection(lease, status):
    """Which location a granted Find Best leaves selected: its winner, the active one, never a third.

    DesktopFindBestService starts candidates with commitSelectionOnSuccessOnly, so the selection moves only once the
    elevated start succeeded, and then to that candidate. The candidates are the owned locations, A and B, ordered by
    their measured connect time; both reach the one owned endpoint, so either may win. A winner A replaces the pending
    selection of B: the restart's rule (selection kept) is not Find Best's.
    """
    a=lease['before']['data']['activeLocationId'];b=lease['pending']['data']['selectedLocationId']
    selected=status['data']['selectedLocationId']
    require(a!=b and selected==status['data']['activeLocationId'] and selected in (a,b),'scoped-tun-find-best-winner-not-an-owned-candidate')
    return {'locationId':selected,'winner':'active-a' if selected==a else 'pending-b','pendingSelectionKept':selected==b}


def finish(owner, lease, runtime, cases, observer, handoff=None, receipts=None):
    """The public terminal of the row's own request. A grant whose TUN came up asks handoff(lease, 'ready') for its
    SYSTEM collector's ready record only now: the collector finds the broker and its runtime only once they run."""
    require(lease in owner.tun_operation_leases and not lease['finished'],'scoped-tun-finish-once')
    state=lease['state'];variant=lease['inputs']['variant'];denied=variant.endswith('deny');native_record=None
    if variant=='stage-squat':
        return squat_finish(owner,lease,runtime,cases,observer)
    # The default wait parks at 120 s, about as long as a prompt lives, so it must outlast the prompt.
    # Every final code the stages know is read; one this variant does not expect is known only as checked below.
    terminal=runtime.finish_operation(owner,state,lease['accepted'],
        {'OK','RUNTIME_FAILED','CANCELLED','PERMISSION_DENIED'},seconds=300)
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    # A fault variant's own end: RUNTIME_FAILED with A kept (preparation) or A back as a new runtime (commit).
    if variant in FAULTS and terminal['code']=='RUNTIME_FAILED':
        found=(prepared_failure if variant in PROMPTLESS else commit_failure)(owner,lease,status,runtime,cases,observer)
        lease.update(finished=True,faultRecovered=terminal['code'])
        owner.event('scoped-tun-fault-recovered',{'variant':variant,'terminal':terminal,'status':status,'census':found,
            'actors':state['actors'],'promptExpected':variant not in PROMPTLESS,'replayAllowed':False})
        return {'terminal':terminal,'status':status,'nativeRecord':None,'faultRecovered':True}
    # An expired prompt reaches a grant as the product's own CANCELLED: the same unchanged A, a known failure.
    cancelled=not denied and variant not in PROMPTLESS and terminal['code']=='CANCELLED'
    unexpected=terminal['code'] not in (denials(variant) if denied else set() if variant in PROMPTLESS
                                        else {'CANCELLED'} if variant in FAULTS else {'OK','CANCELLED'})
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
        require(variant in GRANTS and handoff is not None and receipts is not None,'actual-tun-native-file-required')
        native_record=read_native_record(owner,lease,handoff(lease,'ready'),receipts,'ready')
        require(native_record['stage']=='ready'
                and native_record['productOperationId']==lease['accepted']['operationId'],
                'actual-machine-protected-tun-ready-observation-required')
        require(status['data']['runtimeRunning'] is True and status['data']['activeMode']=='vpn'
                and status['data']['activeLocationId']==status['data']['selectedLocationId']
                and status['restartRequired'] is False
                and native_record['observations']['configuration']['sha256']!=lease['activeConfig'].initial['sha256'],
                'scoped-tun-actual-commit-result')
        if lease['inputs']['variant'].startswith('find-best'):
            lease['findBestSelection']=find_best_selection(lease,status)
        lease['nativeReady']=native_record  # The TUN is up: only now may the direct sampler run.
    lease['finished']=True
    if cancelled:
        lease['knownEnd']=terminal['code']  # No TUN came up: the grant closes by its census, with no off of its own.
        owner.event('scoped-tun-grant-cancelled-known',{'variant':lease['inputs']['variant'],'terminal':terminal,
            'status':status,'knownFailure':True,'replayAllowed':False})
        return {'terminal':terminal,'status':status,'nativeRecord':None,'cancelled':True}
    owner.event('scoped-tun-public-outcome',{'variant':lease['inputs']['variant'],'terminal':terminal,
        'status':status,'nativeRecord':native_record,'findBestSelection':lease.get('findBestSelection'),
        'uacInputOriginStillRequired':True,
        'trafficAndExactOffStillRequired':not denied,'privilegedFaultRecoveryProven':False})
    return {'terminal':terminal,'status':status,'nativeRecord':native_record}


def prepared_failure(owner, lease, status, runtime, cases, observer):
    """A preparation failure in VPN mode: the product refused the document before any prompt, so active A, pending B,
    their config bytes and the census are exactly as before the request."""
    kept(lease['state'],lease['inputs'],lease['before'],lease['pending'],lease['activeConfig'].initial,status,cases,observer)
    return unscoped(lease['inputs'],observer,lease['state'],lease['baseline'])


def commit_failure(owner, lease, status, runtime, cases, observer):
    """A commit-readiness failure after the approval: the product stopped A, the approved runtime could not bind its
    owned-conflict listener, and the product brought A back from its own descriptor (DesktopRuntimeTransition.recover).

    A is the same location and mode with a new runtime, its config bytes as before, pending B still selected in VPN mode;
    the original A runtime is gone and the new one runs unelevated; the runtime log names the conflict the elevated
    runtime hit; and no broker, TUN route, private stage or runtime beyond the baseline and the new A is left.
    """
    state,inputs,before,pending=lease['state'],lease['inputs'],lease['before'],lease['pending']
    initial=lease['activeConfig'].initial
    require(status['data']['runtimeRunning'] is True and status['data']['activeMode']=='proxy-only'
            and status['data']['activeLocationId']==before['data']['activeLocationId']
            and status['data']['runtimeId']!=before['data']['runtimeId']
            and status['restartRequired'] is True and status['data']['configuredMode']=='vpn'
            and status['data']['selectedLocationId']==pending['data']['selectedLocationId']
            and cases.config_bytes(inputs['runtimeConfigPath'])=={key:initial[key] for key in ('sizeBytes','sha256')},
            'scoped-tun-commit-failure-did-not-recover-active-a')
    native=observer.WindowsNative()
    old=state['actors']['runtime']
    gone=observer.observe_exit([old],native)
    require(len(gone)==1 and gone[0].get('originalAbsent') is True,'scoped-tun-commit-failure-original-a-not-retired')
    actors=runtime.capture_proxy_actors(owner,state['serve'],native,state['inputs']['runtimeImagePath'],state['inputs']['runtimeSha256'])
    require((actors['runtime']['pid'],actors['runtime']['creationFileTime'])!=(old['pid'],old['creationFileTime']),
            'scoped-tun-commit-failure-original-a-not-retired')
    cases.exact_actor(native,actors['owner'],elevated=False)
    cases.exact_actor(native,actors['runtime'],elevated=False)
    log=Path(state['workspace'])/'runtime'/'runtime-sing-box.log'
    with log.open('rb') as stream:raw=stream.read(CONFIG_BYTES+1)
    require(len(raw)<=CONFIG_BYTES and b'owned-conflict' in raw.lower() and b'bind' in raw.lower()
            and str(state['ready']['advertisedSocksPort']).encode() in raw,
            'scoped-tun-commit-failure-conflict-log-required')
    state['actors']=actors  # The row's own off and its census take the recovered A.
    return unscoped(inputs,observer,state,lease['baseline'])


def configuration(owner, lease, branches):
    """A configuration grant's runtime config inside its ready window: the bytes the ordinary user reads are the
    ones SYSTEM read for the ready record, and they are the product's VPN config of this variant's own document."""
    variant=lease['inputs']['variant']
    require(lease in owner.tun_operation_leases and lease['finished'] and lease.get('nativeReady') is not None
            and not lease.get('offRequested') and variant in CONFIGS and 'document' in lease
            and not lease.get('configurationObserved'),'scoped-tun-configuration-window')
    observed=lease['nativeReady']['observations']['configuration']
    with Path(lease['inputs']['runtimeConfigPath']).open('rb') as stream:raw=stream.read(CONFIG_BYTES+1)
    require(0<len(raw)<=CONFIG_BYTES and len(raw)==observed['sizeBytes'] and hashlib.sha256(raw).hexdigest()==observed['sha256'],
            'scoped-tun-configuration-not-the-ready-record')
    actual=json.loads(raw);state=lease['state'];port=state['ready']['advertisedSocksPort']
    tun=[row for row in actual['inbounds'] if row.get('type')=='tun']
    if variant=='generated-grant':
        # DesktopProxyConfigFactory.buildVpnConfig: one TUN on the generated address, the location's SOCKS server out.
        require(len(tun)==1 and tun[0].get('address')==['172.19.250.1/30']
                and any(row.get('type')=='socks' and row.get('server')=='127.0.0.1' and row.get('server_port')==port
                        for row in actual['outbounds']),'scoped-tun-generated-configuration')
    else:
        original=lease['document']['original']
        branches.custom_semantics(original,actual)  # Only the product's management and direct-probe transformations.
        probe=[{'process_name':['vpn-control-probe-sing-box','vpn-control-probe-sing-box.exe'],'action':'route',
                'outbound':'vpn-control-direct-probe'},
               {'process_path':[str(Path(state['workspace'])/'validation'/'vpn-control-probe-sing-box.exe')],
                'action':'route','outbound':'vpn-control-direct-probe'}]
        require(tun==[] and actual['route']['rules'][2:-len(original['route']['rules'])]==probe,
                'scoped-tun-custom-configuration')
        require(variant!='large-grant' or lease['document']['sizeBytes']>INLINE_LIMIT,'large-fixture-must-exceed-inline-limit')
    lease['configurationObserved']=True
    owner.event('scoped-tun-configuration-observed',{'variant':variant,'document':lease['document'],
        'runtimeConfig':{'sizeBytes':len(raw),'sha256':observed['sha256']},'tunInbound':bool(tun),
        'directSamplerAllowed':variant in SAMPLED,'replayAllowed':False})
    return actual


def squat_finish(owner, lease, runtime, cases, observer):
    """stage-squat: the approved broker finds its stage already there and refuses with CONFLICT. A and pending B stay,
    the squat folder is exactly as created, and nothing scoped is left once the case removed its own folder. An expired
    prompt is the grant's own known CANCELLED, with the same checks."""
    state,reserved=lease['state'],lease['reserved']
    terminal=reserved.terminal(state,lease['accepted'],{'CONFLICT','CANCELLED'})
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    kept(state,lease['inputs'],lease['before'],lease['pending'],lease['activeConfig'].initial,status,cases,observer)
    reserved.squat_kept_and_removed()
    found=unscoped(lease['inputs'],observer,state,lease['baseline'])
    if terminal['code']=='CANCELLED':
        lease.update(finished=True,knownEnd='CANCELLED')
        owner.event('scoped-tun-grant-cancelled-known',{'variant':'stage-squat','terminal':terminal,'status':status,
            'census':found,'knownFailure':True,'replayAllowed':False})
        return {'terminal':terminal,'status':status,'nativeRecord':None,'cancelled':True}
    lease.update(finished=True,conflictEnd='CONFLICT')
    owner.event('scoped-tun-stage-squat-refused',{'terminal':terminal,'status':status,'census':found,
        'jobId':reserved.job,'activeAKept':True,'pendingBKept':True,'replayAllowed':False})
    return {'terminal':terminal,'status':status,'nativeRecord':None}


def begin_off(owner,lease,runtime):
    require(lease in owner.tun_operation_leases and lease['finished'] and lease.get('nativeReady') is not None
            and lease['inputs']['variant'] in GRANTS and not lease.get('offRequested'),
            'scoped-tun-explicit-off-once')
    state=lease['state']
    # The product's own view right before its off: the TUN runtime it started still runs. A runtime that ended by itself
    # (a crash after the last sample, say) leaves an off that stops nothing of the product's: no exact stop to prove.
    before=runtime.result(owner,state['workspace'],state['identity'],'status')
    require(before['data']['runtimeRunning'] is True and before['data']['activeMode']=='vpn',
            'scoped-tun-runtime-ended-before-off')
    # The guest clock just before the off goes out: finish_off takes only originals that exited after it.
    lease.update(offRequested=True,offRequestedFileTime=guest_filetime())
    # Product owns retirement of the exact elevated child; no process kill.
    terminal=runtime.result(owner,state['workspace'],state['identity'],'off')
    status=runtime.result(owner,state['workspace'],state['identity'],'status')
    require(status['data']['runtimeRunning'] is False,'scoped-tun-public-off-runtime-still-running')
    lease['offTerminal']=terminal
    owner.event('scoped-tun-awaiting-exact-off-observation',{'accepted':lease['accepted'],'statusBeforeOff':before,
        'offRequestedFileTime':lease['offRequestedFileTime'],'offTerminal':terminal,'status':status,
        'originalNativeCustodyMustBeRetained':True})
    return terminal


def finish_off(owner,lease,file_record,receipts):
    require(lease.get('offRequested') and not lease.get('offFinished') and type(lease.get('offRequestedFileTime')) is int,
            'scoped-tun-original-off-stage')
    record=read_native_record(owner,lease,file_record,receipts,'off')
    rows=record['originalProcesses']
    require(len(rows)==2 and {row['role'] for row in rows}=={'helperActor','runtimeActor'}
            and all(row['originalHandleSignaled'] is True and row['times']['creationFileTime']==row['creationFileTime']
                    for row in rows), 'scoped-tun-original-process-handles-not-proven-terminal')
    # The collector publishes off once both original handles signal, for whatever reason: only an exit after the
    # product's own off was asked for is that off's. One that ended before it (a crash) is no exact stop.
    requested=lease['offRequestedFileTime']
    require(all(type(row['times'].get('exitFileTime')) is int and row['times']['exitFileTime']>requested for row in rows),
            'scoped-tun-original-ended-before-the-off')
    lease['offFinished']=True
    # This proves the off ended exactly these two originals after it was asked for. It cannot show the elevated stop
    # spared an unrelated runtime: none runs beside the grant (exact-child-stop stays unmapped for TUN).
    owner.event('scoped-tun-exact-off-observed',{'offTerminal':lease['offTerminal'],'offRequestedFileTime':requested,
        'record':record,'exitedAfterOffRequest':True,'siblingSurvivalObserved':False,'originalOwnerCleanupStillRequired':True})
    return record


def traffic(owner, lease):
    """The direct sampler through this row's own TUN: after its ready record proved the TUN up, before its off.

    Outside that window the benchmark address would leave the guest, so nothing else starts it.
    """
    require(lease in owner.tun_operation_leases and lease['finished'] and lease.get('nativeReady') is not None
            and not lease.get('offRequested') and lease['inputs']['variant'] in SAMPLED,
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

    Once per settled lease: a denial, a known end such as a cancelled grant, a fault variant's own recovery, or a
    grant after its exact off.
    """
    require(lease in owner.tun_operation_leases and settled(lease) and not lease.get('closed'),'scoped-tun-closing-once')
    found=census(lease['inputs'],observer)
    baseline=lease['baseline']
    require(found['brokers']==[] and found['routes']==[] and set(found['runtimes'])<=set(baseline['runtimes'])
            and found['stages']==baseline['stages'],'scoped-tun-scoped-state-left-behind')
    lease['closed']=True
    owner.event('scoped-tun-closing-census',{'baseline':baseline,'closing':found,'replayAllowed':False})
    return found
