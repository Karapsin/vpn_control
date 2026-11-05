"""Explicit fresh gateway route to a new owned inner channel; never a fallback.

Legacy session/channel journals remain historical. Only the explicit prepare
entry can create an intent; repeated calls observe that same original intent.
"""
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import types
from . import ssh_transport as transport

MODE='direct'
OUTER_OPTIONS=('-S','none','-o','ControlMaster=no','-o','ControlPersist=no')
_SOURCE_NAMES_V2=('ssh_direct_nested_channel.py','ssh_fresh_nested_channel.py',
 'ssh_transport.py','ssh_connection_session.py','ssh_connection_recovery.py',
 'private_inventory_lock.py','native_review_source_closure.py','check_output_retention.py',
 'ssh_nested_socket_owned_home_observation.py','ssh_nested_socket_noninteractive_observation.py',
 'ssh_nested_socket_retirement.py','ssh_nested_socket_route_diagnostic.py',
 'ssh_recovery_adoption.py','ssh_channel_inventory_diagnostics.py',
 'ssh_channel_selection.py','mcp_server.py')
_SOURCE_NAMES=_SOURCE_NAMES_V2+('ssh_direct_inventory.py','private_config_custody.py')
_INVENTORY_SOURCE_SHA='41578ce01b919d5e027109d8a6a31a1552b0df142e19aea15ee8cf4779eb5693'

def source_catalog(version):
    return _SOURCE_NAMES if version==3 else _SOURCE_NAMES_V2

def _inventory_module(held=None):
    owned=held is None
    if owned:held=_dependencies()[2]()
    try:
        path=Path(__file__).with_name('ssh_direct_inventory.py')
        raw=held.read(str(path),_INVENTORY_SOURCE_SHA,max_bytes=1048576)
        held.finish();held.final_identity_pass()
        module=types.ModuleType((__package__ or 'agent_tools')+'._direct_private_inventory')
        module.__file__=str(path);module.__package__=__package__
        exec(compile(raw,str(path),'exec',dont_inherit=True),module.__dict__)
        held.finish();held.final_identity_pass();return module
    finally:
        if owned:held.close()

def private_inventory(root):
    return _inventory_module().InventoryCustody(transport._private_config_path(root))


def coordinator_capable():
    """This provider coordinates POSIX SSH from the host, not from the guest."""
    return (os.name=='posix' and all(hasattr(os,name) for name in ('O_NOFOLLOW','O_DIRECTORY','O_NONBLOCK','pread','getuid','geteuid'))
            and importlib.util.find_spec('fcntl') is not None)


def _dependencies():
    if not coordinator_capable():raise ValueError('unsupported_coordinator')
    from . import ssh_connection_session as session,ssh_fresh_nested_channel as channel
    from .native_review_source_closure import _Held
    return session,channel,_Held


def _unsupported():
    return {'state':'unknown','nativeActionAllowed':False,'replayAllowed':False}


def validated_unknown(value):
    return _dependencies()[1].validated_unknown(value)

class Guard:
    def __init__(self,root,host="archlinux",*,legacy=False):
        session,channel,_Held=_dependencies();self.session=session
        self.root=Path(root).resolve(strict=True);self.host=host;self.held=_Held();self.closed=False;self.legacy=legacy;self.inventory=None
        try:
            if legacy:
                self.config,self.outer,self.authority=session._snapshot(self.root,self.host)
            else:
                self.inventory=_inventory_module(self.held).Authority(self.root,self.host)
                self.config,self.outer,self.authority=self.inventory.config,self.inventory.outer,self.inventory.value
            self.authority_sha=hashlib.sha256(session._json(self.authority)).hexdigest()
            self.source_pins={}
            for name in (_SOURCE_NAMES_V2 if legacy else _SOURCE_NAMES):
                path=Path(__file__).with_name(name)
                # File names are fixed source members, never caller paths. The
                # held read verifies regular/owner/full bytes and ancestry; it
                # is repeated before transport and after raw capture retention.
                digest=hashlib.sha256(path.read_bytes()).hexdigest()
                self.held.read(str(path),digest)
                self.source_pins[name]=digest
            if legacy:
                config_path=transport._private_config_path(self.root)
                self.held.read(str(config_path),self.authority['configSha256'])
                for row in self.authority['files']:self.held.read(row['path'],row['sha256'])
            self.guard()
        except BaseException:self.close();raise
    def guard(self):
        self.held.finish();self.held.final_identity_pass()
        if self.legacy:
            config,outer,authority=self.session._snapshot(self.root,self.host)
            if authority!=self.authority or asdict(config)!=asdict(self.config):raise ValueError('generation')
        else:self.inventory.guard()
        self.held.finish();self.held.final_identity_pass()
    def close(self):
        if not self.closed:
            if self.inventory is not None:self.inventory.close()
            self.held.close();self.closed=True
    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def outer_prefix(config,gateway):
    # Build the actual configured direct gateway alias, not the selected Arch
    # route. Exact local config/key/source guards are held by the caller.
    if gateway.transport!='direct' or gateway.password is not None:raise ValueError('route')
    # This explicit recovery route opens its own trusted gateway connection.
    # Copying selected reuse-only options then adding -S none would combine
    # incompatible master sockets and ProxyCommand=false.
    return transport.fresh_direct_prefix(config,gateway.alias)


def prepare(root,host,correlation_id,*,_private_capture=None):
    if not coordinator_capable():return _unsupported()
    session,channel,_Held=_dependencies()
    return channel._operate(root,host,correlation_id,True,_private_capture,direct=True)



def prepare_successor(root,host,correlation_id,previous_correlation,previous_receipt,*,deadline=None):
    """Internal source-qualified independent connection; no old READY adoption."""
    if not coordinator_capable():return _unsupported()
    session,channel,_Held=_dependencies()
    from . import readiness_nested_channel as nested
    nested.verify_executing_sources()
    with nested.membership_successor(root,host,previous_correlation,previous_receipt,deadline)as proof:
        nested.validate_membership_successor(proof,root,host,new_correlation=correlation_id)
        return channel._operate(root,host,correlation_id,True,direct=True,_membership_predecessor=proof)


def status(root,host,correlation_id,*,_private_capture=None,_private_inventory_diagnostic=None):
    if not coordinator_capable():return _unsupported()
    session,channel,_Held=_dependencies()
    return channel._operate(root,host,correlation_id,False,_private_capture,_private_inventory_diagnostic,direct=True)


def route_options(root,host,correlation_id,receipt_sha256,*,_private_capture=None):
    session,channel,_Held=_dependencies()
    channel._corr(correlation_id)
    if type(host)is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',host)is None:raise ValueError('host')
    if type(receipt_sha256)is not str or re.fullmatch('[0-9a-f]{64}',receipt_sha256)is None:raise ValueError('receipt')
    result=status(root,host,correlation_id,**({"_private_capture":_private_capture}if _private_capture is not None else{}))
    if result.get('state')!='ready':
        refusal={**result,'correlationId':correlation_id} if result.get('state')=='unknown' else channel._public(correlationId=correlation_id)
        raise channel.ChannelUnknown(refusal)
    if result.get('receiptSha256')!=receipt_sha256:raise ValueError('receipt')
    return {'transportMode':MODE,'correlationId':correlation_id,'receiptSha256':receipt_sha256,
            'outerAuthoritySha256':result['outerAuthoritySha256'],'outerOptions':OUTER_OPTIONS,
            'innerOptions':('-S','/tmp/vpn-channel-'+correlation_id+'/m',
                '-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false')}


# The module whose digest each outer-authority schema embeds.
_AUTHORITY_MODULE={1:'ssh_connection_session.py',2:'ssh_direct_inventory.py'}


def recorded_authority_continuity(session,intent,authority,old_device=None,new_device=None):
    """The intent's recorded outer authority still names the same gateway route.

    The authority hashes the outer route's private inventory, identity key and
    public host trust together with the digest of the module that computed it.
    Take that module digest from the intent's own retained catalog pin, so a
    later tooling revision alone never changes the answer while every route
    fact must match. After a local remount (``old_device`` to ``new_device``)
    also rewind exactly the known st_dev-bearing fields of the schema. Any
    other difference, or a record on a third device, refuses.
    """
    recorded=intent.get('outerAuthoritySha256') if type(intent)is dict else None
    pins=intent.get('directSourcePins') if type(intent)is dict else None
    if (type(recorded)is not str or re.fullmatch('[0-9a-f]{64}',recorded)is None or type(authority)is not dict
            or type(pins)is not dict):return False
    version=authority.get('version')
    module=_AUTHORITY_MODULE.get(version) if type(version)is int else None
    if module is None or type(pins.get(module))is not str or re.fullmatch('[0-9a-f]{64}',pins[module])is None:return False
    candidate=json.loads(json.dumps(authority));candidate['sourceSha256']=pins[module]
    if hashlib.sha256(session._json(candidate)).hexdigest()==recorded:return True
    if type(old_device)is not int or type(new_device)is not int or old_device==new_device:return False
    def rewind(value,length):
        if type(value)is list and len(value)==length and all(type(item)is int for item in value) and value[0]==new_device:
            return [old_device,*value[1:]]
        return value
    files=candidate.get('files')
    if type(files)is not list:return False
    if version==1:
        if 'configFingerprint' in candidate:candidate['configFingerprint']=rewind(candidate['configFingerprint'],8)
    elif type(candidate.get('configGeneration'))is dict and 'generation' in candidate['configGeneration']:
        candidate['configGeneration']['generation']=rewind(candidate['configGeneration']['generation'],9)
    for row in files:
        if type(row)is not dict:return False
        if type(row.get('generation'))is dict and 'generation' in row['generation']:
            row['generation']['generation']=rewind(row['generation']['generation'],9)
        if 'fingerprint' in row:row['fingerprint']=rewind(row['fingerprint'],8)
    return hashlib.sha256(session._json(candidate)).hexdigest()==recorded


def reconcile_original(root,host,correlation_id):
    """Observe a retained original remote capsule after local tooling changes.

    Only the original status action is executable. It may close a proven ENDED
    connection history; a live/uncertain original is never relaunched or adopted.
    The private original inventory and every retained source capsule must match.
    """
    if not coordinator_capable():return _unsupported()
    session,channel,_Held=_dependencies()
    from contextlib import ExitStack
    from . import private_inventory_lock as private
    try:
        channel._corr(correlation_id);channel._host(host)
        root=Path(root).resolve(strict=True)
        with private.ownership(root) as (presented,base,ownership),ExitStack() as stack:
            directory=stack.enter_context(private.Directory(channel._context_journal(root,host,correlation_id,False,True)))
            held=stack.enter_context(private.Snapshot(directory,correlation_id+'.intent.json'))
            intent=json.loads(held.body,object_pairs_hook=transport._reject_duplicate_keys)
            version=intent.get('version')
            current=stack.enter_context(Guard(root,host,legacy=version!=3))
            config_snapshot=stack.enter_context(private_inventory(root) if version==3 else private.Snapshot(base,transport.CONFIG_FILENAME))
            ready_name=correlation_id+'.ready.json'
            ready=stack.enter_context(private.Snapshot(directory,ready_name)) if os.path.lexists(directory.path/ready_name) else None
            receipt=json.loads(ready.body,object_pairs_hook=transport._reject_duplicate_keys) if ready else None
            if ready is not None and (type(receipt)is not dict or set(receipt)!={'intent','result'}):return channel._public()
            # Retained pins equal the live ones, or all moved with one local
            # volume renumbering; the route authority must still match.
            anchor=channel.directory_device(base)
            pairs=[(intent.get('inventory'),config_snapshot.pin(),anchor)]
            if ready is not None:pairs.append((receipt['intent'],held.pin(),channel.directory_device(directory)))
            old_device=channel.same_records_after_local_reboot(pairs)
            if (version not in (2,3) or intent.get('host')!=host or intent.get('correlationId')!=correlation_id
                    or intent.get('transportMode')!='direct' or old_device is False
                    or not recorded_authority_continuity(session,intent,current.authority,old_device,anchor)):return channel._public()
            sources={'remote':intent['remoteSourceSha256'],'ssh_fresh_nested_channel.py':intent['sourceSha256'],**intent['directSourcePins']}
            if set(intent['directSourcePins'])!=set(source_catalog(version)):return channel._public()
            capsules={}
            for name,digest in sources.items():
                if name!='remote' and (not name.endswith('.py') or Path(name).name!=name):return channel._public()
                capsule=stack.enter_context(private.Snapshot(directory,correlation_id+'.'+name+'.source'))
                if capsule.digest!=digest:return channel._public()
                capsules[name]=capsule
            config=current.config;target=config.hosts[host];gateway=transport.connection_host(config,target.gateway)
            prefix,endpoint=outer_prefix(config,gateway)
            argv=[*prefix,*OUTER_OPTIONS,'-T',endpoint,
                  __import__('shlex').join(('python3','-I','-B','-c','exec('+repr(capsules['remote'].body.decode())+')',
                        correlation_id,'status',str(target.remote_config_file or ''),target.remote_host_alias,intent['sourceSha256']))]
            current.guard();held.guard();config_snapshot.guard()
            captured=channel._collect(argv,b'{}',35)
            current.guard();presented.guard();ownership.guard()
            for capsule in capsules.values():capsule.guard()
            if (not captured['complete'] or captured['overflow'] or captured['returnCode']!=0 or captured['stderr']):return channel._public()
            value=json.loads(captured['stdout'],object_pairs_hook=transport._reject_duplicate_keys)
            prior=receipt['result'] if receipt is not None else None
            # A READY original whose stage vanished with a gateway reboot ended
            # positively; its terminal keeps the READY boot it ended under.
            rebooted=channel.gateway_reboot_end(value,correlation_id,prior) if prior is not None else None
            if (set(value)!={'state','correlationId','prior','gatewayBoot'} or value.get('state')!='ended'
                    or value.get('correlationId')!=correlation_id or (rebooted is None and value.get('prior')!=prior)
                    or type(value.get('gatewayBoot'))is not str
                    or re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',value['gatewayBoot'])is None):return channel._public()
            if prior is not None and rebooted is None and prior['master']['gatewayBoot']!=value['gatewayBoot']:return channel._public()
            terminal={'state':'ended','correlationId':correlation_id,'receiptSha256':ready.digest if ready else None,
                      'intentSha256':held.digest,'gatewayBoot':rebooted['readyGatewayBoot'] if rebooted is not None else value['gatewayBoot']}
            closed=channel.close_ended(stack,directory,correlation_id,terminal,rebooted,ready.digest if ready else None)
            if closed is None:return channel._public()
            current.guard();held.guard();config_snapshot.guard()
            if ready is not None:ready.guard()
            for part in closed:part.guard()
            return channel._public('ended',correlationId=correlation_id)
    except (OSError,ValueError,KeyError,TypeError,session.SessionUnknown):return channel._public()
