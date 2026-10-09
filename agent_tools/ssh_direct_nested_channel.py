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
from . import ssh_transport as transport

MODE='direct'
OUTER_OPTIONS=('-S','none','-o','ControlMaster=no','-o','ControlPersist=no')
_SOURCE_NAMES=('ssh_direct_nested_channel.py','ssh_fresh_nested_channel.py',
 'ssh_transport.py','ssh_connection_session.py','ssh_connection_recovery.py',
 'private_inventory_lock.py','native_review_source_closure.py','check_output_retention.py',
 'ssh_nested_socket_owned_home_observation.py','ssh_nested_socket_noninteractive_observation.py',
 'ssh_nested_socket_retirement.py','ssh_nested_socket_route_diagnostic.py',
 'ssh_recovery_adoption.py','ssh_channel_inventory_diagnostics.py',
 'ssh_channel_selection.py','mcp_server.py')


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
    def __init__(self,root):
        session,channel,_Held=_dependencies();self.session=session
        self.root=Path(root).resolve(strict=True);self.held=_Held();self.closed=False
        try:
            self.config,self.outer,self.authority=session._snapshot(self.root,channel.HOST)
            self.authority_sha=hashlib.sha256(session._json(self.authority)).hexdigest()
            self.source_pins={}
            for name in _SOURCE_NAMES:
                path=Path(__file__).with_name(name)
                # File names are fixed source members, never caller paths. The
                # held read verifies regular/owner/full bytes and ancestry; it
                # is repeated before transport and after raw capture retention.
                digest=hashlib.sha256(path.read_bytes()).hexdigest()
                self.held.read(str(path),digest)
                self.source_pins[name]=digest
            config_path=transport._private_config_path(self.root)
            self.held.read(str(config_path),self.authority['configSha256'])
            for row in self.authority['files']:self.held.read(row['path'],row['sha256'])
            self.guard()
        except BaseException:self.close();raise
    def guard(self):
        self.held.finish();self.held.final_identity_pass()
        config,outer,authority=self.session._snapshot(self.root,'archlinux')
        if authority!=self.authority or asdict(config)!=asdict(self.config):raise ValueError('generation')
        self.held.finish();self.held.final_identity_pass()
    def close(self):
        if not self.closed:self.held.close();self.closed=True
    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def outer_prefix(config,gateway):
    # Build the actual configured direct gateway alias, not the selected Arch
    # route. Exact local config/key/source guards are held by the caller.
    if gateway.transport!='direct' or gateway.password is not None:raise ValueError('route')
    argv=transport.build_ssh_argv(config,gateway.alias,30,command=('true',))
    return [argv[0],'-F','/dev/null',*argv[1:-2]],argv[-2]


def prepare(root,host,correlation_id,*,_private_capture=None):
    if not coordinator_capable():return _unsupported()
    session,channel,_Held=_dependencies()
    return channel._operate(root,host,correlation_id,True,_private_capture,direct=True)


def status(root,host,correlation_id,*,_private_capture=None):
    if not coordinator_capable():return _unsupported()
    session,channel,_Held=_dependencies()
    return channel._operate(root,host,correlation_id,False,_private_capture,direct=True)


def route_options(root,host,correlation_id,receipt_sha256):
    session,channel,_Held=_dependencies()
    channel._corr(correlation_id)
    if host!=channel.HOST or type(receipt_sha256)is not str or re.fullmatch('[0-9a-f]{64}',receipt_sha256)is None:raise ValueError('receipt')
    result=status(root,host,correlation_id)
    if result.get('state')!='ready':
        refusal={**result,'correlationId':correlation_id} if result.get('state')=='unknown' else channel._public(correlationId=correlation_id)
        raise channel.ChannelUnknown(refusal)
    if result.get('receiptSha256')!=receipt_sha256:raise ValueError('receipt')
    return {'transportMode':MODE,'correlationId':correlation_id,'receiptSha256':receipt_sha256,
            'outerAuthoritySha256':result['outerAuthoritySha256'],'outerOptions':OUTER_OPTIONS,
            'innerOptions':('-S','/tmp/vpn-channel-'+correlation_id+'/m',
                '-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=false')}
