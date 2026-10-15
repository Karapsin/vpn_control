"""One fixed SSH-G observation of the consumed orphan observer's failure.

No -T repair, getter retry, credential read, socket archive or connection launch
is performed. Exact SSH stdout/stderr are private diagnostic data, never a public
result. A new correlation directory is a create-only observation fence.
"""
from __future__ import annotations
import base64
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
from contextlib import ExitStack
from agent_tools import ssh_nested_socket_retirement as frozen
from agent_tools import ssh_transport as transport, ssh_recovery_adoption as adoption, ssh_connection_session as session
from agent_tools.private_inventory_lock import Directory,Snapshot,InventoryLock,lock_directory

generation=frozen.generation
parent_guard=frozen.parent_guard
file_pin=frozen.file_pin
ssh_options=frozen.ssh_options
FROZEN_SHA='356985224da09aa4306e0c018b5afd92a86f018312df34bc68685d7da6188731'
FAILED='eba7f274-4278-43f9-9630-0600e13982e4'
FAILED_PINS={
 'stdout':{'generation':[16777234,111540716,33152,503,20,1,0,1791023979874286317,1791023979874286317],'bytes':0,'sha256':'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'},
 'stderr':{'generation':[16777234,111540717,33152,503,20,1,1053,1791023979874435443,1791023979874435443],'bytes':1053,'sha256':'e43d029ca089c66e64a28541da7170926a0e9ae42375179c2d3f655922c038bc'}}
WARNING=b'Pseudo-terminal will not be allocated because stdin is not a terminal.\r\n'


def captured(body):
    return {'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'base64':base64.b64encode(body).decode()}


def diagnose_remote(spec):
    config=file_pin(spec['configFile'],body=True)
    if config['unsupportedConfigDirectives']:raise ValueError('config_dependency_unsupported')
    argv=[*ssh_options(spec),'-G',spec['remoteHostAlias']]
    result=subprocess.run(argv,capture_output=True,timeout=5)
    if len(result.stdout)>65536 or len(result.stderr)>8192:raise ValueError('route_diagnostic_capture_unbounded')
    if file_pin(spec['configFile'],body=True)!=config:raise ValueError('route_config_changed')
    category=('command-failed' if result.returncode!=0 else 'stdout-unavailable' if not result.stdout else
              'exact-nonterminal-warning' if result.stderr in (WARNING,WARNING.replace(b'\r\n',b'\n')) else
              'stderr-present' if result.stderr else 'clean-effective-options')
    return {'schema':1,'state':'fixed-route-diagnostic','returnCode':result.returncode,'category':category,
            'stdout':captured(result.stdout),'stderr':captured(result.stderr),'configPin':config,
            'fixedArgsWithoutTTYOverride':True,'mutationPerformed':False,'observerRetried':False}


def remote_source():
    if file_pin(Path(frozen.__file__),body=True)['sha256']!=FROZEN_SHA:raise ValueError('consumed_observer_changed')
    definitions=(generation,parent_guard,file_pin,ssh_options,captured,diagnose_remote)
    return ('import base64,hashlib,json,os,re,stat,subprocess,sys\nfrom pathlib import Path\nWARNING='+repr(WARNING)+'\n'
            +'\n'.join(inspect.getsource(f) for f in definitions)
            +'\nspec=json.loads(sys.argv[1]);spec["configFile"]=str(Path.home()/".ssh/config") if spec["configFile"]=="~/.ssh/config" else spec["configFile"];'
             'print(json.dumps(diagnose_remote(spec),sort_keys=True,separators=(",",":")))\n')


def diagnose(root: Path|str,host: str,correlation: str) -> dict:
    """Root-only exact fixed SSH-G diagnostic with private create-only receipt."""
    if not isinstance(correlation,str) or not re.fullmatch(r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}',correlation) or correlation==FAILED:
        raise ValueError('new_diagnostic_uuid_required')
    root=Path(root).resolve(strict=True)
    with ExitStack() as stack:
        directory=stack.enter_context(Directory(root));receipts=stack.enter_context(lock_directory(directory));ownership=stack.enter_context(InventoryLock(receipts))
        source=stack.enter_context(Snapshot(directory,transport.CONFIG_FILENAME));stack.source=source
        # Create the new group before pinning historical ancestry. Creation is
        # private local evidence only; native observation remains create-only.
        group=root/'.rag_index/ssh-nested-socket-route-diagnostic';group.mkdir(mode=0o700,exist_ok=True)
        group_directory=stack.enter_context(Directory(group));journal=group/correlation
        journal.mkdir(mode=0o700);output=stack.enter_context(Directory(journal))
        pins={}
        for name,wanted in {**frozen.DEPENDENCIES,'ssh_nested_socket_retirement.py':FROZEN_SHA}.items():
            p=root/'agent_tools'/name;pin=file_pin(p,body=True)
            if pin['sha256']!=wanted:raise ValueError('reviewed_dependency_changed')
            pins[str(p)]=pin
        pins[str(Path(__file__))]=file_pin(Path(__file__),body=True)
        for name,expected in FAILED_PINS.items():
            p=root/'.rag_index/ssh-nested-socket-retirement'/(FAILED+'.'+name);pin=file_pin(p,body=True,private=True)
            if {k:pin[k] for k in ('generation','bytes','sha256')}!=expected:raise ValueError('consumed_failure_changed')
            pins[str(p)]=pin
        config=adoption._validate_candidate(source.body,root);target,binding,histories=frozen._owned_binding(root,config,host,stack)
        spec={'controlPath':str(target.remote_control_path),'remoteHostAlias':target.remote_host_alias,
              'configFile':str(target.remote_config_file) if target.remote_config_file else '~/.ssh/config'}
        remote=remote_source();sha=hashlib.sha256(remote.encode()).hexdigest()
        def guard():
            ownership.guard();source.guard();output.guard();group_directory.guard()
            for h in histories:h.guard()
            for p,pin in pins.items():
                if file_pin(p,body=True,private=p.endswith(('.stdout','.stderr')))!=pin:raise ValueError('diagnostic_source_changed')
        guard()
        intent={'schema':1,'host':host,'correlationId':correlation,'failedCorrelationId':FAILED,'inventory':source.pin(),
                'binding':binding,'inputPins':pins,'remoteSourceSha256':sha,'observerRetried':False,'mutationPerformed':False}
        adoption._write_receipt(output,'intent.json',intent)
        intent_source=stack.enter_context(Snapshot(output,'intent.json'))
        prefix,endpoint=session._outer_prefix(config,transport.connection_host(config,target.gateway))
        argv=[*prefix,'-o','ControlMaster=no','-o','ControlPath=none','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no',endpoint,
              shlex.join(('python3','-I','-B','-c',remote,json.dumps(spec,sort_keys=True)))]
        guard();intent_source.guard();completed=subprocess.run(argv,capture_output=True,timeout=12);guard();intent_source.guard()
        for name,body in (('transport-stdout',completed.stdout),('transport-stderr',completed.stderr)):
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=output.fd)
            with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(output.fd)
        if completed.returncode!=0 or len(completed.stdout)>131072:raise ValueError('route_diagnostic_transport_unknown')
        value=adoption._json(completed.stdout)
        if value.get('state')!='fixed-route-diagnostic' or value.get('mutationPerformed')is not False or value.get('observerRetried')is not False:raise ValueError('route_diagnostic_reply_changed')
        for name,limit in (('stdout',65536),('stderr',8192)):
            cap=value[name];raw=base64.b64decode(cap['base64'],validate=True)
            if len(raw)>limit or cap!=captured(raw):raise ValueError('route_diagnostic_capture_changed')
        proof={'schema':1,'host':host,'correlationId':correlation,'remoteSourceSha256':sha,'result':value,'intent':intent_source.pin()}
        guard();intent_source.guard();pin=adoption._write_receipt(output,'result.json',proof);guard();intent_source.guard()
    return {'ok':True,'state':'fixed-route-diagnostic','category':value['category'],'returnCode':value['returnCode'],
            'stdoutPin':{k:value['stdout'][k] for k in ('bytes','sha256')},'stderrPin':{k:value['stderr'][k] for k in ('bytes','sha256')},
            'correlationId':correlation,'receiptSha256':pin['sha256'],'observerRetried':False,'mutationPerformed':False}
