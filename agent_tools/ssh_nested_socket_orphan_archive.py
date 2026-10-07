"""Archive one proven orphan correlation directory; no recovery or key read.

Root is the sole native operator. Local inventory ownership and this journal's
flock serialize cooperating writers. Full guards observe external drift, but
neither rename nor kernel reads are atomic CAS against arbitrary external actors.
A consumed fence is status-only, including interrupted/unknown effects.
"""
from __future__ import annotations
import ast
import base64
import copy
import ctypes
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from contextlib import ExitStack
from agent_tools import ssh_nested_socket_owned_home_observation as observer
from agent_tools import ssh_nested_socket_retirement as frozen
from agent_tools import ssh_recovery_adoption as adoption,ssh_transport as transport,ssh_connection_session as session
from agent_tools.private_inventory_lock import Directory,Snapshot,InventoryLock,lock_directory

OBSERVER_SHA='9e595d01d4cccc319ed573788ced30ba168a49fe69e2217d50668278c5cde91f'
OBSERVER_REMOTE_SHA='fe13637a9a0386a4490dc96113670c378c10dc577bf5c0d62fe4299c394934fd'
OBSERVATION='0fb841fc-2f24-4eca-ae2b-6cc16f772f28'
PROOF_PIN={'generation':[16777234,111544567,33152,503,20,1,4275,1791026686678654277,1791026686678654277],'size':4275,'sha256':'522ffc5f5f1a9cb6160ffe5b1989c86837b5662ba6fed3fa869b4d9dd1f27069'}
OBS_INTENT_PIN={'generation':[16777234,111544564,33152,503,20,1,17046,1791026686200948882,1791026686200948882],'size':17046,'sha256':'a9b53cd582d99774f593eae2628cb0033157af28d558fde9493f1e789de7f498'}
LOCK_BODY=b'owned-orphan-archive-v1\n'


def _base_source():
    if frozen.file_pin(Path(observer.__file__),body=True)['sha256']!=OBSERVER_SHA:raise ValueError('consumed_observer_source_changed')
    source=observer.remote_source()
    if hashlib.sha256(source.encode()).hexdigest()!=OBSERVER_REMOTE_SHA:raise ValueError('consumed_observer_program_changed')
    marker='spec=json.loads(sys.argv[1]);'
    if source.count(marker)!=1:raise ValueError('observer_entrypoint_changed')
    return source[:source.index(marker)]


# Exact source-closed observer definitions, no entrypoint or native call.
exec(compile(_base_source(),'frozen-orphan-observer-definitions','exec'),globals())


def strict_json(raw):
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate_receipt_key')
            result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique)
    if not isinstance(value,dict):raise ValueError('receipt_object_required')
    return value


def authority(proof):
    if proof.get('state')!='owned-orphan-observed' or proof.get('mutationPerformed')is not False or proof.get('credentialRead')is not False or proof.get('singleOperatorRequired')is not True:
        raise ValueError('positive_orphan_proof_required')
    rounds=proof.get('observations')
    if not isinstance(rounds,list) or len(rounds)!=2:raise ValueError('complete_orphan_rounds_required')
    for round in rounds:
        if not isinstance(round,dict) or set(round)!={'before','check','after'}:raise ValueError('complete_orphan_round_required')
        for name in ('before','after'):
            table=round[name]
            if table.get('completeEOF')is not True or type(table.get('endpointCount'))is not int or table['endpointCount']!=0 or type(table.get('rowCount'))is not int or table['rowCount']<0:
                raise ValueError('kernel_absence_unproven')
        check=round['check']
        if type(check.get('returnCode'))is not int or check['returnCode']!=255 or check.get('exactConnectionRefused')is not True:raise ValueError('exact_refusal_unproven')
    result=copy.deepcopy(proof);result.pop('observations')
    return result


def rewrite_directory_generation(value,before,after):
    # Only exact full metadata for the same controlled directory inode may
    # progress. Other source, socket, namespace and key generations stay exact.
    if isinstance(value,list):
        if value==before:return copy.deepcopy(after)
        return [rewrite_directory_generation(x,before,after) for x in value]
    if isinstance(value,dict):return {k:rewrite_directory_generation(v,before,after) for k,v in value.items()}
    return value


def directory_transition(before,after):
    if before[:5]!=after[:5] or not stat.S_ISDIR(after[2]):raise ValueError('controlled_directory_identity_changed')
    return {'before':before,'after':after,'cooperativeOwnershipOnly':True}


def names(fd):
    result=sorted(os.listdir(fd))
    if len(result)>4096:raise ValueError('directory_listing_unbounded')
    return result


def open_parent(path):
    path=Path(path);chain=[]
    if not path.is_absolute() or '..' in path.parts:raise ValueError('parent_path_unsafe')
    try:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);chain.append((fd,None,generation(os.fstat(fd))))
        for part in path.parts[1:]:
            fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=chain[-1][0]);chain.append((fd,part,generation(os.fstat(fd))))
        info=os.fstat(chain[-1][0])
        if info.st_uid!=os.getuid() or info.st_mode&0o022:raise ValueError('archive_parent_foreign')
        parent_guard(chain);return chain
    except BaseException:
        for fd,_,_ in reversed(chain):os.close(fd)
        raise


def update_parent(chain,before_names,after_names):
    if names(chain[-1][0])!=sorted(after_names):raise ValueError('controlled_parent_names_changed')
    before=chain[-1][2];after=generation(os.fstat(chain[-1][0]));change=directory_transition(before,after)
    added=set(after_names)-set(before_names);removed=set(before_names)-set(after_names)
    # mkdir adds one directory link; same-parent rename leaves it unchanged.
    expected_links=before[5]+(1 if len(added)==1 and not removed else 0)
    if after[5]!=expected_links:raise ValueError('controlled_parent_link_count_changed')
    if generation(os.stat(chain[-1][1],dir_fd=chain[-2][0],follow_symlinks=False))!=after:raise ValueError('controlled_parent_route_changed')
    chain[-1]=(chain[-1][0],chain[-1][1],after);parent_guard(chain)
    change.update(beforeNames=before_names,afterNames=sorted(after_names));return change


def raw_receipt(fd,name):
    before=os.stat(name,dir_fd=fd,follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_uid!=os.getuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=65536:raise ValueError('journal_file_unsafe')
    opened=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
    try:
        pin=generation(before)
        if generation(os.fstat(opened))!=pin:raise ValueError('journal_file_changed')
        chunks=[];length=0
        while True:
            part=os.read(opened,65537-length)
            if not part:break
            chunks.append(part);length+=len(part)
            if length>65536:raise ValueError('journal_file_unbounded')
        raw=b''.join(chunks)
        if len(raw)!=before.st_size or generation(os.fstat(opened))!=pin or generation(os.stat(name,dir_fd=fd,follow_symlinks=False))!=pin:raise ValueError('journal_file_changed')
        return raw,{'generation':pin,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    finally:os.close(opened)


def create_receipt(fd,name,value):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    file=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
    with os.fdopen(file,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    os.fsync(fd)
    actual,pin=raw_receipt(fd,name)
    if actual!=raw:raise ValueError('created_journal_changed')
    return pin


def rename_exclusive(parent_fd,source,destination):
    libc=ctypes.CDLL(None,use_errno=True)
    if sys.platform.startswith('linux'):function=libc.renameat2;flag=1
    elif sys.platform=='darwin':function=libc.renameatx_np;flag=4  # inert Mac regression fixture only
    else:raise ValueError('exclusive_archive_unsupported')
    function.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint];function.restype=ctypes.c_int
    if function(parent_fd,os.fsencode(source),parent_fd,os.fsencode(destination),flag)!=0:raise OSError(ctypes.get_errno(),'exclusive_archive_failed')


def archived_snapshot(parent_fd,destination,original):
    info=os.stat(destination,dir_fd=parent_fd,follow_symlinks=False);before=original['socketSnapshot']['directory'];after=generation(info)
    if before[:8]!=after[:8] or not stat.S_ISDIR(info.st_mode):raise ValueError('archived_directory_changed')
    fd=os.open(destination,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
    try:
        if generation(os.fstat(fd))!=after or names(fd)!=['m']:raise ValueError('archived_contents_changed')
        socket=generation(os.stat('m',dir_fd=fd,follow_symlinks=False))
        if socket!=original['socketSnapshot']['socket']:raise ValueError('archived_socket_changed')
        if generation(os.fstat(fd))!=after or generation(os.stat(destination,dir_fd=parent_fd,follow_symlinks=False))!=after:raise ValueError('archived_directory_raced')
        return {'directory':after,'socket':socket,'contents':['m'],'renameCtimeProgression':{'before':before[8],'after':after[8]}}
    finally:os.close(fd)


def final_guard(spec,expected,chain,journal_fd,pending_pin,lock_pin):
    # Admission calls precede the last descriptor/named source guards. No
    # unrelated call follows this group before the exclusive rename.
    if effective_route(spec)!=expected['effectiveRoute']:raise ValueError('final_effective_route_changed')
    if raw_receipt(journal_fd,'intent.json')[1]!=pending_pin or raw_receipt(journal_fd,'lock')[1]!=lock_pin or names(journal_fd)!=['intent.json','lock']:raise ValueError('final_fence_changed')
    parse_unix_table(read_table(),spec['controlPath'])
    for path,pin in expected['effectiveRoute']['keyMetadata'].items():
        if file_pin(path,private=True)!=pin:raise ValueError('final_key_metadata_changed')
    for path,pin in expected['effectiveRoute'].get('ownedHomePins',{}).items():
        if generation(os.lstat(path))!=pin:raise ValueError('final_home_changed')
    if file_pin(spec['configFile'],body=True)!=expected['remoteConfigPin'] or net_namespace()!=expected['netNamespace'] or socket_snapshot(spec['controlPath'])!=expected['socketSnapshot']:raise ValueError('final_orphan_authority_changed')
    parent_guard(chain)


def journal_status(parent_fd,journal_fd,destination,key,original):
    listing=names(journal_fd)
    if listing==['intent.json','lock']:return {'state':'consumed-unknown','replayAllowed':False,'archivePerformed':'unknown'}
    if listing!=['intent.json','lock','terminal.json']:raise ValueError('journal_history_unknown')
    intent_raw,intent_pin=raw_receipt(journal_fd,'intent.json');intent=strict_json(intent_raw)
    terminal_raw,terminal_pin=raw_receipt(journal_fd,'terminal.json');terminal=strict_json(terminal_raw)
    if intent.get('key')!=key or terminal.get('key')!=key or terminal.get('intentPin')!=intent_pin or terminal.get('state')!='archived' or terminal.get('destination')!=destination:raise ValueError('terminal_binding_changed')
    current=archived_snapshot(parent_fd,destination,original)
    if current!=terminal['archived']:raise ValueError('historical_archive_changed')
    return {'state':'archived','replayAllowed':False,'archivePerformed':True,'terminalPin':terminal_pin,'archived':current,'historicalStatus':True}


def archive_remote(packet):
    if not isinstance(packet,dict) or packet.get('effect')!='archive-owned-orphan-correlation-directory' or packet.get('observationId')!=OBSERVATION:raise ValueError('fixed_archive_admission_required')
    raw=base64.b64decode(packet['observationBase64'],validate=True)
    if len(raw)!=PROOF_PIN['size'] or hashlib.sha256(raw).hexdigest()!=PROOF_PIN['sha256']:raise ValueError('observed_proof_changed')
    wrapped=strict_json(raw)
    if wrapped.get('correlationId')!=OBSERVATION or wrapped.get('intent')!=OBS_INTENT_PIN or wrapped.get('archiveAllowed')is not False or wrapped.get('host')!=packet.get('host'):raise ValueError('observed_proof_binding_changed')
    original=wrapped['result'];expected=authority(original);spec=packet['spec'];path=Path(spec['controlPath'])
    if original['controlPath']!=str(path) or path.name!='m' or not re.fullmatch(r'r-[0-9a-f]{15}',path.parent.name):raise ValueError('fixed_owned_path_changed')
    key=hashlib.sha256((OBSERVATION+PROOF_PIN['sha256']+str(path)).encode()).hexdigest()
    journal_name='.orphan-retire-'+key[:24];destination='.retired-orphan-'+path.parent.name+'-'+key[:16]
    chain=open_parent(path.parent.parent);parent_fd=chain[-1][0];journal_fd=-1;lock=-1
    try:
        listing=names(parent_fd)
        if journal_name in listing:
            journal_fd=os.open(journal_name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
            info=os.fstat(journal_fd)
            if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('journal_directory_foreign')
            lock=os.open('lock',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=journal_fd);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            raw_lock,existing_lock_pin=raw_receipt(journal_fd,'lock')
            if generation(os.fstat(lock))!=existing_lock_pin['generation']:raise ValueError('opened_lock_changed')
            parent_guard(chain)
            if raw_lock!=LOCK_BODY:raise ValueError('journal_lock_changed')
            answer=journal_status(parent_fd,journal_fd,destination,key,original)
            if raw_receipt(journal_fd,'lock')[1]!=existing_lock_pin:raise ValueError('status_lock_changed')
            parent_guard(chain)
            return answer
        if destination in listing:raise ValueError('archive_destination_exists')
        parent_guard(chain)
        first=observe_remote(spec)
        if authority(first)!=expected:raise ValueError('original_orphan_authority_changed')
        parent_guard(chain)
        os.mkdir(journal_name,0o700,dir_fd=parent_fd);os.fsync(parent_fd)
        transition=update_parent(chain,listing,listing+[journal_name]);expected=rewrite_directory_generation(expected,transition['before'],transition['after'])
        journal_fd=os.open(journal_name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
        lock=os.open('lock',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=journal_fd)
        os.write(lock,LOCK_BODY);os.fsync(lock);os.fsync(journal_fd);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        lock_raw,lock_pin=raw_receipt(journal_fd,'lock')
        if lock_raw!=LOCK_BODY or generation(os.fstat(lock))!=lock_pin['generation']:raise ValueError('opened_lock_changed')
        pending={'schema':1,'key':key,'state':'pending','packetSha256':hashlib.sha256(json.dumps(packet,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                 'observationSha256':PROOF_PIN['sha256'],'effect':packet['effect'],'sourceSha256':packet['archiveSourceSha256'],
                 'destination':destination,'originalProof':original,'parentTransition':transition,'cooperativeOwnershipOnly':True}
        pending_pin=create_receipt(journal_fd,'intent.json',pending)
        # All kernel/refusal/route/home checks repeat under the durable fence.
        second=observe_remote(spec)
        if authority(second)!=expected:raise ValueError('fenced_orphan_authority_changed')
        if raw_receipt(journal_fd,'intent.json')[1]!=pending_pin or raw_receipt(journal_fd,'lock')[0]!=LOCK_BODY or names(journal_fd)!=['intent.json','lock']:raise ValueError('pending_fence_changed')
        if names(parent_fd)!=sorted(listing+[journal_name]):raise ValueError('archive_parent_names_changed')
        # Final source/path guards immediately precede exclusive rename. This
        # is cooperative ownership, not an arbitrary-external-writer CAS.
        final_guard(spec,expected,chain,journal_fd,pending_pin,lock_pin)
        rename_exclusive(parent_fd,path.parent.name,destination)
        os.fsync(parent_fd)
        after=update_parent(chain,listing+[journal_name],[n for n in listing if n!=path.parent.name]+[journal_name,destination])
        archived=archived_snapshot(parent_fd,destination,original)
        try:os.stat(path.parent.name,dir_fd=parent_fd,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise ValueError('original_directory_not_absent')
        if net_namespace()!=original['netNamespace']:raise ValueError('postarchive_namespace_changed')
        post_tables=[parse_unix_table(read_table(),str(path)),parse_unix_table(read_table(),str(path.parent.parent/destination/'m'))]
        if raw_receipt(journal_fd,'intent.json')[1]!=pending_pin:raise ValueError('postarchive_intent_changed')
        parent_guard(chain)
        terminal={'schema':1,'key':key,'state':'archived','intentPin':pending_pin,'destination':destination,'archived':archived,
                  'archiveParentTransition':after,'postArchiveTables':post_tables,'postArchiveNamespace':original['netNamespace'],'archivePerformed':True,'replayAllowed':False}
        create_receipt(journal_fd,'terminal.json',terminal)
        return journal_status(parent_fd,journal_fd,destination,key,original)
    finally:
        if lock>=0:os.close(lock)
        if journal_fd>=0:os.close(journal_fd)
        for fd,_,_ in reversed(chain):os.close(fd)


def remote_source():
    functions=(strict_json,authority,rewrite_directory_generation,directory_transition,names,open_parent,update_parent,raw_receipt,create_receipt,rename_exclusive,archived_snapshot,final_guard,journal_status,archive_remote)
    return (_base_source()+'\nimport base64,copy,ctypes,fcntl\nOBSERVATION='+repr(OBSERVATION)+'\nPROOF_PIN='+repr(PROOF_PIN)+'\nOBS_INTENT_PIN='+repr(OBS_INTENT_PIN)+'\nLOCK_BODY='+repr(LOCK_BODY)+'\n'
            +'\n'.join(inspect.getsource(f) for f in functions)
            +'\npacket=strict_json(sys.argv[1]);packet["spec"]["configFile"]=str(Path.home()/".ssh/config") if packet["spec"]["configFile"]=="~/.ssh/config" else packet["spec"]["configFile"];\n'
             'try: print(json.dumps(archive_remote(packet),sort_keys=True,separators=(",",":")))\n'
             'except Exception as error: print(json.dumps({"state":"consumed-unknown","replayAllowed":False,"errorType":type(error).__name__}));raise SystemExit(2)\n')


def _key(host):
    return hashlib.sha256((host+OBSERVATION+PROOF_PIN['sha256']).encode()).hexdigest()


def completed_remote(value,original):
    if not isinstance(value,dict) or value.get('state')!='archived' or value.get('replayAllowed')is not False or value.get('archivePerformed')is not True or value.get('historicalStatus')is not True:return False
    try:
        pin=value['terminalPin'];archived=value['archived'];before=original['socketSnapshot']['directory']
        if set(pin)!={'generation','bytes','sha256'} or not isinstance(pin['generation'],list) or len(pin['generation'])!=9 or any(type(x)is not int for x in pin['generation']) or type(pin['bytes'])is not int or pin['bytes']<=0 or pin['generation'][6]!=pin['bytes'] or not re.fullmatch(r'[0-9a-f]{64}',pin['sha256']):return False
        if set(archived)!={'directory','socket','contents','renameCtimeProgression'} or archived['contents']!=['m'] or archived['socket']!=original['socketSnapshot']['socket'] or archived['directory'][:8]!=before[:8] or len(archived['directory'])!=9:return False
        if archived['renameCtimeProgression']!={'before':before[8],'after':archived['directory'][8]}:return False
        return True
    except (KeyError,TypeError,IndexError):return False


def status(root,host):
    root=Path(root).resolve(strict=True);journal=root/'.rag_index/ssh-nested-socket-orphan-archive'/_key(host)
    try:
        with Directory(journal) as d,Snapshot(d,'intent.json') as intent,Snapshot(d,'result.json') as result,Snapshot(d,'anchor.json') as anchor:
            iv=adoption._json(intent.body);rv=adoption._json(result.body);av=adoption._json(anchor.body)
            if iv['host']!=host or iv['observationId']!=OBSERVATION or av!={'intent':intent.pin(),'result':result.pin()} or rv.get('intent')!=intent.pin():raise ValueError('local_terminal_binding_changed')
            own=iv['observerArchiveSource'];current=frozen.file_pin(Path(__file__),body=True)
            if any(current[k]!=own[k] for k in ('generation','bytes','sha256')):raise ValueError('consumed_archive_source_changed')
            intent.guard();result.guard();anchor.guard()
            original=strict_json(base64.b64decode(iv['packet']['observationBase64'],validate=True))['result']
            complete=completed_remote(rv.get('remote'),original)
            return {'ok':complete,'state':'archived' if complete else 'consumed-unknown','replayAllowed':False,'historicalStatus':True,'remoteRevalidated':False,'archivePerformed':complete}
    except (OSError,ValueError,KeyError):return {'ok':False,'state':'consumed-unknown','replayAllowed':False,'historicalStatus':True}


def archive(root,host):
    root=Path(root).resolve(strict=True)
    if host!='archlinux':raise ValueError('fixed_observed_host_required')
    with ExitStack() as stack:
        d=stack.enter_context(Directory(root));receipts=stack.enter_context(lock_directory(d));ownership=stack.enter_context(InventoryLock(receipts));source=stack.enter_context(Snapshot(d,transport.CONFIG_FILENAME));stack.source=source
        group=root/'.rag_index/ssh-nested-socket-orphan-archive';group.mkdir(mode=0o700,exist_ok=True);group_directory=stack.enter_context(Directory(group));journal=group/_key(host)
        try:journal.mkdir(mode=0o700)
        except FileExistsError:return status(root,host)
        output=stack.enter_context(Directory(journal));proof_dir=stack.enter_context(Directory(root/'.rag_index/ssh-nested-socket-owned-home-observation'/OBSERVATION))
        proof=stack.enter_context(Snapshot(proof_dir,'result.json'));old_intent=stack.enter_context(Snapshot(proof_dir,'intent.json'))
        if proof.pin()!=PROOF_PIN or old_intent.pin()!=OBS_INTENT_PIN:raise ValueError('consumed_orphan_proof_changed')
        pv=adoption._json(proof.body);iv=adoption._json(old_intent.body)
        if pv['intent']!=old_intent.pin() or pv['archiveAllowed']is not False or iv['archiveAllowed']is not False or pv['correlationId']!=OBSERVATION or iv['correlationId']!=OBSERVATION or iv['host']!=host or pv['host']!=host or source.pin()!=iv['inventory']:raise ValueError('orphan_proof_route_changed')
        authority(pv['result']);pins={}
        for path,old in iv['inputPins'].items():
            pin=frozen.file_pin(path,body=True,private=path.endswith(('.stdout','.stderr')))
            if any(pin[k]!=old[k] for k in ('generation','bytes','sha256')):raise ValueError('historical_orphan_source_changed')
            pins[path]=pin
        own=frozen.file_pin(Path(__file__),body=True);pins[str(Path(__file__))]=own
        config=adoption._validate_candidate(source.body,root);target,binding,histories=frozen._owned_binding(root,config,host,stack)
        if binding!=iv['binding']:raise ValueError('orphan_ownership_changed')
        script=remote_source();sha=hashlib.sha256(script.encode()).hexdigest()
        packet={'effect':'archive-owned-orphan-correlation-directory','observationId':OBSERVATION,'host':host,'observationBase64':base64.b64encode(proof.body).decode(),'archiveSourceSha256':sha,
                'spec':{'controlPath':str(target.remote_control_path),'remoteHostAlias':target.remote_host_alias,'configFile':str(target.remote_config_file) if target.remote_config_file else '~/.ssh/config'}}
        def guard():
            ownership.guard();source.guard();proof.guard();old_intent.guard();group_directory.guard();output.guard()
            for h in histories:h.guard()
            for path,pin in pins.items():
                if frozen.file_pin(path,body=True,private=path.endswith(('.stdout','.stderr')))!=pin:raise ValueError('archive_authority_changed')
        guard()
        request={'schema':1,'host':host,'observationId':OBSERVATION,'observationPin':PROOF_PIN,'observationIntentPin':OBS_INTENT_PIN,'inventory':source.pin(),'inputPins':pins,'binding':binding,
                 'effect':packet['effect'],'remoteSourceSha256':sha,'observerArchiveSource':own,'packet':packet,'cooperativeOwnershipOnly':True}
        adoption._write_receipt(output,'intent.json',request);request_source=stack.enter_context(Snapshot(output,'intent.json'))
        prefix,endpoint=session._outer_prefix(config,transport.connection_host(config,target.gateway))
        argv=[*prefix,'-o','ControlMaster=no','-o','ControlPath=none','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no',endpoint,shlex.join(('python3','-I','-B','-c',script,json.dumps(packet,sort_keys=True)))]
        guard();request_source.guard();completed=subprocess.run(argv,capture_output=True,timeout=45);guard();request_source.guard()
        for name,body in (('stdout',completed.stdout),('stderr',completed.stderr)):
            fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=output.fd)
            with os.fdopen(fd,'wb') as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
        os.fsync(output.fd)
        try:remote=adoption._json(completed.stdout) if len(completed.stdout)<=16384 else {'state':'consumed-unknown'}
        except ValueError:remote={'state':'consumed-unknown'}
        if completed.returncode!=0:remote={'state':'consumed-unknown'}
        result={'schema':1,'intent':request_source.pin(),'remote':remote,'remoteSourceSha256':sha,'replayAllowed':False}
        guard();request_source.guard();adoption._write_receipt(output,'result.json',result)
        with Snapshot(output,'result.json') as result_source:adoption._write_receipt(output,'anchor.json',{'intent':request_source.pin(),'result':result_source.pin()})
        guard();request_source.guard()
    return status(root,host)
