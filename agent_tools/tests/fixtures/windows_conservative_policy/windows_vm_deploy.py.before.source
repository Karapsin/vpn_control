"""Input-driven Windows VM operations over saved, hash-checked programmes.

Only this module's finite producers may execute. No public command/source-body
argument, old channel adoption, old VM path, or instance-specific UID is used.
"""
from __future__ import annotations
import ast,hashlib,inspect,json,os,re,secrets,shlex,stat,subprocess,time,uuid
from dataclasses import replace
from contextlib import ExitStack
from .private_credential_file import SecretFile
from pathlib import Path
from .native_vm_spec import FreshWindowsVmSpec,VmSpecError
from . import ssh_source_file_stage as files,ssh_source_file_stage_direct as stage
from . import ssh_direct_nested_channel as direct,ssh_transport as transport


def _gateway_private_capture(custody):
    # Private stdin may be echoed by an unhealthy child. Never persist or hash
    # those streams, including partial output after a timeout or overflow.
    return {'retention':'metadata-only','counts':dict(custody.counts),
            'eof':dict(custody.eof),'credentialSent':custody.sent}


def _gateway_echo_free(raw,protected):
    import base64,binascii
    def check(data):
        if any(secret in data for secret in protected):raise ValueError('private_output_refused')
    check(raw)
    # A QGA/input-envelope echo may contain a base64 encoded payload. Decode
    # only bounded candidates in memory; none of these bytes acquire a hash.
    for token in re.findall(rb'[A-Za-z0-9+/_=-]{16,}',raw):
        if len(token)>CAP:raise ValueError('private_output_refused')
        try:decoded=base64.b64decode(token,validate=True)
        except (ValueError,binascii.Error):continue
        check(decoded)
    try:value=json.loads(raw,object_pairs_hook=reject_pairs)
    except (ValueError,UnicodeError):raise ValueError('private_output_refused') from None
    check(json.dumps(value,ensure_ascii=False).encode())
    return value


def _gateway_payload_result(value,response):
    # Credential-bearing operations have deliberately small public receipts.
    # Reject unrecognized fields before a gateway byte can enter local capture.
    import uuid
    mode=response['mode'];identifier=response['deploymentId'];operation=response['operationId']
    base={'schemaVersion','deploymentId','mode','state','reason','nativeActionAllowed','replayAllowed'}
    if (type(value)is not dict or value.get('deploymentId')!=identifier or value.get('mode')!=mode
            or value.get('replayAllowed')is not False):raise ValueError('private_result_refused')
    state=value.get('state')
    if mode=='secure-continue':
        keys={'state','operationId','productReady','deploymentId','mode','replayAllowed'}
        if state=='secured-observed':keys|={'setupSecured'}
        if state=='unknown':
            keys={'state','deploymentId','mode','operationId','reason','replayAllowed'}
            if value.get('reason')not in response['checks']:raise ValueError('private_result_refused')
        elif state not in ('secured-observed','secure-pending') or value.get('productReady')is not False:raise ValueError('private_result_refused')
    else:
        if(type(value.get('schemaVersion'))is not int or value['schemaVersion']!=1
                or value.get('nativeActionAllowed')is not False):raise ValueError('private_result_refused')
        if state=='blocked':
            keys=base
            if value.get('reason')not in PUBLIC_BLOCKERS:raise ValueError('private_result_refused')
        elif state=='unknown':
            keys=base|{'failurePhase','failureClass','failureCheck'}
            if(value.get('reason')!='instance_effect_or_observation_unknown'
                    or value.get('failurePhase')not in ('resources','principal','preflight','media','credentials','create','firmware','disk','seed','tpm','qemu','first-boot','observation','qualification','secure')
                    or value.get('failureClass')not in ('OSError','ValueError','KeyError','TypeError','SubprocessError')
                    or value.get('failureCheck')is not None and value['failureCheck']not in response['checks']):raise ValueError('private_result_refused')
        elif mode=='start' and state=='booted-observed':
            keys=base|{'qemu','swtpm','qemuStatus','guestAgentReady','ordinarySessionObserved','osName','productReady'}
            for name in ('qemu','swtpm'):
                row=value.get(name)
                if type(row)is not dict or set(row)!={'pid','startTicks'}or any(type(x)is not int or x<=0 for x in row.values()):raise ValueError('private_result_refused')
            if(value.get('qemuStatus')not in ('running','paused','prelaunch','shutdown','suspended','inmigrate','postmigrate','finish-migrate','restore-vm','save-vm','internal-error','io-error','watchdog','guest-panicked','colo')
                    or any(type(value.get(k))is not bool for k in ('guestAgentReady','ordinarySessionObserved'))
                    or value.get('osName')is not None and(type(value['osName'])is not str or not 0<len(value['osName'])<=256)
                    or value.get('productReady')is not False):raise ValueError('private_result_refused')
            # Exact OS text is collected by separate qualification. The one
            # secret-bearing first boot returns no unconstrained guest string.
            value=dict(value);value['osName']=None
        elif mode=='secure' and state in ('secure-pending','secured-observed'):
            keys=base|{'operationId','productReady'}|({'setupSecured'}if state=='secured-observed'else set())
            if value.get('productReady')is not False:raise ValueError('private_result_refused')
        else:raise ValueError('private_result_refused')
        if state not in ('unknown','blocked')and value.get('reason')is not None:raise ValueError('private_result_refused')
    if set(value)!=keys:raise ValueError('private_result_refused')
    if 'operationId'in value:
        if value['operationId']!=operation or str(uuid.UUID(value['operationId']))!=operation:raise ValueError('private_result_refused')
    if state=='secured-observed'and value.get('setupSecured')is not True:raise ValueError('private_result_refused')
    return value


def _gateway_main():
    custody=None;secret_bytes=None;protected=[]
    try:
        corr,config_file,profile,source_sha=sys.argv[1:]
        if re.fullmatch('[0-9a-f]{32}',corr)is None or source_sha!=_DECODED_SOURCE_SHA:raise ValueError('source_binding')
        request=bounded_envelope(sys.stdin.buffer)
        expected={'passphrase'}|({'sudo'} if PRIVILEGED else set())|({'payload'} if INPUT_PAYLOAD else set())
        if type(request)is not dict or set(request)!=expected:raise ValueError('request_shape')
        secret=request.pop('passphrase')
        if type(secret)is not str or not 0<len(secret.encode())<=512 or any(c in secret for c in ('\r','\n','\0')):raise ValueError('secret_shape')
        spec={'configFile':config_file or str(Path.home()/'.ssh/config'),'controlPath':'none','remoteHostAlias':profile}
        config_pin=file_pin(spec['configFile'],body=True);route_pin=effective_route(spec)
        if config_pin['unsupportedConfigDirectives'] or route_pin['user']!=PRINCIPAL:raise ValueError('route_identity')
        def guard():
            if file_pin(spec['configFile'],body=True)!=config_pin or effective_route(spec)!=route_pin:raise ValueError('config_or_keys_changed')
        guard()
        argv=['ssh','-T','-F',spec['configFile'],'-S','none','-o','ControlMaster=no','-o','ControlPersist=no','-o','ProxyCommand=none','-o','PermitLocalCommand=no','-o','ClearAllForwardings=yes','-o','UpdateHostKeys=no','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-o','BatchMode=no','-o','NumberOfPasswordPrompts=1','-o','IdentityAgent=none','-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','ConnectTimeout=10',profile,COMMAND]
        secret_bytes=secret.encode();protected.append(secret_bytes);custody=start_fixed(argv,secret_bytes,route_pin['keyMetadata']);secret=None
        if PRIVILEGED:
            sudo=request.pop('sudo')
            if type(sudo)is not str or not 0<len(sudo.encode())<=512 or any(c in sudo for c in ('\r','\n','\0')):raise ValueError('sudo_shape')
            protected.append(sudo.encode())
            custody.child.stdin.write(sudo.encode()+b'\n');custody.child.stdin.flush();sudo=None
        if INPUT_PAYLOAD:
            payload=request.pop('payload')
            if type(payload)is not dict:raise ValueError('payload_shape')
            if not payload or any(type(value)is not str or not value for value in payload.values()):raise ValueError('payload_shape')
            protected.extend(value.encode()for value in payload.values())
            raw=json.dumps(payload).encode()
            if not 0<len(raw)<=4096:raise ValueError('payload_bound')
            custody.child.stdin.write(raw);custody.child.stdin.flush();payload=None;raw=None
        custody.child.stdin.close();capture=custody.observe(60)
        if not capture['complete'] or capture['refusal'] or capture['returnCode']!=0:raise ValueError('program_observation_unknown')
        value=_gateway_echo_free(bytes(custody.raw['stdout']),protected)
        _gateway_echo_free(json.dumps({'tty':bytes(custody.raw['tty']).decode('utf8','replace')}).encode(),protected)
        if INPUT_PAYLOAD:value=_gateway_payload_result(value,RESPONSE)
        guard()
        print(json.dumps({'state':'observed','correlationId':corr,'result':value,'capture':capture,'_operatorPrivateCapture':_gateway_private_capture(custody)},sort_keys=True),flush=True)
        return 0
    except BaseException as error:
        print(json.dumps({'state':'unknown','correlationId':locals().get('corr'),'errorClass':type(error).__name__,
                          '_operatorPrivateCapture':_gateway_private_capture(custody) if custody else None},sort_keys=True),flush=True)
        if custody is not None and not custody.closed:custody.finish_naturally()
        return 3
    finally:
        protected.clear()


def gateway_program(receipt,privileged=False,input_payload=False,*,file_output=False,response=None):
    # Reuse the reviewed PTY and authenticated-route helpers as complete source
    # nodes, with the staging entry point excluded. Execution is this producer's
    # filename/hash invocation, never a caller-provided command.
    raw=files.GATEWAY_SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=files.GATEWAY_SHA256:raise ValueError('gateway_source_changed')
    text=raw.decode();tree=ast.parse(text);entry=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='stage_main')
    prefix=''.join(text.splitlines(keepends=True)[:entry.lineno-1])
    if type(privileged)is not bool or type(input_payload)is not bool or type(file_output)is not bool:raise ValueError('gateway_mode')
    if input_payload:
        if(type(response)is not dict or set(response)!={'deploymentId','mode','operationId','checks'}
                or response['mode']not in ('start','secure','secure-continue')
                or type(response['checks'])is not tuple or tuple(sorted(set(response['checks'])))!=response['checks']
                or any(type(s)is not str or re.fullmatch('instance_[a-z_]{1,64}',s)is None for s in response['checks'])
                or type(response['deploymentId'])is not str or str(uuid.UUID(response['deploymentId']))!=response['deploymentId']
                or response['mode']=='start'and response['operationId']is not None
                or response['mode']!='start'and(type(response['operationId'])is not str or str(uuid.UUID(response['operationId']))!=response['operationId'])):raise ValueError('gateway_response_binding')
    elif response is not None:raise ValueError('gateway_response_binding')
    loader=stage.loader_program(receipt['uid']) if privileged else stage.LOADER
    command=shlex.join((*(['/usr/bin/sudo','-k','-S','-p','','--'] if privileged else []),'/usr/bin/python3' if privileged else 'python3','-I','-B','-c',loader,receipt['path'],receipt['sha256'],str(receipt['bytes'])))
    if len(command.encode())>60000:raise ValueError('saved_command_bound')
    from .windows_vm_deploy_remote import _REASONS
    body=prefix+('\nCAP=5242880\n' if file_output else '')+'\nPRIVILEGED='+repr(privileged)+'\nINPUT_PAYLOAD='+repr(input_payload)+'\nCOMMAND='+repr(command)+'\nPRINCIPAL='+repr(receipt['principal'])+'\nRESPONSE='+repr(response)+'\nPUBLIC_BLOCKERS='+repr(tuple(sorted(_REASONS)))+'\n'+''.join(inspect.getsource(f)+'\n'for f in (_gateway_private_capture,_gateway_echo_free,_gateway_payload_result,_gateway_main))+"\nif __name__=='__main__':sys.exit(_gateway_main())\n"
    compile(body,'saved Windows VM gateway','exec');return body.encode()


def _runtime_group(root,name):
    runtime=root/'.runtime';runtime.mkdir(mode=0o700,exist_ok=True)
    if runtime.is_symlink() or runtime.stat().st_uid!=os.getuid() or runtime.stat().st_mode&0o022:raise ValueError('deployment_runtime_parent')
    group=runtime/name;group.mkdir(mode=0o700,exist_ok=True)
    if group.is_symlink() or group.stat().st_uid!=os.getuid() or group.stat().st_mode&0o077:raise ValueError('deployment_journal_owner')
    return group


def _retain_sources(directory,paths,guard):
    """Retain actual beforeimages before transport or VM effects, never secrets."""
    target=directory/'sources';target.mkdir(mode=0o700);records=[];total=0
    for path in dict.fromkeys(paths):
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            before=os.fstat(descriptor);limit=files.MAX_SOURCE_BYTES if path.name=='caller.py' else 2*1024**2
            if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=limit:raise ValueError('deployment_source_capsule_bound')
            chunks=[];size=0
            while True:
                block=os.read(descriptor,min(65536,limit+1-size))
                if not block:break
                chunks.append(block);size+=len(block)
                if size>limit:raise ValueError('deployment_source_capsule_bound')
            generation=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_uid,v.st_gid,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
            if size!=before.st_size or generation(os.fstat(descriptor))!=generation(before) or generation(os.stat(path,follow_symlinks=False))!=generation(before):raise ValueError('deployment_source_capsule_changed')
            raw=b''.join(chunks);total+=size
            if total>32*1024**2:raise ValueError('deployment_source_capsule_bound')
            stage._retain(target,path.name,raw)
            records.append({'name':path.name,'sourcePath':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':size,'generation':generation(before)})
        finally:os.close(descriptor)
    guard.guard();stage._retain(target,'manifest.json',{'schemaVersion':1,'sources':records,'sourceClosingBeforeTransfer':True})


def _execute(root,spec,mode,*,credential_file=None,setup=None,context=None,payload=None,before_submit=None,operation_id=None):
    """Save the entire fixed producer before transfer; never replay a start."""
    if not direct.coordinator_capable():raise ValueError('unsupported_deployment_coordinator')
    # An already consumed mutation is a local refusal, even when its transport
    # is unavailable. Keep the later atomic admission check as the race fence.
    groups={'host-policy-apply':'windows-vm-host-policy','start':'windows-vm-deploy-intents',
            'stop':'windows-vm-deploy-stops','secure':'windows-vm-deploy-secure'}
    if mode in groups:
        claims=Path(root).resolve(strict=True)/'.rag_index'/groups[mode]
        if os.path.lexists(claims):
            info=claims.lstat()
            if not stat.S_ISDIR(info.st_mode)or info.st_uid!=os.getuid()or info.st_mode&0o077:raise ValueError('policy_claim_owner')
            if os.path.lexists(claims/(spec.deployment_id+'.intent.json')):raise ValueError('policy_original_exists')
    from . import readiness
    # Resource peer census calls this helper for each actual trusted alias,
    # including aliases outside the enclosing public workflow's initial route.
    # Transport repair is independent of guest power, sessions and desktops.
    with transport.admitted_transport(root,spec.host,operation_id or spec.deployment_id,
            deadline=time.monotonic()+180,
            requirements=readiness.Requirements(frozenset({'transport'}),frozenset({'reconnect'})))as admission:
        admission.revalidate()
        return _execute_admitted(root,spec,mode,credential_file=credential_file,setup=setup,context=context,
            payload=payload,before_submit=before_submit,operation_id=operation_id,admission=admission)


def _execute_admitted(root,spec,mode,*,credential_file,setup,context,payload,before_submit,operation_id,admission):
    from . import windows_vm_deploy_remote as producer
    from . import windows_vm_media as media
    root=Path(root).resolve(strict=True);corr=uuid.uuid4().hex
    file_output=mode in ('media','frame','frame-collect')
    group=_runtime_group(root,'windows-vm-deploy')
    directory=group/corr;directory.mkdir(mode=0o700)
    privileged=mode in ('host-policy-apply','host-resources','start','status','stop','qualify','qualify-status','secure','secure-status')
    # Recovery modes operate as the same configured ordinary principal. Their
    # local and remote O_EXCL fences belong to windows_secure_recovery; password
    # payload remains protected stdin, never command/source/receipt material.
    recovery_mutation=mode=='secure-continue'
    if recovery_mutation and (type(payload)is not dict or set(payload)!={'password'}):raise ValueError('secure_recovery_payload')
    if mode in ('secure-resolve','secure-continue-status')and payload is not None:raise ValueError('secure_recovery_payload')
    mutation=mode in ('host-policy-apply','start','stop','secure')
    if privileged and credential_file is None:raise ValueError('privileged_operation_requires_credential_file')
    media_rows=media.dependency_sources() if mode in ('start','media') else []
    media_reader=media.dependency_capsule(media_rows) if media_rows else None
    caller=producer.program(spec,mode,setup=setup,context=context,media_reader=media_reader,operation_id=operation_id)
    sha=hashlib.sha256(caller).hexdigest()
    stage._retain(directory,'caller.py',caller)
    stage._retain(directory,'request.json',{'spec':spec.as_dict(),'mode':mode,'correlationId':corr,'callerSha256':sha})
    if mutation:
        claim_group={'host-policy-apply':'windows-vm-host-policy','start':'windows-vm-deploy-intents','stop':'windows-vm-deploy-stops','secure':'windows-vm-deploy-secure'}[mode]
        claims=root/'.rag_index'/claim_group;claims.mkdir(mode=0o700,exist_ok=True)
        if claims.is_symlink() or claims.stat().st_uid!=os.getuid() or claims.stat().st_mode&0o077:raise ValueError('policy_claim_owner')
        if os.path.lexists(claims/(spec.deployment_id+'.intent.json')):raise ValueError('policy_original_exists')
    with direct.Guard(root,host=spec.host) as guard,ExitStack() as secrets:
        if privileged:credential=secrets.enter_context(SecretFile(credential_file))
        paths=[Path(__file__),Path(producer.__file__),Path(stage.__file__),Path(files.__file__),Path(__file__).with_name('native_vm_spec.py'),Path(__file__).with_name('arch_package_integrity.py'),Path(__file__).with_name('private_credential_file.py'),Path(__file__).with_name('source_module_loader.py'),files.GATEWAY_SOURCE,directory/'caller.py']
        if mode=='host-resources':paths.extend(Path(__file__).with_name(name+'.py') for name in ('windows_vm_resources','native_host_observation','ssh_tmux_resource_admission'))
        if mode in ('start','status','stop','qualify','qualify-status','secure','secure-status'):paths.extend(Path(__file__).with_name(name+'.py') for name in ('windows_vm_resources','native_host_observation','ssh_tmux_resource_admission','windows_vm_unattend','windows_vm_instance','windows_vm_hardware','windows_vm_lifecycle','native_environment'))
        if mode in ('secure-resolve','secure-continue','secure-continue-status'):paths.extend(Path(__file__).with_name(name+'.py') for name in ('windows_secure_recovery','windows_vm_guest','windows_guest_input','windows_vm_instance'))
        if mode in ('qualify','qualify-status','secure','secure-status'):paths.extend(Path(__file__).with_name(name+'.py') for name in ('windows_vm_guest','windows_guest_input'))
        if mode in ('frame','frame-collect'):paths.extend(Path(__file__).with_name(name+'.py') for name in ('windows_vm_instance','windows_vm_unattend'))
        if media_rows:paths.append(Path(media.__file__))
        for path in paths:
            guard.held.read(str(path),hashlib.sha256(path.read_bytes()).hexdigest())
        for _,path,raw in media_rows:guard.held.read(str(path),hashlib.sha256(raw).hexdigest())
        _retain_sources(directory,[*paths,*(path for _,path,_ in media_rows),*(Path(direct.__file__).with_name(name) for name in direct._SOURCE_NAMES),Path(stage.capture_module.__file__)],guard)
        admission.revalidate()
        receipt=stage.publish(root,spec.host,str(directory/'caller.py'),sha,corr)
        if receipt.get('state')!='staged':raise ValueError('deployment_program_not_staged')
        response=({'deploymentId':spec.deployment_id,'mode':mode,'operationId':operation_id,
                   'checks':tuple(sorted({n.value for n in ast.walk(ast.parse(caller))
                       if isinstance(n,ast.Constant)and type(n.value)is str and re.fullmatch('instance_[a-z_]{1,64}',n.value)}))}if payload is not None else None)
        gateway=gateway_program(receipt,privileged=privileged,input_payload=payload is not None,file_output=file_output,response=response);gateway_sha=hashlib.sha256(gateway).hexdigest()
        stage._retain(directory,'gateway.py',gateway)
        guard.held.read(str(directory/'gateway.py'),gateway_sha)
        target=guard.config.hosts[spec.host];connection=transport.connection_host(guard.config,target.gateway)
        prefix,endpoint=direct.outer_prefix(guard.config,connection)
        outer_corr=uuid.uuid4().hex
        argv=[*prefix,*direct.OUTER_OPTIONS,'-T','-o','ClearAllForwardings=yes','-o','PermitLocalCommand=no','-o','UpdateHostKeys=no',endpoint,shlex.join(('python3','-I','-B','-c',files.receiver_program(outer_corr)))]
        admission.revalidate();guard.guard();saved=stage._run(directory,argv,files.source_payload(gateway),'gateway-stage')
        if (saved.get('state')!='staged' or saved.get('bytes')!=len(gateway) or saved.get('sha256')!=gateway_sha
                or saved.get('principal')!=connection.user or saved.get('path')!=stage._stage_path(saved,outer_corr)):raise ValueError('deployment_gateway_not_staged')
        argv[-1]=shlex.join(('python3','-I','-B','-c',stage.LOADER,saved['path'],gateway_sha,str(len(gateway)),outer_corr,str(target.remote_config_file or ''),target.remote_host_alias,gateway_sha))
        secret=target.password
        if type(secret)is not str or not 0<len(secret.encode())<=512 or any(c in secret for c in ('\r','\n','\0')):raise ValueError('deployment_credential_shape')
        request={'passphrase':secret}
        if payload is not None:request['payload']=payload
        if privileged:
            request['sudo']=credential.text;credential.guard()
        if mutation:stage._retain(claims,spec.deployment_id+'.intent.json',{'spec':spec.as_dict(),'setup':setup,'context':context,'correlationId':corr,'mode':mode,'callerSha256':sha})
        if before_submit is not None:before_submit()
        admission.revalidate();guard.guard();value=stage._run(directory,argv,json.dumps(request).encode(),'native',file_output=file_output)
        request.clear()
        if privileged:credential.guard()
        secret=None;streams=value.pop('_operatorPrivateCapture',None)
        if streams is not None:stage._retain(directory,'native-inner-streams.private.json',streams)
        stage._retain(directory,'native-result.json',value);guard.guard()
        if value.get('state')!='observed' or value.get('correlationId')!=outer_corr:raise ValueError('deployment_observation_unknown')
        result=(_materialize_frame(directory,spec,operation_id,value['result']) if mode in ('frame','frame-collect')
                else producer.validate_result(spec,mode,value['result']))
        guard.guard();guard.close();stage._retain(directory,'closing.json',{'sourceClosing':True,'correlationId':corr})
        return result


def preflight(root,request):
    return _execute(root,FreshWindowsVmSpec.parse(request),'preflight')


def installer_media(root,request):
    return _execute(root,FreshWindowsVmSpec.parse(request),'media')


def _materialize_frame(directory,spec,operation_id,result):
    import base64
    if type(result)is not dict:raise ValueError('frame_response')
    if result.get('state')=='unknown':return {'state':'unknown','reason':'frame_observation_unknown','nativeActionAllowed':False,'replayAllowed':False}
    fields={'engineeringOnly','state','deploymentId','operationId','frame','bytes','sha256','base64','nativeActionAllowed','replayAllowed'}
    if (set(result)!=fields or result['engineeringOnly']is not True or result['state']!='frame-read-observed'
            or result['deploymentId']!=spec.deployment_id or result['operationId']!=operation_id
            or result['frame']!='setup-frame-'+uuid.UUID(operation_id).hex+'.png' or result['nativeActionAllowed']is not False
            or result['replayAllowed']is not False or type(result['bytes'])is not int or not 0<result['bytes']<=3*1024**2
            or type(result['base64'])is not str or len(result['base64'])>4*1024**2):raise ValueError('frame_response')
    raw=base64.b64decode(result['base64'],validate=True)
    if len(raw)!=result['bytes'] or hashlib.sha256(raw).hexdigest()!=result['sha256'] or not raw.startswith(b'\x89PNG\r\n\x1a\n'):raise ValueError('frame_response_bytes')
    stage._retain(directory,'frame.png',raw)
    return {k:v for k,v in result.items()if k not in ('base64','engineeringOnly')}|{'framePath':str(directory/'frame.png')}


def resources(root,request,credential_file):
    return _execute(root,FreshWindowsVmSpec.parse(request),'host-resources',credential_file=credential_file)


def _wait_for_resource_clock(measurement,deadline):
    """Let a slightly ahead remote clock reach the existing admission window.

    Never rewrite a sample or waive freshness. Excessive skew and wall-clock
    rollback remain bounded by the normal readiness monotonic deadline.
    """
    from .native_environment import NativeEnvironmentError
    latest=measurement['samples'][-1]['observedAtUnixMs']
    while latest>time.time_ns()//1_000_000:
        remaining=deadline-time.monotonic()
        if remaining<=0 or (latest-time.time_ns()//1_000_000)/1000>remaining:
            raise NativeEnvironmentError('resource_clock_ahead_deadline')
        time.sleep(min(.05,remaining))


def _prepare_reservation(root,spec,credential_file):
    """Observe all claimed aliases; never forget a row after a route rename."""
    from . import native_environment as environments,windows_vm_resources as facts
    root=Path(root).resolve(strict=True);deadline=time.monotonic()+180
    with direct.Guard(root,host=spec.host) as authority:
        with environments._LockedState(root) as locked:
            rows=json.loads(json.dumps(locked.state['reservations']))
            original=environments._read_private(locked.path).encode() if locked.path.exists() else b''
        aliases=sorted({row['hostAlias'] for row in rows}|{spec.host})
        if len(aliases)>64:raise ValueError('deployment_resource_alias_capacity')
        initial=resources(root,spec.as_dict(),credential_file)
        if initial['state']!='resources-observed':raise ValueError('deployment_resources_unknown')
        selected=[spec.host]
        for alias in aliases:
            if alias==spec.host:continue
            if alias not in authority.config.hosts:raise ValueError('claimed_host_not_configured')
            peer=_execute(root,replace(spec,host=alias),'peer')
            if peer['state']!='peer-observed':raise ValueError('claimed_host_peer_unknown')
            if peer['platform']=='linux' and peer['hostBootId']==initial['hostBootId']:selected.append(alias)
        observation=initial if len(aliases)==1 else resources(root,spec.as_dict(),credential_file)
        if observation['state']!='resources-observed' or observation['hostBootId']!=initial['hostBootId']:raise ValueError('deployment_resource_epoch_changed')
        same_host=environments._host_records(rows,selected)
        mapping=[{'reservationId':row['id'],'memoryBytes':row['requestedMemoryBytes']} for row in same_host if row['allocationState']=='running']
        request={'hostAlias':spec.host,'resourceAliases':sorted(selected),'environment':'windows-'+spec.deployment_id,
                 'operator':'windows-vm-deploy','requestedMemoryBytes':spec.memory_mib*1024**2,
                 'headroomBytes':spec.headroom_mib*1024**2,'allocationState':'pending',
                 'measurement':facts.measurement(observation),'runningAllocationMapping':mapping,
                 'expectedInventorySha256':hashlib.sha256(original).hexdigest()}
        _wait_for_resource_clock(request['measurement'],deadline)
        authority.guard();reservation=environments.reserve_environment(root,request);authority.guard()
        pending=[{'id':row['id'],'memoryBytes':row['requestedMemoryBytes']} for row in same_host if row['allocationState']=='pending']
        return {'reservation':reservation,'request':request,'hostBootId':observation['hostBootId'],'pending':pending}


def _lease_receipt(prepared,outcome):
    identity=prepared['reservation']['identity']
    return {'kind':'active-job','source':'windows-vm-deploy','observedAtUnixMs':time.time_ns()//1_000_000,
            'outcome':outcome,'reservationId':identity['reservationId'],'reservationToken':identity['token']}


def _mark_running(root,spec,prepared,credential_file):
    from . import native_environment as environments,windows_vm_resources as facts
    deadline=time.monotonic()+180
    observation=resources(root,spec.as_dict(),credential_file)
    if observation['state']!='resources-observed' or observation['hostBootId']!=prepared['hostBootId']:raise ValueError('deployment_running_epoch_unknown')
    request=dict(prepared['request']);request.pop('expectedInventorySha256',None)
    with environments._LockedState(root) as locked:
        rows=environments._host_records(locked.state['reservations'],request['resourceAliases'])
        mapping=[{'reservationId':row['id'],'memoryBytes':row['requestedMemoryBytes']} for row in rows if row['allocationState']=='running']
        raw=environments._read_private(locked.path).encode()
    identity=prepared['reservation']['identity']
    if not any(row['reservationId']==identity['reservationId'] for row in mapping):mapping.append({'reservationId':identity['reservationId'],'memoryBytes':spec.memory_mib*1024**2})
    request.update(allocationState='running',measurement=facts.measurement(observation),runningAllocationMapping=mapping,
                   reservationIdentity=identity,observations=[_lease_receipt(prepared,'active')],expectedInventorySha256=hashlib.sha256(raw).hexdigest())
    _wait_for_resource_clock(request['measurement'],deadline)
    return environments.reserve_environment(root,request)


def _bind_preparation(root,spec,setup,credential_file):
    """Keep a retry bound to its original unsubmitted payload and file generation."""
    with SecretFile(credential_file) as credential:
        expected={'schemaVersion':1,'spec':spec.as_dict(),'setup':setup,
                  'credentialPath':str(credential.path),'credentialGeneration':list(credential.pin)}
        credential.guard()
    parent=root/'.rag_index/windows-vm-preparations';parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if parent.is_symlink() or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o077:
        raise ValueError('deployment_preparation_owner')
    path=parent/(spec.deployment_id+'.json')
    try:stage._retain(parent,path.name,expected)
    except FileExistsError:
        descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600
                    or info.st_nlink!=1 or not 0<info.st_size<=65536):raise ValueError('deployment_preparation_metadata')
            body=os.read(descriptor,65537)
            generation=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns,s.st_nlink)
            if (len(body)!=info.st_size or generation(info)!=generation(os.fstat(descriptor))
                    or generation(info)!=generation(os.stat(path,follow_symlinks=False))
                    or json.loads(body)!=expected):raise ValueError('deployment_preparation_changed')
        finally:os.close(descriptor)


def start(root,request,setup,credential_file):
    """Create one blank instance; the immutable start is never resubmitted."""
    if not direct.coordinator_capable():raise ValueError('unsupported_deployment_coordinator')
    from . import windows_vm_unattend as unattended,native_environment as environments
    root=Path(root).resolve(strict=True);spec=FreshWindowsVmSpec.parse(request);setup=unattended.parse_setup(setup)
    if os.path.lexists(root/'.rag_index/windows-vm-deploy-intents'/(spec.deployment_id+'.intent.json')):raise ValueError('deployment_original_exists_use_status')
    if os.path.lexists(root/'.runtime/windows-vm-credentials'/spec.deployment_id):raise ValueError('deployment_preparation_exists_use_original_evidence')
    _bind_preparation(root,spec,setup,credential_file)
    media_result=installer_media(root,spec.as_dict())
    if media_result['state']!='media-observed':return {'state':'blocked','reason':'media_observation_unknown','deploymentId':spec.deployment_id,'vmSubmitted':False,'nativeActionAllowed':False,'replayAllowed':False}
    from .windows_vm_media import select_image
    try:select_image(media_result['images'],setup)
    except ValueError:
        return {'state':'blocked','reason':'media_requested_image_unavailable','deploymentId':spec.deployment_id,'vmSubmitted':False,'nativeActionAllowed':False,'replayAllowed':False}
    with SecretFile(credential_file) as credential:credential.guard()
    try:prepared=_prepare_reservation(root,spec,credential_file)
    except environments.NativeEnvironmentError as error:
        # Admission failed before any VM start submission. Keep preparation
        # evidence and all reservations; a failed local write is not proof that
        # no reservation exists and never permits automatic release/replay.
        failures=_runtime_group(root,'windows-vm-preparation-failures')
        stage._retain(failures,spec.deployment_id+'-'+uuid.uuid4().hex+'.json',{'phase':'reservation','errorClass':type(error).__name__,
                                                                   'detail':str(error),'vmSubmitted':False})
        return {'state':'blocked','reason':'reservation_admission_refused','deploymentId':spec.deployment_id,
                'vmSubmitted':False,'nativeActionAllowed':False,'replayAllowed':False}
    parent=_runtime_group(root,'windows-vm-credentials')
    directory=parent/spec.deployment_id;directory.mkdir(mode=0o700)
    for name,prefix in (('user','User8!'),('administrator','Admin8!'),('final-administrator','Final8!')):
        stage._retain(directory,name+'.secret',(prefix+secrets.token_urlsafe(24)+'\n').encode())
    stage._retain(directory,'reservation.private.json',prepared)
    def submitting():
        update=dict(prepared['request']);update.pop('expectedInventorySha256',None)
        update['observations']=[_lease_receipt(prepared,'unknown')]
        environments.reserve_environment(root,update)
    with SecretFile(str(directory/'user.secret')) as user,SecretFile(str(directory/'administrator.secret')) as administrator:
        result=_execute(root,spec,'start',credential_file=credential_file,setup=setup,
                        context={'hostBootId':prepared['hostBootId'],'pending':prepared['pending']},
                        payload={'user':user.text,'administrator':administrator.text},before_submit=submitting)
        user.guard();administrator.guard()
    stage._retain(directory,'boot-result.private.json',result)
    if result['state']=='booted-observed':
        bound=_mark_running(root,spec,prepared,credential_file)
        stage._retain(directory,'running-reservation.private.json',bound)
        result={**result,'reservationId':bound['identity']['reservationId'],'reservationState':'running'}
    return result


def status(root,deployment_id,credential_file):
    return _original_operation(root,deployment_id,credential_file,'status')


def stop(root,deployment_id,credential_file):
    return _original_operation(root,deployment_id,credential_file,'stop')


def qualify(root,deployment_id,operation_id,credential_file,*,status_only=False):
    if type(operation_id)is not str or str(uuid.UUID(operation_id))!=operation_id or type(status_only)is not bool:raise ValueError('qualification_identity')
    return _original_operation(root,deployment_id,credential_file,'qualify-status' if status_only else 'qualify',operation_id=operation_id)


def secure(root,deployment_id,operation_id,credential_file,*,status_only=False):
    if type(operation_id)is not str or str(uuid.UUID(operation_id))!=operation_id or type(status_only)is not bool:raise ValueError('secure_identity')
    if type(deployment_id)is not str or str(uuid.UUID(deployment_id))!=deployment_id:raise ValueError('deployment_identity')
    claim=Path(root)/'.rag_index/windows-vm-deploy-secure'/(deployment_id+'.intent.json')
    if os.path.lexists(claim):
        from .windows_secure_recovery import recover
        try:return recover(root,deployment_id,operation_id,credential_file,status_only=status_only)
        except ValueError as error:
            if str(error) not in ('secure_recovery_not_preadmission','secure_recovery_original_unknown'):
                raise
            if not status_only:return {'state':'unknown','reason':str(error),'operationId':operation_id,'replayAllowed':False}
    if status_only:return _original_operation(root,deployment_id,credential_file,'secure-status',operation_id=operation_id)
    path=Path(root).resolve(strict=True)/'.runtime/windows-vm-credentials'/deployment_id/'final-administrator.secret'
    with SecretFile(str(path))as secret:
        result=_original_operation(root,deployment_id,credential_file,'secure',operation_id=operation_id,payload={'password':secret.text})
        secret.guard();return result


def frame(root,deployment_id,operation_id,*,collect=False):
    if type(operation_id)is not str or str(uuid.UUID(operation_id))!=operation_id or type(collect)is not bool:raise ValueError('frame_identity')
    return _original_operation(root,deployment_id,None,'frame-collect' if collect else 'frame',operation_id=operation_id)


def _original_operation(root,deployment_id,credential_file,mode,*,operation_id=None,payload=None):
    """Read one original instance, with its local immutable intent held throughout."""
    if not direct.coordinator_capable():raise ValueError('unsupported_deployment_coordinator')
    if type(deployment_id)is not str or str(uuid.UUID(deployment_id))!=deployment_id:raise ValueError('deployment_identity')
    from .native_review_source_closure import _Held
    root=Path(root).resolve(strict=True);path=root/'.rag_index/windows-vm-deploy-intents'/(deployment_id+'.intent.json')
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=65536:raise ValueError('deployment_intent_metadata')
        raw=os.read(descriptor,65537)
        if len(raw)!=info.st_size:raise ValueError('deployment_intent_changed')
    finally:os.close(descriptor)
    held=_Held()
    try:
        held.read(str(path),hashlib.sha256(raw).hexdigest())
        value=json.loads(raw,object_pairs_hook=transport._reject_duplicate_keys)
        if type(value)is not dict or set(value)!={'spec','setup','context','correlationId','mode','callerSha256'} or value['mode']!='start':raise ValueError('deployment_intent_fields')
        import re
        if (type(value['correlationId'])is not str or re.fullmatch('[0-9a-f]{32}',value['correlationId'])is None or
                type(value['callerSha256'])is not str or re.fullmatch('[0-9a-f]{64}',value['callerSha256'])is None):raise ValueError('deployment_intent_source')
        spec=FreshWindowsVmSpec.parse(value['spec'])
        if spec.deployment_id!=deployment_id:raise ValueError('deployment_intent_identity')
        source=held.read(str(root/'.runtime/windows-vm-deploy'/value['correlationId']/'caller.py'),value['callerSha256'],max_bytes=files.MAX_SOURCE_BYTES)
        wanted={'SPEC':value['spec'],'SETUP':value['setup'],'CONTEXT':value['context'],'MODE':'start'}
        bindings={}
        for node in ast.parse(source).body:
            if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in wanted:
                name=node.targets[0].id
                if name in bindings:raise ValueError('deployment_source_binding')
                bindings[name]=ast.literal_eval(node.value)
        if bindings!=wanted:raise ValueError('deployment_source_binding')
        options={'operation_id':operation_id} if operation_id is not None else {}
        if payload is not None:options['payload']=payload
        result=_execute(root,spec,mode,credential_file=credential_file,setup=value['setup'],context=value['context'],**options)
        held.finish();held.final_identity_pass();return result
    finally:held.close()
