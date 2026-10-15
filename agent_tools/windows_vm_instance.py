"""Create-only fresh VM producer and exact original-instance observer."""

def _vm_main():
    import contextlib,hashlib,io,json,os,pathlib,pwd,re,shutil,socket,stat,struct,subprocess,sys,time
    root=pathlib.Path(SPEC['root']);held=[];parents=[];pins=[];phase='resources'
    def require(value,reason):
        if not value:raise ValueError(reason)
    def generation(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    def structure(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid)
    def chain():
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);held.append(fd);parents.append((fd,None,None,structure(os.fstat(fd))))
        for name in root.parent.parts[1:]:
            parent=fd;fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);held.append(fd)
            parents.append((fd,parent,name,structure(os.fstat(fd))))
        info=os.fstat(fd)
        require(info.st_uid==os.geteuid() and not info.st_mode&0o022 or info.st_uid==0 and info.st_mode&stat.S_ISVTX,'instance_parent')
        return fd
    def closing():
        for fd,parent,name,identity in parents:
            require(structure(os.fstat(fd))==identity,'instance_parent_changed')
            require(structure(os.lstat('/') if parent is None else os.stat(name,dir_fd=parent,follow_symlinks=False))==identity,'instance_parent_changed')
        for fd,path,identity in pins:
            require(generation(os.fstat(fd))==identity and generation(os.stat(path,follow_symlinks=False))==identity,'instance_source_changed')
    def pin(path,digest=None,size=None,executable=False):
        require(os.path.realpath(path)==path,'instance_source')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);held.append(fd);info=os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and not info.st_mode&0o022 and 0<info.st_size<=8*1024**3 and (size is None or info.st_size==size),'instance_source')
        require(not executable or os.access(path,os.X_OK),'instance_binary')
        h=hashlib.sha256();total=0
        while True:
            block=os.read(fd,1024**2)
            if not block:break
            total+=len(block);require(total<=info.st_size,'instance_source');h.update(block)
        require(total==info.st_size and (digest is None or h.hexdigest()==digest),'instance_source')
        pins.append((fd,path,generation(info)));return fd,h.hexdigest()
    def private(path,directory=False):
        s=os.lstat(path);require((stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==(0o700 if directory else 0o600) and (directory or s.st_nlink==1),'instance_private');return s
    def save(name,value):
        fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            raw=value if type(value)is bytes else (json.dumps(value,sort_keys=True)+'\n').encode();offset=0
            while offset<len(raw):offset+=os.write(fd,raw[offset:])
            os.fsync(fd)
        finally:os.close(fd)
    def read(name):
        path=root/name;private(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd);require(info.st_size<=65536,'instance_receipt_bound');raw=os.read(fd,65537)
            require(len(raw)==info.st_size and generation(os.fstat(fd))==generation(info) and generation(os.lstat(path))==generation(info),'instance_receipt_changed')
            return json.loads(raw)
        finally:os.close(fd)
    def birth(pid):
        with open('/proc/'+str(pid)+'/stat') as f:row=f.read(8193).rsplit(')',1)[1].split()
        require(row[0] not in ('Z','X') and len(row)>19,'instance_process_dead');return int(row[19])
    def record(child,argv,exe):
        start=birth(child.pid);base='/proc/'+str(child.pid)
        with open(base+'/cmdline','rb') as f:raw=f.read(32769)
        expected=b'\0'.join(os.fsencode(x) for x in argv)+b'\0'
        require(raw==expected and birth(child.pid)==start and generation(os.stat(base+'/exe'))==generation(os.fstat(exe)),'instance_process_identity')
        return {'pid':child.pid,'startTicks':start,'argv':argv,'commandSha256':hashlib.sha256(raw).hexdigest(),'executableGeneration':list(generation(os.fstat(exe)))}
    def process(row):
        require(type(row)is dict and set(row)=={'pid','startTicks','argv','commandSha256','executableGeneration'} and type(row['pid'])is int and row['pid']>0 and type(row['startTicks'])is int and row['startTicks']>0,'instance_process_receipt')
        pid=row['pid'];require(birth(pid)==row['startTicks'],'instance_process_changed');base='/proc/'+str(pid)
        with open(base+'/cmdline','rb') as f:raw=f.read(32769)
        require(raw==b'\0'.join(os.fsencode(x) for x in row['argv'])+b'\0' and hashlib.sha256(raw).hexdigest()==row['commandSha256'] and list(generation(os.stat(base+'/exe')))==row['executableGeneration'] and os.stat(base).st_uid==os.geteuid() and birth(pid)==row['startTicks'],'instance_process_changed')
        return pid
    def owns(pid,path,is_socket=False):
        fdlist=os.listdir('/proc/'+str(pid)+'/fd');require(len(fdlist)<=8192,'instance_fd_capacity')
        if is_socket:
            with open('/proc/net/unix') as f:raw=f.read(1024**2+1)
            require(len(raw)<=1024**2,'instance_socket_capacity')
            # Accepted Unix streams retain the bound pathname too. Identify
            # the listening stream, then prove its descriptor belongs to pid.
            rows=[r.split() for r in raw.splitlines()[1:]]
            matches=[r[6] for r in rows if len(r)>=8 and r[-1]==str(path) and
                     r[3:6]==['00010000','0001','01']]
            require(len(matches)==1,'instance_socket_identity');target='socket:['+matches[0]+']'
            require(any(os.readlink('/proc/'+str(pid)+'/fd/'+n)==target for n in fdlist),'instance_socket_owner')
        else:
            identity=private(path);found=False
            for n in fdlist:
                try:info=os.stat('/proc/'+str(pid)+'/fd/'+n)
                except FileNotFoundError:continue
                if (info.st_dev,info.st_ino)==(identity.st_dev,identity.st_ino):found=True
            require(found,'instance_disk_owner')
    def qmp(command,arguments=None):
        client=socket.socket(socket.AF_UNIX);client.settimeout(3)
        try:
            row=read('qemu-started.json');pid=process(row);named=os.lstat(root/'qmp.sock')
            client.connect(str(root/'qmp.sock'))
            peer=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(peer[:2]==(pid,os.geteuid()) and os.lstat(root/'qmp.sock').st_ino==named.st_ino,'instance_qmp_peer')
            stream=client.makefile('rwb',buffering=0)
            def receive():
                line=stream.readline(65537);require(0<len(line)<=65536,'instance_qmp_bound');return json.loads(line)
            require('QMP' in receive(),'instance_qmp_greeting')
            for sequence,(name,args) in enumerate((('qmp_capabilities',None),(command,arguments))):
                request={'execute':name,'id':sequence}
                if args is not None:request['arguments']=args
                stream.write((json.dumps(request)+'\n').encode())
                for _ in range(32):
                    value=receive()
                    if value.get('id')==sequence:break
                else:raise ValueError('instance_qmp_response')
                require('return' in value,'instance_qmp_error')
            process(row);require(os.lstat(root/'qmp.sock').st_ino==named.st_ino,'instance_qmp_changed')
            return value['return']
        finally:client.close()
    def guest_state(pid):
        state={'guestAgentReady':False,'ordinarySessionObserved':False,'osName':None}
        client=socket.socket(socket.AF_UNIX);client.settimeout(1)
        try:
            owns(pid,root/'qga.sock',True);named=os.lstat(root/'qga.sock');client.connect(str(root/'qga.sock'))
            peer=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(peer[:2]==(pid,os.geteuid()) and os.lstat(root/'qga.sock').st_ino==named.st_ino,'instance_qga_peer')
            stream=client.makefile('rwb',buffering=0)
            nonce=int.from_bytes(os.urandom(8),'big')&((1<<63)-1)
            stream.write(b'\xff'+(json.dumps({'execute':'guest-sync-delimited','arguments':{'id':nonce}})+'\n').encode())
            def receive():
                line=stream.readline(65537);require(0<len(line)<=65536,'instance_qga_bound')
                return json.loads(line.lstrip(b'\xff'))
            # The flush sentinel can itself produce an error; stale complete
            # replies and partial JSON may also precede the real response.
            # QGA requires ignoring all input until a delimited matching nonce.
            deadline=time.monotonic()+3;consumed=0
            for _ in range(32):
                remaining=deadline-time.monotonic();require(remaining>0,'instance_qga_sync')
                client.settimeout(min(1,remaining));line=stream.readline(65537)
                consumed+=len(line);require(0<len(line)<=65536 and consumed<=262144,'instance_qga_bound')
                marker=line.rfind(b'\xff')
                if marker<0:continue
                try:reply=json.loads(line[marker+1:])
                except (ValueError,UnicodeError):continue
                if type(reply)is dict and type(reply.get('return'))is int and reply['return']==nonce:break
            else:raise ValueError('instance_qga_sync')
            client.settimeout(1)
            def query(command):
                stream.write((json.dumps({'execute':command})+'\n').encode());response=receive()
                require('return' in response,'instance_qga_query');return response['return']
            query('guest-ping');state['guestAgentReady']=True
            osinfo=query('guest-get-osinfo');name=osinfo.get('pretty-name') or osinfo.get('name')
            if type(name)is str and 0<len(name)<=256 and not any(ord(c)<32 for c in name):state['osName']=name
            try:
                users=query('guest-get-users')
                if type(users)is list and len(users)<=128:
                    state['ordinarySessionObserved']=any(type(u)is dict and type(u.get('user'))is str and u['user'].rsplit('\\',1)[-1].casefold()==SETUP['user'].casefold() for u in users)
            except (OSError,ValueError):pass
            require(os.lstat(root/'qga.sock').st_ino==named.st_ino,'instance_qga_changed')
        except (OSError,ValueError,KeyError,TypeError):
            state={'guestAgentReady':False,'ordinarySessionObserved':False,'osName':None}
        finally:client.close()
        return state
    def instance_intent():
        private(root,True);intent=read('intent.json')
        require(type(intent)is dict and set(intent)=={'schemaVersion','spec','setup','hostBootId','rootIdentity','assetIdentities'} and type(intent['schemaVersion'])is int and intent['schemaVersion']==1,'instance_intent_fields')
        require(intent['spec']==SPEC and intent['setup']==SETUP and intent['hostBootId']==CONTEXT['hostBootId'] and intent['rootIdentity']==list(structure(os.lstat(root))),'instance_intent')
        require(type(intent['assetIdentities'])is dict and set(intent['assetIdentities'])=={'firmwareCode','installer','drivers'},'instance_asset_receipt')
        return intent
    def observed():
        intent=instance_intent()
        q=read('qemu-started.json');t=read('swtpm-started.json');pid=process(q);tpid=process(t)
        mutable=read('mutable-artifacts.json')
        require(type(mutable)is dict and set(mutable)=={'disk.qcow2','uefi-vars.fd'},'instance_mutable_receipt')
        for name,identity in mutable.items():
            require(type(identity)is list and len(identity)==5 and list(structure(private(root/name)))==identity,'instance_mutable_changed')
            owns(pid,root/name)
        owns(pid,root/'qmp.sock',True);owns(tpid,root/'swtpm.sock',True)
        state=qmp('query-status');sets=qmp('query-fdsets')
        require(type(sets)is list,'instance_asset_descriptors')
        for name,expected in intent['assetIdentities'].items():
            require(type(expected)is dict and set(expected)=={'set','generation'} and type(expected['set'])is int and
                    expected['set']==('firmwareCode','installer','drivers').index(name)+1 and type(expected['generation'])is list and
                    len(expected['generation'])==9 and all(type(x)is int and x>=0 for x in expected['generation']) and
                    expected['generation'][6]==SPEC['assets'][name]['bytes'],'instance_asset_receipt')
            selected=[s for s in sets if s.get('fdset-id')==expected['set']]
            require(len(selected)==1 and len(selected[0].get('fds',[]))==1,'instance_asset_descriptors')
            item=selected[0]['fds'][0];require(item.get('opaque')=='asset:'+name and type(item.get('fd'))is int and item['fd']>2,'instance_asset_descriptors')
            require(list(generation(os.stat('/proc/'+str(pid)+'/fd/'+str(item['fd']))))==expected['generation'],'instance_asset_changed')
        guest=guest_state(pid);process(q);process(t);closing()
        return {'qemu':{'pid':q['pid'],'startTicks':q['startTicks']},'swtpm':{'pid':t['pid'],'startTicks':t['startTicks']},'qemuStatus':state.get('status'),**guest,'productReady':False}
    def launch(name,argv,exe,pass_fds):
        fd=os.open(root/(name+'.log'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=fd,stderr=fd,start_new_session=True,pass_fds=tuple(pass_fds),close_fds=True,env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':str(pathlib.Path.home())})
        finally:os.close(fd)
        for _ in range(40):
            require(child.poll() is None,'instance_process_ended')
            try:row=record(child,argv,exe);break
            except (FileNotFoundError,ValueError):time.sleep(.05)
        else:raise ValueError('instance_process_unknown')
        save(name+'-started.json',row);return child
    try:
        require(os.geteuid()==0,'instance_resource_privilege')
        output=io.StringIO()
        with contextlib.redirect_stdout(output):_resource_main()
        resource=json.loads(output.getvalue());measurement=resource_measurement(resource)
        require(resource['hostBootId']==CONTEXT['hostBootId'],'instance_host_epoch')
        if MODE=='start':
            pending=CONTEXT['pending'];identifiers=set();reserved=0
            require(type(pending)is list and len(pending)<=4096,'instance_reservations')
            for row in pending:
                require(type(row)is dict and set(row)=={'id','memoryBytes'} and type(row['id'])is str and re.fullmatch('[A-Za-z0-9._-]{1,128}',row['id']) is not None and row['id']not in identifiers and type(row['memoryBytes'])is int and row['memoryBytes']>0,'instance_reservations')
                identifiers.add(row['id']);reserved+=row['memoryBytes']
            required=(SPEC['memoryMiB']+SPEC['headroomMiB'])*1024**2
            require(measurement['physicalMemoryBytes']>=measurement['runningConfiguredMemoryBytes']+reserved+required,'instance_capacity')
            require(all(s['psi']=='normal' and s['availableMemoryBytes']>=required for s in measurement['samples']) and
                    all(measurement['samples'][0]['vmstat'][k]==measurement['samples'][1]['vmstat'][k] for k in ('pswpout','oomKill')),'instance_pressure')
        phase='principal'
        uid=os.environ.get('SUDO_UID','');require(re.fullmatch('[0-9]{1,10}',uid)is not None and 0<int(uid)<2**32,'instance_principal')
        account=pwd.getpwuid(int(uid));os.initgroups(account.pw_name,account.pw_gid);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
        os.environ.update(HOME=account.pw_dir,USER=account.pw_name,LOGNAME=account.pw_name)
        parent=chain()
        if MODE=='start':
            phase='preflight'
            require(not os.path.lexists(root),'instance_original_exists')
            output=io.StringIO()
            with contextlib.redirect_stdout(output):_remote_main()
            preflight=json.loads(output.getvalue());require(preflight['state']=='qualified','instance_preflight')
            assets={}
            for name,a in SPEC['assets'].items():assets[name]=pin(a['path'],a['sha256'],a['bytes'])[0]
            phase='media'
            selected_image=select_image(installer_images(assets['installer']),SETUP)
            binaries={}
            for name in ('qemu-system-x86_64','qemu-img','swtpm','virt-fw-vars','xorriso'):
                path=shutil.which(name,path='/usr/bin:/bin');require(path is not None,'instance_binary');binaries[name]=pin(os.path.realpath(path),executable=True)[0]
            phase='credentials'
            credentials=json.loads(sys.stdin.buffer.read(4097));answer=answer_file(SETUP,credentials);credentials.clear()
            phase='create'
            closing();os.umask(0o077);os.mkdir(root.name,0o700,dir_fd=parent);private(root,True)
            source_names=('firmwareCode','installer','drivers')
            asset_sets={name:index+1 for index,name in enumerate(source_names)}
            save('intent.json',{'schemaVersion':1,'spec':SPEC,'setup':SETUP,'hostBootId':CONTEXT['hostBootId'],
                              'rootIdentity':list(structure(os.lstat(root))),
                              'assetIdentities':{name:{'set':asset_sets[name],'generation':list(generation(os.fstat(assets[name])))} for name in source_names}})
            save('installer-image.json',{'installerSha256':SPEC['assets']['installer']['sha256'],'image':selected_image})
            for name in ('tpm','seed'):os.mkdir(root/name,0o700)
            save('seed/Autounattend.xml',answer);save('seed/initialize.ps1',INITIALIZE.encode('utf-8-sig'))
            save('seed/install-agent.ps1',INSTALL_AGENT.encode('utf-8-sig'));answer=None
            def run(argv,timeout=15,limit=65536):
                p=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,pass_fds=tuple(binaries.values())+tuple(assets.values()),env={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C'})
                save('command-'+str(len(list(root.glob('command-*.json'))))+'.json',{'argv':argv,'returnCode':p.returncode,'stdout':p.stdout[:limit].decode('utf8','replace'),'stderr':p.stderr[:limit].decode('utf8','replace'),'stdoutBytes':len(p.stdout),'stderrBytes':len(p.stderr)})
                require(p.returncode==0 and len(p.stdout)<=limit and len(p.stderr)<=limit,'instance_preparation');return p
            def binary(name):return '/proc/self/fd/'+str(binaries[name])
            phase='firmware'
            run([binary('virt-fw-vars'),'--input','/proc/self/fd/'+str(assets['firmwareVars']),'--output',str(root/'uefi-vars.fd'),'--enroll-microsoft','--microsoft-db','win11','--microsoft-kek','all','--secure-boot'])
            private(root/'uefi-vars.fd')
            enrolled=json.loads(run([binary('virt-fw-vars'),'--input',str(root/'uefi-vars.fd'),'--output-json','-'],limit=262144).stdout)
            require(enrolled.get('version')==2 and type(enrolled.get('variables'))is list,'instance_firmware')
            variables={v['name']:v['data'] for v in enrolled['variables']}
            require(variables.get('SecureBootEnable')=='01' and variables.get('CustomMode')=='00' and all(variables.get(k) for k in ('PK','KEK','db')),'instance_firmware')
            phase='disk'
            run([binary('qemu-img'),'create','-f','qcow2',str(root/'disk.qcow2'),str(SPEC['diskGiB'])+'G'])
            image=json.loads(run([binary('qemu-img'),'info','--output=json',str(root/'disk.qcow2')]).stdout)
            require(image.get('format')=='qcow2' and image.get('virtual-size')==SPEC['diskGiB']*1024**3 and not image.get('backing-filename'),'instance_blank_disk')
            private(root/'disk.qcow2')
            save('mutable-artifacts.json',{name:list(structure(private(root/name))) for name in ('disk.qcow2','uefi-vars.fd')})
            phase='seed'
            run([binary('xorriso'),'-as','mkisofs','-quiet','-J','-R','-V','VCSETUP','-o',str(root/'seed.iso'),str(root/'seed')])
            private(root/'seed.iso');closing()
            phase='tpm'
            tpm=[binary('swtpm'),'socket','--tpm2','--tpmstate','dir='+str(root/'tpm'),'--ctrl','type=unixio,path='+str(root/'swtpm.sock')]
            tchild=launch('swtpm',tpm,binaries['swtpm'],(binaries['swtpm'],))
            for _ in range(40):
                if os.path.exists(root/'swtpm.sock'):break
                require(tchild.poll() is None,'instance_tpm_ended');time.sleep(.1)
            else:raise ValueError('instance_tpm_socket')
            phase='qemu'
            qargs=qemu_argv(SPEC,binary('qemu-system-x86_64'),asset_sets)
            for name in source_names:qargs.extend(('-add-fd','fd='+str(assets[name])+',set='+str(asset_sets[name])+',opaque=asset:'+name))
            launch('qemu',qargs,binaries['qemu-system-x86_64'],tuple(assets[name] for name in source_names)+(binaries['qemu-system-x86_64'],))
            for _ in range(40):
                if os.path.exists(root/'qmp.sock'):break
                time.sleep(.1)
            else:raise ValueError('instance_qmp_socket')
            # Bounded first-boot confirmation belongs only to this new blank
            # VM's original start. It is never repeated by status.
            phase='first-boot'
            time.sleep(1)
            qmp('screendump',{'filename':str(root/'boot-before.ppm')})
            for _ in range(4):
                qmp('send-key',{'keys':[{'type':'qcode','data':'spc'}],'hold-time':100});time.sleep(1)
            qmp('screendump',{'filename':str(root/'boot-after.ppm')})
        phase='observation'
        if MODE=='stop' or MODE=='status' and os.path.lexists(root/'stop-intent.json'):
            def stop_closing():instance_intent();closing()
            stop_closing()
            value=(_stop_instance(SPEC,CONTEXT,observed,read,process,birth,qmp,save,stop_closing) if MODE=='stop'
                   else _closed_instance(SPEC,CONTEXT,read,process,birth))
            stop_closing()
            print(json.dumps({'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':MODE,'state':'stopped-observed','reason':None,
                              **value,'nativeActionAllowed':False,'replayAllowed':False},separators=(',',':')))
            return
        value=observed()
        if MODE in ('secure','secure-status'):
            phase='secure'
            value=secure_instance(SPEC,SETUP,OPERATION_ID,MODE=='secure-status',root,read,save,process,owns,instance_intent,closing,observed,qmp)
            print(json.dumps({'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':MODE,'reason':None,**value,'nativeActionAllowed':False,'replayAllowed':False},separators=(',',':')))
            return
        if MODE in ('qualify','qualify-status'):
            phase='qualification'
            value=qualify_instance(SPEC,SETUP,OPERATION_ID,MODE=='qualify-status',root,read,save,process,owns,instance_intent,closing,observed)
            print(json.dumps({'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':MODE,'reason':None,**value,'nativeActionAllowed':False,'replayAllowed':False},separators=(',',':')))
            return
        print(json.dumps({'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':MODE,'state':'booted-observed','reason':None,**value,'nativeActionAllowed':False,'replayAllowed':False},separators=(',',':')))
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) as error:
        # Return only bounded check identifiers, never exception text containing
        # paths, input data or credentials. UNKNOWN never authorizes a replay.
        check=str(error) if type(error)is ValueError and re.fullmatch('instance_[a-z_]{1,64}',str(error)) else None
        category=next(cls.__name__ for cls in (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError) if isinstance(error,cls))
        print(json.dumps({'schemaVersion':1,'deploymentId':SPEC['deploymentId'],'mode':MODE,'state':'unknown','reason':'instance_effect_or_observation_unknown',
                          'failurePhase':phase,'failureClass':category,'failureCheck':check,
                          'nativeActionAllowed':False,'replayAllowed':False},separators=(',',':')))
    finally:
        for fd in reversed(held):os.close(fd)


BOOTSTRAP_PROBE='powershell.exe -nop -noexit -c "get-service qemu-ga;get-scheduledtask -taskname vpncontrolfixtureinitialize | select state;get-scheduledtaskinfo -taskname vpncontrolfixtureinitialize | fl lastruntime,lasttaskresult;gcim win32_operatingsystem | fl caption,version"'


def console_key_plan(text):
    """Plan the complete supported ASCII input before sending any key."""
    if type(text)is not str or not 0<len(text)<=2048:raise ValueError('instance_console_text')
    symbols={' ':('spc',),'.':('dot',),'-':('minus',),':':('shift','semicolon'),'\\':('backslash',),
             '"':('shift','apostrophe'),';':('semicolon',),'|':('shift','backslash'),',':('comma',),'_':('shift','minus')}
    result=[]
    for char in text:
        if char in symbols:result.append(symbols[char])
        elif char in 'abcdefghijklmnopqrstuvwxyz0123456789':result.append((char,))
        elif char in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':result.append(('shift',char.lower()))
        else:raise ValueError('instance_console_character')
    return result


def inspection_program(request,setup,context,operation_id,*,probe=False,frame=None,return_frame=False,read_existing=False):
    """Emit an ordinary-host observer from canonical code and typed data only.

    No previous programme/globals are an input. The optional fixed bootstrap
    query opens an ordinary console; it never grants guest/product authority.
    """
    import ast,inspect,re,uuid
    from .native_vm_spec import FreshWindowsVmSpec
    from .windows_vm_unattend import parse_setup
    spec=FreshWindowsVmSpec.parse(request);setup=parse_setup(setup)
    if (type(operation_id)is not str or str(uuid.UUID(operation_id))!=operation_id or any(type(v)is not bool for v in (probe,return_frame,read_existing))
            or read_existing and (probe or frame is not None or not return_frame)
            or type(context)is not dict or set(context)!={'hostBootId','pending'} or type(context['pending'])is not list
            or type(context['hostBootId'])is not str or str(uuid.UUID(context['hostBootId']))!=context['hostBootId']):raise ValueError('instance_inspection_inputs')
    if probe and setup['locale']!='en-US':raise ValueError('instance_diagnostic_keyboard_locale')
    if frame is not None and (probe or type(frame)is not dict or set(frame)!={'frame','sha256','bytes'}
            or type(frame['frame'])is not str or re.fullmatch('setup-frame-[0-9a-f]{32}\\.png',frame['frame'])is None
            or type(frame['sha256'])is not str or re.fullmatch('[0-9a-f]{64}',frame['sha256'])is None
            or type(frame['bytes'])is not int or not 0<frame['bytes']<=3*1024**2):raise ValueError('instance_frame_input')
    plan=console_key_plan(BOOTSTRAP_PROBE) if probe else []
    source=inspect.getsource(_vm_main);main=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='_vm_main')
    nodes=[n for n in main.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.Assign,ast.FunctionDef)) and not(isinstance(n,ast.FunctionDef) and n.name=='launch')]
    body='\n'.join(ast.get_source_segment(source,n) for n in nodes)
    leaf='setup-frame-'+uuid.UUID(operation_id).hex+'.png'
    text='SPEC='+repr(spec.as_dict())+'\nSETUP='+repr(setup)+'\nCONTEXT='+repr(context)+'\n'
    text+='OPERATION_ID='+repr(operation_id)+'\nLEAF='+repr(leaf)+'\nPLAN='+repr(plan)+'\nPROBE='+repr(probe)+'\nFRAME_INPUT='+repr(frame)+'\nRETURN_FRAME='+repr(return_frame)+'\nREAD_EXISTING='+repr(read_existing)+'\ndef inspect_instance():\n'
    text+=''.join('    '+line+'\n' for line in body.splitlines())
    text+='''    try:
        def epoch():
            with open('/proc/sys/kernel/random/boot_id') as stream:current=stream.read(128).strip()
            require(current==CONTEXT['hostBootId'],'instance_host_epoch')
        global FRAME_INPUT
        epoch();chain();before=observed()
        if READ_EXISTING:
            receipt=read('inspection-'+OPERATION_ID+'.result.json')
            require(type(receipt)is dict and set(receipt)=={'frame','bytes','sha256'} and receipt['frame']==LEAF
                    and type(receipt['bytes'])is int and 0<receipt['bytes']<=3*1024**2
                    and type(receipt['sha256'])is str and re.fullmatch('[0-9a-f]{64}',receipt['sha256'])is not None,'instance_frame_receipt')
            FRAME_INPUT=receipt
        if FRAME_INPUT is not None:
            import base64
            path=root/FRAME_INPUT['frame'];info=private(path)
            require(info.st_size==FRAME_INPUT['bytes'],'instance_frame_bytes')
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            try:
                raw=os.read(fd,3*1024**2+1)
                require(generation(os.fstat(fd))==generation(info),'instance_frame_changed')
            finally:os.close(fd)
            require(len(raw)==FRAME_INPUT['bytes'] and hashlib.sha256(raw).hexdigest()==FRAME_INPUT['sha256'] and raw.startswith(b'\\x89PNG\\r\\n\\x1a\\n') and generation(private(path))==generation(info),'instance_frame_bytes')
            process(read('qemu-started.json'));instance_intent();closing();epoch()
            print(json.dumps({'engineeringOnly':True,'state':'frame-read-observed','deploymentId':SPEC['deploymentId'],'operationId':OPERATION_ID,
                              **FRAME_INPUT,'base64':base64.b64encode(raw).decode(),'nativeActionAllowed':False,'replayAllowed':False}))
            return
        require(not os.path.lexists(root/LEAF),'instance_frame_exists')
        save('inspection-'+OPERATION_ID+'.intent.json',{'schemaVersion':1,'operationId':OPERATION_ID,'probe':PROBE,'before':before})
        if PROBE:
            require(not before['guestAgentReady'],'instance_probe_not_needed')
            def key(codes):
                qmp('send-key',{'keys':[{'type':'qcode','data':c} for c in codes],'hold-time':10});time.sleep(.025)
            # A new bootstrap read clears an old unsubmitted Run dialog; it
            # never resumes or replays the original unknown input operation.
            key(['esc']);key(['esc']);key(['meta_l','r']);time.sleep(1)
            save('inspection-'+OPERATION_ID+'.input-started.json',{'keys':len(PLAN),'replayAllowed':False})
            deadline=time.monotonic()+30
            for codes in PLAN:
                require(time.monotonic()<deadline,'instance_input_deadline');key(codes)
            key(['ret']);save('inspection-'+OPERATION_ID+'.input-complete.json',{'enterSent':True});time.sleep(4)
        require(not os.path.lexists(root/LEAF),'instance_frame_exists')
        qmp('screendump',{'filename':str(root/LEAF),'format':'png'})
        info=private(root/LEAF);require(info.st_size<=3*1024**2,'instance_frame_bound')
        fd=os.open(root/LEAF,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            raw=os.read(fd,3*1024**2+1)
            require(generation(os.fstat(fd))==generation(info),'instance_frame_changed')
        finally:os.close(fd)
        require(len(raw)==info.st_size and raw.startswith(b'\\x89PNG\\r\\n\\x1a\\n') and generation(private(root/LEAF))==generation(info),'instance_frame_bytes')
        process(read('qemu-started.json'));instance_intent();closing();epoch()
        metadata={'frame':LEAF,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        save('inspection-'+OPERATION_ID+'.result.json',metadata)
        if RETURN_FRAME:
            import base64
            print(json.dumps({'engineeringOnly':True,'state':'frame-read-observed','deploymentId':SPEC['deploymentId'],'operationId':OPERATION_ID,
                              **metadata,'base64':base64.b64encode(raw).decode(),'nativeActionAllowed':False,'replayAllowed':False}))
        else:
            print(json.dumps({'engineeringOnly':True,'operationId':OPERATION_ID,**metadata,'qemu':before['qemu'],'probe':PROBE,'nativeActionAllowed':False,'replayAllowed':False}))
    except (OSError,ValueError,KeyError,TypeError) as error:
        check=str(error) if type(error)is ValueError and re.fullmatch('instance_[a-z_]{1,64}',str(error)) else None
        print(json.dumps({'engineeringOnly':True,'operationId':OPERATION_ID,'state':'unknown','reason':check,'errorClass':type(error).__name__,'nativeActionAllowed':False,'replayAllowed':False}))
    finally:
        for fd in reversed(held):os.close(fd)
inspect_instance()
'''
    compile(text,'owned Windows inspection','exec');return text.encode()
