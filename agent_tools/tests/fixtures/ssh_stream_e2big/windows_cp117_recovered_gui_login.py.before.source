"""Fixed prospective CP117 GUI login; credentials never enter source or receipts.

Historical secure observations are evidence only. Each prospective phase gets
its own closed source/nonce and new current secure-input observation. No public
script, guest, account, path, or keyboard selector is accepted.
"""
import ast,base64,hashlib,inspect,json,os,time
from pathlib import Path
from . import windows_cp117_secure_layout_observe as secure
from .windows_diagnostic_authority_capture import AuthorityCapture
login=secure.login
SECURE_SHA='bbcb1de84c89b44d7e541a35a2634ba0cf644e89f5cef7d9061e3a33e6499782'
CORRELATION='6c4bac9a-e05a-49e2-b9f0-4b390385bb4a'
_PHASES={'wake': ('92be3503-58b0-44c6-9d3e-f2debb0a7852', 'b73b5c39-e446-4b13-92b6-8834f0962994'), 'typing': ('1f0ea39d-68e7-44e4-bdf0-0b6f038546e0', 'df788b4d-c869-41d9-b460-e85bd7520c66'), 'enter': ('e1339f6a-7d0b-43bd-b76d-40ba470e42cc', '327baa15-3742-4fa2-9273-dd8d1737fa39')}
_READ_SHA={'wake': ('ecdb8bb086d142cb40e805738ca04b315849131f742173e0457d9bdc3d635bdf', '4ef88944fc44f863b3955cc8a6c424e2c8066ddb500995e093bafec60d4b13ef'), 'typing': ('86709d77f90bd65ac1845361b724126485c0df7f5eef16d2f1f8b6415ccb3c41', '8f19f6f23d0bfb0a0347d578b98cd8f82add12a658a0c5a034c4efcb13384497'), 'enter': ('85cafc667058fb1275dad8628a65703d7825771fd5009a3a14d1f356a6999a12', '635d77aff46268ac5d120be71879847cbf5cf6cd15c40b6aada431533c412148')}
_SUPPORT_SHA='82e01dbc014362502cfc99916557f073ef3a470d2f3c60cdf68b9b871acaeb41'
_PROFILE=[((580,381,702,412),'419b5696ec6b16df17083fbeccd94c3acb9b82dcbad072e9f0d69e7a382833c1'),((510,490,770,517),'a642d3f8b2856f6ac0146ceaab27b0d2094a0d896f375940eec4b68aa4cdc6cf'),((494,443,786,444),'69cc7959973a874a00d19257a3ff4dc0f4702fee0911a3954b3b4bc58ca8ba36')]
_EMPTY=((506,446,730,474),'8b69ba16b1492a4098bd8c8059affb37316bb33620685f9e1c5da2c0841c4239')
_REVIEWED_PROFILES=(tuple(h for _,h in _PROFILE+[_EMPTY]),('5d0c1ff177801e0869d4a61cfeb979f6ed8748e8e05147f357825f4b3c7d4822','1011eb69fa040bb40c3320eeab05483f27daabd723a7e18ad86d79a20fd9890b','3ad44c3c1045da71622a06150c9daa8c7faf42116aca2b34032f2cf734f27d70','7490be5176e9bff4862d1de9943f6422f981438b6b7867e238311dbbb09a542f'))


def _us_keys(secret):
    """Validate the entire private input before any key effect; never log it."""
    if not isinstance(secret,bytes)or not 1<=len(secret)<=64:raise ValueError('gui-private-input-bound')
    try:text=secret.decode('ascii')
    except UnicodeError:raise ValueError('gui-private-input-alphabet')from None
    plain={' ':'spc','-':'minus','=':'equal','[':'bracket_left',']':'bracket_right',';':'semicolon',"'":'apostrophe',',':'comma','.':'dot','/':'slash','\\':'backslash','`':'grave_accent'}
    shifted=dict(zip('!@#$%^&*()_+{}:"<>?|~','1234567890-=[];\',./\\`'))
    result=[]
    for c in text:
        shift=False
        if 'a'<=c<='z'or '0'<=c<='9':key=c
        elif 'A'<=c<='Z':key=c.lower();shift=True
        elif c in plain:key=plain[c]
        elif c in shifted:
            unshifted=shifted[c];key=plain.get(unshifted,unshifted);shift=True
        else:raise ValueError('gui-private-input-alphabet')
        result.append((['shift']if shift else [])+[key])
    return result


def _crop_sha(raw,rect):
    width,height=login.validate_ppm(raw)
    if(width,height)!=(1280,800):raise ValueError('gui-screen-dimensions')
    x0,y0,x1,y1=rect;pixels=raw.split(b'\n',3)[3]
    return hashlib.sha256(b''.join(pixels[(y*width+x0)*3:(y*width+x1)*3]for y in range(y0,y1))).hexdigest()


def _screen_gate(raw,age,empty):
    if type(age)not in(int,float)or not 0<=age<=5:raise ValueError('gui-screen-expired')
    actual=tuple(_crop_sha(raw,rect)for rect,_ in _PROFILE+[_EMPTY])
    if type(empty)is not bool:raise ValueError('gui-field-mode')
    if empty:
        if actual not in _REVIEWED_PROFILES:raise ValueError('gui-selected-account-field-or-caps')
    else:
        if actual[:3]not in[p[:3]for p in _REVIEWED_PROFILES]:raise ValueError('gui-selected-account-field-or-caps')
        if actual[3]in[p[3]for p in _REVIEWED_PROFILES]:raise ValueError('gui-field-state')


def _effect_gate(answer,focus_age,raw,screen_age,empty):
    if type(focus_age)not in(int,float)or not 0<=focus_age<=5:raise ValueError('gui-focus-expired')
    secure.validate_layout(answer['facts']);secure.validate_focus(answer)
    if empty is None:
        if type(screen_age)not in(int,float)or not 0<=screen_age<=5:raise ValueError('gui-screen-expired')
        login._validate_lockscreen(raw)
    else:_screen_gate(raw,screen_age,empty)


def _fresh_reader(record,phase):
    """Private closed three-entry catalog, reusing unchanged reviewed primitives."""
    if phase not in _PHASES:raise ValueError('gui-fixed-phase')
    if hashlib.sha256(Path(secure.__file__).read_bytes()).hexdigest()!=SECURE_SHA:raise ValueError('gui-secure-source')
    correlation,nonce=_PHASES[phase]
    source,oldsha=secure.program(record,secure.NONCE)
    parent,child,oldchildsha=secure.bodies(secure.NONCE)
    if child.count(secure.CORRELATION)!=1 or child.count(secure.NONCE)!=1:raise ValueError('gui-child-factory')
    newchild=child.replace(secure.CORRELATION,correlation).replace(secure.NONCE,nonce)
    childsha=hashlib.sha256(newchild.encode('utf-16le')).hexdigest()
    oldencoded=base64.b64encode(child.encode('utf-16le')).decode();newencoded=base64.b64encode(newchild.encode('utf-16le')).decode()
    for before,after in((secure.CORRELATION,correlation),(secure.NONCE,nonce),(oldencoded,newencoded),(oldchildsha,childsha)):
        if parent.count(before)!=1:raise ValueError('gui-parent-factory')
        parent=parent.replace(before,after)
    sha=hashlib.sha256(parent.encode('utf-16le')).hexdigest()
    if(sha,childsha)!=_READ_SHA[phase]:raise ValueError('gui-reader-source')
    # Rebuild only the exact fixed public-body bootstrap; no caller body exists.
    tree=ast.parse(source);encoded=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='ENCODED'for t in n.targets))
    bootstrap=base64.b64decode(encoded).decode('utf-16le')
    for before,after in((secure.NONCE,nonce),(oldsha,sha)):
        if bootstrap.count(before)!=(2 if before==oldsha else 1):raise ValueError('gui-bootstrap-factory')
        bootstrap=bootstrap.replace(before,after)
    payload=parent.encode()
    original_parent=secure.bodies(secure.NONCE)[0].encode()
    replacements={'D='+repr(secure.CORRELATION):'D='+repr(correlation),'NONCE='+repr(secure.NONCE):'NONCE='+repr(nonce),'BODY_SHA='+repr(oldsha):'BODY_SHA='+repr(sha),'CHILD_SHA='+repr(oldchildsha):'CHILD_SHA='+repr(childsha),'ENCODED='+repr(encoded):'ENCODED='+repr(base64.b64encode(bootstrap.encode('utf-16le')).decode()),repr(base64.b64encode(len(original_parent).to_bytes(4,'big')+original_parent).decode()):repr(base64.b64encode(len(payload).to_bytes(4,'big')+payload).decode())}
    for before,after in replacements.items():
        if source.count(before)!=1:raise ValueError('gui-reader-factory')
        source=source.replace(before,after)
    compile(source,'gui-fixed-reader','exec');return source,sha,childsha


def _remote_input_action(answer,focus_started,phase,keys,prior):
    """Generated fixed host-side action; never emits the private key sequence."""
    import socket,stat,struct
    need(phase in('wake','typing','enter'),'gui-fixed-phase')
    parent=TRANSFER;name='cp117-gui-'+FLOW+('-wake'if phase=='wake'else'')
    pf=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);pi=os.fstat(pf)
    need(stat.S_ISDIR(pi.st_mode)and pi.st_uid==os.geteuid()and stat.S_IMODE(pi.st_mode)==0o700,'gui-parent')
    need(fp(pi)==fp(os.lstat(parent)),'gui-parent-name')
    if phase!='enter':os.mkdir(name,0o700,dir_fd=pf);os.fsync(pf)
    directory=parent+'/'+name;jf=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=pf);ji=os.fstat(jf)
    identity={k:getattr(ji,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid')}
    need(stat.S_ISDIR(ji.st_mode)and ji.st_uid==os.geteuid()and stat.S_IMODE(ji.st_mode)==0o700,'gui-directory')
    pins={};frames={}
    def guard():
        guards()
        for held,named,pinned in((os.fstat(pf),os.lstat(parent),{k:getattr(pi,k)for k in identity}),(os.fstat(jf),os.stat(name,dir_fd=pf,follow_symlinks=False),identity)):
            need(all(getattr(held,k)==getattr(named,k)==v for k,v in pinned.items()),'gui-directory-drift')
        for leaf,pin in pins.items():read_pin(leaf,pin)
        for leaf,pin in frames.items():read_frame_pin(leaf,pin)
        # Recheck held/named ancestry after the last protected authority read.
        for held,named,pinned in((os.fstat(pf),os.lstat(parent),{k:getattr(pi,k)for k in identity}),(os.fstat(jf),os.stat(name,dir_fd=pf,follow_symlinks=False),identity)):
            need(all(getattr(held,k)==getattr(named,k)==v for k,v in pinned.items()),'gui-directory-drift')
        guards()
    def read_frame_pin(leaf,pin):
        f=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jf)
        try:
            s=os.fstat(f);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=16777216 and fp(s)==pin['fingerprint'],'gui-frame-pin');raw=os.read(f,16777217)
            need(len(raw)==s.st_size and hashlib.sha256(raw).hexdigest()==pin['sha256']and fp(s)==fp(os.fstat(f))==fp(os.stat(leaf,dir_fd=jf,follow_symlinks=False)),'gui-frame-pin')
        finally:os.close(f)
    def read_pin(leaf,pin):
        f=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jf)
        try:
            s=os.fstat(f);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=32768,'gui-record-shape');raw=os.read(f,32769)
            need(fp(s)==pin['fingerprint']==fp(os.fstat(f))==fp(os.stat(leaf,dir_fd=jf,follow_symlinks=False))and hashlib.sha256(raw).hexdigest()==pin['sha256'],'gui-record-pin');return json.loads(raw)
        finally:os.close(f)
    def create(leaf,value):
        guard();raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();need(0<len(raw)<=32768,'gui-record-cap')
        f=os.open(leaf,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=jf)
        try:
            need(os.write(f,raw)==len(raw),'gui-record-write');os.fsync(f);s=os.fstat(f);need(stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and fp(s)==fp(os.stat(leaf,dir_fd=jf,follow_symlinks=False)),'gui-record-name');pin={'fingerprint':fp(s),'sha256':hashlib.sha256(raw).hexdigest()};os.fsync(jf)
        finally:os.close(f)
        pins[leaf]=pin;guard();return pin
    c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.settimeout(5);stream=None;serial=0
    try:
        if phase=='enter':
            need(isinstance(prior,dict)and set(prior)=={'identity','pins','frames'}and prior['identity']==identity,'gui-original-typed-authority')
            pins.update(prior['pins']);frames.update(prior['frames']);guard()
            typed=read_pin('typed.json',pins['typed.json']);need(typed=={'state':'typed','flow':FLOW,'qemu':children[1]['child']},'gui-original-typed-record')
        guard();c.connect(LEAF+'/qmp.sock');peer=struct.unpack('3i',c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12));need(peer[0]==children[1]['child']['pid']and peer[1]==os.geteuid(),'gui-qmp-peer');guard();stream=c.makefile('rb')
        def response(wanted):
            for _ in range(16):
                raw=stream.readline(32769);need(0<len(raw)<=32768 and raw.endswith(b'\n'),'gui-qmp-cap');v=json.loads(raw)
                if wanted is None:need('QMP'in v,'gui-qmp-greeting');return
                if v.get('id')==wanted:need('return'in v and 'error'not in v,'gui-qmp-response');return
                need('event'in v,'gui-qmp-id')
            raise ValueError('gui-qmp-event-cap')
        def command(kind,args=None):
            nonlocal serial
            guard();serial+=1;packet={'execute':kind,'id':serial}
            if args is not None:packet['arguments']=args
            c.sendall(json.dumps(packet,separators=(',',':')).encode()+b'\n');response(serial);guard()
        response(None);command('qmp_capabilities')
        def capture(leaf):
            guard();need(not os.path.lexists(directory+'/'+leaf),'gui-frame-existing');command('screendump',{'filename':directory+'/'+leaf});sampled=time.monotonic()
            f=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=jf)
            try:
                s=os.fstat(f);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and 0<s.st_size<=16777216,'gui-frame-shape');os.fchmod(f,0o600);s=os.fstat(f);raw=os.read(f,16777217)
                need(len(raw)==s.st_size and fp(s)==fp(os.fstat(f))==fp(os.stat(leaf,dir_fd=jf,follow_symlinks=False)),'gui-frame-drift');validate_ppm(raw);os.fsync(f);os.fsync(jf);frames[leaf]={'fingerprint':fp(s),'sha256':hashlib.sha256(raw).hexdigest()};create(leaf+'.json',frames[leaf]);guard();return raw,sampled
            finally:os.close(f)
        before,sampled=capture(phase+'-before.ppm')
        _effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,None if phase=='wake'else phase=='typing')
        def fence():return create(phase+'-attempt.json',{'state':'consumed','flow':FLOW,'phase':phase,'qemu':children[1]['child'],'nonce':NONCE,'sourceSha256':BODY_SHA})
        if phase=='wake':
            def current():
                guard();_effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,None)
            def key():current();command('send-key',{'keys':[{'type':'qcode','data':'ret'}],'hold-time':100})
            def post():
                time.sleep(.75);raw,stamp=capture('wake-after.ppm');_screen_gate(raw,time.monotonic()-stamp,True);return raw,stamp
            after,post_at=_guarded_wake(before,time.monotonic()-sampled,current,fence,key,post);state='woken'
        else:
            fence();_effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,phase=='typing');guard()
        if phase=='typing':
            need(isinstance(keys,list)and 1<=len(keys)<=64,'gui-input-count');started=time.monotonic()
            for chord in keys:
                need(time.monotonic()-started<=15,'gui-typing-deadline');_effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,True);command('send-key',{'keys':[{'type':'qcode','data':key}for key in chord],'hold-time':100});time.sleep(.15)
            keys.clear();after,post_at=capture('typing-after.ppm');_screen_gate(after,time.monotonic()-post_at,False)
            create('typed.json',{'state':'typed','flow':FLOW,'qemu':children[1]['child']});state='typed'
        elif phase=='enter':
            _effect_gate(answer,time.monotonic()-focus_started,before,time.monotonic()-sampled,False);guard()
            command('send-key',{'keys':[{'type':'qcode','data':'ret'}],'hold-time':100});time.sleep(.75);after,post_at=capture('enter-after.ppm');state='entered'
        guard()
        return {'state':'observed','phase':state,'qemu':children[1]['child'],'guestChildPid':pid,'hostAuthority':{'identity':identity,'pins':pins,'frames':frames},'frameSha256':hashlib.sha256(after).hexdigest(),'frameAuthority':{'identity':identity,'pins':pins,'frames':frames},'appAdmission':False,'installerAction':False,'replayAllowed':False}
    except Exception as e:
        e.frameAuthority={'identity':identity,'frames':frames,'pins':pins};raise
    finally:
        if stream is not None:stream.close()
        c.close();os.close(jf);os.close(pf)


def _phase_program(record,phase,prior=None):
    source,sha,childsha=_fresh_reader(record,phase)
    if(phase in('wake','typing')and prior is not None)or(phase=='enter'and not isinstance(prior,dict)):raise ValueError('gui-fixed-authority-phase')
    support='FLOW='+repr(CORRELATION)+'\nTRANSFER='+repr(login.TRANSFER)+'\n_PROFILE='+repr(_PROFILE)+'\n_EMPTY='+repr(_EMPTY)+'\n_REVIEWED_PROFILES='+repr(_REVIEWED_PROFILES)+'\n'+inspect.getsource(login.validate_ppm)+inspect.getsource(_us_keys)+inspect.getsource(_crop_sha).replace('login.validate_ppm','validate_ppm')+inspect.getsource(_screen_gate)+inspect.getsource(_effect_gate).replace('secure.validate_layout','validate_layout').replace('secure.validate_focus','validate_focus').replace('login._validate_lockscreen','_validate_lockscreen')+inspect.getsource(login._validate_lockscreen)+inspect.getsource(login._guarded_wake)+inspect.getsource(_remote_input_action)
    if hashlib.sha256(support.encode()).hexdigest()!=_SUPPORT_SHA:raise ValueError('gui-support-source')
    marker='\ntry:\n children='
    if source.count(marker)!=1:raise ValueError('gui-composition-factory')
    source=source.replace(marker,'\n'+support+marker)
    launch=" guards();child=call(LEAF+'/qga.sock','guest-exec',"
    prefix=" guards();nraw=sys.stdin.buffer.read(4);need(len(nraw)==4,'gui-input-header');n=int.from_bytes(nraw,'big');need("+('1<=n<=64'if phase=='typing'else'n==0')+",'gui-input-bound');private_input=sys.stdin.buffer.read(n);need(len(private_input)==n,'gui-input-short');keys="+('_us_keys(private_input)'if phase=='typing'else'[]')+";private_input=b'';focus_started=time.monotonic();child=call(LEAF+'/qga.sock','guest-exec',"
    if source.count(launch)!=1:raise ValueError('gui-launch-factory')
    source=source.replace(launch,prefix)
    terminal=" result({'state':'observed','facts':answer,'qemu':children[1]['child'],'guestChildPid':pid,'appAdmission':False,'installerAction':False})"
    if source.count(terminal)!=1:raise ValueError('gui-terminal-factory')
    source=source.replace(terminal," result(_remote_input_action(answer,focus_started,"+repr(phase)+",keys,"+repr(prior)+"))")
    failure="'installerAction':False,'replayAllowed':False})"
    if source.count(failure)!=1:raise ValueError('gui-failure-factory')
    source=source.replace(failure,"'installerAction':False,'replayAllowed':False,'frameAuthority':getattr(e,'frameAuthority',None)})")
    compile(source,'gui-phase','exec');return source,sha,childsha


def _stream(argv,capture,diagnostic,nonce,sha,qemu,secret):
    import selectors,subprocess
    r=login.guest.recovery
    if not isinstance(secret,bytes)or len(secret)>64:raise ValueError('gui-private-input-bound')
    process=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    selector=selectors.DefaultSelector();chunks={'stdout':bytearray(),'stderr':bytearray()};pending=bytearray();events=[];child=None;deadline=time.monotonic()+60
    selector.register(process.stdout,selectors.EVENT_READ,'stdout');selector.register(process.stderr,selectors.EVENT_READ,'stderr')
    try:
        process.stdin.write(len(secret).to_bytes(4,'big')+secret);process.stdin.flush();secret=b''
        while selector.get_map():
            if time.monotonic()>=deadline:raise ValueError('gui-observer-deadline')
            for key,_ in selector.select(.25):
                data=os.read(key.fileobj.fileno(),4096)
                if not data:selector.unregister(key.fileobj);continue
                chunks[key.data].extend(data)
                if len(chunks[key.data])>262144:raise ValueError('gui-observer-byte-cap')
                if key.data=='stderr':
                    pending.extend(data)
                    while b'\n'in pending:
                        line,rest=pending.split(b'\n',1);pending=bytearray(rest)
                        if not line.startswith(b'CP117-OBSERVE '):continue
                        event=json.loads(line[14:])
                        if any(event.get(k)!=v for k,v in{'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'qemu':qemu}.items()):raise ValueError('gui-event-binding')
                        if event['kind']=='submitted':
                            if child is not None or type(event.get('pid'))is not int or event['pid']<=0:raise ValueError('gui-one-child')
                            child=event['pid']
                        elif event['kind']in('poll','terminal'):
                            if child is None or event.get('pid')!=child:raise ValueError('gui-same-child')
                        elif event['kind']!='exception':raise ValueError('gui-event-kind')
                        pin=capture.create(diagnostic+'-event-%d.json'%len(events),json.dumps(event,sort_keys=True).encode());os.fsync(capture.fd);events.append({'event':event,'pin':pin})
                        if event['kind']=='submitted':
                            ack=r._digest({'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'pid':child});process.stdin.write((ack+'\n').encode());process.stdin.flush()
        if process.wait(timeout=max(.001,deadline-time.monotonic()))!=0:raise ValueError('gui-observer-exit')
        value=json.loads(chunks['stdout']);return value,events
    except BaseException as e:
        e.events=events
        if process.poll()is None:process.kill()  # Only this local observer, never VM/app.
        process.wait(timeout=3);raise
    finally:
        capture.create(diagnostic+'-transport.stdout.private',bytes(chunks['stdout']));capture.create(diagnostic+'-transport.stderr.private',bytes(chunks['stderr']));os.fsync(capture.fd)
        selector.close();process.stdin.close();process.stdout.close();process.stderr.close()


def start(root):
    """One fixed wake, typing and Enter flow, no resumption after a lost local handle."""
    r=login.guest.recovery;root=Path(root).resolve(strict=True);leaf='windows-cp117-gui-login-'+CORRELATION
    if(root/'.runtime/parity-evidence'/leaf).exists():return {'state':'unknown','phase':'gui-consumed','replayAllowed':False}
    (root/'.runtime/parity-evidence'/leaf).mkdir(mode=0o700);capture=AuthorityCapture(root,leaf);original=AuthorityCapture(root,'windows-cp117-recovery-'+r.CORRELATION);secret=b'';events=[]
    try:
        raw=r._local_read(original,login.guest.ORIGINAL['name'],login.guest.ORIGINAL['pin']);record=json.loads(raw)
        files={Path(__file__):None,Path(secure.__file__):SECURE_SHA,Path(login.__file__):secure.LOGIN_SHA,Path(login.guest.__file__):login.GUEST_SHA,Path(login.session.__file__):login.SESSION_SHA};pins={str(path):r.authority._read_bound_file(path)for path in files}
        secret,credential_path,credential_pin=login._configured_secret(root);_us_keys(secret)
        derived=AuthorityCapture(root,'windows-cp117-credential-derived-3f392cc1-2ec8-49b0-b33c-c7a8d5dde0b9')
        try:
            proof_raw=r._local_read(derived,'proof.json',{'sha256':'fd6c745e0a1359ee2c22fb5b51101f5b0902c8892e8dbef3451344d040257226','generation':[16777234,111610387,33152,503,20,1,2709,1791052309116282181,1791052309116282181]});proof=json.loads(proof_raw)
            if proof['state']!='derived'or proof.get('historicalCredentialInputGenerationIndependentlyProven')is not False or proof.get('currentVmAdmission')is not False or proof['credential']['success']is not True or proof['credential']['expectedSid']!=login.guest.SID or proof['currentConfiguredCredentialGeneration']!=credential_pin['generation']:raise ValueError('gui-historical-credential-proof')
            def verify():
                if r._local_read(original,login.guest.ORIGINAL['name'],login.guest.ORIGINAL['pin'])!=raw:raise ValueError('gui-original-receipt')
                if r._local_read(derived,'proof.json',{'sha256':'fd6c745e0a1359ee2c22fb5b51101f5b0902c8892e8dbef3451344d040257226','generation':[16777234,111610387,33152,503,20,1,2709,1791052309116282181,1791052309116282181]})!=proof_raw:raise ValueError('gui-historical-proof-drift')
                for i,item in enumerate(record['authority']):
                    r._validate_frame(item['frame'],record['request'],record['authority'][:i])
                    if json.loads(r._local_read(original,'authority-%d.json'%i,item['localPin']))!=item['frame']:raise ValueError('gui-original-frame')
                sources=r.authority._source_pins(root);sources['recovery']=r.authority._read_bound_file(Path(r.__file__))
                if sources!=record['request']['sources']:raise ValueError('gui-original-source')
                for path,expected in files.items():
                    now=r.authority._read_bound_file(path)
                    if now!=pins[str(path)]or(expected is not None and now['sha256']!=expected):raise ValueError('gui-source-generation')
                if r.authority._read_bound_file(credential_path)!=credential_pin:raise ValueError('gui-credential-generation')
            verify();outer=r.authority._outer_authority(root);config,target,_=r.authority.closure.base._descriptor(root)
            if str(target.fixture_transfer_root)!=login.TRANSFER:raise ValueError('gui-transfer-config')
            capture.create('intent.json',json.dumps({'state':'consumed','flow':CORRELATION,'original':login.guest.ORIGINAL,'sources':pins,'outerAuthority':outer,'credentialGeneration':credential_pin['generation'],'historicalCredentialInputGenerationIndependentlyProven':False},sort_keys=True).encode());os.fsync(capture.fd)
            prior=None;typing_raw=None;typing_pin=None
            for phase in('wake','typing','enter'):
                verify();r.authority._verify_outer(root,{'outerAuthority':outer})
                if phase=='enter'and r._local_read(capture,'typing-result.json',typing_pin)!=typing_raw:raise ValueError('gui-positive-typing-receipt-drift')
                source,sha,childsha=_phase_program(record,phase,prior);diagnostic,nonce=_PHASES[phase]
                capture.create(phase+'-remote.py',source.encode());capture.create(phase+'-request.json',json.dumps({'flow':CORRELATION,'diagnosticId':diagnostic,'nonce':nonce,'sourceSha256':sha,'childSourceSha256':childsha,'programSha256':hashlib.sha256(source.encode()).hexdigest(),'original':login.guest.ORIGINAL},sort_keys=True).encode());os.fsync(capture.fd)
                argv=r.authority.closure.base.ssh_transport.build_ssh_argv(config,r.HOST,60,command=r.authority.closure.base.windows_credential_probe_ssh._remote_command(source))
                capture.create(phase+'-attempt.json',json.dumps({'state':'consumed','flow':CORRELATION,'phase':phase},sort_keys=True).encode());os.fsync(capture.fd);verify();r.authority._verify_outer(root,{'outerAuthority':outer})
                value,current_events=_stream(argv,capture,diagnostic,nonce,sha,record['result']['qemu'],secret if phase=='typing'else b'');events.extend(current_events)
                if phase=='typing':secret=b''
                verify();r.authority._verify_outer(root,{'outerAuthority':outer})
                phase_raw=json.dumps({'result':value,'events':current_events},sort_keys=True).encode();phase_pin=capture.create(phase+'-result.json',phase_raw);os.fsync(capture.fd)
                submitted=[e['event']for e in current_events if e['event']['kind']=='submitted']
                if value.get('state')!='observed'or value.get('phase')!=({'wake':'woken','typing':'typed','enter':'entered'}[phase])or value.get('qemu')!=record['result']['qemu']or len(submitted)!=1 or value.get('guestChildPid')!=submitted[0]['pid']:return {'state':'unknown','phase':value.get('phase','gui-phase-unknown'),'evidenceLeaf':leaf,'receipt':phase_pin,'replayAllowed':False}
                if phase=='typing':
                    typing_raw=phase_raw;typing_pin=phase_pin;prior=value['hostAuthority']
            return {'state':'observed','phase':'entered','evidenceLeaf':leaf,'receipt':phase_pin,'ordinaryOwnerAdmission':False,'installerAction':False,'replayAllowed':False}
        finally:derived.close()
    except Exception as e:
        events.extend(getattr(e,'events',[]));pin=capture.create('unknown.json',json.dumps({'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'events':events},sort_keys=True).encode());os.fsync(capture.fd)
        return {'state':'unknown','phase':str(e)if isinstance(e,ValueError)else type(e).__name__,'evidenceLeaf':leaf,'receipt':pin,'replayAllowed':False}
    finally:secret=b'';original.close();capture.close()
