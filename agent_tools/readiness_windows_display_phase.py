"""Source-owned durable, public-only display wake linked to one login original.

Builders are pure. The fixed phase can move the pointer once, never press a key,
click, dismiss a screen, submit credentials, or grant known-field authority.
"""
from __future__ import annotations
import hashlib
import inspect
import json
from uuid import UUID,uuid5
from . import readiness_windows_login as login,readiness_windows_login_continuation as continuation,readiness_windows_remote as packets
_EXECUTING_CODE=inspect.currentframe().f_code


def relation(original):
    if type(original)is not str or str(UUID(original))!=original:raise ValueError('display_wake_original_invalid')
    return {'originalOperationId':original,'phaseId':'display-wake-1','operationId':str(uuid5(UUID(original),'display-wake-1'))}


class _DisplayWakeOwner(login._ProtectedOwner):
    """Public-source owner; no protected stream is opened or accepted."""
    def __init__(self,root,identity,source):
        import hashlib
        source_sha=hashlib.sha256(source).hexdigest()
        super().__init__(root,identity['relation']['operationId'],identity,source_sha,source_sha)
        self.prefix='display-wake-'+self.operation;self.source=source;self.source_fd=None;self.source_pin=None;self.owner=None;self.attempted=False
    def _source_read(self):
        import os,stat,json
        path=self.root/(self.prefix+'.producer.json');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            s=os.fstat(fd);pin=self._pin(s)
            if not stat.S_ISREG(s.st_mode)or s.st_uid!=os.geteuid()or stat.S_IMODE(s.st_mode)!=0o600 or s.st_nlink!=1 or not 1<=s.st_size<=1048576 or pin!=self._pin(os.lstat(path)):raise ValueError('instance_display_wake_source_changed')
            raw=os.read(fd,1048577)
            if len(raw)!=s.st_size or pin!=self._pin(os.fstat(fd))or pin!=self._pin(os.lstat(path)):raise ValueError('instance_display_wake_source_changed')
            expected=json.dumps({'schemaVersion':1,'source':self.source.decode()},sort_keys=True,separators=(',',':')).encode()
            if raw!=expected:raise ValueError('instance_display_wake_source_changed')
            if self.source_fd is None:self.source_fd=fd;self.source_pin=pin;fd=None
            elif pin!=self.source_pin:raise ValueError('instance_display_wake_source_changed')
            return pin
        finally:
            if fd is not None:os.close(fd)
    def guard(self,deadline=True):
        import os
        super().guard(deadline)
        if self.intent is None:return
        if self.source_pin is None:self._source_read()
        if self._pin(os.fstat(self.source_fd))!=self.intent['producerGeneration']or self._pin(os.lstat(self.root/(self.prefix+'.producer.json')))!=self.intent['producerGeneration']:raise ValueError('instance_display_wake_source_changed')
    def _packet(self,packet):
        if type(packet)is not dict or not self._same(packet.get('relation'),self.identity['relation'])or packet.get('replayAllowed')is not False or packet.get('inputFieldAuthority')is not False or type(packet.get('wakeAttempted'))is not bool:raise ValueError('instance_display_wake_terminal')
        common={'relation','state','wakeAttempted','inputFieldAuthority','replayAllowed'}
        if packet.get('state')=='awake':
            if set(packet)!=common|{'boot','account','console','logon','displayState','acknowledgement'}or packet['boot']!=self.identity['expected']['boot']or packet['account']!=self.identity['account']or packet['console']!=self.identity['expected']['console']or packet['logon']!=self.identity['expected']['logon']or type(packet['displayState'])is not int or packet['displayState']!=1 or packet['wakeAttempted']is not True or packet['acknowledgement']not in {'received','lost'}:raise ValueError('instance_display_wake_terminal')
            if not self._same(self._read('.effect.intent.json'),{'relation':self.identity['relation'],'sourceSha256':self.source_sha,'replayAllowed':False})or not self._same(self._read('.effect.result.json'),{'relation':self.identity['relation'],'sourceSha256':self.source_sha,'acknowledgement':packet['acknowledgement'],'replayAllowed':False}):raise ValueError('instance_display_wake_terminal')
        elif packet.get('state')in {'blocked','cancelled'}:
            import re
            if set(packet)!=common|{'reason'}or type(packet['reason'])is not str or re.fullmatch('instance_[a-z_]{1,64}',packet['reason'])is None:raise ValueError('instance_display_wake_terminal')
        else:raise ValueError('instance_display_wake_terminal')
        return packet
    def existing(self):
        import os
        if not os.path.lexists(self.root/(self.prefix+'.intent.json')):return None
        value=self._read('.intent.json');fields={'schemaVersion','operationId','identity','sourceSha256','root','lock','hostBoot','creator','deadlineNs','replayAllowed','producerGeneration'}
        if type(value)is not dict or set(value)!=fields or type(value['schemaVersion'])is not int or value['schemaVersion']!=1 or value['operationId']!=self.operation or not self._same(value['identity'],self.identity)or value['sourceSha256']!=self.source_sha or value['hostBoot']!=self.identity['hostBoot']or value['replayAllowed']is not False or type(value['deadlineNs'])is not int or type(value['creator'])is not dict or set(value['creator'])!={'pid','birth'}or any(type(value['creator'][k])is not int or value['creator'][k]<=0 for k in ('pid','birth'))or any(type(value[k])is not list or len(value[k])!=n or any(type(x)is not int for x in value[k])for k,n in (('root',5),('lock',9),('producerGeneration',9))):raise ValueError('instance_display_wake_identity')
        self.intent=value;self.guard(False)
        if os.path.lexists(self.root/(self.prefix+'.terminal.json')):
            terminal=self._read('.terminal.json');owner=self._read('.owner.json');self._owner_valid(owner)
            if type(terminal)is not dict or set(terminal)!={'admission','owner','packet'}or not self._same(terminal['admission'],value)or not self._same(terminal['owner'],owner):raise ValueError('instance_display_wake_terminal')
            return {'state':'terminal','packet':self._packet(terminal['packet'])}
        try:owner=self._read('.owner.json')
        except FileNotFoundError:return {'state':'unknown','relation':self.identity['relation'],'replayAllowed':False}
        self._owner_valid(owner)
        return {'state':'running'if self._birth(owner['pid'])==owner['birth']else'unknown','relation':self.identity['relation'],'replayAllowed':False}
    def cancelled(self):
        import os
        if not os.path.lexists(self.root/(self.prefix+'.cancel.json')):return False
        value=self._read('.cancel.json')
        if not self._same(value,{'relation':self.identity['relation'],'sourceSha256':self.source_sha,'replayAllowed':False}):raise ValueError('instance_display_wake_cancel_changed')
        return True
    def cancel(self):
        import os
        self.guard(False)
        if not os.path.lexists(self.root/(self.prefix+'.cancel.json')):self._save('.cancel.json',{'relation':self.identity['relation'],'sourceSha256':self.source_sha,'replayAllowed':False})
        self.cancelled();self.guard(False)
    def start(self,lock,held,*,budget_seconds=90,wait_seconds=60):
        import os,sys,time,math,resource
        if not sys.platform.startswith('linux')or type(budget_seconds)not in {int,float}or not math.isfinite(budget_seconds)or not 0<budget_seconds<=180:raise ValueError('instance_display_wake_budget')
        self.lock=lock
        try:self._source_read()
        except FileNotFoundError:self._save('.producer.json',{'schemaVersion':1,'source':self.source.decode()});self._source_read()
        self.intent={'schemaVersion':1,'operationId':self.operation,'identity':self.identity,'sourceSha256':self.source_sha,'root':self._root_pin(),'lock':self._pin(os.fstat(lock)),'hostBoot':self.identity['hostBoot'],'creator':{'pid':os.getpid(),'birth':self._birth(os.getpid())},'deadlineNs':time.monotonic_ns()+int(budget_seconds*1e9),'replayAllowed':False,'producerGeneration':self.source_pin};self.guard()
        resource.setrlimit(resource.RLIMIT_CORE,(0,0));self._save('.intent.json',self.intent)
        pid=os.fork()
        if pid:
            limit=time.monotonic()+min(wait_seconds,budget_seconds)
            while time.monotonic()<limit:
                value=self.existing()
                if value['state']=='terminal':return value
                if self._birth(pid)is None:return value
                time.sleep(.02)
            return self.existing()
        self.child=True
        try:
            os.setsid();keep=set(held)|{lock,self.source_fd}
            for name in os.listdir('/proc/self/fd'):
                fd=int(name)
                if fd>2 and fd not in keep:
                    try:os.close(fd)
                    except OSError:pass
            null=os.open(os.devnull,os.O_RDWR)
            for fd in (0,1,2):os.dup2(null,fd)
            if null>2:os.close(null)
            self.guard();self.owner={'operationId':self.operation,'sourceSha256':self.source_sha,'pid':os.getpid(),'birth':self._birth(os.getpid())};self._owner_valid(self.owner);self._save('.owner.json',self.owner);self.guard();return None
        except BaseException:os._exit(70)
    def effect(self):
        self.guard()
        if self.cancelled():raise ValueError('instance_display_wake_cancelled')
        self._save('.effect.intent.json',{'relation':self.identity['relation'],'sourceSha256':self.source_sha,'replayAllowed':False})
        self.guard()
        if self.cancelled():raise ValueError('instance_display_wake_cancelled')
    def finish(self,packet):
        self.guard(False);self._packet(packet);self._save('.terminal.json',{'admission':self.intent,'owner':self.owner,'packet':packet});self.guard(False)


def _display_phase_guard(root,guard):
    actual=_original_phase(root,DISPLAY_IDENTITY['relation']['originalOperationId'],DISPLAY_BARRIER['originalIdentity'],DISPLAY_BARRIER['originalSourceSha256'],DISPLAY_OWNER.lock)
    if not DISPLAY_OWNER._same(actual,DISPLAY_BARRIER):raise ValueError('instance_display_wake_original_changed')
    names=[p.name for p in root.iterdir()]
    if len(names)>8192:raise ValueError('instance_display_wake_history_bound')
    for name in names:
        if name.endswith('.intent.json')and name.startswith('display-wake-')and name not in {DISPLAY_OWNER.prefix+'.intent.json',DISPLAY_OWNER.prefix+'.effect.intent.json'}:raise ValueError('instance_display_wake_prior_unresolved')
        if name.endswith('.intent.json')and name.startswith('login-owner-')and name!='login-owner-'+DISPLAY_IDENTITY['relation']['originalOperationId']+'.intent.json':raise ValueError('instance_display_wake_prior_unresolved')
        if name.endswith('.intent.json')and name.startswith('login-credential-'):raise ValueError('instance_display_wake_prior_unresolved')
    DISPLAY_OWNER.guard();guard()


def _display_facts(probe):
    expected=DISPLAY_IDENTITY['expected'];sid=DISPLAY_IDENTITY['account']
    if type(probe)is not dict or set(probe)!={'sessionFacts','displayFacts','accountFacts'}:raise ValueError('instance_display_wake_observation')
    fresh=probe['sessionFacts'];row=fresh['session'];account=probe['accountFacts'];display=probe['displayFacts']
    if fresh['machine'].lower()!=SPEC['deploymentId']or fresh['ordinary']is not True or fresh['expectedSid']!=sid or fresh['tokenSid']!=sid or fresh['boot']!=expected['boot']or fresh['console']!=expected['console']or row['SessionId']!=expected['console']or row['Logon']!=expected['logon']or row['User'].casefold()!=expected['user'].casefold()or type(row['Flags'])is not int or row['Flags']!=0 or type(row['State'])is not int or row['State']!=0:raise ValueError('instance_display_wake_session_changed')
    if type(account)is not dict or set(account)!={'name','fullName','sid','enabled','loginKeyboard'}or account['name'].casefold()!=SETUP['user'].casefold()or account['sid']!=sid or account['enabled']is not True or account['loginKeyboard']!='00000409':raise ValueError('instance_display_wake_account_changed')
    if type(display)is not dict or set(display)!={'schemaVersion','machine','boot','displayState'}or type(display['schemaVersion'])is not int or display['schemaVersion']!=1 or display['machine']!=SPEC['deploymentId']or display['boot']!=expected['boot']or type(display['displayState'])is not int or display['displayState']not in {0,1,2}:raise ValueError('instance_display_wake_display_unknown')
    return display['displayState']


def _display_wake_flow(root,guard,script,monitor,before):
    import os,time
    expected=DISPLAY_IDENTITY['expected']
    if any(before[k]!=expected[k]for k in ('actor','hostBoot','controlConnection')):raise ValueError('instance_display_wake_target_changed')
    def observe():
        _display_phase_guard(root,guard);probe=script('display-phase-'+os.urandom(6).hex(),DISPLAY_SCRIPT);state=_display_facts(probe);_display_phase_guard(root,guard);return state
    if observe()!=0:raise ValueError('instance_display_wake_not_asleep')
    _display_phase_guard(root,guard);DISPLAY_OWNER.effect();_display_phase_guard(root,guard)
    acknowledgement='received';DISPLAY_OWNER.attempted=True
    try:monitor('input-send-event',{'events':[{'type':'rel','data':{'axis':'x','value':1}}]})
    except Exception:acknowledgement='lost'
    DISPLAY_OWNER.guard();DISPLAY_OWNER._save('.effect.result.json',{'relation':DISPLAY_IDENTITY['relation'],'sourceSha256':DISPLAY_OWNER.source_sha,'acknowledgement':acknowledgement,'replayAllowed':False})
    # A missing acknowledgement never permits another event.
    deadline=time.monotonic()+8
    while True:
        state=observe()
        if state==1:break
        if time.monotonic()>=deadline:raise ValueError('instance_display_wake_unresolved')
        time.sleep(.2)
    return {'relation':DISPLAY_IDENTITY['relation'],'state':'awake','wakeAttempted':True,'boot':expected['boot'],'account':DISPLAY_IDENTITY['account'],'console':expected['console'],'logon':expected['logon'],'displayState':1,'acknowledgement':acknowledgement,'inputFieldAuthority':False,'replayAllowed':False}


def observation_source(binding):
    """Canonical WTS+initial display notification+ordinary account, one controller."""
    source=packets._interactive_source(binding['setup']['user'],binding['spec']['deploymentId']);last=source.splitlines()[-1]
    if last!='[Console]::WriteLine((@{sessionFacts=$sessionFacts;displayFacts=$displayFacts}|ConvertTo-Json -Depth 10 -Compress))':raise ValueError('display_wake_observer_producer')
    account=login.LOGIN_ACCOUNT.replace('__USER__',repr(binding['setup']['user']));end=account.splitlines()[-1]
    if not end.startswith('[Console]::WriteLine((')or not end.endswith('|ConvertTo-Json -Compress))'):raise ValueError('display_wake_observer_producer')
    expression=end[len('[Console]::WriteLine(('):-len('|ConvertTo-Json -Compress))')]
    return source.removesuffix(last+'\n')+account.removesuffix(end+'\n')+'$accountFacts='+expression+'\n[Console]::WriteLine((@{sessionFacts=$sessionFacts;displayFacts=$displayFacts;accountFacts=$accountFacts}|ConvertTo-Json -Depth 10 -Compress))\n'


def program(original,barrier,*,budget_seconds=90):
    """Pure current-source builder. Runtime argv is exactly start/status/cancel."""
    from .readiness_windows_remote import validate_binding
    from pathlib import Path
    path=Path(__file__).absolute();own=path.read_bytes()
    if _EXECUTING_CODE!=compile(own,str(path),'exec',dont_inherit=True):raise ValueError('display_wake_producer_code_changed')
    if type(original)is not continuation._AuthenticatedOriginal or type(original.source)is not bytes or type(original.identity)is not dict:raise ValueError('display_wake_source_authority')
    original.guard();original_identity=original.identity
    if set(original_identity)!={'binding','operationId','expectedSid','expected','profile'}:raise ValueError('display_wake_source_authority')
    binding=original_identity['binding'];validate_binding(binding)
    import ast
    assignments={}
    for node in ast.parse(original.source).body:
        if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
            try:assignments[node.targets[0].id]=ast.literal_eval(node.value)
            except (ValueError,TypeError):pass
    if type(barrier)is not dict or set(barrier)!={'schemaVersion','operationId','originalSourceSha256','originalIdentity','root','lock','records','wholeAttemptUnsubmitted','credentialOnly','replayAllowed'}or type(barrier.get('schemaVersion'))is not int or barrier.get('schemaVersion')!=1 or barrier['operationId']!=original_identity['operationId']or barrier['wholeAttemptUnsubmitted']is not False or barrier['credentialOnly']is not True or barrier['replayAllowed']is not False or type(barrier['records'])is not dict or any(type(barrier[k])is not list or len(barrier[k])!=n or any(type(v)is not int for v in barrier[k])for k,n in (('root',5),('lock',9)))or barrier.get('originalSourceSha256')!=hashlib.sha256(original.source).hexdigest()or assignments.get('LOGIN_MODE')!='login-submit'or assignments.get('MODE')!='login-submit'or assignments.get('OPERATION')!=original_identity['operationId']or not continuation._exact(assignments.get('LOGIN_PROFILE'),original_identity['profile'])or not continuation._exact(assignments.get('LOGIN_EXPECTED'),original_identity['expected'])or assignments.get('LOGIN_SID')!=original_identity['expectedSid']:raise ValueError('display_wake_source_authority')
    operation=original_identity['operationId'];linked=relation(operation)
    if not continuation._exact(barrier.get('originalIdentity'),{'expected':original_identity['expected'],'profile':original_identity['profile'],'account':original_identity['expectedSid'],'machine':binding['spec']['deploymentId'],'hostBoot':binding['context']['hostBootId'],'user':binding['setup']['user']}):raise ValueError('display_wake_original_binding')
    if type(budget_seconds)is not int or not 1<=budget_seconds<=180:raise ValueError('display_wake_budget')
    identity={'relation':linked,'expected':original_identity['expected'],'account':original_identity['expectedSid'],'hostBoot':binding['context']['hostBootId'],'barrierSha256':continuation._identity_digest(barrier)}
    source=login.program(binding,'login-probe',operation,expected_sid=identity['account'],profile={},expected=identity['expected'],original_operation=operation).decode()
    init="        epoch();chain()\n        login_owner=None"
    admission="""        epoch();chain()
        phase_owner=_DisplayWakeOwner(root,DISPLAY_IDENTITY,DISPLAY_PRODUCER)
        globals()['DISPLAY_OWNER']=phase_owner
        phase_action=sys.argv[1]if len(sys.argv)==2 else None
        require(phase_action in {'start','status','cancel'},'instance_display_wake_action')
        phase_existing=phase_owner.existing()
        if phase_existing is not None:
            if phase_action=='cancel'and phase_existing['state']!='terminal':phase_owner.cancel()
            print(json.dumps(phase_owner.existing()));return
        if phase_action!='start':print(json.dumps({'state':'unsubmitted','relation':DISPLAY_IDENTITY['relation'],'replayAllowed':False}));return
        login_owner=None"""
    if source.count(init)!=1:raise ValueError('display_wake_main_producer')
    source=source.replace(init,admission,1)
    point="        if login_owner is not None:\n            login_owner.lock=lock"
    start="""        phase_launched=phase_owner.start(lock,held,budget_seconds=DISPLAY_BUDGET)
        if phase_launched is not None:print(json.dumps(phase_launched));return
        plain_phase_guard=vm_guard
        def vm_guard():phase_owner.guard();plain_phase_guard()
        if login_owner is not None:
            login_owner.lock=lock"""
    if source.count(point)!=1:raise ValueError('display_wake_main_producer')
    source=source.replace(point,start,1)
    branch="            fresh=script('login-session-'+os.urandom(6).hex(),SESSION_SCRIPT)\n            result['guestAgent']=True\n            result.update(_login_flow(root,read,save,monitor,vm_guard,script,fresh,result))"
    replacement="            phase_packet=_display_wake_flow(root,vm_guard,script,monitor,result)\n            phase_owner.finish(phase_packet)\n            print(json.dumps({'state':'terminal','packet':phase_packet}));return"
    if source.count(branch)!=1:raise ValueError('display_wake_main_producer')
    source=source.replace(branch,replacement,1)
    failure="        failed={'state':'blocked','operationId':OPERATION,'reason':reason,'errorClass':type(error).__name__,'replayAllowed':False}"
    replacement="""        if locals().get('phase_owner')is not None and phase_owner.child:
            packet={'relation':DISPLAY_IDENTITY['relation'],'state':'cancelled'if reason=='instance_display_wake_cancelled'else'blocked','reason':reason,'wakeAttempted':phase_owner.attempted,'inputFieldAuthority':False,'replayAllowed':False}
            try:phase_owner.finish(packet)
            except BaseException:pass
        failed={'state':'blocked','operationId':OPERATION,'reason':reason,'errorClass':type(error).__name__,'replayAllowed':False}"""
    if source.count(failure)!=1:raise ValueError('display_wake_main_producer')
    source=source.replace(failure,replacement,1)
    final='        if locals().get(\'login_owner\')is not None and login_owner.child:os._exit(0)'
    if source.count(final)!=1:raise ValueError('display_wake_main_producer')
    source=source.replace(final,final+"\n        if locals().get('phase_owner')is not None and phase_owner.child:os._exit(0)",1)
    source=source.removesuffix('_main()\n')+'\n_OriginalProtectedOwner=_ProtectedOwner\nDISPLAY_IDENTITY='+repr(identity)+'\nDISPLAY_BARRIER='+repr(barrier)+'\nDISPLAY_BUDGET='+repr(budget_seconds)+'\nDISPLAY_SCRIPT='+repr(observation_source(binding))+'\n'
    for helper in (continuation._original_phase,_DisplayWakeOwner,_display_phase_guard,_display_facts,_display_wake_flow):source+=inspect.getsource(helper).replace('class _DisplayWakeOwner(login._ProtectedOwner):','class _DisplayWakeOwner(_ProtectedOwner):')+'\n'
    source+='\n_main()\n';compile(source,'fixed source-owned display wake owner','exec')
    # The wrapper retains the complete executable public producer before admission.
    original.guard()
    return ('import base64,hashlib\nDISPLAY_PRODUCER=base64.b64decode('+repr(__import__('base64').b64encode(source.encode()).decode())+')\nexec(compile(DISPLAY_PRODUCER,"fixed display wake producer","exec"))\n').encode()
