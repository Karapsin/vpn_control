"""Whole ordinary postboot action and the helpers the preboot action shares; no import-time effects.

The at-logon GUI, its controller and runtime are retained native actors, never
fabricated Child objects. The GUI and its controller, the GUI's own vpn-control.exe
--headless-controller --state-dir <workspace>, each run their own JVM unless their
launcher relaunched into one child of the same image (own_jvm). Their known OFF/QUIT
retirement is an explicit test boundary. A refusal with no effect pending is a known
failure; only a live or uncertain effect parks the owner.
"""
from pathlib import Path, PureWindowsPath
import hashlib
import json
import math
import time


def need(ok,code):
    if not ok:raise ValueError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def wire(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def public(owner,workspace,identity,*args,codes=('OK',),exits=(0,),final=True):
    owner.guard();before=len(owner.children)
    tail=['--json']+(['--controller-id',identity] if identity is not None else [])+list(args)
    value=owner.invoke(workspace,*tail)
    need(len(owner.children)==before+1,'one-original-public-child')
    child=owner.children[-1]
    need(child.owner is owner and child.terminal is not None and child.terminal['eof']=={'stdout':True,'stderr':True}
         and tuple(child.argv)==(owner.request['cliPath'],'--state-dir',str(workspace),*tail), 'original-public-child-custody')
    need(value.returncode in exits and value.stderr=='' and len(value.stdout.encode())<=1024*1024,'postboot-public-known-terminal')
    body=json.loads(value.stdout)
    need(body.get('schemaVersion')==1 and body.get('code') in codes and body.get('final') is final
         and body.get('ok') is (value.returncode==0) and (body.get('code')=='UNAVAILABLE' or (type(body.get('controllerId'))is str and body['controllerId']))
         and type(body.get('requestId'))is str and body['requestId'] and (identity is None or body['controllerId']==identity),
         'postboot-public-original-envelope')
    owner.guard();return body,child


def version_probe(owner,workspace):
    """--help and --version of the installed CLI under this ordinary token: what an installed-package claim needs."""
    for argv,text in ((['--help'],'Usage:'),(['--version'],owner.request['productVersion'])):
        value=owner.invoke(workspace,*argv)
        need(value.returncode==0 and value.stderr=='' and text in value.stdout,'static-public-launcher-probe')


def held_json(lease,path):
    def unique(pairs):
        value={}
        for key,item in pairs:
            need(key not in value,'duplicate-whole-postboot-input-key');value[key]=item
        return value
    return json.loads(lease.read(path),object_pairs_hook=unique)


def effect(owner,label):
    """An effect whose outcome is not yet observed: a failure while one is pending parks, never returns."""
    need(getattr(owner,'reboot_effect',None) is None,'one-pending-reboot-effect')
    owner.reboot_effect=label


def observed(owner):
    owner.reboot_effect=None


def traffic_input(owner,lease,source_roles):
    traffic=held_json(lease,lease.config['trafficInputPath'])
    need(type(traffic)is dict and set(traffic)=={'schemaVersion','mixedPort','expectedBodyHex','sampleCount','intervalSeconds','ioTimeoutSeconds'}
         and traffic['schemaVersion']==1 and traffic['mixedPort'] is None
         and type(traffic['sampleCount'])is int and 4<=traffic['sampleCount']<=16
         and all(type(traffic[k])in(int,float) and math.isfinite(traffic[k]) and low<=traffic[k]<=high
            for k,low,high in [('intervalSeconds',.02,.5),('ioTimeoutSeconds',.1,5)]),
         'closed-finite-pinned-traffic-input-before-actual-port-override')
    need(bytes.fromhex(traffic['expectedBodyHex'])==source_roles.UPSTREAM_TOKEN.encode('ascii'),'same-owned-upstream-fixture-body')
    return traffic


def start_upstream(owner,lease,source_roles,label):
    """The in-guest SOCKS upstream on its fixed loopback port; it is this owner's child and stops before finish."""
    traffic_input(owner,lease,source_roles)
    ready=owner.root/('upstream-'+label+'.ready')
    need(not ready.exists(),'fresh-owned-upstream-ready-file')
    child=owner.child('owned-upstream-'+label,[owner.request['pythonRuntime']['interpreterPath'],'-I','-B',lease.paths['upstreamFixture'],
        '--port',str(source_roles.UPSTREAM_PORT),'--token',source_roles.UPSTREAM_TOKEN,'--ready-file',str(ready)])
    until=time.monotonic()+30
    while not ready.exists():
        need(child.process.poll() is None,'owned-upstream-ended-before-ready')
        if time.monotonic()>=until:owner.park('owned-upstream-readiness-unknown-no-replay')
        time.sleep(.1)
    time.sleep(.2)
    need(ready.read_text(encoding='utf-8').strip()==str(source_roles.UPSTREAM_PORT) and child.process.poll() is None,'owned-upstream-fixed-port')
    owner.event('owned-upstream-ready',{'child':child.ordinal,'pid':child.pid,'port':source_roles.UPSTREAM_PORT})
    return child


def stop_upstream(owner,child):
    """Exactly one original Popen termination of the owned upstream, journaled first."""
    need(child.owner is owner and child.terminal is None and child.process.poll() is None,'live-original-owned-upstream')
    owner.event('owned-upstream-stop-intent',{'child':child.ordinal,'pid':child.pid,'birthFileTimeUtc':child.birth,'replayAllowed':False})
    effect(owner,'owned-upstream-stop')
    child.process.terminate()
    until=time.monotonic()+15
    while child.observe() is None:
        if time.monotonic()>=until:owner.park('owned-upstream-stop-unknown-no-replay')
        time.sleep(.05)
    observed(owner)
    owner.event('owned-upstream-stopped',child.terminal)
    return child.terminal


def end_upstream(owner,child):
    """After a known refusal: stop the owned upstream that still runs, or collect the end it already reached."""
    if child is None or child.terminal is not None:return
    if child.process.poll() is None:stop_upstream(owner,child)
    else:child.wait()


class Actor:
    def __init__(self,owner,native,expected,role):
        self.owner,self.native,self.expected,self.role=owner,native,dict(expected),role
        self.process=None;self.closed=False
        if not hasattr(owner,'postboot_actor_leases'):owner.postboot_actor_leases=[]
        owner.postboot_actor_leases.append(self)
        owner.guard();self.process=native.open_process(expected['pid'],0x101000)
        self.live()
    def live(self):
        self.owner.guard();need(not self.closed and self.process is not None,'retained-original-startup-actor')
        actual=self.process.describe();e=self.expected;ctx=self.owner.request['context']
        need(self.process.wait()==258 and actual['creationFileTime']==e['creationFileTime']
             and actual['image'].casefold()==e['image'].casefold() and actual['sha256']==e['sha256']
             and actual['token']['sid']==ctx['ordinarySid']==e['sid']
             and actual['token']['sessionId']==ctx['ordinarySessionId']==e['sessionId']
             and actual['token']['elevated']==0,'actual-startup-generation-image-token')
        return actual
    def await_exit(self,label,seconds=30,*,until=None,refusal=None):
        """Wait on the retained handle. At the bound a pending effect parks; with refusal, the caller has already
        observed its effect, so a generation still running is journaled and refused as a known failure."""
        need(not self.closed and self.process is not None,'original-startup-exit-handle')
        until=time.monotonic()+seconds if until is None else until
        while self.process.wait()==258:
            self.owner.guard()
            if time.monotonic()>=until:
                if refusal is None:self.owner.park('postboot-original-'+self.role+'-exit-unknown-no-replay')
                self.owner.event(refusal,{'actor':self.expected,'role':self.role,'replayAllowed':False})
                raise ValueError(refusal)
            time.sleep(.05)
        times=self.process.times();need(self.process.wait()==0 and times['creationFileTime']==self.expected['creationFileTime'],
            'positive-original-startup-handle-exit')
        result={'actor':self.expected,'times':times,'originalHandleSignaled':True,'pidReopened':False,'childEofClaimed':False}
        self.owner.event(label,result);self.process.__exit__(None,None,None);self.closed=True
        return result


class Endpoint:
    """Private endpoint observer: export only port/controller ID, never token."""
    def __init__(self,owner,workspace,leaf,actor,branches,lease):
        need(leaf in {'activation.port','frontend.port'},'fixed-product-endpoint-role')
        self.owner,self.actor,self.handle=owner,actor,None
        if not hasattr(owner,'postboot_endpoint_leases'):owner.postboot_endpoint_leases=[]
        owner.postboot_endpoint_leases.append(self)
        self.path=str(PureWindowsPath(workspace)/leaf)
        self.handle=owner.native.k.CreateFileW(self.path,0x80020000,7,None,3,0x02200000,None)
        need(self.handle not in (None,-1,(1<<64)-1),'original-product-private-endpoint-open')
        opening=owner.native.identity(self.handle);security=owner.native.security(self.handle)
        need(security['ownerSid']==owner.request['context']['ordinarySid'] and opening['sizeBytes']<=4096,
            'ordinary-bounded-private-product-endpoint')
        raw=bytearray()
        try:
            for block in owner.native.read_blocks(self.handle):raw.extend(block);need(len(raw)<=4096,'private-endpoint-read-bound')
            value=json.loads(raw);need(value['schemaVersion']==1 and type(value['controllerId'])is str
                and type(value['port'])is int and 1<=value['port']<=65535,'actual-product-endpoint-schema')
            self.public={'controllerId':value['controllerId'],'port':value['port']}
            value.pop('token',None);value.clear()
        finally:raw[:]=b'\0'*len(raw)
        need(owner.native.identity(self.handle)==opening,'original-private-endpoint-native-closing')
        query={'powerShellPath':lease.paths['powerShell'],'listenerScriptPath':lease.paths['listenerScript']}
        rows=branches.listeners(owner,query,actor.expected)
        need(any(row['pid']==actor.expected['pid'] and row['port']==self.public['port'] and row['address'] in {'127.0.0.1','::1'}
            for row in rows),'private-endpoint-port-original-actor-generation')
        actor.live();owner.event('postboot-original-endpoint-bound',{'leaf':leaf,'actor':actor.expected,
            'public':self.public,'nativeIdentity':opening,'tokenExportedOrHashed':False})
    def close_after_known_actor_exit(self):
        need(self.actor.closed and self.handle is not None,'known-original-endpoint-owner-exit-before-observer-close')
        need(bool(self.owner.native.k.CloseHandle(self.handle)),'original-private-endpoint-observer-close');self.handle=None


def census(owner,lease,label):
    """One read-only native census of GUI, CLI and runtime processes in the ordinary session."""
    workspace=owner.request['workspace'];roles=lease.paths;ctx=owner.request['context']
    collector=owner.child(label,[roles['powerShell'],'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',roles['startupCollector'],'-GuiPath',roles['gui'],'-CliPath',owner.request['cliPath'],'-Workspace',workspace,
        '-ExpectedSession',str(ctx['ordinarySessionId'])])
    value=collector.completed();need(value.returncode==0 and value.stderr=='' and len(value.stdout.encode())<=262144,'startup-census-original-terminal')
    record=json.loads(value.stdout)
    need(record['schemaVersion']==1 and record['collector']=='prequery-native-startup-census' and record['pid']==collector.pid
         and str(record['creationFileTime'])==str(collector.birth) and record['sessionId']==ctx['ordinarySessionId'],
         'same-original-startup-census-source-child')
    rows=record['rows'];need(type(rows)is list and len(rows)<=128,'finite-native-startup-census')
    return record,rows,collector


def born_children(rows,parent,image):
    """A parent PID outlives its process: only a census row born at or after its parent is that parent's child."""
    return [row for row in rows if row['parentPid']==parent['pid'] and row['image'].casefold()==image.casefold()
            and int(row['creationFileTime'])>=int(parent['creationFileTime'])]


def own_jvm(rows,launcher,image,code):
    """The process that runs a launcher's JVM: its one relaunch, or the launcher itself.

    jpackage relaunches a launcher only while PATH lacks <image>\\app, into one same-image child with the
    launcher's own argv (3576 to 1068 in f56f4a4c); a launcher whose PATH holds it runs its JVM in place, as
    the query CLI's controller did there. Other same-image children, such as the controller a GUI that did not
    relaunch starts, are no relaunch. capture_proxy_actors follows the same rule.
    """
    relaunched=[row for row in born_children(rows,launcher,image) if row['argv']==launcher['argv']]
    need(len(relaunched)<=1,code)
    return relaunched[0] if relaunched else launcher


def product_tree(owner,lease,rows,running,*,root_parent=None):
    """The product's own start: the GUI, the controller its JVM started, and the runtime.

    The autostart GUI launcher's parent is no product process. It and the controller its JVM starts with the
    real owner argv each run their own JVM unless they relaunched (own_jvm), and only a launcher that relaunched
    adds a guiLauncher or controllerLauncher role beside its gui or controller. Natively recorded, in f56f4a4c:
    an owner-started GUI that relaunched and a CLI-started controller that did not. Inferred, not recorded: the
    shapes of the GUI the autostart task starts and of the controller that GUI starts through the same
    DesktopHeadlessController.startForCliCommand, so every combination is taken. Every product image in the
    census belongs to this one tree, nothing else.
    """
    workspace=owner.request['workspace'];roles=lease.paths;ctx=owner.request['context']
    gui=roles['gui'];runtime_image=str(PureWindowsPath(workspace)/'runtime'/'tools'/'sing-box.exe')
    same=lambda row,image:row['image'].casefold()==image.casefold()
    launchers=[row for row in rows if same(row,gui) and row['argv']==[gui,'--autostart','--state-dir',workspace]
               and not any(other['pid']==row['parentPid'] for other in rows)]
    need(len(launchers)==1 and (root_parent is None or launchers[0]['parentPid']==root_parent),'one-actual-autostart-gui-launcher')
    jvm=own_jvm(rows,launchers[0],gui,'one-gui-jvm-child')
    controllers=[row for row in born_children(rows,jvm,gui) if row['argv']==[gui,'--headless-controller','--state-dir',workspace]]
    need(len(controllers)==1,'one-gui-started-controller-launcher')
    controller=own_jvm(rows,controllers[0],gui,'one-controller-jvm-child')
    runtimes=born_children(rows,controller,runtime_image)
    need(len(runtimes)==(1 if running else 0),'reconnect-or-off-native-runtime-census')
    tree={'gui':jvm,'controller':controller}
    if jvm is not launchers[0]:tree['guiLauncher']=launchers[0]
    if controller is not controllers[0]:tree['controllerLauncher']=controllers[0]
    if runtimes:tree['runtime']=runtimes[0]
    need({row['pid'] for row in tree.values()}=={row['pid'] for row in rows if same(row,gui) or same(row,runtime_image)},
         'every-product-process-in-the-one-autostart-tree')
    actors={}
    for role,row in tree.items():
        image=runtime_image if role=='runtime' else gui
        digest=lease.runtime_sha256() if role=='runtime' else lease.pins['gui'].record['sha256']
        need(row['sessionId']==ctx['ordinarySessionId'] and row['creationFileTime']>int(ctx['bootFileTimeUtc']),'actual-product-start-this-boot')
        actors[role]={'pid':row['pid'],'parentPid':row['parentPid'],'creationFileTime':row['creationFileTime'],'image':image,
                      'sha256':digest,'sid':ctx['ordinarySid'],'sessionId':ctx['ordinarySessionId']}
    return actors


def retained(owner,native,actors):
    """Hold each GUI, controller and runtime JVM generation: image hash, token and session checked live."""
    held={}
    for role in ('guiLauncher','gui','controllerLauncher','controller','runtime'):
        if role in actors:
            held[role]=Actor(owner,native,{key:actors[role][key] for key in ('pid','creationFileTime','image','sha256','sid','sessionId')},role)
    return held


def startup_before_query(owner,lease,observer,lifecycle,running):
    need(not any(child.label=='public-cli' for child in owner.children),'autostart-native-observation-before-first-public-query')
    record,rows,collector=census(owner,lease,'postboot-startup-native-census')
    native=observer.WindowsNative();actors=product_tree(owner,lease,rows,running)
    held=retained(owner,native,actors)
    windows=lifecycle.GuiWindows();before_windows=windows.windows(held['gui'].expected['pid'])
    owner.event('postboot-startup-prequery-native-observed',{'census':record,'censusChild':collector.ordinal,
        'actors':actors,'windows':before_windows,'actorCustody':'retained-native-handles-not-Child','firstPublicQueryHasNotRun':True})
    return held,actors,native,windows


def verify_gui(owner,workspace,identity,gui,windows):
    for command,visible in [('show',True),('hide',False),('show',True)]:
        gui.live();body,child=public(owner,workspace,identity,'gui',command)
        until=time.monotonic()+30
        while True:
            gui.live();records=windows.windows(gui.expected['pid']);main=[r for r in records if r['width']>=500 and r['height']>=300]
            if (visible and len([r for r in main if r['visible']])==1) or (not visible and main and not any(r['visible'] for r in main)):break
            if time.monotonic()>=until:owner.park('postboot-original-gui-visibility-unknown')
            time.sleep(.05)
        owner.event('postboot-startup-gui-'+command+'-observed',{'actor':gui.expected,'windows':records,'publicChild':child.ordinal,
            'trayIconExistenceProven':False})


def traffic(owner,lease,lifecycle,branches,actor,label,source_roles):
    workspace=owner.request['workspace'];config=str(PureWindowsPath(workspace)/'runtime-config.json')
    port=lifecycle.product_traffic_port(config,source_roles.UPSTREAM_PORT)
    query={'powerShellPath':lease.paths['powerShell'],'listenerScriptPath':lease.paths['listenerScript']}
    bound=branches.listeners(owner,query,actor)
    need({'address':'127.0.0.1','port':port,'pid':actor['pid']} in bound,'postboot-product-listener-original-runtime')
    child=owner.child('postboot-traffic-'+label,[owner.request['pythonRuntime']['interpreterPath'],'-I','-B',lease.paths['trafficWorker'],
        '--input',lease.config['trafficInputPath'],'--mixed-port',str(port)])
    output=child.completed();need(output.returncode==0 and output.stderr=='','postboot-traffic-original-terminal')
    rows=branches.probe_stream(output.stdout,port)
    closing=branches.listeners(owner,query,actor)
    need({'address':'127.0.0.1','port':port,'pid':actor['pid']} in closing,'postboot-traffic-closing-listener-runtime-generation')
    owner.event('postboot-'+label+'-traffic-observed',{'child':child.ordinal,'runtimeActor':actor,'mixedPort':port,
        'sampleCount':len(rows)-1,'continuousUnsampledLossProven':False})
    return rows


def durable_off(owner,workspace,identity,prefix):
    effect(owner,prefix+'-off')
    off,_=public(owner,workspace,identity,'off');closing,_=public(owner,workspace,identity,'status')
    observed(owner)
    need(closing['data']['runtimeRunning'] is False and all(closing['data'][k] is None for k in
        ('runtimeId','runtimeStartedAt','activeLocationId','activeMode')) and closing['restartRequired'] is False,
        'postboot-explicit-off-state')
    # Product data remains mutable. Read via native shared read/write/delete
    # observer; never install an immutable source pin on workspace.json.
    handle=owner.native.k.CreateFileW(str(PureWindowsPath(workspace)/'workspace.json'),0x80020000,7,None,3,0x02200000,None)
    if not hasattr(owner,'postboot_workspace_handles'):owner.postboot_workspace_handles=[]
    owner.postboot_workspace_handles.append(handle)
    need(handle not in (None,-1,(1<<64)-1),'postboot-durable-workspace-native-open')
    identity_open=owner.native.identity(handle);raw=bytearray()
    for block in owner.native.read_blocks(handle):
        raw.extend(block);need(len(raw)<=64*1024*1024,'postboot-durable-workspace-bound')
    need(owner.native.identity(handle)==identity_open and json.loads(raw)['resume_connection_on_launch'] is False,
         'postboot-durable-explicit-off-intent')
    owner.event(prefix,{'off':off,'closing':closing,'workspaceSizeBytes':len(raw),'workspaceSha256':sha(raw)})
    need(bool(owner.native.k.CloseHandle(handle)),'known-durable-workspace-observer-close')
    owner.postboot_workspace_handles.remove(handle)
    return off,closing,bytes(raw)


def quit_and_wait(owner,workspace,identity,leases,label):
    current,_=public(owner,workspace,identity,'status');need(current['data']['runtimeRunning'] is False,'disconnected-before-known-public-quit')
    owner.event(label+'-quit-intent',{'controllerId':identity,'replayAllowed':False})
    effect(owner,label+'-quit')
    result,_=public(owner,workspace,identity,'quit')
    for actor in leases:actor.await_exit(label+'-'+actor.role+'-exit-observed')
    observed(owner)
    owner.event(label+'-known-retirement',{'quit':result,'allOriginalNativeActorsSignaled':True,'childEofClaimed':False})


def discover(owner,workspace,serve=None):
    until=time.monotonic()+30
    while True:
        if serve is not None:need(serve.process.poll() is None,'new-original-serve-ended-before-discovery')
        body,child=public(owner,workspace,None,'status',codes=('OK','UNAVAILABLE'),exits=(0,2))
        if body['code']=='OK':return body,child
        if time.monotonic()>=until:owner.park('postboot-public-discovery-unknown-no-replay')
        time.sleep(.1)


def run_postboot(owner,config,source_roles):
    try:return _run_postboot(owner,config,source_roles)
    except BaseException as error:
        # Startup actors have separate custody from Owner.children. A refusal before any
        # effect, or after each one's outcome was observed, is a known failure: this
        # operation is still never run again. Only an effect still pending parks; a known
        # refusal stops the owned upstream it started, so the owner can finish.
        if getattr(owner,'reboot_effect',None) is not None:
            owner.postboot_whole_action['stage']='unknown-no-replay'
            owner.park('original-whole-postboot-effect-unknown-no-replay',error)
        try:end_upstream(owner,getattr(owner,'postboot_upstream',None))
        except BaseException as closing:
            owner.postboot_whole_action['stage']='unknown-no-replay'
            owner.park('original-whole-postboot-refusal-cleanup-unknown-no-replay',closing)
        raise


def _run_postboot(owner,config,source_roles):
    need(not hasattr(owner,'postboot_whole_action'),'one-original-whole-postboot-action')
    owner.postboot_whole_action={'stage':'binding','result':None};owner.reboot_effect=None
    lease=source_roles.SourceLease(owner,config);lease.persistent_workspace();need(config['phase']=='postboot-final','fixed-postboot-final-phase')
    auto,life,branches,observer=[lease.module(key) for key in ('autostart','lifecycle','runtime','observer')]
    checkpoint_record=held_json(lease,config['checkpointPath'])
    need(checkpoint_record.get('schemaVersion')==1 and checkpoint_record.get('kind')=='reboot-checkpoint','original-preboot-checkpoint-event-input')
    checkpoint=checkpoint_record['value'];ctx=owner.request['context'];workspace=owner.request['workspace']
    scenario=config['scenario'];running=scenario=='reconnect'
    need(checkpoint_record['operationId']==checkpoint['operationId'] and checkpoint['scenario']==scenario
         and checkpoint['workspace']==workspace and checkpoint['machineGuid'].casefold()==ctx['machineGuid'].casefold()
         and checkpoint['ordinarySid']==ctx['ordinarySid'] and int(ctx['bootFileTimeUtc'])>int(checkpoint['oldBootFileTimeUtc']),
         'same-original-reboot-checkpoint-new-native-owner')
    held,actors,native,windows=startup_before_query(owner,lease,observer,life,running)
    version_probe(owner,workspace)
    snapshot=auto.collect(owner,config['autostartInputs'])
    need(int(snapshot['task']['lastRunFileTimeUtc'])>=int(ctx['bootFileTimeUtc']),'actual-autostart-task-ran-this-boot')
    endpoints=[Endpoint(owner,workspace,'activation.port',held['controller'],branches,lease),
        Endpoint(owner,workspace,'frontend.port',held['gui'],branches,lease)]
    first,status_child=discover(owner,workspace)
    need(first['controllerId']==endpoints[0].public['controllerId'],'measured-public-controller-native-listener-join')
    identity=first['controllerId'];state={'workspace':workspace,'identity':identity}
    location=auto.location_name(owner,state,first)
    gui={**held['gui'].expected,'elevated':0}
    join=auto.qualify_new_boot(checkpoint,snapshot,owner.request,first,gui,location)
    owner.event('whole-postboot-startup-observed',{'join':join,'snapshot':snapshot,'statusChild':status_child.ordinal,
        'status':first,'nativeActors':actors,'autostartTaskHistoryAndTrayMembershipComplete':False})
    verify_gui(owner,workspace,identity,held['gui'],windows)
    if running:
        upstream=owner.postboot_upstream=start_upstream(owner,lease,source_roles,'postboot')
        held['runtime'].live();traffic(owner,lease,life,branches,held['runtime'].expected,'startup',source_roles)
        durable_off(owner,workspace,identity,'postboot-startup-explicit-off-observed')
        held['runtime'].await_exit('postboot-startup-runtime-exit-observed')
        stop_upstream(owner,upstream)
    else:
        for _ in range(2):
            current,_=public(owner,workspace,identity,'status');need(current['data']['runtimeRunning'] is False,'postboot-off-query-never-reconnects')
    auto.closing_off(owner,state,config['autostartInputs'])
    quit_and_wait(owner,workspace,identity,[held[role] for role in ('gui','guiLauncher','controller','controllerLauncher') if role in held],
                  'postboot-startup')
    for endpoint in endpoints:endpoint.close_after_known_actor_exit()
    lease.guard()
    need(all(child.terminal is not None for child in owner.children),'whole-postboot-all-original-children-terminal')
    owner.postboot_whole_action.update(stage='ready-for-owner-finish',result={'startupJoin':join,
        'startupRetiredWithNativeHandleExit':True,'autostartClosedOff':True,'nativeAcceptanceComplete':False})
    owner.event('whole-postboot-action-ready-for-finish',owner.postboot_whole_action['result'])
    return 0


def query_then_gui(owner,lease,source_roles,auto,life,branches,observer,state):
    """A config query with no owner starts a transient one that never connects; a GUI then restores intent once.

    Rebootless: the remembered on-intent comes from this owner's own serve, retired by a graceful quit.
    status never starts an owner (DesktopCli noStartupOperations), so a config query starts it.
    """
    workspace,identity,serve=state['workspace'],state['identity'],state['serve'];ws=str(workspace)
    gui_path=lease.paths['gui']
    public(owner,workspace,identity,'on');on,_=public(owner,workspace,identity,'status')
    need(on['data']['runtimeRunning'] is True and on['data']['activeMode']=='proxy-only','query-first-intent-connected')
    effect(owner,'query-first-serve-quit')
    public(owner,workspace,identity,'quit');terminal=serve.wait()
    observed(owner)
    need(terminal['exitCode']==0 and not (Path(ws)/'activation.port').exists(),'query-first-graceful-quit-keeps-intent')
    public(owner,workspace,None,'status',codes=('UNAVAILABLE',),exits=(2,))
    effect(owner,'query-first-transient-owner')
    listed,_=public(owner,workspace,None,'locations','list')
    observed(owner)
    transient=listed['controllerId'];need(transient!=identity,'query-started-a-new-transient-owner')
    first,_=public(owner,workspace,transient,'status');need(first['data']['runtimeRunning'] is False,'query-started-owner-never-connects')
    second,_=public(owner,workspace,transient,'status');need(second['data']['runtimeRunning'] is False,'repeated-query-never-connects')
    gui=owner.child('query-first-gui',[gui_path,'--state-dir',ws])
    state['live']=(gui,transient)  # A known refusal from here quits the transient controller, which ends this GUI.
    until=time.monotonic()+60
    while True:
        need(gui.process.poll() is None,'query-first-gui-ended')
        current,_=public(owner,workspace,transient,'status')
        if current['data']['runtimeRunning'] is True:break
        if time.monotonic()>=until:owner.park('query-first-gui-intent-unresolved-no-replay')
        time.sleep(.5)
    need(current['data']['activeMode']=='proxy-only' and current['controllerId']==transient,'gui-restores-intent-on-the-query-owner')
    _,rows,_=census(owner,lease,'query-first-census')
    same=lambda row,image:row['image'].casefold()==image.casefold()
    controllers=[row for row in rows if same(row,gui_path) and row['argv']==[gui_path,'--headless-controller','--state-dir',ws]]
    # A launcher and its same-image JVM child may share the argv: the launcher is the one whose parent is neither.
    controllers=[row for row in controllers if not any(other['pid']==row['parentPid'] for other in controllers)]
    need(len(controllers)==1,'one-query-started-controller')
    jvm=own_jvm(rows,controllers[0],gui_path,'one-query-controller-jvm')
    runtime_image=str(PureWindowsPath(ws)/'runtime'/'tools'/'sing-box.exe')
    runtimes=born_children(rows,jvm,runtime_image);need(len(runtimes)==1,'one-reconnected-runtime')
    ctx=owner.request['context'];row=runtimes[0];native=observer.WindowsNative()
    actor={'pid':row['pid'],'creationFileTime':row['creationFileTime'],'image':runtime_image,'sha256':lease.runtime_sha256(),
           'sid':ctx['ordinarySid'],'sessionId':ctx['ordinarySessionId']}
    runtime=Actor(owner,native,actor,'runtime')
    # Every other product generation of this census is held from here, the controller included: the product ends its
    # controller only after the GUI acknowledged the quit, so the GUI child's end alone never closes the operation.
    held=[Actor(owner,native,{'pid':row['pid'],'creationFileTime':row['creationFileTime'],'image':gui_path,
                              'sha256':lease.pins['gui'].record['sha256'],'sid':ctx['ordinarySid'],'sessionId':ctx['ordinarySessionId']},
                'controller' if row is jvm else 'controllerLauncher' if row is controllers[0] else 'gui')
          for row in rows if same(row,gui_path) and row['pid']!=gui.pid]
    traffic(owner,lease,life,branches,actor,'query-first',source_roles)
    durable_off(owner,workspace,transient,'query-first-explicit-off-observed')
    runtime.await_exit('query-first-runtime-exit-observed')
    effect(owner,'query-first-quit')
    public(owner,workspace,transient,'quit');closing=gui.wait()
    observed(owner)
    need(closing['exitCode']==0,'query-first-gui-known-exit')
    # The quit's reply and the GUI child's end are observed, so a held generation still running at the bound is a
    # known failure that names it, never a park; the closing census runs only once every one has ended.
    until=time.monotonic()+60
    for generation in held:
        generation.await_exit('query-first-'+generation.role+'-exit-observed',until=until,refusal='query-first-product-exit-timeout')
    _,after,_=census(owner,lease,'query-first-closing-census')
    need(not any(same(row,gui_path) or same(row,runtime_image) for row in after),'query-first-product-fully-retired')
    result={'queryControllerId':transient,'originalControllerId':identity,'queryConnected':False,'guiRestoredIntentOnce':True,
            'nativeAcceptanceComplete':False}
    owner.event('query-owner-gui-reconnect-observed',result)
    return result
