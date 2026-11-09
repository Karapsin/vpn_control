"""Finite preboot action: owned proxy setup, autostart migration, the product's own start, checkpoint.

Uses existing source-held ordinary Owner/native APIs. Nothing here reboots and
nothing is left as this owner's child: its own serve quits gracefully, the app is
started through the product's own autostart task, and the owner finishes. The
running app's exact generations are declared in the checkpoint for the reviewed
idle allowance; readiness-reboot stays the only reboot submitter.
"""
import json
from pathlib import Path
import time


def need(ok,code):
    if not ok:raise ValueError(code)


def start_through_autostart_task(owner,lease,auto,inputs):
    """Run the product's own registered autostart task once, as its logon trigger would."""
    before=auto.collect(owner,inputs)
    need(before['qualifiedOwnership']=='limited' and before['run']['state']=='absent'
         and not before['task']['runningInstances'],'limited-idle-autostart-task-before-start')
    owner.event('product-autostart-start-intent',{'task':before['task'],'replayAllowed':False})
    child=owner.child('product-autostart-start',[inputs['powerShellPath'],'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
        '-File',inputs['startScriptPath'],'-GuiPath',inputs['guiPath'],'-Workspace',inputs['workspace'],
        '-ExpectedSid',owner.request['context']['ordinarySid']])
    output=child.completed()
    need(output.returncode==0 and output.stderr=='' and len(output.stdout.encode())<=4096,'autostart-start-original-terminal')
    started=json.loads(output.stdout)
    need(type(started)is dict and set(started)=={'schemaVersion','taskPath','instanceGuid'} and started['schemaVersion']==1
         and started['taskPath']==auto.TASK and type(started['instanceGuid'])is str,'autostart-start-helper-result')
    owner.event('product-autostart-started',{'child':child.ordinal,'result':started})
    return started


def await_product(owner,lease,postboot,running):
    """No query runs until the GUI's own controller listens: a query first would start a transient owner itself."""
    workspace=Path(owner.request['workspace']);until=time.monotonic()+120
    while True:
        if (workspace/'activation.port').exists():
            _,rows,_=postboot.census(owner,lease,'preboot-product-census')
            try:return postboot.product_tree(owner,lease,rows,running)
            except ValueError:pass
        if time.monotonic()>=until:owner.park('preboot-product-start-unresolved-no-replay')
        time.sleep(1)


def retire(owner,postboot):
    """After a known refusal: stop the owned upstream, then end this action's own serve or query GUI
    through the same journaled public quit to its controller, so no child of the owner stays live."""
    postboot.end_upstream(owner,getattr(owner,'preboot_upstream',None))
    state=getattr(owner,'preboot_state',None)
    child,identity=(None,None) if state is None else state['live']
    if child is None or child.terminal is not None:return
    if child.process.poll() is not None:
        child.wait();return
    need(identity is not None,'preboot-refusal-live-child-controller')
    owner.event('preboot-refusal-quit-intent',{'child':child.ordinal,'controllerId':identity,'replayAllowed':False})
    postboot.effect(owner,'preboot-refusal-quit')
    postboot.public(owner,state['workspace'],identity,'quit');child.wait()
    postboot.observed(owner)


def run_preboot(owner,config,source_roles,postboot):
    need(not hasattr(owner,'preboot_whole_action'),'one-original-preboot-action')
    owner.preboot_whole_action={'stage':'binding'};owner.reboot_effect=None
    try:return _run_preboot(owner,config,source_roles,postboot)
    except BaseException as error:
        # Only an effect still pending parks. A known refusal retires what this action still
        # runs, so the owner finishes with a known failure and the operation never runs again.
        if getattr(owner,'reboot_effect',None) is not None:
            owner.preboot_whole_action['stage']='unknown-no-replay'
            owner.park('original-preboot-effect-unknown-no-replay',error)
        try:retire(owner,postboot)
        except BaseException as closing:
            owner.preboot_whole_action['stage']='unknown-no-replay'
            owner.park('original-preboot-refusal-cleanup-unknown-no-replay',closing)
        raise


def _run_preboot(owner,config,source_roles,postboot):
    lease=source_roles.SourceLease(owner,config);need(config['phase']=='preboot-reboot','fixed-preboot-reboot-phase')
    auto,rt=lease.module('autostart'),lease.module('runtimeStages')
    life,branches,observer=lease.module('lifecycle'),lease.module('runtime'),lease.module('observer')
    workspace=Path(owner.request['workspace']);scenario=config['scenario'];inputs=config['autostartInputs']
    need(workspace.parent==owner.root and not workspace.exists(),'fresh-isolated-preboot-workspace')
    postboot.version_probe(owner,workspace)
    need(not workspace.exists(),'static-launch-created-owner-state')
    upstream=owner.preboot_upstream=postboot.start_upstream(owner,lease,source_roles,'preboot')
    serve=owner.child('serve',[owner.request['cliPath'],'--state-dir',str(workspace),'serve'])
    # 'live' is the child a known refusal retires by its controller's quit: this serve, later the query GUI.
    state=owner.preboot_state={'workspace':workspace,'identity':None,'serve':serve,'live':(serve,None)}
    opening,_=postboot.discover(owner,workspace,serve);identity=opening['controllerId']
    state.update(identity=identity,live=(serve,identity))
    need(opening['data']['runtimeRunning'] is False,'initial-preboot-disconnected-serve')
    def mutate(*args):
        current,_=postboot.public(owner,workspace,identity,'status')
        return postboot.public(owner,workspace,identity,'--if-revision',str(current['configurationRevision']),*args)[0]
    listed,_=postboot.public(owner,workspace,identity,'locations','list')
    need(listed['data']['locations']==[],'empty-owned-preboot-workspace')
    # A no-credential profile for the in-guest upstream on its fixed loopback port. ProxyLinkParser
    # takes socks://; the owner answers any other scheme, socks5:// too, INVALID_ARGUMENT.
    profile=rt.publish(owner,owner.root/'postboot-owned-proxy.txt',
        f'socks://127.0.0.1:{source_roles.UPSTREAM_PORT}#Owned%20Reboot\n'.encode())
    # A fresh workspace reports subscription: the source is set before the first location is added.
    mutate('source','set','current-locations');mutate('locations','add','--input',str(profile));mutate('locations','select','Owned Reboot')
    mutate('routing','set','ignore-rules','true');mutate('settings','set','mode','proxy-only')
    if scenario=='query-first':
        result=postboot.query_then_gui(owner,lease,source_roles,auto,life,branches,observer,state)
        postboot.stop_upstream(owner,upstream)
        owner.preboot_whole_action.update(stage='ready-for-owner-finish',result=result)
        return 0
    migration=auto.migration(owner,state,inputs)
    need(migration['after']['qualifiedOwnership']=='limited','ordinary-actual-autostart-migration-required')
    running=scenario=='reconnect'
    if running:
        postboot.public(owner,workspace,identity,'on')
        status,_=postboot.public(owner,workspace,identity,'status')
        need(status['data']['runtimeRunning'] is True and status['data']['activeMode']=='proxy-only','actual-preboot-proxy-runtime')
    elif scenario=='explicit-off':
        postboot.public(owner,workspace,identity,'on')
        postboot.durable_off(owner,workspace,identity,'preboot-explicit-off-observed')
    # Graceful quit keeps the remembered on/off intent; this owner then has no live child.
    current,_=postboot.public(owner,workspace,identity,'status')
    need(current['data']['runtimeRunning'] is running,'preboot-remembered-intent-before-quit')
    owner.event('preboot-serve-quit-intent',{'controllerId':identity,'replayAllowed':False})
    postboot.effect(owner,'preboot-serve-quit')
    postboot.public(owner,workspace,identity,'quit');terminal=serve.wait()
    postboot.observed(owner)
    need(terminal['exitCode']==0 and not (workspace/'activation.port').exists(),'preboot-own-serve-known-exit')
    owner.preboot_whole_action['stage']='product-start'
    postboot.effect(owner,'product-autostart-start')
    start_through_autostart_task(owner,lease,auto,inputs)
    actors=await_product(owner,lease,postboot,running)
    postboot.observed(owner)
    held=postboot.retained(owner,observer.WindowsNative(),actors)
    status,_=postboot.discover(owner,workspace)
    need(status['data']['runtimeRunning'] is running,'autostarted-product-restores-intent-once')
    product={'workspace':workspace,'identity':status['controllerId']}
    location=auto.location_name(owner,product,status) if running else None
    if running:
        postboot.traffic(owner,lease,life,branches,held['runtime'].expected,'preboot',source_roles)
    postboot.stop_upstream(owner,upstream)
    for actor in held.values():actor.live()
    checkpoint=auto.prepare_reboot_checkpoint(owner,inputs,scenario,status,actors,location)
    owner.preboot_whole_action.update(stage='ready-for-owner-finish',result={'checkpoint':checkpoint['operationId'],
        'declaredProduct':len(checkpoint['declaredProduct']),'appRunningAtFinish':True,'rebootIssued':False})
    owner.event('preboot-action-ready-for-finish',owner.preboot_whole_action['result'])
    return 0
