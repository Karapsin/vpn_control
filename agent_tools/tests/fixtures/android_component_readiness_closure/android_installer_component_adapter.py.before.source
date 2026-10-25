"""Exact installer/TLS public hooks for the closed external Java transport.

Call install() before the unchanged lifecycle main/action. This is an internal
recipe adapter, not an MCP command accepting caller code. The sole guest operator
must provide a current-generation guard covering intent/device/package/epoch;
historical coldboot getters alone are insufficient after root/unroot/install.
"""
from __future__ import annotations
import ast
import hashlib
import inspect
import json
import re
from pathlib import Path
import types
from . import android_component_command_transport as transport

LIFECYCLE_SHA='5a3e3e69d6b300d5f61bf2420907a59ad58ae8209a36bf0ace671e0930085d2b'
TLS_SHA='da95ff0d27aa6178c20455e9440e5adabb376b7628df5fd7ff93a2cb27864a5f'
_PRODUCTION_IMPORTS='import hashlib,json,os,pathlib,re,stat,errno,ctypes,fcntl,signal,subprocess,time,select,shutil\nfrom pathlib import Path\n'

def production_imports(device):
    """Exact two frozen factory contexts; no caller-specified import text."""
    if type(device)is not str or device not in ('api29','api35'):
        raise ValueError('installer_adapter_context_device_required')
    return _PRODUCTION_IMPORTS+('import base64\n' if device=='api35' else '')

def _semantic_code(code):
    # Generated AST source changes filename/line tables, not instruction or
    # constant authority. Nested comprehension bytecode is compared recursively.
    return (code.co_code,code.co_names,code.co_varnames,code.co_freevars,code.co_cellvars,
            code.co_argcount,code.co_posonlyargcount,code.co_kwonlyargcount,
            tuple(_semantic_code(v) if isinstance(v,types.CodeType) else v for v in code.co_consts))

def _module(module, expected, names):
    path=Path(module.__file__).absolute()
    snapshot=transport.readonly.availability._snapshot(path)
    if hashlib.sha256(snapshot[1]).hexdigest()!=expected:
        raise ValueError('installer_adapter_source_changed')
    code=compile(snapshot[1],str(path),'exec',dont_inherit=True)
    tree=ast.parse(snapshot[1])
    for name in names:
        original=next((v for v in code.co_consts if isinstance(v,types.CodeType) and v.co_name==name),None)
        function=getattr(module,name,None)
        if (original is None or not isinstance(function,types.FunctionType) or
            function.__globals__ is not module.__dict__ or function.__code__!=original):
            raise ValueError('installer_adapter_hook_changed')
        nodes=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==name]
        if len(nodes)!=1:raise ValueError('installer_adapter_hook_changed')
        node=nodes[0]
        positional=tuple(ast.literal_eval(value) for value in node.args.defaults) or None
        keywords={arg.arg:ast.literal_eval(value) for arg,value in zip(node.args.kwonlyargs,node.args.kw_defaults) if value is not None} or None
        actual=function.__defaults__;actual_keywords=function.__kwdefaults__
        if ((positional is None and actual is not None) or
            (positional is not None and (type(actual)is not tuple or len(actual)!=len(positional) or
             any(type(value)is not type(expected) or value!=expected for value,expected in zip(actual,positional)))) or
            (keywords is None and actual_keywords is not None) or
            (keywords is not None and (type(actual_keywords)is not dict or set(actual_keywords)!=set(keywords) or
             any(type(actual_keywords[key])is not type(value) or actual_keywords[key]!=value for key,value in keywords.items())))):
            raise ValueError('installer_adapter_hook_changed')
    return path,snapshot

def _phase_protocol(guard,pins):
    """Finite source-authenticated CurrentGuard protocol, never caller callbacks."""
    if not hasattr(guard,'_command_binding'):return None
    call=getattr(type(guard),'__call__',None)
    if not isinstance(call,types.FunctionType) or type(guard).__name__!='CurrentGuard':
        raise ValueError('installer_adapter_phase_guard_required')
    namespace=call.__globals__
    own=Path(__file__).absolute().parent/'android_installer_component_bundle.py'
    expected=transport.readonly.availability._snapshot(own)
    source=Path(namespace['__file__']).absolute()
    actual=transport.readonly.availability._snapshot(source)
    if actual[1]!=expected[1] or namespace.get('CurrentGuard')is not type(guard):
        raise ValueError('installer_adapter_phase_source_changed')
    compiled=compile(actual[1],str(source),'exec',dont_inherit=True)
    tree=ast.parse(actual[1])
    def defaults(function,node):
        args=tuple(ast.literal_eval(value) for value in node.args.defaults) or None
        keywords={name.arg:ast.literal_eval(value) for name,value in zip(node.args.kwonlyargs,node.args.kw_defaults) if value is not None} or None
        if function.__defaults__!=args or function.__kwdefaults__!=keywords:
            raise ValueError('installer_adapter_phase_defaults_changed')
    catalogue=[node.value for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='FILES' for target in node.targets)]
    if len(catalogue)!=1 or namespace.get('FILES')!=ast.literal_eval(catalogue[0]):
        raise ValueError('installer_adapter_phase_catalogue_changed')
    for code in compiled.co_consts:
        if not isinstance(code,types.CodeType) or code.co_name=='CurrentGuard' or code.co_name=='BaselineGuard':continue
        function=namespace.get(code.co_name)
        if (not isinstance(function,types.FunctionType) or function.__globals__ is not namespace or
            _semantic_code(function.__code__)!=_semantic_code(code)):
            raise ValueError('installer_adapter_phase_globals_changed')
        node=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name==code.co_name)
        defaults(function,node)
    klass=next((code for code in compiled.co_consts if isinstance(code,types.CodeType) and code.co_name=='CurrentGuard'),None)
    if klass is None:raise ValueError('installer_adapter_phase_guard_required')
    class_node=next(node for node in tree.body if isinstance(node,ast.ClassDef) and node.name=='CurrentGuard')
    for code in klass.co_consts:
        if not isinstance(code,types.CodeType):continue
        if code.co_name in vars(guard):raise ValueError('installer_adapter_phase_method_shadowed')
        method=type(guard).__dict__.get(code.co_name)
        if not isinstance(method,types.FunctionType) or method.__globals__ is not namespace or _semantic_code(method.__code__)!=_semantic_code(code):
            raise ValueError('installer_adapter_phase_method_changed')
        node=next(node for node in class_node.body if isinstance(node,ast.FunctionDef) and node.name==code.co_name)
        defaults(method,node)
    runner=namespace.get('installer_tls_run')
    original=next((code for code in compiled.co_consts if isinstance(code,types.CodeType) and code.co_name=='installer_tls_run'),None)
    if not isinstance(runner,types.FunctionType) or runner.__globals__ is not namespace or _semantic_code(runner.__code__)!=_semantic_code(original):
        raise ValueError('installer_adapter_phase_runner_changed')
    for path,snapshot in ((own,expected),(source,actual)):
        if path in pins and pins[path]!=snapshot:raise ValueError('installer_adapter_phase_source_changed')
        pins[path]=snapshot
    return runner


def _phase(words, interactive, asynchronous):
    if words==['updates','install']:
        if (interactive,asynchronous)==(False,False):return 'install-noninteractive'
        if (interactive,asynchronous)==(True,True):return 'install-interactive'
        raise ValueError('installer_adapter_flags_invalid')
    if interactive or asynchronous:raise ValueError('installer_adapter_flags_invalid')
    if words in (['updates','check'],['updates','download']):return words[1]
    if words==['updates','status']:return 'reconcile'
    if len(words)==3 and words[:2] in (['operations','status'],['operations','wait'],['operations','cancel']):return 'operation-'+words[1]
    return 'baseline'

def install(lifecycle, tls, backend:dict, args, current_guard):
    """Install exact owned hooks after a durable create-only transport fence.

    Returns restore(), for a single operator's finally block. The caller retains
    all lifecycle fences, UI callbacks, terminal validation and cleanup authority.
    """
    if not callable(current_guard):raise ValueError('installer_adapter_current_guard_required')
    pins=dict([_module(lifecycle,LIFECYCLE_SHA,('invoke','main','action','handoff_identity','reconciled_terminal','verify_governed_callback','write_cli_evidence','reply_binding')),
               _module(tls,TLS_SHA,('verify_public_baseline','public_no_update_probe','public_cli_argv','public_cli_environment','run_fixture_lifecycle','guard_proxy_evidence','fixture_proxy_snapshot','fixture_proxy_presence','proxy_source_authority'))])
    own=Path(__file__).absolute();pins[own]=transport.readonly.availability._snapshot(own)
    source=Path(transport.__file__).absolute();pins[source]=transport.readonly.availability._snapshot(source)
    if backend.get('COMMAND_SOURCE_SHA')!=hashlib.sha256(pins[source][1]).hexdigest():raise ValueError('installer_adapter_backend_changed')
    phase_runner=_phase_protocol(current_guard,pins)
    semantic_pins={(module,name):(getattr(module,name),getattr(module,name).__code__) for module,names in
        ((lifecycle,('action','handoff_identity','reconciled_terminal','verify_governed_callback')),
         (tls,('public_cli_environment','guard_proxy_evidence','fixture_proxy_snapshot','fixture_proxy_presence','proxy_source_authority'))) for name in names}
    intent=lifecycle.target_admission.load_intent(args.intent_file)
    device=backend.get('LAUNCH',{}).get('device')
    context=production_imports(device)
    api,serial={'api29':(29,'emulator-5684'),'api35':(35,'emulator-5682')}[device]
    if (backend.get('EXTERNAL',{}).get('serial')!=serial or args.serial!=serial or
        type(intent.get('expectedApi'))is not int or intent['expectedApi']!=api or args.api!=str(api)):
        raise ValueError('installer_adapter_crossed_context')
    expected_tree=ast.parse(transport.REMOTE+'\n'+transport._bounded_source())
    for name in ('component_command','command_binary','command_request','command_host_identity','command_host_guard','command_bounded'):
        function=backend.get(name)
        nodes=[node for node in expected_tree.body if isinstance(node,ast.FunctionDef) and node.name==name]
        if len(nodes)!=1:raise ValueError('installer_adapter_backend_changed')
        # Match command.prepare/namespace_source's exact normalized production
        # AST and imported-module compiler context. Python3.14 specializes global
        # module attribute calls; isolated raw templates compile differently.
        expected_code=compile(context+ast.unparse(ast.Module(body=nodes,type_ignores=[])),
                              '<installer-fixed-production-function>','exec',dont_inherit=True)
        expected=next(v for v in expected_code.co_consts if isinstance(v,types.CodeType) and v.co_name==name)
        if not isinstance(function,types.FunctionType) or function.__globals__ is not backend or _semantic_code(function.__code__)!=_semantic_code(expected):
            raise ValueError('installer_adapter_backend_changed')
    function=backend['component_command']
    # Retain a separate view before validate_intent() returns; its exact normal
    # guards are still executed by unchanged main(), including backup/pair checks.
    evidence_args=types.SimpleNamespace(intent=intent,output=args.output)
    owner=intent['expectedOwner'];revision=intent['expectedRevision']
    canonical=json.dumps(intent,sort_keys=True,separators=(',',':')).encode()
    cli=str(args.cli);serial=args.serial;environment=getattr(args,'cli_environment',None)
    if serial!=backend['EXTERNAL']['serial'] or cli!=backend['GETTER']['cli']:
        raise ValueError('installer_adapter_crossed_stage_device')
    sequence=0
    admission_pin=None
    effect_pins={}
    uncertain=False
    def guard():
        if phase_runner is not None and _phase_protocol(current_guard,pins)is not phase_runner:
            raise ValueError('installer_adapter_phase_runner_changed')
        backend['command_host_guard']()
        for (module,name),(function,code) in semantic_pins.items():
            if getattr(module,name)is not function or function.__code__ is not code:
                raise ValueError('installer_adapter_semantic_guard_changed')
            _module(module,TLS_SHA if module is tls else LIFECYCLE_SHA,(name,))
        for path,pin in pins.items():
            if transport.readonly.availability._snapshot(path)!=pin:raise ValueError('installer_adapter_source_changed')
        current=lifecycle.target_admission.load_intent(args.intent_file)
        if json.dumps(current,sort_keys=True,separators=(',',':')).encode()!=canonical:
            raise ValueError('installer_adapter_intent_changed')
        if admission_pin is not None and transport.readonly.availability._snapshot(args.output/'component-transport-admission.json')!=admission_pin:
            raise ValueError('installer_adapter_fence_changed')
        for name,pin in effect_pins.items():
            if transport.readonly.availability._snapshot(args.output/name)!=pin:
                raise ValueError('installer_adapter_effect_fence_changed')
        current_guard()
    def capture(record):
        nonlocal sequence
        sequence+=1
        name='component-cli-%05d.json'%sequence
        lifecycle.write_cli_evidence(evidence_args,name,
            {'schema':1,'kind':'android-installer-component-command','binding':lifecycle.reply_binding(evidence_args),
             'sourceSha256':backend['COMMAND_SOURCE_SHA'],'record':record,
             'installedLauncherAccepted':False,'bundledRuntimeAccepted':False})
        if phase_runner is not None:
            retained=transport.readonly.availability._snapshot(args.output/name)
            current_guard._command_capture(record,{'path':str(args.output/name),
                'snapshot':retained[0],'sha256':hashlib.sha256(retained[1]).hexdigest()})
    def invoke(selected_cli, selected_serial, *words, interactive=False, asynchronous=False,
               environment=None, timeout_seconds=None):
        nonlocal uncertain
        if str(selected_cli)!=cli or selected_serial!=serial or type(interactive)is not bool or type(asynchronous)is not bool:
            raise ValueError('installer_adapter_crossed_call')
        # This env is only compared, never used to choose JVM/ADB/environment.
        if environment is not None and environment!=getattr(args,'cli_environment',None):
            raise ValueError('installer_adapter_environment_changed')
        words=list(words)
        if words[:2]==['--timeout-seconds','0'] and len(words)==5 and words[2:4]==['operations','wait']:
            words=words[2:]
        phase=_phase(words,interactive,asynchronous)
        command_intent=intent
        if phase_runner is not None:
            preliminary=backend['command_request'](words,intent['expectedOwner'],intent['expectedRevision'],phase)[3]
            current_guard._command_begin(words,phase,preliminary)
            command_intent=current_guard._command_binding()
        owner=command_intent['expectedOwner'];revision=command_intent['expectedRevision']
        evidence_args.intent=command_intent
        mutation=backend['command_request'](words,owner,revision,phase)[3]
        if mutation:
            if uncertain:raise ValueError('installer_adapter_uncertain_effect_consumed')
            guard()
            # A checked create-only admission is durable BEFORE any JVM/status
            # child. Repeated effects never depend on a caller's phase marker.
            suffix='-'+words[2] if phase=='operation-cancel' else ''
            effect_name='component-effect-'+phase+suffix+'.json'
            lifecycle.write_cli_evidence(evidence_args,effect_name,
                {'schema':1,'kind':'android-installer-component-effect-admission',
                 'binding':lifecycle.reply_binding(evidence_args),'phase':phase,
                 'words':words,'owner':owner,'revision':revision,
                 'outcome':'may-have-started','replayAllowed':False})
            effect_pins[effect_name]=transport.readonly.availability._snapshot(args.output/effect_name)
            guard()
            uncertain=True
        request={'argv':['EXTERNAL_JDK_COMPONENT',*words],'exit':None,'stdout':'','stderr':''}
        start=len(backend.get('GETTER_RECORDS',{}).get('captures',[]))
        positive=False
        try:
            record=function(words,owner,revision,phase,guard,capture,deadline=timeout_seconds)
            if mutation:
                value=record.get('stdout')
                identity=isinstance(value,dict) and value.get('controllerId')==owner and type(value.get('configurationRevision'))is int and value['configurationRevision']==revision
                if phase=='install-interactive':
                    positive=identity and record['returncode']==0 and value.get('ok')is True and value.get('code')=='ACCEPTED' and value.get('final')is False and isinstance(value.get('operationId'),str) and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',value['operationId'])is not None
                elif phase=='install-noninteractive':positive=identity and record['returncode']==1 and value.get('ok')is False and value.get('code')=='INTERACTION_REQUIRED' and value.get('final')is True
                elif phase=='operation-cancel':positive=identity and value.get('final')is True and value.get('operationId')==words[2] and ((record['returncode']==0 and value.get('code')=='OK' and value.get('ok')is True) or (record['returncode']==130 and value.get('code')=='CANCELLED' and value.get('ok')is False))
                else:positive=identity and record['returncode']==0 and value.get('ok')is True and value.get('code')=='OK' and value.get('final')is True
                if positive:uncertain=False
        except (ValueError,OSError,UnicodeError) as error:
            captures=backend.get('GETTER_RECORDS',{}).get('captures',[])
            if len(captures)>start:
                import base64
                last=captures[-1]
                request.update(exit=last.get('returncode'),stdout=base64.b64decode(last.get('stdoutBase64','')).decode('utf-8','replace'),stderr=base64.b64decode(last.get('stderrBase64','')).decode('utf-8','replace'))
            raise lifecycle.InvocationFailure('component invocation unknown',request) from error
        finally:
            if mutation and not positive:
                # Observations can still inspect this session; no observation
                # silently clears uncertain effect authority or admits another.
                uncertain=True
                unknown_name='component-effect-unknown.json'
                lifecycle.write_cli_evidence(evidence_args,unknown_name,
                    {'schema':1,'kind':'android-installer-component-effect-unknown',
                     'binding':lifecycle.reply_binding(evidence_args),'phase':phase,
                     'replayAllowed':False,'effectContinuationAllowed':False})
                effect_pins[unknown_name]=transport.readonly.availability._snapshot(args.output/unknown_name)
        return {'argv':request['argv'],'exit':record['returncode'],'response':record.get('stdout'),
                'stdout':record['stdoutRaw'],'stderr':record['stderrRaw'],
                'componentRuntime':'EXTERNAL_JDK','installedLauncherAccepted':False,'bundledRuntimeAccepted':False}
    def public_run(argv, **kwargs):
        allowed={'check','text','capture_output','env'}
        if set(kwargs)-allowed or kwargs.get('text')is not True or kwargs.get('capture_output')is not True:
            raise ValueError('installer_adapter_tls_call_changed')
        prefix=[*tls.public_cli_argv(Path(cli)),'--json','--android','--serial',serial]
        if argv[:len(prefix)]!=prefix:raise ValueError('installer_adapter_tls_call_changed')
        words=argv[len(prefix):]
        if words[:2]==['--timeout-seconds','180']:words=words[2:]
        if words not in (['status'],['updates','check']):raise ValueError('installer_adapter_tls_call_changed')
        record=invoke(cli,serial,*words,environment=kwargs.get('env'))
        if kwargs.get('check') and record['exit']!=0:raise ValueError('installer_adapter_tls_public_failed')
        return types.SimpleNamespace(returncode=record['exit'],stdout=record['stdout'],stderr=record['stderr'])
    original={name:getattr(tls,name) for name in ('verify_public_baseline','public_no_update_probe')}
    # Replace precisely ONE public subprocess invocation in each real TLS body.
    # Every original package/UID/AVD/hash/proxy/trust guard remains unchanged.
    replacements={}
    for name,function_source in original.items():
        tree=ast.parse(inspect.getsource(function_source));matches=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='subprocess' and node.func.attr=='run':matches.append(node)
        if len(matches)!=1:raise ValueError('installer_adapter_tls_hook_changed')
        matches[0].func=ast.Name(id='_component_public_run',ctx=ast.Load())
        scope=dict(tls.__dict__);scope['_component_public_run']=public_run
        exec(compile(ast.fix_missing_locations(tree),str(tls.__file__),'exec'),scope)
        replacements[name]=scope[name]
    guard()
    lifecycle.write_cli_evidence(evidence_args,'component-transport-admission.json',
        {'schema':1,'kind':'android-installer-component-admission',
         'binding':lifecycle.reply_binding(evidence_args),
         'commandTransportSha256':backend['COMMAND_SOURCE_SHA'],
         'adapterSha256':hashlib.sha256(pins[own][1]).hexdigest(),
         'getterIdentity':backend['EXTERNAL']['getterIdentity'],
         'hostIdentity':backend['command_host_identity'](),
         'installedLauncherAccepted':False,'bundledRuntimeAccepted':False})
    admission_pin=transport.readonly.availability._snapshot(args.output/'component-transport-admission.json')
    guard()
    old_invoke=lifecycle.invoke
    old_run=tls.run_fixture_lifecycle
    if phase_runner is not None:
        def fixed_run(tls_args,action,**kwargs):
            guard()
            return phase_runner(current_guard,tls_args,action,old_run,**kwargs)
        tls.run_fixture_lifecycle=fixed_run
    lifecycle.invoke=invoke
    for name,value in replacements.items():setattr(tls,name,value)
    def restore():
        lifecycle.invoke=old_invoke
        tls.run_fixture_lifecycle=old_run
        for name,value in original.items():setattr(tls,name,value)
    return restore
