"""Actual source-composition/TempFS guards; no native Java/ADB/SSH execution."""
import ast
import contextlib
import copy
import hashlib
import inspect
import json
import os
import tempfile
from pathlib import Path
import subprocess
import textwrap
import types
import unittest
from unittest.mock import patch
from agent_tools import android_packaged_component_read_transport as transport
from agent_tools.tests import test_temurin_product_launcher_recipe as recipe
from agent_tools.tests import test_android_installer_component_bundle as guard_tests

REQUEST={'correlationId':'11111111-1111-4111-8111-111111111111','owner':'22222222-2222-4222-8222-222222222222','revision':0,'environment':{key:'fixture' for key in ('ANDROID_AVD_HOME','ANDROID_HOME','ANDROID_SDK_ROOT','HOME','LOGNAME','PATH','USER')},'adb':{'path':'/opt/android-sdk/platform-tools/adb','generation':[1,2,3,4,5,33261,0,0,1],'sha256':'a'*64}}


def reply(words):
    data={'runtimeRunning':False,'runtimeObservation':'stopped'} if words==('status',) else {'operations':[]}
    return {'ok':True,'final':True,'code':'OK','schemaVersion':1,'controllerId':REQUEST['owner'],
            'configurationRevision':0,'operationId':None,'restartRequired':False,'data':data}


class SourceTests(unittest.TestCase):
    def test_actual_worker_preserves_every_cleanup_source_body(self):
        before=ast.parse(transport._original());after=ast.parse(transport._worker_source(REQUEST))
        old={n.name:ast.dump(n,include_attributes=False) for n in before.body if isinstance(n,ast.FunctionDef)}
        new={n.name:ast.dump(n,include_attributes=False) for n in after.body if isinstance(n,ast.FunctionDef)}
        self.assertEqual({n for n in old if old[n]!=new[n]},{'run_hello_gate','validate_role','generated_image_guard'})
        self.assertFalse(any(isinstance(n,ast.ImportFrom) and n.module and n.module.startswith('agent_tools') for n in after.body))
    def test_actual_whole_compiler_context_and_finite_role_gate(self):
        tree=ast.parse(transport._worker_source(REQUEST))
        names={'validate_role','_json','_reply','_public_result'}
        ns={'history':transport.history,'copy':copy,'json':json}
        for node in tree.body:
            if isinstance(node,ast.Assign) and any(isinstance(n,ast.Name) and n.id.startswith('PACKAGED_') for n in node.targets):
                exec(compile(ast.Module(body=[node],type_ignores=[]),'<fixed-role-literals>','exec'),ns)
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-worker-functions>','exec'),ns)
        kwargs={'check':False,'capture_output':True,'text':True,'timeout':30}
        for index in range(6):
            ns['role_index']=index
            self.assertEqual(ns['validate_role'](ns['PACKAGED_ARGV'][index],kwargs),transport.ROLES[index])
            value=subprocess.CompletedProcess(ns['PACKAGED_ARGV'][index],0,json.dumps(reply(transport.WORDS[index])),'')
            self.assertEqual(ns['_public_result'](value,transport.WORDS[index],REQUEST['owner'],0),reply(transport.WORDS[index])['data'])
            for foreign in ([transport.IMAGE+'/bin/vpn-control','--version'],ns['PACKAGED_ARGV'][index]+['updates','install']):
                with self.assertRaisesRegex(ValueError,'command_refused'):ns['validate_role'](foreign,kwargs)
        ns['role_index']=6
        with self.assertRaises(ValueError):ns['validate_role'](ns['PACKAGED_ARGV'][0],kwargs)
    def test_source_fifo_and_symlink_refuse_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();path=root/'source';path.write_bytes(b'fixed-source')
            self.assertEqual(transport._source_bytes(path),b'fixed-source')
            link=root/'alias';link.symlink_to(path)
            with self.assertRaises(OSError):transport._source_bytes(link)
            if hasattr(os,'mkfifo'):
                fifo=root/'fifo';os.mkfifo(fifo)
                with self.assertRaisesRegex(ValueError,'source_changed'):transport._source_bytes(fifo)
    def test_bad_revision_and_duplicate_json(self):
        for revision in (True,-1,2**63):
            with self.assertRaises(ValueError):transport._worker_source({**REQUEST,'revision':revision})
        with self.assertRaisesRegex(ValueError,'duplicate_json'):transport._json('{"ok":true,"ok":true}')
        value=reply(('status',));value['data']['runtimeRunning']=True
        with self.assertRaisesRegex(ValueError,'runtime_unknown'):transport._reply(value,('status',),REQUEST['owner'],0)


def composed_case(case,mutate,source_path=None):
    """Reuse the exact reviewed real155FD constructor; only child effect is inert.

    Source is authenticated, then the old two-role sentinel is changed into a
    six-role sentinel. All actual image/JDK/archive/source physical predicates,
    durable saved image journals and directory/FD constructors remain intact.
    """
    raw=(source_path or Path(__file__).parent/'fixtures/android_installer_hermetic/product-launcher-test.source').read_bytes()
    if hashlib.sha256(raw).hexdigest()!='b8da298ece97fa517222ff3870eec7662fe5e019d4a45d6284855753a8f0a46b':raise AssertionError('reviewed fixture changed')
    method=ast.parse(textwrap.dedent(inspect.getsource(recipe.ProductLauncherRecipeTests.whole_producer_barrier))).body[0]
    method.name='actual_packaged_composition'
    method.body[0:0]=ast.parse("adb=self.root/'adb';adb.write_bytes(b'owned-adb-fixture');adb.chmod(0o700)").body
    for node in ast.walk(method):
        if isinstance(node,ast.FunctionDef) and node.name=='barrier':
            replacement=ast.parse('''def barrier(command,**kwargs):
    self.assertEqual(ns['validate_role'](command,kwargs),transport.ROLES[len(calls)])
    ns['producer_guards']()
    ns['generated_image_guard']()
    calls.append(command)
    ns['role_index']+=1
    words=transport.WORDS[len(calls)-1]
    # A real bounded harmless child produces each DTO. Java is never run.
    script='import json;print('+repr(json.dumps(reply(words)))+')'
    child=subprocess.run([sys.executable,'-c',script],capture_output=True,text=True,timeout=3)
    value=subprocess.CompletedProcess(command,child.returncode,child.stdout,'')
    if mutate=='adb-drift':adb.write_bytes(b'changed-adb-after-read')
    if mutate=='metadata-stderr':value.stderr='pure virtual method called\\n'
    return value
''').body[0]
            node.body=replacement.body
        if isinstance(node,ast.Constant) and node.value=='producer_strict_gate_failed':node.value='packaged_read_process_unknown'
    # Insert fixed role globals immediately before the old calls=[] declaration.
    pos=next(i for i,n in enumerate(method.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='calls' for t in n.targets))
    method.body[pos:pos]=ast.parse("self.packaged_namespace=ns\nns.update(packaged_adb_fd=None,packaged_adb_chain=[],PACKAGED_REQUEST={**REQUEST,'adb':{'path':str(adb),'generation':ns['fp'](adb.stat()),'sha256':hashlib.sha256(adb.read_bytes()).hexdigest()}},PACKAGED_ROLES=transport.ROLES,PACKAGED_WORDS=transport.WORDS,PACKAGED_ARGV=[[str(self.image/'bin/vpn-control'),'--json','--android','--serial','emulator-5682','--timeout-seconds','30','--controller-id',REQUEST['owner'],*words] for words in transport.WORDS],history=transport.history,copy=copy,shutil=__import__('shutil'))").body
    for node in ast.walk(method):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr=='assertEqual' and len(node.args)==2 and isinstance(node.args[0],ast.Name) and node.args[0].id=='calls' and isinstance(node.args[1],ast.List) and len(node.args[1].elts)==2:
            node.args[1]=ast.parse("ns['PACKAGED_ARGV']",mode='eval').body
    worker=ast.parse(transport._worker_source(REQUEST))
    # Keep all old metadata helpers, substituting only actual new worker funcs.
    metadata=ast.parse(recipe.fixture.METADATA_SOURCE)
    replacements={n.name:n for n in worker.body if isinstance(n,ast.FunctionDef) and n.name in ('validate_role','run_hello_gate','generated_image_guard')}
    metadata.body=[replacements.get(n.name,n) if isinstance(n,ast.FunctionDef) else n for n in metadata.body]
    metadata.body += [n for n in worker.body if isinstance(n,ast.FunctionDef) and n.name in ('_json','_reply','_public_result','packaged_adb_admit','packaged_adb_close')]
    namespace=dict(recipe.__dict__);namespace.update(transport=transport,REQUEST=REQUEST,reply=reply,subprocess=subprocess,copy=copy)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[method],type_ignores=[])),'<actual-full-source-packaged-read-composition>','exec'),namespace)
    with patch.object(recipe.fixture,'METADATA_SOURCE',ast.unparse(ast.Module(body=metadata.body,type_ignores=[]))):
        with patch.object(__import__('shutil'),'which',return_value='/foreign/adb') if mutate=='adb-lookup' else contextlib.nullcontext():
            namespace['actual_packaged_composition'](case,mutate,metadata=True)


class CompositionTests(unittest.TestCase):
    def run_case(self,mutate):
        case=recipe.ProductLauncherRecipeTests();case.setUp()
        try:composed_case(case,mutate)
        finally:
            ns=getattr(case,'packaged_namespace',{})
            if ns.get('packaged_adb_fd') is not None:recipe.os.close(ns['packaged_adb_fd'])
            if ns.get('packaged_adb_chain'):ns['close_parents'](ns['packaged_adb_chain'])
            case.tearDown()
    def test_authenticated_public_barrier_source_mutation_refuses_before_child(self):
        case=recipe.ProductLauncherRecipeTests();case.setUp()
        try:
            with tempfile.TemporaryDirectory() as temp:
                source=Path(temp)/'barrier.source'
                original=Path(__file__).parent/'fixtures/android_installer_hermetic/product-launcher-test.source'
                source.write_bytes(original.read_bytes()+b'\n')
                with patch.object(subprocess,'Popen',side_effect=AssertionError('child must not start')):
                    with self.assertRaisesRegex(AssertionError,'reviewed fixture changed'):
                        composed_case(case,False,source)
        finally:case.tearDown()

    def test_actual_six_read_image_source_fd_composition(self):self.run_case(False)
    def test_actual_image_origin_drift_before_any_child(self):self.run_case('metadata-image-drift')
    def test_pure_virtual_stderr_is_not_accepted(self):self.run_case('metadata-stderr')
    def test_actual_adb_replacement_closes_before_second_read(self):
        with self.assertRaisesRegex(ValueError,'packaged_read_adb_changed'):self.run_case('adb-drift')
    def test_wrong_path_lookup_refuses_before_command(self):
        with self.assertRaisesRegex(ValueError,'packaged_read_adb_lookup_changed'):self.run_case('adb-lookup')


class GuardianTests(unittest.TestCase):
    def test_fabricated_guard_is_not_admission(self):
        with self.assertRaisesRegex(ValueError,'genuine_guard_required'):transport.prepare(object(),REQUEST['correlationId'])
    def test_genuine_api35_prerequisite_then_only_physical_reads(self):
        case=guard_tests.BundleTests();case.setUp()
        try:
            selected,backend,args,state,log,*_=case.api35_fixture()
            case.actual_factory_functions(backend,'api35')
            from agent_tools import android_installer_component_bundle as current_bundle
            from agent_tools.tests.fixtures import historical_source
            historical=Path(__file__).parent/'fixtures/android_installer_hermetic/component-bundle.source'
            raw=current_bundle._read(historical)[0]
            if hashlib.sha256(raw).hexdigest()!=transport.BUNDLE_SHA:
                raise ValueError('historical_bundle_source_changed')
            # Actual historical guard namespace over a fresh real staged tree;
            # no current production SHA anchor is overridden.
            origin=case.source_root/'agent_tools/android_installer_component_bundle.py'
            origin.write_bytes(raw)
            receipt=current_bundle.prepare(case.source_root,case.root/'historical-stage',
                current_bundle.reviewed_tree(case.source_root)['treeSha256'])
            bundle=historical_source.load(Path(receipt['directory'])/'agent_tools/android_installer_component_bundle.py',transport.BUNDLE_SHA)
            case.receipt=receipt
            selected=current_bundle.modules(receipt)
            request={'host':'archlinux','device':'android-api35','correlationId':guard_tests.CORRELATION,
                'sourceSha':bundle._PRODUCT_SHA,'expectedOwner':guard_tests.OWNER,'expectedRevision':0,
                'expectedAvd':'owned-fixture','expectedApi':35,'packageSha256':backend['GETTER']['packageSha256'],
                'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
            current_guard=current_bundle.BaselineGuard(case.receipt,selected,backend,
                {**request,'correlationId':'33333333-3333-4333-8333-333333333333'})
            before_current=log.read_bytes()
            with self.assertRaisesRegex(ValueError,'guard_source_changed'):
                transport.prepare(current_guard,REQUEST['correlationId'])
            self.assertEqual(before_current,log.read_bytes())
            guard=bundle.BaselineGuard(case.receipt,selected,backend,request)
            before=log.read_bytes()
            prepared=transport.prepare(guard,REQUEST['correlationId'])
            with patch.object(transport,'BUNDLE_SHA','08bdbd323d00e19ed28ec32512ffa95cd301d8992144039535de4cfdc1fd7a67'):
                with self.assertRaisesRegex(ValueError,'guard_source_changed'):transport.prepare(guard,REQUEST['correlationId'])
            with patch.object(bundle,'_PROCESS_READ','foreign-command'):
                with self.assertRaisesRegex(ValueError,'guard_globals_changed'):transport.prepare(guard,REQUEST['correlationId'])
            with patch.object(bundle.BaselineGuard,'_task_guard',lambda self:None):
                with self.assertRaisesRegex(ValueError,'guard_method_changed'):transport.prepare(guard,REQUEST['correlationId'])
            original=bundle.CurrentGuard._physical
            foreign=types.FunctionType(original.__code__,dict(original.__globals__),argdefs=original.__defaults__)
            with patch.object(bundle.CurrentGuard,'_physical',foreign):
                with self.assertRaisesRegex(ValueError,'guard_method_changed'):transport.prepare(guard,REQUEST['correlationId'])
            before_batch=log.read_bytes()
            for value in (None,{}):
                guard.batch_admission=value
                for operation in (lambda:transport.prepare(guard,REQUEST['correlationId']),
                                  lambda:transport.namespace_source(prepared),
                                  lambda:transport.finish(prepared,{})):
                    with self.subTest(batch=value),self.assertRaisesRegex(ValueError,'batch_disabled'):operation()
            del guard.batch_admission
            self.assertEqual(before_batch,log.read_bytes())
            original_phase=guard.phase;guard.phase='installer-action'
            with self.assertRaisesRegex(ValueError,'device_unavailable'):transport.prepare(guard,REQUEST['correlationId'])
            guard.phase=original_phase
            new=log.read_bytes()[len(before):]
            rows=[json.loads(row) for row in new.splitlines()]
            self.assertTrue(rows);self.assertTrue(all('shell' in row for row in rows))
            self.assertEqual(prepared.request['owner'],guard_tests.OWNER)
            self.assertEqual(transport.namespace_source(prepared),prepared.program)
            observed=json.loads(state.read_bytes());observed['boot']='38b8f9af-efbb-44da-9836-0237cb714df9';state.write_text(json.dumps(observed))
            with self.assertRaisesRegex(ValueError,'generation_changed'):transport.prepare(guard,REQUEST['correlationId'])
        finally:case.tearDown()


if __name__=='__main__':unittest.main()
