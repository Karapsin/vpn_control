"""Real pure/emitted protocol paths; no Windows/native acceptance claim."""
import ast,base64,builtins,copy,hashlib,io,json,os,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from xml.etree import ElementTree as ET
from agent_tools import windows_vm_unattend as unattended
from agent_tools import windows_vm_deploy_remote as producer
from agent_tools import windows_vm_deploy as deploy
from agent_tools import windows_visual_fixture as visual
from agent_tools import windows_vm_guest as guest
from agent_tools.native_vm_spec import FreshWindowsVmSpec
from agent_tools.tests.test_native_vm_spec import request
from agent_tools.tests import test_windows_vm_guest as guest_fixture

FIXTURE=Path(__file__).parent/'fixtures/windows_visual_purpose'


def settings(visual_purpose=False):
    value={'imageName':'Windows 11 Enterprise Evaluation','locale':'en-US','user':'fixtureUser','administrator':'fixtureAdmin'}
    if visual_purpose:value['purpose']='windowsUacVisual'
    return value


def before_modules():
    """Load authentic complete beforeimages with their original relative imports."""
    metadata=json.loads((FIXTURE/'provenance.json').read_bytes())
    prefix='_visual_before_'+uuid.uuid4().hex
    package=types.ModuleType(prefix);package.__path__=[str(Path(unattended.__file__).parent)];sys.modules[prefix]=package
    modules={}
    for row in metadata['sources']:
        path=FIXTURE/row['fixture'];raw=path.read_bytes()
        if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise AssertionError('authentic visual beforeimage changed')
        name=Path(row['sourcePath']).stem;module=types.ModuleType(prefix+'.'+name)
        module.__file__=str(path);module.__package__=prefix;sys.modules[module.__name__]=module
        setattr(package,name,module);exec(compile(raw,str(path),'exec'),module.__dict__);modules[name]=module
    return modules


def emitted_namespace(setup,mode='qualify',operation=None):
    operation=operation or str(uuid.uuid4());context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]}
    body=producer.program(FreshWindowsVmSpec.parse(request()),mode,setup=setup,context=context,operation_id=operation)
    tree=ast.parse(body)
    # Execute all actual emitted definitions; only suppress its native entry.
    assert isinstance(tree.body[-1],ast.Expr) and ast.unparse(tree.body[-1])=='_vm_main()'
    tree.body.pop();namespace={'__name__':'__main__'}
    exec(compile(ast.fix_missing_locations(tree),'complete emitted visual producer','exec'),namespace)
    return namespace,body


class SetupPurposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.before=before_modules()

    def test_default_four_key_parse_and_xml_are_byte_identical_to_authentic_before(self):
        old=self.before['windows_vm_unattend'];credentials={'user':'User8!'+'a'*24,'administrator':'Admin8!'+'b'*24}
        for data in (settings(),{**settings(),'locale':'fr-FR','user':'anotherUser','administrator':'otherAdmin'}):
            self.assertEqual(json.dumps(old.parse_setup(data),separators=(',',':')),json.dumps(unattended.parse_setup(data),separators=(',',':')))
            self.assertEqual(set(data),set(unattended.parse_setup(data)))
            self.assertEqual(old.answer_file(data,credentials),unattended.answer_file(data,credentials))

    def test_explicit_visual_xml_changes_only_initial_logon_role_password_and_count(self):
        old=self.before['windows_vm_unattend'];credentials={'user':'User8!'+'a'*24,'administrator':'Admin8!'+'b'*24}
        data=settings(True)
        with self.assertRaises(ValueError):old.parse_setup(data)
        try:parsed=unattended.parse_setup(data)
        except ValueError:self.fail('Explicit fresh visual purpose was rejected before XML rendering')
        self.assertEqual(data,parsed)
        ns={'u':'urn:schemas-microsoft-com:unattend'}
        ordinary=ET.fromstring(old.answer_file(settings(),credentials));actual=ET.fromstring(unattended.answer_file(data,credentials))
        changed=[]
        for left,right in zip(ordinary.iter(),actual.iter()):
            self.assertEqual(left.tag,right.tag);self.assertEqual(left.attrib,right.attrib)
            if left.text!=right.text:changed.append((left.tag.rsplit('}',1)[-1],left.text,right.text))
        self.assertEqual([('Username',data['user'],data['administrator']),('LogonCount','3','1'),('Value',credentials['user'],credentials['administrator'])],changed)
        groups={a.findtext('u:Name',namespaces=ns):a.findtext('u:Group',namespaces=ns)for a in actual.findall('.//u:LocalAccount',ns)}
        self.assertEqual({data['user']:'Users',data['administrator']:'Administrators'},groups)

    def test_only_exact_visual_purpose_is_admitted(self):
        for value in (None,False,0,{},[], 'standardProduct','windowsuacvisual','windowsUacVisual '):
            with self.subTest(value=value),self.assertRaises(ValueError):unattended.parse_setup({**settings(),'purpose':value})
        for extra in ({'admin':True},{'purpose':'windowsUacVisual','command':'unused'}):
            with self.assertRaises(ValueError):unattended.parse_setup({**settings(),**extra})

    def test_default_emission_preserves_bound_values_and_standard_procedures(self):
        old=self.before['windows_vm_deploy_remote'];spec=FreshWindowsVmSpec.parse(request())
        context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]};operation=str(uuid.uuid4())
        for mode in ('start','status','qualify','qualify-status','secure','secure-status'):
            old_tree=ast.parse(old.program(spec,mode,setup=settings(),context=context,operation_id=operation))
            current_tree=ast.parse(producer.program(spec,mode,setup=settings(),context=context,operation_id=operation))
            def fixed(tree):
                names={'SPEC','SETUP','CONTEXT','MODE','PS_SCRIPT','SECURE_SCRIPT','SECURE_CHECK_SCRIPT'}
                return {n.targets[0].id:ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)and n.targets[0].id in names}
            self.assertEqual(fixed(old_tree),fixed(current_tree))
            for name in ('validate_setup_result','qualify_instance','secure_instance','_vm_main'):
                before=[n for n in old_tree.body if isinstance(n,ast.FunctionDef)and n.name==name]
                after=[n for n in current_tree.body if isinstance(n,ast.FunctionDef)and n.name==name]
                self.assertEqual([ast.dump(n)for n in before],[ast.dump(n)for n in after])

    def test_visual_emitter_has_complete_namespace_and_unchanged_security_mutation(self):
        operation=str(uuid.uuid4());namespace,body=emitted_namespace(settings(True),'secure',operation)
        self.assertEqual(settings(True),namespace['SETUP']);self.assertEqual('windowsUacVisual',namespace['SETUP']['purpose'])
        self.assertEqual(guest.secure_source(settings(True),operation),namespace['SECURE_SCRIPT'])
        self.assertIs(namespace['qualify_instance'],namespace['_qualify_visual_instance'])
        for source in (namespace['PS_SCRIPT'],namespace['SECURE_CHECK_SCRIPT']):
            self.assertIn("$ProgressPreference='SilentlyContinue'",source)
            self.assertLessEqual(len(base64.b64encode(source.encode('utf-16le')))+256,30000)
        self.assertNotIn('final-administrator.secret',body.decode())
        self.assertNotIn('from .',body.decode())

    def test_original_frame_emission_is_byte_identical_for_four_key_setup(self):
        old=self.before['windows_vm_deploy_remote'];spec=FreshWindowsVmSpec.parse(request())
        context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]};operation=str(uuid.uuid4())
        for mode in ('frame','frame-collect'):
            self.assertEqual(old.program(spec,mode,setup=settings(),context=context,operation_id=operation),
                             producer.program(spec,mode,setup=settings(),context=context,operation_id=operation))

    @unittest.skipUnless(os.name=='posix','physical source custody before transport')
    def test_actual_source_capsule_adds_visual_owner_only_on_consuming_path(self):
        from agent_tools.native_review_source_closure import _Held
        class StopBeforeTransport(Exception):pass
        class SourceOnlyGuard:
            def __init__(self,*args,**kwargs):self.held=_Held()
            def __enter__(self):return self
            def guard(self):self.held.finish();self.held.final_identity_pass()
            def __exit__(self,*args):self.held.close()
        for is_visual in (False,True):
            with self.subTest(visual=is_visual),tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
                root=Path(temporary).resolve();root.chmod(0o700)
                # This public fixture value is not a host/user credential.
                fixture_input=root/'public-fixture-input';fixture_input.write_text('INERT_PUBLIC_TEST_INPUT\n');fixture_input.chmod(0o600)
                with mock.patch.object(deploy.direct,'Guard',SourceOnlyGuard),mock.patch.object(deploy.stage,'publish',side_effect=StopBeforeTransport):
                    with self.assertRaises(StopBeforeTransport):
                        deploy._execute(root,FreshWindowsVmSpec.parse(request()),'qualify',credential_file=str(fixture_input),setup=settings(is_visual),
                            context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]},operation_id=str(uuid.uuid4()))
                manifests=list((root/'.runtime/windows-vm-deploy').glob('*/sources/manifest.json'))
                self.assertEqual(1,len(manifests));manifest=json.loads(manifests[0].read_bytes())
                names={row['name']for row in manifest['sources']}
                self.assertEqual(is_visual,'windows_visual_fixture.py'in names)
                for row in manifest['sources']:
                    raw=(manifests[0].parent/row['name']).read_bytes()
                    self.assertEqual(row['bytes'],len(raw));self.assertEqual(row['sha256'],hashlib.sha256(raw).hexdigest())

    @unittest.skipUnless(os.name=='posix','POSIX original intent custody')
    def test_original_four_key_start_intent_still_resolves_and_cannot_be_reinterpreted(self):
        old=self.before['windows_vm_deploy_remote'];spec=FreshWindowsVmSpec.parse(request())
        context={'hostBootId':'ff6b5d84-f546-4a96-baf7-f9c801c743c0','pending':[]};correlation='a'*32
        source=old.program(spec,'start',setup=settings(),context=context)
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            saved=root/'.runtime/windows-vm-deploy'/correlation;saved.mkdir(parents=True)
            caller=saved/'caller.py';caller.write_bytes(source);caller.chmod(0o600)
            intents=root/'.rag_index/windows-vm-deploy-intents';intents.mkdir(parents=True)
            intent=intents/(spec.deployment_id+'.intent.json')
            value={'spec':spec.as_dict(),'setup':settings(),'context':context,'correlationId':correlation,'mode':'start','callerSha256':hashlib.sha256(source).hexdigest()}
            original=json.dumps(value).encode();intent.write_bytes(original);intent.chmod(0o600)
            for mode in ('status','frame','secure-status'):
                with mock.patch.object(deploy,'_execute',return_value={'readOnlySeam':mode})as execute:
                    result=deploy._original_operation(root,spec.deployment_id,None,mode)
                    self.assertEqual({'readOnlySeam':mode},result)
                    self.assertEqual(settings(),execute.call_args.kwargs['setup'])
                self.assertEqual(original,intent.read_bytes());self.assertEqual(source,caller.read_bytes())
            value['setup']=settings(True);intent.write_bytes(json.dumps(value).encode());intent.chmod(0o600)
            with mock.patch.object(deploy,'_execute',side_effect=AssertionError('no transport')):
                with self.assertRaisesRegex(ValueError,'deployment_source_binding'):
                    deploy._original_operation(root,spec.deployment_id,None,'status')


@unittest.skipUnless(os.name=='posix','physical POSIX qualification records')
class VisualQualificationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=guest_fixture.GuestQualificationTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        f=self.fixture;f.setup['purpose']='windowsUacVisual'
        f.result['os']['bootTime']='2026-10-19T06:35:06.5000001Z'
        opening=['134368653275038175','C:\\Windows\\explorer.exe',f.result['administrator']['sid'],'0','3','True','False','True','2']
        f.result['visualSession']={'activeConsoleSession':2,'closingConsoleSession':2,'administratorProfile':'C:\\Users\\fixtureAdmin','explorerPid':5788,'opening':opening,'closing':list(opening),'bootFileTimeUtc':'134368653065000001'}
        self.namespace,_=emitted_namespace(f.setup,operation=f.operation)
        self.namespace.update(CONTEXT={'hostBootId':'FIXTURE_BOOT'},call=f.call)
        f.subject=self.namespace['qualify_instance']

    def run_subject(self,status_only=False):
        f=self.fixture;f.terminal['out-data']=base64.b64encode(json.dumps(f.result).encode()).decode()
        original=builtins.open
        def opened(path,*args,**kwargs):return io.StringIO('FIXTURE_BOOT')if str(path)=='/proc/sys/kernel/random/boot_id'else original(path,*args,**kwargs)
        with mock.patch.object(builtins,'open',side_effect=opened):
            return f.subject(f.spec,f.setup,f.operation,status_only,f.root,f.read,f.save,
                lambda row:self.assertEqual(f.row,row),lambda *_:None,lambda:None,lambda:None,
                lambda:{'guestAgentReady':True,'ordinarySessionObserved':False})

    def new_query(self):
        f=self.fixture;f.operation=str(uuid.uuid4());f.result['nonce']=f.operation
        self.namespace['PS_SCRIPT']=visual.powershell_source(f.setup,f.operation);f.calls.clear()

    def test_full_qualification_binds_only_real_classified_facts_and_status_never_replays(self):
        value=self.run_subject();self.assertTrue(value['setupReady']);self.assertTrue(value['result']['visualFilteredAdminReady']);self.assertFalse(value['productReady'])
        path=self.fixture.root/'visual-session-qualified.json';before=path.read_bytes()
        self.fixture.calls.clear();self.assertEqual(value,self.run_subject(True));self.assertEqual([],self.fixture.calls);self.assertEqual(before,path.read_bytes())
        self.assertNotIn('setupSecured',value);self.assertNotIn('captureReady',value)

    def test_postsecurity_new_query_accepts_disabled_task_but_requires_same_explorer(self):
        self.run_subject();path=self.fixture.root/'visual-session-qualified.json';before=path.read_bytes()
        self.new_query();self.fixture.result['setup']['taskState']='Disabled'
        value=self.run_subject();self.assertTrue(value['setupReady']);self.assertEqual(before,path.read_bytes())
        self.assertNotIn('setupSecured',value);self.assertNotIn('captureReady',value)
        self.new_query();self.fixture.result['visualSession']['explorerPid']+=1
        with self.assertRaisesRegex(ValueError,'instance_visual_session_changed'):self.run_subject()
        self.assertEqual(before,path.read_bytes());self.fixture.calls.clear()
        with self.assertRaisesRegex(ValueError,'instance_visual_session_changed'):self.run_subject(True)
        self.assertEqual([],self.fixture.calls)

    def test_filetimes_remain_exact_decimal_strings_across_javascript_number_parsing(self):
        self.fixture.result['visualSession']['opening'][1]='c:\\WINDOWS\\Explorer.EXE'
        self.fixture.result['visualSession']['closing'][1]='c:\\WINDOWS\\Explorer.EXE'
        value=self.run_subject();path=self.fixture.root/'visual-session-qualified.json'
        # parse_int=float models JavaScript's JSON number representation. The
        # odd 100ns values exceed 2**53, so numeric wire fields would lose bits.
        result=json.loads(json.dumps(value),parse_int=float)
        binding=json.loads(path.read_bytes(),parse_int=float)['binding']
        for actual in (value['result']['visualSession']['bootFileTimeUtc'],result['result']['visualSession']['bootFileTimeUtc'],binding['bootFileTimeUtc']):
            self.assertIs(type(actual),str);self.assertEqual('134368653065000001',actual)
        for actual in (result['result']['visualSession']['opening'][0],binding['explorerBirth']):
            self.assertIs(type(actual),str);self.assertEqual('134368653275038175',actual)
        self.assertNotEqual(134368653065000001,int(float('134368653065000001')))
        self.assertNotEqual(134368653275038175,int(float('134368653275038175')))

    def test_noncanonical_or_numeric_filetimes_refuse_before_session_binding(self):
        original=copy.deepcopy(self.fixture.result)
        for value in (134368653065000001,float('134368653065000001'),True,False,'0134368653065000001','+134368653065000001','134368653065000001.0','134368653065000001 ','0',str(2**63)):
            self.fixture.result=copy.deepcopy(original);self.fixture.result['visualSession']['bootFileTimeUtc']=value;self.new_query()
            with self.subTest(value=value),self.assertRaisesRegex(ValueError,'instance_visual_identity'):self.run_subject()
            self.assertFalse((self.fixture.root/'visual-session-qualified.json').exists())
        for value in (134368653275038175,float('134368653275038175'),True,'0134368653275038175','+134368653275038175'):
            self.fixture.result=copy.deepcopy(original)
            self.fixture.result['visualSession']['opening'][0]=value;self.fixture.result['visualSession']['closing'][0]=value;self.new_query()
            with self.subTest(birth=value),self.assertRaises(ValueError):self.run_subject()
            self.assertFalse((self.fixture.root/'visual-session-qualified.json').exists())

    def test_full_qualification_rejects_unfiltered_wrong_session_and_changed_process_before_binding(self):
        original=copy.deepcopy(self.fixture.result);session=original['visualSession']
        changes=[]
        for index,value in ((0,'0'),(1,'C:\\Users\\fixtureAdmin\\explorer.exe'),(1,'D:\\Windows\\explorer.exe'),(2,original['user']['sid']),(3,'1'),(4,'1'),(4,'2'),(5,'False'),(6,'True'),(7,'False'),(8,'3')):
            candidate=copy.deepcopy(original);candidate['visualSession']['opening'][index]=value;candidate['visualSession']['closing'][index]=value;changes.append(candidate)
        for field,value in (('activeConsoleSession',True),('closingConsoleSession',3),('explorerPid',True),('bootFileTimeUtc',str(int(session['bootFileTimeUtc'])+1)),('administratorProfile','C:\\Users\\fixtureUser')):
            candidate=copy.deepcopy(original);candidate['visualSession'][field]=value;changes.append(candidate)
        candidate=copy.deepcopy(original);candidate['visualSession']['closing'][0]=str(int(session['opening'][0])+1);changes.append(candidate)
        for index,candidate in enumerate(changes):
            self.fixture.result=candidate;self.new_query()
            with self.subTest(index=index),self.assertRaises(ValueError):self.run_subject()
            self.assertFalse((self.fixture.root/'visual-session-qualified.json').exists())

    def test_partial_setup_account_or_image_failure_never_creates_session_authority(self):
        original=copy.deepcopy(self.fixture.result)
        for group,key,value in (('user','isAdministrator',True),('user','enabled',False),('setup','systemSetupInProgress',False),('setup','oobeInProgress',False),('setup','imageState','INCOMPLETE'),('setup','taskState','Running'),('guestAgent','state','Stopped'),('os','editionId','Wrong')):
            self.fixture.result=copy.deepcopy(original);self.fixture.result[group][key]=value;self.new_query()
            with self.subTest(group=group,key=key):self.assertFalse(self.run_subject()['setupReady'])
            self.assertFalse((self.fixture.root/'visual-session-qualified.json').exists())
        self.fixture.result=copy.deepcopy(original);self.fixture.result['setup']['ready']['installerExit']=False;self.new_query()
        self.assertFalse(self.run_subject()['setupReady']);self.assertFalse((self.fixture.root/'visual-session-qualified.json').exists())


if __name__=='__main__':unittest.main()
