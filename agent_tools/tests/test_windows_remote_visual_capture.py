"""Physical local journal/PNG collection; no Windows/native acceptance claim."""
import base64,contextlib,copy,hashlib,io,json,os,shlex,shutil,subprocess,sys,tempfile,types,unittest,uuid
from pathlib import Path
from unittest import mock
from PIL import Image
from scripts import capture_visual_windows_remote as subject
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from scripts import visual_platform,visual_target

BEFORE=Path(__file__).parent/'fixtures/windows_remote_visual_capture'
DRIVER_BEFORE=BEFORE/'capture_visual_windows_remote.before.source'
TARGET_BEFORE=BEFORE/'visual_target.before.source'
LOCAL={'kind':'native-or-client-vm','libvirt_name':'vpn-control-win11','qemu_disk':'.runtime/visual-vms/windows/vpn-control-win11.qcow2','qemu_ready_marker':'.runtime/visual-vms/windows/READY'}


def authentic(path):
    """Unfixed source bytes, verified against their recorded provenance."""
    raw=path.read_bytes();row=next(r for r in json.loads((BEFORE/'provenance.json').read_bytes())['sources']if r['fixture']==path.name)
    if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise AssertionError('authentic beforeimage changed')
    return raw


def before_selector():
    """Unfixed selector with its canonical __file__, so its ROOT is the checkout."""
    module=types.ModuleType('visual_target_before');module.__file__=visual_target.__file__
    exec(compile(authentic(TARGET_BEFORE),str(TARGET_BEFORE),'exec'),module.__dict__);return module


class Fixture:
    def __init__(self,root):
        self.root=root;self.deployment=str(uuid.uuid4());self.operation=str(uuid.uuid4());self.start='a'*32;self.journal='b'*32
        self.folder=root/'.runtime/windows-vm-deploy'/self.journal;self.output=root/'output';self.output.mkdir()
        self.manifest=root/'visual-tests/scenes.json';self.scenes=self.output/'requested-scenes.json'
        self.put(self.manifest,{'schema_version':1,'capture_contract':{'secure_scene_ids':['windows-uac']},'scenes':[{'id':'windows-uac','platforms':['windows'],'geometry_required':False}]},private=False)
        self.put(self.scenes,['windows-uac'],private=False)
        self.spec={'deploymentId':self.deployment,'host':'fixture-host','root':'/home/fixture/new-visual-vm','vncPort':5955}
        self.setup={'imageName':'Windows 11 Enterprise Evaluation','locale':'en-US','user':'visualUser','administrator':'visualAdmin','purpose':'windowsUacVisual'}
        self.context={'hostBootId':str(uuid.uuid4()),'pending':[]}
        self.start_source=self.source({'SPEC':self.spec,'SETUP':self.setup,'CONTEXT':self.context,'MODE':'start'})
        self.put(root/'.runtime/windows-vm-deploy'/self.start/'caller.py',self.start_source)
        self.intent={'spec':self.spec,'setup':self.setup,'context':self.context,'mode':'start','correlationId':self.start,'callerSha256':self.sha(self.start_source)}
        self.intent_path=root/'.rag_index/windows-vm-deploy-intents'/(self.deployment+'.intent.json');self.put(self.intent_path,self.intent)
        self.frame_source=self.source({'SPEC':self.spec,'SETUP':self.setup,'CONTEXT':self.context,'OPERATION_ID':self.operation,
            'LEAF':'setup-frame-'+uuid.UUID(self.operation).hex+'.png','PROBE':False,'RETURN_FRAME':True,'READ_EXISTING':False,'FRAME_INPUT':None})
        self.put(self.folder/'caller.py',self.frame_source)
        self.request={'spec':self.spec,'mode':'frame','correlationId':self.journal,'callerSha256':self.sha(self.frame_source)};self.put(self.folder/'request.json',self.request)
        self.put(self.folder/'closing.json',{'sourceClosing':True,'correlationId':self.journal})
        self.terminal={'complete':True,'counts':{'stdout':1000,'stderr':0},'eof':{'stdout':True,'stderr':True},'overflow':False,'pid':1234,'returnCode':0,'sendError':None,'timeout':False}
        self.put(self.folder/'native-terminal.json',self.terminal)
        rows=[]
        for name in (*subject.FRAME_OWNERS,'caller.py'):
            origin=self.folder/'caller.py'if name=='caller.py'else root/'agent_tools'/name
            raw=self.frame_source if name=='caller.py'else ('# public source fixture '+name+'\n').encode()
            if name!='caller.py':self.put(origin,raw,private=False)
            self.put(self.folder/'sources'/name,raw);rows.append({'name':name,'sourcePath':str(origin),'bytes':len(raw),'sha256':self.sha(raw),'generation':[1]*9})
        self.put(self.folder/'sources/manifest.json',{'schemaVersion':1,'sourceClosingBeforeTransfer':True,'sources':rows})
        self.image=self.png();self.put(self.folder/'frame.png',self.image)
        self.native={'state':'observed','correlationId':'c'*32,'capture':{'complete':True,'counts':{'stdout':1000,'tty':0},'eof':{'stdout':True,'tty':True},'pid':1235,'refusal':None,'returnCode':0,'timeout':False,'credentialSent':True},
            'result':{'engineeringOnly':True,'state':'frame-read-observed','deploymentId':self.deployment,'operationId':self.operation,
                'frame':'setup-frame-'+uuid.UUID(self.operation).hex+'.png','bytes':len(self.image),'sha256':self.sha(self.image),'base64':base64.b64encode(self.image).decode(),'nativeActionAllowed':False,'replayAllowed':False}}
        self.put(self.folder/'native-result.json',self.native)

    @staticmethod
    def sha(raw):return hashlib.sha256(raw).hexdigest()
    @staticmethod
    def source(values):return ''.join(name+'='+repr(value)+'\n'for name,value in values.items()).encode()
    @staticmethod
    def png(size=(1280,800)):
        stream=io.BytesIO();Image.new('RGB',size,(18,37,63)).save(stream,format='PNG');return stream.getvalue()
    @staticmethod
    def put(path,value,private=True):
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(value if type(value)is bytes else json.dumps(value).encode());path.chmod(0o600 if private else 0o644)
    def collect(self,**changes):
        kwargs={'deployment_id':self.deployment,'operation_id':self.operation,'journal_id':self.journal,'manifest':self.manifest,'scenes':self.scenes,'output':self.output,**changes}
        return subject.collect(self.root,**kwargs)


@unittest.skipUnless(os.name=='posix','POSIX coordinator custody')
class RemoteFrameCollectionTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(dir=Path('/tmp').resolve());self.addCleanup(temporary.cleanup)
        self.f=Fixture(Path(temporary.name).resolve())
    def no_output(self):self.assertFalse((self.f.output/'windows-uac.png').exists())

    def test_original_known_frame_is_copied_verbatim_without_acceptance_claim(self):
        value=self.f.collect();self.assertEqual(self.f.image,(self.f.output/'windows-uac.png').read_bytes())
        self.assertEqual(self.f.sha(self.f.image),value['sha256']);self.assertTrue(value['visualReviewRequired'])
        self.assertNotIn('pass',value);self.assertNotIn('productReady',value)
        self.assertEqual(value,self.f.collect())

    def test_other_existing_output_is_preserved_and_refused(self):
        path=self.f.output/'windows-uac.png';self.f.put(path,b'ORIGINAL_OTHER_CAPTURE')
        with self.assertRaisesRegex(ValueError,'another capture'):self.f.collect()
        self.assertEqual(b'ORIGINAL_OTHER_CAPTURE',path.read_bytes())

    def test_original_deployment_and_frame_operation_must_both_match(self):
        for changes in ({'deployment_id':str(uuid.uuid4())},{'operation_id':str(uuid.uuid4())},{'journal_id':'../frame'},{'operation_id':self.f.operation.upper()}):
            with self.subTest(changes=changes),self.assertRaises((ValueError,OSError)):self.f.collect(**changes)
            self.no_output()

    def test_ordinary_product_vm_is_not_repurposed_as_visual_context(self):
        value=copy.deepcopy(self.f.intent);value['setup'].pop('purpose');self.f.put(self.f.intent_path,value)
        with self.assertRaisesRegex(ValueError,'visual-purpose'):self.f.collect()
        self.no_output()

    def test_changed_original_start_source_is_refused(self):
        self.f.put(self.f.root/'.runtime/windows-vm-deploy'/self.f.start/'caller.py',self.f.start_source+b'# changed\n')
        with self.assertRaisesRegex(ValueError,'start caller changed'):self.f.collect()
        self.no_output()

    def test_changed_frame_source_owner_is_refused(self):
        self.f.put(self.f.root/'agent_tools/windows_vm_instance.py',b'# different current owner\n',private=False)
        with self.assertRaisesRegex(ValueError,'current owner'):self.f.collect()
        self.no_output()

    def test_missing_source_closing_and_nonterminal_transports_cannot_promote_image(self):
        path=self.f.folder/'closing.json';original=path.read_bytes();path.unlink()
        with self.assertRaises(OSError):self.f.collect()
        self.f.put(path,original)
        for field,value in (('complete',False),('timeout',True),('overflow',True),('returnCode',True),('eof',{'stdout':True,'stderr':False})):
            terminal={**self.f.terminal,field:value};self.f.put(self.f.folder/'native-terminal.json',terminal)
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'transport is incomplete'):self.f.collect()
            self.no_output()

    def test_frame_bytes_and_result_are_joined_not_an_arbitrary_png(self):
        original=copy.deepcopy(self.f.native)
        for field,value in (('state','unknown'),('operationId',str(uuid.uuid4())),('sha256','0'*64),('base64',base64.b64encode(b'not this image').decode())):
            changed=copy.deepcopy(original);changed['result'][field]=value;self.f.put(self.f.folder/'native-result.json',changed)
            with self.subTest(field=field),self.assertRaises(ValueError):self.f.collect()
            self.no_output()

    def test_malformed_native_envelopes_are_cleanly_refused(self):
        for field,value in ((None,[]),('capture',None),('capture',[]),('capture',{'eof':[]}),('result',None),('result',[])):
            changed=copy.deepcopy(self.f.native)
            if field is None:changed=value
            else:changed[field]=value
            self.f.put(self.f.folder/'native-result.json',changed)
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):self.f.collect()
            self.no_output()

    def test_only_full_screen_png_in_canonical_scene_is_allowed(self):
        image=self.f.png((640,400));changed=copy.deepcopy(self.f.native)
        changed['result'].update(bytes=len(image),sha256=self.f.sha(image),base64=base64.b64encode(image).decode())
        self.f.put(self.f.folder/'native-result.json',changed);self.f.put(self.f.folder/'frame.png',image)
        with self.assertRaisesRegex(ValueError,'1280x800'):self.f.collect()
        self.no_output()

    def test_symlink_input_or_output_never_follows_another_file(self):
        target=self.f.folder/'frame.png';saved=self.f.folder/'original.png';target.rename(saved);target.symlink_to(saved)
        with self.assertRaises(OSError):self.f.collect()
        target.unlink();saved.rename(target)
        output=self.f.output/'windows-uac.png';output.symlink_to(target)
        with self.assertRaises(OSError):self.f.collect()
        self.assertTrue(output.is_symlink());self.assertEqual(self.f.image,target.read_bytes())

    @contextlib.contextmanager
    def merged_capture(self,source=None):
        """Actual capture-local in the isolated root; no checkout, VM or SSH is involved."""
        root=self.f.root;script=root/'scripts/capture_visual_windows_remote.py';self.f.put(script,source or Path(subject.__file__).read_bytes(),private=False)
        from agent_tools import native_review_source_closure
        self.f.put(root/'agent_tools/native_review_source_closure.py',Path(native_review_source_closure.__file__).read_bytes(),private=False)
        self.f.put(root/'agent_tools/__init__.py',b'',private=False)
        environments=root/'visual-tests/environments.json';self.f.put(environments,{'platforms':{'windows':{'canonical_environment':'windows11-client-1280x800','local':LOCAL}}},private=False)
        driver=shlex.join((sys.executable,str(script),'--deployment-id',self.f.deployment,'--operation-id',self.f.operation,'--journal-id',self.f.journal))
        with mock.patch.object(visual_platform,'ROOT',root),mock.patch.object(visual_platform,'MANIFEST_PATH',self.f.manifest),mock.patch.object(visual_platform,'ENVIRONMENTS_PATH',environments),mock.patch.object(visual_platform,'_head_sha',return_value='a'*40),mock.patch.dict(os.environ,{'VPN_CONTROL_VISUAL_TARGET_SHA':'a'*40,'VPN_CONTROL_VISUAL_PROVIDER':'local'}):
            yield driver

    @contextlib.contextmanager
    def child_streams(self):
        """Retain the actual driver child's streams; its command is unchanged."""
        real=subprocess.run;runs=[]
        def run(command,**options):
            runs.append(real(command,**options,stdout=subprocess.PIPE,stderr=subprocess.PIPE));return runs[-1]
        with mock.patch.object(visual_platform.subprocess,'run',run):yield runs

    def target(self):return 'deployment:'+self.f.deployment

    def test_existing_capture_local_driver_interface_stamps_canonical_output(self):
        with self.merged_capture() as driver:
            value=visual_platform.run_local_driver('windows',driver,self.f.output,['windows-uac'],target=self.target())
        capture=json.loads((self.f.output/'capture-local.json').read_bytes())
        self.assertEqual('a'*40,capture['target_sha']);self.assertEqual('windows-uac.png',capture['scenes']['windows-uac']['actual'])
        self.assertEqual(self.f.sha(self.f.image),capture['scenes']['windows-uac']['actual_sha256']);self.assertEqual(1,value['scene_count'])

    def test_documented_capture_local_command_with_relative_output_collects_the_frame(self):
        self.addCleanup(os.chdir,os.getcwd());os.chdir(self.f.root);stdout=io.StringIO()
        with self.merged_capture() as driver,contextlib.redirect_stdout(stdout):
            code=visual_platform.main(['capture-local','--platform','windows','--target',self.target(),'--driver',driver,'--output','output','--scene','windows-uac'])
        self.assertEqual(0,code,stdout.getvalue());self.assertEqual(1,json.loads(stdout.getvalue())['result']['scene_count'])
        self.assertEqual(self.f.image,(self.f.output/'windows-uac.png').read_bytes())

    def test_preserved_driver_exits_2_on_the_target_merged_capture_local_appends(self):
        with self.merged_capture(authentic(DRIVER_BEFORE)) as driver,self.child_streams() as runs,self.assertRaisesRegex(visual_platform.VisualPlatformError,'exit code 2'):
            visual_platform.run_local_driver('windows',driver,self.f.output,['windows-uac'],target='libvirt:'+LOCAL['libvirt_name'])
        self.assertIn(b'unrecognized arguments: --target',runs[0].stderr);self.no_output()

    def test_preserved_selector_has_no_family_that_names_a_remote_deployment(self):
        before=before_selector()
        with self.assertRaises(before.TargetError):before.select('windows',self.target(),LOCAL)
        self.assertEqual(('deployment-windows',self.f.deployment),visual_target.select_capture('windows',self.target(),LOCAL,self.f.root))

    def test_preserved_driver_refuses_the_relative_scene_file_of_a_relative_output(self):
        fields=['--platform','windows','--manifest',str(self.f.manifest),'--output',str(self.f.output)]
        def run(driver,*extra):return subprocess.run([*shlex.split(driver),*fields,*extra],cwd=self.f.root,capture_output=True,timeout=120)
        with self.merged_capture(authentic(DRIVER_BEFORE)) as driver:
            refused=run(driver,'--scenes','output/requested-scenes.json');self.assertEqual(1,refused.returncode,refused.stderr);self.assertIn(b'collection refused',refused.stderr);self.no_output()
            # Only the spelling of the scene file differs from this control.
            control=run(driver,'--scenes',str(self.f.scenes));self.assertEqual(0,control.returncode,control.stderr)
        (self.f.output/'windows-uac.png').unlink()
        with self.merged_capture() as driver:
            current=run(driver,'--target',self.target(),'--scenes','output/requested-scenes.json');self.assertEqual(0,current.returncode,current.stderr)
        self.assertEqual(self.f.image,(self.f.output/'windows-uac.png').read_bytes())

    def test_wrong_or_unowned_deployment_is_refused_before_output_or_driver(self):
        marker=self.f.root/'driver-ran';output=self.f.root/'not-created';path=self.f.intent_path;good=copy.deepcopy(self.f.intent)
        driver=shlex.join((sys.executable,'-c','import pathlib,sys;pathlib.Path(sys.argv[1]).touch()',str(marker)))
        def refused(target=self.target()):
            with self.assertRaisesRegex(visual_platform.VisualPlatformError,'explicit visual target'):
                visual_platform.run_local_driver('windows',driver,output,['windows-uac'],target=target)
            self.assertFalse(output.exists());self.assertFalse(marker.exists())
        ordinary=copy.deepcopy(good);ordinary['setup'].pop('purpose')
        renamed=copy.deepcopy(good);renamed['spec']['deploymentId']=str(uuid.uuid4())
        with self.merged_capture():
            for target in (None,'','deployment','deployment:','deployment:'+str(uuid.uuid4()),'deployment:'+self.f.deployment.upper(),'Deployment:'+self.f.deployment,
                           'deployment:../'+self.f.deployment,'deployment:'+self.f.deployment+'\n','remote:'+self.f.deployment):
                with self.subTest(target=target):refused(target)
            for changed in (ordinary,renamed,{**good,'mode':'secure'},[],'text',b'{not json',b''):
                self.f.put(path,changed)
                with self.subTest(changed=changed):refused()
            self.f.put(path,good);path.chmod(0o640)
            with self.subTest('readable by others'):refused()
            path.chmod(0o600);saved=self.f.root/'saved.intent.json';path.rename(saved);path.symlink_to(saved)
            with self.subTest('symlink'):refused()
            path.unlink();saved.rename(path)
            # Control: selection alone was refusing; this driver then produces no scene.
            with self.assertRaisesRegex(visual_platform.VisualPlatformError,'incomplete set'):
                visual_platform.run_local_driver('windows',driver,output,['windows-uac'],target=self.target())
            self.assertTrue(marker.exists())
        for platform in ('linux','macos','android'):
            with self.subTest(platform=platform),self.assertRaises(visual_target.TargetError):
                visual_target.select_capture(platform,self.target(),{'avd_name':'a','vm_name':'v'},self.f.root)

    def test_remote_deployment_never_reaches_a_local_lifecycle_path(self):
        with self.merged_capture(),mock.patch.object(visual_platform,'_run')as run,mock.patch.object(visual_platform.subprocess,'Popen')as start:
            for action in (visual_platform.bootstrap,visual_platform.start_platform,visual_platform.stop_platform):
                with self.subTest(action=action.__name__),self.assertRaisesRegex(visual_platform.VisualPlatformError,'explicit visual target'):
                    action('windows',target=self.target(),dry_run=False)
            with self.assertRaisesRegex(visual_platform.VisualPlatformError,'explicit visual target'):visual_platform.local_probe('windows',target=self.target())
            with self.assertRaisesRegex(visual_platform.VisualPlatformError,'explicit visual target'):visual_platform.bootstrap_commands('windows',target=self.target())
            run.assert_not_called();start.assert_not_called()

    def test_local_or_other_target_cannot_reach_collection(self):
        other=str(uuid.uuid4());value=copy.deepcopy(self.f.intent);value['spec']['deploymentId']=other
        self.f.put(self.f.root/'.rag_index/windows-vm-deploy-intents'/(other+'.intent.json'),value)
        disk='qemu:'+str((visual_target.ROOT/LOCAL['qemu_disk']).resolve())
        with self.merged_capture() as driver,self.child_streams() as runs:
            for target in ('libvirt:'+LOCAL['libvirt_name'],disk,'native:windows','deployment:'+other):
                with self.subTest(target=target),self.assertRaisesRegex(visual_platform.VisualPlatformError,'exit code 1'):
                    visual_platform.run_local_driver('windows',driver,self.f.output,['windows-uac'],target=target)
                self.assertIn(b'deployment target mismatch',runs[-1].stderr);self.no_output()
            # Selection reads only the last path component; the driver holds every ancestor.
            intents=self.f.intent_path.parent;moved=intents.with_name('moved-intents');intents.rename(moved);intents.symlink_to(moved)
            with self.assertRaisesRegex(visual_platform.VisualPlatformError,'exit code 1'):
                visual_platform.run_local_driver('windows',driver,self.f.output,['windows-uac'],target=self.target())
            self.assertIn(b'collection refused',runs[-1].stderr);self.no_output()
        fields=['--deployment-id',self.f.deployment,'--operation-id',self.f.operation,'--journal-id',self.f.journal,'--platform','windows','--manifest',str(self.f.manifest),'--scenes',str(self.f.scenes),'--output',str(self.f.output)]
        with self.assertRaises(SystemExit)as missing,contextlib.redirect_stderr(io.StringIO()):subject.main(fields)
        self.assertEqual(2,missing.exception.code);self.no_output()

    def test_every_local_selection_equals_the_preserved_selector(self):
        before=before_selector();disk=str((visual_target.ROOT/LOCAL['qemu_disk']).resolve())
        def outcome(select,*values):
            try:return select(*values)
            except ValueError as error:return type(error).__name__,str(error)
        android={'avd_name':'owned-avd'};tart={'vm_name':'owned-vm'}
        accepted=(('android',android,'android:owned-avd'),('linux',tart,'tart:owned-vm'),('macos',tart,'tart:owned-vm'),('windows',LOCAL,'libvirt:'+LOCAL['libvirt_name']),('windows',LOCAL,'qemu:'+disk),('windows',LOCAL,'native:windows'),('linux',tart,'native:linux'),('macos',tart,'native:macos'))
        refused=(('android',android,'android:foreign'),('windows',LOCAL,'tart:owned-vm'),('windows',LOCAL,'libvirt:foreign'),('windows',LOCAL,'qemu:/foreign.qcow2'),('windows',LOCAL,'native:linux'),('linux',tart,'tart:foreign'),('linux',tart,'libvirt:'+LOCAL['libvirt_name']),('windows',LOCAL,None),('windows',LOCAL,''),('windows',LOCAL,'windows'),('windows',LOCAL,'unknown:windows'),('windows',LOCAL,'native:windows\n'))
        for platform,config,target in (*accepted,*refused):
            with self.subTest(platform=platform,target=target):
                self.assertEqual(outcome(before.select,platform,target,config),outcome(visual_target.select_capture,platform,target,config,self.f.root))
                self.assertEqual(outcome(before.select,platform,target,config),outcome(visual_target.select,platform,target,config))
        for platform,config,target in accepted:
            with self.subTest(platform=platform,target=target):self.assertEqual(tuple,type(before.select(platform,target,config)))
        for platform,config,target in refused:
            with self.subTest(platform=platform,target=target),self.assertRaises(before.TargetError):before.select(platform,target,config)


if __name__=='__main__':unittest.main()
