"""Portable fixed recipe checks. No SSH, Xlib, signals or native product action."""
import contextlib, copy, hashlib, importlib.util, io, json, os, tempfile, tarfile, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from agent_tools import native_owner_gui_lifecycle_ssh as gui
from agent_tools import native_scenario_bundle as bundles, native_scenario_batch as batches
from agent_tools import native_fixture_preflight as preflight, native_scenario_execution as execution
from agent_tools import native_scenario_ssh as ssh
ROOT=Path(__file__).resolve().parents[2]
SOURCE=(ROOT/'scripts/integration/linux_owner_lifecycle_scenario.py').read_bytes()
SOCKS=(ROOT/'scripts/integration/socks_http_fixture.py').read_bytes()
ns=gui._source_namespace(SOURCE,SOCKS)
CID='12345678-1234-4321-8123-123456789abc'
A='sha256-'+'a'*64;B='sha256-'+'b'*64

def valid_input():
    return {'schema':ns['SCHEMA'],'schemaVersion':1,'scenarioId':gui.SCENARIO_ID,'correlationId':CID,
        'sourceIdentity':{'sourceSha':'c'*40,'sourceFingerprint':'d'*64,'artifactSetId':'artifact-set-'+'e'*64},
        'installedPackage':{'artifactId':A,'version':'2.2.8-1','sha256':'a'*64,'desktopMainJarSha256':'f'*64},
        'guestAdmissionArtifactId':A,'displayAdmissionArtifactId':A,'fixtureAdmissionArtifactId':A,
        'protectedOwnerArtifactId':A,'maxObservationSeconds':180}

def plan():
    return {'scenarioId':gui.SCENARIO_ID,'host':'linux-owned','environment':'gui-owned','bundleHash':'a'*64,
        'artifactIds':{'bundleManifest':A,'scenarioInput':B},'correlationId':CID}

class FixedRecipeTest(unittest.TestCase):
    def test_typed_input_accepts_exact_fixed_population(self):
        value=valid_input();self.assertEqual(ns['validate_input'](value,CID),value)
    def test_typed_input_rejects_boolean_or_extended_schema(self):
        for key,value in (('schemaVersion',True),('maxObservationSeconds',True),('maxObservationSeconds',181),('command','true')):
            item=valid_input();item[key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ns['ScenarioError']):ns['validate_input'](item,CID)
    def test_typed_input_rejects_correlation_and_package_hash_substitution(self):
        for update in ('correlation','package','source'):
            item=valid_input()
            if update=='correlation':item['correlationId']='12345678-1234-4321-8123-123456789ABD'
            elif update=='package':item['installedPackage']['artifactId']=B
            else:item['sourceIdentity']['sourceSha']='d32'
            with self.subTest(update=update),self.assertRaises(ns['ScenarioError']):ns['validate_input'](item,CID)
    def test_duplicate_keys_are_rejected_in_real_parser(self):
        with self.assertRaisesRegex(ns['ScenarioError'],'duplicate_json_key'):json.loads('{"schemaVersion":1,"schemaVersion":1}',object_pairs_hook=ns['pairs'])
    def test_recipe_uses_only_existing_fixed_actions(self):
        p={'batchId':'owned-gui','recipe':gui.SCENARIO_ID,'host':'linux-owned','environment':'gui-owned',
            'bundleManifestArtifactId':A,'scenarioInputArtifactId':B,'scenarioCorrelationId':CID}
        normalized=batches._plan(p);nodes=batches._nodes(normalized)
        self.assertEqual(set(nodes),{'artifact','scenarioInput','fixture','start','status','collect'})
        self.assertEqual(nodes['start']['inputs'],plan())
        self.assertEqual(nodes['start']['action'],'scenario-start');self.assertEqual(nodes['status']['action'],'scenario-status')
        self.assertEqual(nodes['collect']['action'],'scenario-collect');self.assertEqual(nodes['fixture']['inputs']['scenarioId'],gui.SCENARIO_ID)
        with self.assertRaises(batches.NativeScenarioBatchError):batches._plan({**p,'command':'true'})
    def test_existing_scheduled_recipe_is_preserved(self):
        p={'batchId':'owned-refresh','recipe':'linux-scheduled-refresh','host':'linux-owned','environment':'gui-owned',
            'bundleManifestArtifactId':A,'scenarioInputArtifactId':B,'scenarioCorrelationId':CID}
        nodes=batches._nodes(batches._plan(p));self.assertEqual(nodes['start']['inputs']['scenarioId'],'linux-scheduled-refresh')
        self.assertEqual(len(bundles._SCENARIOS['linux-scheduled-refresh-driver']),4)
        self.assertEqual(len(bundles._SCENARIOS['linux-public-update-driver']),8)
    def test_bundle_imports_exact_driver_without_native_activity(self):
        with tempfile.TemporaryDirectory() as t:
            r=bundles.prepare_bundle(ROOT,gui.BUNDLE_SCENARIO_ID,Path(t)/'frozen')
            self.assertEqual([x['path'] for x in r['files']],list(gui._FILES))
            checked=bundles.verify_bundle(ROOT,r['directory'],r['manifestSha256']);self.assertEqual(checked['scenarioId'],gui.BUNDLE_SCENARIO_ID)
    def test_fixture_preflight_routes_only_new_fixed_scenario(self):
        request={'scenarioId':gui.SCENARIO_ID,'host':'linux-owned','environment':'gui-owned',
            'bundleManifestArtifactId':A,'scenarioInputArtifactId':B,'scenarioCorrelationId':CID}
        with patch.object(gui,'fixture_preflight',return_value={'ready':False}) as fixed:
            self.assertFalse(preflight.check(ROOT,request,lambda *args: self.fail('unexpected dispatch'))['ready'])
            fixed.assert_called_once()
    def test_unverified_remote_preparation_is_not_admission(self):
        with patch.object(gui.registry,'verify_artifact_readonly',return_value={'verification':'unverified-remote'}):
            with self.assertRaisesRegex(gui.NativeOwnerGuiLifecycleSshError,'registered_local_bytes_required'):
                gui._held_registered(ROOT,A,1024,SimpleNamespace(read=lambda *a,**kw:self.fail('remote path read')))
    def test_actual_guest_probe_denies_stale_boot_before_xlib_or_actors(self):
        guest={'schema':'vpn-control.linux-owner-gui.guest','schemaVersion':1,'host':'linux-owned','environment':'gui-owned',
            'bootId':'stale','uid':1000,'allocation':{},'ownedRoot':'/owned'}
        class Boot:
            def __init__(self,*a):pass
            def read_text(self):return 'fresh'
        with patch.dict(ns,{'sys':SimpleNamespace(platform='linux'),'os':SimpleNamespace(getuid=lambda:1000),'Path':Boot}):
            with self.assertRaisesRegex(ns['ScenarioError'],'guest_generation'):
                ns['admission_probe'](valid_input(),{'guest':guest,'display':{},'fixture':{},'protected':{},'source':{}})
    def test_actual_qemu_probe_rejects_changed_host_boot_without_effects(self):
        # Execute the fixed observer against an explicit read seam; no /proc read.
        class Exit(BaseException):pass
        output=[]
        fake_sys=SimpleNamespace(stdin=SimpleNamespace(buffer=io.BytesIO(json.dumps({'allocation':{'hostBootId':'old'}}).encode())))
        with patch.dict('sys.modules',{'sys':fake_sys}),patch('builtins.open',return_value=io.StringIO('new')),patch('builtins.print',side_effect=lambda x:output.append(json.loads(x))):
            with self.assertRaises(SystemExit):exec(gui._HOST_ALLOCATION_PROBE,{})
        self.assertEqual(output,[{'ready':False}])
    def test_delegate_dispatch_cannot_fall_through_to_import_recipe(self):
        driver=ssh.NativeScenarioSshDriver(ROOT,lambda p:self.fail('bundle resolver'),input_resolver=lambda p:self.fail('input resolver'))
        p=execution.ScenarioPlan.from_mapping(plan());identity=execution.JobIdentity('owned',1,2,'/owned/receipt')
        with patch.object(gui.NativeOwnerGuiLifecycleSshDriver,'submit',return_value=identity) as fixed:
            self.assertEqual(driver.submit(p),identity);fixed.assert_called_once_with(p)
    def test_unknown_original_is_never_submitted_by_resume_or_duplicate(self):
        class Driver:
            calls=0
            def submit(self,p):self.calls+=1;raise TimeoutError()
            def discover(self,p):return None
            def observe(self,p,i):raise AssertionError('no identity')
        driver=Driver();executor=execution.ScenarioExecutor('/source-only-journal',driver)
        records={}
        def create(record):
            records[CID]=copy.deepcopy(record);return True
        with patch.object(executor,'_require_private_journal_platform'),patch.object(executor,'_journal_lock',return_value=contextlib.nullcontext()), \
                patch.object(executor,'_read',side_effect=lambda correlation:copy.deepcopy(records.get(correlation))), \
                patch.object(executor,'_write',side_effect=lambda record:records.update({CID:copy.deepcopy(record)})), \
                patch.object(executor,'_create_intent',side_effect=create):
            executor.start(plan());executor.resume(CID);executor.start(plan());executor.collect(CID)
        self.assertEqual(driver.calls,1)
    def test_fixed_receiver_rejects_extra_inventory_before_job_creation(self):
        source=gui._receiver();fake_sys=SimpleNamespace(argv=['receiver','/unused','linux-owned','gui-owned',gui.SCENARIO_ID,CID,'a'*64,json.dumps({'bundleManifest':A,'scenarioInput':B})],
            stdin=SimpleNamespace(buffer=io.BytesIO(b'{"files":[{"path":"arbitrary.py"}]}\n')))
        outputs=[]
        with patch.dict('sys.modules',{'sys':fake_sys}),patch('builtins.print',side_effect=lambda x:outputs.append(json.loads(x))),patch('os.mkdir',side_effect=lambda *a,**k:self.fail('mutation before inventory admission')):
            with self.assertRaises(SystemExit):exec(source,{})
        self.assertEqual(outputs[0]['reason'],'unexpected_inventory')
    def test_fixed_package_inventory_uses_actual_pinned_bytes(self):
        with tempfile.TemporaryDirectory() as t:
            data=io.BytesIO()
            with tarfile.open(fileobj=data,mode='w:xz') as tar:
                body=b'actual frozen launcher';member=tarfile.TarInfo('./opt/vpn-control/bin/vpn-control');member.size=len(body);tar.addfile(member,io.BytesIO(body))
            content=data.getvalue();header=(b'data.tar.xz/    '+b'0'.ljust(12)+b'0'.ljust(6)+b'0'.ljust(6)+b'100600'.ljust(8)+str(len(content)).encode().ljust(10)+b'`\n')
            self.assertEqual(len(header),60)
            raw=b'!<arch>\n'+header+content+(b'\n' if len(content)%2 else b'');p=Path(t)/'owned.deb';p.write_bytes(raw)
            with patch.object(gui.os,'getuid',return_value=p.stat().st_uid,create=True):
                self.assertEqual(gui._package_inventory(str(p),hashlib.sha256(raw).hexdigest(),None),[{'path':'/opt/vpn-control/bin/vpn-control','sha256':hashlib.sha256(body).hexdigest()}])
                with self.assertRaisesRegex(gui.NativeOwnerGuiLifecycleSshError,'package_bytes'):gui._package_inventory(str(p),'f'*64,None)

if __name__=='__main__':unittest.main()

class PreparationProducerTest(unittest.TestCase):
    def preparation(self):
        spec=valid_input();actor={'pid':701,'startTicks':901,'uid':1000}
        return {'schema':'vpn-control.linux-owner-gui-lifecycle.preparation','schemaVersion':1,
            'host':'linux-owned','environment':'gui-owned','correlationId':CID,
            'sourceIdentity':spec['sourceIdentity'],'installedPackage':spec['installedPackage'],
            'guest':{'bootId':CID,'uid':1000,'allocation':{},'ownedRoot':'/owned'},
            'display':{'display':':202','xauthorityPath':'/owned/auth','xserver':actor,'wm':actor,'tray':actor},
            'fixture':{'certificatePath':'/owned/cert','keyPath':'/owned/key','trustStorePath':'/owned/trust','socksPort':35663,'httpsPort':35779},
            'protected':{'stateDir':'/protected','owner':actor,'controllerId':CID}}
    def test_registered_preparation_population_excludes_authored_readiness(self):
        selected=self.preparation();self.assertEqual(ns['validate_preparation'](selected),selected)
        selected['ready']=True
        with self.assertRaisesRegex(ns['ScenarioError'],'preparation_keys'):ns['validate_preparation'](selected)
    def test_preparation_existing_surface_dispatch_has_no_mutation_node(self):
        request={'scenarioId':gui.PREPARATION_SCENARIO,'host':'linux-owned','environment':'gui-owned','bundleManifestArtifactId':A,'preparationInputArtifactId':B}
        with patch.object(gui,'preparation_preflight',return_value={'ready':False,'nativeActionAllowed':False}) as observed:
            value=preflight.check(ROOT,request,lambda *args:self.fail('unexpected mutation dispatch'))
        observed.assert_called_once();self.assertFalse(value['nativeActionAllowed'])
        with self.assertRaises(preflight.NativeFixturePreflightError):preflight._request({**request,'command':'true'})
    def test_preparation_observer_emits_observed_versions_and_runtime(self):
        selected=self.preparation();commands=[];checks=[]
        runtime={'runtimeId':CID,'runtimeRunning':True,'configuredMode':'proxy-only','activeMode':'proxy-only','activeLocationId':'actual-location','selectedLocationId':'actual-location'}
        class FakePath:
            def __init__(self,value):self.value=str(value)
            def __truediv__(self,leaf):return FakePath(self.value+'/'+str(leaf))
            def lstat(self):return SimpleNamespace(st_mode=0o100600,st_uid=1000,st_nlink=1)
            def read_text(self):return CID
            def read_bytes(self):return b'/usr/bin/Xvfb\0:202\0-auth\0/owned/auth\0'
        def run(argv,**kwargs):
            commands.append(argv)
            if argv[:2]==['dpkg-query','-S']:return SimpleNamespace(returncode=0,stdout=('actual-package: '+argv[2]+'\n').encode(),stderr=b'')
            if argv[:2]==['dpkg-query','-W']:return SimpleNamespace(returncode=0,stdout=b'actual-version-42',stderr=b'')
            return SimpleNamespace(returncode=0,stdout=json.dumps({'code':'OK','final':True,'controllerId':CID,'data':runtime}).encode(),stderr=b'')
        fake_os=SimpleNamespace(getuid=lambda:1000,environ={},open=lambda *a:17,read=lambda *a:b'DISPLAY=:202\0',close=lambda *a:None,O_RDONLY=0,O_NOFOLLOW=0)
        with patch.dict(ns,{'sys':SimpleNamespace(platform='linux'),'os':fake_os,'Path':FakePath,
            'absolute':lambda value:FakePath(value),'private_directory':lambda value:FakePath(value),
            'process_matches':lambda *a,**k:checks.append(a),'generation':lambda value:(1,2,0o100600,1000,1,1,10,20,30),
            'regular':lambda path,cap,*a:b'actual-file-bytes','worker_source':lambda:(SOCKS,hashlib.sha256(SOCKS).hexdigest()),
            'subprocess':SimpleNamespace(run=run),'admission_probe':lambda spec,admissions:checks.append(admissions),
            'protected_status':lambda protected:checks.append(protected)}):
            actual=ns['observe_preparation'](selected,{'packageSourceSha':'c'*40})
        self.assertEqual(actual['state'],'observed');self.assertFalse(actual['nativeActionAllowed']);self.assertFalse(actual['productAcceptance'])
        self.assertEqual(actual['admissions']['display']['dependencies']['Xvfb']['version'],'actual-version-42')
        self.assertEqual(actual['admissions']['protected']['runtime'],runtime)
        self.assertEqual(actual['admissions']['display']['xauthorityGeneration'],[1,2,0o100600,1000,1,1,10,20,30])
        self.assertEqual(len(commands),19)
        self.assertTrue(all(command[0]=='dpkg-query' or command[-1]=='status' for command in commands))
    def test_preparation_unknown_remote_bytes_do_not_register(self):
        request={'scenarioId':gui.PREPARATION_SCENARIO,'host':'linux-owned','environment':'gui-owned','bundleManifestArtifactId':A,'preparationInputArtifactId':B}
        with patch.object(gui.registry,'verify_artifact_readonly',return_value={'verification':'unverified-remote'}),patch.object(gui.registry,'register_artifact',side_effect=AssertionError('registration before observations')):
            result=gui.preparation_preflight(ROOT,request)
        self.assertFalse(result['ready']);self.assertFalse(result['nativeActionAllowed'])
    def test_probe_program_authenticates_and_compiles_current_source_without_native_main(self):
        program=gui._probe_prefix(SOURCE,SOCKS)
        self.assertLess(len(program.encode()),32768)
        namespace={};exec(program,namespace)
        self.assertEqual(namespace['source'],SOURCE);self.assertEqual(namespace['socks'],SOCKS)
        self.assertEqual(namespace['ns']['SCENARIO'],gui.SCENARIO_ID)

class PackageSourceAdmissionTest(unittest.TestCase):
    def test_source_fingerprint_must_be_derived_from_genuine_frozen_proof(self):
        spec=valid_input();driver=gui.NativeOwnerGuiLifecycleSshDriver(ROOT,lambda p:None,lambda p:None)
        actual={'verification':'verified','artifact':{'platform':'linux','artifactKind':'existing-package-label','sha256':'a'*64,'sourceSha':'1'*40},'location':{'localPath':'/source-only-package'}}
        proof={'immutableArtifactIDs':[A],'productTreeSha256':'d'*64}
        with patch.object(gui.registry,'verify_artifact_readonly',return_value=actual),patch.object(gui.reuse,'acceptance_equivalence_check_readonly',return_value=proof) as genuine, \
                patch.object(gui,'_package_inventory',return_value=[{'path':'/opt/vpn-control/lib/app/desktopApp-actual.jar','sha256':'f'*64}]):
            admitted=driver._source_admission(spec,None)
            self.assertEqual(admitted['packageSourceSha'],'1'*40);self.assertEqual(admitted['targetSourceSha'],'c'*40)
            genuine.assert_called_once_with(ROOT,spec['sourceIdentity']['artifactSetId'],'1'*40,'c'*40)
            changed=copy.deepcopy(spec);changed['sourceIdentity']['sourceFingerprint']='2'*64
            with self.assertRaisesRegex(gui.NativeOwnerGuiLifecycleSshError,'derived_frozen_product_fingerprint'):driver._source_admission(changed,None)
    def test_package_image_preserves_only_contained_symlinks(self):
        with tempfile.TemporaryDirectory() as t:
            def archive(target):
                data=io.BytesIO()
                with tarfile.open(fileobj=data,mode='w:gz') as tar:
                    member=tarfile.TarInfo('./opt/vpn-control/lib/runtime/legal/java.logging/LICENSE');member.type=tarfile.SYMTYPE;member.linkname=target;tar.addfile(member)
                body=data.getvalue();header=(b'data.tar.gz/    '+b'0'.ljust(12)+b'0'.ljust(6)+b'0'.ljust(6)+b'100600'.ljust(8)+str(len(body)).encode().ljust(10)+b'`\n')
                self.assertEqual(len(header),60);return b'!<arch>\n'+header+body+(b'\n' if len(body)%2 else b'')
            p=Path(t)/'links.deb';raw=archive('../java.base/LICENSE');p.write_bytes(raw)
            with patch.object(gui.os,'getuid',return_value=p.stat().st_uid,create=True):
                result=gui._package_inventory(str(p),hashlib.sha256(raw).hexdigest(),None)
                self.assertEqual(result[0]['symlinkTarget'],'../java.base/LICENSE')
                raw=archive('../../../../../../home/foreign/key');p.write_bytes(raw)
                with self.assertRaisesRegex(gui.NativeOwnerGuiLifecycleSshError,'installed_image_symlink'):gui._package_inventory(str(p),hashlib.sha256(raw).hexdigest(),None)
