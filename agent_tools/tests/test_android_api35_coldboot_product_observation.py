"""Generated API35 readonly getter checks; no device/transport/credential use."""
import ast
import hashlib
import uuid
import copy
import json
import os
from pathlib import Path
import re
import unittest
from unittest import mock
from agent_tools import android_api35_coldboot_product_observation as getter

ROOT=Path(__file__).resolve().parents[2]


def existing_prepared(root=ROOT,reservation=None):
    producer=Path(__file__).parent/'fixtures/android_existing_readonly/coldboot_producer.source'
    pin,raw=getter.availability._snapshot(producer.resolve())
    evidence={'path':str(producer.resolve()),'generation':list(pin),
              'sha256':hashlib.sha256(raw).hexdigest()}
    if not hasattr(getter,'prepare_existing_readonly'):
        return getter.prepare(root,reservation or CompositionTests().reservation())
    return getter.prepare_existing_readonly(root,reservation or CompositionTests().reservation(),
                                           str(uuid.uuid4()),evidence)


class GetterTests(unittest.TestCase):
    def scope(self):
        nodes=[n for n in ast.parse(getter._GETTER).body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef))]
        scope={'re':re,'json':json,'pathlib':__import__('pathlib')};exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-API35-getter>','exec'),scope)
        scope['GETTER']={'generation':copy.deepcopy(getter.FIXED_GENERATION),'packageSha256':getter.APK}
        scope['original_status']=lambda _:dict(state='guest-generation-admitted',guestAdmitted=True,**copy.deepcopy(scope['GETTER']['generation']))
        scope['getter_apk']=lambda:getter.APK
        scope['getter_cli']=lambda words,owner=None:{'returncode':0,'stdout':{'ok':True,'final':True,'code':'OK','controllerId':'new-api35-owner','configurationRevision':0,'data':{'runtimeRunning':False,'runtimeObservation':'stopped','operations':[],'routing':{}}}}
        return scope

    def test_actual_API35_admits_only_stable_current_generation_getters(self):
        scope=self.scope();result=scope['current_getter'](Path('/fixed'))
        self.assertIs(result['productAdmitted'],True);self.assertIs(result['acceptanceComplete'],False)
        self.assertEqual(getter.APK,result['observedPackageSha256']);self.assertIs(result['historicalUnknownsPreserved'],True)
        self.assertIn('routingAfter',result['records']);self.assertIn('operationsAfter',result['records'])

    def test_generation_old_lease_sid_and_executable_drift_before_cli(self):
        for section,field,value in [('guest','pid',999),('guest','sessionId',999),('guest','exeGeneration',[2]),('device','guestBootId','old-lease-boot'),('device','sdk','29'),('device','shellUid','0'),('child','startTicks',1)]:
            with self.subTest(section=section,field=field):
                scope=self.scope();changed=copy.deepcopy(scope['GETTER']['generation']);changed[section][field]=value
                scope['original_status']=lambda _:dict(state='guest-generation-admitted',guestAdmitted=True,**changed)
                scope['getter_cli']=lambda *args:(_ for _ in ()).throw(AssertionError('no public read before binding'))
                with self.assertRaisesRegex(ValueError,'getter_generation_changed'):scope['current_getter'](Path('/fixed'))

    def test_wrong_installed_apk_is_retained_without_cli_owner_adoption(self):
        scope=self.scope();scope['getter_apk']=lambda:'f'*64;scope['getter_cli']=mock.Mock(side_effect=AssertionError('wrong APK'))
        result=scope['current_getter'](Path('/fixed'));self.assertIs(result['productAdmitted'],False)
        self.assertEqual('installed_apk_differs',result['reason']);self.assertEqual('f'*64,result['observedPackageSha256'])
        scope['getter_cli'].assert_not_called();self.assertEqual(['observedPackageAfter','observedPackageBefore'],sorted(result['records']))

    def test_provider_absent_and_package_drift_remain_diagnostic(self):
        scope=self.scope();scope['getter_cli']=lambda *a:{'returncode':1,'stdout':{'ok':False,'final':True,'code':'NOT_RUNNING'},'stdoutRaw':'private exact reply'}
        result=scope['current_getter'](Path('/fixed'));self.assertIs(result['productAdmitted'],False);self.assertEqual('provider_unavailable',result['reason'])
        self.assertEqual(getter.APK,result['observedPackageSha256']);self.assertEqual('private exact reply',result['records']['statusBefore']['stdoutRaw'])
        self.assertEqual(2,len(result['generation']))

    def test_owner_revision_off_operation_and_routing_drift_refuse(self):
        for mutation in ('owner','revision','routing','operations','runtime'):
            scope=self.scope();original=scope['getter_cli'];count=[0]
            def invoke(words,owner=None):
                result=original(words,owner);count[0]+=1
                if count[0]==4:
                    if mutation=='owner':result['stdout']['controllerId']='foreign'
                    elif mutation=='revision':result['stdout']['configurationRevision']=1
                    elif mutation=='routing':result['stdout']['data']['routing']={'changed':True}
                    elif mutation=='operations':result['stdout']['data']['operations']=[{'final':False}]
                    elif mutation=='runtime':result['stdout']['data']['runtimeRunning']=True
                return result
            scope['getter_cli']=invoke
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):scope['current_getter'](Path('/fixed'))

    def test_before_after_stage_and_guest_generation_drift_never_promote(self):
        scope=self.scope();stage=iter([{'pin':1},{'pin':2}]);scope['getter_stage']=lambda:next(stage)
        result=scope['observed_getter'](Path('/fixed'));self.assertIs(result['productAdmitted'],False);self.assertEqual('getter_stage_generation_changed',result['reason'])
        scope=self.scope();scope['getter_stage']=lambda:{'pin':1};original=scope['original_status'];calls=[0]
        def status(path):
            result=original(path);calls[0]+=1
            if calls[0]==2:result['guest']['sessionId']=999
            return result
        scope['original_status']=status;result=scope['observed_getter'](Path('/fixed'))
        self.assertIs(result['productAdmitted'],False);self.assertEqual(getter.APK,result['observedPackageSha256'])

    def test_actual_cli_serial_controller_and_readonly_whitelist(self):
        scope=self.scope();scope['GETTER'].update(cli='/fixed/cli',manifest={'launcherSha256':'f'*64})
        scope['LAUNCH']={'adbPath':'/fixed/adb','environment':{}}
        scope['read_fixed']=lambda *a:{'raw':b'cli','hashScope':'full','sha256':'f'*64,'generation':[1]}
        scope['public_cli_environment']=lambda a,b,c:c;calls=[]
        scope['getter_binary']=lambda path,pin,args,environment,limit:calls.append(args)or{'returncode':0,'stdoutRaw':'{}'}
        node=next(n for n in ast.parse(getter._GETTER).body if isinstance(n,ast.FunctionDef)and n.name=='getter_cli');exec(compile(ast.Module(body=[node],type_ignores=[]),'<fixed-cli>','exec'),scope)
        scope['getter_cli'](['routing','show'],'current-owner');self.assertIn('emulator-5682',calls[0]);self.assertIn('current-owner',calls[0])
        for words in (['updates','check'],['quit'],['start'],['settings','set']):
            with self.assertRaises(ValueError):scope['getter_cli'](words)
        self.assertEqual(1,len(calls))

    def test_actual_apk_receipts_captured_before_parse_failure(self):
        scope=self.scope();scope['GETTER_RECORDS']={};scope['GETTER_APK_PASS']='Before'
        scope['LAUNCH']={'adbPath':'/fixed/adb','adbFacts':{'generation':[1]},'environment':{}}
        scope['getter_binary']=lambda *a,**k:{'returncode':0,'stdoutRaw':'not-package','stderrRaw':'exact diagnostic'}
        node=next(n for n in ast.parse(getter._GETTER).body if isinstance(n,ast.FunctionDef)and n.name=='getter_apk');exec(compile(ast.Module(body=[node],type_ignores=[]),'<real-apk-reader>','exec'),scope)
        with self.assertRaisesRegex(ValueError,'getter_package_path_unknown'):scope['getter_apk']()
        self.assertEqual('not-package',scope['GETTER_RECORDS']['packagePathBefore']['stdoutRaw'])
        self.assertEqual('exact diagnostic',scope['GETTER_RECORDS']['packagePathBefore']['stderrRaw'])

    def test_readonly_syntax_rejects_creation_and_launch(self):
        for body in ('os.mkdir("foreign")','os.open("foreign",os.O_CREAT)','journal_write("foreign")','os.kill(123,9)'):
            with self.subTest(body=body),self.assertRaises(ValueError):getter.validate_readonly(body+'\ncoldboot_dispatch()\n')

    @unittest.skipUnless(os.name=='posix','POSIX bounded pipe capture')
    def test_actual_bounded_child_timeout_retains_exact_partial_bytes(self):
        import base64,subprocess,sys,time
        scope=self.scope();scope.update(os=os,subprocess=subprocess,time=time,GETTER_RECORDS={})
        original=subprocess.Popen
        def launch(*args,**kwargs):
            return original([sys.executable,'-I','-c',"import sys,time;sys.stdout.buffer.write(b'partial\\xff');sys.stdout.flush();sys.stderr.write('retained diagnostic');sys.stderr.flush();time.sleep(3)"],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        with mock.patch.object(subprocess,'Popen',side_effect=launch),self.assertRaisesRegex(ValueError,'getter_command_timeout'):
            scope['getter_bounded'](['/fixed/approved'],1,{},timeout=.05,limit=1024)
        receipt=scope['GETTER_RECORDS']['lastBoundedCommand']
        self.assertEqual(b'partial\xff',base64.b64decode(receipt['stdoutBase64']))
        self.assertEqual(b'retained diagnostic',base64.b64decode(receipt['stderrBase64']))



class CompositionTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import install
        install(self,globals(),'getter')

    def reservation(self):
        return {'reservationId':'synthetic-api35','token':'synthetic-token','hostAlias':'archlinux',
                'environment':'owned-android-api35-coldboot','operator':'root-android'}

    def test_historical_full_factory_never_reads_checkout_private_context(self):
        from agent_tools.tests.fixtures.android_api35_historical_context import REPO
        original=getter.availability._snapshot
        opened=[]
        def read(path):
            path=Path(path).resolve();opened.append(path)
            if path.is_relative_to(REPO) and any(part in {'.rag_index','.runtime'} for part in path.relative_to(REPO).parts):
                raise AssertionError('real checkout private/native history is forbidden')
            return original(path)
        with mock.patch.object(getter.availability,'_snapshot',side_effect=read):
            value=self.history.prepare();getter.guard_prepared(value)
        self.assertTrue(opened)
        self.assertTrue(all(path.is_relative_to(self.history.root) for path in value['snapshots']))

    def test_actual_historical_intent_source_and_descriptor_drift_refuse(self):
        value=self.history.prepare();getter.guard_prepared(value)
        path=self.history.root/'.rag_index/android-avd-coldboot'/getter.CORRELATION/'launch.json'
        record=json.loads(path.read_bytes());record['intent']['source']['foreign']='f'*64
        path.write_text(json.dumps(record));path.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'coldboot_local_intent_changed'):
            self.history.prepare()
        with self.assertRaisesRegex(ValueError,'census_local_source_changed'):
            getter.guard_prepared(value)

    def test_actual_fixed_local_composition_has_no_effect_definitions(self):
        # Actual authenticated historical factories run over an explicitly
        # synthetic, owned ledger. These unit records are not native authority.
        self.assertTrue((ROOT/'.runtime/parity-evidence'/getter.STATUS).exists(),'owned historical fixture is incomplete')
        prepared=existing_prepared(ROOT,self.reservation());getter.validate_readonly(prepared['program'])
        self.assertIn("'sdk': '35'",prepared['program']);self.assertIn('emulator-5682',prepared['program'])
        self.assertNotIn('def write_capsule(',prepared['program']);self.assertNotIn('O_CREAT',prepared['program'])
        self.assertNotIn('def launch_once(',prepared['program']);self.assertNotIn('def admit_once(',prepared['program'])
        self.assertLess(len(getter.ssh_carrier(prepared)),131072)

    def test_actual_local_prepare_rejects_generation_apk_manifest_and_reservation_drift(self):
        self.assertTrue((ROOT/'.runtime/parity-evidence'/getter.STATUS).exists(),'owned historical fixture is incomplete')
        original=getter.availability._snapshot
        for kind in ('generation','apk','manifest'):
            def read(path):
                pin,raw=original(path);path=Path(path)
                chosen=(kind=='generation' and str(path).endswith(getter.STATUS)or kind=='apk'and str(path).endswith('d32-apk/receipt.json')or kind=='manifest'and str(path).endswith(getter.STAGE+'/intent.json'))
                if chosen:
                    value=json.loads(raw)
                    if kind=='generation':value['guest']['sessionId']=999
                    elif kind=='apk':value['sha256']='f'*64
                    else:value['manifestSha256']='f'*64
                    raw=json.dumps(value).encode()
                return pin,raw
            with self.subTest(kind=kind),mock.patch.object(getter.availability,'_snapshot',side_effect=read),self.assertRaises(ValueError):existing_prepared(ROOT,self.reservation())
        reservation=self.reservation();reservation['token']='foreign'
        with self.assertRaises(ValueError):existing_prepared(ROOT,reservation)


class CurrentDependencyTests(unittest.TestCase):
    def test_current_getter_is_not_silently_adopted_by_historical_consumers(self):
        from agent_tools import android_api35_coldboot_fd_observation as current_fd
        from agent_tools import android_api35_current_proxy_dex_observation as current_dex
        for consumer,code in ((current_fd,'fd_probe_consumed_source_changed'),(current_dex,'dex_original_source_changed')):
            with self.subTest(consumer=consumer.__name__),mock.patch.object(consumer.original,'prepare') as factory:
                with self.assertRaisesRegex(ValueError,code):
                    consumer.prepare(ROOT,CompositionTests().reservation())
                factory.assert_not_called()


if __name__=='__main__':unittest.main()
