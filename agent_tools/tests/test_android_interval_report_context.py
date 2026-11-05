"""Real Context, Custody and frozen durable SourceSession; no native transport."""
from contextlib import redirect_stdout
from pathlib import Path
import ast
import copy
import hashlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
import uuid

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from agent_tools.tests import test_android_interval_reports as REPORTER
from agent_tools.tests import android_interval_fixture_support as SUPPORT
RESOURCES=SUPPORT.RESOURCES
REPORTS=[]


class ActualContextFixture:
    def __init__(self, testcase, *, before=False, drift=False, generation_drift=False, missing_prepared=False):
        self.testcase=testcase
        self.fs=REPORTER.OwnedFilesystem();testcase.addCleanup(self.fs.close)
        for attempt in range(3):self.fs.report(attempt)
        self.temp=tempfile.TemporaryDirectory(prefix='vc-ac-',dir=None);testcase.addCleanup(self.temp.cleanup)
        self.out=Path(self.temp.name).resolve();self.out.chmod(0o700)
        path=RESOURCES/('controller-d9ef.before.source'if before else'controller.fixed.source')
        raw=path.read_bytes()
        if before:assert hashlib.sha256(raw).hexdigest()=='d9ef282e23592746c2c768f68fb3e5b96a858838b35f822de20333fc6bcfe86c'
        self.seal={};self.ns={'__name__':'owned_actual_constructor','__CONTROLLER_SEAL__':self.seal}
        exec(compile(raw,str(path),'exec',dont_inherit=True),self.ns)
        self.ns['OUT']=self.out
        self.write(self.out/'controller.py',raw)
        self.write(self.out/'local-owner-program.py',b'DURABLE_OWNER=True\n'+raw)
        current=self.out/'current';snapshot=self.out/'snapshot'
        names=('agent_tools/source_module_loader.py','agent_tools/native_review_source_closure.py','agent_tools/durable_remote_job.py')
        rows=[]
        for name in names:
            body=(ROOT/name).read_bytes();a=current/name;b=snapshot/name
            self.write(a,body);self.write(b,body)
            rows.append({'path':str(a),'snapshotPath':str(b),'pin':self.pin(a)})
        self.current_source=Path(rows[0]['path'])
        self.manifest={'schema':1,'sources':rows}
        inputs={}
        descriptor={'credential':{'path':'/owned/credential-never-opened','generation':[1,2,33152,0,0,1,1,3,4]}}
        capsource=b'CURRENT_INTERVAL_STORAGE_REQUIRED=True\ndef installer_host_preflight():return {}\n'
        values={'credentialDescriptor':self.canonical(descriptor),'installerSource':capsource,
                'installerMetadata':self.canonical({'sourcePins':{'owned-inert-context': 'a'*64},'sha256':self.sha(capsource),'originalSourceSha256':'a'*64})}
        for name,body in values.items():
            a=current/('input-'+name+'.json');b=snapshot/('input-'+name+'.json')
            self.write(a,body);self.write(b,body)
            inputs[name]={'path':str(a),'pin':self.pin(a),'snapshotPath':str(b),'snapshotPin':self.pin(b),'private':True,'allowEmpty':False}
        root=self.out/'local-owner';root.mkdir(mode=0o700)
        self.local_id=str(uuid.uuid4());job=root/self.local_id;job.mkdir(mode=0o700)
        self.local_binding={'target':'owned-local','machine':'owned-machine','boot':'owned-boot','account':str(os.geteuid())}
        generation=str(uuid.uuid4());programsha='d'*64
        common={'operationId':self.local_id,'generation':generation,'binding':self.local_binding,'programSha256':programsha}
        self.write(job/'intent.json',self.canonical({'schemaVersion':1,**common,'purpose':'owned-frozen-observation','streamLimit':65536}))
        owner={'pid':12345,'birth':'owned-absent-original'}
        self.write(job/'owner.json',self.canonical({**common,'owner':owner}))
        self.stdout=b'{"state":"unknown","ownedOnly":true}\n';self.stderr=b''
        streams={name:{'overflow':False,'retainedBytes':len(body),'totalBytes':len(body),'sha256':self.sha(body)}for name,body in [('stdout',self.stdout),('stderr',self.stderr)]}
        self.write(job/'stdout.bin',self.stdout);self.write(job/'stderr.bin',self.stderr)
        self.write(job/'terminal.json',self.canonical({**common,'owner':owner,'exitCode':65,'streamsClosed':True,**streams}))
        info=root.stat()
        config={'operationId':self.fs.operation,'remoteRoot':self.fs.root,
                'binding':{'target':'owned-native','machine':self.fs.context['machineSha256'],'boot':self.fs.context['hostBootId'],'account':'0'},
                'localOperationId':self.local_id,'localBinding':self.local_binding,'localRootGeneration':[info.st_dev,info.st_ino],
                'inputFiles':inputs,'localAuthorityFiles':[],'explicitSourcePaths':[],
                'credentialPath':descriptor['credential']['path'],'lockAbsences':[]}
        self.write(self.out/'config.json',self.canonical(config));self.write(self.out/'source-manifest.json',self.canonical(self.manifest))
        self.seal.update(configPin=self.pin(self.out/'config.json'),configSha256=self.sha(self.canonical(config)),
                         sourceManifestPin=self.pin(self.out/'source-manifest.json'),sourceManifestSha256=self.sha(self.canonical(self.manifest)))
        self.preparation={'schema':1,'operationId':self.fs.operation,'rootGeneration':self.fs.context['rootGeneration'],
                          'rootIdentity':self.fs.context['rootGeneration']+[16832,0,0],'binding':config['binding'],
                          'controllerConfigSha256':self.seal['configSha256'],'durableSha256':self.sha((ROOT/'agent_tools/durable_remote_job.py').read_bytes()),
                          'receiverSha256':'c'*64}
        if not missing_prepared:self.write(self.out/'prepared.json',self.canonical(self.preparation))
        self.write(self.out/'programme-seal.json',self.canonical({'controllerSha256':self.sha(raw),
                    'ownerProgramSha256':self.sha(b'DURABLE_OWNER=True\n'+raw),'ownerProgramPin':self.pin(self.out/'local-owner-program.py')}))
        self.tool_events=[];self.rpc_events=[];self.sent_values=[]
        original_load=self.ns['load_source'];fixture=self

        class OwnedNetworkSourceSession:
            def __init__(self,directory,entry,*,expected_sources):
                assert entry=='ssh_transport';fixture.tool_events.append(('entry',entry));self.closed=False
                self.held=fixture.ns['Custody']()
                for path,expected in expected_sources.items():
                    body=self.held.add(path,private=True);assert fixture.sha(body)==expected
                self.module=types.SimpleNamespace(ownedTransportOnly=True)
            def load(self,name):
                fixture.tool_events.append(('load',name))
                return REPORTER.FIXED if name=='android_persisted_start'else types.SimpleNamespace(ownedOnly=True)
            def guard(self):self.held.guard()
            def close(self):self.closed=True;self.held.close()

        def load_source(path,expected,name):
            module,custody=original_load(path,expected,name)
            if name.startswith('persisted_start_collection_loader_'):
                module.SourceSession=OwnedNetworkSourceSession
            return module,custody
        self.ns['load_source']=load_source
        self.context=self.ns['Context'](observation_only=True)
        self.original_session=self.context.session;self.original_durable=self.context.durable
        assert not hasattr(self.context,'renderer')
        def deny_acquire(unused):raise AssertionError('fresh collection attempted acquire')
        self.context.inputs.acquire=deny_acquire
        def transaction(action,payload,prepared=None,**options):
            fixture.rpc_events.append(action);fixture.sent_values.append(fixture.context.sent)
            assert fixture.context.session is fixture.original_session
            assert fixture.context.durable is fixture.original_durable
            if action=='recover-prepare':
                recovered=copy.deepcopy(fixture.preparation)
                if generation_drift:recovered['rootGeneration'][1]+=1
                value={'state':'prepared-not-submitted','preparation':recovered}
                return value,fixture.canonical(value),fixture.out
            assert action=='admit','fresh client attempted prepare/submit/effect'
            body=__import__('base64').b64decode(payload['observerBase64'],validate=True)
            tree=ast.parse(body)
            request=next(ast.literal_eval(n.value)for n in tree.body if isinstance(n,ast.Assign)and
                         any(isinstance(x,ast.Name)and x.id=='INTERVAL_REPORT_REQUEST'for x in n.targets))
            value,body=fixture.fs.run(request)
            return value,body,fixture.out
        self.context.transaction=transaction
        if drift:self.current_source.write_bytes(self.current_source.read_bytes()+b'\n# owned mutable authority drift\n')
        self.ns['Context']=lambda**kwargs:self.context

    def sha(self,raw):return hashlib.sha256(raw).hexdigest()
    def canonical(self,value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'
    def write(self,path,raw):
        path.parent.mkdir(parents=True,mode=0o700,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
    def pin(self,path):
        c=self.ns['Custody']()
        try:c.add(path,private=True,allow_empty=not path.stat().st_size);return copy.deepcopy(c.files[str(path)]['pin'])
        finally:c.close()
    def main(self,action):
        stream=io.StringIO()
        with redirect_stdout(stream):self.ns['main']([action])
        return json.loads(stream.getvalue())


class ActualContextTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_authentic_constructor_fresh_collection_before_red_fixed_green(self):
        red=ActualContextFixture(self,before=True);red_result=red.main('local-collect')
        green=ActualContextFixture(self);green_result=green.main('local-collect')
        self.assertEqual(red_result['intervalReports']['state'],'original-interval-report-collection-unknown')
        self.assertEqual(red.rpc_events,[])
        self.assertEqual(green_result['intervalReports']['state'],'original-interval-reports-collected')
        self.assertEqual(green.rpc_events,['recover-prepare','admit','admit','admit'])
        self.assertEqual(green.tool_events,[('entry','ssh_transport'),('load','readiness'),('load','private_credential_file'),('load','android_persisted_start')])
        self.assertTrue(all(value is False for value in green.sent_values))
        self.assertFalse(green.context.sent)
        self.assertEqual(green_result['terminal']['exitCode'],65)
        self.assertEqual((Path(green_result['collectionDirectory'])/'stdout.raw').read_bytes(),green.stdout)
        REPORTS.append({'kind':'real-Context-fresh-collection-causal','before':'collection-unknown-no-tools',
                        'fixed':'three-original-reports-collected','actualFrozenDurableSession':True,
                        'nativeRpcSeamOwned':True,'sentUnchanged':True,'prepareSubmitAcquireCalls':0})

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_mutable_source_drift_refuses_collection_but_frozen_collect_survives(self):
        fixture=ActualContextFixture(self,drift=True);result=fixture.main('local-collect')
        self.assertEqual(result['state'],'terminal')
        self.assertEqual(result['terminal']['exitCode'],65)
        self.assertEqual((Path(result['collectionDirectory'])/'stdout.raw').read_bytes(),fixture.stdout)
        self.assertEqual(result['intervalReports']['state'],'original-interval-report-collection-unknown')
        self.assertEqual(fixture.rpc_events,[])
        self.assertEqual(fixture.tool_events,[])
        self.assertFalse(fixture.context.sent)

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_mutable_source_drift_leaves_local_status_frozen_and_unbound(self):
        fixture=ActualContextFixture(self,drift=True);result=fixture.main('local-status')
        self.assertEqual(result['state'],'terminal')
        self.assertEqual(result['terminal']['exitCode'],65)
        self.assertEqual(fixture.tool_events,[])
        self.assertFalse(hasattr(fixture.context,'renderer'))

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_recovered_same_operation_new_generation_cannot_replace_original(self):
        fixture=ActualContextFixture(self,generation_drift=True);result=fixture.main('local-collect')
        self.assertEqual(result['state'],'terminal')
        self.assertEqual(result['terminal']['exitCode'],65)
        self.assertEqual(result['intervalReports']['state'],'original-interval-report-collection-unknown')
        self.assertEqual(result['intervalReports']['reason'],'controller_interval_original_preparation_changed')
        self.assertEqual(fixture.rpc_events,['recover-prepare'])
        self.assertFalse(fixture.context.sent)

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_missing_original_preparation_refuses_without_remote_fallback(self):
        fixture=ActualContextFixture(self,missing_prepared=True);result=fixture.main('local-collect')
        self.assertEqual(result['state'],'terminal')
        self.assertEqual(result['intervalReports']['state'],'original-interval-report-collection-unknown')
        self.assertEqual(fixture.rpc_events,[])
        self.assertFalse(fixture.context.sent)

    @unittest.skipUnless(os.name == 'posix', 'requires owned POSIX filesystem/controller/Linux emission')
    def test_authentic_old_collector_queries_changed_generation_fixed_refuses_before_query(self):
        fixture=ActualContextFixture(self,generation_drift=True)
        self.addCleanup(fixture.context.close)
        # Close only the unrelated old constructor defect using the actual
        # new guarded binder. The collector below is verbatim from whole d9ef.
        fixture.context.bind_interval_collection()
        raw=(RESOURCES/'controller-d9ef.before.source').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'d9ef282e23592746c2c768f68fb3e5b96a858838b35f822de20333fc6bcfe86c')
        legacy={'__name__':'owned_authentic_generation_collector','__CONTROLLER_SEAL__':fixture.seal}
        exec(compile(raw,'<whole-authentic-d9ef-before>','exec',dont_inherit=True),legacy)
        legacy['OUT']=fixture.out
        legacy['collect_interval_reports'](fixture.context,None,'fresh-client')
        self.assertEqual(fixture.rpc_events[:2],['recover-prepare','admit'])
        before=list(fixture.rpc_events);fixture.rpc_events.clear()
        result=fixture.ns['collect_interval_reports'](fixture.context,None,'fresh-client')
        self.assertEqual(result['reason'],'controller_interval_original_preparation_changed')
        self.assertEqual(fixture.rpc_events,['recover-prepare'])
        self.assertFalse(fixture.context.sent)
        REPORTS.append({'kind':'original-prepared-generation-causal','wholeBeforeSourceSha256':hashlib.sha256(raw).hexdigest(),
                        'beforeActions':before,'fixedActions':list(fixture.rpc_events),'fixedCatalogReads':0,
                        'constructorQualificationSeam':'actual new guarded binder, original durable session unchanged'})


if __name__=='__main__':unittest.main()
