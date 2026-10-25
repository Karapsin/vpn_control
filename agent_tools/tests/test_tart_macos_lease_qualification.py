"""Pure proof consistency on held private files; no native authority is mocked."""
import base64
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import uuid4

from agent_tools import readiness_tart_macos_lease_qualification as q
from agent_tools import readiness_tart_macos_lease_bridge as bridge
from agent_tools.tests.test_readiness_tart_macos import binding


@unittest.skipUnless(os.name=='posix','private held artifact consistency checks')
class NativeQualificationParserTests(unittest.TestCase):
    def test_oversized_or_malformed_proof_declines_before_reading_public_source(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary);root.chmod(0o700)
            lifecycle=root/'.runtime/lifecycle';lifecycle.mkdir(mode=0o700,parents=True)
            path=lifecycle/'lease-native-qualification.json';path.write_text('{}');path.chmod(0o600)
            custody=SimpleNamespace(lifecycle_root=lifecycle)
            for size in (262145,-1,True):
                pin={'generation':[1,2,3,4,5,6,size,8,9],'sha256':'a'*64}
                with self.subTest(size=size),patch.object(q.mac,'PublicProof',side_effect=AssertionError('no source read')):
                    with self.assertRaises(q.mac.MacBlocked):q._load(custody,{'path':str(path),'pin':pin})

    def fixture(self,root):
        lifecycle=root/'.runtime/lifecycle';lifecycle.mkdir(mode=0o700,parents=True)
        directory=lifecycle/('native-iopm-v2-qualification-'+str(uuid4()));directory.mkdir(mode=0o700)
        def write(path,value):
            raw=value if type(value)is bytes else json.dumps(value,sort_keys=True,separators=(',',':')).encode()
            path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
            return {'path':str(path),'pin':{'generation':list(q.mac.private._generation(path.stat())),'sha256':hashlib.sha256(raw).hexdigest()}}
        actual=binding();b=q.leases.MacLeaseBinding(actual.target,actual.machine,str(uuid4()).upper(),'501','toolrecovery','/Users/toolrecovery','101')
        initial=json.loads(bridge.capsule(b));sources={name:hashlib.sha256(base64.b64decode(body)).hexdigest()for name,body in initial['files'].items()}
        namespace={'schemaVersion':1,'root':bridge.ROOT,'target':b.target,'machine':b.machine,'account':b.account,'sources':sources,
                   'rootGeneration':[1,2],'jobGeneration':[1,3],'admissionGeneration':[1,4]}
        raw=bridge.capsule(b,namespace);cap=json.loads(raw);digest=hashlib.sha256(raw).hexdigest();run=str(uuid4())
        producer=b"print('controlled proof-reader fixture')\n";producer_ref=write(directory/'producer.py',producer)
        producer_sha=hashlib.sha256(producer).hexdigest();cases={}
        for kind,ttl in (('expiry',3),('cancel',90),('client-death',15)):
            folder=directory/kind;op=str(uuid4());generation=str(uuid4());job_binding=asdict(b.job_binding());owner={'pid':100,'birth':'darwin:100:1'}
            lease_owner={'pid':101,'birth':'darwin:100:2'};program=q._program_digest(cap,b,namespace,op,ttl)
            state='cancelled'if kind=='cancel'else'expired';stdout=json.dumps({'state':state,'restored':True}).encode()
            streams={name:{'overflow':False,'retainedBytes':len(body),'totalBytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
                     for name,body in [('stdout',stdout),('stderr',b'')]}
            acquired={'operationId':op,'backend':'native','binding':job_binding,'generation':generation,'leaseOwner':lease_owner,
                      'programSha256':program,'session':b.session,'ttlSeconds':ttl,'assertions':[1,2]}
            terminal={**acquired,'state':state,'restored':True}
            receipt={'operationId':op,'binding':job_binding,'generation':generation,'programSha256':program,'exitCode':0,
                     'streamsClosed':True,'owner':owner,**streams}
            status={'operationId':op,'binding':job_binding,'owner':owner,'state':'terminal','replayAllowed':False,'terminal':receipt}
            evidence={'acquired':acquired,'leaseTerminal':terminal,'terminalStatus':status,'actualOwnerPresent':False,
                      'nativeOwnerAbsent':True,'stdout':base64.b64encode(stdout).decode(),'stderr':''}
            final={'operationId':op,'status':{'operationId':op,'state':state,'restored':True},'originalEvidence':evidence}
            active={'acquired':acquired,'actualOwnerPresent':True,'nativeActiveProof':{'active':True,'assertions':[1,2],
                     'nativeInventoryComplete':True,'owner':lease_owner},'status':{'state':'running'}}
            requests=[]
            for action in (('acquire','cancel')if kind=='cancel'else('acquire',)):
                source=q._expected_request(cap,b,namespace,action,op,ttl);reply=json.dumps({'operationId':op,'replayAllowed':False}).encode()
                requests.append({'source':write(folder/(action+'.py'),source),
                    'intent':write(folder/(action+'-intent.json'),{'operationId':op,'originalRun':run,'action':action,'sourceSha256':hashlib.sha256(source).hexdigest()}),
                    'result':write(folder/(action+'-result.json'),{'operationId':op,'action':action,'returncode':0,'stdoutBytes':len(reply),'stderrBytes':0}),
                    'stdout':write(folder/(action+'-stdout.json'),reply),'stderr':write(folder/(action+'-stderr.txt'),b'')})
            cases[kind]={'producer':producer_ref,'admission':write(folder/'admission.json',{'operationId':op,'ttlSeconds':ttl,'binding':asdict(b),'namespace':namespace,'capsuleSha256':digest}),
                         'capsule':write(folder/'capsule.json',raw),'evidence':write(folder/'evidence.json',final),'requests':requests,
                         'active':write(folder/'active.json',active)if kind!='expiry'else None,
                         'client':write(folder/'client.json',{'sameOriginalOperationId':op,'originalControllerAbsent':True,
                             'originalController':{'exitCode':77},'nativeEvidence':{'acquired':acquired}})if kind=='client-death'else None}
        manifest={'schemaVersion':1,'originalRunOperationId':run,'cases':cases};reference=write(lifecycle/'lease-native-qualification.json',manifest)
        custody=SimpleNamespace(root=root,lifecycle_root=lifecycle,run_intent={'operationId':run},binding=actual,load_lease_namespace=lambda version:namespace)
        return custody,reference,manifest,write,producer_sha,sources,hashlib.sha256(base64.b64decode(cap['bridge'])).hexdigest()

    def test_actual_held_proof_consistency_and_wrong_identity_stream_or_missing_case_refuse(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())as temporary:
            root=Path(temporary);root.chmod(0o700)
            custody,reference,manifest,write,producer,sources,bridge_sha=self.fixture(root)
            # Synthetic producer constants are local to this pure parser test;
            # public load still rejects the fixture's non-custody object.
            with patch.dict(q._PRODUCERS,{name:producer for name in q._PRODUCERS}),patch.object(q,'_GUEST_SOURCES',sources),patch.object(q,'_BRIDGE',bridge_sha):
                result=q._load(custody,reference)
                self.assertEqual(result.namespace,custody.load_lease_namespace('v2'))
                with self.assertRaises(q.mac.MacBlocked):q.load(custody,reference)
                with self.assertRaises(q.mac.MacBlocked):q.QualifiedProducer()
                original_evidence=json.loads(Path(manifest['cases']['expiry']['evidence']['path']).read_bytes())
                for corruption in ('operation','stream','missing_case'):
                    bad=json.loads(json.dumps(manifest))
                    if corruption=='missing_case':bad['cases'].pop('expiry')
                    else:
                        case=bad['cases']['expiry'];value=json.loads(json.dumps(original_evidence))
                        if corruption=='operation':value['originalEvidence']['acquired']['operationId']=str(uuid4())
                        else:value['originalEvidence']['terminalStatus']['terminal']['stdout']['sha256']='a'*64
                        case['evidence']=write(Path(case['evidence']['path']),value)
                    bad_ref=write(Path(reference['path']),bad)
                    with self.subTest(corruption=corruption),self.assertRaises(q.mac.MacBlocked):q._load(custody,bad_ref)


if __name__=='__main__':unittest.main()
