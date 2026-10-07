"""Fast generated-source owner regressions. No SSH/ADB or compilation."""
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock
from agent_tools import android_proxy_os_fresh_owner as fresh
from agent_tools import android_proxy_os_observation as frozen
from agent_tools import android_installer_failed_check_retirement as old

OLD='8e9627aa-bbe3-44fe-b9a8-a3f8d3d95c9e'
NEW='d486ea37-d0bd-4e7f-896a-8c0e04c4ac0b'
OTHER='7c2eea10-0a24-4fbd-a7e3-6f2c15b81f12'


def envelopes(owner=NEW,rev=0):
    common={'ok':True,'final':True,'code':'OK','controllerId':owner,'configurationRevision':rev}
    return [{**common,'data':{'runtimeRunning':False,'runtimeObservation':'stopped'}},{**common,'data':{'operations':[]}}]

class FreshOwnerTest(unittest.TestCase):
    def generated_segment(self):
        source=fresh.remote_source();tree=ast.parse(source)
        checks=ast.literal_eval(tree.body[2].value)
        return checks[checks.index('def measure_owner'):checks.index("phase='installer-metadata-census'")]

    def scope(self,root,readbacks,mode='admit',admitted=None):
        failed=root/('android-failed-check-retirement-diagnostic-'+fresh.FAILED);failed.mkdir(mode=0o700)
        failure={'diagnosticCorrelationId':fresh.FAILED,'diagnosticSourceSha256':fresh.FROZEN_SOURCE_SHA,'currentFailurePhase':'metadata-owner-admission','originalOutcome':'unknown','serviceCapture':None,'exception':{'type':'ValueError','message':{'base64':base64.b64encode(b'metadata_owner_changed').decode()}}}
        old._save(failed/'receipt.json',failure)
        def snapshot(path,limit=1048576):
            raw,gen,digest=old.private_snapshot(path,limit);return raw,{'generation':gen,'sha256':digest}
        raw,pin=snapshot(failed/'receipt.json')
        queue=iter(copy.deepcopy(readbacks));diagnostic={'freshOwnerMode':mode,'diagnosticSourceSha256':hashlib.sha256(fresh.remote_source().encode()).hexdigest()}
        if admitted is not None:diagnostic['freshAdmission']=admitted
        return {'root':root,'owner':OLD,'revision':0,'binding':{'owner':OLD,'revision':0},'public_cli':lambda *args:next(queue),'snapshot_file':snapshot,
            'FRESH_FAILED_PIN':{**pin,'bytes':len(raw)},'FRESH_FROZEN_SOURCE_SHA':fresh.FROZEN_SOURCE_SHA,
            'diagnostic':diagnostic,'json':json,'re':re,'hashlib':hashlib,'base64':base64}

    def test_actual_stale_owner_guard_red_then_positive_admission_green(self):
        original=frozen.remote_source();checks=ast.literal_eval(ast.parse(original).body[2].value)
        historical=checks[checks.index("phase='metadata-owner-admission'"):checks.index("phase='installer-metadata-census'")]
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();root.chmod(0o700)
            queue=iter(envelopes()*2)
            with self.assertRaisesRegex(ValueError,'metadata_owner_changed'):
                exec(historical,{'owner':OLD,'revision':0,'public_cli':lambda *args:next(queue)})
            scope=self.scope(root,envelopes()*4)
            exec(self.generated_segment(),scope)
            self.assertEqual(NEW,scope['owner']);self.assertEqual(0,scope['revision'])
            self.assertEqual(2,scope['fresh_owner_admission']['snapshotCount'])
            self.assertEqual({'owner':OLD,'revision':0},scope['binding'])
            self.assertFalse(any(root.glob('android-proxy-os-stage-*')))

    def test_concurrent_owner_revision_and_state_drift_reject(self):
        for snapshots in (envelopes()+envelopes(OTHER),envelopes()+envelopes(NEW,1)):
            queue=iter(snapshots)
            with self.assertRaisesRegex(ValueError,'drift'):fresh.measure_owner(lambda *args:next(queue))
        for kind in ('conflict','nonfinal','notok','running','pending','boolrevision','pair-owner'):
            values=envelopes()*2
            if kind=='conflict':values[0]['code']='CONFLICT'
            if kind=='nonfinal':values[0]['final']=False
            if kind=='notok':values[0]['ok']=False
            if kind=='running':values[0]['data']['runtimeRunning']=True
            if kind=='pending':values[1]['data']['operations']=[{'final':False}]
            if kind=='boolrevision':values[0]['configurationRevision']=False
            if kind=='pair-owner':values[1]['controllerId']=OTHER
            queue=iter(copy.deepcopy(values))
            with self.assertRaises(ValueError,msg=kind):fresh.measure_owner(lambda *args:next(queue))

    def test_observe_requires_exact_admitted_receipt_and_owner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();root.chmod(0o700);corr='9e5b5d20-c158-48df-a2bf-b03c882d24a0'
            admitted_dir=root/('android-failed-check-retirement-diagnostic-'+corr);admitted_dir.mkdir(mode=0o700)
            queue=iter(envelopes()*2);proof=fresh.measure_owner(lambda *args:next(queue))
            old._save(admitted_dir/'receipt.json',{'diagnosticSourceSha256':hashlib.sha256(fresh.remote_source().encode()).hexdigest(),'exception':None,'currentFailurePhase':'fresh-owner-admitted','freshOwnerAdmission':proof,'originalOutcome':'unknown'})
            raw,gen,digest=old.private_snapshot(admitted_dir/'receipt.json')
            admitted={'correlationId':corr,'receiptPin':{'bytes':len(raw),'generation':gen,'sha256':digest}}
            scope=self.scope(root,envelopes()*4,mode='observe',admitted=admitted)
            exec(self.generated_segment(),scope);self.assertEqual(NEW,scope['owner'])
            # A later positive owner cannot replace the immutable admitted epoch.
            scope['public_cli']=lambda *args:next(changed)
            changed=iter(envelopes(OTHER)*4)
            with self.assertRaisesRegex(ValueError,'admission_drift'):exec(self.generated_segment(),scope)

    def test_consumed_sources_and_staging_procedure_unchanged(self):
        self.assertEqual(fresh.FROZEN_SHA,hashlib.sha256(Path(frozen.__file__).read_bytes()).hexdigest())
        self.assertEqual(fresh.FROZEN_SOURCE_SHA,hashlib.sha256(frozen.remote_source().encode()).hexdigest())
        self.assertEqual(frozen.JAVA_SHA,hashlib.sha256((Path(frozen.__file__).parent/'fixtures/android_proxy_os_probe/ProxyProbe.java').read_bytes()).hexdigest())
        generated=fresh.remote_source();compile(generated,'fresh-owner-remote','exec')
        old_checks=ast.literal_eval(ast.parse(frozen.remote_source()).body[2].value)
        checks=ast.literal_eval(ast.parse(generated).body[2].value)
        staging=old_checks[old_checks.index("phase='proxy-os-artifact-admission'"):]
        self.assertIn(staging,checks)
        for needle in ('setGlobalProxy','setHiddenApiExemptions','TRANSACTION_'):self.assertNotIn(needle,generated)

    def test_collector_distinguishes_positive_admission_from_getter_capture(self):
        import subprocess,sys
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();root.chmod(0o700);corr='9e5b5d20-c158-48df-a2bf-b03c882d24a0'
            directory=root/('android-failed-check-retirement-diagnostic-'+corr);directory.mkdir(mode=0o700)
            source_sha=hashlib.sha256(fresh.remote_source().encode()).hexdigest()
            old._save(directory/'receipt.json',{'diagnosticCorrelationId':corr,'admissionCorrelationId':frozen.ADMISSION,'originalCorrelationId':'0dd55704-1e80-4d62-8d9d-2f0a123e0c3b','originalOutcome':'unknown','diagnosticSourceSha256':source_sha,'currentFailurePhase':'fresh-owner-admitted','exception':None,'serviceCapture':None})
            run=subprocess.run([sys.executable,'-I','-B','-c',fresh.remote_collector_source(),str(root),corr,'status','0','null',source_sha],capture_output=True,timeout=5)
            self.assertEqual(0,run.returncode);value=json.loads(run.stdout)
            self.assertEqual('diagnosed-without-capture',value['state']);self.assertEqual('fresh-owner-admitted',value['phase'])

    def test_generated_drift_after_positive_admission_rejects_before_stage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();root.chmod(0o700)
            scope=self.scope(root,envelopes()*2+envelopes(OTHER)*2)
            with self.assertRaisesRegex(ValueError,'metadata_owner_changed'):exec(self.generated_segment(),scope)
            self.assertEqual(NEW,scope['fresh_owner_admission']['owner'])
            self.assertEqual({'owner':OLD,'revision':0},scope['binding'])
            self.assertFalse(any(root.glob('android-proxy-os-stage-*')))

    def retained_fixture(self, root):
        base=root/'.rag_index'/'android-proxy-os-observation'/fresh.FAILED
        base.mkdir(parents=True,mode=0o700)
        intent={'correlationId':fresh.FAILED,'remoteSourceSha256':fresh.FROZEN_SOURCE_SHA,'javaSha256':frozen.JAVA_SHA,'localPins':[],'artifactPath':str(base/'classes.dex')}
        old._save(base/'intent.json',intent)
        ip=frozen._private_pin(base/'intent.json');identity={k:ip[k] for k in ('generation','sha256')}
        old._save(base/'compiler.json',{'intentPin':identity,'correlationId':fresh.FAILED,'javaSha256':frozen.JAVA_SHA})
        fd=os.open(base/'classes.dex',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        os.write(fd,b'dex\n035\0'+b'x'*112);os.close(fd)
        def component(name):
            pin=frozen._private_pin(base/name)
            return {k:pin[k] for k in ('path','generation','sha256','bytes')}
        artifact={'correlationId':fresh.FAILED,'intentPin':identity,'javaSha256':frozen.JAVA_SHA,'primarySource':frozen.PRIMARY,'artifactPin':component('classes.dex'),'compilerReceiptPin':component('compiler.json')}
        old._save(base/'artifact.json',artifact)
        ap=frozen._private_pin(base/'artifact.json')
        request={'correlationId':fresh.FAILED,'intentPin':identity,'artifactPin':{k:ap[k] for k in ('generation','sha256')},'remoteSourceSha256':fresh.FROZEN_SOURCE_SHA,'originalOutcome':'unknown'}
        old._save(base/'observe-request.json',request)
        failure=root/'.runtime'/'parity-evidence'/'android-current'/'api35-proxy-probe-4f77-receipt.json'
        failure.parent.mkdir(parents=True,mode=0o700);old._save(failure,{'fixture':'retained exact failure'})
        fp=frozen._private_pin(failure)
        return base,artifact,request,{k:fp[k] for k in ('sha256','bytes')}

    def test_actual_retained_paths_reject_coherent_artifact_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();root.chmod(0o700)
            base,artifact,request,failure_pin=self.retained_fixture(root)
            request_pin=frozen._private_pin(base/'observe-request.json')
            with mock.patch.dict(fresh.FAILED_PIN,failure_pin),mock.patch.object(fresh,'CONSUMED_REQUEST_PIN',{k:request_pin[k] for k in ('generation','sha256','bytes')}):
                fresh._retained(root)
                # Replace DEX/compiler/artifact coherently; consumed request is untouched.
                (base/'classes.dex').unlink()
                fd=os.open(base/'classes.dex',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'dex\n035\0'+b'y'*112);os.close(fd)
                (base/'compiler.json').unlink();old._save(base/'compiler.json',{'intentPin':artifact['intentPin'],'correlationId':fresh.FAILED,'javaSha256':frozen.JAVA_SHA,'replacement':True})
                for key,name in (('artifactPin','classes.dex'),('compilerReceiptPin','compiler.json')):
                    pin=frozen._private_pin(base/name);artifact[key]={k:pin[k] for k in ('path','generation','sha256','bytes')}
                (base/'artifact.json').unlink();old._save(base/'artifact.json',artifact)
                with self.assertRaisesRegex(ValueError,'consumed_observe_binding_changed'):fresh._retained(root)

    def test_retained_original_binding_edges_reject(self):
        for edge in ('artifact-intent','request-intent','request-source','request-correlation','request-outcome','artifact-java','artifact-primary'):
            with self.subTest(edge=edge),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();root.chmod(0o700)
                base,artifact,request,failure_pin=self.retained_fixture(root)
                original_request_pin=frozen._private_pin(base/'observe-request.json')
                target='artifact.json' if edge.startswith('artifact') else 'observe-request.json'
                value=artifact if target=='artifact.json' else request
                if edge.endswith('intent'):value['intentPin']['sha256']='0'*64
                elif edge=='request-source':value['remoteSourceSha256']='0'*64
                elif edge=='request-correlation':value['correlationId']=OTHER
                elif edge=='request-outcome':value['originalOutcome']='complete'
                elif edge=='artifact-java':value['javaSha256']='0'*64
                else:value['primarySource']={}
                (base/target).unlink();old._save(base/target,value)
                with mock.patch.dict(fresh.FAILED_PIN,failure_pin),mock.patch.object(fresh,'CONSUMED_REQUEST_PIN',{k:original_request_pin[k] for k in ('generation','sha256','bytes')}),self.assertRaises(ValueError):fresh._retained(root)

    def test_coherent_request_rewrite_cannot_replace_consumed_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();root.chmod(0o700)
            base,artifact,request,failure_pin=self.retained_fixture(root)
            original_request_pin=frozen._private_pin(base/'observe-request.json')
            artifact['primarySource']={**frozen.PRIMARY,'replacement':True}
            (base/'artifact.json').unlink();old._save(base/'artifact.json',artifact)
            ap=frozen._private_pin(base/'artifact.json');request['artifactPin']={k:ap[k] for k in ('generation','sha256')}
            (base/'observe-request.json').unlink();old._save(base/'observe-request.json',request)
            with mock.patch.dict(fresh.FAILED_PIN,failure_pin),mock.patch.object(fresh,'CONSUMED_REQUEST_PIN',{k:original_request_pin[k] for k in ('generation','sha256','bytes')}),self.assertRaisesRegex(ValueError,'consumed_observe_request_changed'):fresh._retained(root)

    def test_validated_retained_snapshot_cannot_be_replaced_before_repin(self):
        for name in ('intent.json','artifact.json','observe-request.json'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp).resolve();root.chmod(0o700)
                base,artifact,request,failure_pin=self.retained_fixture(root)
                request_pin=frozen._private_pin(base/'observe-request.json')
                real_pin=frozen._private_pin;changed=False
                def exchange(path,limit=1048576):
                    nonlocal changed
                    if path==base/name and not changed:
                        changed=True
                        value=json.loads(old.private_snapshot(path,65536)[0]);value['replacementAfterValidation']=True
                        path.unlink();old._save(path,value)
                    return real_pin(path,limit)
                with mock.patch.dict(fresh.FAILED_PIN,failure_pin),mock.patch.object(fresh,'CONSUMED_REQUEST_PIN',{k:request_pin[k] for k in ('generation','sha256','bytes')}),mock.patch.object(frozen,'_private_pin',side_effect=exchange),self.assertRaisesRegex(ValueError,'consumed_snapshot_changed'):fresh._retained(root)
