"""Routine projection coverage from actual TempFS admission DTOs, no native IO.

The frozen local caller validator snapshots are tested independently of the
operational caller. Only returned UID/GID metadata is projected to root/user
principals: these ordinary tests never establish a native admission proof.
"""
import base64
import copy
import hashlib
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from agent_tools import android_installer_failed_check_retirement as retirement
from agent_tools import android_installer_component_bundle as bundle
from agent_tools.tests import test_android_installer_failed_check_retirement as receipts
from agent_tools.tests.fixtures import android_component_retirement_projection as fixture


def projected_pin(pin):
    pin=copy.deepcopy(pin);pin['generation'][3:5]=[0,0]
    for parent in pin.get('parents',{}).values():parent[3:5]=[0,0]
    return pin


@unittest.skipUnless(os.name=='posix' and hasattr(os,'O_NOFOLLOW'),'actual descriptor producer requires POSIX NOFOLLOW')
class ActualProducedProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve();self.root.chmod(0o700)
        self.verified=receipts.ComponentTerminalHistoryTest().component_proof()
        original=self.root/('android-installer-'+self.verified['originalCorrelationId'])/'output'
        admitted=self.root/('android-installer-component-baseline-'+self.verified['retirementCorrelationId'])/'component-retirement-admission'
        for path in (original.parent,original,admitted.parent,admitted):path.mkdir(mode=0o700)
        # Execute the actual source-authenticated factory and actual durable
        # create-only producer on TempFS. No private native receipt is loaded.
        raw=Path(retirement.__file__).read_bytes();scope={}
        exec(compile(retirement.component_admission_source(raw,hashlib.sha256(raw).hexdigest()),'<actual-admission-producer>','exec'),scope)
        admission=scope['admit_component_fenced'](original,admitted,self.verified,lambda:None,os.getuid())
        for key in ('proofPin','admissionPin','globalFencePin'):admission[key]=projected_pin(admission[key])
        history=admitted.parent/'component-terminal-history.json';history.write_bytes(retirement._canonical(self.verified['terminalHistory']));history.chmod(0o600)
        rows=[]
        for name,path in (('component-terminal-history.json',history),('component-retirement-admission/component-admitted-proof.json',admitted/'component-admitted-proof.json'),('component-retirement-admission/component-admitted.json',admitted/'component-admitted.json')):
            body,pin=bundle._read(path,True);pin=projected_pin(pin)
            rows.append({'name':name,'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest(),'pin':pin,'rawBase64':base64.b64encode(body).decode()})
        fence=original/'component-retained-retirement-admission-intent.json';body,pin=bundle._read(fence,True);pin=projected_pin(pin)
        self.proof={'componentRetirementRows':rows,'componentRetirementRawRecords':[{'path':str(fence),'state':'present','generation':pin['generation'],'parents':pin['parents'],'bytes':len(body),'sha256':pin['sha256'],'rawBase64':base64.b64encode(body).decode()}]}
        producer=self.verified['componentProducer'];owner=producer['result']['controllerId']
        self.state={'leaf':'synthetic-retirement-census','request':{'correlationId':self.verified['retirementCorrelationId'],'expectedOwner':owner,'expectedRevision':0}}
        certificate=retirement.validate_component_certificate(producer,producer['result']['certificatePin'])
        history_facts=retirement.validate_component_terminal_history(self.verified['terminalHistory'],10209)
        self.result=fixture.produced_dto(admission,history_facts,certificate,self.verified)
    def project(self,result=None,proof=None,repaired=True):
        return fixture.validator(self.root,repaired)(self.result if result is None else result,self.proof if proof is None else proof,self.state,retirement)
    def changed(self,kind):
        result=copy.deepcopy(self.result);proof=copy.deepcopy(self.proof);row=proof['componentRetirementRawRecords'][0]
        body=json.loads(base64.b64decode(row['rawBase64']))
        if kind=='foreign':row['path']='/tmp/foreign-admission-fence.json';body={'kind':'foreign','releaseGranted':True}
        elif kind=='path':row['path']='/tmp/foreign-admission-fence.json'
        elif kind=='schema-bool':body['schema']=True
        elif kind=='release':body['releaseGranted']=True
        elif kind=='principal':row['generation'][3]=1000
        elif kind=='file-type':row['generation'][2]=stat.S_IFLNK|0o600
        elif kind=='parents':row['parents']={}
        elif kind=='parent-type':next(iter(row['parents'].values()))[2]=stat.S_IFLNK|0o700
        elif kind=='duplicate':proof['componentRetirementRawRecords'].append(copy.deepcopy(row))
        raw=retirement._canonical(body);row.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),rawBase64=base64.b64encode(raw).decode());row['generation'][6]=len(raw)
        result['admission']['globalFencePin']={'generation':copy.deepcopy(row['generation']),'sha256':row['sha256']}
        return result,proof
    def test_actual_produced_positive_preserves_unknown_and_grants_nothing(self):
        result=self.project();self.assertEqual('unknown-preserved',result['originalOutcome'])
        for field in ('claimGranted','releaseGranted','acceptanceComplete'):self.assertIs(result[field],False)
    def test_measured_old_foreign_fence_acceptance_and_fixed_refusal(self):
        result,proof=self.changed('foreign')
        self.assertEqual('component-retained-terminal-first-check-admitted',self.project(result,proof,False)['state'])
        with self.assertRaisesRegex(ValueError,'projection_fence_unknown'):self.project(result,proof)
    def test_exact_fixed_path_body_type_principal_ancestry_and_duplicate_refusals(self):
        for kind in ('path','schema-bool','release','principal','file-type','parents','parent-type','duplicate'):
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.project(*self.changed(kind))


class SnapshotIntegrityTests(unittest.TestCase):
    def test_exact_extracted_sources_authenticated_without_private_runtime(self):
        for source,digest in ((fixture.OLD_SOURCE,fixture.OLD_SOURCE_SHA),(fixture.FIXED_SOURCE,fixture.FIXED_SOURCE_SHA)):
            self.assertEqual(digest,hashlib.sha256(source.encode()).hexdigest())
        self.assertNotEqual(fixture.OLD_SOURCE_SHA,fixture.FIXED_SOURCE_SHA)
        with self.assertRaises(ValueError):fixture.validator('/fixed-inert-root')({}, {}, {}, retirement)


if __name__=='__main__':unittest.main()
