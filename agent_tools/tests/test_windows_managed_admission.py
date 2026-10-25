"""Managed original load and public current-graph gates; no VM operations."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock
from uuid import uuid4
from xml.etree import ElementTree as ET

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows as main
from agent_tools import readiness_windows_managed_admission as subject
from agent_tools import readiness_windows_bootstrap_durable as bootstrap
from agent_tools.tests import test_windows_bootstrap_durable as fixtures
from agent_tools.tests import test_windows_seed_detach as seed_fixtures

FIXTURE=Path(__file__).with_name('fixtures')/'windows_managed_admission'


def before_module():
    path=FIXTURE/'private-pin.before.source';raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='fec9b60f0edf7512db6502df304db05ddc4e9352d8d83466ff943dc5e59ce371':raise AssertionError('whole factory private-pin before changed')
    name='agent_tools._managed_factory_private_pin_before';spec=importlib.util.spec_from_loader(name,loader=None,origin=str(path))
    module=importlib.util.module_from_spec(spec);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def graph_before():
    path=FIXTURE/'graph-local.before.source';raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='c209896ca44211a0e7e2e4e567b53758614fd70917c12c71c3ef48301ee8fda1':raise AssertionError('whole graph before changed')
    name='agent_tools._managed_graph_before';spec=importlib.util.spec_from_loader(name,loader=None,origin=str(path))
    module=importlib.util.module_from_spec(spec);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def runtime_before():
    path=FIXTURE/'runtime-id.before.source';raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='4f5092447409193198b3ea7a842f6e52fb203a805ba11b20ab72fe1ed1c92b58':raise AssertionError('whole runtime-id before changed')
    name='agent_tools._managed_runtime_id_before';spec=importlib.util.spec_from_loader(name,loader=None,origin=str(path))
    module=importlib.util.module_from_spec(spec);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def final_runtime_before():
    path=FIXTURE/'runtime-id-final-type.before.source';raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='e466c30aa5c3af1b42bdcbab703bd876c36554d1485fc8d4cbe534db404f828a':raise AssertionError('whole final runtime-id before changed')
    name='agent_tools._managed_final_runtime_id_before';spec=importlib.util.spec_from_loader(name,loader=None,origin=str(path))
    module=importlib.util.module_from_spec(spec);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


class PublicGraphTests(unittest.TestCase):
    def test_opaque_original_current_and_public_xml_before_any_hash(self):
        for cls in (subject.ManagedOriginal,subject.CurrentManagedAdmission):
            with self.assertRaises(TypeError):cls()
            with self.assertRaises(ValueError):object.__new__(cls).as_dict()
        with self.assertRaises(ValueError):subject._public_xml('<domain><graphics passwd="private"/></domain>')
        self.assertEqual(subject.QUALIFIED_RECOVERIES,frozenset())
        provenance=json.loads((FIXTURE/'provenance.json').read_bytes())
        for name,digest in provenance['beforeSha256'].items():self.assertEqual(hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest(),digest)
        self.assertEqual(hashlib.sha256((FIXTURE/'provenance.json').read_bytes()).hexdigest(),'9b6232c1974e984839c8d3f6dfdd654e3328f1dc2559407c9553473ad14bc5bf')
        graph_before()
        self.assertEqual(hashlib.sha256((FIXTURE/'graph-local-failure.json').read_bytes()).hexdigest(),'d32d67fbd0e3d3adf54acd04d0b165201dd34880559cee959e4aea6dfb2e156e')
        runtime_before()
        self.assertEqual(hashlib.sha256((FIXTURE/'runtime-id.provenance.json').read_bytes()).hexdigest(),'cba22fe6b5eaa4a46671d43369625c4c536588e7de34865d4fa0d50265f03405')
        final_runtime_before()
        self.assertEqual(hashlib.sha256((FIXTURE/'runtime-id-final-type.provenance.json').read_bytes()).hexdigest(),'caa3a07dc231d1fbcd0511fc032951b38d795a1aa9a627d020d541d19fa151df')
        self.assertEqual({p.name for p in FIXTURE.iterdir()},{'factory.before.source','private-pin.before.source','provenance.json','graph-local.before.source','graph-local-failure.json','runtime-id.before.source','runtime-id.provenance.json','runtime-id-final-type.before.source','runtime-id-final-type.provenance.json'})
        for raw in ('<domain><secret>neutral</secret></domain>','<domain><graphics secret="neutral"/></domain>'):
            self.assertEqual(runtime_before()._public_xml(raw),raw)
            with self.assertRaises(ValueError):subject._public_xml(raw)

    def test_current_tpm_and_provider_lineage_mismatch_never_mints_from_dto(self):
        from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding
        binding,lineage=managed_binding();summary={'binding':binding,'expectedSid':'S-1-5-21-1-2-3-1001'}
        request={'rootIdentity':lineage['rootIdentity'],'mutable':lineage['mutable']}
        facts={'state':'observed','machine':binding['spec']['deploymentId'],'provider':'libvirt-windows',
            'hostBoot':binding['context']['hostBootId'],'guest':'paused','actor':lineage['qemu'],'guestAgent':False,'sessionFacts':None}
        actual={'kind':'windows-managed-current-admission-v1','graph':{'inactiveXmlSha256':binding['xmlSha256'],'liveGraphVerified':True,
            'seedAttached':False,**request},'lineage':lineage,'observation':facts}
        expected={'holder':{'pid':lineage['tpm']['pid'],'birth':lineage['tpm']['startTicks']},
            'qemu':{'pid':lineage['qemu']['pid'],'birth':lineage['qemu']['startTicks'],'executableGeneration':lineage['qemu']['executableGeneration']}}
        self.assertEqual(subject._validate_current(summary,request,actual,expected),actual)
        with self.assertRaises(ValueError):subject._validate_current(summary,request,actual)
        for path in ('tpm','qemu'):
            wrong=copy.deepcopy(actual);wrong['lineage'][path]['startTicks']+=1
            with self.assertRaises(ValueError):subject._validate_current(summary,request,wrong,expected)
        wrong=copy.deepcopy(actual);wrong['graph']['seedAttached']=True
        with self.assertRaises(ValueError):subject._validate_current(summary,request,wrong,expected)
        wrong=copy.deepcopy(actual);wrong['graph']['inactiveXmlSha256']='0'*64
        with self.assertRaises(ValueError):subject._validate_current(summary,request,wrong,expected)
        self.assertEqual(len(subject._CURRENT),0)

    def test_actual_current_inactive_empty_seed_graph_storage_and_original_intent(self):
        fixture=seed_fixtures.SeedDetachTests('runTest');fixture.setUp()
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary);root.chmod(0o700)
            binding=copy.deepcopy(fixture.binding);binding['spec']['root']=str(root)
            attached=subject.creators.creator.domain_xml(binding['spec'],binding['domain'])
            tree=ET.fromstring(attached);selected=tree.find("devices/disk/alias[@name='ua-vpn-control-credential-seed']/..")
            selected.remove(selected.find('source'));empty=ET.tostring(tree,encoding='unicode')
            plain,_=subject.seed._seed_graph(empty,str(root/'seed.iso'),'ua-vpn-control-credential-seed',attached=False)
            binding['xmlSha256']=hashlib.sha256(empty.encode()).hexdigest()
            mutable={}
            for name in ('disk.qcow2','uefi-vars.fd'):
                jobs._create(root/name,b'public controlled metadata fixture');mutable[name]=None
            # jobs generation is only dev/ino; use the exact existing structure.
            structure=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
            mutable={name:list(structure((root/name).stat()))for name in mutable}
            historic_live=ET.fromstring(plain);historic_live.set('id','3')
            intent={'machine':binding['spec']['deploymentId'],'creatorOperationId':str(uuid4()),'operationId':str(uuid4()),
                'seedGeneration':[1,2,0o100600,os.geteuid(),os.getegid(),1,5,1,1],'seedPath':str(root/'seed.iso'),
                'replayAllowed':False,'otherInactive':plain,'otherLive':ET.tostring(historic_live,encoding='unicode')}
            path=root/('private-seed-'+intent['operationId']+'.intent.json');jobs._publish(path,intent)
            request={'rootIdentity':list(structure(root.stat())),'mutable':mutable,'machine':intent['machine'],
                'creator':{'operationId':intent['creatorOperationId']},'seedGeneration':intent['seedGeneration'],
                'detachment':{'operationId':intent['operationId'],'intentGeneration':list(bootstrap._source_pin(path.stat()))}}
            class Domain:
                current=empty;active=True;runtime=7;live_id=None
                def UUIDString(self):return binding['spec']['deploymentId']
                def name(self):return binding['domain']
                def ID(self):return self.runtime
                def XMLDesc(self,flags):
                    if flags==0 and not self.active:raise AssertionError('stopped guest live lookup')
                    if flags==0:
                        live=ET.fromstring(self.current);live.set('id',str(self.runtime)if self.live_id is None else self.live_id)
                        return ET.tostring(live,encoding='unicode')
                    return self.current
                def isActive(self):return self.active
            domain=Domain();private=lambda path,directory=False:path.lstat()
            run=lambda:subject._current_graph(binding,request,root,domain,bootstrap._source_pin,structure,private,lambda:None)
            with self.assertRaisesRegex(NameError,'_seed_graph'):
                graph_before()._current_graph(binding,request,root,domain,bootstrap._source_pin,structure,private,lambda:None)
            with self.assertRaises(ValueError):runtime_before()._current_graph(binding,request,root,domain,bootstrap._source_pin,structure,private,lambda:None)
            current=run();self.assertFalse(current['seedAttached']);self.assertTrue(current['liveGraphVerified'])
            for invalid in ('8','0','-1','07','unknown'):
                domain.live_id=invalid
                with self.assertRaises(ValueError):run()
            domain.live_id=None
            for invalid in (None,True,0,-1,'7'):
                domain.runtime=invalid
                with self.assertRaises(ValueError):run()
            domain.runtime=7
            sequence=iter((7,8))
            with mock.patch.object(domain,'ID',side_effect=lambda:next(sequence)):
                with self.assertRaises(ValueError):run()
            domain.runtime=1;before=final_runtime_before()
            for invalid in (True,1.0):
                sequence=iter((1,invalid))
                with mock.patch.object(domain,'ID',side_effect=lambda:next(sequence)):
                    self.assertFalse(before._current_graph(binding,request,root,domain,bootstrap._source_pin,structure,private,lambda:None)['seedAttached'])
            selected=before if os.environ.get('VPN_CONTROL_MANAGED_FINAL_ID_BEFORE')=='1'else subject
            for invalid in (True,1.0,None,False,'1',0,-1,2**31):
                with self.subTest(finalRuntimeId=invalid):
                    sequence=iter((1,invalid))
                    with mock.patch.object(domain,'ID',side_effect=lambda:next(sequence)):
                        with self.assertRaises(ValueError):selected._current_graph(binding,request,root,domain,bootstrap._source_pin,structure,private,lambda:None)
            self.assertTrue(run()['liveGraphVerified']);domain.runtime=7
            domain.active=False;self.assertFalse(run()['liveGraphVerified'])
            domain.active=True;domain.current=attached
            with self.assertRaises(ValueError):run()
            domain.current=empty
            wrong=copy.deepcopy(request);wrong['mutable']['disk.qcow2'][1]+=1
            with self.assertRaises(ValueError):subject._current_graph(binding,wrong,root,domain,bootstrap._source_pin,structure,private,lambda:None)
            wrong=copy.deepcopy(request);wrong['detachment']['intentGeneration'][1]+=1
            with self.assertRaises(ValueError):subject._current_graph(binding,wrong,root,domain,bootstrap._source_pin,structure,private,lambda:None)
            domain.current=empty.replace('<devices>','<devices><graphics passwd="private" />')
            with mock.patch.object(hashlib,'sha256',side_effect=AssertionError('private XML hash')):
                with self.assertRaises(ValueError):run()


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary actual original private packets')
class ManagedOriginalTests(unittest.TestCase):
    def test_pure_original_reopen_and_schema2_never_read_private_handle_bytes(self):
        old=before_module()
        def action(original,witness,packet,repo):
            finalizer=bootstrap.retain(repo,original,witness);record=finalizer.as_dict();binding=original.as_dict()['binding']
            loaded=subject.load(repo,binding,record['operationId']);self.assertEqual(loaded.as_dict()['expectedSid'],witness.request['detachment']['account'])
            with self.assertRaises(ValueError):subject.load(repo,binding,str(uuid4()))
            with self.assertRaises(ValueError):subject.program(loaded,{},str(uuid4()),request_only=True)
            runtime=repo/'.runtime';runtime.mkdir(mode=0o700,exist_ok=True);handle=runtime/'controlled-host-handle'
            jobs._create(handle,b'neutral local test marker')
            identity=(handle.stat().st_dev,handle.stat().st_ino);reads=[];real_read=os.read
            def read(fd,*args):
                info=os.fstat(fd)
                if(info.st_dev,info.st_ino)==identity:reads.append(fd)
                return real_read(fd,*args)
            descriptor={'schemaVersion':2,'fixtureId':'managed-opaque-original','provider':'libvirt-windows','binding':binding,
                'sources':main._source_pins(),'originalFinalizerOperationId':record['operationId'],'qualifications':{},
                'leaseRootGeneration':None,'credential':{'path':str(handle),'generation':list(subject.credential_metadata(handle))}}
            folder=repo/'.rag_index/readiness-fixtures';folder.mkdir(mode=0o700)
            path=folder/'managed-opaque-original.json';jobs._publish(path,descriptor);_,pin=main.registry._json(path)
            with mock.patch.object(os,'read',side_effect=read):
                try:old.load_registered_fixture(repo,descriptor['fixtureId'],descriptor,pin)
                except ValueError:pass
            self.assertTrue(reads,'whole before must actually read the neutral private fixture')
            reads.clear()
            with mock.patch.object(os,'read',side_effect=read):
                registered=main.load_registered_fixture(repo,descriptor['fixtureId'],descriptor,pin)
                registered.adapter.backend._guard()
            self.assertEqual(reads,[])
            self.assertIsNotNone(registered.adapter.backend._managed_original)
            self.assertFalse(registered.adapter.backend.capabilities)
            self.assertFalse((Path(record['namespace']['root'])/record['operationId']).exists())
        fixtures.with_original(self,action)


if __name__=='__main__':unittest.main()
