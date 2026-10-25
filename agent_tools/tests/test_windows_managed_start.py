"""Inert managed-start observer routing and original-journal interleaving gates."""
import ast
import copy
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import textwrap
import unittest
from unittest import mock
from uuid import UUID,uuid4,uuid5

from agent_tools import readiness_windows_managed_start as subject
from agent_tools import readiness_windows_lifecycle as lifecycle
from agent_tools import readiness_windows_tpm_owner as owner
from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_resources as resources
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding
from agent_tools.tests.test_readiness_windows_guest import SID
from agent_tools.tests.test_windows_tpm_owner import issued_witness


def admission():
    binding,body=managed_binding();lineage=lifecycle.validate_lineage(binding,body);operation=str(uuid4())
    terminal={'schemaVersion':1,'kind':'windows-clean-poweroff-v1','operationId':operation,
        'recoveryId':'2'*64,'machine':body['machine'],'hostBoot':body['hostBoot'],
        'actor':{k:body['qemu'][k]for k in ('pid','startTicks')},'tpm':{k:body['tpm'][k]for k in ('pid','startTicks')},
        'bootBefore':'2026-10-20T00:00:00.000Z','account':SID,'lineageSha256':lifecycle._lineage_sha(lineage),
        'artifacts':{'rootIdentity':body['rootIdentity'],'mutable':body['mutable'],
            'tpmState':{**body['tpmState'],'files':{'state':[1,50,0o100600,1000,1000]}}},
        'cleanPoweroff':True,'guestJobsAbsent':True,'cleanCause':{'kind':'libvirt-shutoff','reason':'shutdown'},'replayAllowed':False}
    clean=lifecycle.validate_clean_stopped(binding,lineage,terminal);rid='1'*64;op=str(uuid5(UUID(body['machine']),rid))
    return subject.original(binding,lineage,clean,op,rid)


def projection_and_request(original):
    body=original.as_dict();before=body['lineage'];actor=copy.deepcopy(before['qemu']);actor.update(pid=200,startTicks=2000)
    projection={'intentGeneration':[1,2,0o100600,1000,1000,1,100,100,100],
        'ackGeneration':[1,3,0o100600,1000,1000,1,100,100,100],
        'actor':{k:actor[k]for k in ('pid','startTicks','executableGeneration')},
        'manager':{k:before['libvirt']['manager'][k]for k in ('pid','startTicks','executableGeneration')},
        'managerSocketIdentity':before['libvirt']['socketIdentity'],'domainId':2}
    request={'schemaVersion':1,'kind':'windows-tpm-listener-request-v1','machine':before['machine'],'hostBoot':before['hostBoot'],
        'root':body['binding']['spec']['root'],'rootIdentity':before['rootIdentity'],'mutable':before['mutable'],
        'qemu':{'pid':actor['pid'],'birth':actor['startTicks'],'uid':before['rootIdentity'][3],
                'executableGeneration':actor['executableGeneration']},
        'socket':{'path':str(Path(body['binding']['spec']['root']).parent/'.cache/libvirt/qemu/run/swtpm/selected.sock'),
                  'inode':90,'identity':[1,4,0o140600,before['rootIdentity'][3],1000]}}
    return projection,request,actor


class ManagedCollectorTests(unittest.TestCase):
    def setUp(self):
        # Channel-order unit tests isolate the original-HOST factory seam. Its
        # real opaque/source/owner boundary is exercised by dedicated tests.
        self.enterContext(mock.patch.object(subject,'_host_original',return_value=object()))

    def live(self,request,result):
        result={**result,'observedNs':1_000_000_000,'deadlineNs':31_000_000_000}
        return self.enterContext(issued_witness(request,result))

    def test_internal_once_dispatch_retains_pending_claim_and_never_uses_unwitnessed_tpm(self):
        original=admission();body=original.as_dict();binding=body['binding'];operation=body['intent']['operationId']
        target=resources.ResourceTarget(operation,binding['spec']['host'],binding['spec']['root'])
        resource=resources.ResourceAdmission(Path('/tmp'),target,body['intent']['machine'],operation,Path('/tmp'),'/unopened-private-handle',time.monotonic()+30)
        snapshot={'hostBootId':body['intent']['hostBoot'],'census':{},'inventorySha256':'3'*64,'resourceAliases':[target.host],
            'pending':[],'requestedMemoryBytes':binding['spec']['memoryMiB']*1024**2,'headroomBytes':binding['spec']['headroomMiB']*1024**2}
        with mock.patch.object(resources.ResourceAdmission,'submission_snapshot',return_value=snapshot):program=subject.dispatch_program(original,resource)
        self.assertEqual(program.purpose,'windows-persisted-managed-start');text=program.source.decode();compile(text,'managed once pending qualification','exec')
        self.assertTrue(text.startswith("_LIFECYCLE_EXECUTING_CODE="));self.assertEqual(text.count('domain.createWithFlags(0)'),1)
        a=text.index('    def _lifecycle_managed_start():');b=text.index('    try:\n        epoch();chain()',a);effect=text[a:b]
        self.assertIn("'postlaunch-observation-required'",effect);self.assertIn("'.manager-ack.json'",effect)
        self.assertNotIn('_capture_libvirt_lineage',effect);self.assertNotIn('connect(',effect)
        self.assertIn("save(prefix+'.pending.json',actual);claim['writerPid']=actual['actor']['pid']",text)
        # Public raw builder remains blocked on this provider; no capability is
        # granted by the private direct-qualification source builder.
        with self.assertRaisesRegex(ValueError,'managed_start_witness_unqualified'):
            lifecycle.existing_start_program(binding,lifecycle.validate_lineage(binding,body['lineage']),
                lifecycle.CleanStopped(lifecycle._freeze(body['clean'])),operation,body['intent']['recoveryId'],resource)

    def test_pure_builder_is_readonly_and_requires_original_scope(self):
        original=admission();projection,request,actor=projection_and_request(original)
        witness=self.live(request,{'complete':True,'holders':[{'pid':201,'uid':request['qemu']['uid'],'birth':2001}]})
        with mock.patch.object(subject.transport,'admitted_transport',side_effect=AssertionError('transport from getter')):
            source=subject.program(original);compile(source,'original managed request','exec')
            final=subject.program(original,request={'original':projection,'request':request},witness=witness)
            compile(final,'original managed final','exec')
        for source in (source,final):
            self.assertIn(b'original_before==original_after',source)
            self.assertIn(b'MANAGED_EXPECTED',source)
            self.assertNotIn(b'domain.createWithFlags(',source)
            tree=ast.parse(source)
            mode=[node.value.value for node in tree.body if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='MODE'for t in node.targets)]
            self.assertEqual(mode,['observe'])
            text=source.decode();begin=text.index('        original_before=_managed_original(');end=text.index('\n        return\n',begin)
            self.assertNotIn("rpc('guest-shutdown'",text[begin:end])
            self.assertLess(end,text.index('        state=machine_state()'))
        changed=copy.deepcopy(request);changed['machine']=str(uuid4())
        with self.assertRaisesRegex(ValueError,'original_unresolved'):
            subject.program(original,request={'original':projection,'request':changed},witness=witness)

    def test_forged_or_mutated_typed_identity_never_reaches_transport(self):
        original=admission()
        for mutate in (lambda body:body.update(trusted=True),lambda body:body['intent'].update(machine=str(uuid4())),
                       lambda body:body['binding'].update(provider='raw-qemu-windows')):
            body=original.as_dict();mutate(body);forged=subject.OriginalManagedStart(lifecycle._freeze(body))
            with mock.patch.object(subject.transport,'admitted_transport',side_effect=AssertionError('unvalidated identity transport')):
                with self.assertRaises(ValueError):subject.collect(Path('/coordinator'),forged,'/credential',guard=lambda:None)

    def test_collect_joins_two_readonly_channels_to_exact_root_census_original(self):
        original=admission();projection,request,actor=projection_and_request(original);body=original.as_dict()
        actual=copy.deepcopy(body['lineage']);actual['operationId']=body['intent']['operationId'];actual['qemu']=actor
        holder={'pid':actual['tpm']['pid'],'uid':request['qemu']['uid'],'birth':actual['tpm']['startTicks']}
        witness=self.live(request,{'complete':True,'holders':[holder]})
        replies=[{'original':projection,'request':request},{'original':projection,'lineage':actual}]
        with mock.patch.object(subject,'_run',side_effect=replies)as remote, \
             mock.patch.object(subject.owner,'observe',return_value=contextlib.nullcontext(witness))as root:
            collected=subject.collect(Path('/coordinator'),original,'/private/credential',guard=lambda:None)
        self.assertEqual(collected.lineage.as_dict(),actual);self.assertEqual(remote.call_count,2)
        self.assertEqual(root.call_args.args[2],request)
        self.assertEqual(root.call_args.args[1],body['binding']['spec']['host'])
        self.assertEqual(collected.original.as_dict()['intent']['operationId'],body['intent']['operationId'])
        for call in remote.call_args_list:self.assertIs(call.args[1],original)

    def test_expired_census_reobserves_only_same_original_without_start_replay(self):
        original=admission();projection,request,actor=projection_and_request(original);body=original.as_dict()
        actual=copy.deepcopy(body['lineage']);actual['operationId']=body['intent']['operationId'];actual['qemu']=actor
        holder={'pid':actual['tpm']['pid'],'uid':request['qemu']['uid'],'birth':actual['tpm']['startTicks']}
        first=self.live(request,{'complete':True,'holders':[holder]});second=self.live(request,{'complete':True,'holders':[holder]})
        envelope={'original':projection,'request':request}
        with mock.patch.object(subject,'_run',side_effect=[envelope,owner.WitnessExpired(),envelope,{'original':projection,'lineage':actual}])as remote, \
             mock.patch.object(subject.owner,'observe',side_effect=[contextlib.nullcontext(first),contextlib.nullcontext(second)])as root:
            result=subject.collect(Path('/coordinator'),original,'/credential',guard=lambda:None)
        self.assertEqual(result.lineage.as_dict(),actual);self.assertEqual(root.call_count,2)
        self.assertEqual(remote.call_count,4)
        for call in remote.call_args_list:self.assertIs(call.args[1],original)
        with mock.patch.object(subject,'_run',side_effect=ValueError('source mismatch'))as remote:
            with self.assertRaises(ValueError):subject.collect(Path('/coordinator'),original,'/credential',guard=lambda:None)
        self.assertEqual(remote.call_count,1)

    def test_wrong_fixture_changed_actor_or_ack_never_grants_lineage(self):
        original=admission();projection,request,actor=projection_and_request(original);body=original.as_dict()
        changed=copy.deepcopy(request);changed['machine']=str(uuid4())
        with mock.patch.object(subject,'_run',return_value={'original':projection,'request':changed}), \
             mock.patch.object(subject.owner,'observe',side_effect=AssertionError('privileged unrelated target')):
            with self.assertRaises(ValueError):subject.collect(Path('/coordinator'),original,'/private/credential',guard=lambda:None)
        witness=self.live(request,{'complete':True,'holders':[{'pid':201,'uid':request['qemu']['uid'],'birth':2001}]})
        for key in ('intentGeneration','ackGeneration','managerSocketIdentity'):
            after=copy.deepcopy(projection);after[key][1]+=1
            with mock.patch.object(subject,'_run',side_effect=[{'original':projection,'request':request},{'original':after,'lineage':body['lineage']}]), \
                 mock.patch.object(subject.owner,'observe',return_value=contextlib.nullcontext(witness)):
                with self.assertRaises(ValueError):subject.collect(Path('/coordinator'),original,'/private/credential',guard=lambda:None)
        with mock.patch.object(subject.transport,'admitted_transport',side_effect=AssertionError('expired deadline recovered')):
            for deadline in (False,0,float('inf'),time.monotonic()-1):
                with self.assertRaises(ValueError):subject.collect(Path('/coordinator'),original,'/private/credential',guard=lambda:None,deadline=deadline)

    def test_readonly_carrier_constructs_only_after_admission_and_fences_dispatch(self):
        original=admission();events=[];authority=mock.MagicMock();admitted=mock.MagicMock()
        admitted.__enter__.side_effect=lambda:events.append('ready')or admitted
        admitted.revalidate.side_effect=lambda:events.append('ready-guard')
        authority.__enter__.return_value=authority;authority.guard.side_effect=lambda:events.append('source-guard')
        def build(*args,**kwargs):
            events.append('build');self.assertEqual(kwargs['command'][:4],('python3','-I','-B','-c'))
            return [sys.executable,'-I','-B','-c',"print('{\"finite\":true}')"]
        def run(argv,**kwargs):
            events.append('dispatch');self.assertEqual(kwargs['input'],b'')
            self.assertIn('ready-guard',events[events.index('build')+1:])
            return subprocess.run(argv,**kwargs)
        def source():events.append('generate');self.assertIn('ready',events);return b'print(1)'
        with tempfile.TemporaryDirectory()as tmp, \
             mock.patch.object(subject.transport,'admitted_transport',return_value=admitted), \
             mock.patch.object(subject.deploy.direct,'Guard',return_value=authority), \
             mock.patch.object(subject.transport,'build_ssh_argv',side_effect=build), \
             mock.patch.object(subject.transport,'run_ssh',side_effect=run):
            result=subject._run(Path(tmp),original,source,lambda:events.append('caller-guard'),time.monotonic()+5)
        self.assertEqual(result,{'finite':True});self.assertLess(events.index('ready'),events.index('generate'))
        self.assertLess(events.index('generate'),events.index('build'));self.assertEqual(events[-1],'caller-guard')

    def test_original_journal_gate_uses_actual_private_files_and_live_kernel_generation(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);root.chmod(0o700);wire=root/'observer.sock';ready=root/'ready'
            child=subprocess.Popen([sys.executable,'-I','-B','-c',
                "import socket,sys;from pathlib import Path;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);Path(sys.argv[2]).touch();c,_=s.accept();assert c.recv(32)==b'probe';c.sendall(b'{}');c.close();s.close()",str(wire),str(ready)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                end=time.monotonic()+3
                while not ready.exists():self.assertIsNone(child.poll());self.assertLess(time.monotonic(),end);time.sleep(.005)
                birth=jobs._birth(child.pid);expected=admission().as_dict()['intent'];op=expected['operationId'];actor={'pid':child.pid,'startTicks':10001,'executableGeneration':[1]*9}
                manager={'pid':os.getpid(),'startTicks':10002,'executableGeneration':[2]*9};socket_pin=[1,2,0o140600,1000,1000]
                ack={'operationId':op,'recoveryId':expected['recoveryId'],'domainId':2,'actor':actor,'manager':manager,
                     'socketIdentity':socket_pin,'replayAllowed':False}
                def write(name,value):
                    path=root/name;path.write_text(json.dumps(value));path.chmod(0o600)
                prefix='existing-start-'+op
                write(prefix+'.intent.json',expected);write(prefix+'.manager-ack.json',ack)
                def process(row):
                    if row['pid']==child.pid:self.assertIsNone(child.poll());self.assertEqual(jobs._birth(child.pid),birth)
                    else:self.assertEqual(row,manager)
                generation=lambda s:[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
                domain=mock.Mock();domain.ID.return_value=2
                def gate():return subject._original(expected,root,lambda name:json.loads((root/name).read_text()),process,actor,manager,socket_pin,domain,generation,os.lstat)
                before=gate()
                # Execute the complete actual generated early-return branch
                # with native libvirt/QEMU boundary replaced by this harmless
                # real endpoint. Original journal and kernel gates stay real.
                original=admission();generated=subject.program(original).decode()
                start=generated.index('        original_before=_managed_original(');end=generated.index('\n        return\n',start)+len('\n        return\n')
                branch=textwrap.indent(textwrap.dedent(generated[start:end]),'    ')
                def capture(*args):
                    with socket.socket(socket.AF_UNIX)as client:
                        client.connect(str(wire));client.sendall(b'probe');return json.loads(client.recv(32))
                ns={'_managed_original':subject._original,'MANAGED_EXPECTED':expected,'MANAGED_PRIOR_PROJECTION':None,
                    'MANAGED_OLD_ACTOR':{'pid':1,'startTicks':1},'root':root,'read':lambda name:json.loads((root/name).read_text()),
                    'process':process,'current_actor':actor,'manager':manager,'socket_pin':socket_pin,'domain':domain,
                    'generation':generation,'private':os.lstat,'require':lambda value,*a:self.assertTrue(value),
                    '_capture_libvirt_lineage':capture,'json':json,'vm_guard':lambda:process(actor),
                    'LIFECYCLE_TPM_OWNER':None,'LIFECYCLE_TPM_REQUEST_ONLY':True}
                for name in ('SPEC','CONTEXT','OPERATION','connection','URI','DOMAIN','XML_SHA','SOCKET_PATH','owns','closing',
                             'structure','instance_intent','pin','birth'):ns[name]=None
                exec('def generated_call():\n'+branch,ns)
                output=io.StringIO()
                with contextlib.redirect_stdout(output):ns['generated_call']()
                self.assertEqual(json.loads(output.getvalue())['original'],before)
                # Same JSON bytes rewritten after the intermediate observation
                # must still invalidate the held original generation.
                write(prefix+'.manager-ack.json',ack);after=gate();self.assertNotEqual(before,after)
                ack['actor']={**actor,'pid':actor['pid']+1};write(prefix+'.manager-ack.json',ack)
                with self.assertRaisesRegex(ValueError,'original_start_unknown'):gate()
            finally:
                if child.poll()is None:child.terminate()
                child.communicate(timeout=3)


if __name__=='__main__':unittest.main()
