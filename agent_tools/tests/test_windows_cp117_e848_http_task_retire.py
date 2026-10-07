"""Inert one-shot archive/retirement regression tests; no native dispatch."""
from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import json
import re
import subprocess
import sys
import threading
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from agent_tools import windows_cp117_e848_http_task_retire as retire
from agent_tools.tests import test_windows_cp117_e848_http_task as fixture_module
proof=fixture_module.proof
NONCE=fixture_module.NONCE
REAL_RUN=retire._run


def archive():
    p=proof();ns='http://schemas.microsoft.com/windows/2004/02/mit/task'
    tree=ET.Element('Task',xmlns=ns);ET.SubElement(tree,'Triggers')
    principal=ET.SubElement(ET.SubElement(tree,'Principals'),'Principal',id='Author')
    for name,value in [('UserId',retire.observer._GENERATION[4]),('LogonType','InteractiveToken'),('RunLevel','LeastPrivilege')]:ET.SubElement(principal,name).text=value
    execution=ET.SubElement(ET.SubElement(tree,'Actions'),'Exec')
    ET.SubElement(execution,'Command').text=p['execute'];ET.SubElement(execution,'Arguments').text=p['arguments']
    raw=ET.tostring(tree,encoding='utf-8')
    return {'proof':p,'actionSha256':hashlib.sha256((p['execute']+'\0'+p['arguments']).encode()).hexdigest(),
            'observedPort':43210,'xmlSha256':hashlib.sha256(raw).hexdigest(),'xmlLength':len(raw),
            'xmlGzip':base64.b64encode(gzip.compress(raw,mtime=0)).decode()}


@unittest.skipUnless(retire.observer.history._supported(),'POSIX private journal locking required')
class E848TaskRetirementTests(unittest.TestCase):
    def setUp(self):
        fixture=fixture_module.RetainedHttpTaskTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        self.root=fixture.root;self.record=fixture.record;self.closed=fixture.closed
        self.a=archive();self.binding=retire._binding(retire._archive(self.a,self.record));self.source,self.intent=retire._plan(self.binding)
        self.calls=[];self.dispatches=[];self.response='terminal'
        patch=mock.patch.object(retire.observer,'observe',return_value={'state':'ready','phase':'verified','proof':'terminal-success',**retire.observer._FLAGS})
        patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(retire,'_run',side_effect=self.fake_run);patch.start();self.addCleanup(patch.stop)

    def fake_run(self,root,descriptor,closed,source):
        self.calls.append(source)
        if 'Parser]::ParseInput' in source:return {'version':1,'code':'OK'}
        if source==retire._snapshot_script():return {'archive':copy.deepcopy(self.a)}
        if 'Unregister-ScheduledTask' in source:
            self.dispatches.append(source);return None # Lost submission reply, durable terminal may exist.
        if source==retire._reader():
            if self.response=='missing':return None
            terminal={'retirementCorrelationId':retire._RETIREMENT,'state':'retired','bindingSha256':self.intent['bindingSha256'],'actionSha256':self.intent['actionSha256']}
            if self.response=='wrong-terminal':terminal['actionSha256']='0'*64
            a={**copy.deepcopy(self.a),'bindingSha256':self.intent['bindingSha256']}
            return {'binding':self.intent,'archive':a,'terminal':terminal,'absent':self.response!='present'}
        raise AssertionError('Unexpected source')

    def test_parses_actual_snapshot_before_read_and_all_prospective_sources(self):
        before=set(self.root.rglob('*'))
        self.assertEqual(retire.preflight(self.root,{})['state'],'ready')
        self.assertEqual(before,set(self.root.rglob('*')))
        self.assertEqual(self.calls[1],retire._snapshot_script())
        first=self.calls[0]
        packed=first.split("FromBase64String('",1)[1].split("')",1)[0]
        self.assertEqual(gzip.decompress(base64.b64decode(packed)),retire._snapshot_script().encode('utf-16le'))
        self.assertEqual(sum(source==retire._snapshot_script() for source in self.calls),2)
        for source in (retire._snapshot_script(),self.source,retire._reader()):
            command=retire._command(source)
            self.assertLess(len(command),30000)
            packed=re.search(r"FromBase64String\('([^']+)'\)",command).group(1)
            self.assertEqual(gzip.decompress(base64.b64decode(packed)),source.encode('utf-16le'))
        with self.assertRaises(ValueError):retire.transport._encode_ps(self.source)

    def test_invalid_snapshot_ast_stops_before_any_snapshot_or_intent(self):
        with mock.patch.object(retire,'_parse',return_value=False):
            self.assertEqual(retire.start(self.root,{})['phase'],'parser')
        self.assertEqual(self.calls,[]);self.assertFalse((self.root/retire._DIR).exists())

    def test_single_start_archives_before_exact_unregister_and_never_replays(self):
        before={p:p.read_bytes() for p in (self.root/'.rag_index').rglob('*') if p.is_file()}
        result=retire.start(self.root,{})
        self.assertEqual(result,retire._result('retired','complete'));self.assertEqual(len(self.dispatches),1)
        intentpath=self.root/retire._DIR/'intent.json'
        self.assertEqual(intentpath.stat().st_mode&0o777,0o600);self.assertEqual(intentpath.parent.stat().st_mode&0o777,0o700)
        source=self.dispatches[0]
        for step in ["Write-SecureJsonCreate 'archive.json'","$saved=Read-SecureJson 'archive.json'","$fresh=TaskSnapshot;SameSnapshot $fresh $saved"]:
            self.assertLess(source.index(step),source.index('Unregister-ScheduledTask'))
        self.assertEqual(source.count('Unregister-ScheduledTask'),1)
        self.assertIn("-TaskName '"+retire._TASK+"'",source)
        self.assertNotIn('Remove-Item',source);self.assertNotIn('Stop-Process',source)
        self.assertEqual(retire.start(self.root,{})['state'],'retired');self.assertEqual(len(self.dispatches),1)
        for p,raw in before.items():self.assertEqual(p.read_bytes(),raw)
        self.assertNotIn(NONCE,json.dumps(result));self.assertNotIn('xml',json.dumps(result).lower())

    def test_missing_terminal_after_delete_is_unknown_forever_without_replay(self):
        self.response='missing';result=retire.start(self.root,{})
        self.assertEqual(result['state'],'unknown');self.assertEqual(len(self.dispatches),1)
        for action in (retire.start,retire.status,retire.preflight):self.assertEqual(action(self.root,{})['state'],'unknown')
        self.assertEqual(len(self.dispatches),1)
        self.response='wrong-terminal';self.assertEqual(retire.status(self.root,{})['phase'],'terminal')
        self.response='present';self.assertEqual(retire.status(self.root,{})['phase'],'absence')

    def test_changed_snapshots_foreign_action_port_principal_and_running_reject(self):
        for field,value in [('actionSha256','0'*64),('observedPort',43211),('xmlLength',131073),('xmlSha256','0'*64)]:
            with self.subTest(field=field):
                a=archive();a[field]=value
                with self.assertRaises(ValueError):retire._archive(a,self.record)
        for field,value in [('taskState','Running'),('principalSid','S-1-5-18'),('lastTaskResult',1),('correlationProcess','ambiguous')]:
            with self.subTest(field=field):
                self.a=archive();self.a['proof'][field]=value
                self.assertNotEqual(retire.start(self.root,{})['state'],'retired');self.assertEqual(self.dispatches,[])
                self.assertFalse((self.root/retire._DIR/'intent.json').exists())
        self.a=archive();count=0
        def raced(root,descriptor,closed,source):
            nonlocal count
            if source==retire._snapshot_script():
                count+=1;value=archive()
                if count==2:value['proof']['lastRunTicks']+=1
                return {'archive':value}
            return self.fake_run(root,descriptor,closed,source)
        with mock.patch.object(retire,'_run',side_effect=raced):self.assertEqual(retire.start(self.root,{})['state'],'blocked')
        self.assertEqual(self.dispatches,[])

    def test_archive_gzip_bomb_entities_and_wrong_native_xml_reject(self):
        for raw in (b'A'*131073,b'<!DOCTYPE Task [<!ENTITY x "a">]><Task/>',b'<Task/>'):
            a=archive();a['xmlGzip']=base64.b64encode(gzip.compress(raw,mtime=0)).decode();a['xmlLength']=min(len(raw),131072);a['xmlSha256']=hashlib.sha256(raw).hexdigest()
            with self.assertRaises((ValueError,ET.ParseError)):retire._archive(a,self.record)
        a=archive();a['xmlGzip']='!'
        with self.assertRaises(ValueError):retire._archive(a,self.record)
        a=archive();a['xmlGzip']='A'*15001
        with self.assertRaises(ValueError):retire._archive(a,self.record)

    def test_snapshot_archive_identity_failure_is_finite_without_raw_native_data(self):
        raw=b'<Task/>';self.a['xmlGzip']=base64.b64encode(gzip.compress(raw,mtime=0)).decode();self.a['xmlLength']=len(raw);self.a['xmlSha256']=hashlib.sha256(raw).hexdigest()
        result=retire.preflight(self.root,{})
        self.assertEqual(result['phase'],'snapshot-xml-identity');self.assertEqual(result['state'],'blocked')
        self.assertNotIn('Task/',json.dumps(result));self.assertEqual(self.dispatches,[])
        self.assertFalse((self.root/retire._DIR/'intent.json').exists())

    def test_xml_action_mismatches_have_exact_finite_subcauses(self):
        ns='{http://schemas.microsoft.com/windows/2004/02/mit/task}'
        cases=[('Actions/Exec/Command','foreign.exe','command'),
               ('Actions/Exec/Arguments','foreign arguments','arguments'),
               ('Actions/Exec/WorkingDirectory','foreign directory','working-directory'),
               ('Principals/Principal/UserId','S-1-5-18','user'),
               ('Principals/Principal/LogonType','Password','logon'),
               ('Principals/Principal/RunLevel','HighestAvailable','run-level-highest-available')]
        for path,text,phase in cases:
            with self.subTest(phase=phase):
                self.a=archive()
                tree=ET.fromstring(gzip.decompress(base64.b64decode(self.a['xmlGzip'])))
                names=path.split('/');parent=tree
                for name in names[:-1]:parent=parent.find(ns+name)
                leaf=parent.find(ns+names[-1])
                if leaf is None:leaf=ET.SubElement(parent,ns+names[-1])
                leaf.text=text
                raw=ET.tostring(tree,encoding='utf-8')
                self.a.update(xmlGzip=base64.b64encode(gzip.compress(raw,mtime=0)).decode(),
                              xmlLength=len(raw),xmlSha256=hashlib.sha256(raw).hexdigest())
                result=retire.preflight(self.root,{})
                self.assertEqual(result['state'],'blocked')
                self.assertEqual(result['phase'],'snapshot-xml-'+phase)
                self.assertNotIn(text,json.dumps(result));self.assertEqual(self.dispatches,[])
                self.assertFalse((self.root/retire._DIR/'intent.json').exists())

    def test_native_export_omits_run_level_only_with_verified_limited_principal(self):
        # Native receipt 64e9442ec2a56e655f10367dbc404422: RunLevel absent;
        # independent current task proof remains Limited. No real private bytes.
        ns='{http://schemas.microsoft.com/windows/2004/02/mit/task}'
        self.a=archive();tree=ET.fromstring(gzip.decompress(base64.b64decode(self.a['xmlGzip'])))
        principal=tree.find(ns+'Principals')[0];principal.remove(principal.find(ns+'RunLevel'))
        raw=ET.tostring(tree,encoding='utf-8')
        self.a.update(xmlGzip=base64.b64encode(gzip.compress(raw,mtime=0)).decode(),
                      xmlLength=len(raw),xmlSha256=hashlib.sha256(raw).hexdigest())
        before=set(self.root.rglob('*'))
        self.assertEqual(retire.preflight(self.root,{})['state'],'ready')
        self.assertEqual(before,set(self.root.rglob('*')));self.assertEqual(self.dispatches,[])
        self.assertEqual(retire._archive(self.a,self.record)['xmlSha256'],hashlib.sha256(raw).hexdigest())
        for field,value in [('runLevel','Highest'),('principalSid','S-1-5-18'),
                            ('arguments','foreign action'),('triggerCount',1)]:
            with self.subTest(field=field):
                changed=copy.deepcopy(self.a);changed['proof'][field]=value
                with self.assertRaises(ValueError):retire._archive(changed,self.record)

    def test_xml_run_level_failure_distinguishes_only_bounded_forms(self):
        ns='{http://schemas.microsoft.com/windows/2004/02/mit/task}'
        for form,text in [('empty',''),('limited','Limited'),
                          ('other','private unexpected value'),('shape','LeastPrivilege')]:
            with self.subTest(form=form):
                self.a=archive();tree=ET.fromstring(gzip.decompress(base64.b64decode(self.a['xmlGzip'])))
                principal=tree.find(ns+'Principals')[0];level=principal.find(ns+'RunLevel')
                if form=='absent':principal.remove(level)
                else:level.text=text
                if form=='shape':ET.SubElement(principal,ns+'RunLevel').text='LeastPrivilege'
                raw=ET.tostring(tree,encoding='utf-8')
                self.a.update(xmlGzip=base64.b64encode(gzip.compress(raw,mtime=0)).decode(),
                              xmlLength=len(raw),xmlSha256=hashlib.sha256(raw).hexdigest())
                result=retire.preflight(self.root,{})
                self.assertEqual(result['phase'],'snapshot-xml-run-level-'+form)
                self.assertEqual(result['state'],'blocked');self.assertEqual(self.dispatches,[])
                self.assertFalse((self.root/retire._DIR/'intent.json').exists())

    def test_snapshot_guest_guard_and_transport_subcauses_remain_finite(self):
        cases=[({'state':'probe-failed','phase':'transport'},'snapshot-transport'),
               ({'state':'probe-failed','phase':'output-host-bound'},'snapshot-output-host-bound'),
               ({'state':'probe-failed','phase':'output-json'},'snapshot-output-json'),
               ({'state':'snapshot-failed','guard':'XML_SIZE'},'snapshot-guard-xml-size'),
               ({'state':'snapshot-failed','guard':'PROOF_CHANGED'},'snapshot-guard-proof-changed'),
               ({'state':'snapshot-failed','guard':'secret/raw/path'},'snapshot-archive-shape')]
        for response,phase in cases:
            with self.subTest(phase=phase):
                def probe(root,descriptor,closed,source):
                    if source==retire._snapshot_script():return response
                    return self.fake_run(root,descriptor,closed,source)
                with mock.patch.object(retire,'_run',side_effect=probe):result=retire.preflight(self.root,{})
                self.assertEqual(result['phase'],phase);self.assertNotIn('secret',json.dumps(result));self.assertEqual(self.dispatches,[])
        for raw,phase in [(None,'transport'),('not-json','json'),('{}','shape'),
                          (json.dumps({'state':'unknown','phase':'output-envelope'}),'output-envelope'),
                          (json.dumps({'state':'unknown','phase':'raw-secret'}),'shape')]:
            with mock.patch.object(retire.base,'_remote',return_value=raw):
                self.assertEqual(REAL_RUN(self.root,retire.observer._GENERATION,self.closed,'inert fixed source'),{'state':'probe-failed','phase':phase})

    def test_confirmed_status_aggregate_exceeding_host_cap_decodes_bounded_gzip(self):
        archive_value={**copy.deepcopy(self.a),'bindingSha256':self.intent['bindingSha256']}
        terminal={'retirementCorrelationId':retire._RETIREMENT,'state':'retired','bindingSha256':self.intent['bindingSha256'],'actionSha256':self.intent['actionSha256']}
        receipt={'binding':self.intent,'archive':archive_value,'terminal':terminal,'absent':True}
        raw=json.dumps({'state':'observed','receipt':receipt},separators=(',',':')).encode()
        self.assertGreater(len(raw),16384)
        packet={'state':'observed-gzip','length':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'gzip':base64.b64encode(gzip.compress(raw,mtime=0)).decode()}
        self.assertLess(len(json.dumps(packet).encode()),16384)
        with mock.patch.object(retire.base,'_remote',return_value=json.dumps(packet)):
            self.assertEqual(REAL_RUN(self.root,retire.observer._GENERATION,self.closed,'inert fixed source'),receipt)

    def test_aggregate_gzip_hash_bounds_shape_json_and_bombs_fail_closed(self):
        def packet(raw):return {'state':'observed-gzip','length':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'gzip':base64.b64encode(gzip.compress(raw,mtime=0)).decode()}
        cases=[]
        p=packet(b'{}');p['extra']='secret';cases.append((p,'gzip-envelope'))
        p=packet(b'{}');p['length']=False;cases.append((p,'gzip-envelope'))
        p=packet(b'{}');p['sha256']='0'*64;cases.append((p,'gzip-hash'))
        p=packet(b'not-json');cases.append((p,'gzip-json'))
        p=packet(b'A'*50001);p['length']=50000;cases.append((p,'gzip-bounds'))
        p=packet(b'{}');p['gzip']='!';cases.append((p,'gzip-bounds'))
        p=packet(b'{}');p['gzip']='A'*16001;cases.append((p,'gzip-envelope'))
        p=packet(b'{"same":1,"same":2}');cases.append((p,'gzip-json'))
        for value,phase in cases:
            with self.subTest(phase=phase):self.assertEqual(retire._unpack(value),{'state':'probe-failed','phase':phase})

    def test_actual_remote_out_exact_boundary_counts_print_newline(self):
        prefix=retire._REMOTE_BODY.split("\ntry:\n phase='generation'",1)[0]
        for base_value,compressed in [({'state':'observed','receipt':{'archive':''}},True),({'state':'unknown','padding':''},False)]:
            with self.subTest(compressed=compressed):
                empty=json.dumps(base_value,separators=(',',':'),sort_keys=True).encode()
                value=copy.deepcopy(base_value)
                if compressed:value['receipt']['archive']='A'*(16384-len(empty))
                else:value['padding']='A'*(16384-len(empty))
                self.assertEqual(len(json.dumps(value,separators=(',',':'),sort_keys=True).encode()),16384)
                header='import json,base64,hashlib,os,stat,sys\n'
                completed=subprocess.run([sys.executable,'-c',header+prefix+'\nout('+repr(value)+')',*(['inert']*9)],capture_output=True,text=True,timeout=10)
                self.assertEqual(completed.returncode,0,completed.stderr)
                self.assertLessEqual(len(completed.stdout.encode()),16384)
                response=json.loads(completed.stdout)
                if compressed:self.assertEqual(retire._unpack(response),value)
                else:self.assertEqual(response,{'state':'unknown','phase':'output-host-bound'})

    def test_concurrent_callers_can_dispatch_only_one_create_only_intent(self):
        barrier=threading.Barrier(2);results=[]
        admitted=(retire.observer._GENERATION,self.record,self.closed,self.source,self.intent)
        def admit(root):barrier.wait(timeout=5);return admitted
        with mock.patch.object(retire,'_admit',side_effect=admit):
            threads=[threading.Thread(target=lambda:results.append(retire.start(self.root,{}))) for _ in range(2)]
            for thread in threads:thread.start()
            for thread in threads:thread.join(timeout=10);self.assertFalse(thread.is_alive())
        self.assertEqual(len(results),2);self.assertEqual(len(self.dispatches),1)
        self.assertEqual(retire._read(self.root/retire._DIR/'intent.json'),self.intent)

    def test_actual_remote_transport_rechecks_lease_generation_and_lock_after_guest(self):
        for mode in ('good','active-before','active-after','generation-after','lock-mode','host-bound','incompressible'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);campaign=root/'windows-cp117/windows-cp117-campaign';group=root/'windows-cp117/windows-update-fixture-http-stage'
                for path in (root/'windows-cp117',campaign,group):path.mkdir(mode=0o700,exist_ok=True)
                lock=campaign/'.environment.lock';lock.write_bytes(b'');lock.chmod(0o644 if mode=='lock-mode' else 0o600)
                closed=campaign/(retire.observer._LEASE+'.closed.json');closed.write_text(json.dumps(self.closed));closed.chmod(0o600)
                if mode=='active-before':(campaign/'active.json').write_text('invalid')
                header=r'''import os,stat,sys,json,hashlib,base64
count=0
def decode(raw):return raw.decode('utf-8-sig')
def live(sock,pid,ticks):return not (MODE=='generation-after' and count>0)
def call(sock,action,args):
 global count
 if action=='guest-exec':
  assert args['arg'][2]=='-Command' and args['arg'][3]==sys.argv[-1]
  count+=1;return {'pid':1}
 if MODE=='active-after':open(os.path.join(sys.argv[1],'windows-cp117','windows-cp117-campaign','active.json'),'w').write('invalid')
 data=json.dumps({'archive':'private'*3000}).encode() if MODE=='host-bound' else b'{"submitted":true}'
 if MODE=='incompressible':data=json.dumps({'archive':''.join(hashlib.sha256(str(n).encode()).hexdigest() for n in range(600))}).encode()
 return {'exited':True,'exitcode':0,'out-data':base64.b64encode(data).decode()}
'''
                header='MODE='+repr(mode)+'\n'+header
                args=[str(root),*retire.observer._remote_arguments(retire.observer._GENERATION,self.closed),'inert-not-invoked']
                completed=subprocess.run([sys.executable,'-c',header+retire._REMOTE_BODY,*args],capture_output=True,text=True,timeout=10)
                self.assertEqual(completed.returncode,0,completed.stderr);result=json.loads(completed.stdout)
                if mode=='good':self.assertEqual(result,{'state':'observed','receipt':{'submitted':True}})
                elif mode=='host-bound':
                    self.assertEqual(result['state'],'observed-gzip');self.assertLess(len(completed.stdout.encode()),16384)
                    self.assertEqual(retire._unpack(result),{'state':'observed','receipt':{'archive':'private'*3000}})
                else:self.assertEqual(result['state'],'unknown');self.assertEqual(result['phase'],{'active-before':'active','active-after':'active','generation-after':'generation','lock-mode':'lock','host-bound':'output-host-bound','incompressible':'output-host-bound'}[mode])

    def test_active_generation_bad_intent_and_fixed_inputs_fail_closed(self):
        active=self.root/retire.base.campaign_lease._DIR/'active.json';active.write_text('not-json');active.chmod(0o600)
        self.assertEqual(retire.start(self.root,{})['phase'],'active-lease');self.assertEqual(self.calls,[]);active.unlink()
        receipt=self.root/'.rag_index/windows-cp117-staged-fixture-retire/receipt.json';receipt.unlink()
        self.assertEqual(retire.start(self.root,{})['state'],'unknown');self.assertEqual(self.dispatches,[])
        for value in ({'port':1},{'task':retire._TASK},[],None):
            with self.assertRaises(ValueError):retire.start(self.root,value)
        with mock.patch.object(retire.observer.history,'_supported',return_value=False):self.assertEqual(retire.start(self.root,{})['phase'],'platform')


if __name__=='__main__':unittest.main()
