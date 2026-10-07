"""Inert fixed5 disposal regressions; no guest, installer, owner or SSH action."""
import base64
import copy
import gzip
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
from agent_tools import windows_cp117_static_tasks_retire as r

ACTUAL_PARSE=r._parse
ACTUAL_BASE_FREE=r.base._require_base_route_free
NS='http://schemas.microsoft.com/windows/2004/02/mit/task'
def snapshot(e):
    tree=ET.Element('Task',xmlns=NS,version='1.2' if e['task']==r._NAMES[0] else '1.3');ET.SubElement(tree,'Triggers')
    p=ET.SubElement(ET.SubElement(tree,'Principals'),'Principal',id='Author')
    for key,value in [('UserId',r.wire.observer._GENERATION[4]),('LogonType','Password' if e['logonType']=='Password' else 'InteractiveToken')]:ET.SubElement(p,key).text=value
    settings=ET.SubElement(tree,'Settings')
    meta={'executionTimeLimit':e['executionTimeLimit'] or 'PT72H','multipleInstances':'IgnoreNew','restartCount':0,'startWhenAvailable':False,**{key:e[key] for key in ('allowStartOnBattery','dontStopOnBattery','runOnlyIfIdle')}}
    settings_rows=[('MultipleInstancesPolicy','IgnoreNew'),('DisallowStartIfOnBatteries',str(not e['allowStartOnBattery']).lower()),('StopIfGoingOnBatteries',str(not e['dontStopOnBattery']).lower())]
    settings_rows+= [('Enabled','false')] if e['task']==r._NAMES[0] else [('ExecutionTimeLimit',meta['executionTimeLimit']),('UseUnifiedSchedulingEngine','true')]
    for key,value in settings_rows:ET.SubElement(settings,key).text=value
    idle=ET.SubElement(settings,'IdleSettings')
    for key,value in [('Duration','PT10M'),('RestartOnIdle','false'),('StopOnIdleEnd','true'),('WaitTimeout','PT1H')]:ET.SubElement(idle,key).text=value
    a=ET.SubElement(ET.SubElement(tree,'Actions',Context='Author'),'Exec')
    for key,value in [('Command',e['execute']),('Arguments',e['arguments'])]:ET.SubElement(a,key).text=value
    raw=ET.tostring(tree,encoding='utf-8')
    return {'task':e['task'],'taskState':e['taskState'],'enabled':e['enabled'],'argumentsSha256':e['argumentsSha256'],
            'lastRunTicks':638000000000000000,'lastTaskResult':e['lastTaskResult'],
            **meta,'xmlSha256':hashlib.sha256(raw).hexdigest(),'xmlLength':len(raw),'xmlGzip':base64.b64encode(gzip.compress(raw,mtime=0)).decode()}

def packet(archives):
    rows=copy.deepcopy(archives)
    for row in rows:row['xml']=gzip.decompress(base64.b64decode(row.pop('xmlGzip'))).decode()
    raw=json.dumps({'archives':rows},separators=(',',':')).encode()
    return {'length':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'gzip':base64.b64encode(gzip.compress(raw,mtime=0)).decode()}

def change_xml(a,path,value):
    tree=ET.fromstring(gzip.decompress(base64.b64decode(a['xmlGzip'])))
    bits=path.split('/');parent=tree
    for name in bits[:-1]:parent=parent.find('{'+NS+'}'+name)
    node=parent.find('{'+NS+'}'+bits[-1])
    if node is None:node=ET.SubElement(parent,'{'+NS+'}'+bits[-1])
    node.text=value;raw=ET.tostring(tree,encoding='utf-8')
    a.update(xmlLength=len(raw),xmlSha256=hashlib.sha256(raw).hexdigest(),xmlGzip=base64.b64encode(gzip.compress(raw,mtime=0)).decode())

@unittest.skipUnless(r.history._supported(),'POSIX campaign locks required')
class StaticTasksRetirementTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        self.lease=self.root/r.base.campaign_lease._DIR;self.lease.mkdir(parents=True,mode=0o700);self.lease.parent.chmod(0o700)
        lock=self.lease/'.environment.lock';lock.write_text('');lock.chmod(0o600)
        base_directory=self.root/r.base._LOCAL;base_directory.mkdir(mode=0o700)
        base_lock=base_directory/'.environment.lock';base_lock.write_bytes(b'');base_lock.chmod(0o600)
        patch=mock.patch.object(r.base,'_descriptor',return_value=(object(),object(),r.wire.observer._GENERATION));patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(r.base,'_require_base_route_free',return_value=None);patch.start();self.addCleanup(patch.stop)
        self.expected=r._expected();self.archives=[snapshot(e) for e in self.expected]
        self.calls=[];self.dispatches=[];self.response='terminal';self.closed={'fixed':'historical'};self.desc=r.wire.observer._GENERATION
        self.local=mock.patch.object(r,'_admit_local',return_value=(self.desc,self.closed,self.expected));self.local.start();self.addCleanup(self.local.stop)
        for name in ('_fixed_c32_task_terminal','_fixed_recovery_task_terminal'):
            patch=mock.patch.object(r.base,name,return_value=True);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(r,'_run',side_effect=self.fake_run);patch.start();self.addCleanup(patch.stop)
        patch=mock.patch.object(r,'_parse',side_effect=self.parse);patch.start();self.addCleanup(patch.stop)
    def parse(self,root,desc,closed,source):self.calls.append(('parse',source));return True
    def fake_run(self,root,desc,closed,source):
        self.calls.append(('read',source))
        if 'Unregister-ScheduledTask' in source:self.dispatches.append(source);return None
        if source==r._snapshot_script(self.expected):return {'archivesPacket':packet(self.archives)}
        if source in (r._reader(self.expected),r._diagnostic_reader(self.expected)):
            if self.response=='missing':return None
            intent=r.wire._read(self.root/r._DIR/'intent.json')
            terminal={'retirementCorrelationId':r._RETIREMENT,'bindingSha256':intent['bindingSha256'],'actionSha256':intent['actionSha256'],'state':'retired'}
            progress=[{'retirementCorrelationId':r._RETIREMENT,'index':i,'bindingSha256':intent['bindingSha256'],'xmlSha256':a['xmlSha256'],'state':'removed'} for i,a in enumerate(self.archives)]
            if self.response=='corrupt':progress[2]['xmlSha256']='0'*64
            if self.response=='terminal-absent':terminal=None
            result={'binding':intent,'terminal':terminal,'archivesPacket':packet(self.archives),'progress':progress,'absent':self.response!='present'}
            if source==r._diagnostic_reader(self.expected):result['terminalAbsent']=self.response=='terminal-absent'
            return result
        raise AssertionError('unexpected fixed source')
    def test_consumed_journal_diagnostic_classifies_incomplete_without_replay(self):
        self.response='missing'
        self.assertEqual(r.start(self.root,{})['phase'],'journal')
        before=(self.root/r._DIR/'intent.json').read_bytes()
        with mock.patch.object(r,'_run',return_value={'state':'blocked','phase':'diagnostic-stage-archive'}):
            result=r.diagnose(self.root,{})
        self.assertEqual(result['state'],'unknown')
        self.assertEqual(result['phase'],'diagnostic-stage-archive')
        self.assertEqual(before,(self.root/r._DIR/'intent.json').read_bytes())
        self.assertEqual(len(self.dispatches),1)

    def test_diagnostic_does_not_change_consumed_source_and_is_readonly(self):
        self.assertEqual(r.start(self.root,{})['state'],'retired')
        intent=r.wire._read(self.root/r._DIR/'intent.json')
        source,regenerated=r._plan(intent['binding'],self.expected)
        self.assertEqual(regenerated,intent)
        with mock.patch.object(r,'_PHASES',r._PHASES | {'future-diagnostic-only'}):
            self.assertEqual(r._plan(intent['binding'],self.expected),(source,intent))
        diagnostic=r._diagnostic_reader(self.expected)
        for forbidden in ('Unregister-ScheduledTask','Write-SecureJsonCreate','Initialize-SecureJournal','CreateDirectory','CreateNew','FileAccess]::Write'):
            self.assertNotIn(forbidden,diagnostic)
        self.assertIn('UTF8Encoding]::new($false,$true)',diagnostic)
        self.assertIn('[IO.FileShare]::None',diagnostic)
        self.assertIn('Assert-Root $JournalRoot',diagnostic)
        self.assertIn("for($i=0;$i -lt 5;$i++){Absent $expected[$i]};Idle",diagnostic)
        self.assertEqual(r.diagnose(self.root,{})['phase'],'diagnostic-complete')
        self.assertEqual(self.calls[-2][0],'parse')
        self.assertEqual(self.calls[-1],('read',diagnostic))
        self.assertEqual(len(self.dispatches),1)

    def test_diagnostic_finite_failures_never_promote_or_create_receipt(self):
        self.response='missing';r.start(self.root,{})
        before={p:p.read_bytes() for p in (self.root/r._DIR).iterdir()}
        for phase in r._DIAGNOSTIC_PHASES:
            with self.subTest(phase=phase),mock.patch.object(r,'_run',return_value={'state':'blocked','phase':phase}):
                result=r.diagnose(self.root,{})
                self.assertEqual(result,r._result('unknown',phase))
        with mock.patch.object(r,'_parse',return_value=False),mock.patch.object(r,'_run') as run:
            self.assertEqual(r.diagnose(self.root,{})['phase'],'parser');run.assert_not_called()
        with mock.patch.object(r,'_run',return_value={'state':'blocked','phase':'foreign-raw-secret'}):
            self.assertEqual(r.diagnose(self.root,{})['phase'],'diagnostic-schema')
        self.assertEqual(before,{p:p.read_bytes() for p in (self.root/r._DIR).iterdir()})
        self.assertEqual(len(self.dispatches),1)

    def test_measured_missing_terminal_can_only_report_verified_unknown_absence(self):
        self.response='terminal-absent'
        self.assertEqual(r.start(self.root,{})['state'],'unknown')
        before=(self.root/r._DIR/'intent.json').read_bytes()
        reads=len(self.calls)
        value=r.diagnose(self.root,{})
        self.assertEqual(value,r._result('unknown','diagnostic-terminal-absent-verified'))
        self.assertEqual(sum(kind=='read' for kind,source in self.calls[reads:]),2)
        self.assertEqual(r.status(self.root,{})['state'],'unknown')
        self.assertEqual(r.start(self.root,{})['state'],'unknown')
        self.assertEqual(len(self.dispatches),1)
        self.assertEqual(before,(self.root/r._DIR/'intent.json').read_bytes())

    def test_missing_terminal_rejects_progress_archive_binding_absence_and_second_read_drift(self):
        self.response='terminal-absent';r.start(self.root,{})
        before=(self.root/r._DIR/'intent.json').read_bytes()
        for kind in ('progress','archive','binding','absence','terminal-presence','second-read'):
            count=[0]
            def read(root,desc,closed,source):
                value=self.fake_run(root,desc,closed,source)
                count[0]+=1
                if kind=='progress':value['progress'][3]['xmlSha256']='0'*64
                elif kind=='archive':value['archivesPacket']['sha256']='0'*64
                elif kind=='binding':value['binding']=dict(value['binding'],actionSha256='0'*64)
                elif kind=='absence':value['absent']=False
                elif kind=='terminal-presence':value['terminalAbsent']=False
                elif count[0]==2:value['progress'][3]['state']='unknown'
                return value
            with self.subTest(kind=kind),mock.patch.object(r,'_run',side_effect=read):
                result=r.diagnose(self.root,{})
                self.assertEqual(result['state'],'unknown')
                self.assertNotEqual(result['phase'],'diagnostic-terminal-absent-verified')
        self.assertEqual(before,(self.root/r._DIR/'intent.json').read_bytes())
        self.assertEqual(len(self.dispatches),1)

    def test_actual_five_task_census_stays_blocked_until_fixed_retirement(self):
        # Actual native block is five retained tasks; count alone never authorizes disposal.
        census={'version':2,'legacyTaskCount':0,'c32TaskCount':1,'recoveryTaskCount':1,'otherTaskCount':5,'activeInstallerCount':0}
        with mock.patch.object(r.base,'_descriptor',return_value=(None,None,self.desc)),mock.patch.object(r.base,'_remote',return_value=json.dumps({'state':'observed','inventory':census})):
            self.assertEqual(r.base._legacy_task_observation(self.root,self.desc,r._RETIREMENT)['state'],'blocked')
        before=set(self.root.rglob('*'));self.assertEqual(r.preflight(self.root,{})['state'],'ready')
        self.assertEqual(before,set(self.root.rglob('*')));self.assertEqual(self.dispatches,[])
    def test_one_batch_archives_all_before_first_delete_and_never_replays(self):
        self.assertEqual(r.start(self.root,{})['state'],'retired');self.assertEqual(len(self.dispatches),1)
        source=self.dispatches[0]
        self.assertLess(source.index("Write-SecureJsonCreate 'archive.json'"),source.index('Unregister-ScheduledTask'))
        self.assertLess(source.index("$savedArchives=@(ReadArchives)"),source.index('Unregister-ScheduledTask'))
        self.assertIn("Write-SecureJsonCreate ('removed-'",source)
        self.assertEqual((self.root/r._DIR/'intent.json').stat().st_mode&0o777,0o600)
        for action in (r.start,r.preflight,r.status):self.assertEqual(action(self.root,{})['state'],'retired')
        self.assertEqual(r.diagnose(self.root,{})['phase'],'diagnostic-complete')
        self.assertEqual(len(self.dispatches),1)
    def test_concurrent_start_create_only_intent_dispatches_at_most_once(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:r.start(self.root,{}),range(2)))
        self.assertEqual(len(self.dispatches),1)
        self.assertIn('retired',[value['state'] for value in results])
        self.assertEqual(r.start(self.root,{})['state'],'retired');self.assertEqual(len(self.dispatches),1)

    def test_base_wins_unknown_intent_static_start_never_consumes(self):
        path=self.root/r.base._LOCAL/'foreign.json';path.write_text('{}');path.chmod(0o600)
        with mock.patch.object(r.base,'_require_base_route_free',side_effect=ACTUAL_BASE_FREE),mock.patch.object(r.base,'_archived_base_record_names',return_value=set()):
            result=r.start(self.root,{})
        self.assertEqual((result['state'],result['phase']),('blocked','base-route'))
        self.assertFalse((self.root/r._DIR/'intent.json').exists());self.assertEqual(self.dispatches,[])

    def test_static_wins_unknown_intent_queued_base_reservation_never_consumes(self):
        entered=threading.Event();release=threading.Event();original=r._proof;self.response='missing'
        def held(root):
            entered.set();self.assertTrue(release.wait(5));return original(root)
        record={'request':{'correlationId':'0d4d67c5-b593-42e5-a83e-c78736646638'}}
        def reserve():
            try:r.base._reserve(self.root,record,config=object(),target=object(),descriptor=self.desc)
            except r.base.WindowsMsiBasePrepareError:return 'blocked'
            return 'reserved'
        with mock.patch.object(r,'_proof',side_effect=held),mock.patch.object(r.base,'_archived_base_record_names',return_value=set()):
            with ThreadPoolExecutor(max_workers=2) as pool:
                static=pool.submit(r.start,self.root,{})
                self.assertTrue(entered.wait(5))
                fd=os.open(self.root/r.base._LOCAL/'.environment.lock',os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):r.history.fcntl.flock(fd,r.history.fcntl.LOCK_EX|r.history.fcntl.LOCK_NB)
                finally:os.close(fd)
                base=pool.submit(reserve);release.set()
                self.assertEqual(static.result(5)['state'],'unknown');self.assertEqual(base.result(5),'blocked')
        self.assertEqual(len(self.dispatches),1)
        self.assertFalse((self.root/r.base._LOCAL/(record['request']['correlationId']+'.json')).exists())

    def test_start_requires_existing_private_base_lock(self):
        path=self.root/r.base._LOCAL/'.environment.lock';path.chmod(0o644)
        self.assertEqual(r.start(self.root,{})['phase'],'base-lock');path.chmod(0o600)
        path.unlink();self.assertEqual(r.start(self.root,{})['phase'],'base-lock')
        self.assertFalse((self.root/r._DIR/'intent.json').exists());self.assertEqual(self.dispatches,[])

    def test_partial_delete_missing_batch_terminal_forever_unknown_status_only(self):
        self.response='missing';self.assertEqual(r.start(self.root,{})['state'],'unknown')
        before=set(self.root.rglob('*'));count=len(self.calls)
        for action in (r.start,r.preflight,r.diagnose,r.status):self.assertEqual(action(self.root,{})['state'],'unknown')
        self.assertEqual(len(self.dispatches),1);self.assertEqual(before,set(self.root.rglob('*')))
        self.assertFalse(any(source==r._snapshot_script(self.expected) for mode,source in self.calls[count:]))
    def test_exact_action_principal_xml_trigger_and_settings_reject(self):
        for path,value in [('Actions/Exec/Command','foreign.exe'),('Actions/Exec/Arguments','foreign'),
                           ('Principals/Principal/UserId','S-1-5-18'),('Principals/Principal/RunLevel','HighestAvailable'),
                           ('Triggers/BootTrigger',''),('Settings/RestartOnFailure',''),
                           ('Settings/Enabled','false'),('Settings/ExecutionTimeLimit','PT0S')]:
            with self.subTest(path=path):
                a=snapshot(self.expected[1]);change_xml(a,path,value)
                with self.assertRaises(r.Blocked):r._archive(a,self.expected[1])
    def test_extra_effect_settings_and_principal_never_reserve(self):
        for path,value in [('Settings/WakeToRun','true'),('Principals/Principal/ProcessTokenSidType','Unrestricted'),('Actions/Exec/Foreign','true')]:
            with self.subTest(path=path):
                self.archives=[snapshot(e) for e in self.expected];change_xml(self.archives[1],path,value)
                self.assertEqual(r.start(self.root,{})['state'],'blocked')
                self.assertFalse((self.root/r._DIR/'intent.json').exists());self.assertEqual(self.dispatches,[])

    def test_native_xml_shape_exact_attributes_namespaces_and_idle_settings(self):
        for path,value in [('Settings/UseUnifiedSchedulingEngine','false'),('Settings/IdleSettings/StopOnIdleEnd','false'),('Principals/Principal/RunLevel','LeastPrivilege')]:
            a=snapshot(self.expected[1]);change_xml(a,path,value)
            with self.assertRaises(r.Blocked):r._archive(a,self.expected[1])
        for node,attribute in [('Task','foreign'),('Actions','foreign'),('Exec','foreign'),('Principal','foreign')]:
            a=snapshot(self.expected[1]);tree=ET.fromstring(gzip.decompress(base64.b64decode(a['xmlGzip'])))
            target=tree if node=='Task' else tree.find('.//{'+NS+'}'+node);target.set(attribute,'true')
            raw=ET.tostring(tree,encoding='utf-8');a.update(xmlLength=len(raw),xmlSha256=hashlib.sha256(raw).hexdigest(),xmlGzip=base64.b64encode(gzip.compress(raw,mtime=0)).decode())
            with self.assertRaises(r.Blocked):r._archive(a,self.expected[1])

    def test_duplicate_xml_sections_and_decorated_user_reject(self):
        for section in ('Actions','Principals','Triggers','Settings','UserId'):
            with self.subTest(section=section):
                a=snapshot(self.expected[1]);tree=ET.fromstring(gzip.decompress(base64.b64decode(a['xmlGzip'])))
                if section=='UserId':tree.find('.//{'+NS+'}UserId').set('foreign','true')
                else:tree.append(copy.deepcopy(tree.find('{'+NS+'}'+section)))
                raw=ET.tostring(tree,encoding='utf-8');a.update(xmlLength=len(raw),xmlSha256=hashlib.sha256(raw).hexdigest(),xmlGzip=base64.b64encode(gzip.compress(raw,mtime=0)).decode())
                with self.assertRaises(r.Blocked):r._archive(a,self.expected[1])

    def test_running_pending_foreign_action_or_automatic_settings_cannot_reserve(self):
        for key,value in [('taskState','Running'),('lastRunTicks',0),('argumentsSha256','0'*64),('restartCount',1),('startWhenAvailable',True),('enabled',False),('multipleInstances','Parallel')]:
            with self.subTest(key=key):
                self.archives=[snapshot(e) for e in self.expected];self.archives[1][key]=value
                self.assertNotEqual(r.start(self.root,{})['state'],'retired');self.assertEqual(self.dispatches,[])
                self.assertFalse((self.root/r._DIR/'intent.json').exists())
    def test_race_snapshot_changed_never_reserves(self):
        count=0
        def raced(root,desc,closed,source):
            nonlocal count
            value=self.fake_run(root,desc,closed,source)
            if source==r._snapshot_script(self.expected):
                count+=1
                if count==2:
                    rows=r._unpack_archives(value['archivesPacket']);rows[0]['lastRunTicks']+=1;value['archivesPacket']=packet(rows)
            return value
        with mock.patch.object(r,'_run',side_effect=raced):self.assertEqual(r.start(self.root,{})['phase'],'race')
        self.assertFalse((self.root/r._DIR/'intent.json').exists())
    def test_corrupt_progress_and_present_task_never_terminal(self):
        self.assertEqual(r.start(self.root,{})['state'],'retired')
        self.response='corrupt';self.assertEqual(r.status(self.root,{})['state'],'unknown')
        self.response='present';self.assertEqual(r.status(self.root,{})['phase'],'absence')
        self.assertEqual(len(self.dispatches),1)
    def test_actual_sources_parse_before_reads_and_transport_binds_full_bytes(self):
        self.assertEqual(r.preflight(self.root,{})['state'],'ready')
        self.assertEqual(self.calls[0],('parse',r._snapshot_script(self.expected)))
        for mode,source in self.calls:
            if mode=='parse':
                command=r.wire._command(source);self.assertLess(len(command),30000)
                packed=command.split("FromBase64String('",1)[1].split("')",1)[0]
                self.assertEqual(gzip.decompress(base64.b64decode(packed)),source.encode('utf-16le'))
        for source in (r._snapshot_script(self.expected),r._reader(self.expected)):
            for mutation in ('Unregister-ScheduledTask','Start-ScheduledTask','Stop-Process','Stop-Service','Start-Service','& $cli','msiexec.exe\' -'):
                self.assertNotIn(mutation,source)
        with mock.patch.object(r,'_parse',return_value=False):self.assertEqual(r.start(self.root,{})['phase'],'parser')
        self.assertEqual(self.dispatches,[])
    def test_archive_gzip_hash_bombs_entities_reject(self):
        for raw in (b'A'*131073,b'<!DOCTYPE Task [<!ENTITY x "x">]><Task/>',b'<Task/>'):
            a=snapshot(self.expected[0]);a.update(xmlLength=min(len(raw),131072),xmlSha256=hashlib.sha256(raw).hexdigest(),xmlGzip=base64.b64encode(gzip.compress(raw,mtime=0)).decode())
            with self.assertRaises(r.Blocked):r._archive(a,self.expected[0])
        a=snapshot(self.expected[0]);a['xmlSha256']='0'*64
        with self.assertRaises(r.Blocked):r._archive(a,self.expected[0])
    def test_active_missing_lock_platform_inputs_fail_closed(self):
        for raw in ('{}','not-json','{"foreign":true}'):
            active=self.lease/'active.json';active.write_text(raw);active.chmod(0o600)
            self.assertEqual(r.start(self.root,{})['phase'],'active-lease');self.assertEqual(self.dispatches,[]);active.unlink()
        (self.lease/'.environment.lock').unlink();self.assertNotEqual(r.start(self.root,{})['state'],'retired')
        with mock.patch.object(r.history,'_supported',return_value=False):self.assertEqual(r.start(self.root,{})['phase'],'platform')
        with self.assertRaises(ValueError):r.start(self.root,{'task':'foreign'})
    def test_real_static_nested_local_admission_reuses_campaign_descriptor(self):
        self.local.stop()
        directory=self.root/'.rag_index'/'original';directory.mkdir(mode=0o700)
        path=directory/'record.json';raw=b'{"original":"unknown"}';path.write_bytes(raw);path.chmod(0o600)
        records={str(path.relative_to(self.root)):hashlib.sha256(raw).hexdigest()}
        actual=r.history.fcntl.flock;shared=[]
        def tracked(fd,operation):
            if operation==r.history.fcntl.LOCK_SH:shared.append(fd)
            return actual(fd,operation)
        def nested(root,descriptor):
            outer=r.history._READ_LOCK_STATE.token
            with r.history._history_lock(root):self.assertIs(r.history._READ_LOCK_STATE.token,outer)
            return {},self.closed
        with mock.patch.object(r,'_RECORDS',records),mock.patch.object(r.wire.observer,'_admit',side_effect=nested),mock.patch.object(r.history.fcntl,'flock',side_effect=tracked):
            self.assertEqual(r.preflight(self.root,{})['state'],'ready')
        self.assertEqual(len(shared),1)
        self.assertFalse(hasattr(r.history._READ_LOCK_STATE,'token'))

    def test_actual_private_history_readers_reject_unsafe_corrupt_and_duplicate(self):
        self.local.stop()
        directory=self.root/'.rag_index'/'original';directory.mkdir(mode=0o700)
        path=directory/'record.json';raw=b'{"original":"unknown"}';path.write_bytes(raw);path.chmod(0o600)
        records={str(path.relative_to(self.root)):hashlib.sha256(raw).hexdigest()}
        with mock.patch.object(r,'_RECORDS',records),mock.patch.object(r.base,'_descriptor',return_value=(None,None,self.desc)),mock.patch.object(r.wire.observer,'_admit',return_value=({},self.closed)):
            self.assertEqual(r._admit_local(self.root)[0],self.desc)
            before=path.read_bytes()
            path.chmod(0o644)
            with self.assertRaises((ValueError,OSError)):r._admit_local(self.root)
            path.chmod(0o600);path.write_bytes(b'{"original":"unknown","original":"unknown"}')
            with self.assertRaises((ValueError,OSError)):r._admit_local(self.root)
            path.write_bytes(before);path.rename(directory/'target.json');path.symlink_to(directory/'target.json')
            with self.assertRaises((ValueError,OSError)):r._admit_local(self.root)
            self.assertEqual((directory/'target.json').read_bytes(),before)

    def test_guest_process_installer_and_transport_failures_are_finite(self):
        for phase in ('process','installer','principal','settings'):
            with mock.patch.object(r,'_run',return_value={'state':'blocked','phase':phase}):
                value=r.start(self.root,{})
                self.assertEqual((value['state'],value['phase']),('blocked',phase))
                self.assertEqual(set(value),{'state','phase','retirementCorrelationId',*r._FLAGS})
            self.assertFalse((self.root/r._DIR/'intent.json').exists())
        phase=next(iter(r.wire._PROBE_PHASES))
        with mock.patch.object(r,'_run',return_value={'state':'probe-failed','phase':phase}):self.assertEqual(r.preflight(self.root,{})['phase'],'transport-'+phase)

    def test_measured_native_xml_lengths_fit_single_archive_packet(self):
        # Exact native scalar byte lengths, not a claim that synthetic XML is native evidence.
        measured=(8239,11208,1246,12239,12423);rows=[]
        for e,size in zip(self.expected,measured):
            a=snapshot(e);tree=ET.fromstring(gzip.decompress(base64.b64decode(a['xmlGzip'])))
            description=ET.SubElement(ET.SubElement(tree,'{'+NS+'}RegistrationInfo'),'{'+NS+'}Description');description.text='x'
            first=ET.tostring(tree,encoding='utf-8');description.text='x'*(size-len(first)+1)
            raw=ET.tostring(tree,encoding='utf-8');self.assertEqual(len(raw),size)
            a.update(xmlLength=size,xmlSha256=hashlib.sha256(raw).hexdigest(),xmlGzip=base64.b64encode(gzip.compress(raw,mtime=0)).decode());rows.append(a)
        value=packet(rows);self.assertLessEqual(value['length'],50000);self.assertLessEqual(len(value['gzip']),15000)
        for a,e in zip(r._unpack_archives(value),self.expected):r._archive(a,e)

    def test_actual_50607_archive_expansion_admitted_but_52001_denied(self):
        rows=copy.deepcopy(self.archives)
        for row in rows:row['xml']=gzip.decompress(base64.b64decode(row.pop('xmlGzip'))).decode()
        raw=json.dumps({'archives':rows},separators=(',',':')).encode()
        for length,allowed in ((50607,True),(52001,False)):
            actual=raw+b' '*(length-len(raw))
            value={'length':length,'sha256':hashlib.sha256(actual).hexdigest(),'gzip':base64.b64encode(gzip.compress(actual,mtime=0)).decode()}
            if allowed:self.assertEqual(len(r._unpack_archives(value)),5)
            else:
                with self.assertRaises(r.Blocked):r._unpack_archives(value)
        truncated=packet(self.archives);truncated['gzip']=truncated['gzip'][:-4]
        with self.assertRaises(r.Blocked):r._unpack_archives(truncated)

    def test_private_packet_transport_bounded_hash_and_duplicate_schema(self):
        value=packet(self.archives)
        self.assertEqual([r._archive(a,e) for a,e in zip(r._unpack_archives(value),self.expected)],[r._archive(a,e) for a,e in zip(self.archives,self.expected)])
        for raw in (b'A'*52001,b'{"archives":[],"archives":[]}'):
            bad={'length':min(len(raw),52000),'sha256':hashlib.sha256(raw).hexdigest(),'gzip':base64.b64encode(gzip.compress(raw,mtime=0)).decode()}
            with self.assertRaises(r.Blocked):r._unpack_archives(bad)
        bad=dict(value,sha256='0'*64)
        with self.assertRaises(r.Blocked):r._unpack_archives(bad)
        # Snapshot/status emit packet directly; no nested XML Base64 transport inflation.
        self.assertIn('archivesPacket=(PackArchives $all)',r._snapshot_script(self.expected))
        self.assertIn("archivesPacket=(Read-SecureJson 'archive.json')",r._reader(self.expected))
        self.assertLess(len(json.dumps({'archivesPacket':value}))+1,16384)
        self.assertEqual(r.start(self.root,{})['state'],'retired')
        result=self.fake_run(self.root,self.desc,self.closed,r._reader(self.expected))
        raw=json.dumps({'state':'observed','receipt':result},separators=(',',':')).encode()
        encoded=base64.b64encode(gzip.compress(raw,mtime=0)).decode()
        self.assertLessEqual(len(raw),50000);self.assertLessEqual(len(encoded),16000)
        envelope={'state':'observed-gzip','length':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'gzip':encoded}
        self.assertEqual(r.wire._unpack(envelope),{'state':'observed','receipt':result})


    def test_actual_remote_delayed_reply_keeps_shared_lock_and_does_not_resubmit(self):
        root=self.root/'remote';root.mkdir(mode=0o700)
        campaign=root/'windows-cp117/windows-cp117-campaign';group=root/'windows-cp117/windows-update-fixture-http-stage'
        for path in (root/'windows-cp117',campaign,group):path.mkdir(mode=0o700)
        lock=campaign/'.environment.lock';lock.write_bytes(b'');lock.chmod(0o600)
        closed=campaign/(r.wire.observer._LEASE+'.closed.json');closed.write_text(json.dumps(self.closed));closed.chmod(0o600)
        header=r"""import os,stat,sys,json,hashlib,base64,fcntl,time
time.sleep=lambda n:None
polls=0;dispatches=0
def decode(raw):return raw.decode('utf-8-sig')
def live(sock,pid,ticks):return True
def call(sock,action,args):
 global polls,dispatches
 if action=='guest-exec':
  dispatches+=1;assert dispatches==1;return {'pid':1}
 fd=os.open(os.path.join(sys.argv[1],'windows-cp117/windows-cp117-campaign/.environment.lock'),os.O_RDONLY)
 try:
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:pass
  else:raise AssertionError('lease shared lock released before guest exit')
 finally:os.close(fd)
 polls+=1
 if polls<44:return {'exited':False}
 return {'exited':True,'exitcode':0,'out-data':base64.b64encode(b'{"submitted":true}').decode()}
"""
        args=[str(root),*r.wire.observer._remote_arguments(self.desc,self.closed),'inert-not-invoked']
        results=[]
        for body in (r.wire._REMOTE_BODY,r._REMOTE_BODY):
            done=subprocess.run([sys.executable,'-c',header+body,*args],capture_output=True,text=True,timeout=5)
            self.assertEqual(done.returncode,0,done.stderr);results.append(json.loads(done.stdout))
        self.assertEqual(results[0],{'state':'unknown','phase':'status'})
        self.assertEqual(results[1],{'state':'observed','receipt':{'submitted':True}})

    def test_actual_ast_gate_binds_source_and_stops_on_invalid(self):
        source=r._snapshot_script(self.expected)
        self.assertIn('try{',source)
        with mock.patch.object(r,'_run',return_value={'version':1,'code':'FAILED'}) as transport:
            self.assertFalse(ACTUAL_PARSE(self.root,self.desc,self.closed,source))
            parser=transport.call_args.args[-1]
            packed=parser.split("FromBase64String('",1)[1].split("')",1)[0]
            self.assertEqual(gzip.decompress(base64.b64decode(packed)),source.encode('utf-16le'))
            self.assertIn('Parser]::ParseInput',parser)
            self.assertNotIn('Invoke-Expression',parser)
        with mock.patch.object(r,'_parse',return_value=False),mock.patch.object(r,'_run') as dispatch:
            self.assertEqual(r.start(self.root,{})['phase'],'parser');dispatch.assert_not_called()

    def test_actual_diagnostic_ast_gate_exact_bytes_and_no_reader_after_failure(self):
        self.response='missing';r.start(self.root,{})
        source=r._diagnostic_reader(self.expected)
        before=(self.root/r._DIR/'intent.json').read_bytes()
        for code,accepted in (('OK',True),('FAILED',False)):
            with self.subTest(code=code),mock.patch.object(r,'_run',return_value={'version':1,'code':code}) as transport:
                self.assertEqual(ACTUAL_PARSE(self.root,self.desc,self.closed,source),accepted)
                transport.assert_called_once()
                parser=transport.call_args.args[-1]
                packed=parser.split("FromBase64String('",1)[1].split("')",1)[0]
                self.assertEqual(gzip.decompress(base64.b64decode(packed)),source.encode('utf-16le'))
                self.assertIn('Parser]::ParseInput',parser)
                for execution in ('Invoke-Expression','ScriptBlock]::Create','& $','Unregister-ScheduledTask','Read-SecureJson'):
                    self.assertNotIn(execution,parser)
        with mock.patch.object(r,'_parse',side_effect=ACTUAL_PARSE),mock.patch.object(r,'_run',return_value={'version':1,'code':'FAILED'}) as transport:
            self.assertEqual(r.diagnose(self.root,{}),r._result('unknown','parser'))
            transport.assert_called_once()
            parser=transport.call_args.args[-1]
            packed=parser.split("FromBase64String('",1)[1].split("')",1)[0]
            self.assertEqual(gzip.decompress(base64.b64decode(packed)),source.encode('utf-16le'))
        self.assertEqual(before,(self.root/r._DIR/'intent.json').read_bytes())
        self.assertEqual(len(self.dispatches),1)

    def test_archive_leaf_budget_and_expanded_bound_are_fixed(self):
        self.assertEqual(len(r._LEAVES),8)
        rows=copy.deepcopy(self.archives)
        nested=json.dumps({'archives':rows},separators=(',',':')).encode()
        self.assertGreater(len(base64.b64encode(gzip.compress(nested,mtime=0))),15000)
        for row in rows:row['xml']=gzip.decompress(base64.b64decode(row.pop('xmlGzip'))).decode()
        raw=json.dumps({'archives':rows},separators=(',',':')).encode()
        packed=base64.b64encode(gzip.compress(raw,mtime=0)).decode()
        self.assertLessEqual(len(raw),50000);self.assertLessEqual(len(packed),15000)
        envelope=json.dumps({'length':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'gzip':packed},separators=(',',':')).encode()
        self.assertLessEqual(len(envelope)+1,16384)
        source=r._common(self.expected)
        self.assertIn('$out.Length+$n -gt 52000',source)
        self.assertIn('$packed.Length -gt 15000',source)

    def test_foreign_generation_or_missing_current_proof_cannot_reserve(self):
        for name in ('_fixed_c32_task_terminal','_fixed_recovery_task_terminal'):
            with mock.patch.object(r.base,name,return_value=False):self.assertEqual(r.start(self.root,{})['phase'],'history')
            self.assertEqual(self.dispatches,[])
        with mock.patch.object(r,'_admit_local',side_effect=r.Blocked('generation')):self.assertEqual(r.start(self.root,{})['phase'],'generation')
        self.assertFalse((self.root/r._DIR/'intent.json').exists())

    def test_native_bound_expected_actions_and_product_source_separate(self):
        self.assertEqual(tuple(hashlib.sha256(e['arguments'].encode()).hexdigest() for e in self.expected),r._ARGUMENT_HASHES)
        self.assertIn('PT0S',[e['executionTimeLimit'] for e in self.expected])
        result=r.preflight(self.root,{})
        for secret in ('arguments','xmlGzip',r._SOURCE,r._CLI,r.wire.observer._GENERATION[4]):self.assertNotIn(secret,json.dumps(result))

if __name__=='__main__':unittest.main()
