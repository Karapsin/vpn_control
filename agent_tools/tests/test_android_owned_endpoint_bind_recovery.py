"""Measured still-linked d959 bind recovery, isolated from historical cleanup."""
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from agent_tools.tests import test_android_endpoint_admission as legacy

class OwnedEndpointBindRecoveryTest(unittest.TestCase):
    def test_measured_still_linked_bind_needs_distinct_recovery(self):
        tc=legacy.AndroidCleanupReadmissionTest('runTest')
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();expected,state,base,binding=tc.remaining_fixture(root)
            def command(argv,**kwargs):
                words=argv[5:] if argv[3:5]==['shell','-T'] else []
                if '%d:%i:%h:%F' in words and '/system/bin/nsenter' in words:
                    return SimpleNamespace(returncode=0,stdout=b'64800:65543:2:directory',stderr=b'')
                return base(argv,**kwargs)
            result=tc.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-admit',command)
            self.assertEqual('remaining_target_unlinked',result['reason']);self.assertEqual([],state['effects'])

import ast
import base64
import contextlib
import hashlib
import io
import json
import os
import stat
import subprocess
from unittest import mock
from agent_tools import android_owned_endpoint_bind_recovery as recovery

NEW_ID='70b81089-706b-4712-b837-75f8703aec1d'
PLAN={'staging':'/data/local/tmp/vpn-control-endpoint-'+recovery.ORIGINAL,'stagingIdentity':'0:755:64800:65543','target':recovery.TARGET,'zygote':{'pid':'6654','startTicks':46432071,'namespace':'mnt:[4026532630]'}}
STAGE_GEN='0:0:755:64800:65543:2:4096:100:100:directory'
STOCK_GEN='0:0:755:64258:1142:2:4096:100:100:directory'
OWN_ROOT='/local/tmp/vpn-control-endpoint-'+recovery.ORIGINAL
OWN_MOUNT='664 94 253:32 '+OWN_ROOT+' '+recovery.TARGET+' rw - ext4 /dev/block/vdc rw'
STOCK_MOUNT='25 1 251:2 / / ro,nodev,relatime shared:1 - ext4 /dev/block/dm-2 ro,seclabel'

def trees(mounted=True):
    manifest={f'{x:08x}.0':{'size':20,'sha256':hashlib.sha256(str(x).encode()).hexdigest()} for x in range(138)}
    generations={k:f'0:0:644:64258:{1200+n}:1:20:100:100:regular file' for n,k in enumerate(manifest)}
    stock={'manifest':manifest,'generations':generations,'targetGeneration':STOCK_GEN,'stageGeneration':STAGE_GEN,'membership':{'fields':STOCK_MOUNT.split(' - ')[0].split(),'filesystem':'ext4','source':'/dev/block/dm-2','options':'ro,seclabel'}}
    target=STAGE_GEN if mounted else STOCK_GEN;mounts=STOCK_MOUNT+'\n94 25 253:32 / /data rw - ext4 /dev/block/vdc rw'+('\n'+OWN_MOUNT if mounted else '')
    lines=['__NS__',PLAN['zygote']['namespace'],'__TARGET__',target,'__FD__',target,'__LINK__',PLAN['target'],'__FDINFO__','mnt_id: '+('664' if mounted else '25'),'__MOUNTS__',*mounts.splitlines(),'__FILES__']
    for name,item in manifest.items():
        g=generations[name] if not mounted else generations[name].replace('64258:','64800:')
        lines.extend(['NAME|'+name,g,item['sha256']+'  /proc/123/fd/3/'+name,g])
    if mounted:
        g='0:0:644:64800:65544:1:1188:100:100:regular file';lines.extend(['NAME|'+recovery.CA_NAME,g,recovery.CA_SHA+'  /proc/123/fd/3/'+recovery.CA_NAME,g])
    lines.extend(['__AFTER__',target,target,'__MOUNTS_AFTER__',*mounts.splitlines(),'__END__'])
    return '\n'.join(lines),stock

class GeneratedRecoveryHarness:
    def __init__(self,root):
        self.root=root;self.job=root/('android-endpoint-'+recovery.ORIGINAL);self.job.mkdir(mode=0o700)
        self.original={'intent.json':{'historical':'unknown'},'checkpoint-cleanup-unmount.json':{'phase':'cleanup-unmount'}}
        for name,value in self.original.items():recovery._write(self.job/name,value)
        self.mounted=True;self.effects=[];self.before_effect_failure=False;self.effect_failure=None;self.pid_drift=False;self.owner='fresh-owner';self.calls=0
        self.binding={'correlationId':NEW_ID,'endpointCorrelationId':recovery.ORIGINAL,'originalIntentSha256':'f'*64}
        self.bundle={'binding':self.binding,'source':{'helperSha256':'a'*64,'endpointSha256':recovery.ENDPOINT_SHA},'proofs':[]}
    def pair(self,mounted):
        self.calls+=1
        if self.before_effect_failure and (self.job/('owned-bind-'+NEW_ID+'.attempt.json')).exists():self.unknown('bind_owner_changed')
        if self.pid_drift:self.unknown('bind_zygote_changed')
        if mounted!=self.mounted:self.unknown('bind_mount_still_referenced' if self.mounted else 'bind_receipt_stale')
        # The actual parser is exercised in both pre/post snapshots, before compact receipt proof.
        text,stock=trees(mounted);tree=recovery._parse_tree(text,PLAN,stock,mounted,True)
        return {'public':{'owner':self.owner,'revision':1,'rulesSha256':'b'*64},'directories':{},'view':{'namespace':tree['namespace'],'membership':tree['membership'],'manifestSha':hashlib.sha256(json.dumps(tree['manifest'],sort_keys=True).encode()).hexdigest()}}
    def unknown(self,reason):self.emit('unknown',reason)
    def emit(self,state,reason,**extra):raise StopIteration({'state':state,'reason':reason,**extra})
    def private(self,path,*a):return path.read_bytes()
    def pin(self,path,*a):
        value,digest,fp=recovery._private(path);return {'sha256':digest,'generation':fp}
    def native(self,argv,**kwargs):
        self.effects.append(argv)
        assert (self.job/('owned-bind-'+NEW_ID+'.attempt.json')).exists()
        if self.effect_failure=='returncode':return SimpleNamespace(returncode=1,stdout=b'',stderr=b'bounded refusal')
        self.mounted=False
        if self.effect_failure=='timeout':raise subprocess.TimeoutExpired(argv,30)
        return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    def execute(self,action):
        source=ast.parse(recovery._REMOTE);function=next(n for n in source.body if isinstance(n,ast.FunctionDef) and n.name=='operate')
        scope={'lease_lock':lambda:1,'release_lock':lambda _:None,'private':self.private,'private_guard':lambda:PLAN,'plan':PLAN,'current_attempt_pin':None,'BUNDLE':self.bundle,'base_binding':self.binding,'NEW_ID':NEW_ID,'job':self.job,'reserve':self.job/'owned-bind-recovery-reservation.json','admitpath':self.job/('owned-bind-'+NEW_ID+'.json'),'attempt':self.job/('owned-bind-'+NEW_ID+'.attempt.json'),'terminal':self.job/('owned-bind-'+NEW_ID+'.recovered.json'),'action':action,'os':os,'json':json,'pair':self.pair,'record':recovery._write,'emit':self.emit,'fail':self.unknown,'remaining_pin':self.pin,'adb':'/opt/android-sdk/platform-tools/adb','serial':'emulator-5684','subprocess':SimpleNamespace(run=self.native,TimeoutExpired=subprocess.TimeoutExpired,DEVNULL=subprocess.DEVNULL,PIPE=subprocess.PIPE),'hashlib':hashlib,'base64':base64}
        exec(compile(ast.Module(body=[function],type_ignores=[]),'<actual-generated-owned-recovery>','exec'),scope)
        try:scope['operate']()
        except StopIteration as e:return e.value
        raise AssertionError('missing finite result')
    def admit(self):
        result=self.execute('owned-bind-admit');assert result['state']=='ready',result
        self.bundle.update({k:result[k] for k in ('receipt','receiptPin','reservationPin')});return result

class OwnedBindGeneratedTest(unittest.TestCase):
    def test_actual_generated_leftover_bind_one_unmount_then_stock_verified_old_unknown_preserved(self):
        with tempfile.TemporaryDirectory() as raw:
            h=GeneratedRecoveryHarness(Path(raw));h.admit();before={n:(h.job/n).read_bytes() for n in h.original}
            result=h.execute('owned-bind-once');self.assertEqual('recovered',result['state'],result)
            self.assertEqual(1,len(h.effects));self.assertEqual(['/system/xbin/su','0,0','/system/bin/nsenter','-t','6654','-m','--','/system/bin/umount',recovery.TARGET],h.effects[0][5:])
            self.assertEqual(before,{n:(h.job/n).read_bytes() for n in h.original});self.assertFalse((h.job/'cleaned.json').exists());self.assertFalse(result['leaseReleased']);self.assertFalse(result['stageRetired'])
            self.assertEqual('recovered',h.execute('owned-bind-status')['state']);self.assertEqual(1,len(h.effects))
    def test_lost_response_cannot_replay_status_observes_same_new_recovery(self):
        with tempfile.TemporaryDirectory() as raw:
            h=GeneratedRecoveryHarness(Path(raw));h.admit();h.effect_failure='timeout'
            self.assertEqual('bind_unmount_uncertain',h.execute('owned-bind-once')['reason']);self.assertEqual('bind_attempt_recorded',h.execute('owned-bind-once')['reason']);self.assertEqual(1,len(h.effects))
            self.assertEqual('recovered',h.execute('owned-bind-status')['state']);self.assertEqual(1,len(h.effects))
    def test_nonzero_effect_retains_unknown_and_one_attempt(self):
        with tempfile.TemporaryDirectory() as raw:
            h=GeneratedRecoveryHarness(Path(raw));h.admit();h.effect_failure='returncode'
            self.assertEqual('bind_unmount_uncertain',h.execute('owned-bind-once')['reason']);self.assertEqual('bind_mount_still_referenced',h.execute('owned-bind-status')['reason']);self.assertEqual('bind_attempt_recorded',h.execute('owned-bind-once')['reason']);self.assertEqual(1,len(h.effects))
    def test_guard_failure_after_fence_submits_no_effect_and_never_replays(self):
        with tempfile.TemporaryDirectory() as raw:
            h=GeneratedRecoveryHarness(Path(raw));h.admit();h.before_effect_failure=True
            self.assertEqual('bind_owner_changed',h.execute('owned-bind-once')['reason']);self.assertEqual('bind_attempt_recorded',h.execute('owned-bind-once')['reason']);self.assertEqual([],h.effects)
    def test_attempt_same_bytes_replaced_after_fence_submits_no_effect(self):
        with tempfile.TemporaryDirectory() as raw:
            h=GeneratedRecoveryHarness(Path(raw));h.admit();original_pair=h.pair
            def replaced_pair(mounted):
                result=original_pair(mounted)
                path=h.job/('owned-bind-'+NEW_ID+'.attempt.json')
                if path.exists():
                    data=path.read_bytes();path.unlink();path.write_bytes(data);path.chmod(0o600)
                return result
            h.pair=replaced_pair
            self.assertEqual('bind_effect_journal_changed',h.execute('owned-bind-once')['reason'])
            self.assertEqual([],h.effects)
            self.assertEqual('bind_attempt_recorded',h.execute('owned-bind-once')['reason'])
    def test_owner_and_receipt_generation_drift_before_effect(self):
        for change in ('owner','receipt-generation','reservation-generation'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as raw:
                h=GeneratedRecoveryHarness(Path(raw));h.admit()
                if change=='owner':h.owner='different'
                else:
                    p=h.job/('owned-bind-'+NEW_ID+'.json') if change=='receipt-generation' else h.job/'owned-bind-recovery-reservation.json';data=p.read_bytes();p.unlink();p.write_bytes(data);p.chmod(0o600)
                result=h.execute('owned-bind-once');self.assertIn(result['reason'],{'bind_receipt_stale','bind_receipt_changed'});self.assertEqual([],h.effects)
    def test_actual_generated_status_recovers_admission_receipt_without_replaying_admission(self):
        with tempfile.TemporaryDirectory() as raw:
            h=GeneratedRecoveryHarness(Path(raw));h.admit();h.bundle.pop('receipt');h.bundle.pop('receiptPin');h.bundle.pop('reservationPin')
            result=h.execute('owned-bind-status');self.assertEqual('ready',result['state']);self.assertIn('receipt',result);self.assertEqual([],h.effects)
    def test_original_stage_api_rejection_remains_unchanged(self):
        tc=legacy.AndroidCleanupReadmissionTest('runTest')
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();expected,state,base,binding=tc.remaining_fixture(root)
            def command(argv,**kwargs):
                words=argv[5:] if argv[3:5]==['shell','-T'] else []
                if '%d:%i:%h:%F' in words and '/system/bin/nsenter' in words:return SimpleNamespace(returncode=0,stdout=b'64800:65543:2:directory',stderr=b'')
                return base(argv,**kwargs)
            result=tc.execute(root,{**expected,'cleanupRemaining':binding},'remaining-cleanup-admit',command)
            self.assertEqual('remaining_target_unlinked',result['reason']);self.assertEqual([],state['effects'])

class OwnedBindParserTest(unittest.TestCase):
    def test_measured_mount664_fixture_ca_is_admitted_only_as_owned_pre_effect_tree(self):
        text,stock=trees(True);view=recovery._parse_tree(text,PLAN,stock,True,True)
        self.assertEqual('664',view['membership']['fields'][0]);self.assertEqual(139,len(view['manifest']));self.assertEqual(recovery.CA_SHA,view['manifest'][recovery.CA_NAME]['sha256'])
        with self.assertRaises(ValueError):recovery._parse_tree(text,PLAN,stock,False,True)
    def test_stock_postcondition_full138_and_no_own_ca(self):
        text,stock=trees(False);view=recovery._parse_tree(text,PLAN,stock,False,True);self.assertEqual(138,len(view['manifest']));self.assertNotIn(recovery.CA_NAME,view['manifest'])
        bad=text.replace('__AFTER__','NAME|'+recovery.CA_NAME+'\n0:0:644:64258:22:1:1188:100:100:regular file\n'+recovery.CA_SHA+'  /proc/123/fd/3/'+recovery.CA_NAME+'\n0:0:644:64258:22:1:1188:100:100:regular file\n__AFTER__')
        with self.assertRaisesRegex(ValueError,'bind_stock_manifest_changed'):recovery._parse_tree(bad,PLAN,stock,False,True)
    def test_fd_namespace_link_generation_mount_and_manifest_drift_reject(self):
        text,stock=trees(True)
        mutations=[('namespace',text.replace('mnt:[4026532630]','mnt:[99]')),('fd',text.replace('mnt_id: 664','mnt_id: 665')),('mount',text.replace('664 94 253:32','665 94 253:32')),('unlink',text.replace(':65543:2:',':65543:0:')),('certificate',text.replace(recovery.CA_SHA,'f'*64)),('target',text.replace('64800:65543','64800:65545'))]
        for label,bad in mutations:
            with self.subTest(label=label),self.assertRaises(ValueError):recovery._parse_tree(bad,PLAN,stock,True,True)
    def test_stock_certificate_same_bytes_generation_replacement_rejects(self):
        text,stock=trees(False);bad=text.replace(':1200:1:',':2200:1:')
        with self.assertRaisesRegex(ValueError,'bind_stock_generation_changed'):recovery._parse_tree(bad,PLAN,stock,False,True)
    def test_native_program_has_exact_fixed_effect_and_no_product_cleanup_dispatch(self):
        bundle={'binding':{'correlationId':NEW_ID},'source':{}}
        program=recovery._program(bundle,NEW_ID);ast.parse(program)
        self.assertNotIn("if action=='start':",program);self.assertIn("'/system/bin/umount','/system/etc/security/cacerts'",program)
    def test_directory_authority_ignores_incidental_child_ctime_and_nlink(self):
        with tempfile.TemporaryDirectory() as raw:
            p=Path(raw);p.chmod(0o700);before=recovery._directory_fp(p);(p/'unrelated').mkdir();self.assertEqual(before,recovery._directory_fp(p))
    def test_own_journal_same_byte_file_replacement_rejects_by_full_generation(self):
        with tempfile.TemporaryDirectory() as raw:
            p=Path(raw)/'own.json';recovery._write(p,{'a':1});before=recovery._private(p);data=p.read_bytes();p.unlink();p.write_bytes(data);p.chmod(0o600);self.assertNotEqual(before,recovery._private(p))

class SourceSnapshotTest(unittest.TestCase):
    def test_actual_rename_symlink_read_restore_cannot_supply_alternate_source(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'source.py';saved=Path(raw)/'saved.py';alternate=Path(raw)/'alternate.py'
            path.write_bytes(b'original source');alternate.write_bytes(b'alternate source')
            original_read=Path.read_bytes
            def exchanged_read(p):
                if p==path:
                    path.rename(saved);path.symlink_to(alternate)
                    try:return original_read(p)
                    finally:path.unlink();saved.rename(path)
                return original_read(p)
            with mock.patch.object(Path,'read_bytes',exchanged_read):
                try:pin=recovery._source(path)
                except ValueError:return
            self.assertEqual(hashlib.sha256(b'original source').hexdigest(),pin['sha256'])
    def test_actual_generated_program_rejects_exchanged_helper_bytes(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'helper.py';saved=Path(raw)/'saved.py';alternate=Path(raw)/'alternate.py'
            source=Path(recovery.__file__).read_bytes();path.write_bytes(source)
            alternate.write_bytes(source.replace(b"raise ValueError('bind_tree_framing')",b"raise ValueError('EXCHANGED_SOURCE')"))
            original_read=Path.read_text
            def exchanged_read(p,*args,**kwargs):
                if p==path:
                    path.rename(saved);path.symlink_to(alternate)
                    try:return original_read(p,*args,**kwargs)
                    finally:path.unlink();saved.rename(path)
                return original_read(p,*args,**kwargs)
            with mock.patch.object(recovery,'__file__',str(path)),mock.patch.object(Path,'read_text',exchanged_read):
                try:program=recovery._program({'binding':{'correlationId':NEW_ID},'source':{}},NEW_ID)
                except ValueError:return
            self.assertFalse('EXCHANGED_SOURCE' in program,'exchanged source entered generated program')
    def test_descriptor_source_reader_rejects_symlink_and_named_replacement(self):
        with tempfile.TemporaryDirectory() as raw:
            path=Path(raw)/'source.py';alternate=Path(raw)/'alternate.py';alternate.write_bytes(b'other');path.symlink_to(alternate)
            with self.assertRaises(OSError):recovery._source_snapshot(path)
            path.unlink();path.write_bytes(b'original');fdopen=os.fdopen
            class ExchangedFile:
                def __init__(self,f):self.f=f
                def __enter__(self):return self
                def __exit__(self,*args):self.f.close()
                def fileno(self):return self.f.fileno()
                def read(self,size):
                    raw=self.f.read(size);path.unlink();path.write_bytes(b'original');return raw
            with mock.patch.object(os,'fdopen',lambda fd,mode:ExchangedFile(fdopen(fd,mode))):
                with self.assertRaisesRegex(ValueError,'recovery_source_changed'):recovery._source_snapshot(path)
    def test_program_uses_exact_snapshot_not_mutable_globals_or_path_rereads(self):
        paths=(Path(recovery.__file__).absolute(),Path(recovery.endpoint.__file__).absolute())
        snapshots={str(p):recovery._source_snapshot(p) for p in paths}
        binding={'helperSha256':snapshots[str(paths[0])][0]['sha256'],'endpointSha256':snapshots[str(paths[1])][0]['sha256']}
        bundle={'binding':{'correlationId':NEW_ID},'source':binding}
        with mock.patch.object(Path,'read_bytes',side_effect=AssertionError('unbound reread')),mock.patch.object(Path,'read_text',side_effect=AssertionError('unbound reread')),mock.patch.object(recovery,'_REMOTE','EXCHANGED_SOURCE'),mock.patch.object(recovery.endpoint,'_REMOTE','EXCHANGED_SOURCE'):
            program=recovery._program(bundle,NEW_ID,snapshots)
        self.assertFalse('EXCHANGED_SOURCE' in program)
        with self.assertRaisesRegex(ValueError,'bind_local_source_changed'):
            recovery._program({**bundle,'source':{**binding,'helperSha256':'0'*64}},NEW_ID,snapshots)
