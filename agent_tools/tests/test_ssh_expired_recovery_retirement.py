"""Causal TempFS regressions for expired ready recovery admission."""
import json
import copy
import io
import contextlib
import subprocess
import sys
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from agent_tools import ssh_connection_recovery as recovery, ssh_transport as transport
from agent_tools.tests.test_ssh_recovery_adoption import inventory


def absence(target, correlation):
    return {'state':'both-endpoints-absent','context':{'bootId':'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa','netNamespace':'net:[123]'},'observations':[{'controlPath':path,'pathAbsent':True,'check':{'returnCode':255,'exactMissingSocket':True},'before':{'completeEOF':True,'endpointCount':0,'rowCount':1},'after':{'completeEOF':True,'endpointCount':0,'rowCount':1}} for path in (str(target.remote_control_path),str(recovery._recovery_socket_path(target,correlation)[1]))],'mutationPerformed':False,'credentialRead':False}


class ExpiredRecoveryRetirementTest(unittest.TestCase):
    def fixture(self, path):
        root = Path(path).resolve(); old = '/remote/original/m'
        value = inventory(old); value['hosts']['nested']['password'] = 'secret'
        config = root / transport.CONFIG_FILENAME
        config.write_text(json.dumps(value)); config.chmod(0o600)
        target = transport.load_config(root).hosts['nested']; correlation = 'a' * 32
        control = str(recovery._recovery_socket_path(target, correlation)[1])
        recovery._create_intent(root, 'nested', target, correlation, control)
        recovery._update_intent(root, 'nested', target, correlation, 'ready', control)
        return root, target, correlation, recovery._intent_path(root, 'nested', target)

    def test_expired_ready_can_retire_and_admit_exactly_one_new_attempt(self):
        from agent_tools import ssh_expired_recovery_retirement as retirement
        with tempfile.TemporaryDirectory() as path:
            root, target, correlation, intent = self.fixture(path)
            original = intent.read_bytes(); config = (root / transport.CONFIG_FILENAME).read_bytes()
            pins = retirement.authority(root, 'nested', correlation)
            with mock.patch.object(retirement, '_observe', return_value=absence(target, correlation)):
                self.assertEqual('retired', retirement.retire(root, 'nested', correlation, **pins)['state'])
            self.assertEqual(config, (root / transport.CONFIG_FILENAME).read_bytes())
            self.assertEqual(original, next(intent.parent.glob('.retired-*.intent.json')).read_bytes())
            retirement.require_admission(root, 'nested', target)
            self.assertIsNone(recovery._read_intent(root, 'nested', target))
            recovery._create_intent(root, 'nested', target, 'b' * 32, '/remote/original/r-bbbbbbbbbbbbbbb/m')
            with self.assertRaises(FileExistsError):
                recovery._create_intent(root, 'nested', target, 'c' * 32, '/remote/original/r-ccccccccccccccc/m')

    def test_unknown_or_live_endpoint_never_retires(self):
        from agent_tools import ssh_expired_recovery_retirement as r
        for attack in ('live', 'path', 'incomplete', 'missing', 'foreign', 'context', 'bool_count'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as path:
                root,target,corr,intent=self.fixture(path);pins=r.authority(root,'nested',corr)
                proof=absence(target,corr)
                if attack=='live':proof['observations'][1]['before']['endpointCount']=1
                elif attack=='path':proof['observations'][1]['pathAbsent']=False
                elif attack=='incomplete':proof['observations'][0]['after']['completeEOF']=False
                elif attack=='missing':proof['observations'].pop()
                elif attack=='foreign':proof['observations'][0]['controlPath']='/foreign/m'
                elif attack=='context':proof['context']['netNamespace']='unknown'
                else:proof['observations'][0]['before']['endpointCount']=False
                with mock.patch.object(r,'_observe',return_value=proof):
                    self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])
                self.assertTrue(intent.exists());self.assertFalse(list(intent.parent.glob('.retire-*.pending.json')))

    def test_second_absence_unknown_is_consumed_and_never_replayed(self):
        from agent_tools import ssh_expired_recovery_retirement as r
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.fixture(path);pins=r.authority(root,'nested',corr)
            with mock.patch.object(r,'_observe',side_effect=[absence(target,corr),ValueError('unknown')]):
                self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])
            self.assertTrue(intent.exists())
            with mock.patch.object(r,'_observe',side_effect=AssertionError('no replay')):
                self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])
            with self.assertRaises(ValueError):r.require_admission(root,'nested',target)

    def test_exact_pins_and_ready_schema_required_before_probe(self):
        from agent_tools import ssh_expired_recovery_retirement as r
        for attack in ('config','intent','source','unknown','correlation','foreign_directory','mode','hardlink'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as path:
                root,target,corr,intent=self.fixture(path);pins=r.authority(root,'nested',corr)
                if attack=='config':pins['inventory_pin']['sha256']='0'*64
                elif attack=='intent':pins['intent_pin']['generation'][1]+=1
                elif attack=='source':pins['source_pins']={}
                elif attack in ('unknown','correlation'):
                    raw=json.loads(intent.read_bytes());raw['state' if attack=='unknown' else 'correlationId']='unknown';intent.write_text(json.dumps(raw))
                elif attack=='foreign_directory':intent.parent.chmod(0o777)
                elif attack=='mode':intent.chmod(0o644)
                else:os.link(intent,intent.parent/'linked')
                with mock.patch.object(r,'_observe',side_effect=AssertionError('pre-admission probe')):
                    self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])
                self.assertTrue(intent.exists())

    def test_adoption_pending_or_terminal_blocks_retirement(self):
        from agent_tools import ssh_expired_recovery_retirement as r, ssh_recovery_adoption as a
        for kind in ('pending','adopted'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as path:
                root,target,corr,intent=self.fixture(path);pins=r.authority(root,'nested',corr)
                raw=json.loads(intent.read_bytes())
                a._create_receipt(root,'nested',str(target.remote_control_path),raw['controlPath'],raw,kind)
                with mock.patch.object(r,'_observe',side_effect=AssertionError('consumed adoption')):
                    self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])
                self.assertTrue(intent.exists())

    def test_probe_races_reject_same_bytes_new_generation_and_foreign_parent(self):
        from agent_tools import ssh_expired_recovery_retirement as r
        for attack in ('config','intent','directory','source','context'):
            with self.subTest(attack=attack), tempfile.TemporaryDirectory() as path:
                root,target,corr,intent=self.fixture(path);calls=[]
                source=root/'tool-source.py';source.write_bytes(Path(r.__file__).read_bytes());source.chmod(0o644)
                def probe(*args):
                    calls.append(1);proof=absence(target,corr)
                    if len(calls)==2:
                        if attack in ('config','intent'):
                            changed=root/transport.CONFIG_FILENAME if attack=='config' else intent
                            body=changed.read_bytes();tmp=changed.with_suffix('.replacement');tmp.write_bytes(body);tmp.chmod(0o600);tmp.replace(changed)
                        elif attack=='directory':
                            intent.parent.rename(intent.parent.with_name('foreign-old'));intent.parent.mkdir(mode=0o700)
                        elif attack=='context':proof['context']['netNamespace']='net:[456]'
                        else:source.write_bytes(source.read_bytes()+b'\n')
                    return proof
                with mock.patch.object(r,'__file__',str(source)):
                    pins=r.authority(root,'nested',corr)
                    with mock.patch.object(r,'_observe',side_effect=probe):
                        self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])
                self.assertFalse(list(intent.parent.glob('.retired-*.intent.json')))

    def test_terminal_failure_keeps_archive_but_no_successor_or_replay(self):
        from agent_tools import ssh_expired_recovery_retirement as r, ssh_recovery_adoption as a
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.fixture(path);pins=r.authority(root,'nested',corr);write=a._write_receipt
            def writer(directory,name,value):
                if name.endswith('.terminal.json'):raise OSError('terminal failed')
                return write(directory,name,value)
            with mock.patch.object(r,'_observe',return_value=absence(target,corr)),mock.patch.object(a,'_write_receipt',side_effect=writer):
                self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])
            self.assertFalse(intent.exists());self.assertEqual(1,len(list(intent.parent.glob('.retired-*.intent.json'))))
            with self.assertRaises(ValueError):r.require_admission(root,'nested',target)
            with mock.patch.object(r,'_observe',side_effect=AssertionError('no replay')):
                self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])

    def test_archive_replacement_invalidates_status_and_admission(self):
        from agent_tools import ssh_expired_recovery_retirement as r
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.fixture(path);pins=r.authority(root,'nested',corr)
            with mock.patch.object(r,'_observe',return_value=absence(target,corr)):
                self.assertEqual('retired',r.retire(root,'nested',corr,**pins)['state'])
            archived=next(intent.parent.glob('.retired-*.intent.json'));tmp=archived.with_suffix('.replacement')
            tmp.write_bytes(archived.read_bytes());tmp.chmod(0o600);tmp.replace(archived)
            self.assertEqual('unknown',r.status(root,'nested',corr)['state'])
            with self.assertRaises(ValueError):r.require_admission(root,'nested',target)

    def test_final_fence_race_and_exclusive_destination_collision(self):
        from agent_tools import ssh_expired_recovery_retirement as r, ssh_recovery_adoption as a
        for attack in ('pending','config','collision','fsync'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as path:
                root,target,corr,intent=self.fixture(path);pins=r.authority(root,'nested',corr);write=a._write_receipt
                def writer(directory,name,value):
                    pin=write(directory,name,value)
                    if name.endswith('.pending.json'):
                        if attack=='pending':(directory.path/name).write_bytes(b'{}')
                        elif attack=='config':(root/transport.CONFIG_FILENAME).write_bytes((root/transport.CONFIG_FILENAME).read_bytes()+b' ')
                        elif attack=='collision':(directory.path/value['archive']).write_bytes(b'foreign')
                        else:raise OSError('pending directory fsync failed')
                    return pin
                with mock.patch.object(r,'_observe',return_value=absence(target,corr)),mock.patch.object(a,'_write_receipt',side_effect=writer):
                    self.assertEqual('unknown',r.retire(root,'nested',corr,**pins)['state'])
                self.assertTrue(intent.exists())

    def test_historical_status_never_probes_and_results_are_redacted(self):
        from agent_tools import ssh_expired_recovery_retirement as r
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,intent=self.fixture(path);pins=r.authority(root,'nested',corr)
            with mock.patch.object(r,'_observe',return_value=absence(target,corr)):
                self.assertEqual('retired',r.retire(root,'nested',corr,**pins)['state'])
            with mock.patch.object(r,'_observe',side_effect=AssertionError('status no probe')):
                result=r.retire(root,'nested',corr,**pins)
                self.assertEqual('retired',result['state']);self.assertNotIn('secret',json.dumps(result))
                self.assertEqual('retired',r.status(root,'nested',corr)['state'])
            for journal in intent.parent.glob('.retire-*.json'):self.assertNotIn('secret',journal.read_text())

    def test_fixed_remote_observer_positive_and_ambiguous_cases_without_native_effects(self):
        from agent_tools import ssh_expired_recovery_retirement as r
        code=compile(r._REMOTE,'fixed-readonly-observer','exec')
        header=b'Num       RefCount Protocol Flags    Type St Inode Path\n'
        for attack in ('none','endpoint','truncated','check','path','namespace','malformed','stdout'):
            with self.subTest(attack=attack),tempfile.TemporaryDirectory() as path:
                root,target,corr,_=self.fixture(path)
                paths=[str(target.remote_control_path),str(recovery._recovery_socket_path(target,corr)[1])]
                spec={'paths':paths,'alias':'target','config':'/remote/config'}
                def opened(name,*args,**kwargs):
                    if name=='/proc/sys/kernel/random/boot_id':return io.StringIO('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n')
                    self.assertEqual('/proc/net/unix',name)
                    raw=header
                    if attack=='endpoint':raw+=('0000: 0000 0000 0000 0001 01 99 '+paths[1]+'\n').encode()
                    elif attack=='truncated':raw=header[:-1]
                    elif attack=='malformed':raw=header+b'garbage 1 2 3 4 5 6\n'
                    return io.BytesIO(raw)
                commands=[]
                def checked(argv,**kwargs):
                    commands.append(argv);self.assertEqual(['-O','check','target'],argv[-3:])
                    self.assertIn(argv[argv.index('-S')+1],paths)
                    return subprocess.CompletedProcess(argv,255,b'UNRELATED ERROR' if attack=='stdout' else b'',('Control socket connect('+argv[argv.index('-S')+1]+'): No such file or directory\n').encode() if attack!='check' else b'Permission denied')
                missing=FileNotFoundError() if attack!='path' else None
                ns=['net:[123]','net:[456]' if attack=='namespace' else 'net:[123]']
                with mock.patch.object(sys,'argv',['observer',json.dumps(spec)]),mock.patch('builtins.open',side_effect=opened),mock.patch.object(os,'lstat',side_effect=missing),mock.patch.object(os,'readlink',side_effect=ns),mock.patch.object(subprocess,'run',side_effect=checked),contextlib.redirect_stdout(io.StringIO()) as output:
                    if attack!='none':
                        with self.assertRaises(ValueError):exec(code,{})
                    else:exec(code,{})
                if attack=='none':
                    self.assertEqual(2,len(commands));r._proof(json.loads(output.getvalue()),target,corr)

    def test_fixed_gateway_observer_rejects_nonzero_stderr_and_malformed_results(self):
        from agent_tools import ssh_expired_recovery_retirement as r
        with tempfile.TemporaryDirectory() as path:
            root,target,corr,_=self.fixture(path);config=transport.load_config(root)
            for response in (None,subprocess.CompletedProcess([],1,'{}',''),subprocess.CompletedProcess([],0,'{}','warning'),subprocess.CompletedProcess([],0,'garbage','')):
                with self.subTest(response=response),mock.patch.object(recovery,'_gateway_run',return_value=response) as gateway:
                    with self.assertRaises(ValueError):r._observe(config,target,corr,5)
                    command=gateway.call_args.args[2]
                    self.assertEqual(('python3','-I','-B','-c'),command[:4])
                    self.assertEqual('exec('+repr(r._REMOTE)+')',command[4])


if __name__ == '__main__': unittest.main()
