"""Controlled original owners, sockets, kernel actors and per-VM locks only."""
import fcntl,hashlib,json,os,socket,stat,subprocess,sys,tempfile,threading,time,unittest
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from uuid import uuid4
from agent_tools import durable_remote_job as jobs,readiness
from agent_tools import readiness_tart_macos_registry as registry
from agent_tools import readiness_tart_macos_power_fence as fence
from agent_tools import readiness_tart_macos_known_off as known

FIXTURE=Path(__file__).parent/'fixtures/tart_macos_known_off'
ORDER_FIXTURE=Path(__file__).parent/'fixtures/tart_macos_known_off_probe_order'
if os.environ.get('VPN_CONTROL_KNOWN_OFF_LOCK_BEFORE')=='1':
    raw=(ORDER_FIXTURE/'before.source').read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((ORDER_FIXTURE/'provenance.json').read_text())['sourceSha256']
    known=ModuleType('agent_tools._known_off_order_before');known.__package__='agent_tools';known.__file__=str(ORDER_FIXTURE/'before.source')
    sys.modules[known.__name__]=known;exec(compile(raw,known.__file__,'exec'),known.__dict__)

@unittest.skipUnless(os.name=='posix'and getattr(os,'geteuid',lambda:0)()!=0,'actual ordinary POSIX private owners and fcntl locks')
class KnownOffTests(unittest.TestCase):
    @contextmanager
    def fixture(self,*,live=False,expired=False,missing_idle=False):
        with tempfile.TemporaryDirectory(dir=Path('/tmp').resolve())as temporary:
            root=Path(temporary);root.chmod(0o700);vm=root/'selected-vm';vm.mkdir(mode=0o700)
            for name in ('config.json','disk.img','nvram.bin'):
                (vm/name).write_bytes(b'{}'if name=='config.json'else b'private controlled bytes never hashed');(vm/name).chmod(0o600)
            binding=jobs.current_binding('controlled-host','controlled-host-machine');target='selected-target';machine=str(uuid4())
            runop,powerop,capop=[str(uuid4())for _ in range(3)];rid='a'*64
            work=root/'jobs';work.mkdir(mode=0o700);generation=jobs.root_generation(work)
            audit=root/'observations';audit.mkdir(mode=0o700)
            lifecycle=root/'lifecycle';lifecycle.mkdir(mode=0o700);operator=registry.OperatorLock(lifecycle/'operator.lock')
            children=[];socket_path=root/'provider.sock';server=socket.socket(socket.AF_UNIX);server.bind(str(socket_path));server.listen(10);server.settimeout(.1)
            stop=threading.Event();state={'Name':vm.name,'State':'stopped','Running':False}
            def serve():
                while not stop.is_set():
                    try:c,_=server.accept()
                    except TimeoutError:continue
                    with c:
                        if c.recv(100)==('get '+vm.name).encode():c.sendall(json.dumps(state).encode())
            thread=threading.Thread(target=serve);thread.start()
            provider=root/'provider'
            provider_source='#!'+sys.executable+'\nimport fcntl,json,socket,sys\nassert sys.argv[1:]==["get",'+repr(vm.name)+',"--format","json"]\ns=socket.socket(socket.AF_UNIX);s.connect('+repr(str(socket_path))+');s.sendall('+repr(('get '+vm.name).encode())+');body=json.loads(s.recv(65536));s.close()\nf=open('+repr(str(vm/'config.json'))+',"r+")\ntry:fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError:body.update(State="running",Running=True)\nf.close();print(json.dumps(body))\n'
            provider.write_text(provider_source);provider.chmod(0o700)
            def owner(op,purpose,value):
                program=jobs.Program(purpose,('import json\nprint(json.dumps('+repr(value)+'))\n').encode(),262144)
                jobs.submit(work,op,binding,program,generation=generation)
                limit=time.monotonic()+10
                while True:
                    observed=jobs.observe(work,op,binding,generation=generation)
                    if observed['state']=='terminal':break
                    if time.monotonic()>limit:raise AssertionError('controlled owner not terminal')
                    time.sleep(.02)
                return registry.OriginalOwner(work,generation,op,binding,program)
            try:
                for _ in range(2):
                    p=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(60)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);children.append(p)
                actors=[{'pid':p.pid,'birth':jobs._birth(p.pid)}for p in children];self.assertTrue(all(v['birth']for v in actors))
                if not live:
                    for p in children:p.terminate();p.wait(timeout=5)
                report={'kind':'macos-original-run-off-v1','target':target,'machine':machine,'operationId':runop,'powerOperationId':powerop,'powerRecoveryId':rid,'stopCause':'off_unknown','actors':actors}
                run=owner(runop,'controlled-original-run',report)
                power=owner(powerop,'controlled-original-power',{'kind':'macos-original-power-phase-ended-v1','target':target,'machine':machine,'operationId':powerop,'runOperationId':runop,'recoveryId':rid,'state':'ended'})
                report_path=root/'original-run-report.json';jobs._publish(report_path,report)
                ledgers=[]
                for name in ('memory-ledger.json','storage-ledger.json'):
                    path=root/name;jobs._publish(path,{'protected-unrelated-original':'retained','selected':runop});ledgers.append(path)
                with operator.acquire(deadline=time.monotonic()+60):
                    power_fence=fence.PowerFence(lifecycle,target,machine,operator.guard)
                    try:
                        before=readiness.Observation(target,machine,'selected-original-connection','selected-original-guestboot','ordinary','original-session',transport='ready',guest='running',guest_agent=True,trusted=True,owned=True,integrity=True,idle_visibility=readiness.IDLE_VISIBILITY)
                        power_fence.reserve(rid,'shutdown',before,original_run_operation=runop)
                        power_path=lifecycle/('macos-power-reservation-'+rid+'.json')
                        now=time.monotonic_ns();cap={'kind':'macos-aggregate-capacity-v1','target':target,'machine':machine,'hostBoot':binding.boot,
                            'observedNs':now-70_000_000_000 if expired else now,'deadlineNs':now-1 if expired else now+50_000_000_000,
                            'memoryMiB':4096,'requiredMemoryMiB':4096,'diskBytes':1000000,'requiredDiskBytes':500000,
                            'ledgerPins':{str(p):known._pin(p)for p in ledgers},'complete':True}
                        capacity=owner(capop,'controlled-fresh-capacity',cap)
                        inputs=dict(target=target,machine=machine,host_binding=binding,operator=operator,run_owner=run,power_owner=power,capacity_owner=capacity,
                            retained_owners=(run,power,capacity),retained_roots={work:generation},power_fence=power_fence,run_report=report_path,
                            provider_binary=provider,provider_sha256=hashlib.sha256(provider.read_bytes()).hexdigest(),fixture_root=vm,
                            config_sha256=hashlib.sha256((vm/'config.json').read_bytes()).hexdigest(),artifacts={name:known._pin(vm/name)for name in ('config.json','disk.img','nvram.bin')},ledger_files=ledgers)
                        plan=known.observation_plan(**inputs)
                        if missing_idle:
                            row=json.loads(power_path.read_bytes());row['idleVisibility']=row['idleVisibility'][:-1];power_path.write_text(json.dumps(row));power_path.chmod(0o600)
                        def observe():
                            program=known.observation_program(plan);op=str(uuid4());gen=jobs.root_generation(audit)
                            jobs.submit(audit,op,binding,program,generation=gen);limit=time.monotonic()+10
                            while jobs.observe(audit,op,binding,generation=gen)['state']!='terminal':
                                self.assertLess(time.monotonic(),limit);time.sleep(.02)
                            own=registry.OriginalOwner(audit,gen,op,binding,program)
                            return known.close_original_phase(plan,own)
                        yield locals()
                    finally:power_fence.close()
            finally:
                for p in children:
                    if p.poll()is None:p.terminate();p.wait(timeout=5)
                stop.set();thread.join(timeout=3);server.close()

    @unittest.skipUnless(sys.platform=='darwin','actual preserved Mac launch-owner contract')
    def test_whole_legacy_off_unknown_has_no_safe_successor_but_new_admission_preserves_cause(self):
        with self.fixture()as f:
            phase=f['observe']();original=f['power_path'].read_bytes()
            if os.environ.get('VPN_CONTROL_KNOWN_OFF_BEFORE')=='1':
                raw=(FIXTURE/'lifecycle.before.source').read_bytes()
                self.assertEqual(hashlib.sha256(raw).hexdigest(),json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256'])
                legacy=ModuleType('agent_tools._known_off_lifecycle_before');legacy.__package__='agent_tools';legacy.__file__=str(FIXTURE/'lifecycle.before.source')
                sys.modules[legacy.__name__]=legacy;exec(compile(raw,legacy.__file__,'exec'),legacy.__dict__)
                actor=f['actors'][0]
                jobs._publish(f['root']/'child.json',{'operationId':f['runop'],'child':actor})
                jobs._publish(f['root']/'child-terminal.json',{'operationId':f['runop'],'child':actor,'exitCode':0,'delegateOutcome':None})
                owner=legacy.LaunchOwner(f['root'],f['runop'],f['binding'],f['generation'],f['run'].program.digest,('/controlled/tart','run',f['vm'].name))
                actual=legacy.current_instance((owner,),saved_path=f['vm']/'state.vzvmsave',deadline=time.monotonic()+5)['state']
            else:
                actual='known_off_new_start' if known.admit_known_off(phase,'b'*64).as_dict()['cleanStopped']is False else 'wrong'
            self.assertEqual(actual,'known_off_new_start','closed OFF with unobserved cause needs a distinct successor admission')
            self.assertEqual(original,f['power_path'].read_bytes())

    def test_actual_closed_original_admits_one_new_transition_without_clean_stop_or_history_rewrite(self):
        with self.fixture()as f:
            original=f['power_path'].read_bytes();phase=f['observe']()
            first=known.admit_known_off(phase,'b'*64).as_dict();second=known.admit_known_off(phase,'b'*64).as_dict()
            self.assertEqual(first,second);self.assertNotEqual(first['operationId'],f['powerop']);self.assertFalse(first['cleanStopped']);self.assertEqual(first['stopCause'],'off_unknown')
            with self.assertRaises((known.KnownOffBlocked,ValueError)):known.admit_known_off(phase,'c'*64)
            self.assertEqual(len(list(f['lifecycle'].glob('known-off-start-*'))),1)
            self.assertEqual(f['power_path'].read_bytes(),original);self.assertEqual(f['power_fence'].inspect()['state'],'pending')
            with self.assertRaises(fence.PowerPending):f['power_fence'].guard_admission()
            self.assertFalse(known.QUALIFIED_RECOVERIES)

    def test_live_exact_actor_missing_idle_expired_capacity_and_unknown_retained_job_all_block(self):
        for options in ({'live':True},{'missing_idle':True},{'expired':True},{}):
            with self.subTest(options=options),self.fixture(**options)as f:
                if not options:
                    path=f['work']/str(uuid4());path.mkdir(mode=0o700)
                with self.assertRaises((known.KnownOffBlocked,ValueError)):f['observe']()
                self.assertFalse(list(f['lifecycle'].glob('known-off-start-*')))

    def test_saved_state_replaced_nvram_and_competing_config_lock_block_actual_observer(self):
        for attack in ('saved','nvram','lock'):
            with self.subTest(attack=attack),self.fixture()as f:
                child=None
                try:
                    if attack=='saved':(f['vm']/'state.vzvmsave').symlink_to(f['vm']/'missing-memory')
                    elif attack=='nvram':
                        other=f['vm']/'replacement';other.write_bytes(b'private replacement');other.chmod(0o600);os.replace(other,f['vm']/'nvram.bin')
                    else:
                        child=subprocess.Popen([sys.executable,'-I','-B','-c','import fcntl,sys,time;f=open(sys.argv[1],"r+");fcntl.lockf(f,fcntl.LOCK_EX);print("ready",flush=True);time.sleep(60)',str(f['vm']/'config.json')],stdout=subprocess.PIPE)
                        self.assertEqual(child.stdout.readline(),b'ready\n')
                    with self.assertRaises((known.KnownOffBlocked,ValueError)):f['observe']()
                finally:
                    if child is not None:child.terminate();child.communicate(timeout=5)

    def test_partial_streams_changed_original_source_and_foreign_provider_target_block(self):
        for attack in ('streams','source','target'):
            with self.subTest(attack=attack),self.fixture()as f:
                if attack=='streams':(f['work']/f['runop']/'stdout.bin').write_bytes(b'partial')
                elif attack=='source':(f['work']/f['runop']/'program.py').write_bytes(b'print("changed public source")\n')
                else:f['state']['Name']='foreign-vm'
                with self.assertRaises((known.KnownOffBlocked,ValueError)):f['observe']()
                self.assertFalse(list(f['lifecycle'].glob('known-off-start-*')))

    def test_phase_revalidation_detects_state_change_and_caller_dtos_cannot_mint(self):
        for cls in (known.ObservationPlan,known.OriginalOffPhase,known.KnownOffAdmission):
            with self.assertRaises(TypeError):cls()
        with self.fixture()as f:
            phase=f['observe']();f['state']['State']='running';f['state']['Running']=True
            with self.assertRaises((known.KnownOffBlocked,ValueError)):known.admit_known_off(phase,'b'*64)
            self.assertFalse(list(f['lifecycle'].glob('known-off-start-*')))

if __name__=='__main__':unittest.main()
