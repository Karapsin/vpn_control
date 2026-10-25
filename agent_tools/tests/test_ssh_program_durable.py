"""Generated SSH callers execute real fixed remote owner and reconnect it."""
import hashlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import py_compile
import signal
import sys
import tempfile
import time
import unittest
import uuid

from agent_tools import durable_remote_job as jobs
from agent_tools import ssh_channel_keeper_entry as keeper
from agent_tools import ssh_program_execution as subject
from agent_tools import source_module_loader as loader
from agent_tools import readiness_ssh_master as master
from unittest import mock
from agent_tools.tests import test_ssh_program_execution as legacy
SOURCE_ROOT = legacy.SOURCE_ROOT


@unittest.skipUnless(os.name == 'posix', 'POSIX generated remote owner')
class DurableProgramExecutionTests(unittest.TestCase):
    def setUp(self):
        legacy.ProgramExecutionTests.setUp(self)
        previous_tempdir=tempfile.tempdir
        tempfile.tempdir=str(self.peer.peer)
        self.addCleanup(setattr,tempfile,'tempdir',previous_tempdir)
        peer_source=Path(__file__).parent/'fixtures/program_readiness/ssh_peer.source'
        binary=self.root/'bin/ssh'
        binary.write_text('#!'+sys.executable+'\n'+peer_source.read_text());binary.chmod(0o700)
        self.remote_socket=self.root/'remote.sock'
        endpoint=Path(__file__).parent/'fixtures/program_readiness/remote_endpoint.source'
        remote_process=subprocess.Popen([sys.executable,'-B',str(endpoint),str(self.remote_socket)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        def close_remote():
            if remote_process.poll() is None:remote_process.terminate()
            remote_process.wait(timeout=5)
        self.addCleanup(close_remote)
        deadline=time.monotonic()+5
        while not self.remote_socket.exists() and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(self.remote_socket.exists())
        environment=mock.patch.dict(os.environ,{'VC_PROGRAM_READINESS_LOG':str(self.peer.log),
                                               'VC_PROGRAM_REMOTE_ENDPOINT':str(self.remote_socket),
                                               'VC_PROGRAM_MASTER_REJECT':str(self.root/'reject-master')})
        environment.start();self.addCleanup(environment.stop)
        self.addCleanup(self.close_masters)
        # Capture the real transitive implementation, changing only the fixed
        # SSH executable pathname in a private owned source fixture. Production
        # readiness, journals, source custody and socket protocol are unchanged.
        self.qualified_source=self.root/'qualified-source'
        proxy=loader.Adapter(SOURCE_ROOT/'agent_tools','ssh_program_execution')
        try:
            proxy._module.transport._automatic_module()
            proxy._session.held.read(str(SOURCE_ROOT/'agent_tools/private_config_custody.py'),
                                    proxy._module.automatic_program._PRIVATE_CONFIG_SHA)
            for name,(_,generation,digest,raw) in proxy._session.held.files.items():
                relative=Path(name).relative_to(SOURCE_ROOT)
                path=self.qualified_source/relative;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(raw)
        finally:proxy.close()
        transport_source=self.qualified_source/'agent_tools/ssh_transport.py'
        original=transport_source.read_text()
        needle="return ['/usr/bin/ssh', '-F', '/dev/null'"
        self.assertEqual(1,original.count(needle))
        transport_source.write_text(original.replace(needle,"return ["+repr(str(binary))+", '-F', '/dev/null'",1))

    def close_masters(self):
        path=self.root/master.GROUP/'explicit-peer'
        if not path.exists():return
        for record in path.glob('*.child.json'):
            actor=json.loads(record.read_bytes())['actor']
            try:
                if keeper.actor(actor['pid'])==actor:os.kill(actor['pid'],signal.SIGTERM)
            except (OSError,ValueError):pass

    request = legacy.ProgramExecutionTests.request
    observe = legacy.ProgramExecutionTests.observe
    def terminal(self,deadline=15):
        end=time.monotonic()+deadline
        while time.monotonic()<end:
            result=self.observe()
            if result['state']=='terminal':return result
            if result['state']=='unknown' and (self.directory()/'owner-closed.json').exists():
                self.fail('Original owner closed without verified terminal: '+json.dumps(result))
            time.sleep(.03)
        self.fail('Original owner did not reach terminal: '+json.dumps(self.observe()))

    raw = legacy.ProgramExecutionTests.raw

    def start(self, request, source_root=SOURCE_ROOT, *, deadline=None):
        module = loader
        if source_root == SOURCE_ROOT:source_root=self.qualified_source
        if source_root != SOURCE_ROOT:
            name = '_durable_before_loader_' + uuid.uuid4().hex
            spec = importlib.util.spec_from_file_location(name, source_root / 'agent_tools/source_module_loader.py')
            module = importlib.util.module_from_spec(spec);sys.modules[name] = module
            self.addCleanup(sys.modules.pop, name, None);spec.loader.exec_module(module)
        proxy = module.Adapter(source_root / 'agent_tools', 'ssh_program_execution')
        try:
            return proxy.start(self.root, 'explicit-peer', request, source_context=proxy._session,
                               **({} if deadline is None else {'deadline': deadline}))
        finally:
            proxy.close()

    def directory(self):
        return self.root / '.rag_index/ssh-program-execution' / self.operation

    def clean_remote_root(self):
        packet_file = self.directory() / 'remote-admission.json'
        if packet_file.exists():
            packet = json.loads(packet_file.read_bytes())
            root = Path(packet['remoteRoot'])
            self.assertEqual(tuple(packet['generation']), jobs.root_generation(root))
            if (root/self.operation/'owner.json').exists():
                binding=jobs.MachineBinding.from_dict(packet['binding'])
                deadline=time.monotonic()+8
                while time.monotonic()<deadline:
                    status=jobs.observe(root,self.operation,binding,generation=tuple(packet['generation']))
                    if status['state']=='terminal':break
                    time.sleep(.02)
                self.assertEqual('terminal',status['state'])
            shutil.rmtree(root)

    def test_default_new_program_uses_durable_receipt_semantics_and_private_streams(self):
        request = self.request("import __main__,json,os,pickle,sys\nclass Sample: pass\nassert __main__.Sample is Sample\nassert type(pickle.loads(pickle.dumps(Sample()))) is Sample\nprint(json.dumps({'argv':sys.argv,'cwd':os.getcwd()}))\nsys.stderr.write('retained stderr\\n')\nraise SystemExit(255)", ['space value', 'Ω'])
        self.start(request)
        self.addCleanup(self.clean_remote_root)
        result = self.terminal()
        self.assertEqual(255, result['exitCode'])
        self.assertEqual(1, result['durableProtocol'])
        self.assertEqual(['-c', 'space value', 'Ω'], json.loads(self.raw('stdout'))['argv'])
        self.assertEqual(str(self.root), json.loads(self.raw('stdout'))['cwd'])
        self.assertEqual(b'retained stderr\n', self.raw('stderr'))
        self.assertEqual(self.operation, result['remoteOperationId'])
        count=len(self.peer.events())
        self.assertGreaterEqual(count,2)
        self.assertEqual(result, self.start(request))
        self.assertEqual(count,len(self.peer.events()))

    def test_expired_initial_caller_deadline_has_no_remote_or_job_admission(self):
        started = time.monotonic()
        with self.assertRaisesRegex(ValueError, 'readiness_deadline') as refused:
            self.start(self.request("raise AssertionError('must never execute')"), deadline=started-.01)
        self.assertEqual(self.operation, refused.exception.operation_identity)
        self.assertLess(time.monotonic()-started, 5)
        self.assertFalse(self.peer.events())
        self.assertFalse(self.directory().exists())
        self.assertFalse((self.root/master.GROUP/'explicit-peer').exists())

    def test_durable_large_generated_source_uses_saved_transfer_and_original_semantics(self):
        source="PADDING="+repr("Ω'\\\""*14000)+"\nimport json,os,sys\nprint(json.dumps({'argv':sys.argv,'cwd':os.getcwd()}))\n"
        request=self.request(source,['space value','Ω'])
        self.start(request);self.addCleanup(self.clean_remote_root)
        result=self.terminal()
        self.assertEqual('saved-file',result['transport'])
        self.assertGreater(result['originalCommandBounds']['wholeArgvBytes'],60000)
        self.assertLessEqual(result['capture']['submittedCommandBounds']['wholeArgvBytes'],60000)
        self.assertEqual(['-c','space value','Ω'],json.loads(self.raw('stdout'))['argv'])
        self.assertEqual(str(self.root),json.loads(self.raw('stdout'))['cwd'])
        self.assertTrue(all(row['commandBytes']<=60000 and row['maxArgumentBytes']<=60000 for row in self.peer.events()))

    def test_actual_kernel_e2big_durable_attempt_journals_before_red_current_green(self):
        self.start(self.request("print('complete source capsule')"));self.terminal();self.clean_remote_root()
        before_root=self.root/'before-durable-kernel-journals';shutil.copytree(self.directory()/'capsule',before_root)
        fixture=Path(__file__).parent/'fixtures/program_durable_e2big_before'
        before=(fixture/'ssh_program_execution.py.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['sha256'],hashlib.sha256(before).hexdigest())
        (before_root/'agent_tools/ssh_program_execution.py').write_bytes(before)
        argmax=os.sysconf('SC_ARG_MAX')
        if not 65536<=argmax<=8*1024*1024:self.skipTest('finite native ARG_MAX unavailable')
        remaining=argmax-20000-sum(len(os.fsencode(key))+len(os.fsencode(value))+2 for key,value in os.environ.items())
        padding={};index=0
        while remaining>128:
            name='VC_DURABLE_KERNEL_BUDGET_'+str(index);value='E'*min(60000,remaining-len(name)-2)
            padding[name]=value;remaining-=len(name)+len(value)+2;index+=1
        literal='PADDING='+repr('X'*32000)+'\n'
        def scenario(source_root):
            self.operation=str(uuid.uuid4());marker=self.root/('kernel-once-'+self.operation)
            source=literal+"from pathlib import Path\nwith Path("+repr(str(marker))+").open('x') as out:out.write('once')\nprint('durable fallback complete')\n"
            self.start(self.request(source),source_root)
            try:
                result=self.terminal(deadline=25)
                self.assertEqual('once',marker.read_text())
                self.assertEqual(b'durable fallback complete\n',self.raw('stdout'))
                refusals=list(self.directory().glob('remote-attempt-*/prelaunch-refusal.json'))
                self.assertGreaterEqual(len(refusals),1)
                for path in refusals:
                    refusal=json.loads(path.read_bytes())
                    self.assertEqual(errno.E2BIG,refusal['errno'])
                    self.assertIs(refusal['childCreated'],False)
                    self.assertIs(refusal.get('programStarted'),False)
                    fallback=json.loads((path.parent/'file-fallback-intent.json').read_bytes())
                    self.assertEqual(hashlib.sha256(subject._json(refusal)).hexdigest(),fallback['refusalSha256'])
                    self.assertEqual(self.operation,fallback['operationId'])
                self.assertLessEqual(result['capture']['submittedCommandBounds']['wholeArgvBytes'],60000)
            finally:self.clean_remote_root()
        with mock.patch.dict(os.environ,padding):
            with self.assertRaises(OSError) as caught:
                subprocess.Popen([sys.executable,'-c',literal+'pass'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            self.assertEqual(errno.E2BIG,caught.exception.errno)
            with self.assertRaises(AssertionError):scenario(before_root)
            scenario(SOURCE_ROOT)

    def wait_counter(self, counter):
        deadline = time.monotonic()+10
        while not counter.exists() and time.monotonic()<deadline:
            time.sleep(.01)
        self.assertTrue(counter.exists())

    def disconnect_and_expect_original_completion(self, source_root=SOURCE_ROOT):
        counter = self.root / 'advancing-counter'
        source = ("from pathlib import Path\nimport time\np=Path(" + repr(str(counter)) + ")\nwith p.open('a') as out:\n out.write('execution\\n');out.flush()\n for n in range(25):\n  out.write(str(n)+'\\n');out.flush();print(n,flush=True);time.sleep(.08)\n")
        self.start(self.request(source), source_root)
        self.wait_counter(counter)
        directory = self.directory()
        packet_path = directory / 'remote-admission.json'
        if packet_path.exists():
            self.addCleanup(self.clean_remote_root)
            paths = list(directory.glob('remote-attempt-*/child.json'))
            child = json.loads(sorted(paths)[-1].read_bytes())
            packet = json.loads(packet_path.read_bytes())
            original = json.loads((Path(packet['remoteRoot']) / self.operation / 'owner.json').read_bytes())['owner']
        else:
            child = json.loads((directory / 'child.json').read_bytes())
            original = None
        self.assertEqual(child['actor'], keeper.actor(child['actor']['pid']))
        before = len(counter.read_text().splitlines())
        os.kill(child['actor']['pid'], signal.SIGTERM)
        time.sleep(.2)
        self.assertGreater(len(counter.read_text().splitlines()), before)
        result = self.terminal()
        self.assertEqual(list(map(str, range(25))), self.raw('stdout').decode().splitlines())
        self.assertEqual(1, counter.read_text().splitlines().count('execution'))
        if original is not None:
            self.assertEqual(original, result['remoteOwner'])
        return result

    def test_actual_ssh_child_loss_reconnects_original_advancing_job_without_duplicate(self):
        self.disconnect_and_expect_original_completion()
        self.assertGreaterEqual(len(self.peer.events()), 3)

    def test_actual_local_owner_death_reconciles_same_remote_job_from_fresh_client(self):
        counter = self.root / 'client-loss-counter'
        source = ("from pathlib import Path\nimport time\np=Path("+repr(str(counter))+")\nwith p.open('a') as out:\n out.write('execution\\n');out.flush()\n for n in range(20):\n  out.write(str(n)+'\\n');out.flush();print(n,flush=True);time.sleep(.05)\n")
        self.start(self.request(source))
        self.addCleanup(self.clean_remote_root)
        self.wait_counter(counter)
        owner = json.loads((self.directory()/'owner.json').read_bytes())['actor']
        self.assertEqual(owner,keeper.actor(owner['pid']))
        packet=json.loads((self.directory()/'remote-admission.json').read_bytes())
        remote_owner=json.loads((Path(packet['remoteRoot'])/self.operation/'owner.json').read_bytes())['owner']
        os.kill(owner['pid'],signal.SIGTERM)
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            try:alive=keeper.actor(owner['pid'])==owner
            except (ValueError,OSError):alive=False
            if not alive:break
            time.sleep(.01)
        self.assertEqual('unknown',self.observe()['state'])
        qualified_loader=self.qualified_source/'agent_tools/source_module_loader.py'
        spec=importlib.util.spec_from_file_location('_qualified_reconcile_loader_'+uuid.uuid4().hex,qualified_loader)
        module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
        self.addCleanup(sys.modules.pop,spec.name,None)
        proxy=module.Adapter(self.qualified_source/'agent_tools','ssh_program_execution')
        try:
            result=proxy.reconcile(self.root,'explicit-peer',{'operationId':self.operation},source_context=proxy._session)
        finally:proxy.close()
        self.assertEqual('terminal',result['state'])
        self.assertEqual(remote_owner,result['remoteOwner'])
        self.assertEqual(1,counter.read_text().splitlines().count('execution'))
        self.assertEqual(result,self.observe())
        collected=next(self.directory().glob('reconciliation-*/stdout.private')).read_bytes()
        self.assertEqual([str(n).encode() for n in range(20)],collected.splitlines())
        previous_events=len(self.peer.events())
        # Normal local-only tools use retained reconciliation and need no SSH.
        self.peer.config_path.unlink()
        self.assertEqual(result,subject.collect(self.root,'explicit-peer',{'operationId':self.operation}))
        self.assertEqual(previous_events,len(self.peer.events()))

    def test_actual_timestamp_valid_foreign_pyc_before_red_captured_module_green(self):
        from agent_tools import ssh_program_execution_remote as current
        before_path=Path(__file__).parent/'fixtures/program_durable_module_before'
        raw=(before_path/'ssh_program_execution_remote.py.source').read_bytes()
        self.assertEqual(json.loads((before_path/'provenance.json').read_bytes())['sha256'],hashlib.sha256(raw).hexdigest())
        name='_whole_remote_module_before_'+uuid.uuid4().hex
        spec=importlib.util.spec_from_loader(name,loader=None)
        before=importlib.util.module_from_spec(spec);sys.modules[name]=before
        self.addCleanup(sys.modules.pop,name,None)
        exec(compile(raw,str(before_path/'ssh_program_execution_remote.py.source'),'exec'),before.__dict__)
        def check(renderer):
            operation=str(uuid.uuid4());program=self.request("print('not submitted')")['program']
            command=current.prepare_command(operation,program,jobs.owner_source())
            prepared=subprocess.run([sys.executable,*command[1:]],capture_output=True,timeout=10)
            self.assertEqual(0,prepared.returncode,prepared.stderr)
            packet=json.loads(prepared.stdout);root=Path(packet['remoteRoot'])
            self.addCleanup(shutil.rmtree,root)
            module=root/'owner-module.py';original=module.read_bytes();info=module.stat()
            marker=self.root/('foreign-pyc-'+operation)
            foreign=("from pathlib import Path\nPath("+repr(str(marker))+").write_text('foreign')\n").encode()
            self.assertLess(len(foreign),len(original))
            module.write_bytes(foreign+b'#'+b' '*(len(original)-len(foreign)-1))
            os.utime(module,ns=(info.st_atime_ns,info.st_mtime_ns))
            py_compile.compile(str(module),doraise=True)
            module.write_bytes(original);os.utime(module,ns=(info.st_atime_ns,info.st_mtime_ns))
            command=renderer.durable_command(operation,program,packet,mode='observe',wait_seconds=0)
            observed=subprocess.run([sys.executable,*command[1:]],capture_output=True,timeout=10)
            self.assertFalse(marker.exists(),'Digest-verified module source must not execute a foreign cached program')
            self.assertEqual(0,observed.returncode,observed.stderr)
            self.assertEqual('unsubmitted',json.loads(observed.stdout)['status']['state'])
        with self.assertRaises(AssertionError):check(before)
        check(current)

    def test_actual_dead_owned_master_recovery_before_red_current_original_job_green(self):
        self.start(self.request("print('capture complete source closure')"));self.terminal()
        self.clean_remote_root()
        source_root=self.root/'before-master-readiness'
        shutil.copytree(self.directory()/'capsule',source_root)
        fixture=Path(__file__).parent/'fixtures/program_readiness_before'
        before=(fixture/'ssh_program_execution.py.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['sha256'],hashlib.sha256(before).hexdigest())
        (source_root/'agent_tools/ssh_program_execution.py').write_bytes(before)
        def scenario(root):
            self.operation=str(uuid.uuid4())
            counter=self.root/('master-counter-'+self.operation)
            source=("from pathlib import Path\nimport time\np=Path("+repr(str(counter))+")\nwith p.open('x') as out:\n out.write('execution\\n');out.flush()\n for n in range(70):\n  out.write(str(n)+'\\n');out.flush();print(n,flush=True);time.sleep(.05)\n")
            self.start(self.request(source),root);self.wait_counter(counter)
            packet=json.loads((self.directory()/'remote-admission.json').read_bytes())
            original=json.loads((Path(packet['remoteRoot'])/self.operation/'owner.json').read_bytes())['owner']
            old=master.status(self.root,'explicit-peer')
            self.assertEqual(old['child']['actor'],keeper.actor(old['child']['pid']))
            os.kill(old['child']['pid'],signal.SIGTERM)
            before_lines=len(counter.read_text().splitlines());time.sleep(.15)
            self.assertGreater(len(counter.read_text().splitlines()),before_lines)
            try:
                result=self.terminal()
                self.assertEqual(original,result['remoteOwner'])
                self.assertEqual([str(n).encode() for n in range(70)],self.raw('stdout').splitlines())
                self.assertEqual(1,counter.read_text().splitlines().count('execution'))
                new=master.status(self.root,'explicit-peer')
                self.assertNotEqual(old['recoveryId'],new['recoveryId'])
                self.assertTrue(Path(old['socketPath']).exists())
            finally:self.clean_remote_root()
        with self.assertRaises(AssertionError):scenario(source_root)
        # Start's internal readiness must restore the dead connection before it
        # builds any new command, then a second mid-job outage reuses job UUID.
        scenario(SOURCE_ROOT)

    def test_three_rejected_master_recoveries_preserve_original_and_project_finite_blocker(self):
        self.start(self.request("print('capture actual readiness source')"));self.terminal();self.clean_remote_root()
        before_root=self.root/'before-readiness-blocker';shutil.copytree(self.directory()/'capsule',before_root)
        fixture=Path(__file__).parent/'fixtures/program_readiness_blocker_before'
        raw=(fixture/'ssh_program_execution.py.source').read_bytes()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['sha256'],hashlib.sha256(raw).hexdigest())
        (before_root/'agent_tools/ssh_program_execution.py').write_bytes(raw)
        def scenario(root):
            self.operation=str(uuid.uuid4());counter=self.root/('rejection-counter-'+self.operation)
            source=("from pathlib import Path\nimport time\np=Path("+repr(str(counter))+")\nwith p.open('x') as out:\n out.write('execution\\n');out.flush()\n for n in range(20):out.write(str(n)+'\\n');out.flush();print(n,flush=True);time.sleep(.05)\n")
            self.start(self.request(source),root);self.wait_counter(counter)
            old=master.status(self.root,'explicit-peer');count=len(list(master._path(self.root,'explicit-peer').glob('*.intent.json')))
            self.assertEqual(old['child']['actor'],keeper.actor(old['child']['pid']))
            reject=self.root/'reject-master';reject.touch()
            os.kill(old['child']['pid'],signal.SIGTERM)
            try:
                deadline=time.monotonic()+18
                while time.monotonic()<deadline and not (self.directory()/'owner-closed.json').exists():time.sleep(.03)
                self.assertTrue((self.directory()/'owner-closed.json').exists())
                result=self.observe()
                self.assertEqual('unknown',result['state'])
                self.assertEqual(3,len(list(master._path(self.root,'explicit-peer').glob('*.intent.json')))-count)
                self.assertEqual(1,counter.read_text().splitlines().count('execution'))
                self.assertEqual('transport_attempts_exhausted',result.get('readinessBlocker'))
                self.assertEqual('resolve_blocker',result['nextAction'])
            finally:reject.unlink();self.clean_remote_root()
        with self.assertRaises(AssertionError):scenario(before_root)
        scenario(SOURCE_ROOT)

    def test_failed_connection_history_restores_same_original_after_network_returns(self):
        before_root = self.root/'before-failed-connection-history'
        shutil.copytree(self.qualified_source, before_root)
        fixture = Path(__file__).parent/'fixtures/program_failed_reconnect_before'
        pins = json.loads((fixture/'provenance.json').read_bytes())['files']
        for name, pin in pins.items():
            raw = (fixture/(name+'.source')).read_bytes()
            self.assertEqual(pin['sha256'], hashlib.sha256(raw).hexdigest())
            (before_root/'agent_tools'/name).write_bytes(raw)
        named_root = self.root/'before-named-failed-history'
        shutil.copytree(self.qualified_source, named_root)
        named_fixture = Path(__file__).parent/'fixtures/readiness_submission'
        named_before = (named_fixture/'readiness_ssh_master.py.before-named.source').read_bytes()
        self.assertEqual(json.loads((named_fixture/'provenance.json').read_bytes())['beforeSha256']['readiness_ssh_master.py.named'], hashlib.sha256(named_before).hexdigest())
        (named_root/'agent_tools/readiness_ssh_master.py').write_bytes(named_before)
        def scenario(source_root, observer_root=None):
            observer_root = source_root if observer_root is None else observer_root
            self.operation = str(uuid.uuid4())
            counter = self.root/('restoration-counter-'+self.operation)
            source = ("from pathlib import Path\nimport time\np=Path("+repr(str(counter))+")\n"
                      "with p.open('x')as out:\n out.write('execution\\n');out.flush()\n"
                      " for n in range(20):out.write(str(n)+'\\n');out.flush();print(n,flush=True);time.sleep(.05)\n")
            self.start(self.request(source), source_root); self.wait_counter(counter)
            packet = json.loads((self.directory()/'remote-admission.json').read_bytes())
            original = json.loads((Path(packet['remoteRoot'])/self.operation/'owner.json').read_bytes())['owner']
            old = master.status(self.root, 'explicit-peer')
            self.assertEqual(old['child']['actor'], keeper.actor(old['child']['pid']))
            count = len(list(master._path(self.root, 'explicit-peer').glob('*.intent.json')))
            reject = self.root/'reject-master'; reject.touch()
            os.kill(old['child']['pid'], signal.SIGTERM)
            try:
                deadline = time.monotonic()+18
                while time.monotonic()<deadline and not (self.directory()/'owner-closed.json').exists():time.sleep(.03)
                self.assertTrue((self.directory()/'owner-closed.json').exists())
                first = self.observe()
                self.assertEqual('unknown', first['state'])
                self.assertEqual('transport_attempts_exhausted', first['readinessBlocker'])
                self.assertEqual(3, len(list(master._path(self.root, 'explicit-peer').glob('*.intent.json')))-count)
                reject.unlink()
                name = '_restored_original_loader_'+uuid.uuid4().hex
                spec = importlib.util.spec_from_file_location(name, observer_root/'agent_tools/source_module_loader.py')
                module = importlib.util.module_from_spec(spec); sys.modules[name] = module
                self.addCleanup(sys.modules.pop, name, None); spec.loader.exec_module(module)
                proxy = module.Adapter(observer_root/'agent_tools', 'ssh_program_execution')
                original_context = proxy._module.readiness_transport.context
                def bounded_context(*args, **kwargs):
                    # Private caller deadline capability; the real unchanged
                    # core/SSH sockets execute both whole before and fixed code.
                    kwargs['deadline'] = time.monotonic()+5
                    return original_context(*args, **kwargs)
                try:
                    with mock.patch.object(proxy._module.readiness_transport, 'context', side_effect=bounded_context):
                        try:
                            result = proxy.reconcile(self.root, 'explicit-peer', {'operationId':self.operation}, source_context=proxy._session)
                        except ValueError as error:
                            self.assertEqual('recovery_outcome_unknown', getattr(error, 'reason', None))
                            result = {'state':'unknown'}
                finally:proxy.close()
                self.assertEqual('terminal', result['state'])
                self.assertEqual(original, result['remoteOwner'])
                self.assertEqual(1, counter.read_text().splitlines().count('execution'))
                collector = sorted(self.directory().glob('reconciliation-*'))[-1]
                self.assertEqual([str(n).encode()for n in range(20)], (collector/'stdout.private').read_bytes().splitlines())
                self.assertEqual('unknown', json.loads((self.directory()/'terminal.json').read_bytes())['state'])
                self.assertEqual(result, self.observe())
            finally:
                if reject.exists():reject.unlink()
                self.clean_remote_root()
        # The frozen creator and its owner worker put master sockets under the
        # process tempfile default; an actual deployment default is a native OS
        # root. This fixture's private TMPDIR is no original authority, and the
        # fixed reader refuses it (master_socket_provenance), so run the whole
        # history with the native root the fixed creator also selects.
        native = str(master._socket_temp_root())
        with mock.patch.object(tempfile, 'tempdir', native), mock.patch.dict(os.environ, {'TMPDIR': native, 'TMP': native, 'TEMP': native}):
            with self.assertRaisesRegex(AssertionError, "terminal"):
                scenario(before_root)
            with self.assertRaisesRegex(AssertionError, "terminal"):
                scenario(before_root, named_root)
            # Admit the failures under the actual old source, then recover that
            # existing original history with the fresh fixed reader after restart.
            scenario(before_root, self.qualified_source)

    def test_capped_local_master_keeps_remote_guest_file_limit_independent(self):
        # The original complete SSH peer executed its alleged guest under the
        # local master's kernel4096-byte diagnostic limit. Actual remote hosts
        # do not inherit this limit; the separate real-socket guest fixes it.
        fixture=Path(__file__).parent/'fixtures/program_readiness'
        before=(fixture/'ssh_peer.before_local_limit.source').read_text()
        self.assertEqual(json.loads((fixture/'provenance.json').read_bytes())['beforeLocalLimitSha256'],hashlib.sha256(before.encode()).hexdigest())
        current=(fixture/'ssh_peer.source').read_text()
        binary=self.root/'bin/ssh'
        from agent_tools import ssh_program_execution_remote as remote
        def stage(peer_source):
            binary.write_text('#!'+sys.executable+'\n'+peer_source);binary.chmod(0o700)
            # Use actual central readiness, with only the admitted executable
            # source path changed in the private source fixture.
            name='_limit_qualified_loader_'+uuid.uuid4().hex
            spec=importlib.util.spec_from_file_location(name,self.qualified_source/'agent_tools/source_module_loader.py')
            module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
            self.addCleanup(sys.modules.pop,name,None)
            operation=str(uuid.uuid4());proxy=module.Adapter(self.qualified_source/'agent_tools','ssh_program_execution')
            try:proxy._module._ensure_transport(self.root,'explicit-peer',operation)
            finally:proxy.close()
            owner=master.status(self.root,'explicit-peer')
            command=remote.prepare_command(operation,self.request("print('unsubmitted')")['program'],jobs.owner_source())
            from agent_tools import ssh_transport as transport
            argv=transport.build_ssh_argv(transport.load_config(self.root),'explicit-peer',command=command)
            try:
                result=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=8)
                self.assertEqual(0,result.returncode,result.stderr[-400:])
                packet=json.loads(result.stdout)
                self.assertGreater((Path(packet['remoteRoot'])/'owner-module.py').stat().st_size,4096)
            finally:
                if keeper.actor(owner['child']['pid'])==owner['child']['actor']:os.kill(owner['child']['pid'],signal.SIGTERM)
                # Preflight only: exact operation root, owned0700, no admitted
                # job directory. Even the failed partial root is safe to close.
                root=Path('/tmp').resolve()/('vpn-control-program-'+str(os.geteuid())+'-'+operation)
                if root.exists():
                    self.assertEqual(os.geteuid(),root.stat().st_uid)
                    self.assertFalse((root/operation).exists())
                    shutil.rmtree(root)
        with self.assertRaises(AssertionError):stage(before)
        stage(current)

    def test_preserved_foreground_beforeimage_causally_fails_same_disconnect(self):
        # Get the actual transitive source capsule, then replace only the two
        # complete preserved unfixed port modules. Run the same assertion.
        self.start(self.request("print('source capsule')"));self.terminal()
        self.clean_remote_root()
        capsule = self.directory()/'capsule'
        source_root = self.root/'unfixed-source';shutil.copytree(capsule,source_root)
        before = Path(__file__).parent/'fixtures/program_durable_before'
        pins = json.loads((before/'provenance.json').read_bytes())['files']
        for name in ('ssh_program_execution.py','ssh_program_execution_remote.py'):
            raw=(before/(name+'.source')).read_bytes()
            self.assertEqual(pins[name]['sha256'],hashlib.sha256(raw).hexdigest())
            (source_root/'agent_tools'/name).write_bytes(raw)
        self.operation=str(uuid.uuid4())
        # Actual RED: the foreground child stops advancing or cannot return a
        # correlated terminal receipt. No mocked failure or replacement source.
        with self.assertRaises(AssertionError):
            self.disconnect_and_expect_original_completion(source_root)


if __name__=='__main__':
    unittest.main()
