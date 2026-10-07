"""Actual emitted processes and canonical lease source; no SSH/ADB authority."""
import ast,io,json,os,stat,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
from agent_tools import android_installer_direct_transport as direct

class PortableDecisions(unittest.TestCase):
    def test_typed_original_submission_identity(self):
        import copy
        corr='f41d90d8-ac1b-4a1d-b1f2-37d580da93a2'
        value={'state':'submitted','correlationId':corr,'pid':42,'identity':{'pid':42,'startTicks':7,'bootId':corr},'workerSha256':'a'*64,'replayAllowed':False}
        self.assertEqual(value,direct.submission_shape(value,corr,'a'*64))
        for path,invalid in [('pid',True),('pid',43),('startTicks',True),('startTicks',0),('bootId','foreign')]:
            changed=copy.deepcopy(value);changed['identity'][path]=invalid
            with self.assertRaises(ValueError):direct.submission_shape(changed,corr,'a'*64)
    def test_finite_cli_ingress_refuses_before_any_process(self):
        for args in [['--root','.','callback','--correlation-id','foreign','--phase','tap'],['--root','.','shell']]:
            with mock.patch.object(direct.subprocess,'Popen',side_effect=AssertionError('must not spawn')),self.assertRaises(SystemExit):direct.main(args)

    def test_actual_frame_roundtrip_and_refusal(self):
        body=b'print("source-only")\n'
        self.assertEqual(body,direct.read_frame(io.BytesIO(direct.framed_program(body))))
        for raw in [direct.framed_program(body)+b'x',direct.framed_program(body)[:-1],b'{"schema":true,"bytes":1,"sha256":"'+b'a'*64+b'"}\nx']:
            with self.assertRaises(ValueError):direct.read_frame(io.BytesIO(raw))
    def test_unavailable_native_api_refuses(self):
        with mock.patch.object(direct.os,'getuid',None,create=True),self.assertRaisesRegex(ValueError,'direct_posix_required'):direct.posix()
    def test_missing_terminal_is_unknown_not_reentry(self):
        with tempfile.TemporaryDirectory()as temp:
            if os.name=='posix':self.assertEqual('unknown',direct.saved_terminal(Path(temp).resolve(),'a'*64)['state'])
            else:
                with self.assertRaisesRegex(ValueError,'direct_posix_required'):direct.saved_terminal(Path(temp),'a'*64)
            self.assertEqual([],list(Path(temp).iterdir()))

@unittest.skipUnless(os.name=='posix','Actual POSIX descriptor child and flock; portable frame refusal remains covered')
class EmittedSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
    def source(self):
        source=direct.supervisor_source().decode()
        if sys.platform!='linux':
            # Explicit local kernel fixture seam: birth is unavailable on Mac;
            # source, descriptor exec, gate, collector and journal remain actual.
            tree=ast.parse(source)
            for n in tree.body:
                if isinstance(n,ast.FunctionDef)and n.name=='birth':
                    n.body=ast.parse("return {'pid':pid,'startTicks':1,'bootId':'local-kernel-fixture'}").body
            source=ast.unparse(ast.fix_missing_locations(tree)).replace('/proc/self/fd/','/dev/fd/')
        return source
    def run_worker(self,body):
        program=direct.WORKER_GATE+body
        direct.write_once(self.root,'worker.py',program.encode())
        result=subprocess.run([sys.executable,'-I','-u','-B','-c',self.source(),str(self.root),direct.sha(program.encode())],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,(result.stdout,result.stderr))
        return direct.saved_terminal(self.root,direct.sha(program.encode()))
    def test_actual_write_pin_matches_unchanged_prepared_program_read(self):
        producer=direct.write_once(self.root,'program-0000.py',b'original-source\n')
        body,consumer=direct.snapshot(self.root/'program-0000.py',524288,True)
        self.assertEqual(b'original-source\n',body);self.assertTrue(direct.equal(producer,consumer));self.assertIn('parents',producer)
        (self.root/'program-0000.py').write_bytes(b'foreign-source')
        self.assertFalse(direct.equal(producer,direct.snapshot(self.root/'program-0000.py',524288,True)[1]))

    def test_actual_emitted_gate_raw_eof_and_original_identity(self):
        value=self.run_worker("import sys\nprint('original-accepted')\nprint('raw-stderr',file=sys.stderr)\n")
        self.assertEqual('terminal',value['state']);self.assertEqual(b'original-accepted\n',value['raw']['stdout']);self.assertEqual(b'raw-stderr\n',value['raw']['stderr'])
        for name in ['supervisor.json','worker.json']:
            row=json.loads((self.root/name).read_bytes());self.assertGreater(row['identity']['pid'],0);self.assertIs(row['replayAllowed'],False)
        with self.assertRaises(FileExistsError):direct.write_once(self.root,'worker.py',b'foreign')
    def test_actual_original_journal_reader_preserves_terminal_raw_no_actor_adoption(self):
        import uuid
        corr='f41d90d8-ac1b-4a1d-b1f2-37d580da93a2'
        parent=self.root
        self.root=parent/('android-installer-component-bundle-'+str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker')))
        self.root.mkdir(mode=0o700)
        body="print('saved-original-raw')\n"
        value=self.run_worker(body)
        source=direct.original_journal_source(parent,corr,direct.sha((direct.WORKER_GATE+body).encode()))
        observed=subprocess.run([sys.executable,'-I','-u','-B','-c',direct._observer_frame_reader(source)],input=direct.framed_program(source),capture_output=True,timeout=10)
        self.assertEqual(0,observed.returncode,observed.stderr)
        row=json.loads(observed.stdout);self.assertIsNone(row['actorAccepted']);self.assertIsNone(row['actorCustody'])
        self.assertEqual('terminal',row['collector']['state']);self.assertFalse(row['replayAllowed'])
        self.assertEqual(value['receipt'],row['collector']['receipt'])
        self.assertEqual(value['raw']['stdout'],__import__('base64').b64decode(row['raw'][0]['bodyBase64']))
        self.assertEqual('unknown',direct.project_original_capture(corr,{'programSha256':direct.sha((direct.WORKER_GATE+body).encode()),'packet':{}},row)['state'])

    def test_actual_exit_failure_not_hidden_by_transport(self):
        value=self.run_worker("print('original-raw')\nraise SystemExit(7)\n")
        self.assertEqual(7,value['receipt']['returncode']);self.assertEqual(b'original-raw\n',value['raw']['stdout'])
    def test_actual_worker_sha_drift_prevents_child(self):
        direct.write_once(self.root,'worker.py',direct.WORKER_GATE.encode())
        result=subprocess.run([sys.executable,'-c',self.source(),str(self.root),'a'*64],capture_output=True,timeout=5)
        self.assertNotEqual(0,result.returncode);self.assertFalse((self.root/'worker.json').exists())
    def test_saved_missing_eof_is_unknown_and_raw_preserved(self):
        value=self.run_worker("print('retained')\n")
        path=self.root/'terminal.json';row=json.loads(path.read_bytes());row['eof']['stderr']=False;path.write_bytes(direct.canonical(row))
        value=direct.saved_terminal(self.root,row['workerSha256']);self.assertEqual('unknown',value['state']);self.assertEqual(b'retained\n',value['raw']['stdout'])

@unittest.skipUnless(os.name=='posix','Canonical POSIX flock claim; no network/device fixture')
class SharedClaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.corr='65c6a797-d766-4dc2-b6e9-284aa6b59c56'
    def run_claim(self,source):
        body='ADMITTED_ROOT='+repr(str(self.root))+'\n'+source
        result=subprocess.run([sys.executable,'-I','-B','-c',body,'claim',str(self.root),'archlinux','android-api35',self.corr,'android-installer'],capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,(result.stdout,result.stderr));return json.loads(result.stdout)
    def test_actual_original_canonical_claim_and_collision_unchanged(self):
        from agent_tools import android_installer_dispatch as dispatch
        old=self.run_claim(dispatch._REMOTE_SHARED);self.assertEqual('claimed',old['state'])
        before=(self.root/'android-native-device-android-api35.lease').read_bytes()
        new=self.run_claim(direct.shared_claim_source());self.assertEqual('foreign_or_prior_lease',new['reason'])
        self.assertEqual(before,(self.root/'android-native-device-android-api35.lease').read_bytes())
    def test_actual_root_mode_and_symlink_refused(self):
        self.root.chmod(0o755);result=self.run_claim(direct.shared_claim_source());self.assertEqual('root_unsafe',result['reason'])
        self.assertFalse((self.root/'android-native-device-android-api35.lease').exists())
    @unittest.skipUnless(sys.platform=='linux' and getattr(os,'getuid',lambda:-1)()==0,'Actual Linux UID0/owner1000 continuity; not established on Mac')
    def test_actual_mixed_principal_original_red_fixed_green(self):
        from agent_tools import android_installer_dispatch as dispatch
        os.chown(self.root,1000,1000)
        self.assertEqual('root_unsafe',self.run_claim(dispatch._REMOTE_SHARED)['reason'])
        self.assertEqual('claimed',self.run_claim(direct.shared_claim_source())['state'])
        row=(self.root/'android-native-device-android-api35.lease').lstat();self.assertEqual(0,row.st_uid);self.assertEqual(0o600,stat.S_IMODE(row.st_mode))

@unittest.skipUnless(os.name=='posix','Actual detached POSIX carrier; portable frame coverage separate')
class BootstrapTests(unittest.TestCase):
    setUp=EmittedSupervisorTests.setUp
    source=EmittedSupervisorTests.source
    def binding(self):
        from agent_tools import android_installer_component_bundle as bundle
        chain,parents=bundle._parents(self.root)
        try:
            if sys.platform=='linux':boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
            else:boot='feb543a9-c4f5-4dc0-94ef-6dd2300a34c3'
            return {'principal':{'uid':os.getuid(),'euid':os.geteuid(),'gid':os.getgid(),'egid':os.getegid(),'groups':sorted(os.getgroups())},'bootId':boot,'rootParents':parents}
        finally:bundle._close(chain)
    def test_actual_entire_frame_bootstrap_detached_worker_and_saved_raw(self):
        corr='b3e23a9a-fc96-4b0d-869f-fb1b72d5ec37'
        program=(direct.WORKER_GATE+"print('framed-worker-original')\n").encode()
        source=direct.bootstrap_source(self.root,corr,program,self.binding())
        if sys.platform!='linux':
            # Same explicit local-kernel seams as the supervisor tests.
            source=source.replace(repr(direct.supervisor_source().decode()),repr(self.source())).replace('/proc/self/fd/','/dev/fd/').replace("Path('/proc/sys/kernel/random/boot_id').read_text().strip()",repr(self.binding()['bootId']))
        result=subprocess.run([sys.executable,'-I','-u','-B','-c',source],input=direct.framed_program(program),capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,(result.stdout,result.stderr));accepted=json.loads(result.stdout)
        self.assertEqual('submitted',accepted['state']);self.assertGreater(accepted['pid'],0)
        leaf=self.root/('android-installer-component-bundle-'+corr)
        deadline=time.monotonic()+5
        while not (leaf/'terminal.json').exists() and time.monotonic()<deadline:time.sleep(.02)
        value=direct.saved_terminal(leaf,direct.sha(program));self.assertEqual('terminal',value['state']);self.assertEqual(b'framed-worker-original\n',value['raw']['stdout'])
        self.assertEqual(accepted['pid'],json.loads((leaf/'supervisor.json').read_bytes())['identity']['pid'])
        # Reentry is an exclusive leaf refusal, never another worker.
        again=subprocess.run([sys.executable,'-I','-B','-c',source],input=direct.framed_program(program),capture_output=True,timeout=5)
        self.assertNotEqual(0,again.returncode)
    def test_actual_malformed_framing_before_remote_leaf(self):
        corr='b3e23a9a-fc96-4b0d-869f-fb1b72d5ec37';program=direct.WORKER_GATE.encode()
        source=direct.bootstrap_source(self.root,corr,program,self.binding())
        result=subprocess.run([sys.executable,'-c',source],input=direct.framed_program(program)[:-1],capture_output=True,timeout=5)
        self.assertNotEqual(0,result.returncode);self.assertEqual([],list(self.root.iterdir()))
    def test_actual_4096_source_staging_restores_original_child_limit(self):
        corr='1747e426-5c0c-45a0-9248-b977bda4c891'
        program=(direct.WORKER_GATE+'#'+('x'*16384)+"\nimport resource,json\nprint(json.dumps(list(resource.getrlimit(resource.RLIMIT_FSIZE))))\n").encode()
        source=direct.bootstrap_source(self.root,corr,program,self.binding())
        if sys.platform!='linux':
            source=source.replace(repr(direct.supervisor_source().decode()),repr(self.source())).replace('/proc/self/fd/','/dev/fd/').replace("Path('/proc/sys/kernel/random/boot_id').read_text().strip()",repr(self.binding()['bootId']))
        source='import resource\nresource.setrlimit(resource.RLIMIT_FSIZE,(4096,8388608))\n'+source
        result=subprocess.run([sys.executable,'-I','-u','-B','-c',source],input=direct.framed_program(program),capture_output=True,timeout=5)
        self.assertEqual(0,result.returncode,(result.stdout,result.stderr))
        leaf=self.root/('android-installer-component-bundle-'+corr);deadline=time.monotonic()+5
        while not (leaf/'terminal.json').exists()and time.monotonic()<deadline:time.sleep(.02)
        value=direct.saved_terminal(leaf,direct.sha(program))
        self.assertEqual('terminal',value['state'],value)
        self.assertEqual([4096,8388608],json.loads(value['raw']['stdout']))
    def test_actual_source_replacement_after_staging_refuses_before_supervisor(self):
        corr='1c8f74b4-d777-4895-a64a-8836b682a784';program=(direct.WORKER_GATE+"print('original')\n").encode()
        source=direct.bootstrap_source(self.root,corr,program,self.binding());marker=self.root/'foreign-supervisor'
        if sys.platform!='linux':
            source=source.replace(repr(direct.supervisor_source().decode()),repr(self.source())).replace('/proc/self/fd/','/dev/fd/').replace("Path('/proc/sys/kernel/random/boot_id').read_text().strip()",repr(self.binding()['bootId']))
        victim=self.root/('android-installer-component-bundle-'+corr)/'supervisor.py'
        foreign='from pathlib import Path\nPath('+repr(str(marker))+').write_text("foreign")\n'
        hook='import os,stat\nfrom pathlib import Path\noriginal_fsync=os.fsync\nchanged=False\ndef local_fsync(fd):\n global changed\n original_fsync(fd)\n if not changed and stat.S_ISDIR(os.fstat(fd).st_mode)and Path('+repr(str(victim))+').exists():\n  changed=True\n  Path('+repr(str(victim))+').write_text('+repr(foreign)+')\nos.fsync=local_fsync\n'
        result=subprocess.run([sys.executable,'-I','-u','-B','-c',hook+source],input=direct.framed_program(program),capture_output=True,timeout=7)
        self.assertNotEqual(0,result.returncode);self.assertFalse(marker.exists(),(result.stdout,result.stderr))

@unittest.skipUnless(os.name=='posix','Actual emitted worker/actor fixture uses POSIX files; no device authority')
class WholeWorkerTests(unittest.TestCase):
    setUp=EmittedSupervisorTests.setUp
    source=EmittedSupervisorTests.source
    def test_actual_emitted_worker_runs_original_actor_callbacks_terminal_and_unknown(self):
        repo=Path(__file__).resolve().parents[2]
        body="import sys\nsys.path.insert(0,"+repr(str(repo))+ ")\nfrom agent_tools.tests.test_android_installer_outer_transport import WholeEntryTests\ncase=WholeEntryTests()\ncase.setUp()\ntry:\n case.whole_entry(True)\n print('ACTUAL_FULL_ACTOR_TERMINAL_AND_MISSING_EOF_REFUSAL')\nfinally:case.doCleanups()\n"
        program=(direct.WORKER_GATE+body).encode();direct.write_once(self.root,'worker.py',program)
        result=subprocess.run([sys.executable,'-I','-u','-B','-c',self.source(),str(self.root),direct.sha(program)],capture_output=True,timeout=150)
        self.assertEqual(0,result.returncode,(result.stdout,result.stderr))
        value=direct.saved_terminal(self.root,direct.sha(program));self.assertEqual(0,value['receipt']['returncode'],value['raw']['stderr'])
        self.assertIn(b'ACTUAL_FULL_ACTOR_TERMINAL_AND_MISSING_EOF_REFUSAL',value['raw']['stdout'])

@unittest.skipUnless(os.name=='posix','Actual sourceclosed baseline, routing, flock and custody fixture')
class PreclaimCompositionTests(unittest.TestCase):
    def test_actual_genuine_baseline_two_raw_backup_claim_and_no_reentry(self):
        import copy,types,uuid
        from agent_tools import android_installer_component_bundle as bundle
        from agent_tools.tests.test_android_installer_routing_backup import BackupTests
        fixture=BackupTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        backend,request,state_path,log=fixture.fixture()
        # Same API35 physical fixture conversion as the owned getter tests.
        backend['LAUNCH']['device']='api35';backend['LAUNCH']['port']=5682;backend['EXTERNAL']['serial']='emulator-5682'
        state=json.loads(state_path.read_bytes());state['sdk']='35';state_path.write_text(json.dumps(state))
        cmd=backend['PROC']/'18/cmdline';cmd.write_bytes(cmd.read_bytes().replace(b'5684',b'5682'))
        backend['GETTER']['generation']={'child':backend['child_identity'](17),'guest':backend['session_guest'](backend['child_identity'](17),{'qemuFact':backend['qemu_fact']()})}
        request.update(device='android-api35',expectedApi=35)
        fixture.case.actual_factory_functions(backend,'api35')
        # Virtual privileged receiver metadata only. Canonical flock/lease uses
        # real current-UID kernel files, not a manufactured successful receipt.
        osproxy=backend['os'];osproxy.getuid=osproxy.geteuid=osproxy.getgid=osproxy.getegid=lambda:0;osproxy.getgroups=lambda:[0]
        backend['COMMAND_HOST']=backend['command_host_identity']()
        corr='65c6a797-d766-4dc2-b6e9-284aa6b59c56'
        request['correlationId']=str(uuid.uuid5(uuid.UUID(corr),'complete-update-readonly-admission'))
        selected=bundle.modules(fixture.case.receipt);guard=bundle.BaselineGuard(fixture.case.receipt,selected,backend,request);guard()
        backup_request={**request,'correlationId':str(uuid.uuid5(uuid.UUID(corr),'complete-update-backup'))}
        seams=fixture.assembly_seams()
        importer=selected['adapter'].__dict__['__builtins__']['__import__']
        staged=importer('agent_tools.android_installer_routing_backup',{},None,('create',),0)
        real_os=staged.os;native_model=types.SimpleNamespace(**vars(real_os))
        native_model.getuid=native_model.geteuid=native_model.getgid=native_model.getegid=lambda:0;native_model.getgroups=lambda:[0]
        destination=fixture.case.root/('android-installer-component-baseline-'+backup_request['correlationId'])/'routing-backup'/'opening-routing.json'
        def projected(info):
            if stat.S_ISREG(info.st_mode)and destination.exists()and info.st_ino==destination.stat().st_ino:
                facts={name:getattr(info,name)for name in dir(info)if name.startswith('st_')};facts.update(st_uid=0,st_gid=0);return types.SimpleNamespace(**facts)
            return info
        native_model.fstat=lambda fd:projected(real_os.fstat(fd))
        native_model.stat=lambda *args,**kwargs:projected(real_os.stat(*args,**kwargs))
        import builtins
        original_import=builtins.__import__
        expected_file=str(fixture.case.root/'stage'/'agent_tools/android_installer_routing_backup.py')
        def fixture_import(name,globals=None,locals=None,fromlist=(),level=0):
            if name=='os'and globals and globals.get('__file__')==expected_file:return native_model
            return original_import(name,globals,locals,fromlist,level)
        # The actual wrapper constructs a fresh staged namespace. Bind only its
        # OS observation object, not its authenticated functions or result DTO.
        with mock.patch.object(builtins,'__import__',fixture_import),seams[1],seams[2]:backup=bundle.routing_backup(fixture.case.receipt,backend,backup_request)
        self.assertEqual(2,backup['readCount']);self.assertFalse((fixture.case.root/'android-native-device-android-api35.lease').exists())
        journal=fixture.case.root/'claim-journal';journal.mkdir(mode=0o700)
        namespace=dict(direct.__dict__);namespace['_DIRECT_AUTHENTICATED_ROOT']=fixture.case.root;namespace['_SHARED_CLAIM_SOURCE']=direct.shared_claim_source()
        claimant=types.FunctionType(direct.claim_after_backup.__code__,namespace)
        lease=claimant(guard,corr,journal,backup)
        self.assertEqual(corr,json.loads(Path(lease['path']).read_bytes())['correlationId'])
        with self.assertRaises(FileExistsError):claimant(guard,corr,journal,backup)
        self.assertEqual(backup['sha256'],direct.sha(Path(backup['path']).read_bytes()))
        calls=[json.loads(row)for row in log.read_text().splitlines()]
        self.assertFalse(any('install'in row or 'root'in row or 'unroot'in row for row in calls))

@unittest.skipUnless(os.name=='posix','Actual private source custody + bounded pipe subprocess')
class ClientCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.source=self.root/'source.py';self.source.write_bytes(b'ORIGINAL-LOCAL-SOURCE');self.source.chmod(0o600)
        self.pins={'source.py':direct.snapshot(self.source,private=True)[1]}
        self.capsule=self.root/'journal';self.capsule.mkdir(mode=0o700)
    def test_actual_local_pipe_raw_before_parse_and_no_secret_digest(self):
        program="import sys\ndata=sys.stdin.buffer.read()\nprint('raw-original')\nprint('retained-stderr',file=sys.stderr)\n"
        credential=b'{LOCAL-FIXTURE-SECRET}'
        frame=credential+b'\n'+direct.framed_program(program.encode())
        child,out,err,eof,reason=direct._transport_capture(self.capsule,[sys.executable,'-I','-u','-c',program],frame,'start',self.root,self.pins,direct.sha(program.encode()))
        self.assertEqual(0,child.returncode);self.assertEqual(b'raw-original\n',out);self.assertEqual(b'retained-stderr\n',err);self.assertTrue(all(eof.values()));self.assertIsNone(reason)
        bodies=b''.join(path.read_bytes()for path in self.capsule.iterdir())
        self.assertNotIn(credential,bodies);self.assertNotIn(direct.sha(frame).encode(),bodies)
    def test_actual_post_intent_source_replacement_refuses_before_child(self):
        marker=self.root/'foreign-released';original=direct.write_once
        def write(directory,name,raw):
            value=original(directory,name,raw)
            if name.endswith('-dispatch.json'):self.source.write_bytes(b'FOREIGN-SOURCE')
            return value
        argv=[sys.executable,'-c','from pathlib import Path;Path('+repr(str(marker))+').write_text("effect")']
        with mock.patch.object(direct,'write_once',write),self.assertRaisesRegex(ValueError,'direct_source_changed'):
            direct._transport_capture(self.capsule,argv,b'frame','start',self.root,self.pins,'a'*64)
        self.assertFalse(marker.exists());self.assertFalse((self.capsule/'start-child.json').exists())

    def _marker_boundary(self,mutation,after=False):
        marker=self.root/'counted-child';original=direct.write_once
        def write(directory,name,raw):
            value=original(directory,name,raw)
            if name==('start-raw-terminal.json' if after else 'start-dispatch.json'):
                path=self.capsule/'start-dispatch.json'
                if mutation=='delete':path.unlink()
                elif mutation=='replace':path.unlink();path.write_bytes(b'FOREIGN');path.chmod(0o600)
                else:path.chmod(0o660)
            return value
        body='import sys\nfrom pathlib import Path\nsys.stdin.buffer.read()\nPath('+repr(str(marker))+').write_text("ONE")\nprint("PUBLIC-RAW")\n'
        argv=[sys.executable,'-I','-B','-u','-c',body]
        with mock.patch.object(direct,'write_once',write):
            if after:
                child,out,err,eof,reason=direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,direct.sha(body.encode()))
                self.assertEqual(0,child.returncode);self.assertEqual('ONE',marker.read_text())
                self.assertEqual(b'PUBLIC-RAW\n',out);self.assertTrue(all(eof.values()))
                self.assertEqual('direct_dispatch_changed',reason)
                self.assertTrue((self.capsule/'start-stdout-00000.private').exists())
            else:
                with self.assertRaisesRegex(ValueError,'direct_dispatch_changed'):
                    direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,direct.sha(body.encode()))
                self.assertFalse(marker.exists());self.assertFalse((self.capsule/'start-child.json').exists())
        with self.assertRaises(FileExistsError):
            direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,direct.sha(body.encode()))
        self.assertEqual('ONE'if after else None,marker.read_text()if marker.exists()else None)
    def test_original_dispatch_delete_refuses_before_child_and_retry(self):self._marker_boundary('delete')
    def test_original_dispatch_replace_refuses_before_child_and_retry(self):self._marker_boundary('replace')
    def test_original_dispatch_mode_refuses_before_child_and_retry(self):self._marker_boundary('mode')
    def test_postcollection_dispatch_delete_keeps_raw_unknown_no_retry(self):self._marker_boundary('delete',True)
    def test_postcollection_dispatch_replace_keeps_raw_unknown_no_retry(self):self._marker_boundary('replace',True)

    def _late_parent_marker_boundary(self,target,mutation,after=False):
        # Real original source/FD guards and counted harmless child. Trigger at
        # final dispatch parent stat, after the old whole-population leaf reads.
        marker=self.root/'late-parent-child';stat_original=direct.os.stat;fired=[]
        body='import sys\nfrom pathlib import Path\nsys.stdin.buffer.read()\nPath('+repr(str(marker))+').write_text("ONE")\nprint("PUBLIC-RAW")\n'
        def late(path,*args,**kwargs):
            observed=stat_original(path,*args,**kwargs);frame=sys._getframe(1)
            while frame and frame.f_code.co_name!='_dispatch_guard':frame=frame.f_back
            if (not fired and path==str(self.capsule) and frame is not None
                    and frame.f_back.f_code.co_name=='_transport_capture'
                    and str(frame.f_locals['path']).endswith('start-dispatch.json')
                    and (self.capsule/'start-raw-terminal.json').exists()==after):
                leaf=self.capsule/('start-'+target+'.json')
                if mutation=='delete':leaf.unlink()
                elif mutation=='replace':leaf.unlink();leaf.write_bytes(b'FOREIGN');leaf.chmod(0o600)
                else:leaf.chmod(0o660)
                fired.append(True)
            return observed
        argv=[sys.executable,'-I','-B','-u','-c',body]
        with mock.patch.object(direct.os,'stat',side_effect=late):
            if after:
                child,out,err,eof,reason=direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,direct.sha(body.encode()))
                self.assertEqual(0,child.returncode);self.assertEqual(b'PUBLIC-RAW\n',out)
                self.assertTrue(all(eof.values()));self.assertEqual('direct_dispatch_changed',reason)
                self.assertTrue((self.capsule/'start-stdout-00000.private').exists())
            else:
                with self.assertRaisesRegex(ValueError,'direct_dispatch_changed'):
                    direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,direct.sha(body.encode()))
                self.assertFalse(marker.exists());self.assertFalse((self.capsule/'start-child.json').exists())
        self.assertEqual([True],fired)
        with mock.patch.object(direct.subprocess,'Popen',side_effect=AssertionError('no replay')),self.assertRaises(FileExistsError):
            direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,direct.sha(body.encode()))
    def test_final_parent_delete_all_dispatch_leaves_refuses_before_child(self):
        for target in ('once','dispatch'):
            with self.subTest(target=target):
                self.doCleanups();self.setUp();self._late_parent_marker_boundary(target,'delete')
    def test_final_parent_replace_all_dispatch_leaves_refuses_before_child(self):
        for target in ('once','dispatch'):
            with self.subTest(target=target):
                self.doCleanups();self.setUp();self._late_parent_marker_boundary(target,'replace')
    def test_final_parent_mode_all_dispatch_leaves_refuses_before_child(self):
        for target in ('once','dispatch'):
            with self.subTest(target=target):
                self.doCleanups();self.setUp();self._late_parent_marker_boundary(target,'mode')
    def test_postcollection_final_parent_delete_retains_raw_unknown(self):
        self._late_parent_marker_boundary('dispatch','delete',True)

    def _postspawn_publication_failure(self,failed_role):
        count=self.root/'child-count';original=direct.write_once
        body='import sys\nfrom pathlib import Path\nsys.stdin.buffer.read()\np=Path('+repr(str(count))+')\np.write_text((p.read_text()if p.exists()else "")+"ONE\\n")\nprint("PUBLIC_PREFIX")\nprint("PUBLIC_ERROR",file=sys.stderr)\n'
        argv=[sys.executable,'-I','-B','-u','-c',body]
        children=[];popen=direct.subprocess.Popen
        def spawn(*args,**kwargs):
            child=popen(*args,**kwargs);children.append(child);return child
        def publish(directory,name,raw):
            if name==failed_role:raise OSError('INERT-PUBLICATION-FAILURE')
            return original(directory,name,raw)
        try:
            with mock.patch.object(direct,'write_once',publish),mock.patch.object(direct.subprocess,'Popen',spawn):
                child,out,err,eof,reason=direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,direct.sha(body.encode()))
            self.assertIs(child,children[0]);self.assertEqual(0,child.returncode)
            self.assertEqual(b'PUBLIC_PREFIX\n',out);self.assertEqual(b'PUBLIC_ERROR\n',err);self.assertTrue(all(eof.values()))
            self.assertEqual('direct_journal_publication_failed',reason);self.assertEqual('ONE\n',count.read_text())
            self.assertTrue((self.capsule/'start-once.json').exists())
            if failed_role!='start-raw-terminal.json':
                terminal=json.loads((self.capsule/'start-raw-terminal.json').read_bytes())
                self.assertTrue(terminal['publicationFailures']);self.assertEqual(child.pid,terminal['pid'])
                self.assertEqual(0,terminal['returncode']);self.assertEqual({'stdout':True,'stderr':True},terminal['eof'])
            with mock.patch.object(direct.subprocess,'Popen',side_effect=AssertionError('replay forbidden')),self.assertRaises(FileExistsError):
                direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,direct.sha(body.encode()))
        finally:
            # Test cleanup observes the same harmless child if old code raised.
            for child in children:
                if child.poll()is None:child.communicate(b'PUBLIC',timeout=5)
                for stream in (child.stdin,child.stdout,child.stderr):
                    if stream is not None and not stream.closed:stream.close()
    def test_child_journal_failure_keeps_original_child_raw_unknown(self):self._postspawn_publication_failure('start-child.json')
    def test_stdout_storage_failure_keeps_actual_raw_unknown(self):self._postspawn_publication_failure('start-stdout-00000.private')
    def test_terminal_storage_failure_keeps_original_child_unknown(self):self._postspawn_publication_failure('start-raw-terminal.json')

    def test_pipe_setup_failure_returns_original_live_child_without_eof_or_replay(self):
        children=[];original=direct.subprocess.Popen
        def spawn(*args,**kwargs):
            child=original(*args,**kwargs);children.append(child);return child
        argv=[sys.executable,'-I','-B','-u','-c','import sys;sys.stdin.buffer.read();print("PUBLIC-LATE")']
        try:
            with mock.patch.object(direct.subprocess,'Popen',spawn),mock.patch.object(direct.os,'set_blocking',side_effect=OSError('INERT-SETUP')):
                child,out,err,eof,reason=direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,'a'*64)
            self.assertIs(child,children[0]);self.assertIsNone(child.poll())
            self.assertEqual('direct_transport_io_unknown',reason);self.assertEqual({'stdout':False,'stderr':False},eof)
            self.assertEqual((b'',b''),(out,err))
            terminal=json.loads((self.capsule/'start-raw-terminal.json').read_bytes())
            self.assertIsNone(terminal['returncode']);self.assertEqual(child.pid,terminal['pid'])
            self.assertEqual(eof,terminal['eof'])
            with mock.patch.object(direct.subprocess,'Popen',side_effect=AssertionError('replay forbidden')),self.assertRaises(FileExistsError):
                direct._transport_capture(self.capsule,argv,b'PUBLIC','start',self.root,self.pins,'a'*64)
            observed,_=child.communicate(b'PUBLIC',timeout=5)
            self.assertEqual(b'PUBLIC-LATE\n',observed);self.assertEqual(0,child.returncode)
        finally:
            for child in children:
                if child.poll()is None:child.communicate(b'PUBLIC',timeout=5)
                for stream in (child.stdin,child.stdout,child.stderr):
                    if stream is not None and not stream.closed:stream.close()


@unittest.skipUnless(os.name=='posix'and hasattr(os,'O_NOFOLLOW'),'Protected selected-route POSIX fixture; never SSH')
class SelectedRouteTests(unittest.TestCase):
    def setUp(self):
        from agent_tools.tests.test_ssh_channel_selection import SelectionTests
        self.fixture=SelectionTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.assertEqual('selected',self.fixture.select()['state'])
    def test_actual_selected_builder_multiline_refusal_then_framed_bridge_argv(self):
        import shlex,base64
        from agent_tools import ssh_transport
        config=ssh_transport.load_config(self.fixture.root);source="import sys\nprint('source-bound fixture')\n"
        # Real producer ingress is the causal reason a multiline -c source
        # cannot be placed directly in SSH argv. The carrier sends it framed.
        with self.assertRaises(ssh_transport.SshConfigError):ssh_transport.build_ssh_argv(config,'archlinux',command=['python3','-c',source])
        argv=direct.fixed_ssh_argv(self.fixture.root,source)
        child=self.fixture.f.real_popen([sys.executable,'-I','-B','-c','import json,sys;print(json.dumps(sys.argv[1:]))',*argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        out,err=child.communicate(timeout=3);self.assertEqual(0,child.returncode);self.assertEqual(b'',err);self.assertEqual(argv,json.loads(out))
        inner=shlex.split(argv[-1]);command=shlex.split(inner[-1])
        self.assertEqual(['sudo','-S','-p','','--','python3','-I','-u','-B','-c'],command[:-1])
        tree=ast.parse(command[-1]);encoded=next(node.args[0].value for node in ast.walk(tree)if isinstance(node,ast.Call)and isinstance(node.func,ast.Attribute)and node.func.attr=='b64decode')
        self.assertEqual(source.encode(),base64.b64decode(encoded));self.assertNotIn('inert private sentinel',repr(argv))
    def test_actual_expired_or_missing_selection_has_no_fallback(self):
        self.fixture.f.stdout=json.dumps({'state':'ended','correlationId':self.fixture.corr,'prior':self.fixture.remote,'gatewayBoot':self.fixture.remote['master']['gatewayBoot']}).encode()
        from agent_tools import ssh_transport
        with self.assertRaises(ssh_transport.SshConfigError):direct.fixed_ssh_argv(self.fixture.root,'print(1)')
        self.assertEqual(1,sum(call[6]=='prepare'for call in self.fixture.f.calls))
        (self.fixture.group/'current.json').unlink()
        with self.assertRaises(ssh_transport.SshConfigError):direct.fixed_ssh_argv(self.fixture.root,'print(1)')
    def test_actual_selected_pointer_and_configuration_drift_refuse(self):
        from agent_tools import ssh_transport
        pointer=self.fixture.group/'current.json';old=pointer.read_bytes();value=json.loads(old);value['history']='selection-'+('a'*32)+'.json';pointer.write_text(json.dumps(value))
        with self.assertRaises(ssh_transport.SshConfigError):direct.fixed_ssh_argv(self.fixture.root,'print(1)')
        pointer.write_bytes(old);self.fixture.f.f.config_path.write_bytes(self.fixture.f.f.config_path.read_bytes()+b' ')
        with self.assertRaises(ssh_transport.SshConfigError):direct.fixed_ssh_argv(self.fixture.root,'print(1)')

@unittest.skipUnless(os.name=='posix','Whole source flow real custody/kernel children; device observations remain fixture-only')
class JoinedDirectFlowTests(unittest.TestCase):
    setUp=EmittedSupervisorTests.setUp
    source=EmittedSupervisorTests.source
    def test_actual_emitted_worker_read_backup_claim_stage_actor_callbacks_terminal_same_flow(self):
        repo=Path(__file__).resolve().parents[2]
        body='import sys\nsys.path.insert(0,'+repr(str(repo))+')\nfrom agent_tools.tests.test_android_installer_direct_transport import JoinedDirectFlowTests\ncase=JoinedDirectFlowTests()\ntry:\n case._run_joined_fixture()\n print("ACTUAL_JOINED_READ_BACKUP_CLAIM_STAGE_ACTOR_TERMINAL")\nfinally:case.doCleanups()\n'
        program=(direct.WORKER_GATE+body).encode();direct.write_once(self.root,'worker.py',program)
        result=subprocess.run([sys.executable,'-I','-u','-B','-c',self.source(),str(self.root),direct.sha(program)],capture_output=True,timeout=150)
        self.assertEqual(0,result.returncode,(result.stdout,result.stderr))
        saved=direct.saved_terminal(self.root,direct.sha(program))
        self.assertEqual('terminal',saved['state']);self.assertEqual(0,saved['receipt']['returncode'],saved['raw']['stderr'])
        self.assertIn(b'ACTUAL_JOINED_READ_BACKUP_CLAIM_STAGE_ACTOR_TERMINAL',saved['raw']['stdout'])
    def _run_joined_fixture(self):
        import copy,hashlib,inspect,textwrap,types,uuid,zipfile
        from agent_tools import android_installer_component_bundle as bundle
        from agent_tools.tests.test_android_installer_outer_transport import WholeEntryTests
        case=WholeEntryTests();case.setUp();self.addCleanup(case.doCleanups)
        source=textwrap.dedent(inspect.getsource(WholeEntryTests.whole_entry));tree=ast.parse(source);function=tree.body[0]
        # All large source bytes are real local fixture files. No build/installer
        # is executed; package metadata and GUI observations are existing seams.
        geometry=ast.parse('''
with self.args.base_apk.open('ab')as output:output.truncate(45026948)
self.installed.write_bytes(self.args.base_apk.read_bytes())
self.args.base_sha256=hashlib.sha256(self.args.base_apk.read_bytes()).hexdigest()
old=self.backend['GETTER']['packageSha256'];new=self.args.base_sha256
self.backend['GETTER']['packageSha256']=new;self.backend['EXTERNAL']['getterIdentity']['packageSha256']=new
for path in (self.fixture.root/'android-cli-stage-fixture-stage').glob('*.json'):
 path.write_text(path.read_text().replace(old,new))
intent=json.loads(self.args.intent_file.read_bytes());intent['pair']['baseSha256']=new;intent['pair']['baseArtifactId']='sha256-'+new
self.args.intent_file.write_text(json.dumps(intent))
name='assets/local-source-padding.bin';remaining=45026948-self.args.target_apk.stat().st_size-76-2*len(name)
with zipfile.ZipFile(self.args.target_apk,'a',compression=zipfile.ZIP_STORED)as archive:
 with archive.open(name,'w')as output:
  while remaining:
   block=b'x'*min(remaining,524288);output.write(block);remaining-=len(block)
assert self.args.target_apk.stat().st_size==45026948
''').body
        expanded=[]
        for node in function.body:
            expanded.append(node)
            if isinstance(node,ast.With)and 'zipfile.ZipFile(self.args.target_apk' in ast.unparse(node):expanded.extend(geometry)
            if ast.unparse(node)=='self.stage_fixture_assets()':expanded.extend(ast.parse('self.direct_before_actor(scope)\nintent=json.loads(self.args.intent_file.read_bytes())').body)
        function.body=expanded
        # The existing fixture adds its kernel-only outer identity seam after
        # actor construction because actor/backend were separate namespaces.
        # The joined production namespace must pin that seam before admission.
        class EarlierKernelSeam(ast.NodeTransformer):
            def visit_Assign(self,node):
                if ast.unparse(node).startswith("scope['outer_process_identity'] = lambda"):return None
                if ast.unparse(node)=="scope['update_main_factory'] = tracing_factory":return None
                return self.generic_visit(node)
            def visit_Call(self,node):
                if ast.unparse(node.func)=='dispatcher.submit_callback':return ast.parse('self.direct_emitted_callback(dispatcher.accepted,phase_name)',mode='eval').body
                return self.generic_visit(node)
        tree=EarlierKernelSeam().visit(tree)
        class RetainActorFailure(ast.NodeTransformer):
            def visit_With(self,node):
                if any(isinstance(n,ast.Call)and ast.unparse(n.func)=='dispatcher.run' for n in ast.walk(node)):
                    return ast.parse('try:\n '+ast.unparse(node).replace('\n','\n ')+'\nexcept BaseException as failed:\n failed.add_note("Actual actor failure: "+repr(actor.failure))\n raise').body[0]
                return self.generic_visit(node)
        tree=RetainActorFailure().visit(tree)
        namespace=dict(__import__('agent_tools.tests.test_android_installer_outer_transport',fromlist=['x']).__dict__)
        exec(compile(ast.fix_missing_locations(tree),'<explicit-whole-direct-fixture>','exec'),namespace)
        events=[]
        def before(scope):
            corr=json.loads(case.args.intent_file.read_bytes())['correlationId'];root=case.fixture.root
            lease=root/'android-native-device-android-api35.lease';lease.unlink()
            input_dir=root/('android-complete-update-inputs-'+corr)
            authority={'schema':1,'correlationId':corr,'productSourceSha':scope['UPDATE_PRODUCT'],'inputDirectory':str(input_dir),
                'files':{name:scope['outer_file'](input_dir/name,45026948)for name in scope['OUTER_FILES']},'tlsReceipt':scope['outer_file'](input_dir/'receipt.json',65536)}
            old_output=case.args.output;preserved=root/'preserved-original-fixture';old_output.rename(preserved)
            osproxy=case.backend['os'];osproxy.getuid=osproxy.geteuid=osproxy.getgid=osproxy.getegid=lambda:0;osproxy.getgroups=lambda:[0]
            case.backend['COMMAND_HOST']=case.backend['command_host_identity']()
            # Preserve real harmless Java/ADB children while virtualizing only
            # privileged receiver metadata; never change actual child UID.
            original_popen=case.backend['subprocess'].Popen
            def portable(argv,**kwargs):kwargs.pop('preexec_fn',None);return original_popen(argv,**kwargs)
            case.backend['subprocess'].Popen=portable
            request={'host':'archlinux','device':'android-api35','correlationId':str(uuid.uuid5(uuid.UUID(corr),'complete-update-readonly-admission')),
                'sourceSha':scope['UPDATE_PRODUCT'],'expectedOwner':case.backend['GETTER']['generation']['guest'].get('owner',case.intent_owner if hasattr(case,'intent_owner')else __import__('agent_tools.tests.test_android_installer_component_bundle',fromlist=['OWNER']).OWNER),
                'expectedRevision':0,'expectedAvd':'owned-fixture','expectedApi':35,'packageSha256':case.args.base_sha256,'reservation':copy.deepcopy(case.backend['LAUNCH']['intent']['reservation'])}
            scope.update(case.backend);scope.update(UPDATE_CORRELATION=corr,UPDATE_BASELINE_REQUEST=request,
                DIRECT_BACKUP_REQUEST={**request,'correlationId':str(uuid.uuid5(uuid.UUID(corr),'complete-update-backup'))},
                UPDATE_PAIR=json.loads((preserved/'intent.json').read_bytes())['pair'],DIRECT_CUSTODY=authority,
                DIRECT_INPUTS={'hostPrincipal':{'uid':0,'euid':0,'gid':0,'egid':0,'groups':[0]},'hostBootId':'c92688c4-36a7-4e3a-8b0d-8de1a1e8d71d'},
                _DIRECT_AUTHENTICATED_ROOT=root,_SHARED_CLAIM_SOURCE=direct.shared_claim_source(),bundle=bundle,
                require=direct.require,canonical=direct.canonical,equal=direct.equal,sha=direct.sha,correlation=direct.correlation,
                snapshot=direct.snapshot,write_once=direct.write_once,Path=Path,os=osproxy,sys=sys,uuid=uuid)
            # Execute the identical emitted definitions, including every real
            # production import. Only OS observations are modeled afterward.
            import builtins
            scope['__builtins__']=vars(builtins).copy()
            exec(compile(direct.worker_definitions_source(Path(direct.__file__).read_bytes()),'<actual-emitted-direct-definitions>','exec'),scope)
            scope['os']=osproxy
            # The real TempFS leaves belong to the local test account. Model
            # only the native receiver identity observations, leaving the
            # snapshot's own-kernel-file custody checks on that actual account.
            osproxy.getuid=lambda:os.getuid() if inspect.currentframe().f_back.f_code.co_name=='snapshot'else 0
            journal=root/('android-installer-component-bundle-'+str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker')));journal.mkdir(mode=0o700);scope['DIRECT_JOURNAL']=journal
            fixed_inputs={'correlationId':corr,'assetAuthority':authority,**scope['DIRECT_INPUTS']}
            fixed_baseline={**request,'correlationId':str(uuid.uuid5(uuid.UUID(corr),'complete-update-backup'))}
            with mock.patch.dict(os.environ,{'DIRECT_JOURNAL':str(journal)}):
                exec(compile(direct.worker_bindings_source(fixed_inputs,root,fixed_baseline,scope['UPDATE_PAIR'],'b'*64),'<actual-emitted-direct-bindings>','exec'),scope)
            # Only unavailable kernel boot observation is modeled. Real source
            # functions, actual held files, raw records and claim remain intact.
            class FixturePath:
                def __new__(cls,value):
                    if str(value)=='/proc/sys/kernel/random/boot_id':return types.SimpleNamespace(read_text=lambda:'c92688c4-36a7-4e3a-8b0d-8de1a1e8d71d')
                    return Path(value)
            scope['Path']=FixturePath
            if sys.platform!='linux':scope['outer_process_identity']=lambda pid=None:{'pid':os.getpid(),'startTicks':1,'bootId':'5be1a80b-c97e-4622-aa07-ff761767622f','uid':os.getuid(),'gid':os.getgid(),'groups':sorted(os.getgroups())}
            case.fixture.actual_factory_functions(scope,'api35')
            case.backend=scope
            # The backup wrapper loads fresh staged functions. Native root
            # assembly metadata is modeled only for its newly created file.
            real_import=builtins.__import__;real_os=os;model=types.SimpleNamespace(**vars(os));model.getuid=model.geteuid=model.getgid=model.getegid=lambda:0;model.getgroups=lambda:[0]
            dest=root/('android-installer-component-baseline-'+scope['DIRECT_BACKUP_REQUEST']['correlationId'])/'routing-backup'/'opening-routing.json'
            def metadata(info):
                if stat.S_ISREG(info.st_mode)and dest.exists()and info.st_ino==dest.stat().st_ino:
                    fields={n:getattr(info,n)for n in dir(info)if n.startswith('st_')};fields.update(st_uid=0,st_gid=0);return types.SimpleNamespace(**fields)
                return info
            model.fstat=lambda fd:metadata(real_os.fstat(fd));model.stat=lambda *a,**kw:metadata(real_os.stat(*a,**kw))
            expected=str(root/'stage'/'agent_tools/android_installer_routing_backup.py')
            def importer(name,globals=None,locals=None,fromlist=(),level=0):
                if name=='os'and globals and globals.get('__file__')==expected:return model
                # Canonical claim exercises the real local kernel owner,
                # separately from the virtual root receiver observations.
                if name=='os'and globals and globals.get('__name__')=='fixed_shared_claim':return real_os
                return real_import(name,globals,locals,fromlist,level)
            from agent_tools.tests.test_android_installer_routing_backup import BackupTests
            import resource
            limits=[(8388608,67108864)]
            def setlimit(which,value):limits[0]=value
            # Both genuine phases use the same finite resource observation:
            # 32MiB routing assembly, then64MiB copied APK staging. Never lower
            # the local test process's irreversible kernel hard limit.
            seams=(mock.patch.object(resource,'getrlimit',side_effect=lambda which:limits[0]),mock.patch.object(resource,'setrlimit',side_effect=setlimit))
            try:
                def observed(frame,event,arg):
                    if event=='call'and frame.f_code.co_name in {'_direct_prepare','routing_backup','claim_after_backup','_complete_update_stage'}:events.append(frame.f_code.co_name)
                old_profile=sys.getprofile();sys.setprofile(observed)
                try:
                    with mock.patch.object(builtins,'__import__',importer),seams[0],seams[1]:prepared=scope['_direct_prepare']()
                finally:sys.setprofile(old_profile)
            except Exception as failure:
                claim_raw=journal/'lease-claim-raw.private'
                if claim_raw.exists():failure.add_note('Actual harmless fixture claim raw: '+claim_raw.read_text())
                failure.add_note('Local fixture root principal/mode: '+repr((root.stat().st_uid,root.stat().st_gid,stat.S_IMODE(root.stat().st_mode),os.getuid(),scope['os'].getuid())))
                raise
            case.args=prepared['args'];case.args.reconciliation_timeout_seconds=5.;case.args.reconciliation_poll_seconds=.01
            case.original_intent=case.args.intent_file.read_bytes()
            _raw,case.direct_receipt_origin=direct.snapshot(journal/'component-receipt.json',65536,True)
            self.assertTrue((journal/'lease-claim-terminal.json').exists());self.assertTrue((case.args.output/'asset-stage.json').exists())
            self.assertEqual(corr,json.loads(lease.read_bytes())['correlationId'])
        case.direct_before_actor=before
        emitted_callbacks=[]
        original_fail=self.fail
        def preserve_fixture_assertion(message=None):
            print('ACTUAL_CALLBACK_FIXTURE_ASSERTION '+str(message),file=sys.__stderr__,flush=True)
            return original_fail(message)
        self.fail=preserve_fixture_assertion
        def direct_callback(accepted,phase_name):
            corr=accepted['correlationId'];root=case.fixture.root
            journal=root/('android-installer-component-bundle-'+str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker')))
            custody={'schema':1,'correlationId':corr,'sourcePacketSha256':'b'*64,'componentReceipt':case.direct_receipt_origin}
            observer=direct.observer_source(root,corr,journal,phase_name,accepted,'b'*64,custody)
            if sys.platform!='linux':
                # Mac has no Linux /proc birth/status observation. This sole
                # kernel seam positively checks the actual owned worker alive;
                # all custody/mailbox/phase/source bodies remain unchanged.
                tree=ast.parse(observer)
                node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='outer_process_identity')
                node.body=ast.parse('outer_os.kill(pid,0)\nreturn '+repr(accepted['identity'])).body
                observer=(ast.unparse(ast.fix_missing_locations(tree))+'\n').encode()
            capsule=journal/('callback-transport-'+phase_name);capsule.mkdir(mode=0o700)
            repo=Path(direct.__file__).resolve().parents[1];_body,source_pin=direct.snapshot(Path(direct.__file__),private=False)
            argv=[sys.executable,'-I','-u','-B','-c',direct._observer_frame_reader(observer)]
            child,out,err,eof,reason=direct._transport_capture(capsule,argv,direct.framed_program(observer),'callback',repo,{'agent_tools/android_installer_direct_transport.py':source_pin},direct.sha(observer))
            self.assertIsNone(reason);self.assertEqual(0,child.returncode,(out,err));self.assertTrue(all(eof.values()));reply=json.loads(out)
            self.assertEqual('request-written',reply['state']);self.assertFalse(reply['uiActionPerformed']);self.assertEqual(phase_name,reply['phase']);emitted_callbacks.append(phase_name)
        case.direct_emitted_callback=direct_callback
        namespace['whole_entry'](case,True)
        self.assertEqual(['handoff-ready','continue'],emitted_callbacks)
        self.assertEqual(['_direct_prepare','routing_backup','claim_after_backup','_complete_update_stage'],events)
        self.assertTrue((case.args.output/'complete-update-terminal.json').exists())
        # Read the actual completed outer journal through the emitted framed
        # observer. The receipt pin is its original creation, never a new read
        # adopted as authority. This is a saved fixture observation, not fresh
        # device acceptance and does not call any CLI/ADB provider.
        corr=json.loads(case.args.intent_file.read_bytes())['correlationId'];root=case.fixture.root
        journal=root/('android-installer-component-bundle-'+str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker')))
        origin=case.direct_receipt_origin
        accepted=[json.loads(line[len(b'COMPLETE_UPDATE_ACCEPTED '):])for line in case.outer_stdout.splitlines()if line.startswith(b'COMPLETE_UPDATE_ACCEPTED ')][0]
        custody={'schema':1,'correlationId':corr,'sourcePacketSha256':'b'*64,'componentReceipt':origin}
        observer=direct.observer_source(root,corr,journal,'status',accepted,'b'*64,custody)
        result=subprocess.run([sys.executable,'-I','-u','-B','-c',direct._observer_frame_reader(observer)],input=direct.framed_program(observer),capture_output=True,timeout=10)
        self.assertEqual(0,result.returncode,(result.stdout,result.stderr));observed=json.loads(result.stdout)
        self.assertEqual('terminal-recorded',observed['state']);self.assertFalse(observed['freshNativeAcceptance']);self.assertFalse(observed['transportEOFProven'])
        # A same-path changed saved receipt must refuse before loading the
        # purported source catalogue or publishing any successful status.
        with (journal/'component-receipt.json').open('ab')as output:output.write(b'\n')
        bad=subprocess.run([sys.executable,'-I','-u','-B','-c',direct._observer_frame_reader(observer)],input=direct.framed_program(observer),capture_output=True,timeout=10)
        self.assertNotEqual(0,bad.returncode);self.assertIn(b'direct_original_custody_changed',bad.stderr)


@unittest.skipUnless(os.name=='posix','Actual framed harmless callback child')
class CallbackWireTests(unittest.TestCase):
    def test_actual_original_mailbox_callback_capture_without_actor_replay(self):
        import copy,inspect,textwrap,uuid
        from agent_tools.tests.test_android_installer_outer_transport import OuterReleaseTests
        case=OuterReleaseTests();case.setUp();self.addCleanup(case.doCleanups)
        corr=json.loads(case.args.intent_file.read_bytes())['correlationId'];root=case.fixture.root
        original_output=case.args.output;canonical_output=root/('android-installer-component-baseline-'+corr)
        original_output.rename(canonical_output);case.args.output=canonical_output;case.args.intent_file=canonical_output/'intent.json'
        actor,dispatcher,scope=case.actor()
        dispatcher.identity=scope['outer_process_identity']()
        dispatcher._publish('dispatch',{**dispatcher.packet,'identity':dispatcher.identity,'state':'dispatch-intent'})
        accepted={'correlationId':corr,'sourcePacketSha256':'b'*64,'identity':dispatcher.identity,'intentPin':dispatcher.pins[str(dispatcher.directory/'00000-intent.json')],'dispatchPin':dispatcher.pins[str(dispatcher.directory/'00001-dispatch.json')]}
        journal=root/('android-installer-component-bundle-'+str(uuid.uuid5(uuid.UUID(corr),'complete-update-direct-worker')));journal.mkdir(mode=0o700)
        direct.write_once(journal,'component-receipt.json',direct.canonical(case.fixture.receipt));_,case.direct_receipt_origin=direct.snapshot(journal/'component-receipt.json',65536,True)
        tree=ast.parse(Path(__file__).read_bytes())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='JoinedDirectFlowTests')
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name=='_run_joined_fixture')
        callback=next(n for n in method.body if isinstance(n,ast.FunctionDef)and n.name=='direct_callback')
        emitted_callbacks=[]
        namespace={'case':case,'self':self,'direct':direct,'sys':sys,'Path':Path,'ast':ast,'os':os,'json':json,'uuid':uuid,'emitted_callbacks':emitted_callbacks}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[callback],type_ignores=[])),'<actual-callback-wire>','exec'),namespace)
        namespace['direct_callback'](accepted,'handoff-ready')
        self.assertEqual(['handoff-ready'],emitted_callbacks)
        self.assertTrue((dispatcher.directory/'request-handoff-ready.json').exists());self.assertFalse(actor.started)
