import concurrent.futures
from dataclasses import replace
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import readiness
from agent_tools import readiness_tart_macos_lifecycle as lifecycle


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.root.chmod(0o700)
        self.ready = readiness.Observation(
            "owned", "machine", "original-connection", "original-boot", "ordinary", "session",
            transport="ready", guest="running", guest_agent=True, trusted=True,
            owned=True, integrity=True, idle_visibility=readiness.IDLE_VISIBILITY)
        self.original = {"operationId": "11111111-1111-4111-8111-111111111111",
                         "actor": {"pid": 123, "birth": "darwin:1234:5"}}
        self.rid = "a" * 64

    def tearDown(self):
        self.temp.cleanup()

    def journal(self):
        return lifecycle.Journal(self.root, "owned", "machine")

    def test_all_seven_categories_are_required_before_power_admission(self):
        for category in readiness.IDLE_VISIBILITY:
            with self.subTest(category=category):
                journal = self.journal()
                try:
                    with self.assertRaisesRegex(lifecycle.LifecycleBlocked, "idle_incomplete"):
                        journal.admit("reboot", self.rid,
                                      replace(self.ready, idle_visibility=readiness.IDLE_VISIBILITY-{category}),
                                      original_owner=self.original)
                finally: journal.close()
                self.assertEqual(list(self.root.iterdir()), [])

    def test_active_unknown_and_coordinator_work_block_power(self):
        for value in (replace(self.ready, idle_blockers=frozenset({"unknown_jobs"})),
                      replace(self.ready, idle_blockers=frozenset({"running_jobs"})),
                      replace(self.ready, coordinator_host=True)):
            with self.assertRaises(lifecycle.LifecycleBlocked): lifecycle.require_idle(value)

    def test_lost_ack_retains_original_unknown_and_cannot_consume_again(self):
        journal = self.journal()
        try:
            intent = journal.admit("reboot", self.rid, self.ready, original_owner=self.original)
            self.assertEqual(journal.status(self.rid)["state"], "unsubmitted")
            journal.consume(self.rid, self.ready)
            before = {p.name: p.read_bytes() for p in self.root.iterdir()}
            self.assertEqual(journal.status(self.rid), {
                "state": "unknown", "operationId": intent["operationId"], "recoveryId": self.rid})
            with self.assertRaisesRegex(lifecycle.LifecycleBlocked, "original_effect_pending"):
                journal.consume(self.rid, self.ready)
            self.assertEqual(before, {p.name: p.read_bytes() for p in self.root.iterdir()})
        finally: journal.close()

    def test_concurrent_callers_publish_one_effect_and_clean_private_stages(self):
        journal = self.journal()
        journal.admit("reboot", self.rid, self.ready, original_owner=self.original)
        journal.close()
        def contender(_):
            current = self.journal()
            try:
                current.consume(self.rid, self.ready)
                return True
            except (FileExistsError, lifecycle.LifecycleBlocked): return False
            finally: current.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(contender, range(8))), 1)
        self.assertEqual(len(list(self.root.iterdir())), 2)
        self.assertFalse(any(path.name.startswith(".lifecycle-stage-") for path in self.root.iterdir()))

    def test_atomic_publication_window_blocks_without_treating_record_as_absent(self):
        import ast,hashlib,json,textwrap
        from agent_tools import private_inventory_lock as private
        before=Path(__file__).parent/'fixtures/tart_macos_lifecycle_read_before/lifecycle.before.source'
        raw=before.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),
                         '83e0b1e85e9f3bc265feba4fd82d4c523bc7f47b614e67cbee92e6748392b295')
        cls=next(n for n in ast.parse(raw).body if isinstance(n,ast.ClassDef)and n.name=='Journal')
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef)and n.name=='_read')
        source=textwrap.dedent('\n'.join(raw.decode().splitlines()[method.lineno-1:method.end_lineno]))
        namespace={'private':private,'json':json}
        exec(compile(source,'<whole-original-journal-read>','exec'),namespace)
        journal=self.journal()
        try:
            intent=journal.admit('shutdown',self.rid,self.ready,original_owner=self.original)
            name=journal._name(self.rid,'intent');path=self.root/name;stage=self.root/'.live-private-stage'
            os.link(path,stage)
            # The actual original method leaks an unclassified Snapshot failure.
            with self.assertRaises(ValueError)as old:namespace['_read'](journal,name)
            self.assertIs(type(old.exception),ValueError)
            with self.assertRaisesRegex(lifecycle.LifecycleBlocked,'record_unavailable'):journal._read(name)
            self.assertEqual(path.read_bytes(),stage.read_bytes())
            stage.unlink()
            self.assertEqual(journal._read(name),intent)
        finally:journal.close()

    def test_boot_or_session_change_blocks_effect_without_mutation(self):
        journal = self.journal()
        try:
            journal.admit("reboot", self.rid, self.ready, original_owner=self.original)
            for current in (replace(self.ready, boot="new"), replace(self.ready, session="new")):
                with self.assertRaisesRegex(lifecycle.LifecycleBlocked, "identity_changed"):
                    journal.consume(self.rid, current)
            self.assertEqual(len(list(self.root.iterdir())), 1)
        finally: journal.close()

    def test_start_and_resume_distinguish_stopped_from_saved_state(self):
        journal = self.journal()
        try:
            with self.assertRaises(lifecycle.LifecycleBlocked):
                journal.admit("resume", self.rid, replace(self.ready, guest="stopped"), original_owner=self.original)
            journal.admit("resume", self.rid, replace(self.ready, guest="suspended"), original_owner=self.original)
            with self.assertRaises(lifecycle.LifecycleBlocked):
                journal.admit("start", "b"*64, replace(self.ready, guest="suspended"), original_owner=self.original)
        finally: journal.close()

    def test_start_state_is_checked_again_before_dispatch(self):
        journal=self.journal()
        try:
            journal.admit('start',self.rid,replace(self.ready,guest='stopped'),original_owner=self.original)
            with self.assertRaisesRegex(lifecycle.LifecycleBlocked,'state_changed'):
                journal.consume(self.rid,self.ready)
            self.assertEqual(journal.status(self.rid)['state'],'unsubmitted')
        finally:journal.close()

    def test_saved_memory_is_metadata_only_and_symlinks_are_refused(self):
        path = self.root / "state.vzvmsave"
        path.write_bytes(b"owned public fixture memory sentinel")
        path.chmod(0o600)
        with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("memory must not be read")):
            self.assertEqual(lifecycle.saved_state(path)["size"], path.stat().st_size)
        link = self.root / "foreign"
        link.symlink_to(path)
        with self.assertRaisesRegex(lifecycle.LifecycleBlocked, "saved_state_unsafe"):
            lifecycle.saved_state(link)

    def test_replaced_parent_is_blocked_before_any_new_effect_file(self):
        journal = self.journal()
        journal.admit("reboot", self.rid, self.ready, original_owner=self.original)
        moved = self.root.with_name(self.root.name + "-moved")
        self.root.rename(moved)
        self.root.mkdir(mode=0o700)
        try:
            with self.assertRaises(ValueError): journal.consume(self.rid, self.ready)
            self.assertEqual(list(self.root.iterdir()), [])
            self.assertEqual(len(list(moved.iterdir())), 1)
        finally:
            journal.close()
            self.root.rmdir()
            moved.rename(self.root)

    def test_unknown_original_launch_cannot_be_replaced_by_a_pid_guess(self):
        owner = lifecycle.LaunchOwner(self.root, self.original["operationId"],
                                      lifecycle.jobs.MachineBinding("host", "machine", "boot", str(os.getuid())),
                                      (1, 2), "c"*64, ("/public/tart", "run", "owned"))
        with mock.patch.object(lifecycle.jobs, "observe", return_value={"state": "unknown"}):
            self.assertEqual(owner.observe(saved_path=self.root/"state.vzvmsave", deadline=1),
                             {"state": "unknown", "operationId": self.original["operationId"]})


class DelegateOutcomeTests(unittest.TestCase):
    def test_exit_zero_and_actor_absence_do_not_claim_a_clean_stop(self):
        self.assertEqual(lifecycle.terminal_state(0, None, None), 'off_unknown')
        self.assertEqual(lifecycle.terminal_state(0, 'guest_stop_error', None), 'off_unknown')
        self.assertEqual(lifecycle.terminal_state(0, 'ambiguous', None), 'off_unknown')
        self.assertEqual(lifecycle.terminal_state(1, 'guest_did_stop', None), 'off_unknown')
        self.assertEqual(lifecycle.terminal_state(0, 'guest_did_stop', None), 'stopped')
        self.assertEqual(lifecycle.terminal_state(0, 'save_complete', {'inode':1}), 'suspended')
        self.assertEqual(lifecycle.terminal_state(0, None, {'inode':1}), 'off_unknown')

    def test_bounded_streaming_parser_discards_raw_and_error_details(self):
        parser = lifecycle.DelegateOutcomes()
        parser.feed('stderr', b'guest has stopped the virtual machine\n')
        parser.feed('stdout', b'vnc://private-transient-discarded\n'+b'x'*2048+b'\n')
        parser.feed('stdout', b'guest has stopped the virtual ')
        parser.feed('stdout', b'machine\r\n')
        self.assertEqual(parser.outcome, 'guest_did_stop')
        self.assertEqual(parser._line, b'')
        parser.feed('stdout', b'guest has stopped the virtual machine due to error: discarded detail\n')
        self.assertEqual(parser.outcome, 'ambiguous')
        self.assertNotIn('discarded', repr(vars(parser)))

    def test_generated_owner_records_only_finite_delegate_outcome(self):
        body = lifecycle._START_BODY
        self.assertIn('outcomes.feed(key.data,data)', body)
        self.assertIn("'delegateOutcome':outcomes.outcome", body)
        self.assertNotIn('tart stop', body)
        compile(body, '<existing-instance-owner>', 'exec')

@unittest.skipUnless(__import__('sys').platform == 'darwin', 'actual Darwin owner boot/actor identity')
class GeneratedOwnerTests(unittest.TestCase):
    def test_complete_generated_owner_retains_delegate_kind_without_private_output(self):
        import hashlib, inspect, json, resource, subprocess, sys, time
        from agent_tools import readiness_tart_output as output
        from agent_tools import private_inventory_lock as private
        before=Path(__file__).parent/'fixtures/tart_macos_lifecycle_core/owner.before.source'
        old_body=before.read_text()
        self.assertEqual(hashlib.sha256(old_body.encode()).hexdigest(),
                         'b4e1aea7eeab7cbc89e531cb5f9ffcbe7b395db0e8ae406d84dc4ba40c9408d1')
        nvram_before=Path(__file__).parent/'fixtures/tart_macos_lifecycle_nvram/owner.before.source'
        old_nvram_body=nvram_before.read_text()
        self.assertEqual(hashlib.sha256(old_nvram_body.encode()).hexdigest(),
                         'c5b4e70513085a974203831cceebfc62d23a374c60035eee39e7ea890585846e')
        cases=[(lifecycle._START_BODY,'guest has stopped the virtual machine','guest_did_stop',0,False),
               (lifecycle._START_BODY,'guest has stopped the virtual machine due to error: discarded detail','guest_stop_error',0,False),
               (old_nvram_body,'guest has stopped the virtual machine','guest_did_stop',0,True),
               (lifecycle._START_BODY,'guest has stopped the virtual machine',None,1,True)]
        if resource.getrlimit(resource.RLIMIT_CORE)[1]>=65536:
            cases.append((old_body,'guest has stopped the virtual machine',None,1,False))
        for body,delegate,expected,exit_code,mutate_nvram in cases:
            with self.subTest(expected=expected,nvram_changed=mutate_nvram), tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary).resolve(); base.chmod(0o700)
                run=base/'owner';vm=base/'persisted';share=base/'share'
                for path in (run,vm,share):path.mkdir(mode=0o700)
                binary=base/'controlled-tart'
                binary.write_text('#!'+sys.executable+'\nimport json,resource,sys,time\nassert resource.getrlimit(resource.RLIMIT_CORE)==(0,0)\n'
                    +"if sys.argv[1]=='list':print(json.dumps([{'Name':'owned-fixture','State':'stopped'}]))\n"
                    +"else:\n print('VNC server is running at vnc://:gentle-river-silver-moon@127.0.0.1:5999',flush=True)\n"
                    +' time.sleep(.15)\n print('+repr(delegate)+',flush=True)\n')
                binary.chmod(0o700)
                config=vm/'config.json';disk=vm/'disk.img';nvram=vm/'nvram.bin'
                for path in (config,disk,nvram):path.write_bytes(b'public fixture');path.chmod(0o600)
                gen=lambda p:list(private._generation(p.lstat()))
                memory=base/'memory.json';storage=base/'storage.json'
                operation='11111111-1111-4111-8111-111111111111'
                hostboot=subprocess.check_output(['/usr/sbin/sysctl','-n','kern.bootsessionuuid']).decode().strip()
                plan={'root':str(run),'rootGeneration':[run.stat().st_dev,run.stat().st_ino],
                      'operationId':operation,'tart':str(binary),'fixtureDirectory':str(vm),'fixtureName':'owned-fixture',
                      'binaryGeneration':gen(binary),'binarySha256':hashlib.sha256(binary.read_bytes()).hexdigest(),
                      'diskGeneration':gen(disk),'configGeneration':gen(config),'configSha256':hashlib.sha256(config.read_bytes()).hexdigest(),
                      'nvramGeneration':gen(nvram),
                      'storageFixtureId':'controlled','reservationKey':'recovery-test:controlled','hostBoot':hostboot,
                      'memoryMiB':4096,'diskCapacityBytes':disk.stat().st_size,'storageLedger':str(storage),
                      'memoryLedger':str(memory),'expectedState':'stopped','bootstrapShare':str(share),'publicSharePins':[]}
                source=output.standalone_source()+inspect.getsource(lifecycle.jobs._birth)+'\n'+inspect.getsource(lifecycle.DelegateOutcomes)+'\n'+body
                source+='\nwith _output_private.Directory(Path('+repr(str(run))+'))as root_guard,_output_private.Directory(Path('+repr(str(vm))+'))as fixture_guard:\n run('+repr(plan)+')\n'
                def enable_child_core_budget():
                    if resource.getrlimit(resource.RLIMIT_CORE)[1]>=65536:
                        resource.setrlimit(resource.RLIMIT_CORE,(65536,resource.getrlimit(resource.RLIMIT_CORE)[1]))
                child=subprocess.Popen([sys.executable,'-I','-c',source],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                       preexec_fn=enable_child_core_budget)
                def publish(path,value):
                    path.write_text(json.dumps(value));path.chmod(0o600)
                try:
                    until=time.monotonic()+3
                    while not(run/'actor.json').exists()and time.monotonic()<until:time.sleep(.01)
                    actor=json.loads((run/'actor.json').read_bytes())
                    if mutate_nvram:
                        # Public harmless fixture only; real VM NVRAM is never read.
                        nvram.write_bytes(b'public fixture changed before authority')
                    publish(storage,{'plans':{'controlled':{'state':'pending','writerPid':actor['pid'],
                        'directory':str(vm),'disks':[{'path':str(disk),'capacityBytes':disk.stat().st_size}]}}})
                    publish(memory,{'schema_version':1,'reservations':{'recovery-test:controlled':{'memory_mib':4096,'pid':0}}})
                    publish(run/'authority.json',{'operationId':operation,'actor':actor,'storageFixtureId':'controlled',
                        'reservationKey':'recovery-test:controlled','hostBoot':hostboot})
                    stdout,stderr=child.communicate(timeout=5)
                    self.assertEqual(child.returncode,exit_code,stderr)
                    self.assertNotIn(b'gentle-river',stdout+stderr)
                    self.assertNotIn(b'discarded detail',stdout+stderr)
                    if mutate_nvram:
                        self.assertEqual(nvram.read_bytes(),b'public fixture changed before authority')
                    if exit_code:
                        # Whole old owner reaches the controlled actual CLI with
                        # a nonzero inherited core budget and fails its check.
                        self.assertFalse((run/'child.json').exists())
                        self.assertFalse((run/'vnc-auth.bin').exists())
                        continue
                    terminal=json.loads((run/'child-terminal.json').read_bytes())
                    self.assertEqual(terminal['delegateOutcome'],expected)
                    self.assertEqual((run/'vnc-auth.bin').read_bytes(),b'gentle-river-silver-moon')
                    self.assertEqual(lifecycle.terminal_state(terminal['exitCode'],terminal['delegateOutcome'],None),
                                     'stopped'if expected=='guest_did_stop'else'off_unknown')
                finally:
                    if child.poll()is None:child.terminate();child.wait(timeout=2)


if __name__ == "__main__": unittest.main()
