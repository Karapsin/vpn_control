"""Whole retained callers and nohash custody on synthetic private route files."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import types
import unittest
import uuid
from unittest import mock

from agent_tools import ssh_program_execution as owner
from agent_tools import source_module_loader as loader
from agent_tools.tests import test_ssh_program_execution as legacy

FIXTURE = Path(__file__).parent / 'fixtures/ssh_program_private_custody'
ROOT = Path(__file__).resolve().parents[2]


def before():
    raw = (FIXTURE / 'ssh_program_execution.py.before.source').read_bytes()
    assert hashlib.sha256(raw).hexdigest() == json.loads((FIXTURE / 'provenance.json').read_bytes())['beforeSha256']
    alias = 'agent_tools._private_program_before_' + uuid.uuid4().hex
    module = types.ModuleType(alias); module.__file__ = str(FIXTURE / 'ssh_program_execution.py.before.source')
    module.__package__ = 'agent_tools'
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


@unittest.skipUnless(os.name == 'posix', 'POSIX held route files')
class PrivateProgramCustodyTests(unittest.TestCase):
    setUp = legacy.ProgramExecutionTests.setUp
    request = legacy.ProgramExecutionTests.request
    start = legacy.ProgramExecutionTests.start
    observe = legacy.ProgramExecutionTests.observe
    terminal = legacy.ProgramExecutionTests.terminal

    def protected(self):
        config = owner.transport.load_config(self.root)
        key = config.hosts['explicit-peer'].identity_file
        marker = ('SYNTHETIC_PRIVATE_KEY_' + uuid.uuid4().hex + '\n').encode()
        key.write_bytes(marker); key.chmod(0o600)
        return key, marker

    def archived_tree(self):
        destination = self.root / 'source-before'
        proxy = loader.Adapter(ROOT / 'agent_tools', 'ssh_program_execution')
        try:
            proxy._module.transport._automatic_module()
            proxy._session.held.read(str(ROOT / 'agent_tools/private_config_custody.py'),
                                     proxy._module.automatic_program._PRIVATE_CONFIG_SHA)
            for path, (_, _, _, raw) in proxy._session.held.files.items():
                output = destination / Path(path).relative_to(ROOT)
                output.parent.mkdir(parents=True, exist_ok=True); output.write_bytes(raw)
        finally:
            proxy.close()
        (destination / 'agent_tools/ssh_program_execution.py').write_bytes(
            (FIXTURE / 'ssh_program_execution.py.before.source').read_bytes())
        name = '_private_program_loader_' + uuid.uuid4().hex
        spec = importlib.util.spec_from_file_location(name, destination / 'agent_tools/source_module_loader.py')
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module
        self.addCleanup(sys.modules.pop, name, None); spec.loader.exec_module(module)
        return module.Adapter(destination / 'agent_tools', 'ssh_program_execution')

    def test_whole_before_generated_caller_hashes_key_and_private_receipt_current_never_does(self):
        key, marker = self.protected(); synthetic_digest = hashlib.sha256(marker).hexdigest()
        seen = []; actual_sha = hashlib.sha256
        def watch(raw=b'', *args, **kwargs):
            if raw == marker: seen.append('key')
            return actual_sha(raw, *args, **kwargs)
        old = self.archived_tree()
        self.addCleanup(old.close)
        request = self.request("print('fixed public once')\n")
        with mock.patch.object(hashlib, 'sha256', side_effect=watch):
            old.start(self.root, 'explicit-peer', request, source_context=old._session, durable=False)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            result = old.status(self.root, 'explicit-peer', {'operationId': self.operation})
            if result['state'] == 'terminal': break
            time.sleep(.025)
        self.assertEqual('terminal', result['state']); self.assertEqual(0, result['exitCode'])
        directory = self.root / '.rag_index/ssh-program-execution' / self.operation
        old_raw = (directory / 'intent.json').read_bytes()
        self.assertIn('key', seen)
        self.assertIn(synthetic_digest.encode(), old_raw)  # Actual authentic RED.
        def refuse_private_hash(raw=b'', *args, **kwargs):
            if raw == marker or raw == old_raw:
                raise AssertionError('private material reached content hash')
            return actual_sha(raw, *args, **kwargs)
        with mock.patch.object(hashlib, 'sha256', side_effect=refuse_private_hash), \
                mock.patch.object(owner.automatic_program._private_config(), 'PrivateConfigCustody', side_effect=AssertionError('legacy opened credential')), \
                mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('legacy opened process')):
            for action in (owner.status, owner.collect, owner.reconcile):
                result = action(self.root, 'explicit-peer', {'operationId': self.operation})
                self.assertEqual('legacy_private_key_custody_unavailable', result['reason'])
                self.assertEqual(self.operation, result['operationId']); self.assertFalse(result['replayAllowed'])
        self.assertEqual(old_raw, (directory / 'intent.json').read_bytes())
        old.close()
        self.operation = str(uuid.uuid4())
        with mock.patch.object(hashlib, 'sha256', side_effect=refuse_private_hash):
            self.start(self.request("print('new public once')\n")); result = self.terminal()
        self.assertEqual(0, result['exitCode'])
        current = self.root / '.rag_index/ssh-program-execution' / self.operation
        intent = json.loads((current / 'intent.json').read_bytes())
        self.assertEqual(2, intent['schemaVersion'])
        self.assertEqual({str(self.peer.hosts['explicit-peer']['knownHostsFile'])}, set(intent['connectionPins']))
        self.assertEqual({str(key), str(self.root / '.vm-hosts.local.json')}, set(intent['privateConnectionPins']))
        for pin in intent['privateConnectionPins'].values():
            self.assertEqual({'kind', 'generation', 'identity'}, set(pin)); self.assertEqual(8, len(pin['generation']))
            self.assertEqual('private-fd-generation-v2', pin['kind'])
        for path in current.rglob('*'):
            if path.is_file():
                self.assertNotIn(synthetic_digest.encode(), path.read_bytes(), str(path))
                self.assertNotIn(marker, path.read_bytes(), str(path))

    def test_same_original_private_custody_rejects_inplace_replacement_and_hardlink(self):
        key, _ = self.protected()
        for mode in ('inplace', 'replace', 'hardlink'):
            with self.subTest(mode=mode), owner._holding() as held:
                owner._hold_connection(held, self.root, 'explicit-peer')
                if mode == 'inplace': key.write_bytes(b'SYNTHETIC_CHANGED\n')
                elif mode == 'replace':
                    other = self.root / ('new-key-' + uuid.uuid4().hex); other.write_bytes(key.read_bytes()); other.chmod(0o600); other.replace(key)
                else: os.link(key, self.root / 'extra-key-link')
                with self.assertRaises(ValueError): held.finish()
            if mode == 'hardlink': (self.root / 'extra-key-link').unlink()

    def test_worker_reopens_only_same_public_and_private_generations(self):
        key, _ = self.protected()
        with owner._holding() as first:
            _, public = owner._hold_connection(first, self.root, 'explicit-peer')
            private = first.private_connection_pins
        with owner._holding() as second:
            owner._hold_connection(second, self.root, 'explicit-peer', public, private_expected=private)
            second.finish()
        key.write_bytes(b'SYNTHETIC_OTHER_PRIVATE_KEY\n')
        with owner._holding() as changed:
            with self.assertRaisesRegex(ValueError, 'program_private_config_generation_changed'):
                owner._hold_connection(changed, self.root, 'explicit-peer', public, private_expected=private)

    def test_intent_retained_exact_bytes_generation_and_closed_fd(self):
        self.protected(); directory = owner._directory(self.root, self.operation, create=True)
        with owner._holding() as first:
            _, public = owner._hold_connection(first, self.root, 'explicit-peer')
            intent = {'schemaVersion':2,'operationId':self.operation,'privateConnectionPins':first.private_connection_pins,'connectionPins':public}
        owner._save(directory, 'intent.json', intent)
        for mode in ('inplace', 'replace', 'hardlink'):
            path = directory / 'intent.json'
            original = path.read_bytes()
            held = owner._ProgramHeld()
            self.assertEqual(intent, owner._read(directory, 'intent.json', held))
            descriptor = held.private_records[str(path)][0]
            if mode == 'inplace': path.write_bytes(original + b' ')
            elif mode == 'replace':
                temp = directory / 'replacement'; temp.write_bytes(original); temp.chmod(0o600); temp.replace(path)
            else: os.link(path, directory / 'alias')
            with self.assertRaisesRegex(ValueError, 'program_private_record_changed'): held.finish()
            held.close()
            with self.assertRaises(OSError): os.fstat(descriptor)
            if mode == 'hardlink': (directory / 'alias').unlink()
            path.write_bytes(original)

    def test_private_key_cannot_be_reclassified_as_public_trust_before_hash(self):
        key, marker = self.protected()
        config_path = self.root / '.vm-hosts.local.json'
        config = json.loads(config_path.read_bytes())
        config['hosts']['explicit-peer']['knownHostsFile'] = str(key)
        config_path.write_text(json.dumps(config)); config_path.chmod(0o600)
        actual = hashlib.sha256
        def no_private_hash(raw=b'', *args, **kwargs):
            if raw == marker: raise AssertionError('private key reclassified as public trust')
            return actual(raw, *args, **kwargs)
        with mock.patch.object(hashlib, 'sha256', side_effect=no_private_hash), owner._holding() as held:
            with self.assertRaisesRegex(ValueError, 'program_public_trust_file'):
                owner._hold_connection(held, self.root, 'explicit-peer')

    def test_existing_private_custody_schema_is_strict_before_key_open(self):
        self.protected()
        with owner._holding() as held:
            _, public = owner._hold_connection(held, self.root, 'explicit-peer')
            private = held.private_connection_pins
        for mutation in ('extra_digest','unknown_kind','invalid_identity','size_generation','bool_generation','foreign_uid','unsafe_mode','not_object'):
            bad = json.loads(json.dumps(private)); name=next(iter(bad)); pin=bad[name]
            if mutation=='extra_digest': pin['sha256']='a'*64
            elif mutation=='unknown_kind': pin['kind']='private-hash-v1'
            elif mutation=='invalid_identity': pin['identity']='not-an-original-identity'
            elif mutation=='size_generation': pin['generation'].append(1)
            elif mutation=='bool_generation': pin['generation'][0]=True
            elif mutation=='foreign_uid': pin['generation'][3]+=1
            elif mutation=='unsafe_mode': pin['generation'][2]=(pin['generation'][2]&~0o777)|0o644
            else: bad[name]=None
            with self.subTest(mutation=mutation), owner._holding() as held, mock.patch.object(owner.automatic_program._private_config(), 'PrivateConfigCustody', side_effect=AssertionError('malformed pin opened credential')):
                with self.assertRaisesRegex(ValueError, 'program_private_custody_schema'):
                    owner._hold_connection(held, self.root, 'explicit-peer', public, private_expected=bad)
        with owner._holding() as held, mock.patch.object(owner.automatic_program._private_config(), 'PrivateConfigCustody', side_effect=AssertionError('legacy pin opened credential')):
            with self.assertRaisesRegex(ValueError, 'program_legacy_private_key_custody'):
                owner._hold_connection(held, self.root, 'explicit-peer', public)

    def test_fresh_reconcile_after_local_client_death_blocks_changed_private_files_without_replay(self):
        import signal
        from agent_tools.tests.test_ssh_program_durable import DurableProgramExecutionTests
        from agent_tools import durable_remote_job as jobs
        for role, mutation in (('key','inplace'), ('key','replace'), ('config','inplace'), ('config','replace')):
            with self.subTest(role=role, mutation=mutation):
                case = DurableProgramExecutionTests('runTest'); case.setUp()
                try:
                    counter = case.root / 'private-generation-counter'
                    source = ("from pathlib import Path\nimport time\np=Path("+repr(str(counter))+")\nwith p.open('x') as out:\n out.write('execution\\n');out.flush()\n for n in range(16):\n  out.write(str(n)+'\\n');out.flush();print(n,flush=True);time.sleep(.04)\n")
                    case.start(case.request(source)); case.addCleanup(case.clean_remote_root); case.wait_counter(counter)
                    directory = case.directory(); original_intent = (directory/'intent.json').read_bytes()
                    packet = json.loads((directory/'remote-admission.json').read_bytes())
                    actor = json.loads((directory/'owner.json').read_bytes())['actor']
                    self.assertEqual(actor, owner.keeper.actor(actor['pid']))
                    os.kill(actor['pid'], signal.SIGTERM)
                    deadline = time.monotonic()+5
                    while time.monotonic()<deadline:
                        try: alive = owner.keeper.actor(actor['pid']) == actor
                        except (OSError, ValueError): alive = False
                        if not alive: break
                        time.sleep(.01)
                    self.assertFalse(alive)
                    path = case.peer.config_path if role=='config' else Path(case.peer.hosts['explicit-peer']['identityFile'])
                    raw = path.read_bytes()
                    if mutation == 'inplace': path.write_bytes(raw+b' ')
                    else:
                        replacement = case.root / 'changed-private-file'; replacement.write_bytes(raw); replacement.chmod(0o600); replacement.replace(path)
                    previous = len(case.peer.events())
                    name = '_private_generation_reconcile_' + uuid.uuid4().hex
                    spec = importlib.util.spec_from_file_location(name, case.qualified_source/'agent_tools/source_module_loader.py')
                    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
                    try:
                        spec.loader.exec_module(module)
                        proxy = module.Adapter(case.qualified_source/'agent_tools', 'ssh_program_execution')
                        try:
                            with self.assertRaisesRegex(ValueError, 'program_private_config_generation_changed'):
                                proxy.reconcile(case.root, 'explicit-peer', {'operationId':case.operation}, source_context=proxy._session)
                        finally: proxy.close()
                    finally: sys.modules.pop(name, None)
                    self.assertEqual(previous, len(case.peer.events()))
                    self.assertEqual(original_intent, (directory/'intent.json').read_bytes())
                    binding = jobs.MachineBinding.from_dict(packet['binding']); end=time.monotonic()+5
                    while time.monotonic()<end:
                        terminal = jobs.observe(Path(packet['remoteRoot']),case.operation,binding,generation=tuple(packet['generation']))
                        if terminal['state']=='terminal': break
                        time.sleep(.02)
                    self.assertEqual('terminal', terminal['state'])
                    self.assertEqual(['execution', *map(str,range(16))], counter.read_text().splitlines())
                finally: case.doCleanups()

    def test_local_status_does_not_open_key_or_network(self):
        key, _ = self.protected(); self.start(self.request("print('status finite')\n")); self.terminal()
        key.unlink(); (self.root / '.vm-hosts.local.json').unlink()
        with mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('status created process')), \
                mock.patch.object(owner.automatic_program._private_config(), 'PrivateConfigCustody', side_effect=AssertionError('status opened credential')):
            for action in (owner.status, owner.collect):
                self.assertEqual('terminal', action(self.root, 'explicit-peer', {'operationId':self.operation})['state'])
