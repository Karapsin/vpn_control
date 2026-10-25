"""Owned local flock/FD causals; no VM, framework, credential or guest calls.

Kernel/registration/native-qualification data are explicit controlled seams.
Whole original/candidate executor and qualification wrappers run unchanged.
"""
import hashlib, importlib.util, json, os, selectors, subprocess, sys, tempfile, time, types, unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent/'fixtures/macos_original_lease_deadline'
PRODUCTION = Path(__file__).resolve().parents[1]
from agent_tools import readiness_tart_macos_lease_executor as live
from agent_tools import readiness_tart_macos_lease_bridge as bridge
from agent_tools import readiness_tart_macos_leases as leases
from agent_tools import readiness_lease_workflow as workflow


def load(path, name):
    name = 'agent_tools._owned_deadline_' + name
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(path.read_bytes(), str(path), 'exec'), value.__dict__)
    return value


class DeadlineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=HERE)
        self.root = Path(self.tmp.name).resolve()
        self.root.chmod(0o700)
        self.qold = load(HERE/'before/readiness_tart_macos_lease_qualification.py', 'qualification_old')
        self.qnew = load(PRODUCTION/'readiness_tart_macos_lease_qualification.py', 'qualification_new')
        self.old = load(HERE/'before/readiness_tart_macos_lease_executor.py', 'executor_old')
        self.new = load(PRODUCTION/'readiness_tart_macos_lease_executor.py', 'executor_new')
        for e, q in ((self.old, self.qold), (self.new, self.qnew)):
            e.qualification = q
            e._CURRENT_OBSERVER_SOURCES = e.source_pins()
        binding = leases.MacLeaseBinding('local-tart-macos-'+'a'*24,
                    '01234567-89ab-4def-8123-0123456789ab',
                    '11234567-89AB-4DEF-8123-0123456789AB', '502',
                    'toolrecovery', '/Users/toolrecovery', '100237')
        self.binding = binding
        self.namespace = {'schemaVersion':1, 'root':bridge.ROOT,
            'target':binding.target, 'machine':binding.machine, 'account':binding.account,
            'rootGeneration':[1,2], 'jobGeneration':[1,3], 'admissionGeneration':[1,4],
            'sources':{}}
        initial = json.loads(bridge.capsule(binding))
        import base64
        self.namespace['sources'] = {n:hashlib.sha256(base64.b64decode(v)).hexdigest()
                                     for n,v in initial['files'].items()}
        self.raw = bridge.capsule(binding, self.namespace)
        self.lifecycle = self.root/'.runtime/lifecycle'
        directory = self.lifecycle/'lease-executors/capsule'
        directory.mkdir(mode=0o700, parents=True)
        self.cap = directory/'capsule.json'
        self.cap.write_bytes(self.raw); self.cap.chmod(0o600)
        self.reg = self.root/'.rag_index/readiness-fixtures/owned.json'
        self.reg.parent.mkdir(mode=0o700, parents=True)
        self.c = object.__new__(live._OriginalMacCustody)
        self.c.lifecycle_root = self.lifecycle
        self.c.binding = types.SimpleNamespace(target=binding.target, machine=binding.machine,
            ordinary_uid=502, ordinary_account=binding.principal, ordinary_home=binding.home)
        self.c.load_lease_namespace = lambda version:self.namespace
        self.c.close = lambda:None
        self.lock = live.mac.OperatorLock(self.lifecycle/'macos-operator.lock')
        self.guard_calls = []
        def guard(*, deadline):
            self.guard_calls.append(deadline)
            with self.lock.acquire(deadline=deadline):
                self.lock.guard()
        self.c.guard = guard
        # Native evidence parsing stays a declared seam, never a success claim.
        self.proof = types.SimpleNamespace(raw=self.raw, namespace=self.namespace)
        self.qold._load = lambda c,r:self.proof
        self.qnew._load = lambda c,r:self.proof
        self.children = []

    def tearDown(self):
        for process in self.children:
            out, err = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 0, err)
            self.assertIsNone(live.jobs._birth(process.pid))
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:pipe.close()
        self.tmp.cleanup()

    def snapshot(self, module):
        descriptor = {'provider':'tart-macos', 'schemaVersion':3, 'sources':module.source_pins()}
        self.reg.write_text(json.dumps(descriptor)); self.reg.chmod(0o600)
        _, pin = live.registry._json(self.reg)
        _, cap_pin = live.registry._json(self.cap)
        return {'schemaVersion':2, 'provider':'tart-macos', 'kind':module.KIND,
            'fixtureId':'owned', 'registration':{'path':str(self.reg), 'pin':pin},
            'binding':initial_dict(self.binding), 'namespace':self.namespace,
            'capsule':{'path':str(self.cap), 'pin':cap_pin},
            'sources':module.source_pins(), 'qualification':{}}

    def contender(self, seconds=.30):
        # Real independent owned process takes exactly the selected local flock.
        with self.lock.acquire(deadline=time.monotonic()+1):pass
        code = ('import fcntl,os,time\nf=os.open('+repr(str(self.lock.path))+',os.O_RDWR|os.O_NOFOLLOW)\n'
                'fcntl.flock(f,fcntl.LOCK_EX)\nprint("OWNED_LOCK",flush=True)\n'
                'time.sleep('+repr(seconds)+')\nos.close(f)\n')
        p = subprocess.Popen([sys.executable,'-I','-B','-c',code], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.children.append(p)
        with selectors.DefaultSelector() as selector:
            selector.register(p.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(2))
            self.assertEqual(p.stdout.readline(), b'OWNED_LOCK\n')
        return p

    def construct(self, module, snapshot):
        with patch.object(module, '_OriginalMacCustody', return_value=self.c):
            return module.OriginalMacLeaseExecutor(self.root, snapshot)

    def test_full_before_facade_constructor_escapes_cap_current_flock_respects_it(self):
        timings = []
        for module in (self.old, self.new):
            snapshot = self.snapshot(module)
            self.contender()
            def factory(root, selected):return self.construct(module, selected)
            value = {'provider':'tart-macos', 'executor':snapshot, 'operationId':
                     '11111111-1111-4111-8111-111111111111', 'fixtureId':'owned'}
            deadline = time.monotonic()+.06
            start = time.monotonic()
            with patch.object(workflow.fixtures, 'lease_executor_from_snapshot', factory):
                with self.assertRaises((live.mac.MacBlocked, live.registry.FixtureRegistryError, workflow.LeaseWorkflowError)):
                    workflow._external_original(self.root, self.root, 'status', value, {}, deadline=deadline)
            timings.append(time.monotonic()-start)
            self.children[-1].wait(timeout=2)
        self.assertGreater(timings[0], .20)  # authentic original RED
        self.assertLess(timings[1], .18)     # whole candidate GREEN

    def test_qualification_whole_before_fresh30_red_same_absolute_cap_green(self):
        for module, old in ((self.qold, True), (self.qnew, False)):
            self.contender()
            self.guard_calls.clear()
            deadline = time.monotonic()+.06
            start = time.monotonic()
            if old:
                self.assertIs(module.load(self.c, {}), self.proof)
                self.assertGreater(time.monotonic()-start, .20)
                self.assertTrue(all(d>deadline for d in self.guard_calls))
            else:
                with self.assertRaises(live.mac.MacBlocked):module.load(self.c, {}, deadline=deadline)
                self.assertLess(time.monotonic()-start, .18)
                self.assertEqual(self.guard_calls, [deadline])
            self.children[-1].wait(timeout=2)

    def test_constructor_is_local_and_retains_full_capsule_integrity(self):
        snapshot = self.snapshot(self.new)
        executor = self.construct(self.new, snapshot)
        self.assertEqual(self.guard_calls, [])
        self.assertEqual(executor._capsule_metadata(), self.raw)
        self.cap.write_bytes(self.raw+b' ')
        with self.assertRaises(live.mac.MacBlocked):self.construct(self.new, snapshot)
        self.assertEqual(self.guard_calls, [])

    def test_expired_invalid_callers_reject_before_external_guard(self):
        for deadline in (0, True, False, float('nan'), float('inf')):
            self.guard_calls.clear()
            with self.assertRaises((live.mac.MacBlocked, live.registry.FixtureRegistryError)):
                self.qnew.load(self.c, {}, deadline=deadline)
            self.assertEqual(self.guard_calls, [])
        executor = self.construct(self.new, self.snapshot(self.new))
        with self.assertRaises(live.registry.FixtureRegistryError):executor.observe(
            '11111111-1111-4111-8111-111111111111', deadline=0)
        self.assertEqual(self.guard_calls, [])
        self.assertFalse((self.lifecycle/'lease-executors/operations').exists())

    def test_same_cap_both_guards_and_qualified_paths_forward_it(self):
        deadline=time.monotonic()+.5
        self.assertIs(self.qnew.load(self.c, {}, deadline=deadline), self.proof)
        self.assertEqual(self.guard_calls, [deadline, deadline])
        self.guard_calls.clear()
        executor=self.construct(self.new, self.snapshot(self.new))
        executor._capsule(deadline=deadline)
        self.assertEqual(self.guard_calls, [deadline, deadline])
        # Exact complete qualified source callsites may not omit this cap.
        import ast
        tree=ast.parse((PRODUCTION/'readiness_tart_macos_lease_executor.py').read_bytes())
        calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
               and ast.unparse(node.func)=='qualification.load']
        self.assertEqual(len(calls),3)
        self.assertTrue(all(any(k.arg=='deadline'and ast.unparse(k.value)=='deadline'
                                for k in node.keywords)for node in calls))

    def test_metadata_parser_errors_remain_finite_and_no_dispatch(self):
        self.qnew._load=lambda *a:(_ for _ in()).throw(ValueError('PRIVATE_INPUT_NOT_EXPOSED'))
        with self.assertRaisesRegex(live.mac.MacBlocked, '^macos_native_lease_qualification_invalid$'):
            self.construct(self.new, self.snapshot(self.new))
        self.assertEqual(self.guard_calls, [])


def initial_dict(binding):
    from dataclasses import asdict
    return asdict(binding)


if __name__ == '__main__':unittest.main()
