"""Actual detached supervisor/pipe tests, no SSH/VM; Darwin birth syscall seam."""
import ast
import ctypes
import hashlib
import inspect
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
from agent_tools import windows_parallel_vm_startup as startup
from agent_tools import windows_parallel_vm_prepare_transport as transport
from agent_tools import windows_parallel_vm_launch as launch


def native_birth(proc, pid):
    if sys.platform != 'darwin':
        return ORIGINAL_BIRTH(proc, pid)
    class Bsd(ctypes.Structure):
        _fields_=[('ints',ctypes.c_uint32*12),('comm',ctypes.c_char*16),('name',ctypes.c_char*32),('more',ctypes.c_uint32*6),('sec',ctypes.c_uint64),('usec',ctypes.c_uint64)]
    lib=ctypes.CDLL('/usr/lib/libproc.dylib')
    lib.proc_pidinfo.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int]
    lib.proc_pidinfo.restype=ctypes.c_int
    value=Bsd()
    count=lib.proc_pidinfo(pid,3,0,ctypes.byref(value),ctypes.sizeof(value))
    return int(value.sec*1000000+value.usec) if count==ctypes.sizeof(value) else None

ORIGINAL_BIRTH = transport.inventory.process_birth


def definitions():
    source = startup._definitions()
    if sys.platform == 'darwin':
        node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef) and n.name=='process_birth')
        lines=source.splitlines(True)
        seam=inspect.getsource(native_birth).replace('def native_birth(','def process_birth(')
        source=''.join(lines[:node.lineno-1])+seam+'\n'+''.join(lines[node.end_lineno:])
        source='import sys,ctypes\n'+source
    return source


def base_program(root):
    # The actual fixed producer's lifetime tail, with only VM action replaced.
    tail=next(n.value for n in ast.walk(ast.parse(inspect.getsource(launch.launch_program)))
              if isinstance(n,ast.Constant) and isinstance(n.value,str) and 'while any(child.poll()' in n.value)
    tail=tail[tail.index('print(json.dumps(value'):]
    child = "import os,time,sys;fds=[int(n) for n in sys.argv[1:]];pins=[os.fstat(f) for f in fds];time.sleep(1);assert [(s.st_dev,s.st_ino,s.st_size) for s in pins]==[(os.fstat(f).st_dev,os.fstat(f).st_ino,os.fstat(f).st_size) for f in fds]"
    return ('import os,subprocess,time,json\nfrom pathlib import Path\nroot=Path('+repr(str(root))+')\n'
      +"fds=[os.open(root/n,os.O_RDONLY|os.O_NOFOLLOW) for n in ('source.private','overlay.private')]\n"
      +'child=subprocess.Popen(['+repr(sys.executable)+",'-I','-c',"+repr(child)+",*map(str,fds)],pass_fds=tuple(fds),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True)\n"
      +"run={'handles':[child]}\nvalue={'state':'unknown','reason':'pair-launch-or-access','nativeGuestStarted':True,'productAcceptance':False,'replayAllowed':False,'originalPids':[child.pid]}\n"
      +tail+"\nassert child.returncode==0\nassert all(os.fstat(f).st_size>0 for f in fds)\n")


@unittest.skipUnless(os.name=='posix', 'POSIX owned detached job; actual Linux/Darwin process birth')
class StartupTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        for name in ('source.private','overlay.private'):(self.root/name).write_bytes(b'owned-inert')
        self.correlation=str(uuid.uuid4());self.job=self.root/'job';self.base=base_program(self.root)
        self.patch=patch.object(startup,'_definitions',definitions_original_wrapper)
        self.patch.start();self.addCleanup(self.patch.stop)

    def wait_terminal(self):
        deadline=time.monotonic()+5
        while not (self.job/'terminal.json').exists() and time.monotonic()<deadline:time.sleep(.02)
        terminal=json.loads((self.job/'terminal.json').read_bytes())
        self.assertTrue(terminal['stdoutEof']);self.assertEqual(0,terminal['exitCode'])
        return terminal

    def start(self, refused=False):
        if refused:
            # Create-only publication target is inserted before the worker starts;
            # the unchanged job root is still newly created by actual submit.
            marker="print(json.dumps(value,sort_keys=True),flush=True)"
            self.base=self.base.replace(marker,"Path("+repr(str(self.job/'initial.json'))+").write_bytes(b'held-original')\n"+marker)
        self.program,self.base_sha=startup._worker_program(self.base,self.correlation,self.job)
        self.program_sha=hashlib.sha256(self.program.encode()).hexdigest()
        defs=definitions_original_wrapper()
        bootstrap=defs+inspect.getsource(transport.submit)+'\nprint(json.dumps(submit(Path('+repr(str(self.job))+"),Path('/proc'),"+repr(sys.executable)+','+repr(self.correlation)+','+repr(self.program)+','+repr(defs)+'),sort_keys=True),flush=True)\n'
        self.bootstrap=subprocess.Popen([sys.executable,'-I','-u','-c',bootstrap],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        raw,err=self.bootstrap.communicate(timeout=3)
        self.assertEqual(0,self.bootstrap.returncode,err.decode()[-600:]);reply=json.loads(raw)
        self.assertEqual('submitted',reply['state'])
        deadline=time.monotonic()+2
        while not (self.job/'initial.json').exists() and time.monotonic()<deadline:time.sleep(.01)
        return reply

    def status(self):
        ns={};exec(definitions_original_wrapper(),ns)
        return ns['startup_read'](self.job,Path('/proc'),self.correlation,self.program_sha,self.base_sha,hashlib.sha256(transport.worker_source(self.program).encode()).hexdigest(),definitions_original_wrapper(),sys.executable)

    def test_causal_foreground_initial_unknown_has_no_eof_while_original_child_alive(self):
        child=subprocess.Popen([sys.executable,'-I','-u','-c',self.base],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        selector=selectors.DefaultSelector();selector.register(child.stdout,selectors.EVENT_READ)
        try:
            self.assertTrue(selector.select(1));raw=os.read(child.stdout.fileno(),65536);value=json.loads(raw)
            self.assertFalse(selector.select(.1));self.assertIsNone(child.poll())
            self.assertIsNotNone(native_birth(Path('/proc'),child.pid))
            self.assertIsNotNone(native_birth(Path('/proc'),value['originalPids'][0]))
        finally:
            child.communicate(timeout=4);selector.close()
        self.assertEqual(0,child.returncode)

    def test_real_detached_bootstrap_eof_does_not_claim_worker_or_guest_terminal(self):
        reply=self.start();self.assertIsNotNone(native_birth(Path('/proc'),reply['identity']['pid']))
        observed=self.status();self.assertEqual('initial-observed',observed['state'])
        self.assertFalse(observed['workerTerminal']);self.assertFalse(observed['guestAccessAdmitted'])
        self.assertFalse(observed['bootstrapTransportEofObserved']);self.assertFalse((self.job/'terminal.json').exists())
        original=observed['originalWorker'];self.assertEqual(original['startTicks'],native_birth(Path('/proc'),original['pid']))
        terminal=self.wait_terminal();self.assertEqual(original['pid'],terminal['pid'])
        with self.assertRaisesRegex(ValueError,'copy-already-submitted'):
            transport.submit(self.job,Path('/proc'),sys.executable,self.correlation,self.program,transport.remote_definitions())

    def test_create_only_initial_refusal_retains_original_unknown_and_natural_exit(self):
        # Insert pre-existing publication target BEFORE the injected publisher.
        marker='print(json.dumps(value,sort_keys=True),flush=True)'
        self.base=self.base.replace(marker,"Path("+repr(str(self.job/'initial.json'))+").write_bytes(b'held-original')\n"+marker)
        self.start();self.assertEqual(b'held-original',(self.job/'initial.json').read_bytes())
        with self.assertRaises((ValueError,json.JSONDecodeError)):self.status()
        terminal=self.wait_terminal();raw=(self.job/'stdout.private').read_bytes();self.assertIn(b'startup-publication-refused',raw)
        self.assertTrue(terminal['stdoutEof'])

    def test_source_identity_and_partial_initial_refusals(self):
        self.start();self.wait_terminal()
        initial=self.job/'initial.json';saved=initial.read_bytes()
        initial.write_bytes(b'{')
        with self.assertRaises(json.JSONDecodeError):self.status()
        initial.write_bytes(saved);value=json.loads(saved);value['correlationId']=str(uuid.uuid4());initial.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'startup-initial-binding'):self.status()
        initial.write_bytes(saved);worker=self.job/'worker.py';worker.write_bytes(worker.read_bytes()+b'\n')
        with self.assertRaisesRegex(ValueError,'startup-factory-worker-source'):self.status()

    def test_original_identity_mismatch_refuses_without_restarting_worker(self):
        self.start();initial=self.job/'initial.json';child=self.job/'child.json'
        saved_initial=initial.read_bytes();saved_child=child.read_bytes()
        a=json.loads(saved_initial);b=json.loads(saved_child)
        a['startTicks']+=1;b['startTicks']+=1
        initial.write_text(json.dumps(a));child.write_text(json.dumps(b))
        try:
            with self.assertRaisesRegex(ValueError,'startup-child-reused'):self.status()
        finally:
            initial.write_bytes(saved_initial);child.write_bytes(saved_child);self.wait_terminal()

    def test_public_factories_generate_fixed_root_and_complete_namespaces_only(self):
        with patch.object(launch,'launch_program',return_value=self.base):
            start=startup.launch_start_program({}, {}, self.correlation)
            status=startup.launch_status_program({}, {}, self.correlation)
        compile(start,'actual startup submit factory','exec');compile(status,'actual startup status factory','exec')
        self.assertIn(startup.BASE_ROOT+self.correlation,start)
        self.assertIn('startup_read',status)
        with self.assertRaises(ValueError):startup.launch_status_program({}, {}, 'not-a-uuid')

    def test_coherently_rebound_worker_source_is_refused_by_factory_authority(self):
        self.start();self.wait_terminal()
        worker=self.job/'worker.py';worker.write_bytes(worker.read_bytes()+b'\nFOREIGN_BODY_SENTINEL=True\n')
        directory=os.open(self.job,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:pin=transport.read_private(directory,'worker.py',os.geteuid(),262144)[1]
        finally:os.close(directory)
        for name in ('intent.json','child.json','initial.json'):
            path=self.job/name;value=json.loads(path.read_bytes());value['workerPin']=pin;path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'startup-factory-worker-source'):self.status()

    def test_coherently_rebound_supervisor_source_is_refused_by_factory_authority(self):
        self.start();self.wait_terminal()
        source=self.job/'supervisor.py';source.write_bytes(source.read_bytes()+b'\nFOREIGN_BODY_SENTINEL=True\n')
        record=self.job/'supervisor.json';value=json.loads(record.read_bytes())
        value['supervisorSha256']=hashlib.sha256(source.read_bytes()).hexdigest();record.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'startup-factory-supervisor-source'):self.status()

    def test_namespace_and_oversize_initial_refusals(self):
        self.start();self.wait_terminal();initial=self.job/'initial.json'
        initial.write_bytes(b'x'*(startup.INITIAL_LIMIT+1))
        with self.assertRaisesRegex(ValueError,'job-file'):self.status()
        initial.unlink();initial.symlink_to(self.root/'source.private')
        with self.assertRaises(OSError):self.status()

class FactoryCanonicalTest(unittest.TestCase):
    def request(self):
        from agent_tools.tests.test_windows_parallel_vm_launch import native_prepared_fixture, controller_boot
        return {'prepared':native_prepared_fixture(), 'observed':{'state':'boot-observed',
            'nativeGuestStarted':False,'productAcceptance':False,'boot':controller_boot()},
            'correlation':str(uuid.uuid4())}

    def digests(self, request):
        return {factory.__name__:hashlib.sha256(factory(request['prepared'],request['observed'],request['correlation']).encode()).hexdigest()
                for factory in (startup.launch_start_program,startup.launch_status_program)}

    def test_actual_both_public_factories_survive_saved_canonical_json_request(self):
        request=self.request();saved=json.loads(json.dumps(request,sort_keys=True))
        self.assertEqual(self.digests(request),self.digests(saved))

    def test_actual_nested_dictionary_permutations_do_not_change_programme(self):
        def reverse(value):
            if type(value) is dict:return {k:reverse(v) for k,v in reversed(list(value.items()))}
            if type(value) is list:return [reverse(v) for v in value]
            return value
        request=self.request();self.assertEqual(self.digests(request),self.digests(reverse(request)))

    def test_changed_source_input_still_changes_actual_factory_programme(self):
        request=self.request();changed=json.loads(json.dumps(request));changed['prepared']['templateSha256']='b'*64
        self.assertNotEqual(self.digests(request),self.digests(changed))

_ORIGINAL_DEFINITIONS=startup._definitions

def definitions_original_wrapper():
    # Preserve all real generated globals; project only Linux birth syscall.
    with patch.object(startup,'_definitions',_ORIGINAL_DEFINITIONS):
        return definitions()

if __name__=='__main__':unittest.main()
