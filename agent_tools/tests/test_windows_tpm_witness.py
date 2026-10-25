"""Authenticated whole-before proof-admission RED/GREEN and host TTL interleaving."""
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from types import ModuleType
import unittest
from unittest import mock
from uuid import uuid4

import agent_tools
from agent_tools import readiness_windows_tpm_owner as current
from agent_tools import readiness_windows_lifecycle as lifecycle
from agent_tools.tests.test_windows_tpm_owner import request,issued_witness
from agent_tools.tests.test_windows_lifecycle_dispatch import managed_binding

FIXTURE=Path(__file__).parent/'fixtures/windows_tpm_witness'


def old_module(name,file,key):
    raw=(FIXTURE/file).read_bytes();assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())[key]
    value=ModuleType('agent_tools._'+name);value.__package__='agent_tools';value.__file__=str(FIXTURE/file)
    sys.modules[value.__name__]=value;exec(compile(raw,value.__file__,'exec'),value.__dict__);return value


def _observe(request):
    # Explicit controlled root-backend seam; actual ROOT census is separately
    # qualified on Linux. This test owns the real nested SSH admission path.
    return {'complete':True,'holders':[{'pid':201,'uid':request['qemu']['uid'],'birth':2001}]}


class OpaqueWitnessTests(unittest.TestCase):
    def test_whole_before_forged_dataclass_never_crosses_actual_dispatch_socket(self):
        old=os.environ.get('VPN_CONTROL_TPM_WITNESS_BEFORE')=='1'
        owner=old_module('owner_witness_before','owner.before.source','ownerSha256')if old else current
        getter=old_module('lineage_witness_before','lifecycle.before.source','lifecycleSha256')if old else lifecycle
        bound,_=managed_binding();r=request();proof={'complete':True,'holders':[{'pid':20,'uid':1000,'birth':90}]}
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);wire=root/'wire';ready=root/'ready';called=root/'called'
            server=subprocess.Popen([sys.executable,'-I','-B','-c',
                "import socket,sys;from pathlib import Path;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);s.settimeout(.3);Path(sys.argv[2]).touch();\ntry:\n c,_=s.accept();assert c.recv(32)==b'forged-proof';Path(sys.argv[3]).touch();c.close()\nexcept TimeoutError:pass\ns.close()",str(wire),str(ready),str(called)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                end=time.monotonic()+3
                while not ready.exists():self.assertIsNone(server.poll());self.assertLess(time.monotonic(),end);time.sleep(.005)
                try:
                    if old:witness=owner.OwnerWitness(r,proof,hashlib.sha256(owner.program(r)).hexdigest())
                    else:witness=object.__new__(owner.OwnerWitness)
                    with mock.patch.object(agent_tools,'readiness_windows_tpm_owner',owner):
                        getter.libvirt_lineage_program(bound,str(uuid4()),owner_witness=witness)
                    with socket.socket(socket.AF_UNIX)as client:client.connect(str(wire));client.sendall(b'forged-proof')
                except (ValueError,TypeError):pass
                server.communicate(timeout=3)
                self.assertFalse(called.exists(),'unauthenticated census claim crossed dispatch admission')
            finally:
                if server.poll()is None:server.terminate();server.communicate(timeout=3)
                self.assertEqual(server.returncode,0)

    def test_current_host_clock_checked_before_and_after_actual_socket_delay(self):
        source=inspect.getsource(lifecycle._capture_libvirt_lineage);tree=ast.parse(source)
        node=next(v for v in ast.walk(tree)if isinstance(v,ast.FunctionDef)and v.name=='witness_clock')
        module=ast.Module(body=[node],type_ignores=[]);ast.fix_missing_locations(module)
        def need(value,*args):
            if not value:raise ValueError('expired')
        observed=time.monotonic_ns();proof={'observedNs':observed,'deadlineNs':observed+20_000_000}
        ns={'proof':proof,'need':need};exec(compile(module,'actual final native clock gate','exec'),ns)
        ns['witness_clock']()
        first,second=socket.socketpair()
        try:
            first.sendall(b'original-metadata');self.assertEqual(second.recv(32),b'original-metadata')
            time.sleep(.03)
            with self.assertRaisesRegex(ValueError,'expired'):ns['witness_clock']()
        finally:first.close();second.close()
        for changed in ({'observedNs':True,'deadlineNs':2},{'observedNs':observed+10**12,'deadlineNs':observed+10**12+1},
                        {'observedNs':observed,'deadlineNs':observed+30_000_000_001}):
            ns['proof']=changed
            with self.assertRaises(ValueError):ns['witness_clock']()

    def test_real_nested_transport_scope_keeps_original_observer_live_through_dispatch(self):
        from agent_tools.tests.test_readiness_transport import ReadinessTransportTests
        from agent_tools import ssh_transport as transport,ssh_dispatch_admission as dispatch
        fixture=ReadinessTransportTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        root=fixture.root;r=request();op=str(uuid4());authority=mock.MagicMock();authority.__enter__.return_value=authority
        authority.config=transport.load_config(root)
        config_path=transport._private_config_path(root);before=config_path.stat()
        def source_guard():
            now=config_path.stat();self.assertEqual((now.st_dev,now.st_ino,now.st_mtime_ns,now.st_ctime_ns),
                (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns))
        authority.guard.side_effect=source_guard
        credential=root/'credential';credential.write_text('controlled-nested-private');credential.chmod(0o600)
        builder=transport.build_ssh_argv
        def controlled_builder(*args,**kwargs):
            command=kwargs.get('command',())
            if command[:5]==('sudo','-S','-p','','--'):kwargs['command']=command[5:]
            return builder(*args,**kwargs)
        with mock.patch.object(current.deploy.direct,'Guard',return_value=authority), \
             mock.patch.object(current,'_observe',_observe), \
             mock.patch.object(transport,'build_ssh_argv',side_effect=controlled_builder):
            with current.observe(root,'explicit-peer',r,credential,guard=source_guard)as witness:
                outer=dispatch.current(root,'explicit-peer');self.assertEqual(outer.operation_identity,r['machine'])
                with transport.admitted_transport(root,'explicit-peer',op,deadline=time.monotonic()+10)as final:
                    self.assertIs(dispatch.current(root,'explicit-peer'),final);self.assertFalse(outer.closed)
                    witness.consume(op);witness.guard_dispatch(final)
                    marker=root/'once'
                    command=('python3','-I','-B','-c','from pathlib import Path;Path('+repr(str(marker))+').write_text("once");print("{}")')
                    argv=transport.build_ssh_argv(transport.load_config(root),'explicit-peer',command=command)
                    result=transport.run_ssh(argv,capture_output=True,timeout=5)
                    self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'{}\n',b''))
                    self.assertEqual(marker.read_text(),'once')
                self.assertIs(dispatch.current(root,'explicit-peer'),outer);witness.validate(r)
            self.assertIsNone(dispatch.current(root,'explicit-peer'))
            with self.assertRaises(ValueError):witness.validate(r)
        self.assertEqual(len(fixture.children),1)

    def test_live_observer_scope_cannot_be_reused_or_dispatched_for_another_operation(self):
        r=request()
        with issued_witness(r)as witness:
            op=str(uuid4());witness.consume(op)
            from agent_tools import ssh_dispatch_admission
            fake=mock.Mock(operation_identity=str(uuid4()))
            with self.assertRaises(ValueError):witness.guard_dispatch(fake)
            admission=ssh_dispatch_admission.Admission(Path('/'), 'selected',op,None,None)
            witness.guard_dispatch(admission);self.assertEqual(len(admission.extra_guards),1)
            admission.extra_guards[0]()
        with self.assertRaises(ValueError):admission.extra_guards[0]()
        with self.assertRaises(ValueError):witness.consume(op)


if __name__=='__main__':unittest.main()
