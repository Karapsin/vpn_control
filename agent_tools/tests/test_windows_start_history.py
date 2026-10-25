"""Whole preserved producer regression for start-intent/capacity crash gap."""
import hashlib
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

from agent_tools import readiness_windows_lifecycle as current

FIXTURE=Path(__file__).parent/'fixtures/windows_tpm_owner'


def before_module():
    source=(FIXTURE/'before.source').read_bytes()
    assert hashlib.sha256(source).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._start_history_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(source,module.__file__,'exec'),module.__dict__);return module


class StartHistoryTests(unittest.TestCase):
    def test_preserved_other_start_intent_blocks_before_actual_socket_capacity_observation(self):
        subject=before_module()if os.environ.get('VPN_CONTROL_WINDOWS_START_HISTORY_BEFORE')=='1'else current
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp);root.chmod(0o700);op=str(uuid4());prior=str(uuid4());wire=root/'observer.sock';marker=root/'capacity-called'
            # Actual crash interval: durable intent exists, writerPid/pending
            # capacity has not yet been published. No guessed PID-clearing or
            # incomplete capacity state may authorize another operation.
            (root/('existing-start-'+prior+'.intent.json')).write_text('{"replayAllowed":false}')
            server=subprocess.Popen([sys.executable,'-I','-B','-c',
                "import socket,sys;from pathlib import Path;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);s.settimeout(1);Path(sys.argv[1]+'.ready').touch();\ntry:\n c,_=s.accept();assert c.recv(32)==b'capacity';Path(sys.argv[2]).touch();c.sendall(b'{}');c.close()\nexcept TimeoutError:pass\ns.close()",str(wire),str(marker)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                end=time.monotonic()+3
                while not Path(str(wire)+'.ready').exists():
                    self.assertIsNone(server.poll());self.assertLess(time.monotonic(),end);time.sleep(.005)
                def observe():
                    with socket.socket(socket.AF_UNIX)as client:
                        client.connect(str(wire));client.sendall(b'capacity');print(client.recv(32).decode())
                ns=subject._existing_raw_start.__globals__
                with mock.patch.dict(ns,{'_actor_absent':lambda *a:True,'_stopped_artifacts':lambda *a:{},
                    '_lifecycle_resource_main':observe,'_lifecycle_measurement':lambda v:{},
                    '_start_capacity':mock.Mock(side_effect=ValueError('controlled_stop_before_writer'))}):
                    with self.assertRaises(ValueError):
                        subject._existing_raw_start({'root':str(root)},{},op,'1'*64,{'qemu':{},'tpm':{}},{'artifacts':{}},{},{},
                            lambda *a:None,lambda *a:None,lambda *a:None,lambda *a:None,lambda:None,
                            lambda *a:None,lambda *a:None,lambda *a:None,lambda *a:None,[])
                self.assertFalse(marker.exists(),'a new original crossed the prior UNKNOWN admission')
            finally:
                server.communicate(timeout=3)
                self.assertEqual(server.returncode,0)

    def test_orphan_receipt_and_current_operation_are_never_inferred_closed(self):
        with tempfile.TemporaryDirectory()as tmp:
            root=Path(tmp)
            for suffix in ('.qemu-intent.json','.tpm-started.json','.result.json','.intent.json'):
                file=root/('existing-start-'+str(uuid4())+suffix);file.write_text('{}')
                with self.assertRaisesRegex(ValueError,'prior_start_unreconciled'):current._prior_start_fence(root)
                file.unlink()
            current._prior_start_fence(root)


if __name__=='__main__':unittest.main()
