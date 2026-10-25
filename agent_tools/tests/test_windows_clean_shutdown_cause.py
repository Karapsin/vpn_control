"""Absence cannot stand in for the original guest's clean shutdown cause."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import time
from types import ModuleType
import unittest

from agent_tools import readiness_windows_lifecycle as current
from agent_tools.tests import test_windows_lifecycle_dispatch as owner_tests

FIXTURE=Path(__file__).parent/'fixtures/windows_clean_shutdown_cause'


def subject():
    if os.environ.get('VPN_CONTROL_CLEAN_CAUSE_BEFORE')!='1':return current
    raw=(FIXTURE/'before.source').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==json.loads((FIXTURE/'provenance.json').read_text())['sourceSha256']
    module=ModuleType('agent_tools._windows_clean_cause_before');module.__package__='agent_tools';module.__file__=str(FIXTURE/'before.source')
    sys.modules[module.__name__]=module;exec(compile(raw,module.__file__,'exec'),module.__dict__);return module


class CleanCauseTests(unittest.TestCase):
    def test_actual_socket_children_gone_without_authenticated_shutdown_cause_never_mint_clean(self):
        fixture=owner_tests.ActualChildPowerdownTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        fixture.close_endpoint('qemu');fixture.close_endpoint('tpm');module=subject()
        with self.assertRaisesRegex(ValueError,'instance_powerdown_cause_unknown'):
            module._complete_powerdown({'deploymentId':'fixture','root':str(fixture.root)},{'hostBootId':'host'},'operation','a'*64,'b'*64,
                {'actor':fixture.rows['qemu'],'sessionFacts':{'boot':'boot','expectedSid':'account'}},lambda name:fixture.rows['tpm'],
                fixture.save,fixture.process,fixture.birth,lambda:None,timeout=1)
        self.assertEqual(fixture.saved,{})

    def test_actual_socket_shutdown_event_exact_guest_cause_only(self):
        for data,accepted in (({'guest':True,'reason':'guest-shutdown'},True),({'guest':False,'reason':'host-error'},False),({'guest':1,'reason':'guest-shutdown'},False)):
            with self.subTest(data=data):
                left,right=socket.socketpair();self.addCleanup(left.close);self.addCleanup(right.close)
                stream=left.makefile('rwb',buffering=0);self.addCleanup(stream.close)
                right.sendall(json.dumps({'event':'SHUTDOWN','data':data}).encode()+b'\n');right.shutdown(socket.SHUT_WR)
                if accepted:self.assertEqual(current._shutdown_watch_cause((left,stream),time.monotonic()+1),{'kind':'qmp-shutdown-event','guest':True,'reason':'guest-shutdown'})
                else:
                    with self.assertRaisesRegex(ValueError,'instance_powerdown_unclean_cause'):current._shutdown_watch_cause((left,stream),time.monotonic()+1)

    def test_managed_generated_guard_requires_supported_shutdown_reason(self):
        fixture=owner_tests.LifecycleAdmissionTests('runTest');fixture.setUp()
        binding,body=owner_tests.managed_binding();lineage=current.validate_lineage(binding,body)
        raw=current.powerdown_program(binding,lineage,fixture.operation,fixture.rid,expected={'actor':body['qemu'],'hostBoot':body['hostBoot'],'controlConnection':'libvirt:40:440:70'},expected_sid=owner_tests.SID,reservation={}).source
        self.assertIn(b'VIR_DOMAIN_SHUTOFF_SHUTDOWN',raw);self.assertIn(b'shutdown_cause=_lifecycle_clean_cause',raw)
        self.assertIn(b'_open_shutdown_watch(root,LIFECYCLE_QEMU',raw);compile(raw,'fixed-cause-caller','exec')


if __name__=='__main__':unittest.main()
