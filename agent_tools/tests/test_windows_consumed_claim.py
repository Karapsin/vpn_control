"""An existing mutation fence refuses before transport or private input."""
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import windows_vm_deploy as deploy
from agent_tools.native_vm_spec import FreshWindowsVmSpec
from agent_tools.tests.test_native_vm_spec import request

FIXTURE=Path(__file__).parent/'fixtures/windows_consumed_claim'


def before_module():
    raw=(FIXTURE/'deploy.before.source').read_bytes()
    metadata=json.loads((FIXTURE/'provenance.json').read_text())
    if hashlib.sha256(raw).hexdigest()!=metadata['sourceSha256']:
        raise ValueError('consumed_claim_beforeimage_changed')
    module=types.ModuleType('agent_tools._windows_consumed_claim_before')
    module.__package__='agent_tools';module.__file__=str(FIXTURE/'deploy.before.source')
    exec(compile(raw,module.__file__,'exec'),module.__dict__)
    return module


class ConsumedClaimTests(unittest.TestCase):
    def test_complete_before_contacts_transport_RED_and_fixed_refuses_pure_GREEN(self):
        groups={'host-policy-apply':'windows-vm-host-policy','start':'windows-vm-deploy-intents',
                'stop':'windows-vm-deploy-stops','secure':'windows-vm-deploy-secure'}
        for name,module in [('before',before_module()),('fixed',deploy)]:
            for mode,group in groups.items():
                with self.subTest(source=name,mode=mode),tempfile.TemporaryDirectory()as temporary:
                    root=Path(temporary);root.chmod(0o700);spec=FreshWindowsVmSpec.parse(request())
                    parent=root/'.rag_index'/group;parent.mkdir(parents=True,mode=0o700)
                    claim=parent/(spec.deployment_id+'.intent.json');original=b'ORIGINAL_UNKNOWN_KEEP_UNCHANGED'
                    claim.write_bytes(original);claim.chmod(0o600)
                    with mock.patch.object(module.direct,'coordinator_capable',return_value=True),\
                         mock.patch.object(module.transport,'admitted_transport',side_effect=ValueError('transport_reached'))as admission,\
                         mock.patch.object(module,'SecretFile',side_effect=AssertionError('private input forbidden')):
                        with self.assertRaisesRegex(ValueError,'transport_reached'if name=='before'else'policy_original_exists'):
                            module._execute(root,spec,mode,credential_file='/UNOPENED_PRIVATE_HANDLE')
                    self.assertEqual(1 if name=='before'else 0,admission.call_count)
                    self.assertEqual(original,claim.read_bytes())
                    self.assertFalse((root/'.runtime').exists())


if __name__=='__main__':unittest.main()
