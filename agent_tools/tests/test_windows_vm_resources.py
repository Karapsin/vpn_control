"""Whole saved resource producer uses an actual proc/account filesystem model."""
import copy
import hashlib
import json
import os
import types
import unittest
from pathlib import Path
from agent_tools import windows_vm_deploy_remote as producer
from agent_tools import windows_vm_resources as resources
from agent_tools.native_vm_spec import FreshWindowsVmSpec
from agent_tools.tests import test_native_vm_spec as specs
from agent_tools.tests import test_process_census_reproducibility as census


@unittest.skipUnless(os.name=='posix','Linux proc boundary')
class WindowsResourceTests(unittest.TestCase):
    def observation(self):
        fixture=census.ProcessCensusTests('runTest');fixture.setUp()
        try:
            proc=fixture.proc
            (proc/'sys/kernel/random').mkdir(parents=True)
            (proc/'sys/kernel/random/boot_id').write_text('6ddca4a6-d159-4385-a78d-0a5ce9577aef')
            (proc/'pressure').mkdir();(proc/'pressure/memory').write_text('some avg10=0.00\nfull avg10=0.00\n')
            (proc/'vmstat').write_text('pswpin 0\npswpout 0\noom_kill 0\n')
            vm=fixture.process(17,'qemu-system-x86_64','7',777)
            (vm/'cmdline').write_bytes(b'/proc/self/fd/7\0-m\0'+b'6144\0')
            spec=specs.request();spec['root']=str(fixture.home/'new-vm')
            spec=FreshWindowsVmSpec.parse(spec)
            value=fixture.run_program(producer.program(spec,'host-resources').decode())
            self.assertFalse((fixture.home/'new-vm').exists())
            return spec,value
        finally:fixture.doCleanups()
    def test_complete_saved_producer_observes_descriptor_qemu_without_any_vm_profile(self):
        spec,value=self.observation()
        self.assertEqual('resources-observed',value['state'])
        self.assertEqual(value,producer.validate_result(spec,'host-resources',value))
        measurement=resources.measurement(value)
        self.assertEqual(6144*1024**2,measurement['runningConfiguredMemoryBytes'])
        self.assertFalse(value['nativeActionAllowed'])
    def test_resource_decoder_rejects_forged_incomplete_or_boolean_facts(self):
        _,value=self.observation()
        for field,bad in (('inventoryComplete',False),('freeDiskBytes',True),('vms',[{'pid':17}]),('hostBootId','PUBLIC')):
            wrong=copy.deepcopy(value);wrong[field]=bad
            with self.subTest(field=field),self.assertRaises(ValueError):resources.measurement(wrong)

    def test_preserved_native_only_reader_red_explicit_mcp_reader_green(self):
        folder=Path(__file__).parent/'fixtures/mcp_resource_envelope';raw=(folder/'before.source').read_bytes()
        metadata=json.loads((folder/'provenance.json').read_bytes());self.assertEqual(metadata['sourceSha256'],hashlib.sha256(raw).hexdigest())
        before=types.ModuleType('agent_tools._resource_envelope_before');before.__package__='agent_tools';before.__file__=str(folder/'before.source')
        exec(compile(raw,before.__file__,'exec'),before.__dict__)
        spec,value=self.observation()
        wrapped={**value,'tool':'vm_workflow','ok':True,'productAction':False,'evidenceClass':'read-only-deployment-resources',
                 'nextAction':{'action':'inspect-result'}}
        original=copy.deepcopy(wrapped)
        with self.assertRaisesRegex(ValueError,'resource_response'):before.measurement(wrapped)
        self.assertEqual(resources.measurement(value),resources.mcp_measurement(wrapped,spec.deployment_id))
        self.assertEqual(original,wrapped)
        for key,bad in (('ok',False),('productAction',True),('nativeActionAllowed',True),('deploymentId','foreign'),('unknownAuthority',True)):
            with self.subTest(key=key),self.assertRaises(ValueError):resources.mcp_measurement({**wrapped,key:bad},spec.deployment_id)


if __name__=='__main__':unittest.main()
