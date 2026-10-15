"""Fresh VM identity/configuration is reproducible from arguments alone."""
import copy,unittest
from agent_tools.native_vm_spec import FreshWindowsVmSpec,VmSpecError

def request():
    return {'deploymentId':'7fb3fd62-699e-4478-9bd0-498a61efb91c','host':'lab-one','root':'/owned/new-a','memoryMiB':6144,'cpus':4,'diskGiB':96,'vncPort':5941,'headroomMiB':8192,'assets':{name:{'path':'/media/'+name,'bytes':1234,'sha256':'ab'*32} for name in ('installer','drivers','firmwareCode','firmwareVars')}}
class FreshVmSpecTests(unittest.TestCase):
    def test_two_independent_layouts_need_only_different_arguments(self):
        first=request();second=copy.deepcopy(first)
        second.update(deploymentId='ff6b5d84-f546-4a96-baf7-f9c801c743c0',host='another-lab',root='/different/vm beta',vncPort=5949,memoryMiB=8192,cpus=6)
        for name,value in second['assets'].items():value['path']='/another media/'+name
        self.assertEqual(first,FreshWindowsVmSpec.parse(first).as_dict())
        self.assertEqual(second,FreshWindowsVmSpec.parse(second).as_dict())
    def test_invalid_inputs_cannot_be_authority_flags_or_commands(self):
        for key,value in (('ready',True),('command','PUBLIC'),('ownerPid',7),('bootId','PUBLIC')):
            data=request();data[key]=value
            with self.assertRaises(VmSpecError):FreshWindowsVmSpec.parse(data)
    def test_paths_ports_limits_and_asset_identity_fail_before_any_effect(self):
        for key,value in (('root','/owned/../escape'),('root','/owned/'+('x'*110)),('memoryMiB',True),('headroomMiB',1024),('vncPort',22)):
            data=request();data[key]=value
            with self.assertRaises(VmSpecError):FreshWindowsVmSpec.parse(data)
        data=request();data['assets']['drivers']=copy.deepcopy(data['assets']['installer'])
        with self.assertRaises(VmSpecError):FreshWindowsVmSpec.parse(data)
