"""QEMU device topology has unique ports and takes instance facts from data."""
import unittest
from agent_tools.windows_vm_hardware import qemu_argv
from agent_tools.tests import test_native_vm_spec as specs


class HardwareTests(unittest.TestCase):
    def test_disk_and_three_optical_devices_never_compete_for_the_same_port(self):
        args=qemu_argv(specs.request(),'/proc/self/fd/17',{'firmwareCode':1,'installer':2,'drivers':3})
        devices=[args[i+1] for i,a in enumerate(args) if a=='-device' and args[i+1].startswith(('ide-hd,','ide-cd,'))]
        self.assertEqual(4,len(devices))
        ports=[next(p for p in d.split(',') if p.startswith('bus=')) for d in devices]
        self.assertEqual(4,len(set(ports)))
        self.assertEqual('order=c,once=d,menu=off',args[args.index('-boot')+1])
    def test_instance_paths_cpu_memory_uuid_and_vnc_are_argument_driven(self):
        data=specs.request();data.update(root='/different/new vm',cpus=6,memoryMiB=8192,vncPort=5949)
        args=qemu_argv(data,'/proc/self/fd/23',{'firmwareCode':5,'installer':6,'drivers':7})
        self.assertEqual('/proc/self/fd/23',args[0]);self.assertEqual('6',args[args.index('-smp')+1])
        self.assertEqual('8192',args[args.index('-m')+1]);self.assertEqual(data['deploymentId'],args[args.index('-uuid')+1])
        self.assertEqual('127.0.0.1:49',args[args.index('-vnc')+1])
        self.assertTrue(any('file=/different/new vm/disk.qcow2' in a for a in args))


if __name__=='__main__':unittest.main()
