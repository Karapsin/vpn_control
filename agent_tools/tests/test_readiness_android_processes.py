import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from agent_tools import readiness,readiness_android as android,readiness_android_processes as processes,readiness_providers as providers


class AndroidSystemRoleTest(unittest.TestCase):
    def setUp(self):
        self.raw='NAME\ninit\n[kworker/1:3]\nsh\nps\n'
        fields=['S','1','142','142','60928','142','0','0','0','0','0','0','0','0','0','20','0','1','0','440']
        self.stat='142 (sh) '+' '.join(fields)+'\n'
        init=('service console /system/bin/sh\n    class core\n    console\n    disabled\n    user shell\n'
              '    group shell log readproc\n    seclabel u:r:shell:s0\n    setenv HOSTNAME console\n    shutdown critical\n')
        self.replies={('shell','ps','-A','-o','NAME'):self.raw,
          ('shell','ps','-A','-o','PID,UID,S,NAME'):'PID UID S NAME\n1 0 S init\n99 0 I [kworker/1:3]\n142 2000 S sh\n155 2000 R ps\n',
          ('shell','cat','/proc/99/status'):'Pid:\t99\nPPid:\t2\nUid:\t0\t0\t0\t0\nKthread:\t1\nState:\tI (idle)\n',
          ('shell','cat','/proc/142/status'):'Pid:\t142\nPPid:\t1\nUid:\t2000\t2000\t2000\t2000\nKthread:\t0\nState:\tS (sleeping)\n',
          ('shell','cat','/proc/142/stat'):self.stat,('shell','getprop','init.svc.console'):'running\n',
          ('shell','cat','/system/etc/init/hw/init.rc'):init,
          ('shell','readlink','/proc/142/exe'):'/system/bin/sh\n',
          ('shell','cat','/proc/142/cmdline'):'/system/bin/sh\0',
          ('shell','uname','-m'):'aarch64\n',
          ('shell','cat','/proc/142/syscall'):'63 0x0 0x1000 0x1 0x0 0x0 0x0 0x0 0x0\n',
          ('shell','pm','list','packages','com.kardinal.vpncontrol'):'',
          ('shell','dumpsys','package','installs'):'Active install sessions:\n\nFinalized install sessions:\n\nHistorical install sessions:\n\nLegacy install sessions:\n{}\nGentle update with constraints info:\nhasPendingIdleJob=false\n'}
        for fd in ('0','1','2'):self.replies[('shell','readlink','/proc/142/fd/'+fd)]='/dev/console\n'

    def command(self,args,deadline):
        self.assertLess(time.monotonic(),deadline)
        self.assertIn(tuple(args),self.replies)
        return self.replies[tuple(args)],'same-connection'

    def test_whole_idle_gate_accepts_only_proven_kernel_and_inert_init_console(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();root.chmod(0o700)
            descriptor={'binding':{'target':'owned','machine':'avd','adb':'/usr/bin/adb','avdName':'avd','serial':'emulator-5662','serverPort':5042},
              'hostBinding':{'target':'owned','machine':'host','boot':'hostboot','account':str(os.geteuid())},
              'jobRootGeneration':[1,2],'storagePlan':'owned','avdConfig':str(root/'avd/config.ini'),
              'initialActor':{'pid':123,'birth':'same'},'writableDisks':[],'memoryMiB':2048,'jobBaseline':['init']}
            backend=android.AndroidInstanceBackend(root,descriptor,lambda:'same-connection',root);backend._operator_held=True
            observed=readiness.Observation('owned','avd',guest='running',boot='guestboot')
            method=backend._idle
            if os.environ.get('VPN_CONTROL_ANDROID_PROCESS_BEFORE'):
                self.assertEqual(os.environ['VPN_CONTROL_ANDROID_PROCESS_BEFORE'],'1')
                path=Path(__file__).parent/'fixtures'/'android_process_gate_before.py'
                namespace=dict(vars(android));exec(compile(path.read_text(),str(path),'exec'),namespace)
                method=lambda value,deadline:namespace['_idle'](backend,value,deadline)
            with mock.patch.object(backend,'_current',return_value=({'pid':123,'birth':'same'},'live',None)), \
                 mock.patch.object(backend,'_launches',return_value=[]), \
                 mock.patch.object(android.visual,'_read_reservations',return_value={'android':{'memory_mib':2048,'pid':123}}), \
                 mock.patch.object(backend.adb,'_command',side_effect=self.command):
                result=method(observed,time.monotonic()+5)
            self.assertEqual(result.idle_visibility,readiness.IDLE_VISIBILITY)

    def test_userspace_kernel_name_unmanaged_shell_active_console_and_malformed_reply_block(self):
        active=self.stat.split(') ',1)[1].split();active[11]='1'
        cases=[(('shell','cat','/proc/99/status'),self.replies[('shell','cat','/proc/99/status')].replace('Kthread:\t1','Kthread:\t0')),
          (('shell','readlink','/proc/142/fd/0'),'/dev/null\n'),
          (('shell','cat','/proc/142/cmdline'),'PRIVATE-INPUT-NEVER-DISCLOSE\0'),
          (('shell','cat','/proc/142/syscall'),'64 0x0 0x1000 0x1 0x0 0x0 0x0 0x0 0x0\n'),
          (('shell','cat','/proc/142/syscall'),'63 PRIVATE-INPUT-NEVER-DISCLOSE 0x1000 0x1 0x0 0x0 0x0 0x0 0x0\n'),
          (('shell','cat','/proc/142/stat'),'142 (sh) '+' '.join(active)+'\n'),
          (('shell','getprop','init.svc.console'),'stopped\n')]
        for key,value in cases:
            with self.subTest(key=key):
                original=self.replies[key];self.replies[key]=value
                try:
                    with self.assertRaises(providers.ProviderError) as error:
                        processes.idle_names(self.raw,['init'],self.command,time.monotonic()+5)
                    self.assertNotIn('PRIVATE-INPUT',str(error.exception))
                finally:self.replies[key]=original

    def test_unmanaged_sleep_blocks_without_reading_any_process_arguments(self):
        with self.assertRaises(providers.ProviderError):
            processes.idle_names('NAME\ninit\nsleep\n',['init'],lambda *args:self.fail('unexpected private read'),time.monotonic()+5)


if __name__=='__main__':unittest.main()
