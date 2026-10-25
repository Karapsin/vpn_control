"""Whole coordinator → generated ADB argv → real Unix endpoint reboot admission."""
import json
import os
from pathlib import Path
import socketserver
import sys
import threading
import time
import types
import unittest
from dataclasses import replace
from unittest import mock
from uuid import uuid4

from agent_tools import readiness as r, readiness_android as android, readiness_providers as providers
from agent_tools.tests import test_readiness_android as existing


class RebootTest(unittest.TestCase):
    def setUp(self):
        self.fixture=existing.AndroidLifecycleTest('test_reused_original_pid_blocks_replacement')
        self.fixture.setUp();self.addCleanup(self.fixture.temporary.cleanup)
        self.root=self.fixture.root;self.boot=str(uuid4());self.reboots=0;self.calls=[]
        case=self
        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                argv=json.loads(self.rfile.readline());case.calls.append(argv)
                if argv[:6]!=['-H','127.0.0.1','-P','5038','-s','emulator-5660']:
                    raise AssertionError('unexpected generated ADB target')
                args=argv[6:]
                if args==['reboot']:
                    case.reboots+=1;case.boot=str(uuid4());output=''
                elif args==['emu','avd','name']:output='task-avd\nOK\n'
                elif args==['emu','avd','status']:output='virtual device is running\nOK\n'
                elif args==['shell','cat','/proc/sys/kernel/random/boot_id']:output=case.boot+'\n'
                elif args==['shell','getprop','sys.boot_completed']:output='1\n'
                elif args==['shell','am','get-current-user']:output='0\n'
                elif args==['shell','dumpsys','window','policy']:output='  showing=false\n  currentUser=0\n'
                elif len(args)==2 and args[0]=='shell' and args[1].startswith('set -o pipefail'):output='  mWakefulness=Awake\n'
                else:raise AssertionError('unexpected generated ADB command')
                self.wfile.write(json.dumps({'stdout':output}).encode()+b'\n')
        endpoint=self.root/'endpoint';self.server=socketserver.UnixStreamServer(str(endpoint),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.server.server_close);self.addCleanup(self.server.shutdown)
        adb=self.root/'adb';adb.write_text('#!'+sys.executable+'\nimport json,socket,sys\ns=socket.socket(socket.AF_UNIX)\ns.connect('+repr(str(endpoint))+')\ns.sendall(json.dumps(sys.argv[1:]).encode()+b"\\n")\nf=s.makefile("rb")\nv=json.loads(f.readline())\nsys.stdout.write(v["stdout"])\n');adb.chmod(0o700)
        self.fixture.descriptor['binding']['adb']=str(adb)
        self.backend=self.fixture.backend();self.idle=True
        self.current=mock.patch.object(self.backend,'_current',return_value=({'pid':123,'birth':'original'},'live',None));self.current.start();self.addCleanup(self.current.stop)
        self.bind=mock.patch.object(self.backend,'_bind_actor');self.bind.start();self.addCleanup(self.bind.stop)
        def idle(observed,deadline):
            if not self.idle:raise providers.ProviderError('android_idle_work_active')
            return replace(observed,idle_visibility=r.IDLE_VISIBILITY)
        self.project=mock.patch.object(self.backend,'_idle',side_effect=idle);self.project.start();self.addCleanup(self.project.stop)
        for flag,name,filename in [('VPN_CONTROL_ANDROID_REBOOT_OBSERVE_BEFORE','observe','android_reboot_observe_before.py'),
                                    ('VPN_CONTROL_ANDROID_REBOOT_IDENTITY_BEFORE','_recover','android_reboot_identity_before.py'),
                                    ('VPN_CONTROL_ANDROID_REBOOT_FINAL_IDENTITY_BEFORE','_recover','android_reboot_final_identity_before.py')]:
            if os.environ.get(flag):
                self.assertEqual(os.environ[flag],'1');path=Path(__file__).parent/'fixtures'/filename
                namespace=dict(vars(android));exec(compile(path.read_text(),str(path),'exec'),namespace)
                setattr(self.backend,name,types.MethodType(namespace[name],self.backend))
        self.adapter=providers.ProviderAdapter('android-emulator','owned-fixture','task-avd',self.backend)
        (self.root/'journal').mkdir(mode=0o700)
        self.context=r.Context('owned-fixture','task-avd',self.adapter,r.RecoveryJournal(self.root/'journal'),deadline=time.monotonic()+20)

    def test_normal_idle_reboot_uses_guest_identity_and_one_original_effect(self):
        before=self.boot;operation=str(uuid4())
        ready=r.idle_reboot(self.context,operation)
        self.assertNotEqual(ready.boot,before);self.assertEqual(self.reboots,1)
        self.assertIsNone(ready.account);self.assertIsNone(ready.session)
        repeated=r.idle_reboot(self.context,operation)
        self.assertEqual(repeated.identities(),ready.identities());self.assertEqual(self.reboots,1)
        self.assertFalse(any('dumpsys' in argv or 'am' in argv or 'input' in argv for argv in self.calls))

    def test_busy_guest_is_background_ready_but_has_no_power_admission(self):
        self.idle=False
        requirements=r.Requirements(frozenset({'guest_agent'}),frozenset({'reboot'}))
        ready=r.ensure_ready(self.context,requirements,str(uuid4()))
        self.assertEqual(ready.boot,self.boot);self.assertEqual(self.reboots,0)
        with self.assertRaisesRegex(r.ReadinessBlocked,'positive_idle_proof_missing'):
            r.idle_reboot(self.context,str(uuid4()))
        self.assertEqual(self.reboots,0);self.assertFalse(list(self.root.glob('effect-*.json')))

    def test_boot_change_during_final_idle_census_never_submits_power(self):
        original=self.boot;interleaved=[]
        def interleaving(observed,deadline):
            # A real guest boot transition interleaves with the long second
            # census, after _recover's first identity observation has passed.
            frame=sys._getframe(1)
            while frame is not None and frame.f_code.co_filename.endswith('/unittest/mock.py'):frame=frame.f_back
            if frame is not None and frame.f_code.co_name=='_recover':
                self.boot=str(uuid4());interleaved.append(self.boot)
            return replace(observed,idle_visibility=r.IDLE_VISIBILITY)
        self.backend._idle.side_effect=interleaving
        try:r.idle_reboot(self.context,str(uuid4()))
        except r.ReadinessBlocked:pass
        self.assertNotEqual(self.boot,original)
        self.assertEqual(len(interleaved),1)
        self.assertEqual(self.reboots,0)
        self.assertFalse(list(self.root.glob('effect-*.json')))


if __name__=='__main__':unittest.main()
