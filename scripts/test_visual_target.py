"""Explicit target admission through complete callers and actual local peers."""
import importlib.util
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import shutil
import socket
import time
import unittest

import visual_platform as current
import visual_target

BEFORE=Path(__file__).parent/'tests/fixtures/visual_target_before/visual_platform.py.source'
# Host shell callers launch /bin/bash, which runs their '#!' fakes; Windows
# CreateProcess finds no /bin/bash and cannot run a '#!' file.
POSIX_BASH=os.name=='posix' and os.path.isfile('/bin/bash')


def subject():
    if os.environ.get('VPN_CONTROL_VISUAL_TARGET_BEFORE'):
        assert os.environ['VPN_CONTROL_VISUAL_TARGET_BEFORE']=='1'
        import types
        module=types.ModuleType('visual_platform_before');module.__file__=str(BEFORE);module.__package__=''
        raw=BEFORE.read_bytes()
        expected=json.loads((BEFORE.parent/'provenance.json').read_text())['visual_platform.py']['sha256']
        assert hashlib.sha256(raw).hexdigest()==expected
        exec(compile(raw,str(BEFORE),'exec'),module.__dict__)
        return module
    return current


SERVER='''import json,os,socket,sys
disk,sock,effects,ready=sys.argv[1:]
held=open(disk,'r+b');server=socket.socket(socket.AF_UNIX);server.bind(sock);server.listen(4)
open(ready,'w').write(str(os.getpid()))
while True:
 c,_=server.accept()
 with c:
  c.sendall(b'{"QMP":{}}\\n');f=c.makefile('rb')
  for line in f:
   request=json.loads(line);name=request['execute']
   if name=='system_powerdown':
    with open(effects,'a')as out:out.write(name+'\\n');out.flush();os.fsync(out.fileno())
   c.sendall(b'{"return":{}}\\n')
   if name=='system_powerdown':sys.exit(0)
'''


class VisualTargetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve());self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.disk=self.root/'selected.qcow2';self.disk.write_bytes(b'controlled harmless disk');self.disk.chmod(0o600)
        self.endpoint=self.root/'qmp.sock';self.effects=self.root/'effects';self.ready=self.root/'ready'
        self.process=None

    def server(self,*,disk=None):
        self.process=subprocess.Popen([sys.executable,'-I','-c',SERVER,str(disk or self.disk),str(self.endpoint),str(self.effects),str(self.ready)],
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        def close():
            if self.process.poll()is None:self.process.terminate()
            self.process.communicate(timeout=3)
        self.addCleanup(close)
        threading.Thread(target=self.process.wait,daemon=True).start()
        deadline=time.monotonic()+3
        while not self.ready.exists()and time.monotonic()<deadline:
            if self.process.poll()is not None:self.fail(self.process.stderr.read().decode())
            time.sleep(.01)
        self.assertTrue(self.ready.exists())

    @unittest.skipUnless(hasattr(socket,'AF_UNIX'),'requires Unix-domain sockets')
    def test_missing_stop_target_cannot_send_power_to_default_vm(self):
        module=subject();self.server()
        module.RUNTIME_ROOT=self.root;module.RESOURCE_RESERVATIONS_PATH=self.root/'reservations.json'
        module.RESOURCE_LOCK_PATH=self.root/'reservations.lock'
        state={'platform':'windows','backend':'qemu-windows','identifier':str(self.disk),
            'started_by_agent':True,'pid':self.process.pid}
        module._write_state('windows',state)
        # Authentic legacy default socket exists and belongs to the harmless
        # child. Only the missing selector should prevent the actual command.
        windows=self.root/'windows';windows.mkdir();(windows/'qmp.sock').symlink_to(self.endpoint)
        try:module.stop_platform('windows')
        except module.VisualPlatformError:pass
        self.assertFalse(self.effects.exists(),'missing target sent actual system_powerdown')

    @unittest.skipUnless(hasattr(socket,'AF_UNIX'),'requires Unix-domain sockets')
    def test_valid_selected_disk_and_actual_peer_owner_accept_one_power_packet(self):
        self.server()
        actor={'pid':self.process.pid,'birth':visual_target.jobs._birth(self.process.pid)}
        current._qmp_execute(self.endpoint,'system_powerdown',disk=self.disk,expected_actor=actor)
        self.process.wait(timeout=3)
        self.assertEqual(self.effects.read_text(),'system_powerdown\n')

    @unittest.skipUnless(hasattr(socket,'AF_UNIX'),'requires Unix-domain sockets')
    def test_foreign_socket_peer_holding_another_disk_is_never_mutated(self):
        other=self.root/'other.qcow2';other.write_bytes(b'other');other.chmod(0o600)
        self.server(disk=other)
        module=subject();blocked=False
        try:
            # The preserved sender had no disk/actor admission parameters.
            # Invoke its complete original API; current caller supplies its
            # explicit selected disk to the new authenticated sender.
            if module is current:module._qmp_execute(self.endpoint,'system_powerdown',disk=self.disk)
            else:module._qmp_execute(self.endpoint,'system_powerdown')
        except (module.VisualPlatformError,visual_target.TargetError):blocked=True
        self.assertFalse(self.effects.exists(),'foreign actual peer received power')
        self.assertTrue(blocked);self.assertIsNone(self.process.poll())

    @unittest.skipUnless(hasattr(socket,'AF_UNIX'),'requires Unix-domain sockets')
    def test_reused_peer_pid_birth_is_rejected_before_capabilities_or_power(self):
        self.server()
        with self.assertRaises((current.VisualPlatformError,visual_target.TargetError)):
            current._qmp_execute(self.endpoint,'system_powerdown',disk=self.disk,
                expected_actor={'pid':self.process.pid,'birth':'darwin:1:1'})
        self.assertFalse(self.effects.exists())

    @unittest.skipUnless(hasattr(socket,'AF_UNIX'),'requires Unix-domain sockets')
    def test_unsafe_actual_disk_parent_returns_typed_blocker_without_power(self):
        from unittest import mock
        self.server();helper=visual_target
        if os.environ.get('VPN_CONTROL_VISUAL_QMP_ANCESTRY_BEFORE'):
            assert os.environ['VPN_CONTROL_VISUAL_QMP_ANCESTRY_BEFORE']=='1'
            import types
            path=BEFORE.parent/'visual_target.py.source';raw=path.read_bytes()
            expected=json.loads((BEFORE.parent/'provenance.json').read_text())['visual_target.py']['sha256']
            assert hashlib.sha256(raw).hexdigest()==expected
            helper=types.ModuleType('visual_target_before');helper.__file__=str(path)
            exec(compile(raw,str(path),'exec'),helper.__dict__)
        self.root.chmod(0o777)
        try:
            with mock.patch.object(current,'visual_target',helper):
                with self.assertRaises(current.VisualPlatformError):
                    current._qmp_execute(self.endpoint,'system_powerdown',disk=self.disk)
            self.assertFalse(self.effects.exists())
        finally:self.root.chmod(0o700)

    def test_wrong_or_missing_selectors_refuse_all_mutation_paths_before_processes(self):
        from unittest import mock
        for action in (current.bootstrap,current.start_platform,current.stop_platform):
            for target in (None,'android:other-avd','tart:wrong','native:windows'):
                with self.subTest(action=action.__name__,target=target),mock.patch.object(current,'_run')as run, \
                    mock.patch.object(current.subprocess,'Popen')as start:
                    with self.assertRaises(current.VisualPlatformError):action('android',target=target,dry_run=False)
                    run.assert_not_called();start.assert_not_called()

    def test_capture_rejects_target_before_output_creation_or_driver(self):
        output=self.root/'not-created'
        with self.assertRaises(current.VisualPlatformError):
            current.run_local_driver('android','/usr/bin/true',output,[],target='android:foreign')
        self.assertFalse(output.exists())

    @unittest.skipUnless(os.name=='posix','the generated ADB fake is a #! script, which CreateProcess cannot run')
    def test_actual_generated_adb_caller_never_freezes_foreign_avd_on_selected_port(self):
        from unittest import mock
        module=subject();adb=self.root/'adb';effects=self.root/'android-effects'
        adb.write_text('#!'+sys.executable+'\nimport pathlib,sys\na=sys.argv[1:]\n'
            'if a==["devices"]:print("List of devices attached\\nemulator-5580 device")\n'
            'elif a[-3:]==["emu","avd","name"]:print("personal-avd\\nOK")\n'
            'elif "getprop"in a:print("1")\n'
            'elif "settings"in a:pathlib.Path('+repr(str(effects))+').write_text("foreign setting changed")\n')
        adb.chmod(0o700);emulator=self.root/'emulator'
        emulator.write_text('#!/bin/sh\nexit 0\n');emulator.chmod(0o700)
        avds=self.root/'avd';config=avds/'vpn-control-visual-api35.avd'/'config.ini'
        config.parent.mkdir(parents=True);config.write_text('hw.ramSize=2G\n')
        probe={'ready':True,'infrastructureAvailable':True,'backend':'android-emulator','capabilities':['app','native'],'detail':''}
        with mock.patch.object(module,'local_probe',return_value=probe), \
                mock.patch.object(module,'_android_tool',side_effect=lambda name:str(adb if name=='adb'else emulator)), \
                mock.patch.object(module,'_admit_visual_start',return_value={}), \
                mock.patch.object(module,'_bind_visual_reservation'), \
                mock.patch.object(module,'_write_state'), \
                mock.patch.object(module,'RUNTIME_ROOT',self.root), \
                mock.patch.object(module,'ENVIRONMENTS_PATH',current.ENVIRONMENTS_PATH), \
                mock.patch.dict(os.environ,{'ANDROID_AVD_HOME':str(avds)},clear=True):
            try:
                if module is current:module.start_platform('android',target='android:vpn-control-visual-api35')
                else:module.start_platform('android')
            except module.VisualPlatformError:pass
        self.assertFalse(effects.exists(),'generated ADB caller mutated foreign AVD')

    @unittest.skipUnless(POSIX_BASH,'host shell callers run with POSIX /bin/bash')
    def test_windows_bootstrap_full_shell_cannot_create_default_disk_without_target(self):
        tree=self.root/'repo';scripts=tree/'scripts';scripts.mkdir(parents=True)
        before=bool(os.environ.get('VPN_CONTROL_VISUAL_TARGET_BEFORE'))
        source=BEFORE.parent/'bootstrap_windows_visual_vm.sh.source' if before else Path(__file__).parent/'bootstrap_windows_visual_vm.sh'
        shutil.copyfile(source,scripts/'bootstrap_windows_visual_vm.sh')
        tools=self.root/'tools';tools.mkdir();marker=self.root/'default-disk-mutated'
        for name in ('qemu-img','qemu-system-aarch64'):
            tool=tools/name;tool.write_text('#!/bin/sh\nprintf effect > "$MUTATION_MARKER"\n');tool.chmod(0o700)
        iso=self.root/'windows.iso';iso.write_bytes(b'controlled source')
        completed=subprocess.run(['/bin/bash',str(scripts/'bootstrap_windows_visual_vm.sh')],
            env={**os.environ,'PATH':str(tools)+os.pathsep+os.environ['PATH'],
                'VPN_CONTROL_WINDOWS_ISO':str(iso),'MUTATION_MARKER':str(marker)},capture_output=True,timeout=3)
        self.assertFalse(marker.exists(),'full shell created an implicit default disk')
        self.assertEqual(completed.returncode,2)

    def marker_fixture(self,*,before=False):
        tree=self.root/'marker-repo';scripts=tree/'scripts';scripts.mkdir(parents=True)
        runtime=tree/'.runtime/visual-vms/windows';runtime.mkdir(parents=True)
        disk=runtime/'vpn-control-win11.qcow2';disk.write_bytes(b'controlled-disk');disk.chmod(0o600)
        source=BEFORE.parent/'mark_windows_visual_vm_ready.sh.source'if before else Path(__file__).parent/'mark_windows_visual_vm_ready.sh'
        shutil.copyfile(source,scripts/'mark_windows_visual_vm_ready.sh')
        shutil.copyfile(Path(__file__).parent/'visual_target.py',scripts/'visual_target.py')
        config=tree/'visual-tests';config.mkdir()
        (config/'environments.json').write_text(json.dumps({'platforms':{'windows':{'local':{'qemu_disk':str(disk)}}}}))
        log=self.root/'probe-args'
        (scripts/'capture_visual_windows_qemu.py').write_text('import os,pathlib,sys\npathlib.Path(os.environ["PROBE_LOG"]).write_text("\\n".join(sys.argv[1:]))\nsys.exit(int(os.environ.get("PROBE_EXIT","0")))\n')
        tools=self.root/'marker-tools';tools.mkdir()
        tool=tools/'qemu-img';tool.write_text('#!/bin/sh\nprintf \'{"virtual-size":103079215104}\\n\'\n');tool.chmod(0o700)
        environment={**os.environ,'PATH':str(tools)+os.pathsep+os.environ['PATH'],
            'PYTHONPATH':str(current.ROOT),'PROBE_LOG':str(log)}
        return scripts/'mark_windows_visual_vm_ready.sh',disk,runtime/'READY',log,environment

    @unittest.skipUnless(POSIX_BASH,'host shell callers run with POSIX /bin/bash')
    def test_full_marker_refuses_missing_target_before_ready_write(self):
        script,disk,ready,log,env=self.marker_fixture(before=bool(os.environ.get('VPN_CONTROL_VISUAL_TARGET_BEFORE')))
        subprocess.run(['/bin/bash',str(script),'--agent-confirmed'],env=env,capture_output=True,timeout=3)
        self.assertFalse(ready.exists(),'marker wrote READY for an implicit default VM')
        self.assertFalse(log.exists())

    @unittest.skipUnless(POSIX_BASH,'host shell callers run with POSIX /bin/bash')
    def test_marker_forwards_exact_selected_target_and_failed_probe_never_marks_ready(self):
        script,disk,ready,log,env=self.marker_fixture();target='qemu:'+str(disk)
        command=['/bin/bash',str(script),'--target',target,'--agent-confirmed']
        result=subprocess.run(command,env={**env,'PROBE_EXIT':'1'},capture_output=True,timeout=3)
        self.assertNotEqual(result.returncode,0);self.assertFalse(ready.exists())
        self.assertEqual(log.read_text().splitlines(),['--probe','--target',target])
        result=subprocess.run(command,env=env,capture_output=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertIn('target='+target,ready.read_text())

    @unittest.skipUnless(POSIX_BASH,'host shell callers run with POSIX /bin/bash')
    def test_actual_hosted_workflow_caller_forwards_its_created_avd(self):
        path=BEFORE.parent/'visual-regression.yml.source'if os.environ.get('VPN_CONTROL_VISUAL_TARGET_BEFORE')else current.ROOT/'.github/workflows/visual-regression.yml'
        source=path.read_text()
        created=re.search(r'avdmanager create avd --force --name ([a-z0-9-]+)',source).group(1)
        command=next(line.strip()for line in source.splitlines()if line.strip().startswith('scripts/capture_visual_android.sh '))
        scripts=self.root/'scripts';scripts.mkdir()
        driver=scripts/'capture_visual_android.sh';log=self.root/'workflow-args'
        driver.write_text('#!'+sys.executable+'\nimport argparse,json,pathlib,sys\np=argparse.ArgumentParser();p.add_argument("--target",required=True);p.add_argument("output");p.add_argument("scenes");a=p.parse_args()\nassert a.target=='+repr('android:'+created)+'\npathlib.Path('+repr(str(log))+').write_text(json.dumps(vars(a)))\n');driver.chmod(0o700)
        result=subprocess.run(['/bin/bash','-c',command],cwd=self.root,
            env={**os.environ,'VISUAL_SCENES':'controlled-scene'},capture_output=True,timeout=3)
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(json.loads(log.read_text())['target'],'android:'+created)


if __name__=='__main__':unittest.main()
