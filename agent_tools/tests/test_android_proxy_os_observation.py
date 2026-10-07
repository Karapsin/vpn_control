"""Inert causal tests; never compile Java/DEX, call SSH, or use a native Android device."""
import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from agent_tools import android_proxy_os_observation as probe
from agent_tools import android_installer_failed_check_retirement as old
from agent_tools.tests.fixtures import historical_source
from unittest.mock import patch

HISTORICAL = Path(__file__).parent / "fixtures/android_proxy_os_history/retirement_3eed5a2e.source"

CORR='3a892008-0649-4c1a-8d46-c9a9a0c28b74'

class ProxyObservationTest(unittest.TestCase):
    def test_null_is_observation_but_failed_or_unstable_getter_is_unknown(self):
        read={'global':None,'defaultForShell':None}
        valid={'schema':1,'state':'observed','uid':2000,'correlationId':CORR,'reads':[read,read]}
        self.assertIsNone(probe.parse_probe(json.dumps(valid),CORR)['reads'][0]['global'])
        for value in ({'state':'unknown','errorType':'RemoteException'},
                {**valid,'uid':0},{**valid,'reads':[read,{'global':{'host':'127.0.0.1','port':45635,'pacUrl':'','exclusionList':[]},'defaultForShell':None}]},
                {**valid,'reads':[{},{}]}):
            with self.assertRaises(ValueError):probe.parse_probe(json.dumps(value),CORR)

    def test_frozen_sources_and_fixed_java_getters(self):
        source=Path(probe.__file__).parent/'fixtures/android_proxy_os_probe/ProxyProbe.java'
        raw=source.read_bytes();self.assertEqual(probe.JAVA_SHA,hashlib.sha256(raw).hexdigest())
        text=raw.decode()
        self.assertIn('iface.getMethod("getGlobalProxy")',text)
        self.assertIn('iface.getMethod("getProxyForNetwork"',text)
        self.assertIn('uid!=2000',text)
        self.assertIn('InvocationTargetException',text)
        for forbidden in ('setGlobalProxy','setHiddenApiExemptions','service call','TRANSACTION_','setDefaultProxy'):self.assertNotIn(forbidden,text)
        historical = historical_source.load(HISTORICAL, probe.OLD_HELPER_SHA)
        self.assertEqual(probe.OLD_HELPER_SHA,hashlib.sha256(Path(historical.__file__).read_bytes()).hexdigest())
        self.assertEqual(probe.OLD_OS_SOURCE_SHA,hashlib.sha256(historical.remote_metadata_bound_proxy_service_source().encode()).hexdigest())
        with patch.object(probe, "old", historical):
            compile(probe.remote_source(),'proxy-os-remote','exec')

    def test_historical_factory_without_fcntl_never_grants_locking(self):
        import builtins
        real_import=builtins.__import__
        calls=[]
        def unavailable(name,*args,**kwargs):
            if name=='fcntl':
                calls.append(name)
                raise ModuleNotFoundError("No module named 'fcntl'",name='fcntl')
            return real_import(name,*args,**kwargs)
        with patch.object(builtins,'__import__',unavailable):
            historical=historical_source.load(HISTORICAL,probe.OLD_HELPER_SHA)
            self.assertTrue(historical.remote_metadata_bound_proxy_service_source())
        self.assertEqual(calls,[])  # Isolated historical seam, no native API import.
        for name in ('flock','LOCK_SH','LOCK_EX','LOCK_NB','LOCK_UN'):
            with self.subTest(api=name),self.assertRaisesRegex(RuntimeError,'historical_native_locking_forbidden'):
                getattr(historical.fcntl,name)
        historical_source.verify(historical,HISTORICAL,probe.OLD_HELPER_SHA)

    def test_altered_and_current_historical_source_refused(self):
        with self.assertRaisesRegex(ValueError, 'historical_source_binding_changed'):
            historical_source.load(old.__file__, probe.OLD_HELPER_SHA)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'altered.source';path.write_bytes(HISTORICAL.read_bytes()+b'\n# altered\n')
            with self.assertRaisesRegex(ValueError, 'historical_source_binding_changed'):
                historical_source.load(path, probe.OLD_HELPER_SHA)

    def test_mixed_current_function_cannot_impersonate_historical_module(self):
        historical=historical_source.load(HISTORICAL, probe.OLD_HELPER_SHA)
        historical.remote_metadata_bound_proxy_service_source=old.remote_metadata_bound_proxy_service_source
        with self.assertRaisesRegex(ValueError, 'historical_function_binding_changed'):
            historical_source.verify(historical, HISTORICAL, probe.OLD_HELPER_SHA)

    def test_production_prepare_refuses_current_source_before_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'.rag_index').mkdir(mode=0o700)
            source=root/probe.JAVA_REL;source.parent.mkdir(parents=True)
            source.write_bytes((Path(probe.__file__).parent/'fixtures/android_proxy_os_probe/ProxyProbe.java').read_bytes())
            with self.assertRaisesRegex(ValueError, 'reviewed_source_changed'):
                probe.prepare(root,CORR,expected_java_sha256=probe.JAVA_SHA,
                    javac='unused',java='unused',d8_jar='unused')
            self.assertFalse((root/'.rag_index/android-proxy-os-observation'/CORR).exists())

    def test_full_generation_and_parent_replacement_reject(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();parent=root/'private';parent.mkdir(mode=0o700);path=parent/'artifact';path.write_bytes(b'dex bytes');path.chmod(0o600)
            pin=probe._private_pin(path)
            replacement=parent/'replacement';replacement.write_bytes(path.read_bytes());replacement.chmod(0o600);replacement.replace(path)
            with self.assertRaises(ValueError):probe._guard([pin])
            pin=probe._private_pin(path);parent.rename(root/'old');parent.mkdir(mode=0o700)
            (root/'old'/'artifact').rename(parent/'artifact')
            with self.assertRaises(ValueError):probe._guard([pin])

    def fragment_fixture(self, mode):
        temp=tempfile.TemporaryDirectory();root=Path(temp.name).resolve();root.chmod(0o700)
        device=root/'device';device.mkdir(mode=0o700)
        java=root/'app_process';fake_id=root/'id';fake_stat=root/'stat';adb=root/'adb'
        read={'global':None,'defaultForShell':None};reply={'schema':1,'state':'observed','uid':2000,'correlationId':CORR,'reads':[read,read]}
        if mode=='unstable':reply['reads'][1]={'global':{'host':'127.0.0.1','port':45635,'exclusionList':[],'pacUrl':''},'defaultForShell':None}
        if mode=='getter-error':reply={'state':'unknown','phase':'getter-first','errorType':'RemoteException'}
        java.write_text('#!'+sys.executable+'\nimport pathlib\n'+('p=pathlib.Path('+repr(str(device/('vpn-control-os-proxy-'+CORR)/'classes.dex'))+');p.chmod(0o600);p.write_bytes(p.read_bytes()+b"drift")\n' if mode=='stage-drift' else '')+'print('+repr(json.dumps(reply))+')\n'+('raise SystemExit(1)\n' if mode=='getter-error' else ''));java.chmod(0o700)
        fake_id.write_text('#!/bin/sh\nprintf '+('0' if mode=='root-uid' else '2000'));fake_id.chmod(0o700)
        fake_stat.write_text('#!'+sys.executable+'\nimport os,sys,stat\nflag="-Lc" if "-Lc" in sys.argv else "-c";j=sys.argv.index(flag);fmt=sys.argv[j+1]\nfor p in sys.argv[j+2:]:\n x=os.fstat(int(p.rsplit("/",1)[-1])) if flag=="-Lc" else os.lstat(p)\n fields={"%d":x.st_dev,"%i":x.st_ino,"%s":x.st_size,"%y":x.st_mtime_ns,"%z":x.st_ctime_ns,"%a":format(stat.S_IMODE(x.st_mode),"o"),"%u":2000,"%g":2000,"%h":x.st_nlink,"%F":"directory" if stat.S_ISDIR(x.st_mode) else "symbolic link" if stat.S_ISLNK(x.st_mode) else "regular file"}\n print("|".join(str(fields[t]) for t in fmt.split("|")))\n');fake_stat.chmod(0o700)
        decoder=root/'base64';decoder.write_text('#!'+sys.executable+'\nimport base64,sys\nsys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read(),validate=True))\n');decoder.chmod(0o700)
        adb.write_text('#!'+sys.executable+'\nimport os,sys,subprocess,pathlib,shutil\na=sys.argv[1:]\nif "push" in a:\n shutil.copyfile(a[-2],a[-1].replace("/data/local/tmp",'+repr(str(device))+'));pathlib.Path(a[-1].replace("/data/local/tmp",'+repr(str(device))+')).chmod(0o600);raise SystemExit(0)\ncmd=" ".join(a[a.index("-T")+1:])\ncmd=cmd.replace("/system/bin/id",'+repr(str(fake_id))+').replace("/system/bin/stat",'+repr(str(fake_stat))+').replace("/system/bin/mkdir","/bin/mkdir").replace("/system/bin/chmod","/bin/chmod").replace("/proc/self/fd/3","/dev/fd/3").replace("/proc/self/fd/4","/dev/fd/4").replace("/system/bin/base64",'+repr(str(decoder))+').replace("/system/bin/sha256sum","/usr/bin/shasum -a 256").replace("/system/bin/app_process",'+repr(str(java))+').replace("/data/local/tmp",'+repr(str(device))+')\nr=subprocess.run(["/bin/sh","-c",cmd],capture_output=True);sys.stdout.buffer.write(r.stdout.replace('+repr(str(device).encode())+',b"/data/local/tmp"));sys.stderr.buffer.write(r.stderr);raise SystemExit(r.returncode)\n');adb.chmod(0o700)
        prior=root/('android-failed-check-retirement-diagnostic-'+probe.OS_OBSERVATION);prior.mkdir(mode=0o700)
        census={};value={'diagnosticSourceSha256':probe.OLD_OS_SOURCE_SHA,'exception':None,'currentFailurePhase':'metadata-os-closing-guard','originalOutcome':'unknown','installerMetadataCensus':census}
        old._save(prior/'receipt.json',value);(prior/'connectivity.txt').write_bytes(b'original private OS capture');(prior/'connectivity.txt').chmod(0o600)
        def snapshot(path,limit=1048576):
            raw,gen,digest=old.private_snapshot(path,limit);return raw,{'generation':gen,'sha256':digest}
        receipt,receipt_pin=snapshot(prior/'receipt.json');capture,capture_pin=snapshot(prior/'connectivity.txt')
        dex=b'dex\n035\x00'+b'0'*112
        art={'correlationId':CORR,'javaSha256':probe.JAVA_SHA,'primarySource':probe.PRIMARY,'dexBase64':base64.b64encode(dex).decode(),'artifactSha256':hashlib.sha256(dex).hexdigest()}
        if mode=='wrong-artifact':art['artifactSha256']='0'*64
        constants={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(probe.remote_source()).body[:3]}
        section=constants['CHECKS'];section=section[section.index('def parse_probe'):section.index("phase='metadata-os-closing-guard'")]
        namespace={'root':root,'diagnostic_id':CORR,'diagnostic':{'probeArtifact':art},'expected':{'adb':str(adb),'serial':'fake'},'identity':{'census':census},'shell':None,'METADATA_SCRIPT':'readonly metadata',
            'authenticated_privileged_read':lambda *args:'metadata','parse_installer_metadata_census':lambda x:census,
            'guard_files':lambda *args:None,'verify_manifest':lambda:None,'fixture_stopped':lambda x:None,
            'pins':[],'paths':[],'parents':[],'output':None,'snapshot_file':snapshot,'_create':old._create,
            'PROBE_JAVA_SHA':probe.JAVA_SHA,'PROBE_PRIMARY':probe.PRIMARY,'PROBE_STAGE_AUTHORITY':probe.STAGE_AUTHORITY,'PROBE_OLD_OS_SHA':probe.OLD_OS_SOURCE_SHA,
            'PROBE_OS_RECEIPT_PIN':{**receipt_pin,'bytes':len(receipt)},'PROBE_OS_CAPTURE_PIN':{**capture_pin,'bytes':len(capture)},
            'os':os,'stat':stat,'subprocess':subprocess,'hashlib':hashlib,'base64':base64,'json':json,'re':__import__('re')}
        return temp,root,section,namespace

    def test_actual_generated_stage_and_getter_controlflow(self):
        for mode in ('null','root-uid','wrong-artifact','getter-error','unstable','stage-drift'):
            temp,root,section,scope=self.fragment_fixture(mode)
            try:
                before={str(p):p.read_bytes() for p in root.glob('android-failed*/**/*') if p.is_file()}
                if mode=='null':
                    exec(section,scope);self.assertIsNone(scope['observed']['reads'][0]['global'])
                else:
                    with self.assertRaises(ValueError):exec(section,scope)
                    if mode in ('root-uid','wrong-artifact'):self.assertFalse((root/('android-proxy-os-stage-'+CORR)).exists())
                    if mode in ('getter-error','unstable','stage-drift'):
                        self.assertIn('service_bytes',scope)
                        if mode=='getter-error':self.assertEqual('unknown',json.loads(scope['service_bytes'])['state'])
                self.assertEqual(before,{str(p):p.read_bytes() for p in root.glob('android-failed*/**/*') if p.is_file()})
            finally:temp.cleanup()

    def test_compilation_receipt_requires_exact_commands_and_integer_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();(root/'.rag_index').mkdir(mode=0o700)
            directory=probe._directory(root,CORR);directory.mkdir(mode=0o700)
            artifact=directory/'classes.dex';artifact.write_bytes(b'dex\n035\x00'+b'0'*112);artifact.chmod(0o600)
            commands=[['fixed-javac','fixed-source'],['fixed-java','fixed-d8']]
            intent={'kind':'android-proxy-os-build-intent','correlationId':CORR,'javaSha256':probe.JAVA_SHA,'remoteSourceSha256':hashlib.sha256(probe.remote_source().encode()).hexdigest(),'localPins':[],'commands':commands,'artifactPath':str(artifact)}
            old._save(directory/'intent.json',intent)
            _,gen,digest=old.private_snapshot(directory/'intent.json',65536)
            base={'correlationId':CORR,'intentPin':{'generation':gen,'sha256':digest},'javaSha256':probe.JAVA_SHA,'artifactSha256':hashlib.sha256(artifact.read_bytes()).hexdigest()}
            for case in ('boolean','wrong-argv','success'):
                receipt={**base,'commands':[{'argv':argv,'exit':0,'stdoutSha256':'0'*64,'stderrSha256':'1'*64} for argv in commands]}
                if case=='boolean':receipt['commands'][0]['exit']=False
                if case=='wrong-argv':receipt['commands'][0]['argv']=['unrelated-compiler']
                path=directory/(case+'.json');old._save(path,receipt)
                if case=='success':self.assertEqual('bound',probe.bind_artifact(root,CORR,path)['state'])
                else:
                    with self.assertRaises(ValueError):probe.bind_artifact(root,CORR,path)
                    self.assertFalse((directory/'artifact.json').exists())

    def test_nested_source_carrier_avoids_measured_exec_argument_overflow(self):
        from agent_tools import ssh_transport as ssh
        from pathlib import PurePosixPath
        root=Path('/inert-proxy-probe-test-inventory')
        gateway=ssh.SshHost('gateway','example.invalid',22,'user',root/'key',root/'hosts')
        target=ssh.SshHost('archlinux','example.invalid',22,'user',root/'key',PurePosixPath('/home/user/hosts'),transport='nested',gateway='gateway',remote_host_alias='archlinux')
        config=ssh.SshConfig(root,{'gateway':gateway,'archlinux':target})
        source=probe.remote_source();packet=json.dumps({'artifact':'A'*30000})
        def size(carrier):
            argv=ssh.build_ssh_argv(config,'archlinux',60,command=('python3','-I','-B','-c',carrier,'diagnose','/fixture','archlinux','api35',CORR,packet))
            return max(len(x.encode()) for x in argv)
        self.assertGreaterEqual(size('exec('+repr(source)+')'),131072)
        self.assertLess(size(probe.source_carrier(source)),131072)
        code=probe.source_carrier("result='bounded decoded fixed source'")
        scope={};exec(code,scope);self.assertEqual('bounded decoded fixed source',scope['result'])

    def test_generated_exclusive_stage_foreign_symlink_and_directory_exchange_refuse(self):
        for exchange in (False,True):
            temp,root,section,scope=self.fragment_fixture('null')
            try:
                victim=root/'foreign';victim.write_bytes(b'FOREIGN_DATA');victim.chmod(0o600)
                before=old._generation(victim.stat())
                device_dir=root/'device'/('vpn-control-os-proxy-'+CORR)
                executable=root/'stat';text=executable.read_text()
                marker='for p in sys.argv[j+2:]:\n'
                # At the actual first held-FD stat: swap its name/parent, then run
                # the unchanged generated checks and actual shell decode pipeline.
                mutation=('d.rename(d.with_name(d.name+"-owned"));d.mkdir(mode=0o700);(d/"classes.dex").symlink_to(v)' if exchange else '(d/"classes.dex").unlink();(d/"classes.dex").symlink_to(v)')
                injected=('marker=__import__("pathlib").Path('+repr(str(root/'race-once'))+');d=__import__("pathlib").Path('+repr(str(device_dir))+');v='+repr(str(victim))+'\n'
                    'if flag=="-Lc" and sys.argv[-1]=="/dev/fd/4" and not marker.exists():\n marker.touch();'+mutation+'\n')
                executable.write_text(text.replace(marker,injected+marker,1))
                with self.assertRaises(ValueError):exec(section,scope)
                self.assertEqual(before,old._generation(victim.stat()))
                self.assertEqual(b'FOREIGN_DATA',victim.read_bytes())
                self.assertNotIn('probe_result',scope)
            finally:temp.cleanup()

    def test_generated_noclobber_symlink_created_at_exclusive_open_refuses(self):
        temp,root,section,scope=self.fragment_fixture('null')
        try:
            victim=root/'foreign';victim.write_bytes(b'FOREIGN_DATA');victim.chmod(0o600)
            before=old._generation(victim.stat());adb=Path(scope['expected']['adb']);text=adb.read_text()
            marker='cmd=cmd.replace('
            injected='cmd=cmd.replace("set -C; exec 4>","set -C; /bin/ln -s '+str(victim)+' ./classes.dex; exec 4>")\n'
            self.assertIn(marker,text);adb.write_text(text.replace(marker,injected+marker,1))
            with self.assertRaises(ValueError):exec(section,scope)
            self.assertEqual(before,old._generation(victim.stat()))
            self.assertEqual(b'FOREIGN_DATA',victim.read_bytes());self.assertNotIn('probe_result',scope)
        finally:temp.cleanup()

    def test_pre_cd_private_parent_substitution_is_explicit_acquired_authority(self):
        # The approved single operator controls shell UID2000. This test makes
        # the acquisition boundary explicit, rather than claiming original mkdir
        # identity continuity against another adversarial same-UID operator.
        temp,root,section,scope=self.fragment_fixture('null')
        try:
            victim=root/'foreign';victim.write_bytes(b'FOREIGN_DATA');victim.chmod(0o600)
            before=old._generation(victim.stat())
            parent=root/'device'/('vpn-control-os-proxy-'+CORR);original=parent.with_name(parent.name+'-original')
            adb=Path(scope['expected']['adb']);text=adb.read_text();marker='cmd=cmd.replace('
            commands='; /bin/mv '+str(parent)+' '+str(original)+'; /bin/mkdir -m 700 '+str(parent)+'; /bin/ln -s '+str(victim)+' '+str(parent/'unrelated')+'; CDPATH=;'
            injected='cmd=cmd.replace("; CDPATH=;",'+repr(commands)+')\n'
            self.assertIn(marker,text);adb.write_text(text.replace(marker,injected+marker,1))
            exec(section,scope)
            self.assertIsNone(scope['observed']['reads'][0]['global'])
            self.assertEqual([],list(original.iterdir()))
            self.assertEqual(base64.b64decode(scope['diagnostic']['probeArtifact']['dexBase64']),(parent/'classes.dex').read_bytes())
            self.assertEqual(before,old._generation(victim.stat()));self.assertEqual(b'FOREIGN_DATA',victim.read_bytes())
            self.assertEqual('not-proven',scope['service_capture']['stageAuthority']['preCdMkdirInodeContinuity'])
        finally:temp.cleanup()
