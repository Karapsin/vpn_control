"""Causal boundaries for the fixed Android package installation workflow."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock
from types import SimpleNamespace

from agent_tools import android_package_install as installer
from agent_tools import android_installer_dispatch as shared_dispatch


class AndroidPackageInstallTest(unittest.TestCase):
    def test_apksigner_single_signer_output_without_count_is_admitted(self):
        badging = ("package: name='com.kardinal.vpncontrol' versionCode='16800' versionName='2.2.0'\n"
                   "native-code: 'x86_64'\n")
        signature = ("Signer #1 certificate DN: C=US, O=Android, CN=Android Debug\n"
                     "Signer #1 certificate SHA-256 digest: " + "a" * 64 + "\n")
        with mock.patch.object(installer, "_build_tools", return_value=(Path("/aapt"), Path("/apksigner"))), \
             mock.patch.object(installer.subprocess, "run", side_effect=[
                 SimpleNamespace(stdout=badging.encode()), SimpleNamespace(stdout=signature.encode())]):
            actual = installer._inspect_apk(".", Path("/fixture.apk"))
        self.assertEqual("a" * 64, actual["signerSha256"])
        second_signer = signature + "Signer #2 certificate SHA-256 digest: " + "b" * 64 + "\n"
        with mock.patch.object(installer, "_build_tools", return_value=(Path("/aapt"), Path("/apksigner"))), \
             mock.patch.object(installer.subprocess, "run", side_effect=[
                 SimpleNamespace(stdout=badging.encode()), SimpleNamespace(stdout=second_signer.encode())]):
            with self.assertRaises(ValueError):
                installer._inspect_apk(".", Path("/fixture.apk"))

    def test_version_name_and_code_must_form_monotonic_base20_identity(self):
        self.assertEqual((2,2,0),installer._version_identity({"version":"2.2.0","code":16800}))
        self.assertLess(installer._version_identity({"version":"2.1.18","code":16760}),
                        installer._version_identity({"version":"2.2.0","code":16800}))
        for version,code in (("2.1.18",16800),("2.20.0",17600),("02.2.0",16800),
                             ("2.2.0",16760),("2.2",16800),("0.2.0",800)):
            with self.assertRaises(ValueError): installer._version_identity({"version":version,"code":code})

    def test_terminal_status_rechecks_private_post_routing_and_collect_binds_intent(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); root.chmod(0o700)
            corr="9304d8aa-578d-4df1-9eaa-81021744cd43"
            backup_corr="45a4066c-265a-40ea-8a44-731f0c44ad4e"
            old_dir=root/("android-readback-"+backup_corr); old_dir.mkdir(mode=0o700)
            old_file=old_dir/"routing.json"; old_file.write_bytes(b"opening"); old_file.chmod(0o600)
            backup_sha=hashlib.sha256(b"opening").hexdigest()
            job=root/("android-install-job-"+corr); job.mkdir(mode=0o700)
            post_file=job/"postinstall-routing.json"; post_file.write_bytes(b"closing"); post_file.chmod(0o600)
            post_sha=hashlib.sha256(b"closing").hexdigest()
            intent={"host":"archlinux","device":"api35","correlationId":corr,"fixtureRoot":str(root),
                "backupCorrelationId":backup_corr,"backupSha256":backup_sha,"targetSha256":"a"*64,
                "oldBaseSha256":"b"*64,"oldOwner":"old-owner","oldRevision":4,"expectedAvd":"owned-api35",
                "api":35,"package":{"version":"2.2.0","code":16800}}
            result={"state":"complete","package":{"baseSha256":"a"*64,"version":"2.2.0","code":16800,"debuggable":False},
                "owner":{"controllerId":"new-owner","configurationRevision":4,"runtimeObservation":"stopped","terminalHistory":True},
                "device":{"uid":"2000","api":35,"avd":"owned-api35"},
                "before":{"baseSha256":"b"*64,"controllerId":"old-owner","configurationRevision":4},
                "backupSha256":backup_sha,"postInstallRouting":"verified","mutationAllowed":False,
                "postRouting":{"path":str(post_file),"sha256":post_sha,"size":7,"matchesOpeningRules":True}}
            installer._save(root,intent)
            for name,value in (("intent.json",intent),("identity.json",{"pid":1234,"startTicks":5678}),
                               ("result.json",{"state":"complete","result":result,"reason":None})):
                path=job/name; path.write_text(json.dumps(value)); path.chmod(0o600)
            command=[sys.executable,"-c","exec("+repr(installer._STATUS)+")",str(root),corr,
                     json.dumps(intent,sort_keys=True,separators=(",",":"))]
            observed=subprocess.run(command,capture_output=True,text=True,timeout=5)
            self.assertEqual(0,observed.returncode,observed.stderr)
            value=json.loads(observed.stdout)
            self.assertEqual("complete",value["state"],value)
            with mock.patch.object(installer,"status",return_value=value):
                collected=installer.collect(root,corr)
            self.assertTrue(collected["ok"],collected)
            self.assertFalse(collected["admissionReady"])
            post_file.write_bytes(b"tampered")
            altered=subprocess.run(command,capture_output=True,text=True,timeout=5)
            self.assertEqual("unknown",json.loads(altered.stdout)["state"])

    def test_start_journals_once_before_submission_and_duplicate_cannot_replay(self):
        correlation="9304d8aa-578d-4df1-9eaa-81021744cd43"
        backup_correlation="45a4066c-265a-40ea-8a44-731f0c44ad4e"
        profile={"adb":"/remote/adb","cli":"/remote/cli","serial":"emulator-5554","expectedAvd":"owned-api35","api":35}
        configured=SimpleNamespace(android_devices={"api35":profile},fixture_transfer_root=Path("/private/fixtures"))
        config=SimpleNamespace(hosts={"archlinux":configured})
        target="a"*64; old="b"*64; backup_hash="c"*64
        target_artifact={"verification":"verified","artifact":{"platform":"android","artifactKind":"native-fixture-apk",
            "sha256":target,"size":100,"sourceSha":"source-sha"},"location":{"localPath":"/tmp/target.apk"}}
        old_artifact={"verification":"verified","artifact":{"platform":"android","artifactKind":"apk",
            "sha256":old,"size":90,"sourceSha":"old-source"},"location":{"localPath":"/tmp/old.apk"}}
        stage={"scenarioId":"android-apk-stage","owner":"android-parity","environment":"api35",
               "correlationId":"3a328d13-28a6-442b-bcc0-266ca20368f5","sourceManifestSha256":"d"*64}
        backup={"ok":True,"result":{"stage":"backup_present","deviceIdentity":True,
            "controllerId":"old-owner","configurationRevision":4,"backup":{"sha256":backup_hash,"formatValid":True}}}
        opening={"ok":True,"result":{"package":{"baseSha256":old},"guard":{"controllerId":"old-owner",
            "configurationRevision":4},"backup":{"sha256":backup_hash}}}
        class GitResult: stdout="source-sha\n"
        with tempfile.TemporaryDirectory() as raw, \
             mock.patch.object(installer.ssh_transport,"load_config",return_value=config), \
             mock.patch.object(installer.ssh_transport,"connection_host",return_value=SimpleNamespace(password=None)), \
             mock.patch.object(installer.native_artifact_registry,"verify_artifact",side_effect=lambda _root,aid: target_artifact if aid=="sha256-"+target else old_artifact), \
             mock.patch.object(installer,"_inspect_apk",side_effect=lambda _root,path: {"package":"com.kardinal.vpncontrol",
                 "code":16800,"version":"2.2.0",
                 "abi":"x86_64","signerSha256":"e"*64,"debuggable":False}), \
             mock.patch.object(installer.ssh_transfer,"android_apk_stage_status",return_value={"state":"published","destinationHashes":{"app-nativeFixture.apk":target},"destinationSizes":{"app-nativeFixture.apk":100}}), \
             mock.patch.object(installer.android_admission_readback,"readback_status",return_value=backup), \
             mock.patch.object(installer.android_admission_readback,"async_collect",return_value=opening), \
             mock.patch.object(installer.subprocess,"run",return_value=GitResult()), \
             mock.patch.object(installer.ssh_transport,"build_ssh_argv",return_value=["ssh"]), \
             mock.patch.object(shared_dispatch,"remote_shared_lease",return_value={"state":"claimed"}), \
             mock.patch.object(installer.android_observation,"_run_probe",return_value=(0,json.dumps({"state":"submitted","correlationId":correlation,"identity":{"pid":1,"startTicks":2}}).encode())) as remote:
            first=installer.start(raw,"archlinux","api35",correlation,"sha256-"+target,stage,
                                  backup_correlation,backup_hash,old,"old-owner",4)
            self.assertEqual("submitted",first["state"])
            self.assertIsNotNone(installer._load(raw,correlation))
            with self.assertRaises(FileExistsError):
                installer.start(raw,"archlinux","api35",correlation,"sha256-"+target,stage,
                                backup_correlation,backup_hash,old,"old-owner",4)
            with self.assertRaises(FileExistsError):
                installer.start(raw,"archlinux","api35","5875f940-7529-4b1c-8118-b9532b096abf",
                                "sha256-"+target,stage,backup_correlation,backup_hash,old,"old-owner",4)
            remote.assert_called_once()

    def test_start_rejects_unrelated_verified_artifact_kind_before_apk_inspection(self):
        configured=SimpleNamespace(android_devices={"api29":{}},fixture_transfer_root=Path("/private/fixtures"))
        config=SimpleNamespace(hosts={"archlinux":configured})
        foreign={"verification":"verified","artifact":{"platform":"android","artifactKind":"desktop-package"}}
        with mock.patch.object(installer.ssh_transport,"load_config",return_value=config), \
             mock.patch.object(installer.ssh_transport,"connection_host",return_value=SimpleNamespace(password=None)), \
             mock.patch.object(installer.android_observation,"_profile",return_value={"expectedAvd":"owned-api29","api":29}), \
             mock.patch.object(installer.native_artifact_registry,"verify_artifact",return_value=foreign), \
             mock.patch.object(installer,"_inspect_apk") as inspect:
            with self.assertRaisesRegex(ValueError,"not verified"):
                installer.start(".","archlinux","api29","6e348905-10c0-4e79-9b06-3453893507b8",
                    "sha256-"+"a"*64,{},"df6e6c61-66d0-4bd6-a15a-dc5a2a016090","b"*64,"c"*64,"owner",0)
            inspect.assert_not_called()

    def test_start_reaches_apk_inspection_for_canonical_kind(self):
        config=SimpleNamespace(hosts={"archlinux":SimpleNamespace(android_devices={"api29":{}},fixture_transfer_root=Path("/fixture"))})
        artifact={"verification":"verified","artifact":{"platform":"android","artifactKind":"apk","sourceSha":"source",
            "sha256":"a"*64},"location":{"localPath":"/target.apk"}}
        with mock.patch.object(installer.ssh_transport,"load_config",return_value=config), \
             mock.patch.object(installer.ssh_transport,"connection_host",return_value=SimpleNamespace(password=None)), \
             mock.patch.object(installer.android_observation,"_profile",return_value={"expectedAvd":"owned-api29","api":29}), \
             mock.patch.object(installer.native_artifact_registry,"verify_artifact",return_value=artifact), \
             mock.patch.object(installer.subprocess,"run",return_value=SimpleNamespace(stdout="source\n")), \
             mock.patch.object(installer,"_inspect_apk",side_effect=RuntimeError("apk inspected")) as inspect:
            with self.assertRaisesRegex(RuntimeError,"apk inspected"):
                installer.start(".","archlinux","api29","6e348905-10c0-4e79-9b06-3453893507b8",
                    "sha256-"+"a"*64,{},"df6e6c61-66d0-4bd6-a15a-dc5a2a016090","b"*64,"c"*64,"owner",0)
            inspect.assert_called_once()

    def test_start_rejects_downgrade_and_same_bytes_before_stage(self):
        config=SimpleNamespace(hosts={"archlinux":SimpleNamespace(android_devices={"api29":{}},fixture_transfer_root=Path("/fixture"))})
        for target_hash,target_version,target_code,old_hash in (("a"*64,"2.1.18",16760,"b"*64),
                                                                  ("a"*64,"2.2.0",16800,"a"*64)):
            with self.subTest(target_version=target_version,old_hash=old_hash):
                artifact={"verification":"verified","artifact":{"platform":"android","artifactKind":"native-fixture-apk",
                    "sourceSha":"source","sha256":target_hash},"location":{"localPath":"/target.apk"}}
                previous={"verification":"verified","artifact":{"platform":"android","artifactKind":"apk",
                    "sha256":old_hash},"location":{"localPath":"/old.apk"}}
                def inspect(_root,path):
                    current=str(path)=="/target.apk"
                    return {"version":target_version if current else "2.2.0","code":target_code if current else 16800,
                            "signerSha256":"e"*64}
                with mock.patch.object(installer.ssh_transport,"load_config",return_value=config), \
                     mock.patch.object(installer.ssh_transport,"connection_host",return_value=SimpleNamespace(password=None)), \
                     mock.patch.object(installer.android_observation,"_profile",return_value={"expectedAvd":"owned-api29","api":29}), \
                     mock.patch.object(installer.native_artifact_registry,"verify_artifact",side_effect=[artifact,previous]), \
                     mock.patch.object(installer.subprocess,"run",return_value=SimpleNamespace(stdout="source\n")), \
                     mock.patch.object(installer,"_inspect_apk",side_effect=inspect), \
                     mock.patch.object(installer.ssh_transfer,"android_apk_stage_status") as stage:
                    with self.assertRaisesRegex(ValueError,"not compatible"):
                        installer.start(".","archlinux","api29","6e348905-10c0-4e79-9b06-3453893507b8",
                            "sha256-"+target_hash,{},"df6e6c61-66d0-4bd6-a15a-dc5a2a016090","b"*64,old_hash,"owner",0)
                    stage.assert_not_called()

    def test_collect_rejects_missing_or_unbound_terminal_fields(self):
        correlation = "9304d8aa-578d-4df1-9eaa-81021744cd43"
        bad = {"state":"complete","receipt":{"result":{"state":"complete","package":{"baseSha256":"a"*64}}}}
        with mock.patch.object(installer,"status",return_value=bad):
            self.assertFalse(installer.collect(".",correlation)["ok"])

    def test_terminal_lease_reconciliation_requires_current_admission_and_exact_owner(self):
        old="17ccbfc7-e8dc-4c2a-aa07-ad47bdc390a0"
        readback="7e65c7cb-7a4f-4952-9655-c321c6335d86"
        target="a"*64; owner="new-owner"
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); root.chmod(0o700)
            installer._save(root,{"host":"archlinux","device":"api29","correlationId":old,
                                  "targetSha256":target,"expectedAvd":"owned-api29","api":29})
            installer._claim_device(root,"archlinux","api29",old)
            shared_dispatch._claim_local(root,"archlinux","api29",old,"android-package-install")
            lease=installer._device_lease(root,"archlinux","api29")
            terminal={"ok":True,"state":"complete","result":{"package":{"baseSha256":target},
                       "owner":{"controllerId":"historical-owner"}}}
            observed={"ok":True,"result":{"stage":"backup_present","deviceIdentity":True,
                       "controllerId":owner,"configurationRevision":0,"backup":{"sha256":"b"*64,"formatValid":True}}}
            current={"ok":True,"state":"complete","result":{"package":{"baseSha256":target},
                     "guard":{"controllerId":owner,"configurationRevision":0},
                     "backup":{"sha256":"b"*64},"device":{"uid":"2000","avd":"owned-api29","api":29}}}
            public={"ok":True,"outcome":"admitted","result":{"runtime":{"running":False,"observation":"stopped"},
                    "operationCount":0,"packageSha256":target,"controllerId":owner,"configurationRevision":0}}
            with mock.patch.object(installer,"collect",return_value={"ok":False,"state":"unknown"}), \
                 mock.patch.object(installer.android_admission_readback,"readback_status") as readback_probe:
                rejected=installer.reconcile_terminal_lease(root,old,readback,owner,0)
            self.assertEqual("install_not_terminal",rejected["reason"])
            self.assertTrue(lease.exists())
            readback_probe.assert_not_called()
            with mock.patch.object(shared_dispatch,"remote_shared_lease",return_value={"state":"released"}), \
                 mock.patch.object(installer,"collect",return_value=terminal), \
                 mock.patch.object(installer.android_admission_readback,"readback_status",return_value=observed), \
                 mock.patch.object(installer.android_admission_readback,"async_collect",return_value=current), \
                 mock.patch.object(installer.android_public_inspect,"inspect",return_value={"ok":False,"outcome":"unknown"}):
                rejected=installer.reconcile_terminal_lease(root,old,readback,owner,0)
            self.assertFalse(rejected["ok"])
            self.assertTrue(lease.exists())
            changed=json.loads(json.dumps(current)); changed["result"]["guard"]["controllerId"]="other-owner"
            with mock.patch.object(installer,"collect",return_value=terminal), \
                 mock.patch.object(installer.android_admission_readback,"readback_status",return_value=observed), \
                 mock.patch.object(installer.android_admission_readback,"async_collect",return_value=changed), \
                 mock.patch.object(installer.android_public_inspect,"inspect") as public_probe:
                rejected=installer.reconcile_terminal_lease(root,old,readback,owner,0)
            self.assertEqual("current_readback_changed",rejected["reason"])
            self.assertTrue(lease.exists())
            public_probe.assert_not_called()
            with mock.patch.object(shared_dispatch,"remote_shared_lease",return_value={"state":"released"}), \
                 mock.patch.object(installer,"collect",return_value=terminal), \
                 mock.patch.object(installer.android_admission_readback,"readback_status",return_value=observed), \
                 mock.patch.object(installer.android_admission_readback,"async_collect",return_value=current), \
                 mock.patch.object(installer.android_public_inspect,"inspect",return_value=public):
                accepted=installer.reconcile_terminal_lease(root,old,readback,owner,0)
            self.assertTrue(accepted["ok"],accepted)
            self.assertFalse(lease.exists())
            self.assertTrue(installer._journal(root,old).exists())
            installer._claim_device(root,"archlinux","api29","different-correlation")
            self.assertFalse(installer._release_device(root,"archlinux","api29",old))
            self.assertTrue(lease.exists())

    def test_terminal_release_serializes_with_new_device_claim(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); root.chmod(0o700)
            old="17ccbfc7-e8dc-4c2a-aa07-ad47bdc390a0"
            new="ca4582eb-f8e1-48a9-8d59-2b6298221408"
            installer._claim_device(root,"archlinux","api29",old)
            lease=installer._device_lease(root,"archlinux","api29")
            release_entered=threading.Event(); resume_release=threading.Event(); claim_done=threading.Event()
            outcomes={}; original_unlink=Path.unlink
            def held_unlink(path,*args,**kwargs):
                if path==lease and not release_entered.is_set():
                    release_entered.set()
                    if not resume_release.wait(3): raise TimeoutError("release test timed out")
                return original_unlink(path,*args,**kwargs)
            def release(): outcomes["release"]=installer._release_device(root,"archlinux","api29",old)
            def claim():
                try: installer._claim_device(root,"archlinux","api29",new); outcomes["claim"]="claimed"
                except Exception as error: outcomes["claim"]=type(error).__name__
                finally: claim_done.set()
            with mock.patch.object(Path,"unlink",held_unlink):
                releasing=threading.Thread(target=release); claiming=threading.Thread(target=claim)
                releasing.start()
                try:
                    self.assertTrue(release_entered.wait(2))
                    claiming.start()
                    self.assertFalse(claim_done.wait(.3),"new claim must wait for terminal release")
                finally:
                    resume_release.set()
                    releasing.join(3)
                    if claiming.ident is not None: claiming.join(3)
            self.assertEqual(True,outcomes.get("release"))
            self.assertEqual("claimed",outcomes.get("claim"))
            self.assertEqual(new,json.loads(lease.read_text())["correlationId"])

    def test_worker_adapter_recognizes_install_complete_only(self):
        worker = installer._worker_source("print(1)",[])
        self.assertIn('value.get("state")=="complete"',worker)
        self.assertNotIn('value.get("admitted")',worker)

    @unittest.skipUnless(os.name == "posix", "fake executable probe needs POSIX")
    def test_remote_install_requires_stopped_owner_private_backup_and_exact_package(self):
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw); root.chmod(0o700)
            adb=root/"adb"; cli=root/"control.py"; stage_dir=root/"stage"; stage_dir.mkdir(mode=0o700)
            backup_dir=root/"backup"; backup_dir.mkdir(mode=0o700)
            stage=stage_dir/"app-nativeFixture.apk"; stage.write_bytes(b"target package"); stage.chmod(0o600)
            routing=b'{"type":"vpn_control_routing_rules","version":7,"rules":{"ignore_rules":false,"block_quic_udp_443":false,"proxy_packages":[],"direct_domain_suffixes":[]}}'
            backup=backup_dir/"routing.json"; backup.write_bytes(routing); backup.chmod(0o600)
            old="a"*64; target=hashlib.sha256(stage.read_bytes()).hexdigest(); backup_hash=hashlib.sha256(backup.read_bytes()).hexdigest()
            marker=root/"install-called"
            correlation="9304d8aa-578d-4df1-9eaa-81021744cd43"
            (root/("android-install-job-"+correlation)).mkdir(mode=0o700)
            shared=root/"android-native-device-api35.lease"
            shared.write_text(json.dumps({"owner":"android-package-install","host":"archlinux",
                "device":"api35","correlationId":correlation})+"\n"); shared.chmod(0o600)
            adb.write_text('''#!/usr/bin/env python3
import os,sys
from pathlib import Path
a=sys.argv[1:]; tail=a[3:] if a[:3]==['-s','emulator-5554','shell'] else []
if tail[:1]==['-T']: tail=tail[1:]
if tail==['id','-u']: print(os.environ.get('INSTALL_UID','2000'))
elif tail==['getprop','ro.build.version.sdk']: print('35')
elif tail==['getprop','ro.kernel.qemu.avd_name']: print('owned-api35')
elif tail==['getprop','ro.boot.qemu.avd_name']: print('owned-api35')
elif tail==['getprop','ro.product.cpu.abi']: print('x86_64')
elif tail==['pm','path','com.kardinal.vpncontrol']: print('package:/data/app/test/base.apk')
elif tail==['sha256sum','/data/app/test/base.apk']: print((os.environ['TARGET_HASH'] if Path(os.environ['INSTALL_MARKER']).exists() else 'a'*64)+'  /data/app/test/base.apk')
elif tail==['dumpsys','package','com.kardinal.vpncontrol']: print(' versionName=2.2.0 versionCode=16800 ')
elif a[:3]==['-s','emulator-5554','install']:
 Path(os.environ['INSTALL_MARKER']).write_text('called')
 print('Performing Streamed Install\\nSuccess')
else: sys.exit(3)
''')
            cli.write_text('''#!/usr/bin/env python3
import json,os,sys
a=sys.argv[1:]
if a[-1]=='status': data={'runtimeRunning':os.environ.get('INSTALL_RUNNING')=='1','runtimeObservation':'stopped'}
elif a[-2:]==['operations','list']: data={'operations':[]}
elif 'export' in a:
 from pathlib import Path
 target=Path(a[a.index('--output')+1]); content=Path(os.environ['INSTALL_BACKUP']).read_bytes()
 if os.environ.get('INSTALL_EXPORT_TAMPER')=='1': content=content.replace(b'"ignore_rules":false',b'"ignore_rules":true')
 target.write_bytes(content); target.chmod(0o600)
 print(json.dumps({'ok':True,'final':True,'code':'OK','controllerId':'new-owner','configurationRevision':4,
  'data':{'format':'json','bytes':target.stat().st_size}})); sys.exit(0)
else: sys.exit(3)
print(json.dumps({'ok':True,'final':True,'code':'OK','controllerId':('new-owner' if __import__('pathlib').Path(os.environ['INSTALL_MARKER']).exists() else os.environ.get('INSTALL_OWNER','old-owner')),
 'configurationRevision':4,'data':data}))
''')
            adb.chmod(0o700); cli.chmod(0o700)
            args=[str(adb),str(cli),"emulator-5554","owned-api35","35",str(root),correlation,str(stage),target,
                  old,target,"old-owner","4",str(backup),backup_hash,"16800","2.2.0","archlinux","api35"]
            command=[sys.executable,"-c","exec("+repr(installer._remote_source())+")",*args]
            env={**os.environ,"TARGET_HASH":target,"INSTALL_MARKER":str(marker),"INSTALL_BACKUP":str(backup)}
            shared.write_text(json.dumps({"owner":"android-endpoint","host":"archlinux",
                "device":"api35","correlationId":correlation})+"\n")
            foreign=subprocess.run(command,capture_output=True,text=True,env=env,timeout=10)
            self.assertEqual("shared_device_lease_changed",json.loads(foreign.stdout)["reason"])
            self.assertFalse(marker.exists())
            shared.write_text(json.dumps({"owner":"android-package-install","host":"archlinux",
                "device":"api35","correlationId":correlation})+"\n")
            running=subprocess.run(command,capture_output=True,text=True,env={**env,"INSTALL_RUNNING":"1"},timeout=10)
            self.assertEqual(0,running.returncode,running.stderr)
            self.assertEqual("preinstall_owner_or_runtime_changed",json.loads(running.stdout)["reason"])
            self.assertFalse(marker.exists())
            wrong_owner=subprocess.run(command,capture_output=True,text=True,env={**env,"INSTALL_OWNER":"replacement"},timeout=10)
            self.assertEqual("preinstall_owner_or_runtime_changed",json.loads(wrong_owner.stdout)["reason"])
            self.assertFalse(marker.exists())
            backup.write_bytes(b"changed"); backup.chmod(0o600)
            changed=subprocess.run(command,capture_output=True,text=True,env=env,timeout=10)
            self.assertEqual("input_hash_changed",json.loads(changed.stdout)["reason"])
            self.assertFalse(marker.exists())
            backup.write_bytes(routing); backup.chmod(0o600)
            real_stage=root/"real-stage"; stage_dir.rename(real_stage); stage_dir.symlink_to(real_stage)
            symlinked=subprocess.run(command,capture_output=True,text=True,env=env,timeout=10)
            self.assertEqual("private_input_ancestor_invalid",json.loads(symlinked.stdout)["reason"])
            self.assertFalse(marker.exists())
            stage_dir.unlink(); real_stage.rename(stage_dir)
            accepted=subprocess.run(command,capture_output=True,text=True,env=env,timeout=10)
            self.assertEqual(0,accepted.returncode,accepted.stderr)
            self.assertEqual("complete",json.loads(accepted.stdout)["state"],accepted.stdout)
            self.assertEqual("verified",json.loads(accepted.stdout)["postInstallRouting"])
            self.assertTrue(marker.exists())
            marker.unlink()
            changed_correlation="a2c8cd03-4324-45dd-ae91-28421bfd05d6"
            (root/("android-install-job-"+changed_correlation)).mkdir(mode=0o700)
            changed_args=args.copy(); changed_args[6]=changed_correlation
            shared.write_text(json.dumps({"owner":"android-package-install","host":"archlinux",
                "device":"api35","correlationId":changed_correlation})+"\n")
            changed_command=[sys.executable,"-c","exec("+repr(installer._remote_source())+")",*changed_args]
            altered=subprocess.run(changed_command,capture_output=True,text=True,
                                   env={**env,"INSTALL_EXPORT_TAMPER":"1"},timeout=10)
            self.assertEqual("postinstall_routing_changed",json.loads(altered.stdout)["reason"])


if __name__ == "__main__": unittest.main()
