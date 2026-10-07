"""Causal failed-check retirement admission and durable fencing checks."""
import copy
import base64
import json
import os
import hashlib
import socket
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agent_tools import android_installer_failed_check_retirement as retirement


CORR = "0dd55704-1e80-4d62-8d9d-2f0a123e0c3b"
NEW = "ee259350-d109-4d03-bb31-3c9fe1bdb545"


# Exact consumed unsafe function snapshot; provenance helper SHA2fd652ef.
# It exists only for realFD causal RED/GREEN, never operational dispatch.
OLD_COMPONENT_RELEASE_FUNCTION_SHA256='8f7aec1a14ed1a37cd07d5e3272fdac67740131850d5fff9bbe0684be503c7a4'
OLD_COMPONENT_RELEASE_FUNCTION='def release_component_fenced(lease: Path, expected_pin: dict[str, Any],\n                             admitted_proof: dict[str, Any], release_correlation_id: str,\n                             current_proof, role: str,\n                             remote_result: dict[str, Any] | None = None) -> dict[str, Any]:\n    """Separate component release, invoked only by the sealed direct adapter.\n\n    The adapter continuously holds the original device lock, authenticates the\n    persisted original admission and supplies complete freshly measured proofs\n    before every effect. No MCP input supplies paths, callbacks or assertions.\n    Root measures the ordinary-user remote lease without adopting its owner.\n    Local release follows an independently authenticated successful remote\n    response. Any exception after the global fence consumes this operation.\n    """\n    old=validate_component_retained_proof(admitted_proof)\n    original=old[\'originalCorrelationId\'];digest=hashlib.sha256(_canonical(old)).hexdigest()\n    if type(release_correlation_id) is not str or not _UUID.fullmatch(release_correlation_id) or str(uuid.UUID(release_correlation_id))!=release_correlation_id or release_correlation_id in (original,old[\'retirementCorrelationId\']):\n        raise ValueError(\'component_release_correlation_invalid\')\n    if role not in (\'remote-original\',\'local-original\'):\n        raise ValueError(\'component_release_role_invalid\')\n    remote=role==\'remote-original\';uid=1000 if remote else old[\'principals\'][\'localLeaseUid\']\n    actor=0 if remote else uid\n    actor_gid=0 if remote else os.getgid();lease_gid=1000 if remote else actor_gid\n    if os.getuid()!=actor or os.getgid()!=actor_gid:\n        raise ValueError(\'component_release_actor_invalid\')\n    lease=Path(lease).absolute()\n    if lease.name!=(\'android-native-device-api35.lease\' if remote else \'lease-archlinux-api35.json\'):\n        raise ValueError(\'component_release_path_invalid\')\n    release_name=(\'android-native-device-api35-\'+original+\'.release-intent\') if remote else \'release-\'+original+\'.json\'\n    fence_name=(\'android-native-device-api35-\'+original+\'.component-retirement-fence\') if remote else \'component-retirement-\'+original+\'.json\'\n    expected={\'owner\':\'android-installer\',\'host\':\'archlinux\',\'device\':\'api35\',\'correlationId\':original}\n    if not remote:\n        required={\'schema\':1,\'kind\':\'android-installer-component-remote-lease-released\',\n            \'originalCorrelationId\':original,\'admissionCorrelationId\':old[\'retirementCorrelationId\'],\n            \'releaseCorrelationId\':release_correlation_id,\'admittedProofSha256\':digest,\n            \'originalOutcome\':\'unknown\',\'leaseReleased\':True,\'replayAllowed\':False}\n        if type(remote_result) is not dict or _canonical(remote_result)!=_canonical(required):\n            raise ValueError(\'component_remote_release_unproven\')\n    elif remote_result is not None:\n        raise ValueError(\'component_release_role_invalid\')\n    if type(expected_pin) is not dict or set(expected_pin)!={\'generation\',\'sha256\',\'parents\'}:\n        raise ValueError(\'component_release_pin_invalid\')\n    generation=expected_pin[\'generation\'];parents=expected_pin[\'parents\']\n    if type(generation) is not list or len(generation)!=9 or any(type(v) is not int or v<0 for v in generation) or generation[2:6]!=[0o100600,uid,lease_gid,1] or generation[6]!=121 or min(generation[:2]+generation[7:])<1 or expected_pin[\'sha256\']!=\'44f2b1d325cbd0dedda6d6af5b1bf856792edf327accad99475e8cde6e4e865a\':\n        raise ValueError(\'component_release_pin_invalid\')\n    if type(parents) is not list or not parents or any(type(row) is not list or len(row)!=5 or any(type(v) is not int or v<0 for v in row) for row in parents):\n        raise ValueError(\'component_release_parent_invalid\')\n    old_pin=old[\'files\'][\'remote-lease.json\' if remote else \'local-lease.json\']\n    projected=generation if old_pin[\'format\']==\'descriptor9\' else [generation[0],generation[1],generation[6],generation[7],generation[8],stat.S_IMODE(generation[2]),generation[3],generation[5]]\n    if old_pin[\'generation\']!=projected or old_pin[\'sha256\']!=expected_pin[\'sha256\']:\n        raise ValueError(\'component_release_original_lease_changed\')\n    def fp(info):\n        return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]\n    def ancestry():\n        fd=os.open(\'/\',os.O_RDONLY|os.O_DIRECTORY);rows=[]\n        try:\n            for part in lease.parent.parts[1:]:\n                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)\n                os.close(fd);fd=child;info=os.fstat(fd)\n                rows.append([info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid])\n            if rows!=parents or rows[-1][2:]!=[0o40700,uid,lease_gid]:\n                raise ValueError(\'component_release_parent_changed\')\n            return fd\n        except BaseException:os.close(fd);raise\n    parent=ancestry()\n    try:\n        parent_pin=fp(os.fstat(parent));names=sorted(os.listdir(parent));created={};link_step=None\n        def guard_parent():\n            other=ancestry()\n            try:\n                if fp(os.fstat(other))!=parent_pin or fp(os.fstat(parent))!=parent_pin or sorted(os.listdir(parent))!=names:\n                    raise ValueError(\'component_release_parent_changed\')\n            finally:os.close(other)\n        def read_lease():\n            guard_parent()\n            fd=os.open(lease.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)\n            with os.fdopen(fd,\'rb\') as stream:\n                before=fp(os.fstat(stream.fileno()));raw=stream.read(1025);after=fp(os.fstat(stream.fileno()))\n            if before!=generation or after!=generation or fp(os.stat(lease.name,dir_fd=parent,follow_symlinks=False))!=generation or len(raw)!=121 or hashlib.sha256(raw).hexdigest()!=expected_pin[\'sha256\'] or _canonical(json.loads(raw))!=_canonical(expected):\n                raise ValueError(\'component_release_lease_changed\')\n            guard_records();guard_parent()\n        def guard_records():\n            for name,(payload,pin) in created.items():\n                fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)\n                with os.fdopen(fd,\'rb\') as stream:\n                    first=fp(os.fstat(stream.fileno()));data=stream.read(len(payload)+1);last=fp(os.fstat(stream.fileno()))\n                if first!=pin or last!=pin or fp(os.stat(name,dir_fd=parent,follow_symlinks=False))!=pin or data!=payload:\n                    raise ValueError(\'component_release_created_record_changed\')\n        def fresh():\n            read_lease()\n            measured=validate_component_retained_proof(current_proof())\n            for key in (\'originalCorrelationId\',\'retirementCorrelationId\',\'sourceSha\',\'toolBundleId\',\'intentSha256\',\'lifecycleSha256\',\'phaseCheckSha256\',\'opening\'):\n                if _canonical(measured[key])!=_canonical(old[key]):\n                    raise ValueError(\'component_release_fresh_binding_changed\')\n            for key in (\'packageSha256\',\'routingSha256\',\'settingsSha256\',\'terminalHistorySha256\',\'latestPublicReceipt\'):\n                if _canonical(measured[\'snapshots\'][0][key])!=_canonical(old[\'snapshots\'][0][key]):\n                    raise ValueError(\'component_release_fresh_baseline_changed\')\n            if measured[\'principals\']!=old[\'principals\'] or measured[\'files\'][\'remote-lease.json\']!=old[\'files\'][\'remote-lease.json\'] or measured[\'files\'][\'local-lease.json\']!=old[\'files\'][\'local-lease.json\']:\n                raise ValueError(\'component_release_fresh_lease_changed\')\n            read_lease()\n        def create(name,value):\n            nonlocal parent_pin,names,link_step\n            guard_parent();payload=_canonical(value)\n            _create(parent,name,value)\n            current_names=sorted(os.listdir(parent));now=fp(os.fstat(parent))\n            # Linux directories retain nlink for a file create; APFS counts the\n            # new child. Admit only the measured sole controlled entry change,\n            # then require that same progression for the second create/unlink.\n            delta=now[5]-parent_pin[5]\n            if link_step is None:link_step=delta\n            if current_names!=sorted(names+[name]) or now[:5]!=parent_pin[:5] or delta not in ((0,) if remote else (0,1)) or delta!=link_step:\n                raise ValueError(\'component_release_parent_changed\')\n            pin=fp(os.stat(name,dir_fd=parent,follow_symlinks=False))\n            if pin[2:6]!=[0o100600,actor,actor_gid,1] or pin[6]!=len(payload):\n                raise ValueError(\'component_release_created_record_changed\')\n            names=current_names;parent_pin=now;created[name]=(payload,pin)\n            read_lease()\n        fresh()\n        if any(name in names for name in (release_name,fence_name)):\n            raise ValueError(\'component_release_already_fenced\')\n        create(fence_name,{\'schema\':1,\'kind\':\'android-installer-component-retained-terminal-release-intent\',\n            \'role\':role,\'originalCorrelationId\':original,\'admissionCorrelationId\':old[\'retirementCorrelationId\'],\n            \'releaseCorrelationId\':release_correlation_id,\'admittedProofSha256\':digest,\n            \'leaseGeneration\':generation,\'leaseSha256\':expected_pin[\'sha256\'],\n            \'originalOutcome\':\'unknown\',\'replayAllowed\':False})\n        fresh();create(release_name,expected);fresh()\n        os.unlink(lease.name,dir_fd=parent);os.fsync(parent)\n        closing_pin=fp(os.fstat(parent))\n        if sorted(os.listdir(parent))!=sorted(name for name in names if name!=lease.name) or closing_pin[:5]!=parent_pin[:5] or closing_pin[5]!=parent_pin[5]-link_step:\n            raise ValueError(\'component_release_closing_parent_changed\')\n        guard_records();other=ancestry()\n        try:\n            if fp(os.fstat(other))!=closing_pin or fp(os.fstat(parent))!=closing_pin:\n                raise ValueError(\'component_release_closing_parent_changed\')\n        finally:os.close(other)\n        return {\'schema\':1,\'kind\':\'android-installer-component-\'+(\'remote\' if remote else \'local\')+\'-lease-released\',\n            \'originalCorrelationId\':original,\'admissionCorrelationId\':old[\'retirementCorrelationId\'],\n            \'releaseCorrelationId\':release_correlation_id,\'admittedProofSha256\':digest,\n            \'originalOutcome\':\'unknown\',\'leaseReleased\':True,\'replayAllowed\':False}\n    finally:os.close(parent)'


class ComponentTerminalHistoryTest(unittest.TestCase):
    """Source-shaped receipt producer, exact raw/full generations, no native IO."""
    def history(self):
        rows=[];entries=[]
        for index, phase in enumerate(('CANCELLED','INSTALLED','CANCELLED')):
            receipt={'id':f'00000000-0000-4000-8000-{index+1:012d}',
                'nonce':f'10000000-0000-4000-8000-{index+1:012d}', 'sessionId':index+1,
                'version':'2.2.2','build':16840,'sha256':'a'*64,'byteCount':45026948,
                'phase':phase,'createdAt':index+1,'confirmation':None,'signers':['b'*64]}
            raw=retirement._canonical(receipt);name=receipt['id']+'.json'
            generation=f'1|{index+2}|{len(raw)}|mtime|ctime|600|10209|10209|1|regular file'
            entries.append({'name':name,'generation':generation})
            rows.append({'name':name,'generation':generation,'sha256':hashlib.sha256(raw).hexdigest(),
                'bytes':len(raw),'rawBase64':base64.b64encode(raw).decode(),'phase':phase,
                'classification':'terminal','sessionId':index+1})
        raw=b'Active install sessions:\n\nFinalized install sessions:\n\nHistorical install sessions:\n\nLegacy install sessions:\n  {}\n'
        inventory={'state':'empty','complete':True,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'rawBase64':base64.b64encode(raw).decode(),'activeSectionSha256':hashlib.sha256(b'\n\n\x00').hexdigest()}
        metadata={'no_backup/control-install-sessions':{'kind':'directory','generation':'1|1|4096|mtime|ctime|700|10209|10209|2|directory','entries':entries},
            'files/control-installs':{'kind':'absent','generation':'','entries':[]}}
        row={'rows':rows,'osInventory':inventory,'metadata':metadata}
        return [row,copy.deepcopy(row)]

    def component_source(self):
        raw=Path(retirement.__file__).read_bytes()
        return retirement.component_admission_source(raw,hashlib.sha256(raw).hexdigest())

    def component_producer(self):
        """Actual producer schema with synthetic source-bound facts, no private data."""
        request={'correlationId':'10000000-0000-4000-8000-000000000001','host':'archlinux',
            'device':'android-api35','expectedApi':35,'expectedAvd':'vpn-control-parity113-api35',
            'sourceSha':'d32f719a08db57e5d40ce2bf77e0d7c5b42de557',
            'packageSha256':'352af218242311884a355f789c0d1c45b736c35270b096f41408de55e2c4ed33',
            'reservation':{'syntheticPrivateBinding':True}}
        owner='20000000-0000-4000-8000-000000000001'
        certificate={'schema':1,'kind':'api35-current-owner-read-only-admission','request':request,
            'controllerId':owner,'configurationRevision':0,'componentRuntime':'EXTERNAL_JDK',
            'facts':{'sdk':'35','abi':'x86_64','shellUid':'2000','bootCompleted':'1',
                'guestBootId':'d177ded3-526f-486d-bd19-3042d1836d9a','packageSha256':request['packageSha256']},
            'appProcess':{'pid':1234,'startTicks':5678,'uid':10209,'name':'com.kardinal.vpncontrol',
                'guestBootId':'d177ded3-526f-486d-bd19-3042d1836d9a'},
            'host':{'uid':0,'euid':0,'gid':0,'egid':0,'groups':[0]},
            'status':{'runtimeRunning':False,'runtimeObservation':'stopped'},
            'operations':{'scope':'android-provider-operations','operations':[]},
            'sourceSha256':'a'*64,'commandSourceSha256':'b'*64,'environmentSha256':'c'*64,
            'bundleReceipt':{'sourceClosedFixture':True},'backendBinding':{'sourceClosedFixture':True},
            'stage':{'sourceClosedFixture':True},'responsePins':{'sourceClosedFixture':True}}
        flags=('installedLauncherAccepted','bundledRuntimeAccepted','installerLeaseGranted','guestMutationPerformed','acceptanceComplete','replayAllowed')
        certificate.update({k:False for k in flags});raw=retirement._canonical(certificate)
        pin={'generation':[1,2,0o100600,0,0,1,len(raw),3,4],
            'parents':{'/fixed-fixture':[1,3,0o40700,0,0]},'sha256':hashlib.sha256(raw).hexdigest()}
        result={'state':'api35-current-owner-admitted','componentRuntime':'EXTERNAL_JDK',
            'controllerId':owner,'configurationRevision':0,'certificatePin':pin,
            **{k:False for k in ('installerLeaseGranted','guestMutationPerformed','acceptanceComplete','replayAllowed')}}
        return {'schema':1,'kind':'api35-current-owner-admission-proof','request':request,'result':result,
            'failure':None,'failureDetail':None,'installedLauncherAccepted':False,'bundledRuntimeAccepted':False,'acceptanceComplete':False,
            'rows':[{'name':'admission.json','pin':pin,'sha256':pin['sha256'],'bytes':len(raw),'rawBase64':base64.b64encode(raw).decode()}]}

    def component_proof(self):
        producer=self.component_producer();pin=producer['result']['certificatePin']
        certificate=retirement.validate_component_certificate(producer,pin)
        history=retirement.validate_component_terminal_history(self.history(),10209)
        old=proof();old.update(kind='android-installer-component-retained-terminal-first-check',
            sourceSha='d32f719a08db57e5d40ce2bf77e0d7c5b42de557',
            toolBundleId='sha256-64c3b9f8176515770db963dd5858d3044ebd969b8d460272eb9ef3f4c9deb7ac',
            intentSha256='1b1eba7b0744ae47adc98b6b7fd7cc1480bc62a5b2ed7d4902fb36de580d7656',
            lifecycleSha256='b550f7ae50f60bcf53c0d688efda2165a6c39b505a997235bd9d78c710757e59',
            phaseCheckSha256='dadfe1eb79d0ea884dd9f9ad71f7f47f3bce56856fb15a61ec54e7495b2c6b33',
            worker={'pid':1169929,'startTicks':72285068,'stopped':True},
            fixture={'pid':1172004,'startTicks':72288190,'stopped':True,'portRefused':True},
            handoffAbsent=True,deviceLockHeld=True,canonicalLeaseAbsent=True,
            componentProducer=producer,componentCertificatePin=pin,terminalHistory=self.history(),
            principals={'historicalWorkerUid':1000,'hostMeasurementUid':0,'hostPublicUid':1000,
                'adbShellUid':2000,'appMetadataUid':10209,'localLeaseUid':os.getuid()})
        snapshot=old['snapshots'][0];snapshot.update(owner=certificate['controllerId'],
            packageSha256=certificate['request']['packageSha256'],terminalHistorySha256=history['historySha256'],
            latestPublicReceipt=history['latestPublicReceipt'])
        old['snapshots']=[snapshot,copy.deepcopy(snapshot)];old['opening']['packageSha256']=snapshot['packageSha256']
        files={}
        for name in retirement.COMPONENT_REQUIRED_FILES:
            original=name not in ('component-admission.json','closing-component-routing.json','terminal-history.json','local-lease.json')
            uid=1000 if original else os.getuid() if name=='local-lease.json' else 0
            files[name]={'principal':'historical-worker'if original else'local-lease'if name=='local-lease.json'else'component-worker',
                'format':'private8','generation':[1,2,3,4,5,0o600,uid,1],'sha256':'d'*64}
        files['component-admission.json'].update(format='descriptor9',generation=pin['generation'],sha256=pin['sha256'])
        for name,key in (('output/intent.json','intentSha256'),('output/lifecycle-receipt.json','lifecycleSha256'),('output/phase-check.json','phaseCheckSha256')):files[name]['sha256']=old[key]
        old['files']=files;return old

    def test_component_producer_cannot_enter_legacy_release(self):
        value=self.component_proof()
        # Real producer schema is accepted by its own validator; the legacy
        # release refuses before opening even a nonexistent lease path.
        retirement.validate_component_retained_proof(value)
        with self.assertRaisesRegex(ValueError,'file_generations_missing|retirement_correlation_invalid'):
            retirement.release_fenced(Path('/unused/lease'),Path('/unused/release'),
                Path('/unused/fence'),{},[], '0'*64,value)

    def test_component_release_factory_exists(self):
        raw=Path(retirement.__file__).read_bytes()
        source=retirement.component_release_source(raw,hashlib.sha256(raw).hexdigest())
        scope={};exec(compile(source,'<component-release>','exec'),scope)
        self.assertIn('release_component_fenced',scope)

    def release_fixture(self,root):
        source=retirement.component_release_source(Path(retirement.__file__).read_bytes(),
            hashlib.sha256(Path(retirement.__file__).read_bytes()).hexdigest())
        scope={};exec(compile(source,'<actual-component-release>','exec'),scope)
        lease=root/'lease-archlinux-api35.json'
        raw=retirement._canonical({'owner':'android-installer','host':'archlinux','device':'api35','correlationId':CORR})
        self.assertEqual(len(raw),121)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'44f2b1d325cbd0dedda6d6af5b1bf856792edf327accad99475e8cde6e4e865a')
        lease.write_bytes(raw);lease.chmod(0o600)
        def fp(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
        pin={'generation':fp(lease.stat()),'sha256':hashlib.sha256(raw).hexdigest(),
            'parents':[[x.stat().st_dev,x.stat().st_ino,x.stat().st_mode,x.stat().st_uid,x.stat().st_gid]
                for x in reversed([root,*list(root.parents)[:-1]])]}
        value=self.component_proof()
        remote_generation=[*pin['generation'][:3],1000,1000,*pin['generation'][5:]]
        value['files']['remote-lease.json']={'principal':'historical-worker','format':'descriptor9','generation':remote_generation,'sha256':pin['sha256']}
        value['files']['local-lease.json']={'principal':'local-lease','format':'private8',
            'generation':retirement._generation(lease.stat()),'sha256':pin['sha256']}
        # Actual source-generated admission writes the proof/result on realFDs;
        # no release/admission result is supplied by the fixture.
        original=root/'original';original.mkdir(mode=0o700)
        admitted=root/'admission';admitted.mkdir(mode=0o700)
        scope['admit_component_fenced'](original,admitted,value,lambda:retirement.private_snapshot(lease,1024),os.getuid())
        value=json.loads((admitted/'component-admitted-proof.json').read_bytes())
        corr='30000000-0000-4000-8000-000000000003'
        receipt={'schema':1,'kind':'android-installer-component-remote-lease-released',
            'originalCorrelationId':CORR,'admissionCorrelationId':value['retirementCorrelationId'],
            'releaseCorrelationId':corr,'admittedProofSha256':hashlib.sha256(retirement._canonical(value)).hexdigest(),
            'originalOutcome':'unknown','leaseReleased':True,'replayAllowed':False,
            'retiredEvidence':{'path':'/fixture/android-native-device-api35-'+CORR+'.component-retirement-quarantine/captured-original-lease.json',
                'generation':remote_generation,'sha256':pin['sha256'],'parents':[[1,2,0o40700,0,0]],'leaseCapturedNotDeleted':True}}
        def fresh():
            # Real exact lease read accompanies every typed measured proof.
            raw2,gen,digest=retirement.private_snapshot(lease,1024)
            self.assertEqual((raw2,gen,digest),(raw,value['files']['local-lease.json']['generation'],pin['sha256']))
            return copy.deepcopy(value)
        return scope,lease,pin,value,corr,receipt,fresh

    def test_actual_component_release_fd_producer_and_once_fence(self):
        with tempfile.TemporaryDirectory()as raw:
            root=Path(raw).resolve();root.chmod(0o700)
            scope,lease,pin,value,corr,receipt,fresh=self.release_fixture(root)
            result=scope['release_component_fenced'](lease,pin,value,corr,fresh,'local-original',receipt)
            self.assertTrue(result['leaseReleased']);self.assertFalse(result['replayAllowed'])
            self.assertFalse(lease.exists());self.assertEqual(json.loads((root/('release-'+CORR+'.json')).read_bytes())['correlationId'],CORR)
            captured=Path(result['retiredEvidence']['path'])
            self.assertEqual(captured.stat().st_ino,pin['generation'][1])
            self.assertEqual(hashlib.sha256(captured.read_bytes()).hexdigest(),pin['sha256'])
            self.assertEqual(captured.read_bytes(),(captured.parent/'held-original-snapshot.json').read_bytes())
            # Recreated identical lease cannot bypass the original global fence.
            lease.write_bytes(retirement._canonical({'owner':'android-installer','host':'archlinux','device':'api35','correlationId':CORR}));lease.chmod(0o600)
            with self.assertRaises(ValueError):scope['release_component_fenced'](lease,pin,value,corr,fresh,'local-original',receipt)
            self.assertTrue(lease.exists())

    def test_component_root_guardian_releases_original_uid1000_lease(self):
        import types
        with tempfile.TemporaryDirectory()as raw:
            root=Path(raw).resolve();root.chmod(0o700)
            scope,local,pin,value,corr,receipt,fresh=self.release_fixture(root)
            lease=root/'android-native-device-api35.lease';os.rename(local,lease)
            # Portability seam ONLY projects metadata principals: actual opens,
            # FD generations, reads, flock-free primitive operations, fsync,
            # O_EXCL fences, hashes and unlink are the production functions.
            paths={}
            def projected(info,path):
                fields={name:getattr(info,name)for name in dir(info)if name.startswith('st_')}
                principal=1000 if path in (root,lease)or path.name=='captured-original-lease.json'else 0
                fields.update(st_uid=principal,st_gid=principal)
                # Linux directory nlink counts only subdirectories; APFS counts
                # all entries. Fixed projection keeps guardian-role tests real.
                if path.is_dir():fields['st_nlink']=2+sum(x.is_dir()for x in path.iterdir())
                return types.SimpleNamespace(**fields)
            def opened(path,flags,*args,**kwargs):
                fd=os.open(path,flags,*args,**kwargs)
                parent=paths.get(kwargs.get('dir_fd'))
                paths[fd]=(parent/str(path)if parent is not None else Path(path)).absolute()
                return fd
            def fst(fd):return projected(os.fstat(fd),paths[fd])
            def named(path,*args,**kwargs):
                parent=paths.get(kwargs.get('dir_fd'))
                full=(parent/str(path)if parent is not None else Path(path)).absolute()
                return projected(os.stat(path,*args,**kwargs),full)
            def closed(fd):paths.pop(fd,None);os.close(fd)
            proxy=types.SimpleNamespace(**{name:getattr(os,name)for name in dir(os)})
            proxy.open=opened;proxy.fstat=fst;proxy.stat=named;proxy.close=closed
            proxy.getuid=lambda:0;proxy.getgid=lambda:0
            scope['os']=proxy
            def fp(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
            info=projected(lease.stat(),lease);pin['generation']=fp(info)
            for row in pin['parents']:
                row[3:5]=[1000,1000]if row[:2]==[root.stat().st_dev,root.stat().st_ino]else[0,0]
            value['files']['remote-lease.json']={'principal':'historical-worker','format':'descriptor9',
                'generation':pin['generation'],'sha256':pin['sha256']}
            # Bind the actual admitted proof to projected remote generation.
            observed=copy.deepcopy(value)
            def measured():
                with lease.open('rb')as stream:self.assertEqual(hashlib.sha256(stream.read()).hexdigest(),pin['sha256'])
                return copy.deepcopy(observed)
            result=scope['release_component_fenced'](lease,pin,value,corr,measured,'remote-original')
            self.assertEqual(result['kind'],'android-installer-component-remote-lease-released')
            self.assertTrue(result['leaseReleased']);self.assertFalse(lease.exists())
            self.assertTrue((root/('android-native-device-api35-'+CORR+'.component-retirement-fence')).exists())

    def test_component_release_failure_after_fence_consumed_without_unlink(self):
        with tempfile.TemporaryDirectory()as raw:
            root=Path(raw).resolve();root.chmod(0o700)
            scope,lease,pin,value,corr,receipt,fresh=self.release_fixture(root);calls=0
            def fail():
                nonlocal calls
                calls+=1
                if calls==2:raise RuntimeError('lost response')
                return fresh()
            with self.assertRaises(RuntimeError):scope['release_component_fenced'](lease,pin,value,corr,fail,'local-original',receipt)
            self.assertTrue(lease.exists());self.assertTrue((root/('component-retirement-'+CORR+'.json')).exists())
            self.assertFalse((root/('release-'+CORR+'.json')).exists())
            with self.assertRaisesRegex(ValueError,'already_fenced'):
                scope['release_component_fenced'](lease,pin,value,corr,fresh,'local-original',receipt)

    def test_archived_component_release_name_race_red_actual_function(self):
        self.assertEqual(hashlib.sha256(OLD_COMPONENT_RELEASE_FUNCTION.encode()).hexdigest(),OLD_COMPONENT_RELEASE_FUNCTION_SHA256)
        with tempfile.TemporaryDirectory()as raw:
            root=Path(raw).resolve();root.chmod(0o700)
            scope,lease,pin,value,corr,receipt,fresh=self.release_fixture(root)
            exec(compile(OLD_COMPONENT_RELEASE_FUNCTION,'<exact-consumed-unsafe-release>','exec'),scope)
            receipt.pop('retiredEvidence') # Exact former result schema.
            original_unlink=os.unlink;exchanged=False
            def exchange_at_unlink(name,*args,**kwargs):
                nonlocal exchanged
                if name==lease.name and not exchanged:
                    exchanged=True;replacement=root/'foreign-replacement'
                    replacement.write_bytes(b'foreign replacement');replacement.chmod(0o600)
                    os.replace(replacement,lease)
                return original_unlink(name,*args,**kwargs)
            with mock.patch.object(scope['os'],'unlink',side_effect=exchange_at_unlink):
                result=scope['release_component_fenced'](lease,pin,value,corr,fresh,'local-original',receipt)
            self.assertTrue(exchanged);self.assertTrue(result['leaseReleased'])
            self.assertFalse(lease.exists()) # Demonstrates exact old unsafe RED.

    def test_component_release_exact_unlink_boundary_exchange_preserves_foreign(self):
        with tempfile.TemporaryDirectory()as raw:
            root=Path(raw).resolve();root.chmod(0o700)
            scope,lease,pin,value,corr,receipt,fresh=self.release_fixture(root)
            original_rename=os.rename;exchanged=False
            foreign=b'foreign replacement must not be removed'
            def exchange_at_capture(name,*args,**kwargs):
                nonlocal exchanged
                if name==lease.name and not exchanged:
                    exchanged=True;replacement=root/'foreign-replacement'
                    replacement.write_bytes(foreign);replacement.chmod(0o600)
                    os.replace(replacement,lease)
                return original_rename(name,*args,**kwargs)
            with mock.patch.object(scope['os'],'rename',side_effect=exchange_at_capture):
                with self.assertRaisesRegex(ValueError,'captured_foreign_unknown'):
                    scope['release_component_fenced'](lease,pin,value,corr,fresh,'local-original',receipt)
            captured=root/('component-retirement-'+CORR+'.quarantine')/'captured-original-lease.json'
            self.assertTrue(captured.exists());self.assertEqual(captured.read_bytes(),foreign)
            self.assertEqual(hashlib.sha256((captured.parent/'held-original-snapshot.json').read_bytes()).hexdigest(),pin['sha256'])
            self.assertFalse(lease.exists()) # Explicit: foreign name was moved.

    def test_component_release_quarantine_name_drift_preserves_original_inode(self):
        with tempfile.TemporaryDirectory()as raw:
            root=Path(raw).resolve();root.chmod(0o700)
            scope,lease,pin,value,corr,receipt,fresh=self.release_fixture(root)
            original_rename=os.rename;qname='component-retirement-'+CORR+'.quarantine'
            moved=root/'displaced-private-quarantine';changed=False
            def drift_at_capture(name,*args,**kwargs):
                nonlocal changed
                if name==lease.name and not changed:
                    changed=True;original_rename(root/qname,moved);(root/qname).mkdir(mode=0o700)
                return original_rename(name,*args,**kwargs)
            with mock.patch.object(scope['os'],'rename',side_effect=drift_at_capture):
                with self.assertRaisesRegex(ValueError,'quarantine_changed'):
                    scope['release_component_fenced'](lease,pin,value,corr,fresh,'local-original',receipt)
            captured=moved/'captured-original-lease.json'
            self.assertEqual(captured.stat().st_ino,pin['generation'][1])
            self.assertEqual(hashlib.sha256(captured.read_bytes()).hexdigest(),pin['sha256'])
            self.assertEqual(captured.read_bytes(),(moved/'held-original-snapshot.json').read_bytes())
            self.assertEqual(list((root/qname).iterdir()),[]) # Foreign folder untouched.

    def test_component_release_unknown_after_release_record_or_unlink_no_replay(self):
        for boundary in ('release-record','capture'):
            with self.subTest(boundary=boundary),tempfile.TemporaryDirectory()as raw:
                root=Path(raw).resolve();root.chmod(0o700)
                scope,lease,pin,value,corr,receipt,fresh=self.release_fixture(root);calls=0
                def interrupted():
                    nonlocal calls
                    calls+=1
                    if boundary=='release-record'and calls==3:raise RuntimeError('lost response')
                    return fresh()
                original_rename=os.rename
                def rename_then_unknown(*args,**kwargs):
                    original_rename(*args,**kwargs);raise RuntimeError('lost response')
                if boundary=='capture':
                    with mock.patch.object(scope['os'],'rename',side_effect=rename_then_unknown):
                        with self.assertRaises(RuntimeError):scope['release_component_fenced'](lease,pin,value,corr,interrupted,'local-original',receipt)
                else:
                    with self.assertRaises(RuntimeError):scope['release_component_fenced'](lease,pin,value,corr,interrupted,'local-original',receipt)
                self.assertTrue((root/('release-'+CORR+'.json')).exists())
                self.assertTrue((root/('component-retirement-'+CORR+'.json')).exists())
                self.assertEqual(lease.exists(),boundary=='release-record')
                if boundary=='capture':
                    captured=root/('component-retirement-'+CORR+'.quarantine')/'captured-original-lease.json'
                    self.assertEqual(captured.stat().st_ino,pin['generation'][1])
                    self.assertEqual(hashlib.sha256(captured.read_bytes()).hexdigest(),pin['sha256'])
                with self.assertRaises((ValueError,FileNotFoundError)):
                    scope['release_component_fenced'](lease,pin,value,corr,fresh,'local-original',receipt)

    def test_component_release_exact_pin_parent_and_remote_success_negatives(self):
        for change in ('generation','sha','principal','parent','remote','fresh'):
            with self.subTest(change=change),tempfile.TemporaryDirectory()as raw:
                root=Path(raw).resolve();root.chmod(0o700)
                scope,lease,pin,value,corr,receipt,fresh=self.release_fixture(root)
                if change=='generation':pin['generation'][7]+=1
                elif change=='sha':pin['sha256']='0'*64
                elif change=='principal':pin['generation'][3]+=1
                elif change=='parent':pin['parents'][-1][1]+=1
                elif change=='remote':receipt['leaseReleased']=1
                else:
                    prior=fresh
                    def fresh():
                        result=prior();result['snapshots'][0]['runtimeRunning']=True;return result
                with self.assertRaises(ValueError):scope['release_component_fenced'](lease,pin,value,corr,fresh,'local-original',receipt)
                self.assertTrue(lease.exists());self.assertFalse((root/('release-'+CORR+'.json')).exists())

    def test_component_release_parent_and_created_record_exchange_refused(self):
        for change in ('parent','fence'):
            with self.subTest(change=change),tempfile.TemporaryDirectory()as raw:
                root=Path(raw).resolve();root.chmod(0o700)
                scope,lease,pin,value,corr,receipt,fresh=self.release_fixture(root);calls=0
                def exchange():
                    nonlocal calls
                    calls+=1;measured=fresh()
                    if calls==2:
                        if change=='parent':root.chmod(0o777)
                        else:
                            fence=root/('component-retirement-'+CORR+'.json');replacement=root/'replacement'
                            replacement.write_bytes(fence.read_bytes());replacement.chmod(0o600);os.replace(replacement,fence)
                    return measured
                try:
                    with self.assertRaises(ValueError):scope['release_component_fenced'](lease,pin,value,corr,exchange,'local-original',receipt)
                    self.assertTrue(lease.exists())
                finally:root.chmod(0o700)

    def test_complete_typed_proof_without_principal_conversion(self):
        value=self.component_proof();self.assertEqual(value,retirement.validate_component_retained_proof(value))
        with self.assertRaises(ValueError):retirement.validate_proof(value)
        for field in ('sourceSha','phaseCheckSha256','canonicalLeaseAbsent','deviceLockHeld'):
            changed=copy.deepcopy(value);changed[field]=False if type(changed[field])is bool else'changed'
            with self.assertRaises(ValueError):retirement.validate_component_retained_proof(changed)
        changed=copy.deepcopy(value);changed['files']['output/intent.json']['generation'][6]=0
        with self.assertRaises(ValueError):retirement.validate_component_retained_proof(changed)

    def test_factory_uses_authenticated_snapshot_not_reopened_name(self):
        raw=Path(retirement.__file__).read_bytes();digest=hashlib.sha256(raw).hexdigest()
        with mock.patch.object(retirement.inspect,'getsource',side_effect=AssertionError('named source reread')):
            source=retirement.component_admission_source(raw,digest)
        scope={};exec(compile(source,'<held-source>','exec'),scope)
        self.assertEqual(scope['validate_component_retained_proof'](self.component_proof()),self.component_proof())
        with self.assertRaisesRegex(ValueError,'component_factory_source_changed'):
            retirement.component_admission_source(raw+b'\n# exchange',digest)
        with self.assertRaisesRegex(ValueError,'component_factory_source_changed'):
            retirement.component_admission_source(raw,'0'*64)

    def test_generated_created_record_same_bytes_replacement_rejected(self):
        scope={};exec(compile(self.component_source(),'<held-source>','exec'),scope)
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();root.chmod(0o700);original=root/'original';original.mkdir(mode=0o700)
            admitted=root/'admitted';admitted.mkdir(mode=0o700);count=0
            def guard():
                nonlocal count
                count+=1
                if count==3:
                    path=admitted/'component-admitted-proof.json'
                    alternate=admitted/'temporary';alternate.write_bytes(path.read_bytes());alternate.chmod(0o600)
                    os.replace(alternate,path)
            with self.assertRaisesRegex(ValueError,'component_admission_(record|parent)_changed'):
                scope['admit_component_fenced'](original,admitted,self.component_proof(),guard,os.getuid())
            self.assertFalse((admitted/'component-admitted.json').exists())
            self.assertTrue((original/'component-retained-retirement-admission-intent.json').exists())

    def test_generated_parent_mode_change_refuses_after_fence(self):
        scope={};exec(compile(self.component_source(),'<held-source>','exec'),scope)
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();root.chmod(0o700);original=root/'original';original.mkdir(mode=0o700)
            admitted=root/'admitted';admitted.mkdir(mode=0o700);count=0
            def guard():
                nonlocal count
                count+=1
                if count==2:original.chmod(0o777)
            try:
                with self.assertRaisesRegex(ValueError,'component_admission_parent_changed'):
                    scope['admit_component_fenced'](original,admitted,self.component_proof(),guard,os.getuid())
                self.assertFalse((admitted/'component-admitted.json').exists())
            finally:original.chmod(0o700)

    def test_actual_generated_fd_admission_and_global_unknown_no_replay(self):
        scope={'__name__':'component_retirement_generated_fixture'}
        exec(compile(self.component_source(),'<actual-closed-component-admission>','exec'),scope)
        value=self.component_proof()
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();root.chmod(0o700)
            original=root/'original-output';original.mkdir(mode=0o700)
            admitted=root/'new-admission';admitted.mkdir(mode=0o700)
            guards=[]
            result=scope['admit_component_fenced'](original,admitted,value,lambda:guards.append('guard'),os.getuid())
            self.assertEqual(result['state'],'component-retained-terminal-admitted')
            self.assertFalse(result['leaseReleased']);self.assertEqual(len(guards),3)
            self.assertEqual(json.loads((admitted/'component-admitted-proof.json').read_bytes()),value)
            self.assertEqual(result['proofPin']['sha256'],hashlib.sha256((admitted/'component-admitted-proof.json').read_bytes()).hexdigest())
            # Different retirement UUID still cannot bypass original global fence.
            value['retirementCorrelationId']='30000000-0000-4000-8000-000000000001'
            later=root/'other-admission';later.mkdir(mode=0o700)
            with self.assertRaises(FileExistsError):scope['admit_component_fenced'](original,later,value,lambda:None,os.getuid())
            self.assertEqual(list(later.iterdir()),[])

    def test_actual_generated_partial_guard_failure_consumes_fence(self):
        scope={};exec(compile(self.component_source(),'<actual-closed-component-admission>','exec'),scope)
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();root.chmod(0o700);original=root/'original';original.mkdir(mode=0o700)
            admitted=root/'admitted';admitted.mkdir(mode=0o700);count=0
            def guard():
                nonlocal count
                count+=1
                if count==2:raise ValueError('measured_owner_changed')
            with self.assertRaisesRegex(ValueError,'measured_owner_changed'):
                scope['admit_component_fenced'](original,admitted,self.component_proof(),guard,os.getuid())
            self.assertTrue((original/'component-retained-retirement-admission-intent.json').exists())
            self.assertEqual(list(admitted.iterdir()),[])
            with self.assertRaises(FileExistsError):scope['admit_component_fenced'](original,admitted,self.component_proof(),lambda:None,os.getuid())

    def test_actual_generated_foreign_regular_child_refused(self):
        scope={};exec(compile(self.component_source(),'<actual-closed-component-admission>','exec'),scope)
        with tempfile.TemporaryDirectory() as raw:
            root=Path(raw).resolve();root.chmod(0o700);original=root/'original';original.mkdir(mode=0o700)
            admitted=root/'admitted';admitted.mkdir(mode=0o700);count=0
            def guard():
                nonlocal count
                count+=1
                if count==2:(original/'foreign.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'component_admission_(inventory|parent)_changed'):
                scope['admit_component_fenced'](original,admitted,self.component_proof(),guard,os.getuid())
            self.assertFalse((admitted/'component-admitted.json').exists())

    def test_actual_terminal_producer_requires_explicit_typed_branch(self):
        result=retirement.validate_component_terminal_history(self.history(),10209)
        self.assertEqual(result['latestPublicReceipt'],{'installReceiptId':'00000000-0000-4000-8000-000000000003',
            'installSessionId':3,'installPhase':'cancelled','installed':False})
        self.assertEqual(result['terminalCount'],3)

    def test_nonterminal_unknown_and_principal_drift_reject(self):
        for mutation in ('phase','uid','nonce','signers','source','session'):
            value=self.history()
            if mutation=='uid': value[1]['rows'][0]['generation']=value[1]['rows'][0]['generation'].replace('|10209|10209|','|2000|2000|')
            elif mutation=='session':value[0]['osInventory']['state']='present'
            else:
                row=value[0]['rows'][0];body=json.loads(base64.b64decode(row['rawBase64']))
                if mutation=='phase':body['phase']='UNKNOWN'
                if mutation=='nonce':body['nonce']='bad'
                if mutation=='signers':body['signers']=[]
                if mutation=='source':body['version']='2.2.20'
                raw=retirement._canonical(body);row.update(rawBase64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
                old=row['generation'];row['generation']=old.replace('|'+old.split('|')[2]+'|','|'+str(len(raw))+'|',1)
                value[0]['metadata']['no_backup/control-install-sessions']['entries'][0]['generation']=row['generation']
            with self.assertRaises(ValueError):retirement.validate_component_terminal_history(value,10209)

    def test_certificate_revision_and_host_groups_are_strict_integers(self):
        producer=self.component_producer();producer['result']['configurationRevision']=False
        with self.assertRaises(ValueError):retirement.validate_component_certificate(producer,producer['result']['certificatePin'])
        producer=self.component_producer();row=producer['rows'][0];body=json.loads(base64.b64decode(row['rawBase64']));body['host']['groups']=[False]
        raw=retirement._canonical(body);row.update(rawBase64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        row['pin']['generation'][6]=len(raw);row['pin']['sha256']=row['sha256']
        with self.assertRaises(ValueError):retirement.validate_component_certificate(producer,producer['result']['certificatePin'])

    def test_public_terminal_dto_strict_bool_and_integer_consumers(self):
        value=self.component_proof()
        for malformed in (0,1,None,'false'):
            changed=copy.deepcopy(value)
            for snapshot in changed['snapshots']:snapshot['latestPublicReceipt']['installed']=malformed
            with self.subTest(consumer='proof',installed=malformed):
                with self.assertRaises(ValueError):retirement.validate_component_retained_proof(changed)
        history=retirement.validate_component_terminal_history(self.history(),10209)
        certificate=retirement.validate_component_certificate(value['componentProducer'],value['componentCertificatePin'])
        rules={'type':'vpn_control_routing_rules','version':7,'rules':{'ignore_rules':False,'block_quic_udp_443':False,'proxy_packages':[],'direct_domain_suffixes':[]}}
        for field,malformed in (('installed',0),('installSessionId',True),('installReceiptId','bad'),('installPhase','pending')):
            dto=copy.deepcopy(history['latestPublicReceipt']);dto[field]=malformed
            data={'status':{'runtimeRunning':False,'runtimeObservation':'stopped'},'operations list':{'operations':[]},'settings show':{},'source show':{},'updates status':{'phase':'idle','installRecoveryUnavailable':False,'legacyInstallerPins':0,'installReceipt':dto}}
            def public(*words):return {'ok':True,'final':True,'code':'OK','controllerId':certificate['controllerId'],'configurationRevision':0,'data':copy.deepcopy(data[' '.join(words)])}
            with self.subTest(consumer='snapshot',field=field):
                with self.assertRaises(ValueError):retirement.measure_component_retained_snapshot(public,lambda:rules,certificate,lambda:history)

    def test_real_public_dto_terminal_snapshot_and_owner_drift(self):
        history=retirement.validate_component_terminal_history(self.history(),10209)
        owner='10000000-0000-4000-8000-000000000001'
        certificate={'controllerId':owner,'configurationRevision':0,'appProcess':{'uid':10209},
            'request':{'packageSha256':'a'*64}}
        data={'status':{'runtimeRunning':False,'runtimeObservation':'stopped'},'operations list':{'operations':[]},
            'settings show':{'configuredMode':'proxy_only'},'source show':{'kind':'none'},
            'updates status':{'phase':'idle','installRecoveryUnavailable':False,'legacyInstallerPins':0,
                'installReceipt':history['latestPublicReceipt']}}
        rules={'type':'vpn_control_routing_rules','version':7,'rules':{'ignore_rules':False,
            'block_quic_udp_443':False,'proxy_packages':[],'direct_domain_suffixes':[]}}
        calls=[]
        def public(*words):
            command=' '.join(words);calls.append(command)
            return {'ok':True,'final':True,'code':'OK','controllerId':owner,'configurationRevision':0,'data':copy.deepcopy(data[command])}
        result=retirement.measure_component_retained_snapshot(public,lambda:rules,certificate,lambda:history)
        self.assertEqual(result['latestPublicReceipt'],history['latestPublicReceipt'])
        self.assertEqual(calls.count('status'),2)
        data['updates status']['installReceipt']=None
        with self.assertRaisesRegex(ValueError,'terminal_dto_changed'):
            retirement.measure_component_retained_snapshot(public,lambda:rules,certificate,lambda:history)
        def drift(*words):
            result=public(*words)
            if words==('updates','status'):result['controllerId']='20000000-0000-4000-8000-000000000002'
            return result
        with self.assertRaisesRegex(ValueError,'owner_changed'):
            retirement.measure_component_retained_snapshot(drift,lambda:rules,certificate,lambda:history)


def proof():
    snapshot = {"owner": "fresh-owner", "revision": 0, "allFinal": True,
        "updateWorkIdle": True, "installerIdle": True,
        "runtimeRunning": False, "runtimeObservation": "stopped", "packageSha256": "a" * 64,
        "routingSha256": "b" * 64, "settingsSha256": "c" * 64, "sourceSha256": "d" * 64}
    return {"originalCorrelationId": CORR, "retirementCorrelationId": NEW,
        "originalOutcome": "unknown", "sourceSha": "e" * 40,
        "historicalSettingsSource": "unavailable", "productDataMutationAllowed": False,
        "measurementUid": os.getuid(), "localLeaseUid": os.getuid(),
        "toolBundleId": "sha256-" + "f" * 64, "intentSha256": "1" * 64,
        "lifecycleSha256": "2" * 64, "worker": {"pid": 123, "startTicks": 456, "stopped": True},
        "fixture": {"pid": 124, "startTicks": 457, "stopped": True, "portRefused": True},
        "phases": {"check": True, "download": False, "noninteractive": False, "interactive": False},
        "failureType": "RuntimeError", "cleanupFailures": [], "probeAbsent": True,
        "closingReadbackCorrelationId": "39156032-ebaa-4edf-9020-99d7146ac7d0",
        "freshOwnerAdmission": True, "opening": {key: snapshot[key] for key in
            ("packageSha256", "routingSha256")},
        "snapshots": [snapshot, copy.deepcopy(snapshot)], "nativeRestored": True,
        "files": {name: {"sha256": "1" * 64 if name == "output/intent.json" else "2" * 64
            if name == "output/lifecycle-receipt.json" else "3" * 64,
            "generation": [1, 2, 3, 4, 5, 384, os.getuid(), 1]} for name in retirement.REQUIRED_FILES}}


class RetirementTest(unittest.TestCase):
    def test_privileged_script_survives_actual_adb_shell_flattening(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); helper = root / 'su'
            helper.write_text('#!' + sys.executable + '\nimport os,sys\nassert sys.argv[1]=="0"\nos.execv(sys.argv[2],sys.argv[2:])\n')
            helper.chmod(0o700)
            script = 'set -eu; x="privileged value"; printf "%s" "$x"'
            words = retirement.privileged_command(script)
            flattened = ' '.join(words).replace('/system/xbin/su', str(helper)).replace('/system/bin/sh', '/bin/sh')
            result = subprocess.run(['/bin/sh', '-c', flattened], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual('privileged value', result.stdout)

    def remote_fixture(self, admission_id=NEW):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name).resolve(); root.chmod(0o700)
        job = root / ('android-installer-' + CORR); job.mkdir(mode=0o700)
        out = job / 'output'; out.mkdir(mode=0o700)
        def write(path, value):
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(retirement._canonical(value)); path.chmod(0o600)
        rules = {'type': 'vpn_control_routing_rules', 'version': 7,
            'rules': {'ignore_rules': False, 'block_quic_udp_443': False, 'proxy_packages': [], 'direct_domain_suffixes': []}}
        opening = root / 'opening' / 'routing.json'; write(opening, rules)
        original = {'correlationId': CORR, 'host': 'archlinux', 'device': 'api35',
            'backupPath': str(opening), 'backupSha256': hashlib.sha256(opening.read_bytes()).hexdigest(), 'backupSize': opening.stat().st_size,
            'pair': {'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557', 'baseSha256': 'a' * 64, 'targetArtifactId': 'sha256-' + 'b' * 64}}
        write(out / 'intent.json', original)
        lifecycle = {'installerIntent': {'correlationId': CORR, 'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557',
            'targetArtifactId': 'sha256-' + 'b' * 64, 'backupSha256': original['backupSha256']},
            'failure': {'type': 'RuntimeError'}, 'cleanupFailures': [], 'target': '/apex/com.android.conscrypt/cacerts',
            'effectiveProxyBaseline': {name: 'null' for name in ('http_proxy', 'global_http_proxy_host', 'global_http_proxy_port', 'global_http_proxy_pac', 'global_http_proxy_exclusion_list')},
            'commands': [{'args': ['reverse', '--list'], 'exit': 0, 'stdout': '', 'stdoutTruncated': False}]}
        lifecycle['effectiveProxyBaseline']['global_http_proxy_exclusion_list']=''
        write(out / 'lifecycle-receipt.json', lifecycle); write(out / 'phase-check.json', {'correlationId': CORR, 'phase': 'check'})
        write(job / 'identity.json', {'pid': 2147483640, 'startTicks': 123})
        with socket.socket() as sock: sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
        fixture = {'correlationId': CORR, 'pid': 2147483641, 'startTicks': 124, 'port': port}
        write(out / 'fixture-identity.json', fixture); write(out / 'worker-finished.json', {**fixture, 'state': 'fixture_stopped'})
        write(out / 'fixture-receipt.json', {'state': 'ready', 'pid': fixture['pid'], 'port': port}); write(out / 'ready.json', {'port': port})
        lease = root / 'android-native-device-api35.lease'
        write(lease, {'owner': 'android-installer', 'host': 'archlinux', 'device': 'api35', 'correlationId': CORR})
        closing_corr = '39156032-ebaa-4edf-9020-99d7146ac7d0'
        write(root / ('android-readback-' + closing_corr) / 'routing.json', rules)
        closing = {'guard': {'controllerId': 'fresh-owner', 'configurationRevision': 0}, 'package': {'baseSha256': 'a' * 64}}
        write(root / ('android-readback-job-' + closing_corr) / 'result.json', {'state': 'complete', 'result': closing})
        adb = root / 'adb'; cli = root / 'cli'; mode = root / 'mode'; mode.write_text('valid')
        fake_bin = root / 'fake-bin'; fake_bin.mkdir(mode=0o700)
        for name, text in [('id', '0'), ('pidof', '371')]:
            executable = fake_bin / name; executable.write_text('#!/bin/sh\nprintf ' + text + '\n'); executable.chmod(0o700)
        fake_su = root / 'su'; fake_su.write_text('#!' + sys.executable + '\nimport os,sys\nassert sys.argv[1]=="0"\nos.execv(sys.argv[2],sys.argv[2:])\n'); fake_su.chmod(0o700)
        fake_app = root / 'fake-app'; (fake_app / 'no_backup' / 'control-install-sessions').mkdir(parents=True)
        fake_stat = fake_bin/'stat'; fake_stat.write_text('#!'+sys.executable+'\nimport sys,os,stat,pathlib\nx=os.lstat(sys.argv[-1]);ctime=x.st_ctime_ns\nm=pathlib.Path('+repr(str(mode))+').read_text()\nif m=="metadata-drift" and sys.argv[-1].endswith("/control-install-sessions"):\n p=pathlib.Path('+repr(str(root/'metadata-stat-count'))+');n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n));ctime+=n\nprint("|".join(map(str,[x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns,ctime,oct(stat.S_IMODE(x.st_mode)),x.st_uid,x.st_gid,x.st_nlink,"directory" if stat.S_ISDIR(x.st_mode) else "symlink" if stat.S_ISLNK(x.st_mode) else "regular file"])))\n');fake_stat.chmod(0o700)
        fake_mounts = root / 'mountinfo'; fake_mounts.write_text('1 2 0:1 / / rw - rootfs rootfs rw\n')
        help_text = "usage: su [WHO [COMMAND...]]\n\nSwitch to WHO (default 'root') and run the given COMMAND (default sh).\n\nWHO is a comma-separated list of user, group, and supplementary groups\nin that order."
        adb.write_text('#!' + sys.executable + '\nimport sys,pathlib,os,subprocess\na=sys.argv[1:];m=pathlib.Path(' + repr(str(mode)) + ').read_text()\n'
            'cmd=" ".join(a[a.index("-T")+1:]) if "-T" in a else ""\n'
            'if cmd.startswith("/system/bin/stat "):\n p=pathlib.Path(' + repr(str(root / 'stat-count')) + ');n=int(p.read_text())+1 if p.exists() else 1;p.write_text(str(n));print("2000:2000:755:1:9:regular file" if m=="bad-su" else "0:2000:4750:1:10:regular file" if m=="su-after-read" and n>=3 else "0:2000:4750:1:9:regular file");sys.exit(0)\n'
            'if cmd.startswith("/system/bin/sha256sum "):print("' + '8' * 64 + '  /system/xbin/su");sys.exit(0)\n'
            'if cmd=="/system/xbin/su --help":print("other helper grammar" if m=="bad-grammar" else ' + repr(help_text) + ');sys.exit(0)\n'
            'if cmd.startswith("/system/xbin/su "):\n'
            ' if m=="installer" and "installer_metadata_empty" in cmd:print("dirty");sys.exit(0)\n'
            ' cmd=cmd.replace("/system/xbin/su",' + repr(str(fake_su)) + ').replace("/system/bin/sh","/bin/sh").replace("/data/user/0/com.kardinal.vpncontrol",' + repr(str(fake_app)) + ').replace("/proc/$z/mountinfo",' + repr(str(fake_mounts)) + ').replace("/system/bin/stat",'+repr(str(fake_stat))+')\n'
            ' env=os.environ.copy();env["PATH"]=' + repr(str(fake_bin)) + '+":"+env["PATH"];sys.exit(subprocess.run(["/bin/sh","-c",cmd],env=env).returncode)\n'
            'if "id" in a: print("2000")\nelif "getprop" in a: print("35" if a[-1]=="ro.build.version.sdk" else "x86_64" if a[-1]=="ro.product.cpu.abi" else "owned")\n'
            'elif "pm" in a: print("package:/data/app/owned/base.apk")\nelif "sha256sum" in a: print("' + 'a' * 64 + ' /data/app/owned/base.apk")\n'
            'elif "settings" in a: print("" if a[-1]=="global_http_proxy_exclusion_list" else "45635" if m in ("proxy-host-drift","metadata-drift") and a[-1]=="global_http_proxy_port" else "127.0.0.1" if m in ("proxy-host-drift","metadata-drift") and a[-1]=="global_http_proxy_host" else "null")\n'
            'elif cmd=="/system/bin/dumpsys connectivity":\n'
            ' if pathlib.Path('+repr(str(root/'drift-on-service'))+').exists():pathlib.Path('+repr(str(fake_app/'no_backup'/'control-install-sessions'/'retained.json'))+').write_text("FOREIGN_DRIFT")\n'
            ' print("unknown authoritative-service syntax\\n"+"x"*20000)\n'
            'elif "dumpsys" in a: print("Active install sessions:\\n\\nHistorical install sessions:\\n")\n')
        adb.chmod(0o700)
        cli.write_text('#!' + sys.executable + '\nimport sys,json,pathlib\na=sys.argv[1:];m=pathlib.Path(' + repr(str(mode)) + ').read_text()\n'
            'with pathlib.Path(' + repr(str(root / 'cli-calls.jsonl')) + ').open("a") as f:f.write(json.dumps(a)+"\\n")\n'
            'if "routing" in a and "--output" in a:\n p=pathlib.Path(a[a.index("--output")+1]);p.write_text(' + repr(json.dumps(rules)) + ');p.chmod(0o600);d={"format":"json","bytes":p.stat().st_size}\n'
            'elif a[-2:]==["routing","show"]:d={"routing":' + repr(rules) + '}\n'
            'elif a[-2:]==["operations","list"]:d={"operations":[{"final":m!="pending"}]}\n'
            'elif a[-2:]==["settings","show"]:d={"theme":"dark"}\nelif a[-2:]==["source","show"]:d={"mode":"all"}\n'
            'elif a[-2:]==["updates","status"]:d={"phase":"failed","installReceipt":None,"legacyInstallerPins":0,"installRecoveryUnavailable":False}\n'
            'else:d={"runtimeRunning":False,"runtimeObservation":"stopped"}\n'
            'print(json.dumps({"ok":m!="conflict","final":True,"code":"CONFLICT" if m=="conflict" else "OK","controllerId":"fresh-owner","configurationRevision":0,"data":d}))\n')
        cli.chmod(0o700)
        names = sorted(name.removeprefix('bundle/') for name in retirement.REQUIRED_FILES if name.startswith('bundle/'))
        # Manifest order must match the frozen seven-path contract.
        from agent_tools import android_installer_dispatch as dispatch
        names = dispatch._BUNDLE
        files = []; manifest_files = []
        for name in names:
            path = job / 'bundle' / name; write(path, {})
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            files.append({'name': 'bundle/' + name, 'size': path.stat().st_size, 'sha256': digest})
            manifest_files.append({'path': name, 'size': path.stat().st_size, 'sha256': digest})
        manifest = {'schema': 1, 'kind': 'android-installer-reviewed-tools', 'files': manifest_files}
        tree = hashlib.sha256(retirement._canonical(manifest)).hexdigest()
        bundle = {'toolBundleId': 'sha256-64c3b9f8176515770db963dd5858d3044ebd969b8d460272eb9ef3f4c9deb7ac', 'reviewedTreeSha256': tree, 'manifest': manifest}
        expected = {'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557', 'targetArtifactId': original['pair']['targetArtifactId'], 'toolBundle': bundle,
            'files': files, 'adb': str(adb), 'cli': str(cli), 'serial': 'emulator-5554', 'api': 35, 'avd': 'owned','devicePort':45635}
        write(job / 'dispatch.json', expected)
        write(job / 'tool-bundle-owned.json', {'schema': 1, 'toolBundleId': bundle['toolBundleId'], 'reviewedTreeSha256': tree,
            'files': {name: retirement.private_snapshot(job / 'bundle' / name)[1] for name in names}})
        binding = {'retirementCorrelationId': admission_id, 'closingReadbackCorrelationId': closing_corr, 'owner': 'fresh-owner', 'revision': 0,
            'originalIntent': original, 'closingResult': closing, 'lifecycleSha256': hashlib.sha256((out / 'lifecycle-receipt.json').read_bytes()).hexdigest(),
            'localLeasePin': {'sha256': '9' * 64, 'generation': [1, 2, 3, 4, 5, 384, os.getuid(), 1]}}
        for path in root.rglob('*'):
            if path.is_dir(): path.chmod(0o700)
        admitted_pins = {}
        def call(action='admit', proof_hash=None, overrides=None):
            b = {**binding, **({'admittedProofSha256': proof_hash} if proof_hash else {})}
            if proof_hash:
                b['admittedProofPin'] = admitted_pins[proof_hash]
            packet = {**expected, 'retirementBinding': b, **(overrides or {})}
            source = retirement.remote_source()
            if action in ('diagnose','diagnose-service','diagnose-metadata','diagnose-os'):
                packet['diagnosticBinding'] = {'diagnosticCorrelationId': '1de16a80-7cac-45f5-9e9b-68af6c7c36fd',
                    'originalAdapterSha256': hashlib.sha256(source.encode()).hexdigest()}
                if action=='diagnose-metadata':packet['diagnosticBinding']['diagnosticCorrelationId']='335f858b-13f5-49b6-8b48-a45e2760655c'
                source = retirement.remote_diagnostic_source()
                if action in ('diagnose-service','diagnose-metadata','diagnose-os'):
                    prior = {'admissionCorrelationId': admission_id, 'originalCorrelationId': CORR,
                        'originalOutcome': 'unknown', 'effectiveProxy': {'current': {'http_proxy':'null',
                        'global_http_proxy_host':'127.0.0.1','global_http_proxy_port':'45635',
                        'global_http_proxy_pac':'null','global_http_proxy_exclusion_list':''},
                        'baseline': lifecycle['effectiveProxyBaseline'], 'lifecycleSha256': binding['lifecycleSha256']}}
                    prior_path = root/'android-failed-check-retirement-diagnostic-d0fb92e8-34fd-49b1-8e84-8617e524d8eb'/'receipt.json'
                    write(prior_path, prior); prior_path.parent.chmod(0o700)
                    # Inert equivalent fixture pins its own immutable prior receipt;
                    # production source stays pinned to the real protected d0fb SHA.
                    source = retirement.remote_proxy_service_diagnostic_source().replace(
                        '96489c3073bb358ba9a51e61331c6dc67eefae5de7c13f0dd2cff727c0b04eba',
                        hashlib.sha256(prior_path.read_bytes()).hexdigest())
                    packet['diagnosticBinding']['diagnosticSourceSha256'] = hashlib.sha256(retirement.remote_proxy_service_diagnostic_source().encode()).hexdigest()
                    if action in ('diagnose-metadata','diagnose-os'):
                        old={'diagnosticCorrelationId':'10ebc536-9b47-4d0e-a6a6-0e289868aa2d',
                            'diagnosticSourceSha256':hashlib.sha256(retirement.remote_proxy_service_diagnostic_source().encode()).hexdigest(),
                            'currentFailurePhase':'current-public-snapshot','originalOutcome':'unknown'}
                        old_path=root/'android-failed-check-retirement-diagnostic-10ebc536-9b47-4d0e-a6a6-0e289868aa2d'/'receipt.json';write(old_path,old);old_path.parent.chmod(0o700)
                        source=retirement.remote_installer_metadata_diagnostic_source().replace(
                            '96489c3073bb358ba9a51e61331c6dc67eefae5de7c13f0dd2cff727c0b04eba',hashlib.sha256(prior_path.read_bytes()).hexdigest()).replace(
                            '519d6d96c5683e10e08134ad6084ed650a34a4cf3dda5bd075b4d654abe0020a',hashlib.sha256(old_path.read_bytes()).hexdigest())
                        packet['diagnosticBinding']['diagnosticSourceSha256']=hashlib.sha256(retirement.remote_installer_metadata_diagnostic_source().encode()).hexdigest()
                    if action=='diagnose-os':
                        captured=json.loads((root/'metadata-baseline-fixture.json').read_bytes())
                        captured['diagnosticCorrelationId']='d1ad89ea-b504-4421-bc86-408e699f1564'
                        identity_path=root/'android-failed-check-retirement-diagnostic-d1ad89ea-b504-4421-bc86-408e699f1564'/'receipt.json'
                        write(identity_path,captured);identity_path.parent.chmod(0o700)
                        _,identity_gen,identity_sha=retirement.private_snapshot(identity_path)
                        identity={**retirement._OS_METADATA_IDENTITY,'census':captured['installerMetadataCensus'],
                            'receiptPin':{'bytes':identity_path.stat().st_size,'generation':identity_gen,'sha256':identity_sha}}
                        source=retirement.remote_metadata_bound_proxy_service_source().replace(
                            '96489c3073bb358ba9a51e61331c6dc67eefae5de7c13f0dd2cff727c0b04eba',hashlib.sha256(prior_path.read_bytes()).hexdigest()).replace(
                            '519d6d96c5683e10e08134ad6084ed650a34a4cf3dda5bd075b4d654abe0020a',hashlib.sha256(old_path.read_bytes()).hexdigest()).replace(
                            repr(retirement._OS_METADATA_IDENTITY).replace('96489c3073bb358ba9a51e61331c6dc67eefae5de7c13f0dd2cff727c0b04eba',hashlib.sha256(prior_path.read_bytes()).hexdigest()),repr(identity))
                        packet['diagnosticBinding'].update({'diagnosticCorrelationId':'698b2fc4-682b-4980-af8f-359369693c27',
                            'diagnosticSourceSha256':hashlib.sha256(retirement.remote_metadata_bound_proxy_service_source().encode()).hexdigest(),
                            'metadataIdentity':identity,'metadataIdentityCapsulePin':{'sha256':retirement._OS_METADATA_CAPSULE_SHA}})
                    action = 'diagnose'
            run = subprocess.run([sys.executable, '-I', '-B', '-c', source, action, str(root),
                'archlinux', 'api35', CORR, json.dumps(packet)], capture_output=True, timeout=15)
            self.assertEqual(0, run.returncode, run.stderr[-2500:]); result = json.loads(run.stdout)
            if result.get('state') == 'admitted': admitted_pins[result['proofSha256']] = result['proofPin']
            return result
        return temporary, root, out, mode, lease, call

    def test_generated_remote_admission_and_exact_metadata_retirement(self):
        temporary, root, out, mode, lease, call = self.remote_fixture()
        try:
            before = {str(path): path.read_bytes() for path in out.iterdir()}
            admitted = call(); self.assertEqual('admitted', admitted['state'], admitted)
            self.assertTrue(lease.exists()); self.assertEqual('unknown', admitted['originalOutcome'])
            result = call('retire', admitted['proofSha256']); self.assertEqual('retired', result['state'], result)
            self.assertFalse(lease.exists())
            self.assertEqual(before, {str(path): path.read_bytes() for path in out.iterdir()})
            self.assertEqual('unknown', json.loads((root / ('android-failed-check-retirement-' + NEW) / 'terminal.json').read_bytes())['originalOutcome'])
        finally: temporary.cleanup()

    def test_generated_remote_blocks_pending_laterphase_and_installer_before_getter(self):
        for bad in ('pending', 'conflict', 'installer', 'later-phase', 'bad-su', 'su-after-read', 'bad-grammar'):
            temporary, root, out, mode, lease, call = self.remote_fixture()
            try:
                mode.write_text(bad)
                if bad == 'later-phase':
                    path = out / 'phase-download.json'; path.write_text('{}'); path.chmod(0o600)
                result = call(); self.assertEqual('unknown', result['state'], (bad, result)); self.assertTrue(lease.exists())
                self.assertFalse((root / ('android-native-device-api35-' + CORR + '.release-intent')).exists())
                if bad == 'installer':
                    calls = [json.loads(line) for line in (root / 'cli-calls.jsonl').read_text().splitlines()]
                    self.assertFalse(any(a[-2:] == ['updates', 'status'] for a in calls))
            finally: temporary.cleanup()

    def test_generated_remote_restriction_precedes_any_retirement_effect(self):
        temporary, root, out, mode, lease, call = self.remote_fixture()
        try:
            result = call(overrides={'sourceSha': '9' * 40})
            self.assertEqual('reviewed_original_restriction', result['reason'])
            self.assertFalse((root / ('android-failed-check-retirement-' + NEW)).exists())
            self.assertTrue(lease.exists())
        finally: temporary.cleanup()

    def test_diagnostic_retains_current_cause_without_replaying_admission(self):
        temporary, root, out, mode, lease, call = self.remote_fixture('45a379b3-417e-4e00-a8e4-e2e8657c1705')
        try:
            mode.write_text('bad-su')
            old = call(); self.assertEqual('retirement_proof_or_generation_unknown', old['reason'])
            before = {str(path): path.read_bytes() for path in root.rglob('*') if path.is_file()}
            result = call('diagnose')
            self.assertEqual('native-restoration', result['currentFailurePhase'], result)
            self.assertEqual('ValueError', result['errorType'])
            self.assertEqual('unavailable', result['historicalFailureCause'])
            self.assertTrue(lease.exists()); self.assertFalse((root / ('android-native-device-api35-' + CORR + '.release-intent')).exists())
            for path, raw in before.items():
                if path.endswith(('stat-count','cli-calls.jsonl')): continue
                self.assertEqual(raw, Path(path).read_bytes())
            receipt = root / ('android-failed-check-retirement-diagnostic-' + result['diagnosticCorrelationId']) / 'receipt.json'
            self.assertEqual(0o600, receipt.stat().st_mode & 0o777)
            retained = json.loads(receipt.read_bytes())
            self.assertEqual(b'su_identity_unverified', base64.b64decode(retained['exception']['message']['base64']))
            self.assertTrue(retained['commands'])
        finally: temporary.cleanup()

    def test_diagnostic_phase_schema_failure_and_passed_guards_preserve_unknown(self):
        for case in ('schema', 'valid'):
            temporary, root, out, mode, lease, call = self.remote_fixture('45a379b3-417e-4e00-a8e4-e2e8657c1705')
            try:
                if case == 'schema':
                    path=out/'fixture-receipt.json';path.write_bytes(retirement._canonical({'state':'unrecognized','pid':2147483641}));path.chmod(0o600)
                    old=call();self.assertEqual('unknown',old['state'])
                else:
                    old=call();self.assertEqual('admitted',old['state'],old)
                before={str(path):path.read_bytes() for path in out.iterdir()}
                result=call('diagnose');self.assertEqual('diagnosed',result['state'],result)
                self.assertEqual('unknown',result['originalOutcome']);self.assertEqual('unavailable',result['historicalFailureCause'])
                if case=='schema':self.assertEqual('fixture-shutdown',result['currentFailurePhase'])
                else:self.assertIsNone(result['errorType'])
                self.assertEqual(before,{str(path):path.read_bytes() for path in out.iterdir()});self.assertTrue(lease.exists())
            finally:temporary.cleanup()

    def test_proxy_residue_diagnostic_reads_all_five_before_preserving_block(self):
        temporary, root, out, mode, lease, call = self.remote_fixture('45a379b3-417e-4e00-a8e4-e2e8657c1705')
        try:
            mode.write_text('proxy-host-drift');old=call();self.assertEqual('unknown',old['state'])
            result=call('diagnose');self.assertEqual('native-restoration',result['currentFailurePhase'])
            path=root/('android-failed-check-retirement-diagnostic-'+result['diagnosticCorrelationId'])/'receipt.json'
            receipt=json.loads(path.read_bytes());current=receipt['effectiveProxy']['current']
            self.assertEqual({'http_proxy','global_http_proxy_host','global_http_proxy_port','global_http_proxy_pac','global_http_proxy_exclusion_list'},set(current))
            self.assertEqual('127.0.0.1',current['global_http_proxy_host'])
            self.assertEqual('unknown',receipt['originalOutcome']);self.assertTrue(lease.exists())
        finally:temporary.cleanup()

    def test_service_diagnostic_retains_complete_large_unknown_os_format(self):
        temporary, root, out, mode, lease, call = self.remote_fixture('45a379b3-417e-4e00-a8e4-e2e8657c1705')
        try:
            mode.write_text('proxy-host-drift'); call()
            result = call('diagnose-service')
            path = root / ('android-failed-check-retirement-diagnostic-' + result['diagnosticCorrelationId']) / 'receipt.json'
            receipt = json.loads(path.read_bytes())
            service = receipt['serviceCapture']
            self.assertGreater(service['bytes'], 16384)
            capture = path.parent / service['name']
            self.assertEqual(service['bytes'], capture.stat().st_size)
            self.assertEqual(service['sha256'], hashlib.sha256(capture.read_bytes()).hexdigest())
            self.assertEqual('unknown', receipt['originalOutcome']); self.assertTrue(lease.exists())
        finally: temporary.cleanup()

    def test_metadata_diagnostic_distinguishes_absent_empty_retained_without_updates_getter(self):
        for case in ('absent','empty','retained'):
            temporary, root, out, mode, lease, call = self.remote_fixture('45a379b3-417e-4e00-a8e4-e2e8657c1705')
            try:
                mode.write_text('proxy-host-drift');call()
                sessions=root/'fake-app'/'no_backup'/'control-install-sessions'
                if case=='absent':sessions.rmdir()
                if case=='retained':(sessions/'private-session.json').write_text('PRIVATE_INSTALLER_DATA')
                before={str(path):path.read_bytes() for path in out.iterdir()}
                result=call('diagnose-metadata')
                path=root/('android-failed-check-retirement-diagnostic-'+result['diagnosticCorrelationId'])/'receipt.json'
                receipt=json.loads(path.read_bytes());census=receipt['installerMetadataCensus']
                self.assertEqual('absent' if case=='absent' else 'directory',census['no_backup/control-install-sessions']['kind'])
                self.assertEqual(1 if case=='retained' else 0,len(census['no_backup/control-install-sessions']['entries']))
                self.assertEqual('absent',census['files/control-installs']['kind'])
                calls=[json.loads(line) for line in (root/'cli-calls.jsonl').read_text().splitlines()]
                self.assertFalse(any(words[-2:]==['updates','status'] for words in calls))
                self.assertTrue(lease.exists());self.assertEqual('unknown',receipt['originalOutcome'])
                self.assertEqual(before,{str(path):path.read_bytes() for path in out.iterdir()})
            finally:temporary.cleanup()

    def test_os_observation_has_separate_source_and_no_updates_getter(self):
        source=retirement.remote_metadata_bound_proxy_service_source()
        compile(source,'os-observation','exec')
        import ast
        constants={n.targets[0].id:ast.literal_eval(n.value) for n in ast.parse(source).body[:3]}
        self.assertNotIn("phase='current-public-snapshot'",constants['CHECKS'])
        self.assertIn('metadata_os_census_changed',constants['CHECKS'])
        self.assertIn('/system/bin/dumpsys connectivity',constants['CHECKS'])

    def test_generated_os_observation_retained_metadata_and_drift(self):
        for drift in ('none','before','during'):
            temporary,root,out,mode,lease,call=self.remote_fixture('45a379b3-417e-4e00-a8e4-e2e8657c1705')
            try:
                mode.write_text('proxy-host-drift');call()
                retained=root/'fake-app'/'no_backup'/'control-install-sessions'/'retained.json'
                retained.write_text('PRIVATE_RETAINED_METADATA')
                old=call('diagnose-service')
                self.assertEqual('current-public-snapshot',old['currentFailurePhase'])
                # Existing strict empty-dir guard causally blocks OS observation.
                self.assertIsNone(old['serviceCapture'])
                diagnostic_dir=root/('android-failed-check-retirement-diagnostic-'+old['diagnosticCorrelationId'])
                # Metadata read uses a separate immutable inert correlation.
                baseline=call('diagnose-metadata')
                raw=(root/('android-failed-check-retirement-diagnostic-'+baseline['diagnosticCorrelationId'])/'receipt.json').read_bytes()
                (root/'metadata-baseline-fixture.json').write_bytes(raw)
                if drift=='before':retained.write_text('CHANGED_RETAINED_METADATA')
                if drift=='during':(root/'drift-on-service').touch()
                before=retained.read_bytes();original={str(p):p.read_bytes() for p in out.iterdir()}
                result=call('diagnose-os')
                receipt=json.loads((root/('android-failed-check-retirement-diagnostic-'+result['diagnosticCorrelationId'])/'receipt.json').read_bytes())
                if drift=='before':
                    self.assertEqual('metadata-os-census-admission',result['currentFailurePhase'])
                    self.assertIsNone(result['serviceCapture'])
                elif drift=='during':
                    self.assertEqual('metadata-os-closing-guard',result['currentFailurePhase'])
                    self.assertIsNotNone(receipt['exception'])
                else:
                    self.assertEqual('metadata-os-closing-guard',result['currentFailurePhase'],receipt.get('exception'))
                    self.assertIsNone(receipt['exception'])
                    self.assertGreater(result['serviceCapture']['bytes'],16384)
                    self.assertEqual('unavailable',result['serviceCapture']['historicalMetadataEquality'])
                run=subprocess.run([sys.executable,'-I','-B','-c',retirement.remote_metadata_bound_proxy_collector_source(),str(root),result['diagnosticCorrelationId'],'status','0','null',hashlib.sha256(retirement.remote_metadata_bound_proxy_service_source().encode()).hexdigest()],capture_output=True,timeout=5)
                collected=json.loads(run.stdout)
                self.assertEqual('diagnosed-with-failure' if drift!='none' else 'capture-complete',collected['state'],collected)
                if drift=='none':
                    collector=retirement.remote_metadata_bound_proxy_collector_source()
                    marker=" if read(directory/'receipt.json',4194304)[1]!=receipt_pin:raise ValueError('collector_receipt_changed')"
                    for exchange in (False,True):
                        injected=("\n directory.rename(directory.with_name(directory.name+'-old'));directory.mkdir(mode=0o700);(directory/'receipt.json').write_bytes(raw);(directory/'receipt.json').chmod(0o600)" if exchange else "\n directory.chmod(0o755)")
                        raced=collector.replace(marker,marker+injected,1)
                        run=subprocess.run([sys.executable,'-I','-B','-c',raced,str(root),result['diagnosticCorrelationId'],'status','0','null',hashlib.sha256(retirement.remote_metadata_bound_proxy_service_source().encode()).hexdigest()],capture_output=True,timeout=5)
                        self.assertEqual('unknown',json.loads(run.stdout)['state'])
                        target=root/('android-failed-check-retirement-diagnostic-'+result['diagnosticCorrelationId'])
                        if not exchange:target.chmod(0o700)

                self.assertEqual(b'FOREIGN_DRIFT' if drift=='during' else before,retained.read_bytes());self.assertTrue(lease.exists())
                self.assertEqual(original,{str(p):p.read_bytes() for p in out.iterdir()})
                calls=[json.loads(line) for line in (root/'cli-calls.jsonl').read_text().splitlines()]
                self.assertFalse(any(words[-2:]==['updates','status'] for words in calls))
            finally:temporary.cleanup()

    def test_fixed_metadata_identity_collector_pins_full_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();diag='d1ad89ea-b504-4421-bc86-408e699f1564'
            directory=root/('android-failed-check-retirement-diagnostic-'+diag);directory.mkdir(mode=0o700)
            source_sha='f325d70e54c3012a8e24e3efb5fc96e7e31fae273cdf8a1056d3def3c80d381f'
            census={'no_backup/control-install-sessions':{'kind':'directory','generation':'fixed-private-generation','entries':[{'name':'retained','generation':'retained-generation'}]},'files/control-installs':{'kind':'absent','generation':'','entries':[]}}
            value={'diagnosticCorrelationId':diag,'diagnosticSourceSha256':source_sha,'admissionCorrelationId':'45a379b3-417e-4e00-a8e4-e2e8657c1705','originalCorrelationId':CORR,'originalOutcome':'unknown','exception':None,'currentFailurePhase':'metadata-final-input-guard','installerMetadataCensus':census}
            path=directory/'receipt.json';path.write_bytes(retirement._canonical(value));path.chmod(0o600)
            source=retirement._METADATA_IDENTITY_COLLECT.replace('72e6a5c8b34d58e51b95517c070e45cc0cb905911122f35d334f1c8754e35e02',hashlib.sha256(path.read_bytes()).hexdigest())
            def call():
                run=subprocess.run([sys.executable,'-I','-B','-c','exec('+repr(source)+')',str(root),diag,'status','0','null',source_sha],capture_output=True,check=True)
                return json.loads(run.stdout)
            result=call();self.assertEqual('collected',result['state']);self.assertEqual(census,result['census'])
            self.assertEqual('unavailable',result['historicalMetadataEquality'])
            path.write_bytes(path.read_bytes()+b' ');self.assertEqual('unknown',call()['state'])

    def test_metadata_identity_closing_parent_mode_and_replacement_races_refuse(self):
        for race in ('chmod','replacement'):
            with self.subTest(race=race),tempfile.TemporaryDirectory() as temp:
                root=Path(temp).resolve();diag='d1ad89ea-b504-4421-bc86-408e699f1564';directory=root/('android-failed-check-retirement-diagnostic-'+diag);directory.mkdir(mode=0o700)
                source_sha='f325d70e54c3012a8e24e3efb5fc96e7e31fae273cdf8a1056d3def3c80d381f'
                value={'diagnosticCorrelationId':diag,'diagnosticSourceSha256':source_sha,'admissionCorrelationId':'45a379b3-417e-4e00-a8e4-e2e8657c1705','originalCorrelationId':CORR,'originalOutcome':'unknown','exception':None,'currentFailurePhase':'metadata-final-input-guard','installerMetadataCensus':{'no_backup/control-install-sessions':{'kind':'directory','generation':'private','entries':[]},'files/control-installs':{'kind':'absent','generation':'','entries':[]}}}
                path=directory/'receipt.json';path.write_bytes(retirement._canonical(value));path.chmod(0o600)
                source=retirement._METADATA_IDENTITY_COLLECT.replace('72e6a5c8b34d58e51b95517c070e45cc0cb905911122f35d334f1c8754e35e02',hashlib.sha256(path.read_bytes()).hexdigest())
                # Exercise the real generated closing sequence: exchange occurs
                # AFTER its final protected receipt read, before result emission.
                marker=" if read(directory/'receipt.json',4194304)[1]!=pin:raise ValueError('metadata_identity_generation_changed')"
                mutation=" directory.chmod(0o755)" if race=='chmod' else " saved=directory.with_name(directory.name+'-saved');directory.rename(saved);directory.mkdir(mode=0o700);(directory/'receipt.json').write_bytes(raw);(directory/'receipt.json').chmod(0o600)"
                self.assertIn(marker,source);source=source.replace(marker,marker+'\n'+mutation)
                result=subprocess.run([sys.executable,'-I','-B','-c','exec('+repr(source)+')',str(root),diag,'status','0','null',source_sha],capture_output=True,check=True)
                self.assertEqual('unknown',json.loads(result.stdout)['state'])

    def test_metadata_census_instability_keeps_original_unknown_without_getter(self):
        temporary, root, out, mode, lease, call=self.remote_fixture('45a379b3-417e-4e00-a8e4-e2e8657c1705')
        try:
            mode.write_text('proxy-host-drift');call();mode.write_text('metadata-drift')
            result=call('diagnose-metadata');self.assertEqual('installer-metadata-census',result['currentFailurePhase'])
            self.assertEqual('ValueError',result['errorType']);self.assertTrue(lease.exists())
            receipt=json.loads((root/('android-failed-check-retirement-diagnostic-'+result['diagnosticCorrelationId'])/'receipt.json').read_bytes())
            self.assertEqual('metadata_census_changed_between_reads',base64.b64decode(receipt['exception']['message']['base64']).decode())
            self.assertEqual('unknown',receipt['originalOutcome'])
            calls=[json.loads(line) for line in (root/'cli-calls.jsonl').read_text().splitlines()]
            self.assertFalse(any(words[-2:]==['updates','status'] for words in calls))
        finally:temporary.cleanup()

    def test_diagnostic_transport_retains_actual_stderr_before_unknown_classification(self):
        from agent_tools import ssh_transfer
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp).resolve() / 'transport.json'
            argv = [sys.executable, '-c', "import sys;sys.stderr.write('PRIVATE_CAUSAL_TRANSPORT_ERROR');sys.exit(255)"]
            code, stdout = retirement.diagnostic_transport(argv, path, {"diagnosticCorrelationId": NEW}, 5)
            self.assertEqual((255, b''), (code, stdout))
            # The diagnostic contract needs the original error retained privately.
            self.assertTrue(path.exists())
            import base64
            capsule = json.loads(path.read_bytes())
            self.assertEqual(b'PRIVATE_CAUSAL_TRANSPORT_ERROR', base64.b64decode(capsule['stderr']['base64']))
            self.assertTrue(capsule['stderr']['complete'])
            self.assertEqual('unknown', capsule['originalOutcome'])
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(ValueError): retirement.diagnostic_transport(argv, path, {}, 5)

    def test_existing_service_receipt_collection_preserves_failed_guard_and_complete_chunks(self):
        for failure in (False, True):
            temporary, root, out, mode, lease, call = self.remote_fixture('45a379b3-417e-4e00-a8e4-e2e8657c1705')
            try:
                mode.write_text('proxy-host-drift');call()
                if failure:mode.write_text('bad-su')
                result=call('diagnose-service');diag=result['diagnosticCorrelationId']
                service_hash=hashlib.sha256(retirement.remote_proxy_service_diagnostic_source().encode()).hexdigest()
                def collect(kind='status', offset=0, pin=None):
                    run=subprocess.run([sys.executable,'-I','-B','-c',retirement._PROXY_SERVICE_COLLECT,
                        str(root),diag,kind,str(offset),json.dumps(pin),service_hash],capture_output=True,check=True)
                    self.assertLessEqual(len(run.stdout),4096)
                    return json.loads(run.stdout)
                status=collect()
                self.assertEqual('diagnosed-with-failure' if failure else 'capture-complete',status['state'])
                self.assertEqual('unknown',status['originalOutcome']);self.assertTrue(lease.exists())
                if failure:
                    self.assertIsNone(status['serviceCapture']);self.assertEqual('ValueError',status['errorType'])
                else:
                    service=status['serviceCapture'];pin={'generation':service['generation'],'sha256':service['sha256'],'bytes':service['bytes']}
                    import base64
                    data=b''
                    while len(data)<service['bytes']:
                        chunk=collect('connectivity',len(data),pin);data+=base64.b64decode(chunk['chunk'])
                    self.assertEqual(service['sha256'],hashlib.sha256(data).hexdigest())
                    wrong={**pin,'sha256':'0'*64};self.assertEqual('unknown',collect('connectivity',0,wrong)['state'])
            finally:temporary.cleanup()

    def local_retirement_fixture(self):
        temporary = tempfile.TemporaryDirectory(); root = Path(temporary.name).resolve(); root.chmod(0o700)
        directory = retirement._local_directory(root, NEW); directory.mkdir(mode=0o700)
        original_dir = root / '.rag_index' / 'android-installer-dispatch' / CORR; original_dir.mkdir(mode=0o700, parents=True)
        dispatch = {'correlationId': CORR, 'host': 'archlinux', 'device': 'api35',
            'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557',
            'toolBundleId': 'sha256-64c3b9f8176515770db963dd5858d3044ebd969b8d460272eb9ef3f4c9deb7ac'}
        product = {'correlationId': CORR, 'pair': {'sourceSha': dispatch['sourceSha']}}
        def write(path, value): path.write_bytes(retirement._canonical(value)); path.chmod(0o600)
        write(original_dir / 'dispatch.json', dispatch); write(original_dir / 'intent.json', product)
        # Use canonical existing shared-directory helper rather than guess its name.
        from agent_tools import android_installer_dispatch as original_dispatch
        shared = original_dispatch._shared_directory(root)
        lease = shared / 'lease-archlinux-api35.json'; write(lease, {'owner': 'android-installer', 'host': 'archlinux', 'device': 'api35', 'correlationId': CORR})
        _, gen, sha = retirement.private_snapshot(lease)
        binding = {'retirementCorrelationId': NEW, 'originalIntent': product, 'localLeasePin': {'generation': gen, 'sha256': sha}}
        local = {'dispatch': dispatch, 'binding': binding}
        for name, key in [('dispatch.json', 'dispatchPin'), ('intent.json', 'intentPin')]:
            _, gen, sha = retirement.private_snapshot(original_dir / name); local[key] = {'generation': gen, 'sha256': sha}
        write(directory / 'intent.json', local)
        measured = proof(); proof_sha = hashlib.sha256(retirement._canonical(measured)).hexdigest()
        write(directory / 'admitted.json', {'state': 'admitted', 'retirementCorrelationId': NEW, 'proofSha256': proof_sha, 'proofPin': {'sha256': proof_sha}, 'proof': measured})
        return temporary, root, directory

    def test_collector_actual_nested_build_callsite_accepts_flat_source_carrier(self):
        from agent_tools import ssh_transport
        from pathlib import PurePosixPath
        import shlex
        temporary, root, old_directory = self.local_retirement_fixture()
        try:
            admission='45a379b3-417e-4e00-a8e4-e2e8657c1705'; directory=old_directory.with_name(admission)
            old_directory.rename(directory)
            local=json.loads((directory/'intent.json').read_bytes());local['dispatch']['fixtureRoot']=str(root/'missing-remote')
            (directory/'intent.json').write_bytes(retirement._canonical(local))
            _,gen,sha=retirement.private_snapshot(directory/'intent.json',65536)
            diag='1de16a80-7cac-45f5-9e9b-68af6c7c36fd'
            request=directory/('diagnostic-'+diag+'.json')
            request.write_bytes(retirement._canonical({'diagnosticSourceSha256':hashlib.sha256(retirement.remote_proxy_service_diagnostic_source().encode()).hexdigest(),
                'admissionIntentPin':{'generation':gen,'sha256':sha}}));request.chmod(0o600)
            config=ssh_transport.SshConfig(root,{
                'gateway':ssh_transport.SshHost('gateway','example.test',22,'fixture',root/'key',root/'known'),
                'archlinux':ssh_transport.SshHost('archlinux','archlinux',22,'fixture',root/'key',PurePosixPath('/private/known'),
                    transport='nested',gateway='gateway',remote_host_alias='archlinux',remote_control_path=PurePosixPath('/private/master'))})
            def transport(argv, *_args):
                self.assertTrue(all('\n' not in word for word in argv))
                nested=shlex.split(argv[-1]);command=shlex.split(nested[-1])
                self.assertEqual('exec('+repr(retirement._PROXY_SERVICE_COLLECT)+')',command[command.index('-c')+1])
                # Execute ONLY the decoded Python collector locally, never SSH.
                result=subprocess.run([sys.executable,*command[1:]],capture_output=True,check=True)
                return result.returncode,result.stdout
            with mock.patch.object(ssh_transport,'load_config',return_value=config), mock.patch.object(retirement,'diagnostic_transport',side_effect=transport) as run:
                result=retirement.collect_proxy_service_receipt(root,diag,NEW)
                self.assertEqual('absent',result['state']);run.assert_called_once()
        finally:temporary.cleanup()

    def test_diagnostic_transport_unreapable_child_keeps_bounded_partial_capsule(self):
        import io
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp).resolve()/'transport.json'
            class Child:
                stdout=io.BytesIO();stderr=io.BytesIO()
                def poll(self):return None
                def kill(self):pass
                def wait(self,timeout=None):
                    if timeout is None:raise AssertionError('unbounded_wait')
                    raise subprocess.TimeoutExpired('fixed-diagnostic',timeout)
            with mock.patch.object(subprocess,'Popen',return_value=Child()), mock.patch('select.select',side_effect=ValueError('fixed_failure')):
                result=retirement.diagnostic_transport(['fixed-diagnostic'],path,{},5)
            self.assertEqual((None,b''),result)
            capsule=json.loads(path.read_bytes());self.assertEqual('unknown',capsule['originalOutcome'])
            self.assertEqual('not-reaped',capsule['processReap'])
            self.assertFalse(capsule['stdout']['complete'])

    def test_local_retire_revalidates_original_before_native_call(self):
        temporary, root, directory = self.local_retirement_fixture()
        try:
            value = json.loads((directory / 'intent.json').read_bytes()); value['dispatch']['sourceSha'] = '9' * 40
            (directory / 'intent.json').write_bytes(retirement._canonical(value))
            with mock.patch.object(retirement, '_call') as call:
                with self.assertRaises(ValueError): retirement.retire(root, NEW)
                call.assert_not_called()
        finally: temporary.cleanup()

    def test_local_admission_replacement_before_call_prevents_remote_effect(self):
        temporary, root, directory = self.local_retirement_fixture()
        try:
            save = retirement._save
            def replace(path, value):
                save(path, value)
                if path.name == 'release-request.json':
                    admitted = directory / 'admitted.json'; replacement = directory / 'replacement'
                    replacement.write_bytes(admitted.read_bytes()); replacement.chmod(0o600); replacement.replace(admitted)
            with mock.patch.object(retirement, '_save', side_effect=replace), mock.patch.object(retirement, '_call') as call:
                with self.assertRaises(ValueError): retirement.retire(root, NEW)
                call.assert_not_called()
        finally: temporary.cleanup()

    def test_generated_remote_rejects_same_byte_input_generation_replacement(self):
        temporary, root, out, mode, lease, call = self.remote_fixture()
        try:
            admitted = call(); self.assertEqual('admitted', admitted['state'], admitted)
            path = out / 'lifecycle-receipt.json'; replacement = out / 'replacement'
            replacement.write_bytes(path.read_bytes()); replacement.chmod(0o600); replacement.replace(path)
            result = call('retire', admitted['proofSha256'])
            self.assertEqual('unknown', result['state'], result); self.assertTrue(lease.exists())
            self.assertFalse((root / ('android-native-device-api35-' + CORR + '.release-intent')).exists())
        finally: temporary.cleanup()

    def test_snapshot_measures_getters_and_rejects_pending_update_and_conflict(self):
        calls = []
        data = {("status",): {"runtimeRunning": False, "runtimeObservation": "stopped"},
            ("operations", "list"): {"operations": [{"final": True}]},
            ("settings", "show"): {"theme": "dark"}, ("source", "show"): {"mode": "all"},
            ("updates", "status"): {"phase": "failed", "installReceipt": None,
                "installRecoveryUnavailable": False, "legacyInstallerPins": 0}}
        def read(*words):
            calls.append(words)
            return {"ok": True, "final": True, "code": "OK", "controllerId": "fresh-owner",
                    "configurationRevision": 0, "data": data[words]}
        routing = {"type": "vpn_control_routing_rules", "version": 7,
            "rules": {"ignore_rules": False, "block_quic_udp_443": False,
                      "proxy_packages": [], "direct_domain_suffixes": []}}
        observed = retirement.measure_public_snapshot(read, lambda: routing, "fresh-owner", 0, "a" * 64, lambda: calls.append(("installer-preflight",)))
        self.assertTrue(observed["installerIdle"])
        self.assertEqual({("status",), ("operations", "list"), ("settings", "show"),
                          ("source", "show"), ("updates", "status"), ("installer-preflight",)}, set(calls))
        self.assertLess(calls.index(("installer-preflight",)), calls.index(("updates", "status")))
        data[("updates", "status")]["phase"] = "ready"
        with self.assertRaises(ValueError): retirement.measure_public_snapshot(read, lambda: routing, "fresh-owner", 0, "a" * 64, lambda: None)
        with self.assertRaises(ValueError):
            retirement.measure_public_snapshot(lambda *words: {"ok": False, "code": "CONFLICT",
                "controllerId": "fresh-owner", "configurationRevision": 0}, lambda: routing, "fresh-owner", 0, "a" * 64, lambda: None)

    def test_first_check_failure_does_not_require_success_probe_or_same_owner(self):
        value = retirement.validate_proof(proof())
        self.assertEqual("unknown", value["originalOutcome"])
        self.assertEqual("fresh-owner", value["snapshots"][0]["owner"])

    def test_unavailable_original_settings_never_claimed_unchanged(self):
        value = retirement.validate_proof(proof())
        self.assertEqual("unavailable", value["historicalSettingsSource"])
        self.assertFalse(value["productDataMutationAllowed"])
        self.assertNotIn("settingsSha256", value["opening"])
        for claim in ("unchanged", "restored", "verified"):
            altered = proof(); altered["historicalSettingsSource"] = claim
            with self.assertRaises(ValueError): retirement.validate_proof(altered)

    def test_every_effect_or_missing_evidence_blocks(self):
        for phase in ("download", "noninteractive", "interactive"):
            value = proof(); value["phases"][phase] = True
            with self.assertRaises(ValueError): retirement.validate_proof(value)
        for field in ("freshOwnerAdmission", "nativeRestored", "probeAbsent"):
            value = proof(); value[field] = False
            with self.assertRaises(ValueError): retirement.validate_proof(value)
        for field in ("settingsSha256", "sourceSha256", "routingSha256", "packageSha256"):
            value = proof(); value["snapshots"][1][field] = "9" * 64
            with self.assertRaises(ValueError): retirement.validate_proof(value)

    def test_routing_timestamps_ignored_but_full_rules_compared(self):
        value = {"type": "vpn_control_routing_rules", "version": 7, "exported_at": 1,
                 "rules": {"ignore_rules": False, "block_quic_udp_443": False,
                           "proxy_packages": ["x"], "direct_domain_suffixes": ["example.com"]}}
        other = copy.deepcopy(value); other["exported_at"] = 2
        self.assertEqual(retirement.routing_digest(value), retirement.routing_digest(other))
        other["rules"]["proxy_packages"].append("y")
        self.assertNotEqual(retirement.routing_digest(value), retirement.routing_digest(other))

    def test_durable_fence_precedes_unlink_and_pins_exact_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700)
            lease = root / "lease"; record = root / "release-intent"; fence = root / "retirement.json"
            expected = {"owner": "android-installer", "host": "archlinux", "device": "api35", "correlationId": CORR}
            lease.write_text(json.dumps(expected)); lease.chmod(0o600)
            _, generation, digest = retirement.private_snapshot(lease)
            retirement.release_fenced(lease, record, fence, expected, generation, digest, proof())
            self.assertFalse(lease.exists())
            self.assertEqual(expected, json.loads(record.read_bytes()))
            self.assertEqual("unknown", json.loads(fence.read_bytes())["proof"]["originalOutcome"])
            self.assertEqual(0o600, fence.stat().st_mode & 0o777)

    def test_rewritten_identical_lease_is_not_released(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700); lease = root / "lease"
            expected = {"owner": "android-installer", "host": "archlinux", "device": "api35", "correlationId": CORR}
            lease.write_text(json.dumps(expected)); lease.chmod(0o600)
            _, generation, digest = retirement.private_snapshot(lease)
            replacement = root / "replacement"; replacement.write_bytes(lease.read_bytes()); replacement.chmod(0o600)
            replacement.replace(lease)
            with self.assertRaises(ValueError):
                retirement.release_fenced(lease, root / "release-intent", root / "fence", expected, generation, digest, proof())
            self.assertTrue(lease.exists()); self.assertFalse((root / "fence").exists())

    def test_all_required_immutable_inputs_must_be_pinned(self):
        for name in retirement.REQUIRED_FILES:
            value = proof(); del value["files"][name]
            with self.assertRaises(ValueError): retirement.validate_proof(value)
        value = proof(); value["files"]["output/intent.json"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError): retirement.validate_proof(value)

    def test_fence_failure_does_not_unlink_or_create_release_record(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700); lease = root / "lease"
            expected = {"owner": "android-installer", "host": "archlinux", "device": "api35", "correlationId": CORR}
            lease.write_text(json.dumps(expected)); lease.chmod(0o600)
            _, generation, digest = retirement.private_snapshot(lease)
            with mock.patch.object(retirement, "_create", side_effect=OSError("disk failure")):
                with self.assertRaises(OSError):
                    retirement.release_fenced(lease, root / "release-intent", root / "fence", expected, generation, digest, proof())
            self.assertTrue(lease.exists()); self.assertFalse((root / "release-intent").exists())

    def test_hardlinks_symlinks_and_replay_are_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700); lease = root / "lease"
            expected = {"owner": "android-installer", "host": "archlinux", "device": "api35", "correlationId": CORR}
            lease.write_text(json.dumps(expected)); lease.chmod(0o600)
            alias = root / "alias"; alias.symlink_to(lease)
            with self.assertRaises(OSError): retirement.private_snapshot(alias)
            alias.unlink(); os.link(lease, alias)
            with self.assertRaises(ValueError): retirement.private_snapshot(lease)
            alias.unlink(); _, generation, digest = retirement.private_snapshot(lease)
            fence = root / "fence"; fence.write_text("{}"); fence.chmod(0o600)
            with self.assertRaises(ValueError):
                retirement.release_fenced(lease, root / "release-intent", fence, expected, generation, digest, proof())
            self.assertTrue(lease.exists())

    def test_named_lease_exchange_after_open_blocks_fencing(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve(); root.chmod(0o700); lease = root / "lease"
            expected = {"owner": "android-installer", "host": "archlinux", "device": "api35", "correlationId": CORR}
            lease.write_text(json.dumps(expected)); lease.chmod(0o600)
            _, generation, digest = retirement.private_snapshot(lease)
            original_fstat = os.fstat; exchanged = False
            def fstat(fd):
                nonlocal exchanged
                info = original_fstat(fd)
                if info.st_ino == generation[1] and not exchanged:
                    exchanged = True; lease.rename(root / "old-lease")
                    lease.write_text(json.dumps(expected)); lease.chmod(0o600)
                return info
            with mock.patch.object(retirement.os, "fstat", side_effect=fstat):
                with self.assertRaises(ValueError):
                    retirement.release_fenced(lease, root / "release", root / "fence", expected, generation, digest, proof())
            self.assertTrue(lease.exists()); self.assertFalse((root / "fence").exists())

    def test_parent_replacement_after_fence_never_unlinks_either_lease(self):
        with tempfile.TemporaryDirectory() as raw:
            base = Path(raw).resolve(); base.chmod(0o700); root = base / "parent"; root.mkdir(mode=0o700)
            lease = root / "lease"
            expected = {"owner": "android-installer", "host": "archlinux", "device": "api35", "correlationId": CORR}
            lease.write_text(json.dumps(expected)); lease.chmod(0o600)
            _, generation, digest = retirement.private_snapshot(lease); create = retirement._create
            def replace(parent, name, value):
                create(parent, name, value)
                if name == "fence":
                    root.rename(base / "old-parent"); root.mkdir(mode=0o700)
                    lease.write_text(json.dumps(expected)); lease.chmod(0o600)
            with mock.patch.object(retirement, "_create", side_effect=replace):
                with self.assertRaises(ValueError):
                    retirement.release_fenced(lease, root / "release", root / "fence", expected, generation, digest, proof())
            self.assertTrue(lease.exists()); self.assertTrue((base / "old-parent" / "lease").exists())
