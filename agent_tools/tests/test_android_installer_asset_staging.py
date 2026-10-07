"""Routine causal fixed asset receiver tests; no SSH or original custody reads.

TempFS uses synthetic APK literals in an isolated fixture programme, preserving
all receiver statements. Child-only OS UID/GID and boot seams are explicit; real
FD/mode/nlink/bytes/parents and stream behavior remain actual. Native root case
is separately skipped when not running privileged Linux.
"""
import copy,hashlib,json,os,stat,subprocess,sys,tempfile,unittest,uuid
from pathlib import Path
from unittest import mock
from agent_tools import android_installer_asset_staging as staging

CORR='34fa91f1-9215-4416-b4cf-af66c899988b'
BOOT='32fe7f51-a662-4287-a0e6-4b3cdb533086'

class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.data={'base.apk':b'fixture-base','target.apk':b'fixture-target','ca.pem':b'fixture-ca','leaf.pem':b'fixture-leaf','key.pem':b'fixture-key'}
        self.base=staging.sha(self.data['base.apk']);self.target=staging.sha(self.data['target.apk'])
        facts={'sourceSha':staging.PRODUCT,'baseArtifactId':'sha256-'+self.base,'targetArtifactId':'sha256-'+self.target,'targetSha256':self.target,'baseVersion':'2.2.2','targetVersion':'2.2.3','baseCode':16840,'targetCode':16860,'targetSize':len(self.data['target.apk'])}
        receipt={'schema':1,'kind':'android-disposable-fixture-tls','testOnly':True,'campaignId':CORR,'sourceFacts':facts,'files':{origin:{'bytes':len(self.data[dest]),'sha256':staging.sha(self.data[dest])}for dest,origin in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem')]}}
        self.data['receipt.json']=staging.canonical(receipt)
        self.manifest={'schema':1,'correlationId':CORR,'productSourceSha':staging.PRODUCT,'files':[{'name':n,'size':len(self.data[n]),'sha256':staging.sha(self.data[n])}for n in staging.NAMES]}
        # Exact controlled artifact literal seam only. No receiver function,
        # guard condition, metadata/byte/stream branch is replaced.
        self.source=staging.RECEIVER.replace(staging.BASE,self.base).replace(staging.TARGET,self.target)
        self.source=self.source.replace("m['files'][0]['size']==45026948", "m['files'][0]['size']==12").replace("m['files'][1]['size']==45026948", "m['files'][1]['size']==14").replace("facts['targetSize']==45026948", "facts['targetSize']==14")
        self.prefix='''import os,builtins,types,io
real_stat=os.stat;real_fstat=os.fstat
# Explicit root-principal metadata seam only, child process isolated.
def rootmeta(s):
 d={n:getattr(s,n)for n in dir(s)if n.startswith('st_')};d['st_uid']=0;d['st_gid']=0;return types.SimpleNamespace(**d)
os.stat=lambda *a,**k:rootmeta(real_stat(*a,**k))
os.fstat=lambda *a,**k:rootmeta(real_fstat(*a,**k))
os.getuid=lambda:0;os.geteuid=lambda:0;os.getgid=lambda:0;os.getegid=lambda:0
real_open=builtins.open
builtins.open=lambda p,*a,**k:io.StringIO('''+repr(BOOT+'\n')+''')if p=='/proc/sys/kernel/random/boot_id'else real_open(p,*a,**k)
'''
        self.prepared={'correlationId':CORR,'receiverRoot':str(self.root),'manifest':self.manifest,'manifestSha256':staging.sha(staging.canonical(self.manifest))}

    def run_receiver(self,wire=None,manifest=None,source=None,prefix=None):
        manifest=manifest or self.manifest
        wire=staging.canonical(manifest)+b''.join(self.data[n]for n in staging.NAMES)if wire is None else wire
        p=subprocess.run([sys.executable,'-I','-B','-c',(self.prefix if prefix is None else prefix)+(self.source if source is None else source),str(self.root),CORR,staging.sha(staging.canonical(manifest)),BOOT],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr.decode());self.assertEqual(p.stderr,b'');return json.loads(p.stdout),p.stdout

    def test_real_child_complete_custody_and_reentry_unknown(self):
        value,raw=self.run_receiver();self.assertEqual(value['state'],'complete');self.assertFalse(value['leaseIssued']);self.assertFalse(value['nativeInstallerStarted'])
        out=staging.project(self.prepared,raw,b'',0,{'stdout':True,'stderr':True});self.assertEqual(out['state'],'complete');self.assertNotIn('lease',out['authority'])
        leaf=self.root/('android-complete-update-inputs-'+CORR)
        self.assertEqual(set(p.name for p in leaf.iterdir()),set(staging.NAMES));self.assertFalse((leaf/'ca-key.pem').exists())
        for n in staging.NAMES:self.assertEqual((leaf/n).read_bytes(),self.data[n]);self.assertEqual(stat.S_IMODE((leaf/n).stat().st_mode),0o600)
        second,_=self.run_receiver();self.assertEqual(second['state'],'unknown');self.assertEqual(second['code'],'asset_leaf_consumed')
        self.assertFalse((self.root/'android-native-device-android-api35.lease').exists())

    def test_actual_receiver_duplicate_authority_refused(self):
        _,raw=self.run_receiver()
        contradictory=b'{"leaseIssued":true,'+raw[1:]
        self.assertEqual(staging.project(self.prepared,contradictory,b'',0,{'stdout':True,'stderr':True})['state'],'unknown')

    def test_actual_receiver_duplicate_manifest_and_receipt_refused(self):
        header=b'{"schema":false,'+staging.canonical(self.manifest)[1:]
        child=subprocess.run([sys.executable,'-I','-B','-c',self.prefix+self.source,str(self.root),CORR,staging.sha(header),BOOT],input=header+b''.join(self.data[n]for n in staging.NAMES),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(child.returncode,0);self.assertEqual(child.stderr,b'');value=json.loads(child.stdout);self.assertEqual(value['code'],'asset_json_duplicate');self.assertFalse(value['partialLeafRetained'])
        receipt=b'{"testOnly":false,'+self.data['receipt.json'][1:];self.data['receipt.json']=receipt
        self.manifest['files'][-1].update(size=len(receipt),sha256=staging.sha(receipt))
        value,_=self.run_receiver();self.assertEqual(value['state'],'unknown');self.assertEqual(value['code'],'asset_json_duplicate');self.assertTrue(value['partialLeafRetained'])
        with self.assertRaisesRegex(ValueError,'asset_json_duplicate'):staging.decode(receipt)

    def test_actual_mixed_principal_receiver_boundary(self):
        # Actual BaselineGuard constructor+call and exact emitted parent entry.
        # OS root/UID metadata, controlled JVM/ADB observations, source archive
        # bindings and raw transport are declared local seams. No guard body or
        # admission DTO is replaced; every byte/inode/mode check remains actual.
        import base64,contextlib,io,types
        from agent_tools import android_installer_component_bundle as bundle
        from agent_tools.tests import test_android_installer_component_bundle as bm
        from agent_tools.tests.test_android_component_receiver_timeout import ReceiverTimeout
        f=bm.BundleTests();f.setUp();self.addCleanup(f.tearDown)
        selected,backend,args,*_=f.api35_fixture();f.actual_factory_functions(backend,'api35')
        (f.root/'base.apk').write_bytes(self.data['base.apk'])
        backend['GETTER']['packageSha256']=self.base;backend['EXTERNAL']['getterIdentity']['packageSha256']=self.base
        for name in ('getuid','geteuid','getgid','getegid'):setattr(backend['os'],name,lambda:0)
        backend['os'].getgroups=lambda:[]
        for name in ('setuid','setgid','setgroups'):setattr(backend['os'],name,lambda *a:None)
        backend['COMMAND_HOST']=backend['command_host_identity']()
        (f.root/'android-native-device-android-api35.lease').unlink();args.intent_file.unlink()
        root_inode=f.root.stat().st_ino;local_uid=os.getuid();proxy=types.SimpleNamespace(**vars(os))
        proxy.getuid=proxy.geteuid=proxy.getgid=proxy.getegid=lambda:0
        def info(value):
            uid=1000 if value.st_ino==root_inode else 0 if value.st_uid==local_uid else value.st_uid
            return types.SimpleNamespace(**{n:uid if n in ('st_uid','st_gid')else getattr(value,n)for n in dir(value)if n.startswith('st_')})
        proxy.stat=lambda *a,**k:info(os.stat(*a,**k));proxy.fstat=lambda *a,**k:info(os.fstat(*a,**k))
        request={'host':'archlinux','device':'android-api35','correlationId':bm.CORRELATION,'sourceSha':staging.PRODUCT,'expectedOwner':bm.OWNER,'expectedRevision':0,'expectedAvd':'owned-fixture','expectedApi':35,'packageSha256':self.base,'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
        with mock.patch.object(bundle,'os',proxy),mock.patch.object(bm,'os',proxy):
            backend['EXTERNAL']['selectedJdk']=backend['external_jdk']('jdk17')
            (f.root/'root-owned').mkdir(mode=0o700)
            receipt=bundle.prepare(Path.cwd(),f.root/'root-owned'/'stage',bundle.reviewed_tree(Path.cwd())['treeSha256']);selected=bundle.modules(receipt)
            backend.update(COMPONENT_BUNDLE=bundle,COMPONENT_RECEIPT=receipt,COMPONENT_MODULES=selected,ASSET_PARENT_REQUEST=request,ASSET_PARENT_CORRELATION=CORR)
            out=io.StringIO()
            with contextlib.redirect_stdout(out):exec(compile(staging.PARENT_ENTRY,'<actual-parent-entry>','exec',dont_inherit=True),backend)
            raw=out.getvalue().encode()
            prepared,_=f.protected_production_prefix(f.root)
            with mock.patch.object(staging,'BASE',self.base):programme=staging.parent_admission_source(receipt,prepared,request,CORR)
        # Actual retained receiver emits this terminal from a real harmless
        # child carrying the already-source-produced raw; no SSH/sudo invocation.
        transport=ReceiverTimeout()
        terminal,streams=transport.exercise('import sys,base64;sys.stdin.buffer.read();sys.stdout.buffer.write(base64.b64decode('+repr(base64.b64encode(raw).decode())+'))',payload=programme)
        self.assertEqual(bytes(streams[b'out']),raw);self.assertEqual(bytes(streams[b'err']),b'')
        closing={'schema':1,'correlationId':CORR,'sourceClosingVerified':True,'transportTerminalAuthenticated':True,'rawSha256':staging.sha(raw),'rawBytes':len(raw),'programmeSha256':staging.sha(programme)}
        custody=f.root/'local-custody';custody.mkdir(mode=0o700);evidence={}
        blobs={'programme':programme,'raw':raw,'terminal':staging.canonical(terminal),'closing':staging.canonical(closing)}
        for name,blob in blobs.items():
            path=custody/name;path.write_bytes(blob);path.chmod(0o600);evidence[name]=staging.snapshot(path,33554432)
        self.root=f.root;self.prepared['receiverRoot']=str(self.root)
        self.prefix+='os.getgroups=lambda:[]\n'
        mixed=self.prefix+"\nbase_rootmeta=rootmeta\ndef mixed_rootmeta(s):\n value=base_rootmeta(s)\n if s.st_ino=="+str(root_inode)+":value.st_uid=1000;value.st_gid=1000\n return value\nos.stat=lambda *a,**k:mixed_rootmeta(real_stat(*a,**k))\nos.fstat=lambda *a,**k:mixed_rootmeta(real_fstat(*a,**k))\n"
        with mock.patch.object(staging,'CANONICAL_ROOT',str(f.root)),mock.patch.object(staging,'BASE',self.base):
            authority=staging.parent_custody(evidence,CORR,backend['boot'](),programme)
            # Preserve peer's actual coherent-prefix RED. All original raw
            # admission bytes remain genuine, but a forged shorter producer and
            # coherent terminal/closing cannot select their own expectation.
            forged=copy.deepcopy(evidence)
            forged_source=('ASSET_PARENT_REQUEST='+repr(request)+'\nASSET_PARENT_CORRELATION='+repr(CORR)+'\n'+staging.PARENT_ENTRY).encode()
            forged_blobs={'programme':forged_source,'terminal':copy.deepcopy(terminal),'closing':copy.deepcopy(closing)}
            forged_blobs['terminal'].update(sourceBytes=len(forged_source),sourceSha256=staging.sha(forged_source))
            forged_blobs['closing']['programmeSha256']=staging.sha(forged_source)
            for name,body in forged_blobs.items():
                path=custody/('forged-'+name);path.write_bytes(body if type(body)is bytes else staging.canonical(body));path.chmod(0o600);forged[name]=staging.snapshot(path,33554432)
            with self.assertRaisesRegex(ValueError,'asset_parent_producer_changed'):staging.parent_custody(forged,CORR,backend['boot'](),programme)

            for role in evidence:
                bad=copy.deepcopy(evidence);bad[role]['sha256']='0'*64
                with self.assertRaisesRegex(ValueError,'asset_parent_provenance_changed'):staging.parent_custody(bad,CORR,backend['boot'](),programme)
            with self.assertRaisesRegex(ValueError,'asset_parent_provenance_required'):staging.parent_custody(json.loads(raw),CORR,backend['boot'](),programme)
            # Coherently repinned forged receipt frames still fail the actual
            # typed provenance/producer consumer rather than only their hash.
            for role,field,value in [('closing','sourceClosingVerified',False),('terminal','returncode',True),('terminal','sourceSha256','0'*64),('raw','root',str(f.root)+'/foreign'),('raw','owner',True),('raw','guestMutationPerformed',True)]:
                forged=copy.deepcopy(evidence);body=json.loads(blobs[role]);body[field]=value
                path=custody/(role+'-'+field);path.write_bytes(staging.canonical(body));path.chmod(0o600);forged[role]=staging.snapshot(path,33554432)
                with self.assertRaises((ValueError,TypeError)):staging.parent_custody(forged,CORR,backend['boot'](),programme)

        # Source-fixed ROOT and boot literals map only to this measured TempFS.
        source=self.source.replace(staging.CANONICAL_ROOT,str(f.root));authority['bootId']=BOOT
        self.manifest['parentAuthority']=authority
        for mutation in ('root','principal','parent','boot','hash'):
            bad=copy.deepcopy(self.manifest);a=bad['parentAuthority']
            if mutation=='root':a['root']+='/foreign'
            elif mutation=='principal':a['principal']['uid']=True
            elif mutation=='parent':a['parents'][str(f.root)][1]+=1
            elif mutation=='boot':a['bootId']='0'*36
            else:a['programmeSha256']='x'*64
            value,_=self.run_receiver(manifest=bad,source=source,prefix=mixed)
            self.assertEqual(value['state'],'unknown');self.assertFalse(value['partialLeafRetained'])
        no_provenance=copy.deepcopy(self.manifest);no_provenance.pop('parentAuthority')
        value,_=self.run_receiver(manifest=no_provenance,source=source,prefix=mixed)
        self.assertEqual(value['code'],'asset_root_unsafe');self.assertFalse(value['partialLeafRetained'])
        value,raw=self.run_receiver(source=source,prefix=mixed)
        self.assertEqual(value['state'],'complete');self.assertFalse(value['leaseIssued'])
        self.prepared['manifest']=self.manifest;self.prepared['manifestSha256']=staging.sha(staging.canonical(self.manifest))
        self.assertEqual(staging.project(self.prepared,raw,b'',0,{'stdout':True,'stderr':True})['state'],'complete')
        self.assertFalse((f.root/'android-native-device-android-api35.lease').exists())

    def test_partial_and_extra_stream_retained_unknown(self):
        value,_=self.run_receiver(staging.canonical(self.manifest)+self.data['base.apk'][:-1]);self.assertEqual(value['state'],'unknown');self.assertTrue(value['partialLeafRetained']);self.assertEqual(value['code'],'asset_stream_short')
        # Fresh separate exact leaf for the extra-byte boundary.
        with tempfile.TemporaryDirectory(dir=self.root)as p:
            old=self.root;self.root=Path(p);self.root.chmod(0o700)
            try:value,_=self.run_receiver(staging.canonical(self.manifest)+b''.join(self.data[n]for n in staging.NAMES)+b'x')
            finally:self.root=old
        self.assertEqual(value['code'],'asset_stream_extra');self.assertEqual(value['state'],'unknown')

    def test_duplicate_or_order_manifest_refuses_before_leaf(self):
        for mutate in ('duplicate','order','bool'):
            m=copy.deepcopy(self.manifest)
            if mutate=='duplicate':m['files'][1]=copy.deepcopy(m['files'][0])
            elif mutate=='order':m['files'][0],m['files'][1]=m['files'][1],m['files'][0]
            else:m['files'][0]['size']=True
            value,_=self.run_receiver(manifest=m);self.assertEqual(value['state'],'unknown');self.assertFalse(value['partialLeafRetained'])
        self.assertFalse((self.root/('android-complete-update-inputs-'+CORR)).exists())

    def test_source_hash_and_tls_receipt_refuse(self):
        m=copy.deepcopy(self.manifest);m['files'][2]['sha256']='0'*64
        value,_=self.run_receiver(manifest=m);self.assertEqual(value['code'],'asset_stream_hash_changed')

    def test_projection_missing_eof_and_typed_drift_unknown(self):
        value,raw=self.run_receiver()
        for rc,err,eof in [(True,b'',{'stdout':True,'stderr':True}),(0,b'private exception',{'stdout':True,'stderr':True}),(0,b'',{'stdout':False,'stderr':True})]:
            self.assertEqual(staging.project(self.prepared,raw,err,rc,eof)['state'],'unknown')
        for field in ('sha','uid','parent','missing_parent'):
            bad=copy.deepcopy(value);pin=bad['authority']['files']['base.apk']
            if field=='sha':pin['sha256']='0'*64
            elif field=='uid':pin['generation'][3]=True
            elif field=='parent':pin['parents'][bad['authority']['inputDirectory']][3]=1000
            else:pin['parents'].pop('/')
            self.assertEqual(staging.project(self.prepared,staging.canonical(bad),b'',0,{'stdout':True,'stderr':True})['state'],'unknown')

    def test_failure_frame_never_exposes_arbitrary_exception_text(self):
        prefix=self.prefix+"import json\ndef injected(*a,**k):raise ValueError('asset_PRIVATE_TEST_MARKER')\njson.loads=injected\n"
        value,raw=self.run_receiver(prefix=prefix)
        self.assertEqual(value['state'],'unknown');self.assertEqual(value['code'],'asset_receiver_unknown');self.assertNotIn(b'PRIVATE_TEST_MARKER',raw)

    def test_native_principal_refusal_before_staging(self):
        if os.getuid()==0:self.skipTest('ordinary-user refusal needs nonroot')
        p=subprocess.run([sys.executable,'-I','-B','-c',self.source,str(self.root),CORR,self.prepared['manifestSha256'],BOOT],input=staging.canonical(self.manifest),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertNotEqual(p.returncode,0);self.assertFalse((self.root/('android-complete-update-inputs-'+CORR)).exists())

    @unittest.skipUnless(sys.platform.startswith('linux')and os.getuid()==0,'privileged Linux root identity/boot fixture unavailable')
    def test_privileged_linux_receiver_actual_principal(self):
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.prepared['bootId']=boot
        p=subprocess.run([sys.executable,'-I','-B','-c',self.source,str(self.root),CORR,self.prepared['manifestSha256'],boot],input=staging.canonical(self.manifest)+b''.join(self.data[n]for n in staging.NAMES),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(p.returncode,0);self.assertEqual(json.loads(p.stdout)['state'],'complete')

class LocalCustodyTests(unittest.TestCase):
    def test_owned_real_fd_metadata_and_drift(self):
        with tempfile.TemporaryDirectory()as p:
            leaf=Path(p).resolve()/'key';leaf.write_bytes(b'owned-local-fixture');leaf.chmod(0o600)
            original=staging.snapshot(leaf,65536);self.assertEqual(original['sha256'],staging.sha(leaf.read_bytes()))
            leaf.write_bytes(b'changed');self.assertNotEqual(staging.snapshot(leaf,65536),original)
            leaf.chmod(0o644)
            with self.assertRaisesRegex(ValueError,'file_unsafe'):staging.snapshot(leaf,65536)

    def test_prepare_invalid_keys_no_directory_or_transport(self):
        with tempfile.TemporaryDirectory()as p,mock.patch.object(staging.ssh_transport,'load_config',side_effect=AssertionError('transport forbidden')):
            with self.assertRaisesRegex(ValueError,'inputs_invalid'):staging.prepare_local(p,CORR,'/fixed-admitted-root',BOOT,{})
            self.assertEqual(list(Path(p).iterdir()),[])


class CompletePreparationTests(unittest.TestCase):
    def test_late_route_payload_mutation_refuses_executable_request(self):
        for changed in ('payload','intent',*staging.NAMES,'parent','post-fence-payload','post-fence-intent'):
            with self.subTest(changed=changed):
                with tempfile.TemporaryDirectory()as temp:
                    root=Path(temp).resolve();root.chmod(0o700);inputs=root/'inputs';inputs.mkdir(mode=0o700);(root/'.runtime/parity-evidence').mkdir(parents=True)
                    data={'base.apk':b'base','target.apk':b'next','ca.pem':b'ca','leaf.pem':b'leaf','key.pem':b'inert-key'}
                    base,target=staging.sha(data['base.apk']),staging.sha(data['target.apk'])
                    receipt={'schema':1,'kind':'android-disposable-fixture-tls','testOnly':True,'campaignId':CORR,'sourceFacts':{'sourceSha':staging.PRODUCT,'baseArtifactId':'sha256-'+base,'targetArtifactId':'sha256-'+target,'targetSha256':target,'baseVersion':'2.2.2','targetVersion':'2.2.3','baseCode':16840,'targetCode':16860,'targetSize':4},'files':{origin:{'bytes':len(data[n]),'sha256':staging.sha(data[n])}for n,origin in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem')]}}
                    data['receipt.json']=staging.canonical(receipt)
                    for n,b in data.items():(inputs/n).write_bytes(b);(inputs/n).chmod(0o600)
                    config=staging.ssh_transport.SshConfig(root,{'archlinux':staging.ssh_transport.SshHost('archlinux','test.invalid',22,'fixture',root/'not-opened-key',root/'not-opened-hosts')});real_builder=staging.ssh_transport.build_ssh_argv
                    with mock.patch.multiple(staging,BASE=base,TARGET=target,APK_SIZE=4),mock.patch.object(staging.ssh_transport,'load_config',return_value=config),mock.patch.object(subprocess,'Popen',side_effect=AssertionError('native forbidden')):
                        prepared=staging.prepare_local(root,CORR,root,BOOT,{n:inputs/n for n in staging.NAMES});payload=Path(prepared['payloadPin']['path'])
                        def late_builder(*a,**k):
                            argv=real_builder(*a,**k)
                            if changed.startswith('post-fence-'):return argv
                            changed_path=payload if changed=='payload'else Path(prepared['intentPin']['path'])if changed=='intent'else inputs/changed
                            if changed=='parent':inputs.chmod(0o755)
                            else:
                                with changed_path.open('ab')as out:out.write(b'foreign')
                            return argv
                        real_writer=staging.dispatch.android_installer_target._write_private
                        def late_writer(*a,**k):
                            real_writer(*a,**k)
                            if changed.startswith('post-fence-'):
                                changed_path=payload if changed.endswith('payload')else Path(prepared['intentPin']['path'])
                                with changed_path.open('ab')as out:out.write(b'foreign')
                        with mock.patch.object(staging.ssh_transport,'build_ssh_argv',side_effect=late_builder),mock.patch.object(staging.dispatch.android_installer_target,'_write_private',side_effect=late_writer):
                            with self.assertRaisesRegex(ValueError,'asset_custody_changed'):staging.transport_request(root,prepared)
                        self.assertTrue((payload.parent/'submission-intent.json').exists())

    def test_actual_prepare_stream_request_receiver_projection_no_native(self):
        from agent_tools import android_fixture_tls_mint as mint,android_native_fixture as fixture
        with tempfile.TemporaryDirectory()as temp:
            root=Path(temp).resolve();root.chmod(0o700);inputs=root/'inputs';inputs.mkdir(mode=0o700)
            data={'base.apk':b'BASE-FIXTURE-0000','target.apk':b'NEXT-FIXTURE-0000'};base=staging.sha(data['base.apk']);target=staging.sha(data['target.apk']);size=len(data['base.apk']);self.assertEqual(size,len(data['target.apk']))
            for n,b in data.items():(inputs/n).write_bytes(b);(inputs/n).chmod(0o600)
            plan={'sourceSha':staging.PRODUCT,'baseArtifactId':'sha256-'+base,'targetArtifactId':'sha256-'+target,'targetSha256':target,'baseVersion':'2.2.2','targetVersion':'2.2.3','baseCode':16840,'targetCode':16860,'baseSignerSha256':'a'*64,'targetSize':size,'endpoint':fixture.endpoint_contract(),'deviceMutationAllowed':False}
            minted=mint.mint(root,CORR,plan);capsule=Path(minted['directory'])
            import shutil
            for dest,origin in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem'),('receipt.json','receipt.json')]:shutil.copyfile(capsule/origin,inputs/dest);(inputs/dest).chmod(0o600)
            (root/'.runtime'/'parity-evidence').mkdir(parents=True)
            receiver=staging.RECEIVER.replace(staging.BASE,base).replace(staging.TARGET,target).replace('45026948',str(size))
            config=staging.ssh_transport.SshConfig(root,{'archlinux':staging.ssh_transport.SshHost('archlinux','test.invalid',22,'fixture',root/'identity-not-opened',root/'known-hosts-not-opened')})
            real_builder=staging.ssh_transport.build_ssh_argv
            with mock.patch.multiple(staging,BASE=base,TARGET=target,APK_SIZE=size,RECEIVER=receiver),mock.patch.object(staging.ssh_transport,'load_config',return_value=config)as selected,mock.patch.object(staging.ssh_transport,'build_ssh_argv',wraps=real_builder)as route,mock.patch.object(staging.subprocess if hasattr(staging,'subprocess')else subprocess,'Popen',side_effect=AssertionError('SSH submission forbidden')):
                prepared=staging.prepare_local(root,CORR,root,BOOT,{n:inputs/n for n in staging.NAMES})
                argv,stream=staging.transport_request(root,prepared,b'')
                self.assertEqual(argv[0],'ssh');self.assertIn('test.invalid',argv);self.assertEqual(stream.path,Path(prepared['payloadPin']['path']));route.assert_called_once();selected.assert_called_once()
                with self.assertRaisesRegex(ValueError,'asset_submit_consumed'):staging.transport_request(root,prepared,b'')
                with self.assertRaises(FileExistsError):staging.prepare_local(root,CORR,root,BOOT,{n:inputs/n for n in staging.NAMES})
            # Execute exact emitted body under only this child root/boot seam.
            fixture_case=ReceiverTests('test_real_child_complete_custody_and_reentry_unknown');fixture_case.setUp()
            try:
                command=fixture_case.prefix+receiver
                child=subprocess.run([sys.executable,'-I','-B','-c',command,str(root),CORR,prepared['manifestSha256'],BOOT],input=stream.prefix+stream.path.read_bytes(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(child.returncode,0);self.assertEqual(child.stderr,b'')
                projected=staging.project(prepared,child.stdout,child.stderr,child.returncode,{'stdout':True,'stderr':True});self.assertEqual(projected['state'],'complete');self.assertFalse(projected['leaseIssued'])
                self.assertEqual((capsule/'ca-key.pem').stat().st_mode&0o777,0o600);self.assertFalse((root/('android-complete-update-inputs-'+CORR)/'ca-key.pem').exists())
                altered=copy.deepcopy(prepared);altered['receiverRoot']='/foreign-root'
                with mock.patch.multiple(staging,BASE=base,TARGET=target,APK_SIZE=size,RECEIVER=receiver),mock.patch.object(staging.ssh_transport,'load_config',side_effect=AssertionError('must refuse mutated preparation')):
                    with self.assertRaisesRegex(ValueError,'asset_preparation_changed'):staging.transport_request(root,altered)
                source=inputs/'ca.pem';source.write_bytes(b'changed')
                with mock.patch.multiple(staging,BASE=base,TARGET=target,APK_SIZE=size,RECEIVER=receiver),mock.patch.object(staging.ssh_transport,'load_config',side_effect=AssertionError('must refuse')):
                    # Existing preparation must retain source custody as well as snapshot.
                    with self.assertRaisesRegex(ValueError,'asset_source_changed'):staging.transport_request(root,prepared)
            finally:fixture_case.doCleanups()

if __name__=='__main__':unittest.main()
