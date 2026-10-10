"""Actual source collector, TempFS and bounded child regressions; no native."""
import ast
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
try:
    import resource
except ImportError:
    resource=None
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

from agent_tools import android_installer_routing_backup as backup
from agent_tools import android_installer_component_bundle as bundle
from agent_tools import android_api35_large_routing_observation as large
from agent_tools import android_avd_launch_recovery as inherited
from agent_tools.tests import test_android_installer_component_bundle as fixtures

ROOT=Path(__file__).resolve().parents[2]
PACKED_CONFIG=b'[Application]\napp.classpath=$APPDIR/desktopApp-704d77f7be46b33797b3c53e3b7b349.jar\napp.mainclass=com.kardinal.vpncontrol.desktop.MainKt\napp.classpath=$APPDIR/Collections-2.4-31239860de7727f982b519e160bf9d60.jar\napp.classpath=$APPDIR/Desktop-1.1-a4b6471e313122ae4caa90e98f58c04e.jar\napp.classpath=$APPDIR/Executor-3.13-119bc7b319d96dac11f96c1345c9e21a.jar\napp.classpath=$APPDIR/JNA-1.2-7871c0621188b12cd75ad8259b18c0.jar\napp.classpath=$APPDIR/OS-1.8-bda4e9aa2311b2e8fb3b6b06ba74cd0.jar\napp.classpath=$APPDIR/SystemTray-4.4-73fd25f2db4db0fab3601a5a5840d482.jar\napp.classpath=$APPDIR/Updates-1.1-796d91f83834249682c8c9809cc163.jar\napp.classpath=$APPDIR/Utilities-1.46-29a044a5bb13c2516c94b21bff27827.jar\napp.classpath=$APPDIR/animation-core-desktop-1.7.3-87bb47dcf611207d17ac1fabc2155e1.jar\napp.classpath=$APPDIR/animation-desktop-1.7.3-405fd87261449d20aacb4543f98b26b.jar\napp.classpath=$APPDIR/annotation-jvm-1.8.0-3c74b73c0c75521f67964f11b28dec9.jar\napp.classpath=$APPDIR/annotations-23.0.0-8484cd17d040d837983323f760b2c660.jar\napp.classpath=$APPDIR/atomicfu-jvm-0.23.2-5e4f88ed1c37222d791f5dcadf481498.jar\napp.classpath=$APPDIR/collection-jvm-1.4.0-3f0597ec99a52ecdbf6f3962c5dc77a.jar\napp.classpath=$APPDIR/core-3.5.4-23cc13611f7f222b9988220fa28a115.jar\napp.classpath=$APPDIR/core-common-2.2.0-2212d240dfe1e8a7598ee117ccc316d.jar\napp.classpath=$APPDIR/core-desktop-bf1e2b41e1cd46357c414ab15274eca4.jar\napp.classpath=$APPDIR/desktop-jvm-1.7.3-de424e1ca627c3ee7de0f1f65430b2c5.jar\napp.classpath=$APPDIR/foundation-desktop-1.7.3-4dbe5e38e559448051b0edf6263c1e5c.jar\napp.classpath=$APPDIR/foundation-layout-desktop-1.7.3-42275c8b9c017549d648869827055c3.jar\napp.classpath=$APPDIR/java-uuid-generator-4.2.0-82d2ccc2fdf93965c3ac20b73acb129a.jar\napp.classpath=$APPDIR/javassist-3.29.2-GA-9783c9ffa4d36eddda9526fde6f3ea.jar\napp.classpath=$APPDIR/jna-jpms-5.13.0-93d047bfe01f058f6bcf8d714e51e92.jar\napp.classpath=$APPDIR/jna-platform-jpms-5.13.0-281fbcc2764cb6a0543dd5501c58574.jar\napp.classpath=$APPDIR/kotlin-stdlib-2.1.0-895fde81aafd572b5853c1b4a250a94d.jar\napp.classpath=$APPDIR/kotlin-stdlib-jdk7-1.9.24-36ceb164e825dcfd5d1c5c25482bec8.jar\napp.classpath=$APPDIR/kotlin-stdlib-jdk8-1.9.24-592f5e22e994e5dd4f3868f13bcf74d8.jar\napp.classpath=$APPDIR/kotlinx-coroutines-core-jvm-1.9.0-7c86c3f6dbf92d46634a45f7727a3f6.jar\napp.classpath=$APPDIR/kotlinx-coroutines-jdk8-1.9.0-aaa3712eb33442538e8d990902997d.jar\napp.classpath=$APPDIR/kotlinx-datetime-jvm-0.6.1-caf753e32a0b028450eaf38bb43c7b.jar\napp.classpath=$APPDIR/kotlinx-serialization-core-jvm-1.8.0-66d98a2ddbdf228e6e203a3d2f8029b2.jar\napp.classpath=$APPDIR/kotlinx-serialization-json-jvm-1.8.0-d35f63b17e2d791d18abb1499212cc0.jar\napp.classpath=$APPDIR/lifecycle-common-jvm-2.8.5-8c81b745cb7664b0f78619d2e523d018.jar\napp.classpath=$APPDIR/lifecycle-runtime-compose-desktop-2.8.4-7aa4c61a74a64c3df8de58b46c853dc8.jar\napp.classpath=$APPDIR/lifecycle-runtime-desktop-2.8.5-7fc568586d392d3d5dbda79492e18d.jar\napp.classpath=$APPDIR/lifecycle-viewmodel-desktop-2.8.5-34f77ff425af3216d357e6cbf3b7d12b.jar\napp.classpath=$APPDIR/material-desktop-1.7.3-7cbd7baf9be1c437d8af7e5d9cd5ff6.jar\napp.classpath=$APPDIR/material-icons-core-desktop-1.7.3-23eaca5d2a4caa3e4077a0e9fd549d68.jar\napp.classpath=$APPDIR/material-icons-extended-desktop-1.7.3-848bc0f13628d5b3accc94dd3afdfa27.jar\napp.classpath=$APPDIR/material-ripple-desktop-1.7.3-eaa17112a2817a534d1be922e59182fd.jar\napp.classpath=$APPDIR/material3-desktop-1.7.3-86a5717eed6ef3c263c3552ac537a12.jar\napp.classpath=$APPDIR/model-desktop-97dd22927a366781954e7a5ba22cb1a5.jar\napp.classpath=$APPDIR/runtime-desktop-1.7.3-7ab98d9506ccb634316b9b9eeecf5b8.jar\napp.classpath=$APPDIR/runtime-saveable-desktop-1.7.3-682605976c053c6e295e37eb69ebb5f.jar\napp.classpath=$APPDIR/skiko-awt-0.8.18-a19fd5d37c7330965054a0a732d09b18.jar\napp.classpath=$APPDIR/skiko-awt-runtime-linux-x64-0.8.18-8a85de6684aa264d8caf96d5fdeb51e.jar\napp.classpath=$APPDIR/slf4j-api-2.0.7-403dffa46cdd2e3c82da19df4f394a4c.jar\napp.classpath=$APPDIR/storage-api-desktop-a17332d2a9b646a2739838984ff8814.jar\napp.classpath=$APPDIR/ui-desktop-1.7.3-146599b01f5da0fdd1841ac8b664de57.jar\napp.classpath=$APPDIR/ui-desktop-e34aa13c45223a54867a5dc9981e3af.jar\napp.classpath=$APPDIR/ui-geometry-desktop-1.7.3-c8a01a3ba0c9545187876a28acd79.jar\napp.classpath=$APPDIR/ui-graphics-desktop-1.7.3-bb90a9a5b8f366b9f6162a35a4e16da.jar\napp.classpath=$APPDIR/ui-text-desktop-1.7.3-fb336187493d2dc39a883e640415a99.jar\napp.classpath=$APPDIR/ui-tooling-preview-desktop-1.7.3-f86e811916e9fcecb72a5e1ce6eac638.jar\napp.classpath=$APPDIR/ui-unit-desktop-1.7.3-4d19fde85b276f26591df697b9b883c.jar\napp.classpath=$APPDIR/ui-util-desktop-1.7.3-5472e6dd5d146c395d508cf67df34db.jar\n\n[JavaOptions]\njava-options=-Djpackage.app-version=2.2.2\njava-options=-Dcompose.application.resources.dir=$APPDIR/resources\njava-options=-Dcompose.application.configure.swing.globals=true\njava-options=-Dskiko.library.path=$APPDIR\n'
EXTRA=('agent_tools/android_installer_routing_backup.py',backup.READER,backup.READER_TEST)


def _fixture_catalogue(paths):
    """Historical 37-file fixture compatibility; production 40 stays untouched."""
    return tuple(paths)+tuple(name for name in EXTRA if name not in paths)


@unittest.skipUnless(resource is not None and os.name=='posix','POSIX FD/resource support required')
class BackupTests(unittest.TestCase):
    def setUp(self):
        self.catalogue=None
        historical=_fixture_catalogue(bundle.FILES)
        if historical!=bundle.FILES:
            self.catalogue=mock.patch.object(bundle,'FILES',historical);self.catalogue.start()
        self.case=fixtures.BundleTests();self.case.setUp()
    def tearDown(self):
        self.case.tearDown()
        if self.catalogue is not None:self.catalogue.stop()

    def fixture(self,changes=None,large_bytes=0):
        selected,backend,args,statepath,log,*_=self.case.fixture()
        state=json.loads(statepath.read_bytes())
        state['routing']={'type':'vpn_control_routing_rules','version':7,'exported_at':'now',
                          'rules':{'direct_domain_suffixes':['x'*large_bytes] if large_bytes else ['one.test']}}
        state['varyTimestamp']=True
        state.update(changes or {});statepath.write_text(json.dumps(state))
        java=self.case.root/'jdk/bin/java'
        source=java.read_text().replace("if args[-2:]==['operations','list']:",
            "if args[-2:]==['routing','show']:data={'routing':state['routing']}\n elif args[-2:]==['operations','list']:")
        source=source.replace("'final':True", "'final':state.get('routingFinal',True) if args[-2:]==['routing','show'] else True")
        source=source.replace("'controllerId':state['owner']", "'controllerId':state.get('routingOwner',state['owner']) if args[-2:]==['routing','show'] else state['owner']")
        source=source.replace("if args[-2:]==['routing','show']:data={'routing':state['routing']}",
            "if args[-2:]==['routing','show']:\n  count=sum(json.loads(line)[-2:]==['routing','show'] for line in pathlib.Path(LOG).read_text().splitlines())\n  if state.get('varyTimestamp'):state['routing']['exported_at']=str(count)\n  if state.get('changeRouting') and count>1:state['routing']['rules']['direct_domain_suffixes'].append('changed.test')\n  data={'routing':state['routing']}")
        java.write_text(source);backend['EXTERNAL']['selectedJdk']=backend['external_jdk']('jdk17')
        # The real frozen packaged configuration binds all JDK arguments.
        stage=self.case.root/'android-cli-stage-fixture-stage';tree=stage/'tree'
        old=Path(backend['GETTER']['cli']);launcher=tree/'opt/vpn-control/bin/vpn-control'
        launcher.parent.mkdir(parents=True);old.rename(launcher);old.parent.rmdir()
        appdir=tree/'opt/vpn-control/lib/app';appdir.mkdir(parents=True)
        (appdir/'vpn-control.cfg').write_bytes(PACKED_CONFIG);(appdir/'vpn-control.cfg').chmod(0o600)
        classes=[line[14:][8:] for line in PACKED_CONFIG.decode().splitlines() if line.startswith('app.classpath=')]
        for name in classes:(appdir/name).write_bytes(b'actual-staged-fixture-jar');(appdir/name).chmod(0o600)
        backend['GETTER']['cli']=str(launcher);backend['EXTERNAL']['getterIdentity']['cli']=str(launcher)
        directories=[];files=[]
        for path in tree.rglob('*'):
            relative=str(path.relative_to(tree))
            if path.is_dir():directories.append({'path':relative,'mode':path.stat().st_mode&0o777})
            else:files.append({'path':relative,'mode':path.stat().st_mode&0o777,'size':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        manifest={'directories':directories,'files':files};backend['GETTER']['manifest']=manifest
        backend['EXTERNAL']['classpath']=classes
        backend['EXTERNAL']['javaOptions']=[line[13:] for line in PACKED_CONFIG.decode().splitlines() if line.startswith('java-options=')]
        for name in ('intent.json','receipt.json'):
            path=stage/name;value=json.loads(path.read_bytes())
            if name=='intent.json':value['manifest']=manifest
            else:value['cliPath']=str(launcher)
            path.write_text(json.dumps(value))
        original=backend['subprocess'].Popen
        def portable(argv,**kwargs):
            # Child observations only: fake host UID1000 metadata on non-root CI.
            kwargs.pop('preexec_fn',None)
            return original(argv,**kwargs)
        backend['subprocess'].Popen=portable
        (self.case.root/'android-native-device-android-api29.lease').unlink();args.intent_file.unlink()
        request={'host':'archlinux','device':'android-api29','correlationId':fixtures.CORRELATION,
                 'sourceSha':bundle._PRODUCT_SHA,'expectedOwner':fixtures.OWNER,'expectedRevision':0,
                 'expectedAvd':'owned-fixture','expectedApi':29,'packageSha256':backend['GETTER']['packageSha256'],
                 'reservation':copy.deepcopy(backend['LAUNCH']['intent']['reservation'])}
        return backend,request,statepath,log

    def assembly_seams(self):
        identity=[os.getuid(),os.geteuid(),os.getgid(),os.getegid(),sorted(os.getgroups())]
        limits=[(8388608,33554432)]
        def setlimit(which,value):limits[0]=value
        return (mock.patch.object(backup,'_root_identity',return_value=identity),
                mock.patch.object(resource,'getrlimit',side_effect=lambda which:limits[0]),
                mock.patch.object(resource,'setrlimit',side_effect=setlimit))

    def test_actual_complete_source_closed_backup_before_installer_lease(self):
        backend,request,_,log=self.fixture(large_bytes=2000000)
        seams=self.assembly_seams()
        with seams[0],seams[1],seams[2]:result=backup.create(self.case.receipt,backend,request)
        raw=Path(result['path']).read_bytes()
        self.assertEqual(result['sha256'],hashlib.sha256(raw).hexdigest());self.assertEqual(len(raw),result['size'])
        self.assertEqual(7,json.loads(raw)['version']);self.assertGreater(len(raw),1048576)
        self.assertTrue(result['limitsRestored']);self.assertFalse(result['installerLeaseGranted'])
        directory=Path(result['path']).parent
        for phase in ('routingBefore','routingAfter'):
            record=json.loads((directory/(phase+'-raw.json')).read_bytes())
            self.assertTrue(record['stdoutEof']);self.assertTrue(record['stderrEof'])
            chunks=record['stdout']['chunks'];full=b''.join((directory/row['name']).read_bytes() for row in chunks)
            self.assertEqual(record['stdout']['sha256'],hashlib.sha256(full).hexdigest())
            self.assertTrue(all(row['bytes']<=524288 for row in chunks));self.assertEqual(300,record['publicTimeoutSeconds'])
        calls=[json.loads(row) for row in log.read_text().splitlines()]
        self.assertEqual(2,sum(row[-2:]==['routing','show'] for row in calls))
        self.assertFalse(any('install' in row or 'root' in row or 'unroot' in row for row in calls))
        self.assertEqual(0o600,Path(result['path']).stat().st_mode&0o777)

    def test_current_binding_and_source_refusal_precedes_large_child(self):
        self.assertEqual(41,len(bundle.FILES));self.assertEqual(41,len(set(bundle.FILES)))
        self.assertIn('agent_tools/android_api35_coldboot_product_observation.py',bundle.FILES)
        self.assertEqual(bundle.FILES,_fixture_catalogue(bundle.FILES))
        historical=tuple(name for name in bundle.FILES if name not in EXTRA)
        self.assertEqual(38,len(historical));self.assertEqual(set(bundle.FILES),set(_fixture_catalogue(historical)))
        backend,request,_,log=self.fixture()
        request['device']='android-api35'
        with self.assertRaises(ValueError):backup.create(self.case.receipt,backend,request)
        self.assertFalse(log.exists())
        request['device']='android-api29'
        # Real same-byte inode replacement defeats the original full FD receipt.
        path=Path(self.case.receipt['directory'])/backup.READER;raw=path.read_bytes()
        path.rename(self.case.root/'old-reader.private');path.write_bytes(raw);path.chmod(0o600)
        with self.assertRaises(ValueError):backup.create(self.case.receipt,backend,request)
        self.assertFalse(log.exists())

    def test_nonfinal_foreign_owner_and_invalid_format_preserve_raw_then_refuse(self):
        for changes in ({'routingOwner':'foreign'}, {'routingFinal':False},
                        {'routing':{'type':'foreign','version':7,'exported_at':'now','rules':{}}}):
            with self.subTest(changes=changes):
                # Each frame gets a genuinely fresh immutable staging directory.
                backend,request,_,_=self.fixture(changes)
                with self.assertRaises(ValueError):backup.create(self.case.receipt,backend,request)
                directory=self.case.root/('android-installer-component-baseline-'+fixtures.CORRELATION)/'routing-backup'
                self.assertTrue((directory/'routingBefore-raw.json').is_file())
                self.assertFalse((directory/'opening-routing.json').exists())
                self.case.tearDown();self.case.setUp()

    def test_only_generated_export_time_is_ignored(self):
        backend,request,_,_=self.fixture()
        namespace=backup._collector(backup._sources(self.case.receipt),{**backend,'BACKUP_OWNER':request['expectedOwner']},['fixed','routing','show'],'routingBefore')
        a={'data':{'routing':{'type':'vpn_control_routing_rules','version':7,'exported_at':'one','rules':{'values':['one','two']}}}}
        b=copy.deepcopy(a);b['data']['routing']['exported_at']='two'
        self.assertEqual(namespace['large_semantic'](a),namespace['large_semantic'](b))
        b['data']['routing']['rules']['values'].reverse()
        self.assertNotEqual(namespace['large_semantic'](a),namespace['large_semantic'](b))

    def test_actual_second_read_semantic_drift_retains_both_raw_and_no_backup(self):
        backend,request,_,_=self.fixture({'changeRouting':True})
        with self.assertRaisesRegex(ValueError,'semantic_changed'):backup.create(self.case.receipt,backend,request)
        directory=self.case.root/('android-installer-component-baseline-'+fixtures.CORRELATION)/'routing-backup'
        self.assertTrue((directory/'routingBefore-raw.json').exists());self.assertTrue((directory/'routingAfter-raw.json').exists())
        self.assertFalse((directory/'opening-routing.json').exists())

    def test_jdk_arguments_cannot_override_actual_pinned_configuration(self):
        backend,request,_,log=self.fixture()
        backend['EXTERNAL']['javaOptions']=['-Dforeign=true']
        with self.assertRaisesRegex(ValueError,'configuration_changed'):backup.create(self.case.receipt,backend,request)
        calls=[json.loads(row) for row in log.read_text().splitlines()]
        self.assertFalse(any(row[-2:]==['routing','show'] for row in calls))

    def test_actual_inherited_fd_bytes_producer_to_argv(self):
        backend,request,_,log=self.fixture()
        names={'fp','parent_fds','close_parents','guard_parents','read_fixed'}
        nodes=[node for node in ast.parse(inherited._CENSUS).body if isinstance(node,ast.FunctionDef) and node.name in names]
        self.assertEqual(names,{node.name for node in nodes})
        namespace=dict(os=os,pathlib=__import__('pathlib'),stat=__import__('stat'),hashlib=hashlib)
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<actual-inherited-census-FD-producer>','exec'),namespace)
        backend['read_fixed']=namespace['read_fixed']
        path=Path(backend['GETTER']['cli']).parent.parent/'lib/app/vpn-control.cfg'
        fact=namespace['read_fixed'](path,1048576)
        self.assertIs(type(fact['raw']),bytes);self.assertEqual(PACKED_CONFIG,fact['raw'])
        self.assertEqual('full',fact['hashScope']);self.assertEqual(hashlib.sha256(PACKED_CONFIG).hexdigest(),fact['sha256'])
        guard=types.SimpleNamespace(modules=bundle.modules(self.case.receipt),receipt=self.case.receipt,owner=request['expectedOwner'])
        java,argv=backup._argv(backend,guard)
        self.assertEqual(str(java),argv[0]);self.assertEqual(['routing','show'],argv[-2:])
        self.assertEqual('300',argv[argv.index('--timeout-seconds')+1]);self.assertFalse(log.exists())

        path.write_bytes(b'\xff-invalid-UTF8')
        with self.assertRaises(UnicodeError):backup._argv(backend,guard)
        path.write_bytes(PACKED_CONFIG)
        original=namespace['read_fixed']
        backend['read_fixed']=lambda path,limit:original(path,16)
        with self.assertRaisesRegex(ValueError,'configuration_changed'):backup._argv(backend,guard)
        backend['read_fixed']=lambda path,limit:{**original(path,limit),'raw':bytearray(PACKED_CONFIG)}
        with self.assertRaisesRegex(ValueError,'configuration_changed'):backup._argv(backend,guard)

    def test_actual_api35_context_and_fixed_serial_read_only_backup(self):
        backend,request,statepath,log=self.fixture()
        state=json.loads(statepath.read_bytes());state['sdk']='35';statepath.write_text(json.dumps(state))
        backend['LAUNCH'].update(device='api35',port=5682);backend['EXTERNAL']['serial']='emulator-5682'
        path=self.case.root/'proc/18/cmdline';path.write_bytes(path.read_bytes().replace(b'5684',b'5682'))
        selected=bundle.modules(self.case.receipt);transport=selected['transport'];reader=transport.readonly
        raw_sources=(transport.REMOTE+transport._bounded_source(),selected['getter_api35']._GETTER.replace('__GETTER__',repr({})),
                     reader.getter_source.coldboot._BOOT.replace('__LAUNCH__',repr({})),reader.proven._REMOTE.replace('__EXTERNAL__',repr({})))
        names={'component_command','command_binary','command_request','command_host_identity','command_host_guard','command_bounded',
               'getter_stage','child_identity','session_guest','qemu_fact','external_file','external_jdk','external_jdk_guard'}
        nodes=[node for raw in raw_sources for node in ast.parse(raw).body if isinstance(node,ast.FunctionDef) and node.name in names]
        exec(compile(selected['adapter'].production_imports('api35')+ast.unparse(ast.Module(body=nodes,type_ignores=[])),
                     '<actual-api35-canonical-backend>','exec'),backend)
        backend['GETTER']['generation']={'child':backend['child_identity'](17),
            'guest':backend['session_guest'](backend['child_identity'](17),{'qemuFact':backend['qemu_fact']()})}
        request.update(device='android-api35',expectedApi=35)
        seams=self.assembly_seams()
        with seams[0],seams[1],seams[2]:result=backup.create(self.case.receipt,backend,request)
        self.assertEqual(35,result['request']['expectedApi']);self.assertFalse(result['guestMutationPerformed'])
        calls=[json.loads(row) for row in log.read_text().splitlines() if json.loads(row)[-2:]==['routing','show']]
        self.assertEqual(2,len(calls));self.assertTrue(all(row[row.index('--serial')+1]=='emulator-5682' for row in calls))


@unittest.skipUnless(resource is not None and os.name=='posix','POSIX FD/resource support required')
class CollectorTests(unittest.TestCase):
    def namespace(self,code):
        original=subprocess.Popen
        def child(argv,**kwargs):return original([sys.executable,'-I','-B','-c',code],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        process=types.SimpleNamespace(**vars(subprocess));process.Popen=child
        backend=dict(os=os,subprocess=process,
                     select=__import__('select'),time=__import__('time'),BACKUP_OWNER=fixtures.OWNER)
        return backup._collector(large._OBSERVER,backend,['fixed','routing','show'],'routingBefore')

    def test_actual_old_small_budget_and_cap_red_new_source_collector_green(self):
        namespace=self.namespace("import time;time.sleep(.12);print('finite')")
        old=next(n for n in ast.parse(large.original._GETTER).body if isinstance(n,ast.FunctionDef) and n.name=='getter_bounded')
        exec(compile(ast.Module(body=[old],type_ignores=[]),'<actual-old-getter>','exec'),namespace)
        with self.assertRaisesRegex(ValueError,'timeout'):namespace['getter_bounded'](['fixed','routing','show'],1,{},timeout=.04)
        namespace=self.namespace("import time;time.sleep(.12);print('finite')")
        self.assertEqual('finite\n',namespace['getter_bounded'](['fixed','routing','show'],1,{},timeout=.04,limit=backup.LIMIT)['stdoutRaw'])
        namespace=self.namespace("import sys;sys.stdout.write('x'*2000000)")
        exec(compile(ast.Module(body=[old],type_ignores=[]),'<actual-old-small-cap>','exec'),namespace)
        with self.assertRaisesRegex(ValueError,'output_limit'):namespace['getter_bounded'](['fixed','routing','show'],1,{},limit=1048576)
        namespace=self.namespace("import sys;sys.stdout.write('x'*2000000)")
        result=namespace['getter_bounded'](['fixed','routing','show'],1,{},limit=backup.LIMIT)
        self.assertEqual(2000000,len(result['stdoutRaw']))

    def test_actual_timeout_and_held_pipe_partial_is_durable(self):
        namespace=self.namespace("import time;print('partial',flush=True);time.sleep(1)")
        namespace['LARGE_OUTER_SECONDS']=.08
        with self.assertRaisesRegex(ValueError,'timeout'):namespace['getter_bounded'](['fixed','routing','show'],1,{},limit=backup.LIMIT)
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp).resolve();directory.chmod(0o700)
            result=backup._archive(directory,'routingBefore',namespace['GETTER_RECORDS']['routingBefore'])
            self.assertFalse(result['stdoutEof']);self.assertEqual(8,result['stdout']['bytes'])
            self.assertTrue((directory/'routingBefore-raw.json').is_file())

    @unittest.skipUnless(hasattr(os,'fork'),'POSIX fork required')
    def test_actual_exited_child_with_held_stdout_stays_unknown(self):
        namespace=self.namespace("import os,time;print('partial',flush=True);pid=os.fork();time.sleep(.3) if pid==0 else None")
        namespace['LARGE_OUTER_SECONDS']=.08
        with self.assertRaisesRegex(ValueError,'timeout'):namespace['getter_bounded'](['fixed','routing','show'],1,{},limit=backup.LIMIT)
        record=namespace['GETTER_RECORDS']['routingBefore']
        self.assertEqual(0,record['returncode']);self.assertFalse(record['stdoutEof'])
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp).resolve();directory.chmod(0o700)
            manifest=backup._archive(directory,'routingBefore',record)
            self.assertEqual(b'partial\n',backup._retained(directory,'routingBefore',manifest)['stdout'])

    @unittest.skipUnless(sys.platform.startswith('linux') and os.getuid()==0,'actual Linux root credential transition required')
    def test_actual_source_collector_child_uid1000_supervisor_remains_root(self):
        code="import os,json;print(json.dumps([os.getuid(),os.geteuid(),os.getgid(),os.getegid(),os.getgroups()]))"
        argv=[sys.executable,'-I','-B','-c',code,'routing','show']
        backend=dict(os=os,subprocess=subprocess,select=__import__('select'),time=__import__('time'),BACKUP_OWNER=fixtures.OWNER)
        namespace=backup._collector(large._OBSERVER,backend,argv,'routingBefore')
        fd=os.open(sys.executable,os.O_RDONLY)
        try:result=namespace['getter_bounded'](argv,fd,{},limit=backup.LIMIT)
        finally:os.close(fd)
        self.assertEqual([1000,1000,1000,1000,[1000]],json.loads(result['stdoutRaw']))
        self.assertEqual(0,os.getuid());self.assertEqual(0,os.geteuid())

    def test_raw_hash_refusal_and_duplicate_json(self):
        namespace=self.namespace("print('payload')")
        namespace['getter_bounded'](['fixed','routing','show'],1,{},limit=backup.LIMIT)
        record=namespace['GETTER_RECORDS']['routingBefore'];record['stdout']['sha256']='0'*64
        with tempfile.TemporaryDirectory() as tmp,self.assertRaisesRegex(ValueError,'raw_changed'):
            backup._archive(Path(tmp).resolve(),'routingBefore',record)
        with self.assertRaisesRegex(ValueError,'duplicate_json'):backup._strict(b'{"ok":true,"ok":false}')

    def test_retained_fd_generation_replacement_refused(self):
        namespace=self.namespace("print('payload')")
        namespace['getter_bounded'](['fixed','routing','show'],1,{},limit=backup.LIMIT)
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp).resolve();directory.chmod(0o700)
            manifest=backup._archive(directory,'routingBefore',namespace['GETTER_RECORDS']['routingBefore'])
            row=manifest['stdout']['chunks'][0];path=directory/row['name'];raw=path.read_bytes()
            path.rename(directory/'old');path.write_bytes(raw);path.chmod(0o600)
            with self.assertRaisesRegex(ValueError,'raw_changed'):backup._retained(directory,'routingBefore',manifest)

    def test_actual_parent_race_and_create_only_restore_limits(self):
        seams=BackupTests.assembly_seams(self)
        with tempfile.TemporaryDirectory() as tmp,seams[0],seams[1],seams[2]:
            directory=Path(tmp).resolve()/'backup';directory.mkdir(mode=0o700)
            original=os.write;changed=False
            def race(fd,raw):
                nonlocal changed
                count=original(fd,raw)
                if not changed:
                    changed=True;directory.rename(directory.parent/'old');directory.mkdir(mode=0o700)
                return count
            with mock.patch.object(os,'write',side_effect=race),self.assertRaisesRegex(ValueError,'file_changed'):
                backup._assemble(directory,b'owned')
            self.assertEqual((8388608,33554432),resource.getrlimit(resource.RLIMIT_FSIZE))
            result=backup._assemble(directory,b'owned')
            with self.assertRaises(FileExistsError):backup._assemble(directory,b'replaced')
            self.assertEqual(b'owned',Path(result['path']).read_bytes())
            self.assertEqual((8388608,33554432),resource.getrlimit(resource.RLIMIT_FSIZE))

    def test_actual_8MiB_file_limit_red_then_32MiB_create_restore_green(self):
        code="""import os,resource,signal,tempfile,json
from pathlib import Path
from unittest import mock
from agent_tools import android_installer_routing_backup as backup
signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE,(8388608,33554432))
with tempfile.TemporaryDirectory() as tmp:
 p=Path(tmp).resolve();p.chmod(0o700);raw=b'x'*9000000
 try:
  (p/'old').write_bytes(raw)
  raise AssertionError('old file cap accepted')
 except OSError:assert (p/'old').stat().st_size==8388608
 identity=[os.getuid(),os.geteuid(),os.getgid(),os.getegid(),sorted(os.getgroups())]
 with mock.patch.object(backup,'_root_identity',return_value=identity):result=backup._assemble(p,raw)
 assert result['size']==9000000 and result['limitsRestored']
 assert resource.getrlimit(resource.RLIMIT_FSIZE)==(8388608,33554432)
 print('ACTUAL_8M_RED_32M_GREEN_RESTORED')
"""
        result=subprocess.run([sys.executable,'-c',code],capture_output=True,timeout=15,cwd=ROOT)
        self.assertEqual(0,result.returncode,result.stderr.decode());self.assertIn(b'ACTUAL_8M_RED_32M_GREEN_RESTORED',result.stdout)


if __name__=='__main__':unittest.main()
