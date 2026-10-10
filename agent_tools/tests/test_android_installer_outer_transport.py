"""Local actual API35 TLS/action composition, OS/product observations inert.

These tests never access an AVD. Actual stage loader, compiler contexts, lifecycle
check/download/install/receipt and raw capture execute against temporary files.
"""
import ast, copy, hashlib, inspect, json, os, sys, types, unittest
from pathlib import Path
from agent_tools import android_installer_component_bundle as bundle
from agent_tools.tests import test_android_installer_component_bundle as bf
from agent_tools.tests import test_android_installer_phase_guards as phase
ROOT = Path(__file__).resolve().parents[2]
ENTRY = ROOT / 'agent_tools/android_installer_outer_transport.py'

@unittest.skipUnless(os.name=='posix', 'POSIX custody/child fixture; portable refusal covered separately')
class ActualApi35(phase.InstallerPhaseGuardTests):

    def setUp(self):
        self.fixture = bf.BundleTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.selected, self.backend, self.args, self.state_path, self.log, _, _ = self.fixture.api35_fixture()
        t = self.selected['transport']
        r = t.readonly
        sources = [t.REMOTE + t._bounded_source(), self.selected['getter_api35']._GETTER.replace('__GETTER__', repr({})), r.getter_source.coldboot._BOOT.replace('__LAUNCH__', repr({})), r.proven._REMOTE.replace('__EXTERNAL__', repr({}))]
        names = {'component_command', 'command_binary', 'command_request', 'command_host_identity', 'command_host_guard', 'command_bounded', 'getter_stage', 'child_identity', 'session_guest', 'qemu_fact', 'external_file', 'external_jdk', 'external_jdk_guard'}
        nodes = [n for source in sources for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name in names]
        code = compile(self.selected['adapter'].production_imports('api35') + ast.unparse(ast.Module(body=nodes, type_ignores=[])), '<canonical-api35-composition>', 'exec', dont_inherit=True)
        for value in code.co_consts:
            if isinstance(value, types.CodeType) and value.co_name in names:
                original = self.backend[value.co_name]
                self.backend[value.co_name] = types.FunctionType(value, self.backend, argdefs=original.__defaults__)
        self.backend['subprocess'].Popen = phase.InProcessProduct
        self.args.cli_environment = self.backend['LAUNCH']['environment']
        self.installed = self.fixture.root / 'installed.apk'
        self.installed.write_bytes(self.args.base_apk.read_bytes())
        self.original_intent = self.args.intent_file.read_bytes()

    def stage_fixture_assets(self):
        """Real copied custody bytes; certificates are explicitly inert OS inputs."""
        corr=json.loads(self.args.intent_file.read_bytes())['correlationId']
        source=self.fixture.root/('android-complete-update-inputs-'+corr);source.mkdir(mode=0o700)
        dest=self.args.output/'assets';dest.mkdir(mode=0o700)
        pins={};staged={}
        names={'base.apk':'base_apk','target.apk':'target_apk','ca.pem':'ca_certificate','leaf.pem':'leaf_certificate','key.pem':'private_key'}
        for name,attr in names.items():
            raw=Path(getattr(self.args,attr)).read_bytes()
            for parent,catalogue in [(source,pins),(dest,staged)]:
                path=parent/name;path.write_bytes(raw);path.chmod(0o600)
                catalogue[str(path)]={'path':str(path),**bundle._fixture_asset_pin(path)}
            setattr(self.args,attr,dest/name)
        pair=json.loads(self.args.intent_file.read_bytes())['pair']
        files={}
        for name,origin in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem')]:
            pin=pins[str(source/name)];files[origin]={'bytes':pin['generation'][6],'sha256':pin['sha256']}
        receipt={'schema':1,'kind':'android-disposable-fixture-tls','campaignId':corr,'testOnly':True,
            'sourceFacts':{'sourceSha':bundle._PRODUCT_SHA,'targetArtifactId':'sha256-'+pair['targetSha256']},'files':files}
        path=source/'receipt.json';bundle._write(path,bundle._raw(receipt));pins[str(path)]={'path':str(path),**bundle._fixture_asset_pin(path)}
        path=self.fixture.root/'android-native-device-android-api35.lease'
        pins[str(path)]={'path':str(path),**bundle._fixture_asset_pin(path)}
        path=self.args.output/'asset-stage.json'
        bundle._write(path,bundle._raw({'schema':1,'correlationId':corr,'origins':pins,'staged':staged,'caPrivateKeyTransferred':False}))
        return bundle._read(path,True)[1]

class WholeEntryTests(ActualApi35):

    def test_actual_persistent_outer_callbacks_and_terminal(self):
        self.whole_entry(True)

    def whole_entry(self, outer):
        if outer:
            destination=self.fixture.root/('android-installer-component-baseline-'+bf.CORRELATION)
            self.args.output.rename(destination);self.args.output=destination;self.args.intent_file=destination/'intent.json'
            original=json.loads(self.args.intent_file.read_bytes());original['backupPath']=str(destination/'backup.json')
            self.args.intent_file.write_text(json.dumps(original))
        scope = {'__name__': 'local_update_entry', 'COMPONENT_BUNDLE': bundle, 'COMPONENT_RECEIPT': self.fixture.receipt}
        exec(compile(ENTRY.read_bytes(), str(ENTRY), 'exec'), scope)
        import zipfile
        with zipfile.ZipFile(self.args.target_apk, 'w') as archive:
            archive.writestr('lib/x86_64/libfixture.so', b'INERT-NATIVE-ASSET')
        self.args.target_sha256 = hashlib.sha256(self.args.target_apk.read_bytes()).hexdigest()
        intent = json.loads(self.args.intent_file.read_bytes())
        intent['expectedTerminal'] = 'installed'
        intent['pair']['targetSha256'] = self.args.target_sha256
        intent['pair']['targetArtifactId'] = 'sha256-' + self.args.target_sha256
        self.args.intent_file.write_text(json.dumps(intent))
        backup_path = Path(intent['backupPath'])
        backup_path.write_text(json.dumps({'type': 'vpn_control_routing_rules', 'version': 7, 'exported_at': 'now', 'rules': {'direct_domain_suffixes': ['one.test']}}))
        intent['backupSha256'] = hashlib.sha256(backup_path.read_bytes()).hexdigest()
        intent['backupSize'] = backup_path.stat().st_size
        self.args.intent_file.write_text(json.dumps(intent))
        pair = intent['pair']
        scope.update(UPDATE_BASE=pair['baseSha256'], UPDATE_TARGET=pair['targetSha256'], UPDATE_SIGNER=pair['signerSha256'])
        for name in ('ca_certificate', 'leaf_certificate', 'private_key'):
            path = self.fixture.root / (name + '.pem')
            path.write_bytes(b'INERT-OS-CERTIFICATE-SEAM')
            setattr(self.args, name, path)
        self.args.device_port = 45635
        self.args.continue_file = self.args.output / 'continue'
        self.args.handoff_ready_file = self.args.output / 'handoff-ready'
        self.args.governed_callbacks = True
        self.args.expected_terminal = 'installed'
        self.args.reconciliation_timeout_seconds = 5.0
        self.args.reconciliation_poll_seconds = 0.01
        self.product_children()
        adb = Path(self.backend['LAUNCH']['adbPath'])
        raw = adb.read_text()
        raw = raw.replace("if 'shell' in args or 'exec-out' in args:", "if args[2:]==['reverse','--list']:print('');sys.exit(0)\nif 'shell' in args or 'exec-out' in args:")
        raw = raw.replace("elif words==['id','-u']:", "elif words==['settings','get','global','http_proxy']:print('null')\n elif words==['id','-u']:")
        focus_code = ' elif words==[\'dumpsys\',\'window\']:\n  installer=bool(state[\'operations\']) and not state.get(\'terminal\')\n  print(\'mCurrentFocus=Window{abc u0 \'+(\'com.android.packageinstaller/InstallActivity\' if installer else \'com.kardinal.vpncontrol/MainActivity\')+\'}\')\n elif words[:2]==[\'uiautomator\',\'dump\']:print(\'UI hierarchy dumped\')\n elif words[:1]==[\'rm\']:print(\'\')\n elif words[:1]==[\'cat\'] and words[1].startswith(\'/sdcard/\'):\n  installer=bool(state[\'operations\']) and not state.get(\'terminal\')\n  print(\'<hierarchy><node package="com.android.packageinstaller" text="VPN Control"/><node package="com.android.packageinstaller" text="Update" enabled="true"/><node package="com.android.packageinstaller" text="Cancel" enabled="true"/></hierarchy>\' if installer else \'<hierarchy><node package="com.kardinal.vpncontrol" text="VPN Control"/></hierarchy>\')\n'
        raw = raw.replace(" elif words[:1]==['cat']:", focus_code + " elif words[:1]==['cat']:")
        adb.write_text(raw)
        self.backend['LAUNCH']['adbFacts']['generation'] = self.backend['fp'](adb.stat())
        java = Path(self.backend['EXTERNAL']['selectedJdk']['root']) / 'bin/java'
        raw = java.read_text()
        needle = " owner=args[args.index('--controller-id')+1] if '--controller-id' in args else None\n"
        routing = json.loads(Path(intent['backupPath']).read_bytes())
        branch = " if args[-2:]==['routing','show']:\n  print(json.dumps({'ok':True,'code':'OK','final':True,'controllerId':state['owner'],'configurationRevision':0,'data':{'routing':" + repr(routing) + '}}));sys.exit(0)\n'
        raw = raw.replace(needle, needle + branch)
        java.write_text(raw)
        self.backend['EXTERNAL']['selectedJdk'] = self.backend['external_jdk']('jdk17')
        from agent_tools.tests.test_android_installer_routing_backup import PACKED_CONFIG
        stage = self.fixture.root / 'android-cli-stage-fixture-stage'
        tree = stage / 'tree'
        old = Path(self.backend['GETTER']['cli'])
        launcher = tree / 'opt/vpn-control/bin/vpn-control'
        launcher.parent.mkdir(parents=True)
        old.rename(launcher)
        old.parent.rmdir()
        appdir = tree / 'opt/vpn-control/lib/app'
        appdir.mkdir(parents=True)
        cfg = appdir / 'vpn-control.cfg'
        cfg.write_bytes(PACKED_CONFIG)
        cfg.chmod(384)
        classes = [line[22:] for line in PACKED_CONFIG.decode().splitlines() if line.startswith('app.classpath=$APPDIR/')]
        for name in classes:
            jar = appdir / name
            jar.write_bytes(b'INERT-STAGED-JAR')
            jar.chmod(384)
        self.backend['GETTER']['cli'] = str(launcher)
        self.backend['EXTERNAL']['getterIdentity']['cli'] = str(launcher)
        self.args.cli = launcher
        directories = []
        files = []
        for path in tree.rglob('*'):
            relative = str(path.relative_to(tree))
            if path.is_dir():
                directories.append({'path': relative, 'mode': path.stat().st_mode & 511})
            else:
                files.append({'path': relative, 'mode': path.stat().st_mode & 511, 'size': path.stat().st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
        manifest = {'directories': directories, 'files': files}
        self.backend['GETTER']['manifest'] = manifest
        self.backend['EXTERNAL']['classpath'] = classes
        self.backend['EXTERNAL']['javaOptions'] = [line[13:] for line in PACKED_CONFIG.decode().splitlines() if line.startswith('java-options=')]
        for name in ('intent.json', 'receipt.json'):
            path = stage / name
            value = json.loads(path.read_bytes())
            if name == 'intent.json':
                value['manifest'] = manifest
            else:
                value['cliPath'] = str(launcher)
            path.write_text(json.dumps(value))
        self.stage_fixture_assets()
        actor = scope['CompleteUpdate'](self.args, self.backend)
        scope.update(ROOT=self.fixture.root,UPDATE_CORRELATION=actor.intent['correlationId'])
        self.selected = actor.selected
        self.guard = actor.guard
        dispatcher = None
        if outer:
            scope['UPDATE_SOURCE_PACKET_SHA'] = 'b' * 64
            import os
            scope['outer_process_identity'] = lambda pid=None: {'pid': os.getpid(), 'startTicks': 1, 'bootId': '5be1a80b-c97e-4622-aa07-ff761767622f', 'uid': os.getuid(), 'gid': os.getgid(), 'groups': sorted(os.getgroups())}
            dispatcher = scope['CompleteUpdateOuter'](actor)

        def callback(phase_name):
            if dispatcher is None:
                return actor.callback(phase_name)
            import time
            dispatcher.submit_callback(phase_name)
            path = dispatcher.directory / ('result-' + phase_name + '.json')
            deadline = time.monotonic() + 25
            while not path.exists():
                if dispatcher.unknown:
                    raise AssertionError('outer dispatcher unknown')
                if time.monotonic() > deadline:
                    raise AssertionError('outer callback not observed')
                time.sleep(0.01)
            return json.loads(path.read_bytes())
        source = inspect.getsource(phase.InstallerPhaseGuardTests.campaign)
        import textwrap
        tree = ast.parse(textwrap.dedent(source))
        function = tree.body[0]
        substitutions = {45629: 45635, '/data/local/tmp/vpn-control-installer-api29': '/data/local/tmp/vpn-control-installer-api35', '/system/etc/security/cacerts': '/apex/com.android.conscrypt/cacerts'}
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and type(node.value) in (int, str) and (node.value in substitutions):
                node.value = substitutions[node.value]
        remove = {'self.product_children(foreign_pending)', 'self.args.intent_file.write_text(json.dumps(intent))', 'self.addCleanup(restore)'}
        body = []
        for node in function.body:
            text = ast.unparse(node)
            if text in remove or text.startswith("restore = self.selected['adapter'].install("):
                continue
            if text.startswith('self.guard = bundle.CurrentGuard('):
                continue
            if text.startswith('self.args.intent = self.selected['):
                node = ast.parse('self.args.intent = actor.intent').body[0]
            body.append(node)
        function.body = body

        class Driver(ast.NodeTransformer):

            def visit_Assign(self, node):
                if ast.unparse(node).startswith('result = tls.run_fixture_lifecycle('):
                    return ast.parse('result = drive_actor()').body[0]
                return self.generic_visit(node)
        tree = Driver().visit(tree)

        class ActualCallbacks(ast.NodeTransformer):

            def visit_FunctionDef(self, node):
                if node.name == 'ready':
                    node.body = ast.parse("callback('handoff-ready')\nreturn True").body
                    return node
                if node.name == 'continue_ui':
                    retained = []
                    for statement in node.body:
                        if isinstance(statement, ast.Assign) and ast.unparse(statement).startswith('xml ='):
                            break
                        retained.append(statement)
                    retained.extend(ast.parse("callback('continue')\nif drift: self.state(owner=FOREIGN)").body)
                    node.body = retained
                    return node
                return self.generic_visit(node)
        tree = ActualCallbacks().visit(tree)
        namespace = dict(phase.__dict__)
        namespace['actor'] = actor
        namespace['callback'] = callback

        class Api35Adb(phase.FakeAdb):

            def record(self, words):
                self.records.append({'args': list(words), 'exit': 0, 'stderr': '', 'stderrTruncated': False})

            def run(self, *words):
                value = super().run(*words)
                self.record(words)
                return value

            def unroot(self):
                value = super().unroot()
                self.record(('unroot',))
                return value

            def wait_for_device(self):
                value = super().wait_for_device()
                self.record(('wait-for-device',))
                return value

            def shell(self, *words):
                self.record(('shell', *words))
                if words == ('getprop', 'ro.build.version.sdk'):
                    return '35'
                return super().shell(*words)
        namespace['FakeAdb'] = Api35Adb

        def drive_actor():
            module = actor.lifecycle.fixture
            from unittest import mock
            process = types.SimpleNamespace(pid=424243)
            with mock.patch.object(module, 'launch_supervised_fixture', return_value=process), mock.patch.object(module, 'read_ready_file', return_value=61000), mock.patch.object(module, '_stop_fixture') as stop, mock.patch.object(actor.lifecycle, 'fixture_start_ticks', return_value=12345):
                if dispatcher is None:
                    actor.start()
                    actor.thread.join(30)
                else:
                    import contextlib,io
                    captured=io.StringIO()
                    with contextlib.redirect_stdout(captured):dispatcher.run()
                    self.outer_stdout=captured.getvalue().encode('utf-8')
                    # Durable raw bytes precede any semantic classification.
                    bundle._write(self.args.output/'outer-capture.stdout.private',self.outer_stdout)
                self.assertFalse(actor.thread.is_alive())
                self.assertIsNone(actor.failure, (actor.failure, errors))
                stop.assert_called_once_with(process)
            return json.loads((self.args.output / 'lifecycle-receipt.json').read_bytes())
        original_factory = scope['update_main_factory']
        errors = []

        def tracing_factory(*args):
            actual = original_factory(*args)

            def invoke():
                try:
                    return actual()
                except BaseException as error:
                    import traceback
                    errors.append(traceback.format_exc())
                    raise
            return invoke
        scope['update_main_factory'] = tracing_factory
        namespace['drive_actor'] = drive_actor
        exec(compile(ast.fix_missing_locations(tree), '<explicit-local-os-harness>', 'exec'), namespace)
        receipt = namespace['campaign'](self)
        checkpoint = json.loads((self.args.output / 'probe.json').read_bytes())
        handoff = json.loads((self.args.output / 'handoff.json').read_bytes())
        terminal = actor.lifecycle.target_admission._terminal(intent, checkpoint, receipt, handoff, intent_path=self.args.intent_file)
        self.assertEqual('complete', terminal['state'])
        self.assertEqual(phase.TARGET_OWNER, terminal['terminalOwner'])
        self.assertEqual(1, len([r for r in self.rows() if r[-2:] == ['updates', 'install'] and '--interactive' in r]))
        self.assertTrue((self.args.output / 'worker-finished.json').exists())
        result = actor.finish(timeout=1) if dispatcher is None else json.loads(next(dispatcher.directory.glob('*-terminal.json')).read_bytes())['result']
        self.assertTrue(result['routingEqual'])
        self.assertTrue(result['fixtureCleanupObserved'])
        self.assertFalse(result['installedLauncherAccepted'])
        self.assertEqual(2, len(result['routingManifests']))
        self.assertTrue((self.args.output / 'complete-update-terminal.json').exists())
        if outer:
            scope['UPDATE_OUTER_ACCEPTED']=dispatcher.accepted
            saved=scope['outer_saved_status']()
            self.assertEqual('terminal-recorded',saved['state']);self.assertFalse(saved['freshNativeAcceptance']);self.assertFalse(saved['transportEOFProven'])
            parsed=scope['outer_capture_projection'](self.outer_stdout,b'',0,{'stdout':True,'stderr':True})
            self.assertEqual('complete',parsed['state']);self.assertFalse(parsed['installedLauncherAccepted'])
            missing=self.outer_stdout[:self.outer_stdout.rfind(b'COMPLETE_UPDATE_EOF ')]
            for out,err,exit_code,eof in [(missing,b'',0,{'stdout':True,'stderr':True}),(self.outer_stdout,b'',0,{'stdout':False,'stderr':True}),(self.outer_stdout,b'raw failure',0,{'stdout':True,'stderr':True}),(self.outer_stdout,b'',True,{'stdout':True,'stderr':True})]:
                projected=scope['outer_capture_projection'](out,err,exit_code,eof)
                self.assertEqual('unknown',projected['state']);self.assertFalse(projected['replayAllowed'])
            with self.assertRaisesRegex(ValueError,'once_consumed'):dispatcher.run()

class OuterReleaseTests(ActualApi35):

    def actor(self):
        scope = {'__name__': 'local_outer_release', 'COMPONENT_BUNDLE': bundle, 'COMPONENT_RECEIPT': self.fixture.receipt, 'UPDATE_SOURCE_PACKET_SHA': 'b' * 64}
        exec(compile(ENTRY.read_bytes(), str(ENTRY), 'exec'), scope)
        pair = json.loads(self.args.intent_file.read_bytes())['pair']
        scope.update(UPDATE_BASE=pair['baseSha256'], UPDATE_TARGET=pair['targetSha256'], UPDATE_SIGNER=pair['signerSha256'])
        for name in ('ca_certificate', 'leaf_certificate', 'private_key'):
            path = self.fixture.root / (name + '.pem')
            path.write_bytes(b'INERT-OS-CERTIFICATE-SEAM')
            setattr(self.args, name, path)
        self.args.device_port = 45635
        self.args.continue_file = self.args.output / 'continue'
        self.args.handoff_ready_file = self.args.output / 'handoff-ready'
        self.args.governed_callbacks = True
        self.args.expected_terminal = 'installed'
        self.args.reconciliation_timeout_seconds = 1.0
        self.args.reconciliation_poll_seconds = 0.01
        intent = json.loads(self.args.intent_file.read_bytes())
        intent['expectedTerminal'] = 'installed'
        self.args.intent_file.write_text(json.dumps(intent))
        self.stage_fixture_assets()
        actor = scope['CompleteUpdate'](self.args, self.backend)
        import os
        scope['outer_process_identity'] = lambda pid=None: {'pid': os.getpid(), 'startTicks': 1, 'bootId': '5be1a80b-c97e-4622-aa07-ff761767622f', 'uid': os.getuid(), 'gid': os.getgid(), 'groups': sorted(os.getgroups())}
        return (actor, scope['CompleteUpdateOuter'](actor), scope)

    def test_actual_durable_dispatch_unlink_refuses_before_actor_and_is_sticky(self):
        from unittest import mock
        actor, dispatcher, scope = self.actor()
        write = bundle._write

        def unlink(path, raw):
            result = write(path, raw)
            if path.name == '00001-dispatch.json':
                path.unlink()
            return result
        with mock.patch.object(bundle, '_write', side_effect=unlink), self.assertRaises(FileNotFoundError):
            dispatcher.run()
        self.assertFalse(actor.started)
        self.assertIsNone(actor.thread)
        self.assertTrue(dispatcher.unknown)
        with self.assertRaisesRegex(ValueError, 'once_consumed'):
            dispatcher.run()
        self.assertFalse((self.args.output / 'complete-update-dispatch-intent.json').exists())

    def test_actual_source_replacement_after_dispatch_refuses_before_actor(self):
        from unittest import mock
        actor, dispatcher, scope = self.actor()
        write = bundle._write

        def replace(path, raw):
            result = write(path, raw)
            if path.name == '00001-dispatch.json':
                (Path(self.fixture.receipt['directory']) / bundle.FILES[0]).chmod(384)
            return result
        with mock.patch.object(bundle, '_write', side_effect=replace), self.assertRaises(ValueError):
            dispatcher.run()
        self.assertFalse(actor.started)
        self.assertIsNone(actor.thread)
        self.assertTrue(dispatcher.unknown)

    def test_actual_callback_foreign_binding_retained_unknown_no_new_worker(self):
        actor, dispatcher, scope = self.actor()
        request = {**dispatcher.packet, 'phase': 'handoff-ready', 'correlationId': '739cb5c2-c8de-4bc6-994f-85be1cffd77a'}
        bundle._write(dispatcher.directory / 'request-handoff-ready.json', bundle._raw(request))
        with self.assertRaisesRegex(ValueError, 'callback_binding_changed'):
            dispatcher._callback('handoff-ready')
        self.assertFalse(actor.started)
        self.assertIsNone(actor.thread)
        self.assertFalse((dispatcher.directory / 'result-handoff-ready.json').exists())

    def test_actual_bound_asset_drift_refuses_next_task_guard(self):
        actor,dispatcher,scope=self.actor()
        original=copy.deepcopy(actor.guard.expected);phase_pins=copy.deepcopy(actor.guard.phase_pins)
        self.args.ca_certificate.write_bytes(b'foreign-TLS-material')
        with self.assertRaisesRegex(ValueError,'evidence_generation_changed|fixture_asset_changed'):
            actor.guard._task_guard()
        self.assertEqual(actor.guard.expected,original);self.assertEqual(actor.guard.phase_pins,phase_pins)
        self.assertFalse(actor.started)

@unittest.skipUnless(os.name=='posix','Actual POSIX private FD custody; portable refusal tested separately')
class AssetCustodyTests(unittest.TestCase):
    def setUp(self):
        import tempfile,shutil
        from agent_tools import android_fixture_tls_mint as mint,android_native_fixture as fixture
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.root.chmod(0o700)
        self.ns={'__name__':'ordinary_local_asset_source','COMPONENT_BUNDLE':bundle,'ROOT':self.root,'UPDATE_CORRELATION':bf.CORRELATION}
        exec(compile(ENTRY.read_bytes(),str(ENTRY),'exec'),self.ns)
        source=self.root/('android-complete-update-inputs-'+bf.CORRELATION);source.mkdir(mode=0o700)
        # Synthetic bytes are explicitly a local custody seam, never official
        # artifact/signature or native acceptance authority. Sizes stay fixed.
        for name,key in [('base.apk','UPDATE_BASE'),('target.apk','UPDATE_TARGET')]:
            path=source/name
            with path.open('wb')as stream:stream.write(name.encode());stream.truncate(45026948)
            path.chmod(0o600);self.ns[key]=self.ns['outer_file'](path,45026948)['sha256']
        plan={'sourceSha':self.ns['UPDATE_PRODUCT'],'baseArtifactId':'sha256-'+self.ns['UPDATE_BASE'],'baseVersion':'2.2.2','baseCode':16840,
            'baseSignerSha256':self.ns['UPDATE_SIGNER'],'targetArtifactId':'sha256-'+self.ns['UPDATE_TARGET'],'targetVersion':'2.2.3','targetCode':16860,
            'targetSha256':self.ns['UPDATE_TARGET'],'targetSize':45026948,'endpoint':fixture.endpoint_contract(),'deviceMutationAllowed':False}
        result=mint.mint(self.root,bf.CORRELATION,plan);capsule=Path(result['directory']);self.ca_key=capsule/'ca-key.pem'
        for dest,origin in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem'),('receipt.json','receipt.json')]:
            shutil.copyfile(capsule/origin,source/dest);(source/dest).chmod(0o600)
        lease=self.root/'android-native-device-android-api35.lease'
        bundle._write(lease,bundle._raw({'owner':'android-installer','host':'archlinux','device':'android-api35','correlationId':bf.CORRELATION}))
        read=self.ns['outer_file'];self.authority={'schema':1,'correlationId':bf.CORRELATION,'productSourceSha':self.ns['UPDATE_PRODUCT'],
            'inputDirectory':str(source),'files':{n:read(source/n,45026948 if n.endswith('.apk')else 65536)for n in self.ns['OUTER_FILES']},
            'tlsReceipt':read(source/'receipt.json',65536),'lease':read(lease,65536)}

    def test_actual_mint_copy_birth_full_sha_and_once(self):
        import resource
        before=resource.getrlimit(resource.RLIMIT_FSIZE);secret=self.ca_key.read_bytes()
        value=self.ns['outer_stage_assets'](self.authority)
        self.assertEqual(before,resource.getrlimit(resource.RLIMIT_FSIZE));self.assertEqual(secret,self.ca_key.read_bytes())
        self.assertFalse((value['assets']/'ca-key.pem').exists())
        for name in self.ns['OUTER_FILES']:
            self.assertEqual(self.authority['files'][name]['sha256'],self.ns['outer_file'](value['assets']/name,45026948)['sha256'])
        self.assertEqual(value['journalPin'],self.ns['outer_file'](value['output']/'asset-stage.json',65536))
        with self.assertRaises(FileExistsError):self.ns['outer_stage_assets'](self.authority)

    def test_actual_source_and_typed_pin_drift_precede_mkdir(self):
        bad=copy.deepcopy(self.authority);bad['files']['base.apk']['generation'][5]=True
        with self.assertRaisesRegex(ValueError,'outer_pin_invalid'):self.ns['outer_stage_assets'](bad)
        Path(self.authority['files']['ca.pem']['path']).write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError,'outer_asset_source_changed'):self.ns['outer_stage_assets'](self.authority)
        self.assertFalse((self.root/('android-installer-component-baseline-'+bf.CORRELATION)).exists())

    def test_actual_partial_write_restores_limit_no_success_journal(self):
        import resource
        from unittest import mock
        before=resource.getrlimit(resource.RLIMIT_FSIZE)
        with mock.patch.object(os,'write',side_effect=OSError('explicit inert actual FD write failure')),self.assertRaises(OSError):
            self.ns['outer_stage_assets'](self.authority)
        self.assertEqual(before,resource.getrlimit(resource.RLIMIT_FSIZE))
        self.assertFalse((self.root/('android-installer-component-baseline-'+bf.CORRELATION)/'asset-stage.json').exists())

    def test_actual_tracked_initializer_stages_and_binds_original_intent_before_actor(self):
        """Routing observations are inert here; full real routing is in whole flow."""
        from unittest import mock
        from agent_tools import android_installer_target as target
        fixture=bf.BundleTests();fixture.setUp();self.addCleanup(fixture.tearDown)
        _selected,backend,_args,*_=fixture.api35_fixture()
        pair={'sourceSha':bundle._PRODUCT_SHA,'baseArtifactId':'sha256-'+self.ns['UPDATE_BASE'],'baseSha256':self.ns['UPDATE_BASE'],
            'baseVersion':'2.2.2','baseCode':16840,'targetArtifactId':'sha256-'+self.ns['UPDATE_TARGET'],'targetSha256':self.ns['UPDATE_TARGET'],
            'targetVersion':'2.2.3','targetCode':16860,'signerSha256':self.ns['UPDATE_SIGNER']}
        backup=self.root/'inert-routing-backup.json';bundle._write(backup,bundle._raw({'type':'vpn_control_routing_rules','version':7,'rules':{}}))
        self.ns.update(UPDATE_ASSET_AUTHORITY=self.authority,UPDATE_PAIR=pair,COMPONENT_RECEIPT=fixture.receipt,
            UPDATE_SOURCE_PACKET_SHA='a'*64,UPDATE_BASELINE_REQUEST={'correlationId':'ebf29407-17f9-42ac-b41a-6bc9af2f8f60',
                'expectedAvd':'fixture-api35','expectedOwner':bf.OWNER,'expectedRevision':0},
            LAUNCH=backend['LAUNCH'],GETTER=backend['GETTER'])
        record={'path':str(backup),'sha256':bundle._read(backup,True)[1]['sha256'],'size':backup.stat().st_size}
        with mock.patch.object(bundle,'routing_backup',return_value=record)as routing:
            prepared=self.ns['complete_update_prepare']()
        routing.assert_called_once();args=prepared['args'];intent=target.load_intent(args.intent_file)
        self.assertEqual(intent['expectedOwner'],bf.OWNER);self.assertEqual(intent['pair']['targetSha256'],pair['targetSha256'])
        self.assertEqual(args.output,self.root/('android-installer-component-baseline-'+bf.CORRELATION))
        self.assertTrue((args.output/'asset-stage.json').is_file());self.assertFalse(prepared['nativeSubmitted'])
        self.assertFalse(prepared['installerLeaseGranted']);self.assertIs(args.governed_callbacks,True)
        self.assertFalse((args.output/'outer').exists())

    def test_malformed_future_inputs_refuse_before_read_only_backup_or_staging(self):
        from unittest import mock
        self.ns['UPDATE_ASSET_AUTHORITY']=copy.deepcopy(self.authority)
        self.ns['UPDATE_ASSET_AUTHORITY']['files']['base.apk']['generation'][5]=True
        with mock.patch.object(bundle,'routing_backup',side_effect=AssertionError('not released')),self.assertRaisesRegex(ValueError,'outer_pin_invalid'):
            self.ns['complete_update_prepare']()
        self.assertFalse((self.root/('android-installer-component-baseline-'+bf.CORRELATION)).exists())

class PortableOuterDecisions(unittest.TestCase):
    def namespace(self):
        scope={'__name__':'portable_source_only','UPDATE_CORRELATION':bf.CORRELATION}
        exec(compile(ENTRY.read_bytes(),str(ENTRY),'exec'),scope)
        return scope

    def test_unavailable_native_apis_refuse_before_file_or_process_effect(self):
        from unittest import mock
        ns=self.namespace()
        for name in ('getuid','getsid','getgroups'):
            with self.subTest(name=name),mock.patch.object(ns['outer_os'],name,None,create=True),mock.patch.object(ns['outer_os'],'open',side_effect=AssertionError('effect forbidden')):
                for call in [lambda:ns['outer_file']('/unavailable',1),lambda:ns['outer_process_identity'](),lambda:ns['outer_stage_assets']({})]:
                    with self.assertRaisesRegex(ValueError,'outer_posix_custody_required'):call()

    def test_read_only_guard_cannot_bind_installer_assets(self):
        from unittest import mock
        guard=object.__new__(bundle.BaselineGuard)
        with mock.patch.object(bundle,'_fixture_asset_record',side_effect=AssertionError('file effect forbidden')),self.assertRaisesRegex(ValueError,'installer_asset_scope_required'):
            guard.bind_fixture_assets({})

    def test_missing_fcntl_refuses_before_effect(self):
        from unittest import mock
        ns=self.namespace()
        with mock.patch.dict(sys.modules,{'fcntl':None}),mock.patch.object(ns['outer_os'],'open',side_effect=AssertionError('effect forbidden')):
            with self.assertRaisesRegex(ValueError,'outer_posix_custody_required'):ns['outer_file']('/unavailable',1)

    def test_source_fence_and_missing_eof_never_submit_or_accept(self):
        ns=self.namespace();source=ns['outer_namespace_source'](ENTRY.read_bytes())
        self.assertIn('def complete_update_outer_main',source)
        self.assertEqual(ns['outer_capture_projection'](b'',b'',0,True)['state'],'unknown')
        with self.assertRaises(ValueError):ns['outer_namespace_source'](b'print("foreign")')

class StrictOuterWireTests(unittest.TestCase):
    def test_actual_projection_duplicate_authority_is_unknown(self):
        # Inert public wire DTO; this is a parser contract, not native authority.
        scope=PortableOuterDecisions().namespace();corr=bf.CORRELATION;source='a'*64
        scope['UPDATE_SOURCE_PACKET_SHA']=source
        pin={'generation':[1,2,3,4,5,6,7,8,9],'parents':{'/public-fixture':[1,2,3,4,5]},'sha256':'b'*64}
        start={'correlationId':corr,'sourcePacketSha256':source,'identity':{'pid':1,'startTicks':1,'bootId':corr,'uid':0,'gid':0,'groups':[0]},'intentPin':pin,'dispatchPin':pin}
        result={'ok':True,'state':'complete','correlationId':corr,'terminal':'installed','operationId':corr,'receiptId':'INERT','sessionId':1,'terminalOwner':corr,'terminalRevision':1,'replayAllowed':False,'routingEqual':True,'routingManifests':[{},{}],'componentRuntime':'EXTERNAL_JDK','installedLauncherAccepted':False,'bundledRuntimeAccepted':False,'fixtureCleanupObserved':True,'componentUpdateScenarioComplete':True}
        end={'schema':1,'correlationId':corr,'result':result,'replayAllowed':False}
        encode=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'))
        prefix='COMPLETE_UPDATE_ACCEPTED '+encode(start)+'\nCOMPLETE_UPDATE_TERMINAL '
        tail='\nCOMPLETE_UPDATE_EOF '+corr+' '+source+'\n';body=encode(end)
        project=lambda raw:scope['outer_capture_projection'](raw.encode(),b'',0,{'stdout':True,'stderr':True})
        self.assertEqual('complete',project(prefix+body+tail)['state'])
        for label,changed in [('terminal','{"replayAllowed":true,'+body[1:]),('result',body.replace('"result":{','"result":{"replayAllowed":true,',1)),('routing',body.replace('"routingManifests":[{}','"routingManifests":[{"same":true,"same":false}',1))]:
            with self.subTest(label=label):self.assertEqual('unknown',project(prefix+changed+tail)['state'])
        accepted=encode(start);changed='{"correlationId":"FOREIGN",'+accepted[1:]
        self.assertEqual('unknown',project('COMPLETE_UPDATE_ACCEPTED '+changed+'\nCOMPLETE_UPDATE_TERMINAL '+body+tail)['state'])

def load_tests(loader, tests, pattern):
    return unittest.TestSuite([WholeEntryTests('test_actual_persistent_outer_callbacks_and_terminal'), OuterReleaseTests('test_actual_durable_dispatch_unlink_refuses_before_actor_and_is_sticky'), OuterReleaseTests('test_actual_source_replacement_after_dispatch_refuses_before_actor'), OuterReleaseTests('test_actual_callback_foreign_binding_retained_unknown_no_new_worker'),OuterReleaseTests('test_actual_bound_asset_drift_refuses_next_task_guard'),loader.loadTestsFromTestCase(PortableOuterDecisions),loader.loadTestsFromTestCase(StrictOuterWireTests),loader.loadTestsFromTestCase(AssetCustodyTests)])
if __name__ == '__main__':
    unittest.main()
