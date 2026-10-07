"""Public historical factories over a private, synthetic TempFS ledger.

Only the upstream preflight producer and historical protocol receipts are
modeled. Actual source loaders, census/alias/coldboot/getter factories and FD
snapshot guards execute. No checkout journal, reservation, configuration,
credential, host inventory or native programme is read. These DTOs carry no
native authority. Host/device execution remains each test's declared seam.
"""
import copy
import hashlib
import json
import types
from pathlib import Path
from agent_tools import android_device_availability as availability
from agent_tools.tests.fixtures import historical_source

BASE = Path(__file__).resolve().parent
REPO = BASE.parents[2]
GETTER_SHA = 'c908a23200cf633c9db6a2ccfc057f2e360267519153593a23c4471fbefe528b'
SOURCES = {
    'reader': ('android_component_legacy/android_avd_launch_recovery.source', 'eb89ef4cccdb5417becd02b4116eccd10b2e4da4d9fe81f3a8c54d8f97b13fa0'),
    'diagnostic': ('android_component_legacy/android_avd_census_diagnostic.source', 'ac5c810179a0f3a2efaef3ed18dbe45787cb1b3409c8ac98895d21cea62f6fc8'),
    'alias': ('android_component_legacy/android_avd_sdk_alias_observation.source', 'ab2f1d0249a68a47d7a11ba74400615f0fc9aa27a067a1e0839ee188e63976c9'),
    'census': ('android_component_legacy/android_avd_sdk_alias_census.source', 'caac560d9183469ef1bc8fa4a267c69ca23db3960c43baec1edb02e83fab2ccf'),
    'coldboot': ('android_existing_readonly/coldboot_producer.source', '7d90c06070ffad1439e613c9ad5d63f979d43b738944f0630b2b15187f09fec6'),
    'analog': ('android_component_legacy/product_observer.source', 'ec56e238b0bac95d67ae1942b7218bb844db1e48b29cff1ad7b390b1721d8ae7'),
    'getter': ('android_api35_historical_context.source', GETTER_SHA),
}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class Context:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.modules = {}
        self._temps = []
        self._restore_producers = {}
        for role, (name, sha) in SOURCES.items():
            source = BASE/name
            raw = source.read_bytes()
            if digest(raw) != sha:
                raise ValueError('historical_public_source_changed')
            # Source relocation is explicit; complete authenticated bytes stay
            # unchanged and each function owns this private module namespace.
            path = self.root/'agent_tools'/('android_'+role+'.py')
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            self.modules[role] = historical_source.load(path, sha)
        r, d, a, c, b, analog, g = (self.modules[k] for k in SOURCES)
        d.census = a.census = c.census = b.census = r
        c.diagnostic = d
        c.alias_observation = a
        b.admitted_census = c
        g.coldboot = b
        g.analog = analog
        self.getter = g
        self.reservation = {'reservationId': 'synthetic-api35', 'token': 'synthetic-token',
                            'hostAlias': 'archlinux', 'environment': 'owned-android-api35-coldboot',
                            'operator': 'root-android'}
        row = {'id': self.reservation['reservationId'], **{k: v for k, v in self.reservation.items() if k != 'reservationId'},
               'requestedMemoryBytes': b.MEMORY, 'allocationState': 'running'}
        self.write('.rag_index/native-environments/reservations.json', {'reservations': [row]})
        self._upstream()
        self._receipts()
        # Actual admit creates the synthetic original ledger once. The registry
        # is pending only for admit, then running for readonly status factories.
        row['allocationState'] = 'pending'
        self.write('.rag_index/native-environments/reservations.json', {'reservations': [row]})
        (self.root/'.rag_index').chmod(0o700)
        b.prepare(self.root, 'api35', g.CORRELATION, self.reservation, 'admit')
        row['allocationState'] = 'running'
        self.write('.rag_index/native-environments/reservations.json', {'reservations': [row]})

    def write(self, relative, value, size=None):
        raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()
        if size is not None:
            if len(raw) > size:
                raise AssertionError('synthetic protocol exceeds historical size bound')
            raw += b' '*(size-len(raw))
        path = self.root/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)
        return digest(raw)

    def pin(self, relative, declared_size=None):
        pin, raw = availability._snapshot(self.root/relative)
        # This is a synthetic remote producer descriptor, not a TempFS inode
        # attestation. The actual local reader snapshots remain real separately.
        generation = [1, 2, len(raw) if declared_size is None else declared_size, 4, 5, 0o100600, 0, 0, 1]
        return {'generation': generation, 'sha256': digest(raw), 'bytesRead': len(raw), 'hashScope': 'full'}

    def _upstream(self):
        r = self.modules['reader']
        snapshots = {}
        for name in ('android_device_availability.py', 'android_endpoint_admission.py', 'android_owned_endpoint_bind_recovery.py', 'android_avd_fixture_recovery.py'):
            destination = self.root/'agent_tools'/name
            destination.write_bytes((REPO/'agent_tools'/name).read_bytes())
            snapshots[destination] = availability._snapshot(destination)
        # The producer has no authority to run any native child in this fixture.
        cfg = {'source': {'agent_tools/android_avd_fixture_recovery.py': r.PREFLIGHT_SHA}, 'localClaims': {}}
        self.cfg = cfg
        facts = {'generation': [1, 2, 10, 4, 5, 0o100755, 1000, 1000, 1], 'bytesRead': 10, 'hashScope': 'full', 'sha256': 'a'*64}
        avds = {}
        for device, owned in r.preflight.OWNED.items():
            image = str(Path(owned['sdk'])/'system-images'/('android-'+str(owned['api']))/'google_apis/x86_64/kernel-ranchu')
            avds[device] = {'historicalSelection': copy.deepcopy(owned), 'avdDirectory': {'path': owned['avdHome']+'/'+owned['avd']+'.avd'},
                            'sdkFiles': {owned['emulator']: facts, '/opt/android-sdk/platform-tools/adb': facts, image: facts}}
        self.observation = {'avds': avds, 'processes': {'holders': []}}
        proof = {'source': cfg['source'], 'stable': True, 'observations': [self.observation, self.observation]}
        name = '.runtime/parity-evidence/android-current/owned-avd-preflight-'+r.PROOF_ID+'.json'
        r.PROOF_SHA = self.write(name, proof)
        self.write(name.replace('.json', '.receipt.json'), {'cfg': cfg, 'result': {'pin': self.pin(name)}})
        # Exact source-bound preflight producer seam. All downstream factory
        # functions and their source/snapshot checks are actual implementations.
        def prepare(root, correlation):
            if Path(root).resolve() != self.root or correlation != r.PROOF_ID:
                raise AssertionError('foreign synthetic producer request')
            return copy.deepcopy(cfg), dict(snapshots), {}, {}
        r.preflight = types.SimpleNamespace(**{**vars(r.preflight), '_prepare': prepare})
        for attr, name in (('availability', 'android_device_availability.py'), ('endpoint', 'android_endpoint_admission.py'), ('private_io', 'android_owned_endpoint_bind_recovery.py')):
            original = getattr(r, attr)
            setattr(r, attr, types.SimpleNamespace(**{**vars(original), '__file__': str(self.root/'agent_tools'/name)}))

    def _receipts(self):
        r, d, a, c, b, g = (self.modules[k] for k in ('reader', 'diagnostic', 'alias', 'census', 'coldboot', 'getter'))
        def receipt(directory, value, size):
            name = '.runtime/parity-evidence/'+directory+'/remote-full.json'
            sha = self.write(name, value, size)
            self.write('.runtime/parity-evidence/'+directory+'/result.json', {'pin': self.pin(name)})
            return sha
        d.FAILED_SHA = receipt('android-avd-privileged-census-'+d.FAILED_ID, {'correlationId': d.FAILED_ID}, 2053)
        ancestors = [{'level': n, 'kind': 'directory', 'generation': [n]*9} for n in range(1, 5)]
        ancestors.append({'level': 5, 'kind': 'symlink', 'generation': [5]*9})
        diagnostic = {'phase': 'api29-sdk-kernel', 'reason': 'not-directory', 'ancestry': ancestors}
        a.DIAGNOSTIC_SHA = receipt('android-avd-census-diagnostic-'+a.DIAGNOSTIC_ID, {'observations': [diagnostic, diagnostic]}, 3607)
        # Obtain ALIAS from the actual generator, then model its original public
        # producer's two equal observations; never adopt current filesystem facts.
        prepared = a.prepare_observation(self.root, g.CORRELATION)
        import ast
        alias = ast.literal_eval(next(n.value for n in ast.parse(prepared['program']).body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'ALIAS' for t in n.targets)))
        observation = {'linkGeneration': alias['generation'], 'normalizedTarget': alias['target'], 'linkText': alias['target'],
                       'targetDirectoryGeneration': [6]*9, 'allLeavesMatchHistorical': True, 'targetMatchesKnownSDK': True,
                       'leaves': {k: {'matchesHistorical': True, 'facts': v} for k, v in alias['leaves'].items()}}
        c.ALIAS_SHA = receipt('android-avd-sdk-alias-'+c.ALIAS_ID, {'correlationId': c.ALIAS_ID, 'observations': [observation, observation],
                                 'summary': {'stable': True, 'knownTargetMatched': True, 'historicalLeafFactsMatched': True}, 'lifecycleAllowed': False}, 45643)
        b.CENSUS_SHA = receipt('android-avd-sdk-alias-census-'+b.CENSUS_ID, {'correlationId': b.CENSUS_ID, 'observations': [self.observation, self.observation],
                                'summary': {'stable': True, 'complete': True, 'ownedPortsFree': True}}, None)
        g.STATUS_SHA = self.write('.runtime/parity-evidence/'+g.STATUS, {'state': 'guest-generation-admitted', 'correlationId': g.CORRELATION,
                               'guestAdmitted': True, **copy.deepcopy(g.FIXED_GENERATION)})
        manifest = {'launcherSha256': 'a'*64, 'files': [{'path': 'opt/vpn-control/lib/app/fixture%d.jar'%n} for n in range(57)]}
        g.MANIFEST = digest(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode())
        self.write('.rag_index/android-cli-stages/'+g.STAGE+'/intent.json', {'correlationId': g.STAGE, 'fixtureRoot': '/home/kardinal/.vpn-control-mcp-fixtures',
                   'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557', 'manifestSha256': g.MANIFEST, 'manifest': manifest, 'rpmSha256': 'b'*64})
        self.write('.runtime/parity-evidence/android-current/d32-apk/receipt.json', {'sha256': g.APK, 'bytes': 45026948, 'sourceSha': 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557'})
        script = self.root/'scripts/android_no_update_tls_preflight.py'
        script.parent.mkdir()
        script.write_bytes((REPO/'scripts/android_no_update_tls_preflight.py').read_bytes())

    def prepare(self):
        return self.getter.prepare(self.root, dict(self.reservation))

    def consumer(self, module):
        """Clone a public consumer, retaining its exact source guards."""
        name = Path(module.__file__).name
        key = 'consumer:'+name
        if key in self.modules:
            return self.modules[key]
        raw = Path(module.__file__).read_bytes()
        destination = self.root/'agent_tools'/name
        destination.write_bytes(raw)
        value = historical_source.load(destination, digest(raw))
        self.modules[key] = value
        for attribute, dependency in list(vars(value).items()):
            if not isinstance(dependency, types.ModuleType):
                continue
            depname = getattr(dependency, '__name__', '')
            if depname == 'agent_tools.android_api35_coldboot_product_observation':
                setattr(value, attribute, self.getter)
            elif depname == 'agent_tools.android_avd_coldboot':
                setattr(value, attribute, self.modules['coldboot'])
            elif depname.startswith('agent_tools.android_api35_'):
                setattr(value, attribute, self.consumer(dependency))
        if name == 'android_api35_current_proxy_dex_observation.py':
            self._dex_receipts(value)
        elif name == 'android_api35_routing_step_diagnostic.py':
            value.PRIOR_SHA = self.write(value.PRIOR, {'productAdmitted': False, 'reason': 'getter_command_timeout',
                'records': {'statusBefore': {'stdout': {'controllerId': value.OWNER}}}})
        elif name == 'android_api35_proxy_stage_diagnostic.py':
            historic = historical_source.load(BASE/'android_api35_proxy_probe_initial.py', value.SOURCE_SHA)
            value.consumed = self.consumer(historic)
            result = {'correlationId': value.CORRELATION, 'state': 'diagnostic-only', 'reason': 'probe_command_unknown',
                      'closingGuardsVerified': True, 'effectiveProxy': None, 'stageFence': {},
                      'records': {'stageReply': {'exitCode': 1, 'stdoutBase64': '', 'stderrBase64': ''}}}
            import base64
            raw = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
            value.RESULT_SHA = digest(raw)
            value.RESULT_FILE_SHA = self.write('.runtime/parity-evidence/'+value.CAPSULE+'/stdout-0.private',
                                               b'out:'+base64.b64encode(raw)+b'\n')
        elif name == 'android_api35_owned_proxy_restore.py':
            self._restore_receipts(value)
        return value

    def _component(self, owner):
        archive = BASE/'android_api29_epoch/component.source'
        raw = archive.read_bytes()
        if digest(raw) != owner.COMPONENT_SOURCE:
            raise ValueError('historical_component_source_changed')
        path = self.root/'agent_tools/android_external_java_component_transport.py'
        path.write_bytes(raw)
        component = historical_source.load(path, owner.COMPONENT_SOURCE)
        # Public source relocation only; source pins remain c466/ec56/818f.
        component.getter_source = self.modules['analog']
        for attribute in ('proven', 'bounded_source'):
            source = getattr(component, attribute)
            dest = self.root/'agent_tools'/Path(source.__file__).name
            content = Path(source.__file__).read_bytes()
            dest.write_bytes(content)
            setattr(component, attribute, historical_source.load(dest, digest(content)))
        proven = component.proven
        options = ['-Djpackage.app-version=2.2.2', '-Dcompose.application.resources.dir=$APPDIR/resources', '-Dcompose.application.configure.swing.globals=true', '-Dskiko.library.path=$APPDIR']
        config = ('app.mainclass=com.kardinal.vpncontrol.desktop.MainKt\n'+''.join('app.classpath=$APPDIR/fixture%d.jar\n'%n for n in range(57))+''.join('java-options='+v+'\n' for v in options)).encode()
        proven.CONFIG_SHA = self.write('.rag_index/android-cli-stages/'+self.getter.STAGE+'/tree/opt/vpn-control/lib/app/vpn-control.cfg', config)
        selected = {'state': 'observed', 'alias': 'jdk17', 'root': proven.CANDIDATES['jdk17'], 'declaredJavaVersion': '17.0.20.1',
                    'files': {name: {'generation': [1, 2, 10, 4, 5, 0o100755, 0, 0, 1], 'bytesRead': 10, 'sha256': 'd'*64, 'hashScope': 'full'} for name in proven.JDK_FILES}}
        census = {'state': 'external-jdk-census', 'censusComplete': True, 'closingGuardsVerified': True, 'componentRuntime': 'EXTERNAL_JDK',
                  'sourceSha256': component.SOURCE_SHA, 'originalSourceSha256': proven.ORIGINAL_SHA, 'baselineSha256': proven.BASELINE_SHA,
                  'generation': self.getter.FIXED_GENERATION, 'stageId': self.getter.STAGE, 'packageSha256': self.getter.APK,
                  'cliStagePins': [{'syntheticProtocol': True}]*2, 'candidates': {'jdk17': selected, 'jdk21': {'state': 'unknown'}}}
        component.CENSUS_SHA = self.write(proven.CENSUS, census)
        component.PROOF_SHA = self.write(component.PROOF, {'componentFlowObserved': True, 'closingGuardsVerified': True,
                        'jdkClosingGuardsVerified': True, 'installedLauncherAccepted': False, 'bundledRuntimeAccepted': False, 'selectedJdk': selected})
        owner.component = component

    def _stage_generation(self, owner):
        from agent_tools.tests import test_android_api35_current_proxy_probe as probes
        return {'directory': probes.PARENT, 'file': probes.FILE, 'sha256': owner.DEX_SHA}

    def _restore_receipts(self, owner):
        self._component(owner)
        owner.DEX_SHA = owner.current.admission.DEX_SHA
        owner.CURRENT_RECEIPT = self.write('.runtime/parity-evidence/'+owner.CAPSULE+'/result-0.private',
            {'state': 'current-os-proxy-observed', 'closingGuardsVerified': True, 'correlationId': owner.PROBE_CORRELATION,
             'proxyObservationVerified': True, 'stageFence': {}, 'deviceStageGeneration': self._stage_generation(owner)})
        owner.HISTORY = copy.deepcopy(owner.HISTORY)
        baseline = {'http_proxy': 'null', 'global_http_proxy_host': 'null', 'global_http_proxy_port': 'null', 'global_http_proxy_pac': 'null', 'global_http_proxy_exclusion_list': ''}
        commands = [{} for _ in range(340)]
        for index, value in ((333, '127.0.0.1:45635'), (339, 'null')):
            commands[index] = {'args': ['shell', 'settings', 'put', 'global', 'http_proxy', value], 'exit': 0, 'stderr': '', 'stderrTruncated': False, 'stdout': '', 'stdoutTruncated': False}
        owner.HISTORY['lifecycleSha256'] = self.write('.runtime/parity-evidence/android-current/api35-update-0dd-lifecycle-receipt.json',
                                               {'effectiveProxyBaseline': baseline, 'commands': commands})
        retirement = self.write('.runtime/parity-evidence/android-current/api35-retirement-d0fb-native-receipt.json',
                    {'effectiveProxy': {'baseline': baseline, 'originalCombinedProxyCommands': [{'exit': 0, 'index': 333, 'sha256': owner.HISTORY['setupSha256']}, {'exit': 0, 'index': 339, 'sha256': owner.HISTORY['cleanupSha256']}]}})
        old = '96489c3073bb358ba9a51e61331c6dc67eefae5de7c13f0dd2cff727c0b04eba'
        original = owner._authority
        constants = original.__code__.co_consts
        if constants.count(old) != 1:
            raise ValueError('historical_retirement_digest_role_changed')
        code = original.__code__.replace(co_consts=tuple(retirement if c == old else c for c in constants))
        if code.co_code != original.__code__.co_code or any(a != b for a, b in zip(constants, code.co_consts) if a != old):
            raise ValueError('historical_retirement_control_flow_changed')
        owner._authority = types.FunctionType(code, original.__globals__, original.__name__, original.__defaults__, original.__closure__)
        owner._syntheticRetirementDigestBinding = {'original': old, 'synthetic': retirement, 'nativeAuthority': False}
        for name, key in (('intent.json', 'intentSha256'), ('dispatch.json', 'dispatchSha256')):
            owner.HISTORY[key] = self.write('.rag_index/android-installer-dispatch/'+owner.HISTORY['correlationId']+'/'+name, {'syntheticProtocol': True, 'role': name})

    def restore_metadata(self, owner):
        """Generate the original unit arm and metadata through real producers.

        Only device/principal/transport seams belong to RestoreTests.full;
        source helpers, local intent, journals, full pins and FD guards remain
        actual. The generated programme is unit output, never a native archive.
        """
        from unittest import mock
        from agent_tools.tests import test_android_api35_owned_proxy_restore as cases
        path = self.root/'agent_tools'/'historical_owned_proxy_arm.py'
        raw = (BASE/'android_api35_historical_arm.source').read_bytes()
        if digest(raw) != owner._INTERRUPTED_SOURCE:
            raise ValueError('historical_arm_public_source_changed')
        path.write_bytes(raw)
        old = historical_source.load(path, owner._INTERRUPTED_SOURCE)
        for name in ('current', 'coldboot', 'availability', 'component', 'CURRENT_RECEIPT', 'HISTORY', 'DEX_SHA'):
            setattr(old, name, getattr(owner, name))
        # Same actual authority body, with the approved isolated receipt digest
        # seam already applied; function globals belong to this old module.
        if old._authority.__code__.co_code != owner._authority.__code__.co_code:
            raise ValueError('historical_authority_body_changed')
        old._authority = types.FunctionType(owner._authority.__code__, vars(old))
        prepared = old.prepare(self.root, self.reservation, owner._INTERRUPTED, 'arm')
        owner._INTERRUPTED_PROGRAM = self.write('.runtime/parity-evidence/'+owner._INTERRUPTED_CAPSULE+'/arm-program.py', prepared['program'].encode())
        self.write('.runtime/parity-evidence/'+owner._INTERRUPTED_CAPSULE+'/helper.py', raw)
        current = owner.arm_metadata(self.root, self.reservation)
        case = cases.RestoreTests()
        with mock.patch.object(cases, 'ROOT', self.root), mock.patch.object(cases, 'restore', owner), mock.patch.object(cases, 'coldboot', self.modules['coldboot']), mock.patch.object(cases, 'CORRELATION', owner._INTERRUPTED), mock.patch.object(cases.probes, 'probe', owner.current):
            tmp, device, directory, execute = case.full(prepared_override=current)
            try:
                armed = execute('arm')
                if armed['state'] != 'restore-armed':
                    raise AssertionError(armed['reason'])
                metadata = execute('metadata')
                if metadata['state'] != 'arm-metadata-observed':
                    raise AssertionError(metadata['reason'])
                # The device/principal seam produced this actual parent fence.
                # Bind that observed unit record through the real assignment
                # composer; do not copy any historical native programme.
                original_binding = copy.deepcopy(prepared['restoreBinding'])
                original_binding['stageFence'] = case.original_stage_fence
                owner._replace_restore(prepared, original_binding)
                owner._INTERRUPTED_PROGRAM = self.write('.runtime/parity-evidence/'+owner._INTERRUPTED_CAPSULE+'/arm-program.py', prepared['program'].encode())
                owner._ORIGINAL_ARM_GEN = metadata['result']['record']['generation']
                owner._ORIGINAL_ARM_SHA = metadata['result']['record']['sha256']
                owner._METADATA_SHA = self.write('.runtime/parity-evidence/'+owner._METADATA_CAPSULE+'/metadata-remote-stdout-0.private', metadata)
            finally:
                self._temps.append(tmp)
                self._restore_producers[id(owner)] = (case.generated_namespace, directory)
        metadata_raw = (BASE/'android_api35_historical_metadata.source').read_bytes()
        if digest(metadata_raw) != owner._METADATA_SOURCE:
            raise ValueError('historical_metadata_public_source_changed')
        self.write('.runtime/parity-evidence/'+owner._METADATA_CAPSULE+'/helper.py', metadata_raw)

    def partial_context(self, module):
        # This observer consumes the exact old source recipe, not the current
        # source-compatible restore test branch. Authenticate complete bytes.
        raw = (BASE/'android_api35_historical_readmission.source').read_bytes()
        if digest(raw) != module.SOURCE:
            raise ValueError('historical_readmission_public_source_changed')
        path = self.root/'historical_sources'/'android_api35_owned_proxy_restore.py'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        historical = historical_source.load(path, module.SOURCE)
        self.modules.pop('consumer:'+path.name, None)
        owner = self.consumer(historical)
        module.original = owner
        self.restore_metadata(owner)
        ns, directory = self._restore_producers[id(owner)]
        admitted = owner.readmission_admit(self.root, self.reservation, module.OPERATION)
        operation = admitted['restoreBinding']['readmission']
        body = {'schema': 1, 'operation': operation, 'originalArmPin': operation['originalArmPin'],
                'originalOutcome': 'unknown', 'replayAllowed': False}
        record = ns['restore_record'](directory, 'readmission.json', body)
        document = {'state': 'restore-readmission-admitted', 'closingGuardsVerified': True,
                    'correlationId': owner._INTERRUPTED, 'historicalUnknownsPreserved': True,
                    'replayAllowed': False, 'result': {'record': record}}
        raw = json.dumps(document).encode()
        owner.retain_readmission(self.root, admitted, raw)
        owner.readmission_restore_once(self.root, self.reservation, module.OPERATION)
        module.PROOFS = {name: self.write('.runtime/parity-evidence/'+module.CAPSULE+'/'+name,
                             document if name.startswith('admit-') else {'syntheticProtocol': True, 'originalOutcome': 'unknown'})
                         for name in module.PROOFS}

    def remaining_context(self, owner):
        from unittest import mock
        from agent_tools.tests import test_android_api35_partial_proxy_diagnostic as cases
        self.partial_context(owner.diagnostic)
        original = owner.diagnostic.original
        bindings = ((cases,'ROOT',self.root), (cases,'diagnostic',owner.diagnostic), (cases,'OWNER',owner.OWNER),
                    (cases.restored,'restore',original), (cases.restored,'coldboot',self.modules['coldboot']),
                    (cases.probes,'probe',original.current))
        import contextlib
        with contextlib.ExitStack() as stack:
            for module, name, value in bindings:
                stack.enter_context(mock.patch.object(module, name, value))
            tmp, document, calls, before, after = cases.PartialTests().full()
            try:
                if document['observationComplete'] is not True:
                    raise AssertionError(document['reason'])
                if before != after:
                    raise AssertionError('unit diagnostic mutated journal')
                owner.PROOF_SHA = self.write('.runtime/parity-evidence/'+owner.PROOF_CAPSULE+'/diagnostic-remote-stdout-0.private', document)
                (self.root/'.runtime/parity-evidence'/owner.PROOF_CAPSULE).chmod(0o700)
            finally:
                tmp.cleanup()

    def close(self):
        for temporary in self._temps:
            temporary.cleanup()

    def _dex_receipts(self, module):
        """Compiler protocol seam; no compiler/native binary is executed/read."""
        self.write('agent_tools/fixtures/android_proxy_os_probe/ProxyProbe.java',
                   (REPO/'agent_tools/fixtures/android_proxy_os_probe/ProxyProbe.java').read_bytes())
        directory = Path('.rag_index/android-proxy-os-observation')/module.HISTORY
        raw = b'dex\n039\0'+b'\0'*(module.DEX_BYTES-8)
        module.DEX_SHA = self.write(directory/'dex/classes.dex', raw)
        self.write(directory/'intent.json', {'correlationId': module.HISTORY, 'javaSha256': module.JAVA_SHA,
                                            'artifactPath': str(self.root/directory/'dex/classes.dex')})
        def pin(name):
            generation, body = availability._snapshot(self.root/directory/name)
            return {'generation': [*generation[:5], generation[5]&0o777, generation[6], generation[8]], 'sha256': digest(body)}
        intent = pin('intent.json')
        self.write(directory/'compiler-receipt.json', {'correlationId': module.HISTORY, 'javaSha256': module.JAVA_SHA,
                    'artifactSha256': module.DEX_SHA, 'intentPin': intent, 'commands': [{'exit': 0}, {'exit': 0}]})
        self.write(directory/'artifact.json', {'correlationId': module.HISTORY, 'javaSha256': module.JAVA_SHA,
                    'intentPin': intent, 'compilerReceiptPin': pin('compiler-receipt.json'), 'artifactPin': pin('dex/classes.dex')})


def install(test, namespace, *bindings):
    """Own one TempFS per actual factory test; never change shared modules."""
    import tempfile
    from unittest import mock
    temporary = tempfile.TemporaryDirectory(prefix='api35-public-history-')
    test.addCleanup(temporary.cleanup)
    context = Context(Path(temporary.name))
    replacements = {'ROOT': context.root}
    for binding in bindings:
        replacements[binding] = context.getter if binding == 'getter' else context.consumer(namespace[binding])
    patch = mock.patch.dict(namespace, replacements)
    patch.start()
    test.addCleanup(patch.stop)
    test.history = context
    test.addCleanup(context.close)
    return context
