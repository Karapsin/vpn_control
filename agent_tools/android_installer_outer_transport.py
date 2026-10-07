"""Finite source-closed API35 complete-update actor and persistent transport.

No import or direct CLI invocation submits work. The authenticated initializer
must supply genuine current backend/receipt, typed future lease/assets and source
packet. Read-only callbacks never click a dialog or issue another install.
"""
# Actor origin candidate1612 SHA ba31de2e690f00b6fd67dcb99a40455aa0ca64ec5d473cd1723cff18d899ea4c
"""Source-closed API35 installer composition. Import never submits native work.

Append only to bundle.carrier_source's genuine namespace. This composition
contains no SSH entry, arbitrary command callback or device lease creation.
Operator must separately admit the exact installer lease and staged asset pins.
"""
import ast as update_ast
import copy as update_copy
import hashlib as update_hashlib
import json as update_json
import re as update_re
import threading as update_threading
import time as update_time
import types as update_types
import xml.etree.ElementTree as update_et
UPDATE_PRODUCT = 'd32f719a08db57e5d40ce2bf77e0d7c5b42de557'
UPDATE_BASE = '352af218242311884a355f789c0d1c45b736c35270b096f41408de55e2c4ed33'
UPDATE_TARGET = '2734b5da9b3e8becbe54bc7e980f06402f65994e071ef95123511ddaac78bcf9'
UPDATE_SIGNER = 'a43b5330501b02f5558fa381c52e7f7dcdd9db362d6807d449d7bbb5e207c5a0'

def update_equal(a, b):
    return update_json.dumps(a, sort_keys=True, separators=(',', ':'), allow_nan=False) == update_json.dumps(b, sort_keys=True, separators=(',', ':'), allow_nan=False)

def update_main_factory(selected, args, backend):
    """Actual main body, two finite substitutions; unchanged action/TLS semantics.

    parse_args is replaced by already typed/bound exact args. Environment is
    explicitly the seven-key LAUNCH source authority, passed to the ORIGINAL
    public_cli_environment. No subprocess, action or cleanup statement changes.
    """
    lifecycle = selected['lifecycle']
    source = COMPONENT_BUNDLE.load(COMPONENT_RECEIPT)['scripts/android_installer_lifecycle.py']
    nodes = [n for n in update_ast.parse(source).body if isinstance(n, update_ast.FunctionDef) and n.name == 'main']
    if len(nodes) != 1:
        raise ValueError('update_main_source_changed')
    node = update_copy.deepcopy(nodes[0])
    node.name = 'complete_update_main'
    first = node.body[0]
    if update_ast.unparse(first) != 'args = parse_args()':
        raise ValueError('update_main_parse_changed')
    first.value = update_ast.Name(id='UPDATE_BOUND_ARGS', ctx=update_ast.Load())
    matches = [n for n in update_ast.walk(node) if isinstance(n, update_ast.Call) and update_ast.unparse(n.func) == 'tls.public_cli_environment']
    if len(matches) != 1 or update_ast.unparse(matches[0]) != 'tls.public_cli_environment(args.adb, args.cli)':
        raise ValueError('update_main_environment_changed')
    matches[0].args.append(update_ast.Name(id='UPDATE_SOURCE_ENVIRONMENT', ctx=update_ast.Load()))
    scope = dict(lifecycle.__dict__)
    scope.update(UPDATE_BOUND_ARGS=args, UPDATE_SOURCE_ENVIRONMENT=update_copy.deepcopy(backend['LAUNCH']['environment']))
    exec(compile(update_ast.fix_missing_locations(update_ast.Module(body=[node], type_ignores=[])), str(lifecycle.__file__), 'exec', dont_inherit=True), scope)
    return scope['complete_update_main']

def update_terminal(guard, original_intent, checkpoint, receipt, handoff):
    return guard.modules['lifecycle'].target_admission._terminal(original_intent, checkpoint, receipt, handoff, intent_path=guard.args.intent_file)

class CompleteUpdate:
    """Single actual action worker plus separately governed UI observations.

    UI methods observe only. The sole native operator handles visible Android
    permission/Update controls; no guessed coordinates or API29 warning taps.
    Missing callbacks leave the original operation UNKNOWN, never resubmit it.
    """

    def __init__(self, args, backend):
        self.backend = backend
        self.args = args
        self.selected = COMPONENT_BUNDLE.modules(COMPONENT_RECEIPT)
        self.lifecycle = self.selected['lifecycle']
        self.tls = self.selected['tls']
        self.intent = self.lifecycle.target_admission.load_intent(args.intent_file)
        pair = self.intent['pair']
        if self.intent['host'] != 'archlinux' or self.intent['device'] != 'android-api35' or self.intent['expectedApi'] != 35 or (args.api != '35') or (args.serial != 'emulator-5682') or (self.intent['expectedTerminal'] != 'installed') or (args.expected_terminal != 'installed') or (pair['sourceSha'] != UPDATE_PRODUCT) or (pair['baseSha256'] != UPDATE_BASE) or (pair['targetSha256'] != UPDATE_TARGET) or (pair['signerSha256'] != UPDATE_SIGNER) or ((pair['baseVersion'], pair['baseCode'], pair['targetVersion'], pair['targetCode']) != ('2.2.2', 16840, '2.2.3', 16860)):
            raise ValueError('update_fixed_pair_or_device_changed')
        if args.output != args.intent_file.parent or args.continue_file != args.output / 'continue' or args.handoff_ready_file != args.output / 'handoff-ready' or (args.governed_callbacks is not True) or (args.device_port != 45635):
            raise ValueError('update_callback_or_endpoint_changed')
        self.output = args.output
        self.thread = None
        self.failure = None
        self.result = None
        self.unknown = False
        self.started = False
        self.intent_raw, self.intent_pin = COMPONENT_BUNDLE._read(args.intent_file, True)
        self.tls.require_artifact_hash(args.base_apk, UPDATE_BASE)
        self.tls.require_artifact_hash(args.target_apk, UPDATE_TARGET)
        self.guard = COMPONENT_BUNDLE.CurrentGuard(COMPONENT_RECEIPT, self.selected, backend, args)
        self.guard.bind_fixture_assets(outer_small_read(self.output/'asset-stage.json')[1])
        self.restore = None

    def source_guard(self):
        COMPONENT_BUNDLE.load(COMPONENT_RECEIPT)
        self.backend['command_host_guard']()
        self.backend['external_jdk_guard']()
        if COMPONENT_BUNDLE._read(self.args.intent_file, True) != (self.intent_raw, self.intent_pin):
            raise ValueError('update_original_intent_changed')
        if not update_equal(self.backend['getter_stage'](), self.guard.stage):
            raise ValueError('update_cli_stage_changed')
        self.guard._fixture_assets_guard()

    def start(self):
        if self.started or self.unknown:
            raise ValueError('update_once_consumed')
        self.source_guard()
        self.guard()
        COMPONENT_BUNDLE._write(self.output / 'complete-update-dispatch-intent.json', COMPONENT_BUNDLE._raw({'schema': 1, 'correlationId': self.intent['correlationId'], 'scope': 'api35-exact-update-installed', 'replayAllowed': False}))
        self.source_guard()
        self.guard()
        self.started = True
        self.restore = self.selected['adapter'].install(self.lifecycle, self.tls, self.backend, self.args, self.guard)
        main = update_main_factory(self.selected, self.args, self.backend)

        def worker():
            try:
                main()
                self.result = {'state': 'lifecycle-returned', 'terminalUnverified': True}
            except BaseException as error:
                self.unknown = True
                self.failure = {'type': type(error).__name__, 'code': str(error) if type(error) is ValueError and str(error) in ('component_guard_generation_changed', 'component_guard_owner_changed', 'installer_adapter_unknown', 'update_once_consumed') else None}
            finally:
                if self.restore is not None:
                    self.restore()
        self.thread = update_threading.Thread(target=worker, name='owned-api35-installer-' + self.intent['correlationId'], daemon=False)
        self.thread.start()
        return {'state': 'running', 'correlationId': self.intent['correlationId'], 'replayAllowed': False}

    def _read_json(self, name, limit=1048576):
        raw, _ = COMPONENT_BUNDLE._read(self.output / name, True)
        if len(raw) > limit:
            raise ValueError('update_saved_record_limit')
        return update_json.loads(raw)

    def _ui(self, phase):
        if phase not in ('handoff-ready', 'continue'):
            raise ValueError('update_ui_phase_unknown')
        self.source_guard()
        focus = self.guard._text(['shell', '-T', 'dumpsys', 'window'])
        lines = [line for line in focus.splitlines() if 'mCurrentFocus=' in line]
        if len(lines) != 1:
            raise ValueError('update_focus_ambiguous')
        match = update_re.search('mCurrentFocus=Window\\{[0-9a-fA-F]+\\s+u\\d+\\s+([A-Za-z0-9_.]+)/([A-Za-z0-9_.$]+)\\}', lines[0])
        if match is None:
            raise ValueError('update_focus_ambiguous')
        installer = ('com.google.android.packageinstaller', 'com.android.packageinstaller')
        focused = match[1] if match[1] in installer else None
        path = '/sdcard/android-installer-' + self.intent['correlationId'] + '-' + phase + '.xml'
        self.guard._text(['shell', '-T', 'uiautomator', 'dump', path])
        try:
            xml = self.guard._text(['shell', '-T', 'cat', path]).encode()
        finally:
            self.guard._text(['shell', '-T', 'rm', path])
        tree = update_et.fromstring(xml)
        if tree.tag != 'hierarchy':
            raise ValueError('update_ui_xml_unknown')
        nodes = list(tree.iter('node'))
        titles = [n for n in nodes if n.get('package') == focused and n.get('text') == 'VPN Control']
        buttons = {n.get('text') for n in nodes if n.get('package') == focused and n.get('enabled') == 'true'}
        if phase == 'handoff-ready':
            if focused is None or len(titles) != 1 or (not {'Update', 'Cancel'} <= buttons):
                raise ValueError('update_dialog_not_owned')
        elif focused is not None or any((n.get('package') in installer and n.get('text') in ('Update', 'Cancel') for n in nodes)):
            raise ValueError('update_dialog_still_visible')
        if self.guard._text(['shell', '-T', 'dumpsys', 'window']) != focus:
            raise ValueError('update_focus_changed')
        self.source_guard()
        return (xml, focused)

    def callback(self, phase):
        if not self.started or self.thread is None or (not self.thread.is_alive()) or self.unknown:
            raise ValueError('update_worker_not_waiting')
        if phase not in ('handoff-ready', 'continue'):
            raise ValueError('update_ui_phase_unknown')
        checkpoint = self._read_json('probe.json')['callbackReceipt']['installerLifecycle']
        accepted = checkpoint['interactiveAccepted']['response']
        operation = checkpoint['operationId']
        binding = self.guard._command_binding()
        if accepted.get('ok') is not True or accepted.get('code') != 'ACCEPTED' or accepted.get('final') is not False or (accepted.get('operationId') != operation) or (accepted.get('controllerId') != binding['expectedOwner']):
            raise ValueError('update_original_operation_changed')
        if phase == 'handoff-ready':
            record = self.lifecycle.invoke(self.args.cli, self.args.serial, 'operations', 'status', operation, environment=self.args.cli_environment)
            identity = self.lifecycle.handoff_identity(record, operation, '2.2.3', UPDATE_TARGET, binding['expectedOwner'])
            owner, revision = (binding['expectedOwner'], binding['expectedRevision'])
        else:
            identity = self._read_json('handoff.json')['identity']
            previous = self._read_json('callback-handoff-ready-evidence.json', 4096)
            if identity['operationId'] != operation or any((previous[k] != identity[k] for k in ('operationId', 'receiptId', 'sessionId'))):
                raise ValueError('update_callback_lineage_changed')
            facts = self.guard._candidate_physical(UPDATE_TARGET)
            owner, revision = self.guard._fresh_owner(facts, UPDATE_TARGET)
            terminal = self.guard._fresh_reply(['updates', 'status'], owner, facts, UPDATE_TARGET)
            if not self.lifecycle.reconciled_terminal({'exit': 0, 'response': terminal}, identity, 'installed'):
                raise ValueError('update_callback_terminal_unknown')
        xml, focused = self._ui(phase)
        value = {'correlationId': self.intent['correlationId'], 'phase': phase, 'sourceSha': UPDATE_PRODUCT, 'targetArtifactId': 'sha256-' + UPDATE_TARGET, 'uiSha256': update_hashlib.sha256(xml).hexdigest(), **{k: identity[k] for k in ('operationId', 'receiptId', 'sessionId')}, 'owner': owner, 'revision': revision, 'focusedInstaller': focused}
        self.lifecycle.write_cli_evidence(update_types.SimpleNamespace(output=self.output, intent=binding), 'callback-' + phase + '-evidence.json', value)
        COMPONENT_BUNDLE._write(self.output / ('callback-' + phase + '-ui.xml'), xml)
        self.source_guard()
        COMPONENT_BUNDLE._write(self.output / phase, b'continue\n')
        return {'state': 'callback-recorded', 'phase': phase, 'operationId': operation, 'receiptId': identity['receiptId'], 'sessionId': identity['sessionId'], 'replayAllowed': False}

    def finish(self, timeout=900):
        if self.thread is None or type(timeout) is not int or (not 1 <= timeout <= 1800):
            raise ValueError('update_wait_scope_changed')
        self.thread.join(timeout)
        if self.thread.is_alive():
            self.unknown = True
            raise ValueError('update_original_worker_still_running')
        if self.failure is not None:
            raise ValueError('update_original_worker_unknown')
        self.source_guard()
        receipt = self._read_json('lifecycle-receipt.json')
        checkpoint = self._read_json('probe.json')
        handoff = self._read_json('handoff.json')
        cleanup_guard = COMPONENT_BUNDLE.cleanup_readmission(self.guard)
        terminal = update_terminal(self.guard, self.intent, checkpoint, receipt, handoff)
        if receipt.get('cleanupFailures') or receipt.get('retainedStaging') or receipt.get('unknownMount'):
            raise ValueError('update_tls_cleanup_unknown')
        importer = self.selected['adapter'].__dict__['__builtins__']['__import__']
        backup = importer('agent_tools.android_installer_routing_backup', {}, None, ('_read',), 0)
        reader = backup._sources(COMPONENT_RECEIPT)
        routing_directory = self.output / 'routing-after-cleanup'
        COMPONENT_BUNDLE._new_directory(routing_directory)
        results = []
        for name in ('first', 'second'):
            directory = routing_directory / name
            COMPONENT_BUNDLE._new_directory(directory)
            results.append(backup._read(reader, self.backend, cleanup_guard, directory, 'routingAfter'))
        routing, semantic, manifest = results[0]
        if type(semantic) is not bytes or type(results[1][1]) is not bytes or semantic != results[1][1]:
            raise ValueError('update_routing_unstable')
        before = update_json.loads(self.lifecycle.target_admission._private_file(__import__('pathlib').Path(self.intent['backupPath']), 67108864))
        if {k: v for k, v in routing.items() if k != 'exported_at'} != {k: v for k, v in before.items() if k != 'exported_at'}:
            raise ValueError('update_routing_changed')
        self.source_guard()
        cleanup_guard()
        result = {**terminal, 'routingEqual': True, 'routingManifests': [row[2] for row in results], 'componentRuntime': 'EXTERNAL_JDK', 'installedLauncherAccepted': False, 'bundledRuntimeAccepted': False, 'fixtureCleanupObserved': True, 'componentUpdateScenarioComplete': True}
        COMPONENT_BUNDLE._write(self.output / 'complete-update-terminal.json', COMPONENT_BUNDLE._raw(result))
        return result

"""Fixed persistent update dispatcher; source-only until an admitted carrier calls it.

All names are prefixed to preserve the upstream compiler/import context. The
caller supplies future held custody facts, never historical device authority.
"""
import hashlib as outer_hashlib,json as outer_json,os as outer_os,stat as outer_stat,time as outer_time,uuid as outer_uuid
from pathlib import Path as OuterPath

OUTER_FILES=('base.apk','target.apk','ca.pem','leaf.pem','key.pem')
OUTER_CALLBACKS=('handoff-ready','continue')
OUTER_LIMIT=67108864

def outer_json_pairs(pairs):
    """Closed journal/frame objects reject duplicates at every nesting depth."""
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('outer_json_duplicate')
        result[key]=value
    return result


def outer_decode(raw):
    return outer_json.loads(raw,object_pairs_hook=outer_json_pairs)


def outer_equal(a,b):
    return outer_json.dumps(a,sort_keys=True,separators=(',',':'),allow_nan=False)==outer_json.dumps(b,sort_keys=True,separators=(',',':'),allow_nan=False)

def outer_uuid_value(value):
    if type(value)is not str or str(outer_uuid.UUID(value))!=value:raise ValueError('outer_correlation_invalid')
    return value

def outer_pin_shape(pin):
    if (type(pin)is not dict or set(pin)!={'path','generation','parents','sha256'} or type(pin['path'])is not str or
        type(pin['generation'])is not list or len(pin['generation'])!=9 or any(type(x)is not int for x in pin['generation']) or
        type(pin['parents'])is not dict or not pin['parents'] or any(type(k)is not str or type(v)is not list or len(v)!=5 or any(type(x)is not int for x in v)for k,v in pin['parents'].items()) or
        type(pin['sha256'])is not str or len(pin['sha256'])!=64 or any(x not in '0123456789abcdef'for x in pin['sha256'])):
        raise ValueError('outer_pin_invalid')

def outer_future_input_shape(authority,root,correlation):
    """Validate a future custody binding without observing/adopting that host."""
    root=OuterPath(root);outer_uuid_value(correlation)
    if not root.is_absolute() or '..'in root.parts:raise ValueError('outer_asset_paths_changed')
    if type(authority)is not dict or set(authority)!={'schema','correlationId','productSourceSha','inputDirectory','files','tlsReceipt','lease'}:raise ValueError('outer_asset_authority_invalid')
    if type(authority['schema'])is not int or authority['schema']!=1 or authority['correlationId']!=correlation or authority['productSourceSha']!=UPDATE_PRODUCT:raise ValueError('outer_asset_authority_changed')
    directory=root/('android-complete-update-inputs-'+correlation)
    if authority['inputDirectory']!=str(directory) or type(authority['files'])is not dict or set(authority['files'])!=set(OUTER_FILES):raise ValueError('outer_asset_paths_changed')
    for name,pin in authority['files'].items():
        outer_pin_shape(pin)
        if pin['path']!=str(directory/name):raise ValueError('outer_asset_paths_changed')
        if name.endswith('.apk')and (pin['generation'][6]!=45026948 or pin['sha256']!=(UPDATE_BASE if name=='base.apk'else UPDATE_TARGET)):raise ValueError('outer_apk_identity_changed')
    for key,path in [('tlsReceipt',directory/'receipt.json'),('lease',root/'android-native-device-android-api35.lease')]:
        outer_pin_shape(authority[key])
        if authority[key]['path']!=str(path):raise ValueError('outer_asset_paths_changed')
    # Never retain a caller-shared mutable pin list.
    return outer_decode(outer_json.dumps(authority,sort_keys=True,separators=(',',':'),allow_nan=False))

def outer_posix_required():
    if (outer_os.name!='posix' or not all(callable(getattr(outer_os,name,None)) for name in ('getuid','geteuid','getgid','getegid','getgroups','getsid')) or
        not all(hasattr(outer_os,name)for name in ('O_NOFOLLOW','O_NONBLOCK','O_DIRECTORY'))):
        raise ValueError('outer_posix_custody_required')
    try:import fcntl
    except ImportError:raise ValueError('outer_posix_custody_required') from None

def outer_file(path,limit,include_body=False):
    outer_posix_required()
    path=OuterPath(path);chain,parents=COMPONENT_BUNDLE._parents(path.parent);fd=None
    try:
        fd=outer_os.open(path.name,outer_os.O_RDONLY|outer_os.O_NOFOLLOW|outer_os.O_NONBLOCK,dir_fd=chain[-1][1])
        info=outer_os.fstat(fd);generation=COMPONENT_BUNDLE._pin(info)
        if (not outer_stat.S_ISREG(info.st_mode) or info.st_uid!=outer_os.getuid() or info.st_gid!=outer_os.getgid() or
            info.st_nlink!=1 or outer_stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=limit):raise ValueError('outer_file_unsafe')
        digest=outer_hashlib.sha256();size=0;chunks=[]
        while part:=outer_os.read(fd,524288):
            size+=len(part)
            if size>limit:raise ValueError('outer_file_limit')
            digest.update(part)
            if include_body:chunks.append(part)
        pin={'path':str(path),'generation':generation,'parents':parents,'sha256':digest.hexdigest()}
        COMPONENT_BUNDLE._evidence_generation_closure({str(path):pin})
        for name,parent_fd in chain:
            if COMPONENT_BUNDLE._pin(outer_os.fstat(parent_fd))[:5]!=parents[name] or COMPONENT_BUNDLE._pin(outer_os.stat(name,follow_symlinks=False))[:5]!=parents[name]:raise ValueError('outer_parent_changed')
        if size!=generation[6]:raise ValueError('outer_file_changed')
        return (b''.join(chunks),pin) if include_body else pin
    finally:
        if fd is not None:outer_os.close(fd)
        COMPONENT_BUNDLE._close(chain)

def outer_small_read(path):
    raw,pin=outer_file(path,65536,True)
    return raw,{key:pin[key]for key in ('generation','parents','sha256')}

def outer_asset_admission(authority):
    authority=outer_future_input_shape(authority,ROOT,UPDATE_CORRELATION)
    if type(authority)is not dict or set(authority)!={'schema','correlationId','productSourceSha','inputDirectory','files','tlsReceipt','lease'}:raise ValueError('outer_asset_authority_invalid')
    corr=outer_uuid_value(authority['correlationId'])
    if type(authority['schema'])is not int or authority['schema']!=1 or authority['productSourceSha']!=UPDATE_PRODUCT or corr!=UPDATE_CORRELATION:raise ValueError('outer_asset_authority_changed')
    input_dir=ROOT/('android-complete-update-inputs-'+corr)
    if authority['inputDirectory']!=str(input_dir) or type(authority['files'])is not dict or set(authority['files'])!=set(OUTER_FILES):raise ValueError('outer_asset_paths_changed')
    COMPONENT_BUNDLE._directory(input_dir)
    pins={}
    for name in OUTER_FILES:
        expected=authority['files'][name];outer_pin_shape(expected)
        if expected['path']!=str(input_dir/name):raise ValueError('outer_asset_paths_changed')
        actual=outer_file(input_dir/name,45026948 if name.endswith('.apk')else 65536)
        if not outer_equal(actual,expected):raise ValueError('outer_asset_source_changed')
        if name.endswith('.apk') and (actual['generation'][6]!=45026948 or actual['sha256']!=(UPDATE_BASE if name=='base.apk'else UPDATE_TARGET)):raise ValueError('outer_apk_identity_changed')
        pins[actual['path']]=actual
    expected=authority['tlsReceipt'];outer_pin_shape(expected)
    if expected['path']!=str(input_dir/'receipt.json'):raise ValueError('outer_asset_paths_changed')
    raw,pin=outer_small_read(input_dir/'receipt.json')
    pin={'path':str(input_dir/'receipt.json'),**pin}
    if not outer_equal(pin,expected):raise ValueError('outer_tls_receipt_changed')
    receipt=outer_decode(raw)
    if (receipt.get('schema')!=1 or type(receipt.get('schema'))is not int or receipt.get('kind')!='android-disposable-fixture-tls' or
        receipt.get('campaignId')!=corr or receipt.get('testOnly')is not True or receipt.get('sourceFacts',{}).get('sourceSha')!=UPDATE_PRODUCT or
        receipt.get('sourceFacts',{}).get('targetArtifactId')!='sha256-'+UPDATE_TARGET):raise ValueError('outer_tls_receipt_changed')
    for name,origin in [('ca.pem','ca.pem'),('leaf.pem','leaf.pem'),('key.pem','leaf-key.pem')]:
        detail=receipt.get('files',{}).get(origin,{})
        if type(detail.get('bytes'))is not int or detail['bytes']!=pins[str(input_dir/name)]['generation'][6] or detail.get('sha256')!=pins[str(input_dir/name)]['sha256']:raise ValueError('outer_tls_material_changed')
    pins[pin['path']]=pin
    lease=authority['lease'];outer_pin_shape(lease)
    lease_path=ROOT/'android-native-device-android-api35.lease'
    if lease['path']!=str(lease_path):raise ValueError('outer_lease_path_changed')
    raw,pin=outer_small_read(lease_path)
    pin={'path':str(lease_path),**pin}
    expected={'owner':'android-installer','host':'archlinux','device':'android-api35','correlationId':corr}
    if not outer_equal(pin,lease) or not outer_equal(outer_decode(raw),expected):raise ValueError('outer_lease_changed')
    pins[pin['path']]=pin
    COMPONENT_BUNDLE._evidence_generation_closure(pins)
    return pins

def outer_stage_assets(authority):
    outer_posix_required()
    # The verified transport supplies a fresh input custody leaf. This function
    # neither downloads nor issues/adopts a lease or certificate.
    pins=outer_asset_admission(authority)
    output=ROOT/('android-installer-component-baseline-'+UPDATE_CORRELATION)
    COMPONENT_BUNDLE._new_directory(output,receiver_root=ROOT)
    assets=output/'assets';COMPONENT_BUNDLE._new_directory(assets)
    import resource as outer_resource
    old=outer_resource.getrlimit(outer_resource.RLIMIT_FSIZE);changed=False;origins={}
    try:
        # Only this owned collector's finite assembly allowance changes. Restore
        # both original values before public commands or any child is released.
        ceiling=OUTER_LIMIT
        if old[1]!=outer_resource.RLIM_INFINITY and old[1]<ceiling:raise ValueError('outer_asset_file_limit_unavailable')
        outer_resource.setrlimit(outer_resource.RLIMIT_FSIZE,(ceiling,old[1]));changed=True
        if outer_resource.getrlimit(outer_resource.RLIMIT_FSIZE)!=(ceiling,old[1]):raise ValueError('outer_asset_file_limit_changed')
        for name in OUTER_FILES:
            source=authority['files'][name];chain,_=COMPONENT_BUNDLE._parents(OuterPath(source['path']).parent);src=None;dest=None
            try:
                src=outer_os.open(name,outer_os.O_RDONLY|outer_os.O_NOFOLLOW|outer_os.O_NONBLOCK,dir_fd=chain[-1][1])
                if not outer_equal(COMPONENT_BUNDLE._pin(outer_os.fstat(src)),source['generation']):raise ValueError('outer_asset_source_changed')
                dest=outer_os.open(assets/name,outer_os.O_WRONLY|outer_os.O_CREAT|outer_os.O_EXCL|outer_os.O_NOFOLLOW,0o600)
                digest=outer_hashlib.sha256();size=0
                while part:=outer_os.read(src,524288):
                    size+=len(part)
                    if size>source['generation'][6]:raise ValueError('outer_asset_source_changed')
                    digest.update(part);at=0
                    while at<len(part):
                        count=outer_os.write(dest,part[at:])
                        if count<=0:raise ValueError('outer_asset_partial_write')
                        at+=count
                outer_os.fsync(dest)
                if size!=source['generation'][6] or digest.hexdigest()!=source['sha256']:raise ValueError('outer_asset_source_changed')
                copy_generation=COMPONENT_BUNDLE._pin(outer_os.fstat(dest))
                if not outer_equal(COMPONENT_BUNDLE._pin(outer_os.stat(assets/name,follow_symlinks=False)),copy_generation):raise ValueError('outer_asset_copy_changed')
            finally:
                if src is not None:outer_os.close(src)
                if dest is not None:outer_os.close(dest)
                COMPONENT_BUNDLE._close(chain)
            # Capture destination birth after the write, and compare its bytes
            # to the immutable origin before adopting any stage pin.
            actual=outer_file(assets/name,45026948 if name.endswith('.apk')else 65536)
            if actual['sha256']!=source['sha256'] or not outer_equal(actual['generation'],copy_generation):raise ValueError('outer_asset_copy_changed')
            origins[actual['path']]=actual
        outer_asset_admission(authority)
        COMPONENT_BUNDLE._evidence_generation_closure({**pins,**origins})
        COMPONENT_BUNDLE._write(output/'asset-stage.json',COMPONENT_BUNDLE._raw({'schema':1,'correlationId':UPDATE_CORRELATION,'origins':pins,'staged':origins,'caPrivateKeyTransferred':False}))
        COMPONENT_BUNDLE._evidence_generation_closure({**pins,**origins})
        journal=outer_file(output/'asset-stage.json',65536)
        COMPONENT_BUNDLE._evidence_generation_closure({**pins,**origins,str(output/'asset-stage.json'):journal})
        return {'output':output,'assets':assets,'originPins':pins,'stagedPins':origins,'journalPin':journal}
    finally:
        if changed:
            outer_resource.setrlimit(outer_resource.RLIMIT_FSIZE,old)
            if outer_resource.getrlimit(outer_resource.RLIMIT_FSIZE)!=old:raise ValueError('outer_asset_file_limit_restore_unknown')

class CompleteUpdateOuter:
    """One persistent process keeps the genuine actor/adapter and callback state.

    Mailbox commands are fixed observation callbacks. They never click UI, issue
    an installer action, reload a lost worker or adopt another correlation.
    """
    def __init__(self,actor):
        if type(actor)is not CompleteUpdate:raise ValueError('outer_genuine_actor_required')
        self.actor=actor;self.directory=actor.output/'outer';COMPONENT_BUNDLE._new_directory(self.directory)
        self.correlation=outer_uuid_value(actor.intent['correlationId']);self.pins={};self.sequence=0;self.unknown=False;self.consumed=False
        self.packet={'schema':1,'correlationId':self.correlation,'sourcePacketSha256':UPDATE_SOURCE_PACKET_SHA,'scope':'api35-complete-update','replayAllowed':False}
        self._publish('intent',self.packet)

    def _publish(self,kind,value):
        name=f'{self.sequence:05d}-{kind}.json';self.sequence+=1
        path=self.directory/name;COMPONENT_BUNDLE._write(path,COMPONENT_BUNDLE._raw(value))
        raw,pin=outer_small_read(path);self.pins[str(path)]=pin
        if not outer_equal(outer_decode(raw),value):raise ValueError('outer_journal_changed')
        return path

    def _guard(self):
        self.actor.source_guard()
        if hasattr(self,'identity') and not outer_equal(outer_process_identity(),self.identity):raise ValueError('outer_worker_identity_changed')
        for path,pin in self.pins.items():
            if not outer_equal(outer_small_read(OuterPath(path))[1],pin):raise ValueError('outer_journal_changed')
        # After every body read, close all retained named/held evidence once.
        COMPONENT_BUNDLE._evidence_generation_closure(self.pins)

    def submit_callback(self,phase):
        if phase not in OUTER_CALLBACKS:raise ValueError('outer_callback_invalid')
        if self.unknown:raise ValueError('outer_unknown_consumed')
        self._guard()
        value={**self.packet,'phase':phase};path=self.directory/('request-'+phase+'.json')
        COMPONENT_BUNDLE._write(path,COMPONENT_BUNDLE._raw(value))
        return {'request':str(path),'correlationId':self.correlation,'replayAllowed':False}

    def _callback(self,phase):
        path=self.directory/('request-'+phase+'.json')
        if not path.exists():return False
        result_path=self.directory/('result-'+phase+'.json')
        if result_path.exists():return False
        raw,pin=outer_small_read(path)
        if not outer_equal(outer_decode(raw),{**self.packet,'phase':phase}):raise ValueError('outer_callback_binding_changed')
        if phase=='continue' and not (self.directory/'result-handoff-ready.json').exists():raise ValueError('outer_callback_order_changed')
        self.pins[str(path)]=pin;self._guard()
        result=self.actor.callback(phase)
        COMPONENT_BUNDLE._write(result_path,COMPONENT_BUNDLE._raw(result))
        self.pins[str(result_path)]=outer_small_read(result_path)[1]
        self._guard();return True

    def run(self):
        if self.consumed:raise ValueError('outer_once_consumed')
        self.consumed=True
        try:
            self.identity=outer_process_identity()
            self._publish('dispatch',{**self.packet,'identity':self.identity,'state':'dispatch-intent'})
            self._guard()
            self.accepted={'correlationId':self.correlation,'sourcePacketSha256':UPDATE_SOURCE_PACKET_SHA,'identity':self.identity,
                'intentPin':self.pins[str(self.directory/'00000-intent.json')],'dispatchPin':self.pins[str(self.directory/'00001-dispatch.json')]}
            print('COMPLETE_UPDATE_ACCEPTED '+outer_json.dumps(self.accepted,sort_keys=True,separators=(',',':')),flush=True)
            self._guard();started=self.actor.start();self._publish('running',started)
            deadline=outer_time.monotonic()+1800
            while self.actor.thread.is_alive():
                self._guard()
                if outer_time.monotonic()>=deadline:raise ValueError('outer_worker_deadline_unknown')
                for phase in OUTER_CALLBACKS:self._callback(phase)
                outer_time.sleep(.1)
            result=self.actor.finish(timeout=1);self._guard()
            self._publish('terminal',{'schema':1,'correlationId':self.correlation,'state':'complete','result':result,'replayAllowed':False})
            self._guard()
            print('COMPLETE_UPDATE_TERMINAL '+outer_json.dumps({'schema':1,'correlationId':self.correlation,'result':result,'replayAllowed':False},sort_keys=True,separators=(',',':')),flush=True)
            print('COMPLETE_UPDATE_EOF '+self.correlation+' '+UPDATE_SOURCE_PACKET_SHA,flush=True)
            return result
        except BaseException:
            self.unknown=True
            # Every command/raw record already belongs to the original actor.
            # Journal failures stay sticky even if publication itself is broken.
            try:self._publish('unknown',{**self.packet,'state':'unknown','workerAlive':self.actor.thread is not None and self.actor.thread.is_alive(),'replayAllowed':False})
            except BaseException:pass
            raise

def outer_process_identity(pid=None):
    outer_posix_required()
    # Exactly this dispatcher or its saved own PID. This is observation only;
    # no signal, process adoption or foreign child lifecycle is available.
    pid=outer_os.getpid() if pid is None else pid
    if type(pid)is not int or pid<=0:raise ValueError('outer_worker_identity_invalid')
    def read(path,limit):
        fd=outer_os.open(path,outer_os.O_RDONLY|outer_os.O_NOFOLLOW|outer_os.O_NONBLOCK)
        try:
            raw=b''
            while part:=outer_os.read(fd,limit+1-len(raw)):
                raw+=part
                if len(raw)>limit:raise ValueError('outer_worker_identity_limit')
            return raw
        finally:outer_os.close(fd)
    path='/proc/'+str(pid)+'/stat';first=read(path,4096)
    def birth(raw):
        words=raw.decode('ascii').split(') ',1)
        if len(words)!=2 or words[0].split(' (',1)[0]!=str(pid):raise ValueError('outer_worker_identity_invalid')
        fields=words[1].split()
        if len(fields)<20 or not fields[19].isdigit() or int(fields[19])<=0:raise ValueError('outer_worker_identity_invalid')
        return int(fields[19])
    ticks=birth(first)
    status=read('/proc/'+str(pid)+'/status',8192).decode('ascii');facts={}
    for row in status.splitlines():
        key,sep,value=row.partition(':')
        if key in ('Uid','Gid','Groups'):
            if key in facts or not sep or any(not word.isdigit()for word in value.split()):raise ValueError('outer_worker_identity_invalid')
            facts[key]=[int(word)for word in value.split()]
    expected={'Uid':[outer_os.getuid()]*4,'Gid':[outer_os.getgid()]*4,'Groups':sorted(outer_os.getgroups())}
    if not outer_equal(facts,expected) or birth(read(path,4096))!=ticks:raise ValueError('outer_worker_identity_changed')
    boot=read('/proc/sys/kernel/random/boot_id',128).decode('ascii').strip();outer_uuid_value(boot)
    return {'pid':pid,'startTicks':ticks,'bootId':boot,'uid':outer_os.getuid(),'gid':outer_os.getgid(),'groups':sorted(outer_os.getgroups())}

def outer_submit_saved_callback(phase):
    """Fixed operator entry in a separate authenticated callback carrier.

    It cannot recreate a worker. It checks the saved original process birth and
    only creates one fixed observation request for that same source/correlation.
    """
    if phase not in OUTER_CALLBACKS:raise ValueError('outer_callback_invalid')
    accepted=UPDATE_OUTER_ACCEPTED
    if type(accepted)is not dict or set(accepted)!={'correlationId','sourcePacketSha256','identity','intentPin','dispatchPin'} or accepted['correlationId']!=UPDATE_CORRELATION or accepted['sourcePacketSha256']!=UPDATE_SOURCE_PACKET_SHA:raise ValueError('outer_original_handle_required')
    directory=ROOT/('android-installer-component-baseline-'+UPDATE_CORRELATION)/'outer'
    raw,pin=outer_small_read(directory/'00000-intent.json');intent=outer_decode(raw)
    if not outer_equal(pin,accepted['intentPin']):raise ValueError('outer_original_handle_changed')
    expected={'schema':1,'correlationId':UPDATE_CORRELATION,'sourcePacketSha256':UPDATE_SOURCE_PACKET_SHA,'scope':'api35-complete-update','replayAllowed':False}
    if not outer_equal(intent,expected):raise ValueError('outer_callback_binding_changed')
    dispatch_raw,dispatch_pin=outer_small_read(directory/'00001-dispatch.json');dispatch=outer_decode(dispatch_raw)
    if not outer_equal(dispatch_pin,accepted['dispatchPin']):raise ValueError('outer_original_handle_changed')
    if type(dispatch)is not dict or set(dispatch)!=set(expected)|{'identity','state'} or not outer_equal({k:dispatch[k]for k in expected},expected) or dispatch['state']!='dispatch-intent':raise ValueError('outer_callback_binding_changed')
    if not outer_equal(dispatch['identity'],accepted['identity']) or not outer_equal(outer_process_identity(accepted['identity']['pid']),accepted['identity']):raise ValueError('outer_worker_identity_changed')
    # No running/terminal receipt is inferred from PID existence. The live
    # original dispatcher performs the phase/UI/current guard before markers.
    COMPONENT_BUNDLE._evidence_generation_closure({str(directory/'00000-intent.json'):pin,str(directory/'00001-dispatch.json'):dispatch_pin})
    COMPONENT_BUNDLE._write(directory/('request-'+phase+'.json'),COMPONENT_BUNDLE._raw({**expected,'phase':phase}))
    COMPONENT_BUNDLE._evidence_generation_closure({str(directory/'00000-intent.json'):pin,str(directory/'00001-dispatch.json'):dispatch_pin})
    return {'correlationId':UPDATE_CORRELATION,'phase':phase,'state':'request-written','replayAllowed':False,'uiActionPerformed':False}


def complete_update_prepare():
    outer_future_input_shape(UPDATE_ASSET_AUTHORITY,ROOT,UPDATE_CORRELATION)
    # Actual sourceclosed backup contains two full routing reads, raw manifests,
    # finite32MiB assembly/restored limits and original current physical guards.
    backup=COMPONENT_BUNDLE.routing_backup(COMPONENT_RECEIPT,globals(),UPDATE_BASELINE_REQUEST)
    return _complete_update_stage(backup)

def _complete_update_stage(backup):
    # Only source-closed initializer/direct entry calls this private stage.
    outer_future_input_shape(UPDATE_ASSET_AUTHORITY,ROOT,UPDATE_CORRELATION)
    # Finite custody staging creates an allowed root-private baseline leaf.
    # The uuid5 backup has a different leaf; no original source image is altered.
    staged=outer_stage_assets(UPDATE_ASSET_AUTHORITY)
    output=staged['output'];slots=staged['assets']
    pair={**UPDATE_PAIR,'basePath':str(slots/'base.apk'),'targetPath':str(slots/'target.apk')}
    selected=COMPONENT_BUNDLE.modules(COMPONENT_RECEIPT)
    selected['lifecycle'].target_admission.verify_staged_pair(pair,slots/'base.apk',slots/'target.apk')
    intent={'schema':1,'correlationId':UPDATE_CORRELATION,'host':'archlinux','device':'android-api35','pair':pair,
        'expectedAvd':UPDATE_BASELINE_REQUEST['expectedAvd'],'expectedApi':35,
        'expectedOwner':UPDATE_BASELINE_REQUEST['expectedOwner'],'expectedRevision':UPDATE_BASELINE_REQUEST['expectedRevision'],
        'backupCorrelationId':UPDATE_BASELINE_REQUEST['correlationId'],'inspectCorrelationId':UPDATE_BASELINE_REQUEST['correlationId'],
        'backupPath':backup['path'],'backupSha256':backup['sha256'],'backupSize':backup['size'],'expectedTerminal':'installed','replayAllowed':False}
    COMPONENT_BUNDLE._write(output/'intent.json',COMPONENT_BUNDLE._raw(intent))
    # No lease is minted or adopted here. CurrentGuard requires the original
    # exact android-installer host/device/correlation lease before effects.
    args=update_types.SimpleNamespace(api='35',serial='emulator-5682',avd=intent['expectedAvd'],
        adb=LAUNCH['adbPath'],cli=COMPONENT_BUNDLE.Path(GETTER['cli']),device_port=45635,
        output=output,intent_file=output/'intent.json',base_apk=slots/'base.apk',target_apk=slots/'target.apk',
        base_sha256=UPDATE_BASE,base_version='2.2.2',base_code='16840',
        target_sha256=UPDATE_TARGET,target_version='2.2.3',target_code='16860',
        ca_certificate=slots/'ca.pem',leaf_certificate=slots/'leaf.pem',private_key=slots/'key.pem',
        expected_terminal='installed',continue_file=output/'continue',handoff_ready_file=output/'handoff-ready',
        governed_callbacks=True,reconciliation_timeout_seconds=120.0,reconciliation_poll_seconds=1.0,
        cli_environment=selected['tls'].public_cli_environment(LAUNCH['adbPath'],COMPONENT_BUNDLE.Path(GETTER['cli']),LAUNCH['environment']))
    return {'args':args,'backup':backup,'sourcePacketSha256':UPDATE_SOURCE_PACKET_SHA,'toolTreeSha256':COMPONENT_RECEIPT['treeSha256'],
        'productSourceSha':UPDATE_PRODUCT,'helperSourceEqualsProductCommit':False,'nativeSubmitted':False,'installerLeaseGranted':False}

def complete_update_outer_main():
    prepared=complete_update_prepare()
    actor=CompleteUpdate(prepared['args'],globals())
    return CompleteUpdateOuter(actor).run()

def outer_capture_projection(stdout,stderr,returncode,eof):
    """Classify only after the caller durably retains complete raw channels.

    A saved terminal cannot repair missing transport EOF or grant replay. Full
    routing manifests remain in the raw journal; the projection is finite.
    """
    unknown={'ok':False,'state':'unknown','correlationId':UPDATE_CORRELATION,'replayAllowed':False,'installedLauncherAccepted':False,'bundledRuntimeAccepted':False}
    if (type(stdout)is not bytes or type(stderr)is not bytes or type(returncode)is not int or returncode!=0 or stderr or
        len(stdout)+len(stderr)>1048576 or type(eof)is not dict or set(eof)!={'stdout','stderr'} or eof['stdout']is not True or eof['stderr']is not True):return unknown
    try:
        lines=stdout.decode('utf-8','strict').splitlines()
        accepted=[(i,line)for i,line in enumerate(lines)if line.startswith('COMPLETE_UPDATE_ACCEPTED ')]
        terminal=[(i,line)for i,line in enumerate(lines)if line.startswith('COMPLETE_UPDATE_TERMINAL ')]
        ending=[(i,line)for i,line in enumerate(lines)if line.startswith('COMPLETE_UPDATE_EOF ')]
        if len(accepted)!=1 or len(terminal)!=1 or len(ending)!=1 or not accepted[0][0]<terminal[0][0]<ending[0][0] or ending[0][0]!=len(lines)-1 or ending[0][1]!='COMPLETE_UPDATE_EOF '+UPDATE_CORRELATION+' '+UPDATE_SOURCE_PACKET_SHA:return unknown
        start=outer_decode(accepted[0][1][len('COMPLETE_UPDATE_ACCEPTED '):]);end=outer_decode(terminal[0][1][len('COMPLETE_UPDATE_TERMINAL '):])
        if (type(start)is not dict or set(start)!={'correlationId','sourcePacketSha256','identity','intentPin','dispatchPin'} or
            start['correlationId']!=UPDATE_CORRELATION or start['sourcePacketSha256']!=UPDATE_SOURCE_PACKET_SHA or
            type(end)is not dict or set(end)!={'schema','correlationId','result','replayAllowed'} or type(end['schema'])is not int or end['schema']!=1 or end['correlationId']!=UPDATE_CORRELATION or end['replayAllowed']is not False):return unknown
        identity=start['identity']
        if (type(identity)is not dict or set(identity)!={'pid','startTicks','bootId','uid','gid','groups'} or any(type(identity[k])is not int or identity[k]<0 for k in ('pid','startTicks','uid','gid')) or identity['pid']==0 or identity['startTicks']==0 or
            type(identity['groups'])is not list or len(identity['groups'])>64 or any(type(x)is not int or x<0 for x in identity['groups']) or identity['groups']!=sorted(set(identity['groups']))):return unknown
        outer_uuid_value(identity['bootId'])
        for key in ('intentPin','dispatchPin'):
            pin=start[key]
            if type(pin)is not dict or set(pin)!={'generation','parents','sha256'}:return unknown
            outer_pin_shape({'path':'/saved/'+key,**pin})
        result=end['result'];keys={'ok','state','correlationId','terminal','operationId','receiptId','sessionId','terminalOwner','terminalRevision','replayAllowed','routingEqual','routingManifests','componentRuntime','installedLauncherAccepted','bundledRuntimeAccepted','fixtureCleanupObserved','componentUpdateScenarioComplete'}
        if (type(result)is not dict or set(result)!=keys or result['ok']is not True or result['state']!='complete' or result['correlationId']!=UPDATE_CORRELATION or result['terminal']!='installed' or result['replayAllowed']is not False or
            any(result[k]is not True for k in ('routingEqual','fixtureCleanupObserved','componentUpdateScenarioComplete')) or
            any(result[k]is not False for k in ('installedLauncherAccepted','bundledRuntimeAccepted')) or result['componentRuntime']!='EXTERNAL_JDK' or
            type(result['sessionId'])is not int or result['sessionId']<0 or type(result['terminalRevision'])is not int or result['terminalRevision']<0 or
            type(result['receiptId'])is not str or not 0<len(result['receiptId'])<=256 or type(result['routingManifests'])is not list or len(result['routingManifests'])!=2 or any(type(x)is not dict for x in result['routingManifests'])):return unknown
        outer_uuid_value(result['operationId']);outer_uuid_value(result['terminalOwner'])
        return {key:result[key]for key in ('ok','state','correlationId','terminal','operationId','receiptId','sessionId','terminalOwner','terminalRevision','replayAllowed','routingEqual','componentRuntime','installedLauncherAccepted','bundledRuntimeAccepted','fixtureCleanupObserved','componentUpdateScenarioComplete')}
    except (ValueError,TypeError,KeyError,UnicodeError):return unknown

def outer_saved_status():
    """Read the original journal only. This never restarts a lost dispatcher."""
    accepted=UPDATE_OUTER_ACCEPTED
    if type(accepted)is not dict or set(accepted)!={'correlationId','sourcePacketSha256','identity','intentPin','dispatchPin'} or accepted['correlationId']!=UPDATE_CORRELATION or accepted['sourcePacketSha256']!=UPDATE_SOURCE_PACKET_SHA:raise ValueError('outer_original_handle_required')
    directory=ROOT/('android-installer-component-baseline-'+UPDATE_CORRELATION)/'outer';pins={}
    for name,key in [('00000-intent.json','intentPin'),('00001-dispatch.json','dispatchPin')]:
        raw,pin=outer_small_read(directory/name)
        if not outer_equal(pin,accepted[key]):raise ValueError('outer_original_handle_changed')
        pins[str(directory/name)]=pin
    terminal=directory/'00003-terminal.json'
    if terminal.exists():
        raw,pin=outer_small_read(terminal);pins[str(terminal)]=pin;record=outer_decode(raw)
        if type(record)is not dict or set(record)!={'schema','correlationId','state','result','replayAllowed'} or type(record['schema'])is not int or record['schema']!=1 or record['correlationId']!=UPDATE_CORRELATION or record['state']!='complete' or record['replayAllowed']is not False:raise ValueError('outer_terminal_journal_changed')
        COMPONENT_BUNDLE._evidence_generation_closure(pins)
        return {'state':'terminal-recorded','correlationId':UPDATE_CORRELATION,'terminalSha256':pin['sha256'],'freshNativeAcceptance':False,'transportEOFProven':False,'replayAllowed':False}
    identity=outer_process_identity(accepted['identity']['pid'])
    if not outer_equal(identity,accepted['identity']):raise ValueError('outer_worker_identity_changed')
    COMPONENT_BUNDLE._evidence_generation_closure(pins)
    return {'state':'running-observed','correlationId':UPDATE_CORRELATION,'identity':identity,'freshNativeAcceptance':False,'transportEOFProven':False,'replayAllowed':False}


def outer_namespace_source(raw):
    if type(raw)is not bytes or not 0<len(raw)<=1048576:raise ValueError('outer_source_shape')
    tree=update_ast.parse(raw)
    if update_ast.unparse(tree.body[-1])!="if __name__ == '__main__':\n    raise SystemExit('SOURCE ONLY: no native entry or authority')":raise ValueError('outer_source_fence_changed')
    tree.body.pop()
    return update_ast.unparse(tree)+'\n'

if __name__=='__main__':raise SystemExit('SOURCE ONLY: no native entry or authority')
