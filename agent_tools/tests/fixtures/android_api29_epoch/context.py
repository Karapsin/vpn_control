"""Hermetic epoch composition, with explicitly synthetic upstream protocol facts.

No native histories, inventories, credentials or reservations are read. Actual
old/epoch/c466 factories and source guards run unchanged. Only the upstream
permission-observer provider, its host/device DTOs and fixture-root relocation
are seams; synthetic hashes are never called the historical 0806/325/936 proofs.
"""
import ast
import copy
import functools
import hashlib
import json
import types
from pathlib import Path
from agent_tools import android_api29_current_epoch_diagnostics as production
from agent_tools import android_avd_coldboot as coldboot
from agent_tools.tests.fixtures import historical_source

SOURCE_SHA = 'c466a58180280fc0606481b423f19e51f9900b82ea09718df4f3b8b504ad7782'
PROVENANCE_SHA = '1a2ffe6efc1b45a194871a242d9fc8f8ba26b5611517f02355ec33f901fe657e'
BASE = Path(__file__).resolve().parent


def clone(module):
    raw = Path(module.__file__).read_bytes()
    value = types.ModuleType('agent_tools._epoch_protocol_fixture')
    value.__package__ = 'agent_tools'
    value.__file__ = module.__file__
    exec(compile(raw, module.__file__, 'exec'), value.__dict__)
    return value


def guard(prepared):
    for path, snapshot in prepared['snapshots'].items():
        if production.availability._snapshot(path) != snapshot:
            raise ValueError('fixture_upstream_source_changed')


def program(getter, getter_source):
    """Actual dispatch plus actual getter/permission generators; no native prefix.

    The upstream census/alias history is an explicit protocol boundary. Its two
    fixed calls remain visible to the existing whole-receiver host seams.
    """
    node = copy.deepcopy(next(n for n in ast.parse(coldboot._BOOT.replace('__LAUNCH__', '{}')).body
                              if isinstance(n, ast.FunctionDef) and n.name == 'coldboot_dispatch'))
    admission = next(n for n in ast.walk(node) if isinstance(n, ast.If)
                     and ast.unparse(n.test) == "LAUNCH['action'] == 'admit'")
    for parent in ast.walk(node):
        for _, values in ast.iter_fields(parent):
            if isinstance(values, list) and admission in values:
                values.remove(admission)
    result = next(n for n in ast.walk(node) if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == 'result' for t in n.targets))
    result.value = ast.parse('observed_getter(directory)', mode='eval').body
    opened = next(n for n in ast.walk(node) if isinstance(n, ast.Call)
                  and ast.unparse(n.func) == 'os.open' and ast.unparse(n.args[0]) == 'lock_name')
    opened.args[1] = ast.parse('os.O_RDWR | os.O_NOFOLLOW', mode='eval').body
    base = ast.parse(getter_source._GETTER.replace('__GETTER__', repr(getter)))
    observer = ast.parse(production.old.historical._OBSERVER.replace('__OWNER__', repr(production.old.OWNER)))
    replaced = {n.name for n in observer.body if isinstance(n, ast.FunctionDef)}
    base.body = [n for n in base.body if not isinstance(n, ast.FunctionDef) or n.name not in replaced]
    prefix = "import os,stat,json,pathlib,subprocess,time,re,hashlib,fcntl\nCFG={'failedCensus':{'pin':{}}}\n_failed=read_fixed('synthetic-upstream-census',1)\nalias_history_guard()\n"
    launch = {'correlationId': production.BOOT, 'device': 'api29', 'action': 'status', 'intent': {'syntheticProtocol': True}}
    return prefix + 'LAUNCH=' + repr(launch) + '\n' + ast.unparse(base) + '\n' + ast.unparse(observer) + '\n' + ast.unparse(ast.fix_missing_locations(node)) + '\ncoldboot_dispatch()\n'


class Context:
    def __init__(self, root, old_result):
        self.root = Path(root).resolve()
        self.component = historical_source.load(BASE/'component.source', SOURCE_SHA)
        self.component.getter_source = historical_source.load(BASE.parent/'android_component_legacy/product_observer.source', 'ec56e238b0bac95d67ae1942b7218bb844db1e48b29cff1ad7b390b1721d8ae7')
        if hashlib.sha256((BASE/'provenance.json').read_bytes()).hexdigest() != PROVENANCE_SHA:
            raise ValueError('fixture_provenance_changed')
        self.epoch = clone(production)
        self.old = clone(production.old)
        self.proven = clone(self.component.proven)
        self.component.proven = self.proven
        self.epoch.old = self.old
        self.epoch.component = self.component
        self.getter = {'generation': {'child': {'synthetic': True}, 'guest': {'synthetic': True}, 'device': {'sdk': '29', 'matched': True}},
                       'cli': '/fixture/opt/vpn-control/bin/vpn-control', 'stageId': 'synthetic-stage',
                       'packageSha256': 'a'*64, 'manifestSha256': 'b'*64,
                       'manifest': {'launcherSha256': 'c'*64, 'files': [{'path': 'opt/vpn-control/lib/app/fixture%d.jar'%n} for n in range(57)]}}
        upstream = types.SimpleNamespace(**vars(production.old.historical))
        upstream.prepare = self.upstream
        upstream.guard_prepared = guard
        # Real public compression/carrier constructor, with fixture source guard.
        carrier = clone(coldboot)
        carrier.guard_prepared = guard
        upstream.ssh_carrier = carrier.ssh_carrier
        self.old.historical = self.epoch.historical = upstream
        self.epoch.RESULT = 'synthetic-old-result.json'
        self.epoch.RESULT_SHA = self.write(self.epoch.RESULT, old_result)
        old_binding = {'correlationId': production.OLD_CORRELATION, 'controllerId': self.old.OWNER, 'generation': self.getter['generation']}
        directory = Path('.rag_index/android-api29-owned-permission-diagnostics')/production.BOOT
        self.epoch.OLD_LEAVES = {name: self.write(directory/name, {'binding': old_binding, 'replayAllowed': False}) for name in production.OLD_LEAVES}
        options = ['-Djpackage.app-version=2.2.2', '-Dcompose.application.resources.dir=$APPDIR/resources', '-Dcompose.application.configure.swing.globals=true', '-Dskiko.library.path=$APPDIR']
        config = ('app.mainclass=com.kardinal.vpncontrol.desktop.MainKt\n' + ''.join('app.classpath=$APPDIR/fixture%d.jar\n'%n for n in range(57)) + ''.join('java-options='+x+'\n' for x in options)).encode()
        self.proven.CONFIG_SHA = self.write(Path('.rag_index/android-cli-stages')/self.getter['stageId']/'tree/opt/vpn-control/lib/app/vpn-control.cfg', config)
        jdk = {'state': 'observed', 'alias': 'jdk17', 'root': self.proven.CANDIDATES['jdk17'], 'declaredJavaVersion': '17.0.20.1',
               'files': {name: {'generation': [1, 2, 10, 4, 5, 0o100755, 0, 0, 1], 'bytesRead': 10, 'sha256': 'd'*64, 'hashScope': 'full'} for name in self.proven.JDK_FILES}}
        census = {'state': 'external-jdk-census', 'censusComplete': True, 'closingGuardsVerified': True, 'componentRuntime': 'EXTERNAL_JDK',
                  'sourceSha256': self.component.SOURCE_SHA, 'originalSourceSha256': self.proven.ORIGINAL_SHA, 'baselineSha256': self.proven.BASELINE_SHA,
                  'generation': self.getter['generation'], 'stageId': self.getter['stageId'], 'packageSha256': self.getter['packageSha256'],
                  'cliStagePins': [{'synthetic': True}]*2, 'candidates': {'jdk17': jdk, 'jdk21': {'state': 'unknown'}}}
        self.component.CENSUS_SHA = self.write(self.proven.CENSUS, census)
        self.component.PROOF_SHA = self.write(self.component.PROOF, {'componentFlowObserved': True, 'closingGuardsVerified': True, 'jdkClosingGuardsVerified': True,
                                                                  'installedLauncherAccepted': False, 'bundledRuntimeAccepted': False, 'selectedJdk': jdk})
        original = self.component.prepare_binding
        fixture_module_root = Path(self.component.__file__).resolve().parents[1]
        @functools.wraps(original)
        def relocated(root, prepared, device):
            # install's source-relative root resolves to the archive directory.
            # This sole relocation maps that exact root to this own TempFS.
            if Path(root).resolve() == fixture_module_root:
                root = self.root
            elif Path(root).resolve() != self.root:
                raise AssertionError('unexpected fixture root')
            return original(root, prepared, device)
        self.component.prepare_binding = relocated
        historical_source.verify(self.component, BASE/'component.source', SOURCE_SHA)

    def write(self, relative, value):
        raw = value if isinstance(value, bytes) else (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()
        path = self.root/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)
        return hashlib.sha256(raw).hexdigest()

    def upstream(self, root, reservation):
        if Path(root).resolve() != self.root or reservation != {'syntheticProtocol': True}:
            raise AssertionError('unexpected upstream authority')
        modules = (production.old.historical, self.component.getter_source, coldboot)
        snapshots = {Path(m.__file__).absolute(): production.availability._snapshot(Path(m.__file__).absolute()) for m in modules}
        return {'program': program(self.getter, self.component.getter_source), 'snapshots': snapshots, 'binding': {'syntheticProtocol': True}}

    def prepare(self, correlation):
        return self.epoch.prepare(self.root, {'syntheticProtocol': True}, correlation)
