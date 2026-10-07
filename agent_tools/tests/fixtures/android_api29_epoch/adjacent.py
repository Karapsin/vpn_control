"""Actual adjacent public factories, isolated synthetic upstream/receipt inputs.

Production source anchors are not edited. No retained native payload is opened;
modeled launcher failure and JDK/stage DTOs are explicitly protocol examples.
"""
import ast
import copy
from pathlib import Path
from .context import Context, clone, guard, program, BASE
from agent_tools import android_api29_current_permission_observation as permission
from agent_tools import android_api29_current_owner_observation as owner
from agent_tools.tests.fixtures import historical_source


class AdjacentContext(Context):
    def __init__(self, root):
        # Synthetic negative old effect receipt, not historical 0806 proof.
        from agent_tools.tests.test_android_api29_current_epoch_diagnostics import old_result
        super().__init__(root, old_result())
        self.permission = clone(permission)
        self.product = self.component.getter_source
        self.product.prepare = self.product_provider
        self.product.guard_prepared = guard
        self.permission.original = self.product
        self.owner = clone(owner)
        self.owner.original = self.permission
        self.external = self.proven
        self.external.original = self.owner
        self.baseline = {'records': {'statusDiscovery': {'returncode': 0, 'stderrRaw': 'pure virtual method called\nterminate called without an active exception\n',
                                                        'stdout': {'ok': True, 'code': 'OK', 'controllerId': '6373d143-1372-4835-a89b-baafb0959b9f', 'configurationRevision': 0}}},
                         'closingGuardsVerified': True, 'syntheticProtocol': True}
        self.external.BASELINE_SHA = self.write(self.external.BASELINE, self.baseline)

    def product_provider(self, root, reservation):
        prepared = self.upstream(root, reservation)
        tree = ast.parse(program(self.getter, self.product))
        observer = ast.parse(permission._OBSERVER.replace('__OWNER__', repr(permission.OWNER)))
        removed = {n.name for n in observer.body if isinstance(n, ast.FunctionDef)}
        tree.body = [n for n in tree.body if not isinstance(n, ast.FunctionDef) or n.name not in removed]
        # Genuine historical product getter generator, before permission prepare
        # replaces its bounded reader/observer. Keep dispatch original call.
        getter = ast.parse(self.product._GETTER.replace('__GETTER__', repr(self.getter)))
        existing = {n.name for n in getter.body if isinstance(n, ast.FunctionDef)}
        tree.body = [n for n in tree.body if not isinstance(n, ast.FunctionDef) or n.name not in existing]
        tree.body[-1:-1] = getter.body
        reader_path = BASE.parent/'android_component_legacy/android_avd_launch_recovery.source'
        reader = historical_source.load(reader_path, 'eb89ef4cccdb5417becd02b4116eccd10b2e4da4d9fe81f3a8c54d8f97b13fa0')
        # Actual inherited definitions removed by permission.compose before any
        # receiver execution; no fake placeholder definitions or native calls.
        nodes = [n for n in ast.parse(reader._CENSUS.replace('__CFG__', '{}')).body
                 if isinstance(n, ast.FunctionDef) and n.name in ('write_capsule', 'capture')]
        assert len(nodes) == 2
        tree.body[-1:-1] = nodes
        prepared['program'] = ast.unparse(ast.fix_missing_locations(tree))+'\n'
        for module in (self.product, reader):
            p = Path(module.__file__).absolute()
            prepared['snapshots'][p] = permission.availability._snapshot(p)
        guard(prepared)
        return prepared

    def permission_prepared(self):
        return self.permission.prepare(self.root, {'syntheticProtocol': True})

    def owner_prepared(self):
        return self.owner.prepare(self.root, {'syntheticProtocol': True})

    def external_prepared(self, action):
        first = self.external.prepare(self.root, {'syntheticProtocol': True}, 'census')
        b = self.component._assignment(ast.parse(first['program']), 'EXTERNAL')
        proof = {k: b[k] for k in ('sourceSha256', 'originalSourceSha256', 'baselineSha256', 'generation', 'stageId', 'packageSha256')}
        jdk = {'state': 'observed', 'alias': 'jdk17', 'root': self.external.CANDIDATES['jdk17'], 'declaredJavaVersion': '17.0.20.1',
               'files': {name: {'generation': [1, 2, 10, 4, 5, 0o100755, 0, 0, 1], 'bytesRead': 10, 'sha256': 'a'*64, 'hashScope': 'full'} for name in self.external.JDK_FILES}}
        proof.update(state='external-jdk-census', censusComplete=True, closingGuardsVerified=True, componentRuntime='EXTERNAL_JDK',
                     cliStagePins=[{'155': 'fixed'}, {'155': 'fixed'}], candidates={'jdk17': jdk, 'jdk21': {'state': 'unknown', 'reason': 'external_jdk_unavailable'}})
        self.write(self.external.CENSUS, proof)
        return (first if action == 'census' else self.external.prepare(self.root, {'syntheticProtocol': True}, 'compare')), b, proof
