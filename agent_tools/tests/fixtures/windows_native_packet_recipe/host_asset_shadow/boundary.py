"""One authentic whole-entry host decoder pair using the existing packet World.

Only logical filesystem/backend data are peers. The original caller bytes and f9
loader execute complete; current registered SourceSession _request/remote.validate
remain actual. No ignored runtime path is opened or real API/network invoked.
"""
from pathlib import Path, PurePosixPath
from importlib.machinery import SourceFileLoader
import hashlib
import importlib.util
import json
import sys
import uuid

HERE = Path(__file__).resolve().parent
BEFORE_SHA = '115836dfac880948a1e1317975adb5c4edd25c32c398783e53813ad04e53477e'
AFTER_SHA = '97e28e9a69724665288f4efd2ac075e5959ed0d2eefc942d0a9cdb0729b83fb2'
sha = lambda raw: hashlib.sha256(raw).hexdigest()


def _path_peer(base_path, actual_root, *parts):
    if parts and str(parts[0]) == '/Users/karapsin_de/projects/vpn_control':
        parts = (str(actual_root), *parts[1:])
    return base_path(*parts)


def run_shadow_pair(before, after, loader, repo_root, output_root):
    assert str(_path_peer(PurePosixPath, '/inert/alternate-ci-checkout',
        '/Users/karapsin_de/projects/vpn_control')) == '/inert/alternate-ci-checkout'
    assert sha(before) == BEFORE_SHA and sha(after) == AFTER_SHA
    assert sha(loader) == 'f9d5b99d1dac6f13e02d01fbd268b66f08f6ec7230c4ff2a170648e8838c8d3b'
    provenance = json.loads((HERE / 'provenance.json').read_bytes())
    positive_raw = (HERE / 'positive-result.json').read_bytes()
    collector_raw = (HERE / 'collector.source').read_bytes()
    for name, raw in [('operator.before.source', before), ('positive-result.json', positive_raw), ('collector.source', collector_raw)]:
        assert sha(raw) == provenance['fixturePins'][name]['sha256']
    positive = json.loads(positive_raw)
    common_path = repo_root / 'agent_tools/tests/fixtures/windows_native_packet_recipe/boundary.py'
    name = '_host_asset_shadow_common_' + uuid.uuid4().hex
    spec = importlib.util.spec_from_file_location(name, common_path,
        loader=SourceFileLoader(name, str(common_path)))
    common = importlib.util.module_from_spec(spec)
    sys.modules[name] = common
    try:
        spec.loader.exec_module(common)
        logical = repo_root / '.inert-fixture/windows/native/packet'
        label = 'direct-baseline-two-host-revalidation'
        collector = logical / 'collector.source'
        request_path = logical / 'request.json'
        request = {'operationId': positive['collectorId'], 'program': {
            'language': 'python3', 'source': collector_raw.decode(), 'args': [],
            'cwd': '/home/kardinal', 'targetContext': {
                'kind': 'ssh', 'uid': 1000, 'principal': 'kardinal',
                'home': '/home/kardinal', 'bootId': positive['actorOpening']['bootId']}}}
        request_raw = (json.dumps(request, sort_keys=True) + '\n').encode()
        pin = {'label': label, 'operationId': request['operationId'],
            'collectorId': positive['collectorId'], 'probeId': positive['collectorId'],
            'sourcePath': str(collector), 'sourceSha256': sha(collector_raw),
            'sourceBytes': len(collector_raw), 'requestPath': str(request_path),
            'requestSha256': sha(request_raw), 'sourcePins': [
                {'path': str(collector), 'sha256': sha(collector_raw)}], 'resultJoins': {}}
        manifest = {'schemaVersion': 1, 'operatorSourcePath': str(logical / 'direct-operator.py'),
            'expectedRoot': positive['root'], 'expectedFiles': [
                {'path': row['path'], 'bytes': row['bytes'], 'sha256': row['sha256']}
                for row in positive['files']], 'requests': [pin],
            'canonicalEmitterSha256': '0' * 64, 'canonicalQgaSha256': '0' * 64}
        worlds = []

        class ShadowWorld(common.World):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                worlds.append(self)
                self.sys.argv[3] = label + '@' + str(logical / 'packet/manifest.private.json')
                # The retained caller's single repository literal is a declared
                # virtual path alias, so its whole unchanged bytes run on CI too.
                base_path = self.pathlib.Path
                actual_root = str(repo_root)
                self.pathlib.Path = lambda *parts: _path_peer(base_path, actual_root, *parts)
                data = (json.dumps(positive, sort_keys=True) + '\n').encode()
                ledger = self.repo + '/.rag_index/ssh-program-execution/' + self.pin['operationId']
                self.files[ledger + '/stdout.private']['data'] = bytearray(data)
                self.terminal['streams']['stdout'] = {'retainedSha256': sha(data),
                    'receivedSha256': sha(data), 'bytes': len(data), 'receivedBytes': len(data)}
                terminal_raw = (json.dumps(self.terminal, sort_keys=True) + '\n').encode()
                self.add(ledger + '/terminal.json', terminal_raw)
                closed = {'operationId': self.pin['operationId'],
                    'terminalSha256': sha(terminal_raw), 'sourceClosing': self.fault != 'owner-closing'}
                self.files[ledger + '/owner-closed.json']['data'] = bytearray(json.dumps(closed).encode())
                self.original = {path: bytes(row['data']) for path, row in self.files.items()}

        config = {'repo_root': repo_root, 'logical_root': logical,
            'input_files': {str(collector): collector_raw, str(request_path): request_raw},
            'world_class': ShadowWorld, 'loader_bytes': loader}

        def encoded(source):
            value = dict(manifest, operatorSourceSha256=sha(source))
            return (json.dumps(value, sort_keys=True) + '\n').encode()

        try:
            common.execute(label, before, encoded(before), output_root,
                'before-shadow', config, expected_error=None)
        except AssertionError as caught:
            assert str(caught) == 'own descriptor leaked', str(caught)
            world = worlds[-1]
            failure = json.loads(world.read_bytes(world.out + '/original-failure.json'))
            assert failure['errorClass'] == 'TypeError'
            assert failure['error'] == "'list' object is not callable"
            frames = caught.__traceback__
            actual_error = None
            while frames is not None:
                if frames.tb_frame.f_code.co_name == 'execute':
                    actual_error = frames.tb_frame.f_locals.get('error')
                frames = frames.tb_next
            assert actual_error and actual_error['class'] == 'TypeError'
            leaked = [{'fd': fd, 'path': row['path']} for fd, row in world.fds.items()]
            assert len(leaked) == 1 and leaked[0]['path'].endswith('/terminal.json')
            red = {'sourceSha256': sha(before), 'positiveOraclePassed': False,
                'error': actual_error, 'actualFailureReceipt': failure,
                'leakedOwnedVirtualDescriptors': leaked, 'startCount': world.starts,
                'collectCount': world.collects, 'allOwnDescriptorsClosed': False,
                'productionRequestProofs': world.parser_proofs,
                'completeHeldLoaderOperatorNamespaces': True, 'noSourceRewrite': True}
            # Preserve the leak evidence before releasing only the declared peer.
            (output_root / 'before-shadow.red.json').write_text(json.dumps(red, indent=2) + '\n')
            world.fds.clear()
        else:
            raise AssertionError('preserved unfixed whole caller unexpectedly passed positive oracle')
        green = common.execute(label, after, encoded(after), output_root,
            'after-shadow', config, expected_error=None)
        controls = []
        for case, fault, reason, started in [
            ('admission', 'admission-false', 'original_admission_refused', False),
            ('unknown', 'unknown-collect', 'original_operation_unknown', True),
            ('source-closing', 'owner-closing', 'original_owner_source_not_closed', True)]:
            controls.append(common.execute(label, after, encoded(after), output_root,
                'after-' + case, config, fault=fault, expected_error=reason, expected_started=started))
        return {'before': red, 'after': green, 'controls': controls,
            'samePositiveOracle': True, 'positiveResultSha256': sha(positive_raw),
            'declaredPeers': 'existing packet World filesystem/backend; one finite root-path alias',
            'nativeOrNetworkActions': False}
    finally:
        sys.modules.pop(name, None)
