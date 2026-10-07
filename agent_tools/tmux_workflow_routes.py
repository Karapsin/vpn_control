"""Fixed MCP entry points for persistent packaging and its tmux dependency."""
from pathlib import Path
import re

from . import ssh_tmux_mcp_adapter as adapter
from . import arch_tmux_install as installer
from . import tmux_public_projection as projection
from . import ssh_tmux_resource_admission as resource
from . import ssh_tmux_terminal_closure as closure
import json

BUILD_PREFIX = 'linux-package-tmux-'
INSTALL_PREFIX = 'arch-tmux-install-'
ACTIONS = frozenset(BUILD_PREFIX + action for action in ('availability', 'preflight', 'start', 'status', 'collect', 'resource-prepare')) | frozenset(INSTALL_PREFIX + action for action in ('preflight', 'start', 'status'))


def _protected_identity(root, request):
    """One explicit standard reservation; public caller never supplies its token."""
    raw, original = closure.pipe._read(Path(root) / '.rag_index/native-environments/reservations.json', 1048576)
    records = json.loads(raw, object_pairs_hook=closure.ssh_transport._reject_duplicate_keys)
    resource.need(type(records) is dict and set(records) == {'version', 'reservations'} and
                  type(records['reservations']) is list, 'resource_inventory_invalid')
    environment = 'owned-linux-package-build-' + request['correlationId']
    matches = [row for row in records['reservations'] if type(row) is dict and
               row.get('hostAlias') == 'archlinux' and row.get('environment') == environment and
               row.get('operator') == 'root-tmux-build']
    resource.need(len(matches) == 1, 'resource_reservation_not_unique')
    row = matches[0]
    identity = {'reservationId': row.get('id'), 'token': row.get('token'),
                'hostAlias': 'archlinux', 'environment': environment, 'operator': 'root-tmux-build'}
    pin, _ = resource.inventory(root, request, identity)
    resource.need(pin == original, 'resource_inventory_changed')
    return identity


def dispatch(root, action, inputs):
    if action not in ACTIONS:
        return None
    unknown = {'tool': 'vm_workflow', 'ok': False, 'state': 'unknown',
               'reason': 'tmux-workflow-unavailable', 'replayAllowed': False,
               'nativeActionAllowed': False, 'productAction': False}
    if type(inputs) is not dict:
        return unknown
    try:
        if action.startswith(BUILD_PREFIX):
            operation = action[len(BUILD_PREFIX):]
            source = inputs.get('sourceRoot')
            if 'sourceRoot' in inputs and (operation not in ('preflight', 'start', 'resource-prepare') or
                    type(source) is not str or not Path(source).is_absolute() or
                    '\x00' in source or len(source) > 4096):
                return unknown
            raw = {key: value for key, value in inputs.items() if key != 'sourceRoot'}
            if operation == 'availability' and raw:
                return unknown
            projection.request_for('preflight' if operation == 'resource-prepare' else operation, raw)
            if operation == 'resource-prepare':
                if source is None:
                    return unknown
                # Validate clean same-Git source and fixed host before private
                # reservation lookup or any remote resource observation.
                resource.build.preflight(root, raw, source_root=source)
                identity = _protected_identity(root, raw)
                result = resource.prepare(root, raw, identity, source_root=source)
                if (type(result) is not dict or set(result) != {'state', 'correlationId', 'resourceBound', 'nativeActionAllowed'} or
                        type(result['state']) is not str or result['state'] != 'ready' or
                        type(result['correlationId']) is not str or result['correlationId'] != raw['correlationId'] or
                        result['resourceBound'] is not True or result['nativeActionAllowed'] is not False):
                    return unknown
                return {'tool': 'vm_workflow', **result, 'ok': True, 'replayAllowed': False,
                        'productAction': False, 'evidenceClass': 'source-bound-resource-admission'}
            # The existing coordinator validates sourceRoot against its Git
            # common directory; it is never a remote command or path override.
            entry = adapter.operate if operation == 'availability' else resource.operate
            result = entry(root, operation, raw, source_root=source)
            result = projection.project(operation, result, raw)
            return {'tool': 'vm_workflow', **result, 'ok': result.get('state') in
                    ('ready', 'submitted', 'running', 'collected') or result.get('available') is True,
                    'replayAllowed': False, 'nativeActionAllowed': False,
                    'productAction': False, 'evidenceClass': 'source-bound-package-fixture'}
        operation = action[len(INSTALL_PREFIX):]
        if set(inputs) not in ({'host', 'correlationId', 'sourceSha'},
                              {'host', 'correlationId', 'sourceSha', 'timeoutSeconds'}):
            return unknown
        timeout = inputs.get('timeoutSeconds', 240 if operation == 'start' else 30)
        installer._validate(inputs['host'], inputs['correlationId'], inputs['sourceSha'], timeout)
        result = getattr(installer, operation)(root, host=inputs['host'],
                    correlation_id=inputs['correlationId'], source_sha=inputs['sourceSha'],
                    timeout_seconds=timeout)
        allowed = {'state', 'candidateVersion', 'installedVersion', 'lockClear',
                   'cachePolicyValid', 'fullGeneration', 'soleTransactionGuard',
                   'pacmanSignatureVerified', 'packageIntegrityVerified', 'tmuxPresent',
                   'remoteFence', 'correlationId', 'sourceSha', 'host', 'repository',
                   'package', 'replayAllowed', 'nativeActionAllowed'}
        if operation == 'preflight':
            allowed |= {'credentialMetadataValid', 'signaturePolicy', 'sourceBinding', 'safeStartAllowed'}
        if type(result) is not dict or set(result) != allowed or result.get('host') != 'archlinux' or result.get('package') != 'tmux' or result.get('repository') != 'extra' or result.get('correlationId') != inputs['correlationId'] or result.get('sourceSha') != inputs['sourceSha'] or result.get('replayAllowed') is not False or result.get('nativeActionAllowed') is not False:
            return unknown
        states = {'ready', 'package-present', 'candidate-unavailable', 'lock-present',
                  'cache-policy-invalid', 'transaction-guard-unavailable', 'transaction-active',
                  'generation-unavailable', 'admission-changed', 'transaction-failed', 'verified',
                  'package-verification-failed', 'unverified', 'unknown', 'source-closed',
                  'source-changed', 'intent-absent'}
        if result['state'] not in states or result['remoteFence'] not in ('absent', 'recorded', 'unknown', None):
            return unknown
        for key in ('lockClear', 'cachePolicyValid', 'soleTransactionGuard',
                    'pacmanSignatureVerified', 'packageIntegrityVerified', 'tmuxPresent'):
            if result[key] is not None and type(result[key]) is not bool:
                return unknown
        for key in ('candidateVersion', 'installedVersion'):
            if result[key] is not None and (type(result[key]) is not str or not installer._VERSION.fullmatch(result[key])):
                return unknown
        for key in ('fullGeneration', 'sourceBinding'):
            if key in result and result[key] is not None and (type(result[key]) is not str or not re.fullmatch(r'[0-9a-f]{64}', result[key])):
                return unknown
        if operation == 'preflight' and (type(result['credentialMetadataValid']) is not bool or type(result['safeStartAllowed']) is not bool or result['signaturePolicy'] not in {'required-trusted-explicit', 'required-trusted-implicit', 'rejected', 'repo-listing-failed', 'repo-override-unreadable', 'global-query-failed', 'unavailable-path', 'unavailable-repo-query', 'unavailable-repo-listing', 'unavailable-global-query', 'unavailable-policy-parse'}):
            return unknown
        return {'tool': 'vm_workflow', **result,
                'ok': result.get('state') in ('ready', 'package-present', 'verified'),
                'productAction': False, 'evidenceClass': 'build-host-dependency'}
    except Exception:
        return unknown
