"""Pure selection of the dispatch fixture readers for a shared read namespace.

No module/template is executed here. Callers retain their source provenance pins
and admission checks; this helper only selects and scopes two read definitions.
"""
from __future__ import annotations

import ast
import hashlib


def scoped_fixture_read_definitions(dispatch_raw: bytes) -> tuple[str, dict]:
    """Keep the dispatch PID reader distinct from the census path reader.

    The canonical CLI environment prefix is composed in ``_REMOTE``. Select its
    literal containing the two functions without evaluating that prefix. Only
    ``ticks``' definition and Name references are renamed; verify the inverse
    against the authentic selected AST before returning compilable source.
    """
    tree = ast.parse(dispatch_raw)
    assignments = [
        node for node in tree.body if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "_REMOTE"
                for target in node.targets)
    ]
    if len(assignments) != 1:
        raise ValueError("facts_dispatch_template_changed")
    pieces = [
        node.value for node in ast.walk(assignments[0].value)
        if isinstance(node, ast.Constant) and type(node.value) is str
        and "def fixture_stopped(" in node.value
    ]
    if len(pieces) != 1:
        raise ValueError("facts_dispatch_read_literal_changed")
    remote = pieces[0]
    nodes = [
        node for node in ast.parse(remote).body
        if isinstance(node, ast.FunctionDef)
        and node.name in {"ticks", "fixture_stopped"}
    ]
    if len(nodes) != 2 or {node.name for node in nodes} != {"ticks", "fixture_stopped"}:
        raise ValueError("facts_original_read_symbols_changed")
    dispatch_source = "\n\n".join(ast.get_source_segment(remote, node) for node in nodes) + "\n"
    original_tree = ast.parse(dispatch_source)
    scoped_tree = ast.parse(dispatch_source)
    scoped_name = "_facts_original_ticks"
    if any(
        isinstance(node, ast.Name) and node.id == scoped_name
        or isinstance(node, ast.FunctionDef) and node.name == scoped_name
        for node in ast.walk(scoped_tree)
    ):
        raise ValueError("facts_original_tick_scope_collision")
    for node in ast.walk(scoped_tree):
        if isinstance(node, ast.FunctionDef) and node.name == "ticks":
            node.name = scoped_name
        elif isinstance(node, ast.Name) and node.id == "ticks":
            node.id = scoped_name
    scoped_source = ast.unparse(scoped_tree) + "\n"
    inverse = ast.parse(scoped_source)
    for node in ast.walk(inverse):
        if isinstance(node, ast.FunctionDef) and node.name == scoped_name:
            node.name = "ticks"
        elif isinstance(node, ast.Name) and node.id == scoped_name:
            node.id = "ticks"
    if ast.dump(inverse, include_attributes=False) != ast.dump(original_tree, include_attributes=False):
        raise ValueError("facts_original_tick_scope_inverse_changed")
    compile(scoped_source, "<scoped-original-fixture-read-definitions>", "exec", dont_inherit=True)
    return scoped_source, {
        "dispatch": [
            {"name": node.name,
             "astSha256": hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()}
            for node in nodes
        ],
        "dispatchScopeInverseVerified": True,
        "originalTickScopedName": scoped_name,
        "exclusiveCustodyConstructed": False,
        "retirementEntrySelected": False,
    }


# Source-bound read-only emission and framing; no execution or native admission.
import json
import os
from agent_tools import android_installer_direct_transport as direct

SOURCE_PINS = {
    'coldboot': 'e80f7c833ca5dbf817afadb7c4fe896d6ddb6e1a792fcc2759311fcf996b0957',
    'census': '0d4ac9875ef793d8d1ebfe613f5c89557e1ac027d8fbbc6ff6ab084fc6f57e4d',
    'owner': '3588b0abd238cd594df0bad1cb0bb1b296c5ade4a9330b47f1f66abcd4a6462c',
    'retained': '3367f498d3a1cb20f733fc7d6333e68bd4b42df09eab9d2ff5a3065cd959dffb',
}

READS = {
    'census': ('fp', 'parent_fds', 'guard_parents', 'close_parents', 'boot', 'ticks'),
    'coldboot': ('child_identity', 'qemu_fact', 'session_guest'),
}

def assignment(tree, name):
    rows = [node.value for node in tree.body if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name]
    if len(rows) != 1:
        raise ValueError('identity_fixed_source_assignment')
    return ast.literal_eval(rows[0])

def emit_identity(coldboot_raw, census_raw, owner_raw, retained_raw, body_raw):
    inputs = dict(coldboot=coldboot_raw, census=census_raw,
                  owner=owner_raw, retained=retained_raw)
    for name, raw in inputs.items():
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != SOURCE_PINS[name]:
            raise ValueError('identity_fixed_source_changed')
    if type(body_raw) is not bytes or len(body_raw) > 65536:
        raise ValueError('identity_body_source_invalid')
    templates = {
        'census': assignment(ast.parse(census_raw), '_CENSUS'),
        'coldboot': assignment(ast.parse(coldboot_raw), '_BOOT'),
    }
    expected = assignment(ast.parse(owner_raw), 'FIXED_GENERATION')
    launch = assignment(ast.parse(retained_raw), 'LAUNCH')
    getter = assignment(ast.parse(retained_raw), 'GETTER')
    if getter['generation'] != expected:
        raise ValueError('identity_retained_expected_binding_changed')
    subset = {key: launch[key] for key in ('qemuPath', 'avd', 'port')}
    if (type(subset['qemuPath']) is not str or not subset['qemuPath'].startswith('/')
            or '..' in subset['qemuPath'].split('/')
            or subset['avd'] != expected['device']['bootAvd']
            or type(subset['port']) is not int or subset['port'] != 5682):
        raise ValueError('identity_retained_launch_binding_changed')
    source = ('import hashlib,json,os,pathlib,re,stat,sys,time\n'
              'PROC=pathlib.Path("/proc")\n'
              'LAUNCH=' + repr(subset) + '\n'
              'EXPECTED=' + repr(expected) + '\n'
              'IDENTITY_CUTOFF=time.monotonic()+50\n'
              'IDENTITY_PRINCIPAL=(os.getuid(),os.geteuid(),os.getgid(),os.getegid(),tuple(sorted(os.getgroups())))\n'
              'if IDENTITY_PRINCIPAL[:4]!=(0,0,0,0) or len(IDENTITY_PRINCIPAL[4])>64:raise ValueError("identity_uid_unknown")\n')
    dispatch = next(node for node in ast.parse(templates['coldboot']).body if isinstance(node,ast.FunctionDef) and node.name=='coldboot_dispatch')
    context = dispatch.body[0]
    if ast.unparse(context) != "if os.getuid() != 0 or os.geteuid() != 0:\n    raise ValueError('coldboot_root_required')":raise ValueError('identity_root_context_changed')
    source += ast.get_source_segment(templates['coldboot'],context) + '\n'
    audit = []
    for name in ('census', 'coldboot'):
        template = templates[name]
        tree = ast.parse(template)
        for function in READS[name]:
            nodes = [node for node in tree.body
                     if isinstance(node, ast.FunctionDef) and node.name == function]
            if len(nodes) != 1:
                raise ValueError('identity_fixed_read_symbol_changed')
            text = ast.get_source_segment(template, nodes[0])
            source += text + '\n\n'
            audit.append({'name': function, 'source': name,
                          'sourceSha256': hashlib.sha256(text.encode()).hexdigest(),
                          'astSha256': hashlib.sha256(ast.dump(nodes[0], include_attributes=False).encode()).hexdigest()})
    source += body_raw.decode('utf-8', 'strict') + '\n'
    source += ('IDENTITY_VALUE=identity_diagnostic_run()\n'
               'if (os.getuid(),os.geteuid(),os.getgid(),os.getegid(),tuple(sorted(os.getgroups())))!=IDENTITY_PRINCIPAL:raise ValueError("identity_uid_changed")\n'
               'IDENTITY_WIRE=(json.dumps(IDENTITY_VALUE,sort_keys=True,separators=(",",":"),allow_nan=False)+"\\n").encode("utf-8")\n'
               'if len(IDENTITY_WIRE)>4096:raise ValueError("identity_finite_output_limit")\n'
               'sys.stdout.write(IDENTITY_WIRE.decode("utf-8"));sys.stdout.flush()\n')
    result = source.encode()
    if len(result) > 65536:
        raise ValueError('identity_readonly_programme_limit')
    emitted = ast.parse(result)
    for row in audit:
        node = next(node for node in emitted.body
                    if isinstance(node, ast.FunctionDef) and node.name == row['name'])
        if hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest() != row['astSha256']:
            raise ValueError('identity_read_function_inverse_changed')
    compile(result, '<fixed-api35-identity-readonly>', 'exec', dont_inherit=True)
    return result, {'functions': audit, 'functionsUnchanged': True,
                    'expectedGenerationOwner': 'canonical-api35-fixed-e3e97',
                    'retainedProgrammeExecuted': False, 'retainedFieldsSelected': ['qemuPath', 'avd', 'port'],
                    'nativeSubmitted': False, 'nativeActionAllowed': False,
                    'replayAllowed': False, 'originalOutcome': 'unknown'}

PINS = {
    'coldboot': 'e80f7c833ca5dbf817afadb7c4fe896d6ddb6e1a792fcc2759311fcf996b0957',
    'census': '0d4ac9875ef793d8d1ebfe613f5c89557e1ac027d8fbbc6ff6ab084fc6f57e4d',
    'collector': 'da4eee30d1aef47d553b6217680967c4e3ced67235596f129f454ad6abe79503',
}

def literal(raw, symbol):
    rows = [node.value for node in ast.parse(raw).body if isinstance(node, ast.Assign)
            and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == symbol]
    if len(rows) != 1:
        raise ValueError('control_fixed_literal_changed')
    return ast.literal_eval(rows[0])

def emit_control(coldboot_raw, census_raw, collector_raw, control_raw, control_sha):
    originals = dict(coldboot=coldboot_raw, census=census_raw, collector=collector_raw)
    for name, raw in originals.items():
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != PINS[name]:
            raise ValueError('control_authentic_source_changed')
    if (type(control_raw) is not bytes or not 0 < len(control_raw) <= 65536
            or hashlib.sha256(control_raw).hexdigest() != control_sha):
        raise ValueError('control_owned_source_changed')
    entries = [node for node in ast.parse(control_raw).body
               if isinstance(node, ast.FunctionDef) and node.name == 'linux_crossprincipal_run']
    if len(entries) != 1:
        raise ValueError('control_fixed_entry_changed')
    templates = dict(coldboot=literal(coldboot_raw, '_BOOT'), census=literal(census_raw, '_CENSUS'))
    dispatch = next(node for node in ast.parse(templates['coldboot']).body
                    if isinstance(node, ast.FunctionDef) and node.name == 'coldboot_dispatch')
    context = dispatch.body[0]
    if ast.unparse(context) != "if os.getuid() != 0 or os.geteuid() != 0:\n    raise ValueError('coldboot_root_required')":
        raise ValueError('control_canonical_root_context_changed')
    programme = 'import hashlib,json,os,pathlib,re,stat,sys,time\nPROC=pathlib.Path("/proc")\n'
    programme += ast.get_source_segment(templates['coldboot'], context) + '\n'
    audit = []
    for name in ('census', 'coldboot'):
        tree = ast.parse(templates[name])
        for function in READS[name]:
            rows = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function]
            if len(rows) != 1:
                raise ValueError('control_read_symbol_changed')
            text = ast.get_source_segment(templates[name], rows[0])
            programme += text + '\n\n'
            audit.append({'name':function, 'source':name,
                          'astSha256':hashlib.sha256(ast.dump(rows[0],include_attributes=False).encode()).hexdigest(),
                          'sourceSha256':hashlib.sha256(text.encode()).hexdigest()})
    programme += control_raw.decode('utf-8','strict') + '\n'
    programme += ('CONTROL_VALUE=linux_crossprincipal_run()\n'
                  'CONTROL_WIRE=(json.dumps(CONTROL_VALUE,sort_keys=True,separators=(",",":"),allow_nan=False)+"\\n").encode("utf-8")\n'
                  'if len(CONTROL_WIRE)>4096:raise ValueError("control_output_bound")\n'
                  'sys.stdout.write(CONTROL_WIRE.decode("utf-8"));sys.stdout.flush()\n')
    raw = programme.encode('utf-8')
    if len(raw) > 65536:
        raise ValueError('control_programme_bound')
    emitted = ast.parse(raw)
    for row in audit:
        node = next(node for node in emitted.body if isinstance(node,ast.FunctionDef) and node.name == row['name'])
        if hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest() != row['astSha256']:
            raise ValueError('control_helper_inverse_changed')
    compile(raw, '<fixed-own-process-crossprincipal-control>', 'exec', dont_inherit=True)
    collector = literal(collector_raw, 'COLLECTOR_SOURCE')
    root_boot = literal(collector, 'ROOT_BOOT')
    if root_boot.count('__BYTES__') != 1 or root_boot.count('__SHA__') != 1:
        raise ValueError('control_root_bridge_changed')
    bootstrap = root_boot.replace('__BYTES__', str(len(raw))).replace('__SHA__', repr(hashlib.sha256(raw).hexdigest()))
    compile(bootstrap, '<unchanged-authenticated-root-stdin-bridge>', 'exec', dont_inherit=True)
    return raw, bootstrap, {'helpers':audit,'canonicalRootContextUnchanged':True,
                            'rootStdinBridgeUnchanged':True,'nativeSubmitted':False}

def prepare_auth_frame(path, held, source_guard, programme):
    """Only future caller supplies the fixed ignored auth path; never publish it."""
    if type(programme) is not bytes or not 0 < len(programme) <= 65536 or not callable(source_guard) or type(held) is not list:
        raise ValueError('control_frame_source_required')
    source_guard()
    raw, pin = direct.snapshot(path, private=True, limit=514)
    held.append(direct._dispatch_hold(path, pin, raw))
    source_guard()
    credential = raw.rstrip(b'\r\n')
    if not 0 < len(credential) <= 512 or b'\n' in credential or b'\r' in credential or b'\0' in credential:
        raise ValueError('control_private_auth_shape')
    header = ('VPNCONTROL_COMPONENT_SOURCE_V1 ' + str(len(programme)) + ' ' + hashlib.sha256(programme).hexdigest() + '\n').encode('ascii')
    frame = credential + b'\n' + header + programme
    source_guard()
    for _, origin, _, fd in held:
        if hashlib.sha256(os.pread(fd, origin['generation'][6] + 1, 0)).hexdigest() != origin['sha256']:
            raise ValueError('control_held_body_changed')
    direct._dispatch_guard(held)
    return frame

def prepare_receiver_frame(path, held, source_guard, programme):
    # The genuine UID1000 receiver, rather than its root child, receives the
    # private prefix and source. That receiver constructs the existing header.
    frame = prepare_auth_frame(path, held, source_guard, programme)
    credential, separator, remainder = frame.partition(b'\n')
    header, separator2, source = remainder.partition(b'\n')
    expected = ('VPNCONTROL_COMPONENT_SOURCE_V1 ' + str(len(programme)) + ' ' + hashlib.sha256(programme).hexdigest()).encode('ascii')
    if not separator or not separator2 or header != expected or source != programme:
        raise ValueError('control_receiver_frame_changed')
    return credential + b'\n' + source

def receiver_source(collector_raw, programme, bootstrap):
    if hashlib.sha256(collector_raw).hexdigest() != PINS['collector']:
        raise ValueError('control_authentic_source_changed')
    collector = literal(collector_raw, 'COLLECTOR_SOURCE')
    remote = literal(collector, 'REMOTE')
    needle = 'deadline=collection_started+1200'
    if remote.count(needle) != 1:
        raise ValueError('control_receiver_watchdog_changed')
    # This admitted short phase has a stricter watchdog. All source, principal,
    # framing, byte caps, collection/cleanup and UNKNOWN rules stay exact.
    remote = remote.replace(needle, 'deadline=collection_started+50')
    remote = remote.replace('__BYTES__', str(len(programme))).replace('__SHA__', repr(hashlib.sha256(programme).hexdigest())).replace('__BOOT__', repr(bootstrap))
    compile(remote, '<fixed-short-root-reader-receiver>', 'exec', dont_inherit=True)
    return remote
