"""Fixed tertiary recovery preparation; no native operation on import.

The consumed secondary producer remains unchanged. This module owns only the
separately identified original tertiary and its task-owned recovery namespace.
"""
from __future__ import annotations

from pathlib import Path
import json
import hashlib
import inspect
import re
import subprocess
import time
import os
import stat
import uuid

from . import windows_parallel_vm_launch as launch


def tertiary_argv(guest, boot, *, overlay_fd, template_fd, code_fd, vars_fd, correlation):
    """Source-proven controller with fixed owned tertiary ports and sockets."""
    launch.need(guest==launch.fixed_guest('tertiary') and type(correlation) is str
        and str(uuid.UUID(correlation))==correlation,'tertiary-recipe-scope')
    argv=launch.fixed_argv(guest,boot,overlay_fd=overlay_fd,template_fd=template_fd,
        code_fd=code_fd,vars_fd=vars_fd,repair_correlation=None)
    original=guest.root/'vm-state';owned=guest.root/('vm-r-'+correlation[:8])
    launch.need(all(len(os.fsencode(owned/name))<=107 for name in ('qmp.sock','qga.sock')),
        'tertiary-socket-length')
    # Structured, fixed argument fields only. Controller/NIC/ports/MAC/images
    # remain the authenticated existing recipe; no command or path selector.
    fields=(('-chardev','socket,path='+str(original/'qga.sock')+',server=on,wait=off,id=owned-qga',
             'socket,path='+str(owned/'qga.sock')+',server=on,wait=off,id=owned-qga'),
            ('-qmp','unix:'+str(original/'qmp.sock')+',server=on,wait=off',
             'unix:'+str(owned/'qmp.sock')+',server=on,wait=off'))
    for flag,before,after in fields:
        launch.need(argv.count(flag)==1,'tertiary-recipe-field')
        index=argv.index(flag)+1;launch.need(argv[index]==before,'tertiary-recipe-field')
        argv[index]=after
    return argv


ORIGINAL_UNKNOWN_SHA='cb7e4aece6b5d0ec4b0ea409677811172dc6616d3e40162963ede85ec1e57681'
SECONDARY_UNKNOWN_SHA='78de511d1dfc8b351f714bbb7cf6ffe9eaf3d2b9c9b9294c0b36abff48f5293f'
SECONDARY_PROGRAM_SHA='974bbc63bf6c9f1257141a5dc4dafde1c4b786dc194e5b0a6ac0ab84bc5a46d1'


def tertiary_phase(proc, proof, require_off=True):
    """Exact consumed parents retain custody; neither can replay a guest."""
    import base64
    import hashlib
    launch.need(type(proof) is dict and set(proof)=={'original','secondary'},'tertiary-original-proof')
    original,secondary=proof['original'],proof['secondary']
    launch.need(type(original) is dict and set(original)=={'unknownBase64','supervisor'}
        and type(secondary) is dict and set(secondary)=={'unknownBase64','supervisor'},'tertiary-original-proof')
    raw=base64.b64decode(original['unknownBase64'],validate=True)
    currentraw=base64.b64decode(secondary['unknownBase64'],validate=True)
    launch.need(hashlib.sha256(raw).hexdigest()==ORIGINAL_UNKNOWN_SHA
        and hashlib.sha256(currentraw).hexdigest()==SECONDARY_UNKNOWN_SHA,'tertiary-original-phase')
    old,current=json.loads(raw),json.loads(currentraw)
    launch.need(old['state']=='unknown' and old['originalPids']==[3474305,3474306]
        and current['state']=='unknown' and current['originalPids']==[3726886]
        and current['nativeGuestStarted'] is True,'tertiary-original-phase')
    parent=original['supervisor'];secondary_parent=secondary['supervisor']
    launch.need(parent['pid']==3474300 and parent['startTicks']==21163499 and parent['uid']==0
        and parent['programSha256']=='f3bcd78753ac455926a68e5629beb3fea83acacab6d3b2d077434efc28b49ac6'
        and secondary_parent['pid']==3726881 and secondary_parent['startTicks']==21863561
        and secondary_parent['uid']==0 and secondary_parent['programSha256']==SECONDARY_PROGRAM_SHA,
        'tertiary-original-supervisors')
    launch.need(not os.path.lexists(proc/'3474305'),'tertiary-old-secondary-live')
    launch.need(type(require_off) is bool,'tertiary-phase-mode')
    if require_off:
        launch.need(not os.path.lexists(proc/'3474306'),'tertiary-not-terminal')
        # The authenticated f3b tail returns after its last original child
        # exits. Its absent parent is legitimate only beyond BOTH child ends.
        if os.path.lexists(proc/str(parent['pid'])):
            launch.observed_process(proc,parent,parent['programSha256'])
    else:
        launch.observed_process(proc,parent,parent['programSha256'])
        launch.observed_process(proc,old['identities'][1])
        launch.need(int((proc/'3474306/stat').read_text().rsplit(')',1)[1].split()[1])==3474300,
            'tertiary-original-parent')
    launch.observed_process(proc,secondary_parent,secondary_parent['programSha256'])
    protected=current['identities'][0]
    launch.need(protected['pid']==3726886 and protected['startTicks']==21863571
        and protected['uid']==1000,'tertiary-protected-secondary')
    launch.observed_process(proc,protected)
    launch.need(int((proc/'3726886/stat').read_text().rsplit(')',1)[1].split()[1])==3726881,
        'tertiary-protected-parent')
    # Both authenticated source tails have emitted these immutable UNKNOWNs
    # and perform only original Popen.poll/time.sleep. Their FDs stay with them.
    return {'parent':parent,'secondaryParent':secondary_parent,'secondary':protected}


def tertiary_census(proc, path, census, authority):
    """Only exact inert image roles and protected secondary template reads."""
    launch.need(census['complete'] and not census['argvUsers'],'tertiary-image-census')
    for holder in census['holders']:
        pid,fd=holder['pid'],holder['fd'];root=proc/str(pid)
        flags=int(next(v.split()[1] for v in (root/'fdinfo'/fd).read_text().splitlines()
            if v.startswith('flags:')),8)&os.O_ACCMODE
        launch.need(os.readlink(root/'fd'/fd)==str(path),'tertiary-holder-path')
        if pid==authority['parent']['pid']:
            parent=authority['parent'];launch.observed_process(proc,parent,parent['programSha256'])
            expected=next((v for v in parent['imageFiles'] if v['fd']==fd and v['path']==str(path)),None)
            launch.need(expected is not None and holder['startTicks']==parent['startTicks']
                and flags==expected['accessMode']==(os.O_RDONLY if path.name=='template.qcow2' else os.O_RDWR)
                and launch.inventory.generation((root/'fd'/fd).stat())[:6]==expected['generation'][:6],
                'tertiary-original-holder-role')
        else:
            launch.need(path.name=='template.qcow2' and flags==os.O_RDONLY,'tertiary-foreign-image-holder')
            if pid==authority['secondaryParent']['pid']:
                parent=authority['secondaryParent'];launch.observed_process(proc,parent,parent['programSha256'])
                expected=next((v for v in parent['imageFiles'] if v['fd']==fd and v['path']==str(path)),None)
                launch.need(expected is not None and holder['startTicks']==parent['startTicks']
                    and expected['accessMode']==os.O_RDONLY
                    and launch.inventory.generation((root/'fd'/fd).stat())[:6]==expected['generation'][:6],
                    'tertiary-secondary-parent-holder')
            else:
                child=authority['secondary']
                launch.need(pid==child['pid'] and holder['startTicks']==child['startTicks'],
                    'tertiary-foreign-image-holder')
                launch.observed_process(proc,child)


def fresh_tertiary_repair(scope, prepared, observed, proof):
    """Refresh mutable generations only after the exact original is terminal."""
    template, guests, proc, *_ = scope
    authority = tertiary_phase(proc, proof)
    launch.need(len(guests) == 1 and guests[0].slot == 'tertiary', 'tertiary-repair-only')
    guest = guests[0]
    rows = [row for row in prepared['overlays'] if row['path'] == str(guest.root / 'disk.qcow2')]
    launch.need(len(rows) == 1, 'tertiary-overlay-binding')
    old = rows[0]
    overlay = guest.root / 'disk.qcow2'
    vars_path = guest.root / 'vm-state/vars.fd'
    launch.need(launch.inventory.generation(overlay.lstat())[:6] == old['generation'][:6]
        and launch.inventory.parent_identity(guest.root.lstat()) == old['guestGeneration'],
        'tertiary-owned-overlay')
    expected = next((row for row in authority['parent']['imageFiles']
                     if row['path'] == str(vars_path)), None)
    launch.need(expected is not None
        and launch.inventory.generation(vars_path.lstat())[:6] == expected['generation'][:6]
        and expected['generation'][3:6] == [scope[7], scope[8], 1]
        and stat.S_IMODE(expected['generation'][2]) == 0o600, 'tertiary-owned-vars')
    row = dict(old, generation=launch.inventory.generation(overlay.lstat()))
    current = dict(prepared, overlays=[row])
    binding = dict(observed, overlays=[row], repair={'proof': proof,
        'varsGeneration': launch.inventory.generation(vars_path.lstat())})
    return current, binding

from .windows_parallel_vm_launch import (need, inventory, prepare, file_hash,
    held_source_disk_recipe, launch_resources, binary_alias, native_identity,
    PairUnknown, LIVE_LAUNCHES)


def launch_tertiary(scope, prepared, observed, correlation):
    """Fixed tertiary-only original-overlay reboot; no other guest may enter."""
    template, guests, proc, binary, code, seed, source_root, uid, gid, kvm_gid, trusted_uid = scope
    need(str(uuid.UUID(correlation)) == correlation and tuple((g.slot for g in guests)) == ('tertiary',), 'launch-correlation')
    repair = observed.get('repair')
    need(type(repair) is dict and set(repair) == {'proof', 'varsGeneration'} and (len(guests) == 1), 'tertiary-repair-only')
    need(observed['state'] == 'boot-observed' and observed['boot']['bootMode'] == 'uefi' and (observed['templateGeneration'] == prepared['templateGeneration']) and (observed['overlays'] == prepared['overlays']), 'launch-boot-binding')
    need(correlation not in LIVE_LAUNCHES, 'launch-original-run-exists')
    parents = inventory.parent_pins(template, source_root)
    run = {'correlationId': correlation, 'handles': [], 'files': [], 'directories': [], 'identities': [], 'rootFd': None, 'nativeGuestStarted': False}
    LIVE_LAUNCHES[correlation] = run
    try:
        authority = tertiary_phase(proc, repair['proof']) if repair is not None else None
        run['repairAuthority'] = authority
        run['repairProof'] = repair['proof'] if repair is not None else None
        image_pins = [(template, prepared['templateGeneration'])] + [(guest.root / 'disk.qcow2', row['generation']) for guest, row in zip(guests, prepared['overlays'])]
        for path, pin in image_pins:
            fd = os.open(path, (os.O_RDONLY if path == template else os.O_RDWR) | os.O_NOFOLLOW | os.O_NONBLOCK)
            run['files'].append((path, fd, pin))
            need(inventory.generation(os.fstat(fd)) == pin == inventory.generation(path.lstat()), 'launch-image-generation')
            census = inventory.holder_census(proc, tuple(pin[:2]), (os.getpid(), str(fd)), time.monotonic() + 30, str(path))
            if authority is not None:
                tertiary_census(proc, path, census, authority)
            else:
                need(census['complete'] and (not census['holders']) and (not census['argvUsers']), 'launch-image-holder')
        need(not inventory.tcp_conflicts(proc, tuple((v for g in guests for v in (g.ssh_port, g.vnc_port)))) and (not set(census['macs']) & {g.mac for g in guests}), 'launch-port-or-mac')
        controller = held_source_disk_recipe(source_root, observed, run)
        parents += run['controllerParents']
        resources = launch_resources(proc, source_root)
        binaries = []
        for path, cap in ((binary, 134217728), (code, 16777216), (seed, 16777216)):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            pin = file_hash(fd, cap)
            run['files'].append((path, fd, pin['generation']))
            binaries.append((fd, pin))
            need(pin['generation'][3] == trusted_uid and (not pin['generation'][2] & 18) and (os.path.realpath(path) == str(path)) and (inventory.generation(path.lstat()) == pin['generation']), 'launch-binary-trust')
        need(os.access(binary, os.X_OK), 'launch-binary-not-executable')
        for path, (_, pin) in zip((code, seed), binaries[1:]):
            candidate = next((v for v in observed['firmwareCandidates'] if v['path'] == str(path)))
            need(candidate['available'] is True and candidate['generation'] == pin['generation'] and (candidate['sha256'] == pin['sha256']), 'launch-firmware-generation')
        root = template.parent / ('launch-' + correlation)
        root.mkdir(mode=448)
        run['root'] = root
        run['rootFd'] = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_pin = inventory.parent_identity(os.fstat(run['rootFd']))
        run.update(proc=proc, uid=uid, guests=guests, prepared=prepared, parents=parents, rootPin=root_pin, immutable={template, binary, code, seed} | run['controllerInputs'])
        prepare.record_at(run['rootFd'], 'intent.json', {'correlationId': correlation, 'templateGeneration': prepared['templateGeneration'], 'templateSha256': prepared['templateSha256'], 'overlays': prepared['overlays'], 'resources': resources, 'sourceDiskRecipe': observed['sourceDiskRecipe'], 'diskController': controller, 'binary': binaries[0][1], 'firmware': [v[1] for v in binaries[1:]], 'nativeGuestStarted': False, 'productAcceptance': False})
        for guest, row in zip(guests, prepared['overlays']):
            need(inventory.parent_identity(guest.root.lstat()) == row['guestGeneration'], 'launch-guest-generation')
            state_name = 'vm-state' if repair is None else 'vm-r-' + correlation[:8]
            run.setdefault('stateNames', {})[guest.slot] = state_name
            state = guest.root / state_name
            state.mkdir(mode=448)
            os.chown(state, uid, gid)
            directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            state_pin = inventory.parent_identity(os.fstat(directory))
            run['directories'].append((state, directory, state_pin))
            if repair is not None:
                vars_path = guest.root / 'vm-state/vars.fd'
                var_fd = os.open(vars_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
                var_pin = file_hash(var_fd, 16777216)
                need(var_pin['generation'] == repair['varsGeneration'] == inventory.generation(vars_path.lstat()), 'repair-vars-current')
                run['files'].append((vars_path, var_fd, var_pin['generation']))
                original_vars = next((v for v in authority['parent']['imageFiles'] if v['path'] == str(vars_path)))
                census = inventory.holder_census(proc, tuple(var_pin['generation'][:2]),
                    (os.getpid(), str(var_fd)), time.monotonic() + 30, str(vars_path))
                tertiary_census(proc, vars_path, census, authority)
                prepare.record_at(run['rootFd'], 'tertiary-vars-transition.json', {'sameOwnedIdentity': var_pin['generation'][:6], 'beforeShutdownGeneration': original_vars['generation'], 'afterTerminal': var_pin, 'copiedOrRewound': False})
            else:
                var_fd = os.open('vars.fd', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=directory)
                os.fchown(var_fd, uid, gid)
                os.lseek(binaries[2][0], 0, os.SEEK_SET)
                data = os.read(binaries[2][0], 16777217)
                need(len(data) == binaries[2][1]['generation'][6], 'launch-vars-seed')
                offset = 0
                while offset < len(data):
                    offset += os.write(var_fd, data[offset:])
                os.fsync(var_fd)
                var_pin = file_hash(var_fd, 16777216)
                need(var_pin['sha256'] == binaries[2][1]['sha256'], 'launch-vars-copy')
                run['files'].append((state / 'vars.fd', var_fd, var_pin['generation']))
            log_fd = os.open(guest.slot + '-qemu.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 384, dir_fd=run['rootFd'])
            run.setdefault('logs', []).append((guest.slot, log_fd, inventory.generation(os.fstat(log_fd))))
            argv = tertiary_argv(guest, observed['boot'], overlay_fd=run['files'][1 + len(run['handles'])][1], template_fd=run['files'][0][1], code_fd=binaries[1][0], vars_fd=var_fd, correlation=correlation)
            argv[0] = binary_alias(binaries[0][0])
            selected = {template, binary, code, seed, guest.root / 'disk.qcow2', guest.root / 'vm-state/vars.fd' if repair is not None else state / 'vars.fd'} | run['controllerInputs']
            for path, fd, pin in run['files']:
                if path in selected:
                    need(inventory.generation(os.fstat(fd)) == pin == inventory.generation(path.lstat()), 'launch-preexec-generation')
            for parent, pin in parents:
                need(inventory.parent_identity(parent.lstat()) == pin, 'launch-preexec-parent')
            for path, fd, pin in run['directories']:
                need(inventory.parent_identity(os.fstat(fd)) == pin == inventory.parent_identity(path.lstat()), 'launch-preexec-directory')
            need(root_pin == inventory.parent_identity(os.fstat(run['rootFd'])) == inventory.parent_identity(root.lstat()), 'launch-preexec-root')
            need(not inventory.tcp_conflicts(proc, (guest.ssh_port, guest.vnc_port)), 'launch-preexec-port')
            if repair is not None:
                tertiary_phase(proc, repair['proof'])
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log_fd, stderr=log_fd, pass_fds=tuple({binaries[0][0], binaries[1][0], var_fd, run['files'][0][1], run['files'][1 + len(run['handles'])][1]}), start_new_session=True, user=uid, group=gid, extra_groups=[kvm_gid], env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            run['handles'].append(child)
            run['nativeGuestStarted'] = True
            identity = native_identity(proc, child, argv, binaries[0][1], uid)
            run['identities'].append(identity)
            prepare.record_at(run['rootFd'], guest.slot + '-started.json', identity)
        close_tertiary(run)
        value = {'state': 'pair-started', 'correlationId': correlation, 'guests': run['identities'], 'journal': str(root), 'nativeGuestStarted': True, 'guestAccessVerified': False, 'installedProductVerified': False, 'productAcceptance': False, 'replayAllowed': False}
        prepare.record_at(run['rootFd'], 'result.json', value)
        return (value, run)
    except BaseException as error:
        if run['rootFd'] is not None:
            try:
                prepare.record_at(run['rootFd'], 'unknown.json', {'state': 'unknown', 'correlationId': correlation, 'reason': str(error) if isinstance(error, ValueError) and re.fullmatch('[a-z-]{1,80}', str(error)) else type(error).__name__, 'originalPids': [child.pid for child in run['handles']], 'identities': run['identities'], 'nativeGuestStarted': bool(run['handles']), 'replayAllowed': False, 'productAcceptance': False})
            except BaseException:
                pass
        raise PairUnknown('launch-pair-unknown', run) from error


def close_tertiary(run):
    need(LIVE_LAUNCHES.get(run['correlationId']) is run, 'launch-original-run')
    if run.get('repairAuthority') is not None:
        tertiary_phase(run['proc'], run['repairProof'])
    for child, identity in zip(run['handles'], run['identities']):
        need(native_identity(run['proc'], child, identity['argv'], identity['binary'], run['uid']) == identity, 'launch-closing-process')
    immutable = run['immutable']
    for path, fd, pin in run['files']:
        held, named = (inventory.generation(os.fstat(fd)), inventory.generation(path.lstat()))
        need(held == pin == named if path in immutable else held[:6] == pin[:6] == named[:6], 'launch-closing-file')
    for slot, fd, pin in run['logs']:
        need(inventory.generation(os.fstat(fd))[:6] == pin[:6] == inventory.generation((run['root'] / (slot + '-qemu.private')).lstat())[:6], 'launch-closing-log')
    for guest, row in zip(run['guests'], run['prepared']['overlays']):
        need(inventory.parent_identity(guest.root.lstat()) == row['guestGeneration'], 'launch-closing-guest')
    for path, fd, pin in run['directories']:
        need(inventory.parent_identity(os.fstat(fd)) == pin == inventory.parent_identity(path.lstat()), 'launch-closing-directory')
    for parent, pin in run['parents']:
        need(inventory.parent_identity(parent.lstat()) == pin, 'launch-closing-parent')
    need(run['rootPin'] == inventory.parent_identity(os.fstat(run['rootFd'])) == inventory.parent_identity(run['root'].lstat()), 'launch-closing-root')


UI_STEPS = {
    'advanced': ('ce0ef484e2beb44167c41e4db453db7ea464ee95e88d2aa8a6f26286f4271a71',
                 ('tab', 'ret'), ('473e76a2931105728db973181f1fe06615d1c055c08cf9373fa5f6333df9fe02',
                                  'a69b1860cde0585701b1c9fddb57eeb26197bfaa23a42a540dc44c0fd114859e')),
    'focus': ('1e920932df3b079e06116bb6cf9f3ccc926a592d72ad0bc837bbbbb9b1f142f2',
              ('right',), ('1b4f6ea775648e73eed47c994f225e1633ca481244158c775fcd67e469170bd1',)),
    'turn-off': ('1b4f6ea775648e73eed47c994f225e1633ca481244158c775fcd67e469170bd1',
                 ('ret',), ()),
}


def _header(prepared, observed, correlation):
    """Reuse unchanged authenticated dependency definitions, never its effect tail."""
    source = launch.launch_program(prepared, observed, correlation)
    header = source.split('\nrun=None\n', 1)[0]
    header += '\nimport base64\n'
    # Own functions use only these fixed primitives. No caller-supplied code,
    # paths, guest slots or function-name replacement enters generated source.
    header += 'launch=SimpleNamespace(need=need,fixed_guest=fixed_guest,fixed_argv=fixed_argv,observed_process=observed_process,inventory=inventory)\n'
    for fn in (tertiary_argv, tertiary_phase, tertiary_census,
               fresh_tertiary_repair, launch_tertiary, close_tertiary):
        header += inspect.getsource(fn) + '\n'
    header += 'ORIGINAL_UNKNOWN_SHA=' + repr(ORIGINAL_UNKNOWN_SHA) + '\n'
    header += 'SECONDARY_UNKNOWN_SHA=' + repr(SECONDARY_UNKNOWN_SHA) + '\n'
    header += 'SECONDARY_PROGRAM_SHA=' + repr(SECONDARY_PROGRAM_SHA) + '\n'
    return header


def tertiary_repair_program(prepared, observed, proof, correlation):
    """One fixed new boot, preserving original overlay/VARS and live custodians."""
    prepared, observed, proof = json.loads(json.dumps([prepared, observed, proof], sort_keys=True))
    launch.prepared_binding(prepared)
    launch.validate_disk_controller(observed['boot'])
    launch.need(type(proof) is dict and set(proof) == {'original', 'secondary'}, 'tertiary-original-proof')
    header = _header(prepared, observed, correlation)
    body = '''
run=None
try:
 need(os.geteuid()==0,'tertiary-launch-privilege')
 account=pwd.getpwnam('kardinal')
 need(account.pw_uid==1000 and account.pw_gid==1000,'tertiary-launch-account')
 kvm=Path('/dev/kvm').lstat();kvm_gid=grp.getgrnam('kvm').gr_gid
 need(stat.S_ISCHR(kvm.st_mode) and kvm.st_uid==0 and kvm.st_gid==kvm_gid and kvm_gid>0,'tertiary-launch-kvm')
 scope=(Path(PREPARED['template']),(fixed_guest('tertiary'),),Path('/proc'),Path('/usr/bin/qemu-system-x86_64'),Path(CODE),Path(SEED),Path('/home/kardinal'),1000,1000,kvm_gid,0)
 current,binding=fresh_tertiary_repair(scope,PREPARED,OBSERVED,PROOF)
 value,run=launch_tertiary(scope,current,binding,CORRELATION)
 value=dict(value,state='tertiary-started',guestAccessVerified=False)
except BaseException as error:
 if isinstance(error,PairUnknown):run=error.run
 value={'state':'unknown','reason':'tertiary-reboot','nativeGuestStarted':bool(run and run['handles']),'productAcceptance':False,'replayAllowed':False,'originalPids':[child.pid for child in run['handles']] if run else [],'identities':run['identities'] if run else []}
print(json.dumps(value,sort_keys=True),flush=True)
# Custody stays with the ORIGINAL SSH/Popen/FDs for every live child, including
# a successful infrastructure start. Guest access is a separate read-only step.
if run:
 while any(child.poll() is None for child in run['handles']):time.sleep(1)
'''
    data = ('PREPARED=' + repr(prepared) + '\nOBSERVED=' + repr(observed)
        + '\nPROOF=' + repr(proof) + '\nCORRELATION=' + repr(correlation)
        + '\nCODE=' + repr(str(launch.UEFI_CODE)) + '\nSEED=' + repr(str(launch.UEFI_VARS)) + '\n')
    program = header + data + body
    compile(program, 'fixed original tertiary reboot', 'exec')
    return program


def tertiary_ui_step(prepared, proof, correlation, step):
    """One finite UI step on the exact original tertiary; no ACPI or signal."""
    import base64
    import socket
    import struct
    launch.need(step in UI_STEPS and str(uuid.UUID(correlation)) == correlation,
                'tertiary-ui-step')
    expected, keys, after_hashes = UI_STEPS[step]
    value = {'state': 'unknown', 'reason': 'tertiary-ui-step',
             'newGuestStarted': False, 'productAcceptance': False, 'replayAllowed': False}
    fd = None
    try:
        launch.need(os.geteuid() == 0, 'tertiary-ui-privilege')
        proc = Path('/proc')
        tertiary_phase(proc, proof, require_off=False)
        guest = launch.fixed_guest('tertiary')
        old = json.loads(base64.b64decode(proof['original']['unknownBase64'], validate=True))['identities'][1]
        template = Path(prepared['template'])
        launch.need(launch.inventory.generation(template.lstat()) == prepared['templateGeneration'],
                    'tertiary-ui-template')
        rows = [row for row in prepared['overlays'] if row['path'] == str(guest.root / 'disk.qcow2')]
        launch.need(len(rows) == 1 and launch.inventory.parent_identity(guest.root.lstat())
                    == rows[0]['guestGeneration'], 'tertiary-ui-guest')
        root = template.parent / ('tertiary-ui-' + correlation)
        root.mkdir(mode=0o700)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_pin = launch.inventory.parent_identity(os.fstat(fd))
        prepare.record_at(fd, 'intent.json', {'correlationId': correlation,
            'step': step, 'keys': keys, 'originalTertiary': old, 'replayAllowed': False})
        framer = launch.AccessClient('fixed-qmp', max_response_bytes=4096).bind(
            {'rootFd': fd}, guest, old)
        sock = guest.root / 'vm-state/qmp.sock'
        launch.need(stat.S_ISSOCK(sock.lstat().st_mode) and sock.lstat().st_uid == 1000,
                    'tertiary-ui-socket')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(sock))
            peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            launch.need(peer[:2] == (3474306, 1000), 'tertiary-ui-peer')
            def command(name, arguments=None):
                token = correlation + '-' + name + '-' + str(framer.frames)
                request = {'execute': name, 'id': token}
                if arguments is not None:
                    request['arguments'] = arguments
                connection.sendall(json.dumps(request).encode() + b'\n')
                for _ in range(16):
                    reply = json.loads(framer._read_qmp_response(connection, time.monotonic() + 3))
                    if reply.get('id') == token:
                        launch.need('return' in reply, 'tertiary-ui-refusal')
                        return reply
                raise ValueError('tertiary-ui-response')
            def screenshot(index):
                path = guest.root / 'vm-state' / ('tertiary-ui-' + correlation[:8] + '-' + str(index) + '.png')
                launch.need(not os.path.lexists(path), 'tertiary-ui-screen-exists')
                command('screendump', {'filename': str(path), 'format': 'png'})
                screen_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                try:
                    snapshot = launch.file_hash(screen_fd, 1048576)
                    launch.need(snapshot['generation'] == launch.inventory.generation(path.lstat())
                        and snapshot['generation'][3:6] == [1000, 1000, 1], 'tertiary-ui-screen-identity')
                    return snapshot
                finally:
                    os.close(screen_fd)
            greeting = json.loads(framer._read_qmp_response(connection, time.monotonic() + 3))
            launch.need('QMP' in greeting, 'tertiary-ui-greeting')
            command('qmp_capabilities')
            launch.need(command('query-status')['return']['status'] == 'running', 'tertiary-ui-running')
            before = screenshot(0)
            launch.need(before['sha256'] == expected, 'tertiary-ui-current-screen')
            snapshots, actions = [before], []
            prepare.record_at(fd, 'before.json', before)
            for index, key in enumerate(keys):
                tertiary_phase(proc, proof, require_off=False)
                launch.need(launch.inventory.generation(template.lstat()) == prepared['templateGeneration']
                    and root_pin == launch.inventory.parent_identity(os.fstat(fd))
                    == launch.inventory.parent_identity(root.lstat()), 'tertiary-ui-pre-effect')
                prepare.record_at(fd, 'key-' + ('one', 'two')[index] + '.json', {'key': key,
                    'originalPid': 3474306, 'startTicks': 21163512,
                    'beforeSha256': snapshots[-1]['sha256'], 'replayAllowed': False})
                actions.append(command('send-key', {'keys': [{'type': 'qcode', 'data': key}], 'hold-time': 80}))
                time.sleep(.5)
                if step != 'turn-off':
                    snapshot = screenshot(index + 1)
                    snapshots.append(snapshot)
                    prepare.record_at(fd, 'after-' + ('one', 'two')[index] + '.json', snapshot)
                    launch.need(snapshot['sha256'] == after_hashes[index], 'tertiary-ui-after-screen')
        if step == 'turn-off':
            deadline = time.monotonic() + 90
            while os.path.lexists(proc / '3474306'):
                launch.need(launch.inventory.process_birth(proc, 3474306) == 21163512,
                            'tertiary-ui-original-generation')
                launch.need(time.monotonic() < deadline, 'tertiary-ui-terminal-deadline')
                time.sleep(.2)
            tertiary_phase(proc, proof)
        else:
            tertiary_phase(proc, proof, require_off=False)
        launch.need(root_pin == launch.inventory.parent_identity(os.fstat(fd))
            == launch.inventory.parent_identity(root.lstat())
            and launch.inventory.generation(template.lstat()) == prepared['templateGeneration'],
            'tertiary-ui-closing')
        value = {'state': 'tertiary-ui-observed', 'correlationId': correlation,
            'step': step, 'journal': str(root), 'actions': actions, 'snapshots': snapshots,
            'originalTertiaryTerminal': step == 'turn-off', 'newGuestStarted': False,
            'productAcceptance': False, 'replayAllowed': False}
        prepare.record_at(fd, 'result.json', value)
    except BaseException as error:
        value['errorType'] = type(error).__name__
        if isinstance(error, ValueError) and re.fullmatch('[a-z-]{1,80}', str(error)):
            value['reason'] = str(error)
        if fd is not None:
            try:
                prepare.record_at(fd, 'unknown.json', value)
            except BaseException:
                pass
    return value


def ordinary_tertiary_shutdown_program(prepared, observed, proof, correlation, step):
    """Fixed Advanced/focus/Turn off steps; separate admission for every step."""
    prepared, observed, proof = json.loads(json.dumps([prepared, observed, proof], sort_keys=True))
    launch.need(step in UI_STEPS, 'tertiary-ui-step')
    header = _header(prepared, observed, correlation)
    header += 'UI_STEPS=' + repr(UI_STEPS) + '\n'
    header += 'launch.AccessClient=AccessClient\nlaunch.file_hash=file_hash\n'
    header += inspect.getsource(tertiary_ui_step) + '\n'
    body = ('value=tertiary_ui_step(' + repr(prepared) + ',' + repr(proof) + ','
            + repr(correlation) + ',' + repr(step) + ')\n'
            + 'print(json.dumps(value,sort_keys=True),flush=True)\n')
    program = header + body
    compile(program, 'fixed tertiary ordinary UI shutdown step', 'exec')
    return program
