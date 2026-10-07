"""Fixed additional Windows guest boot facts and launch recipe.

Source-only implementation: callers cannot choose disks, commands or firmware.
Actual owned-template boot observations must precede a native launch. No
historical firmware, borrowed TPM, CP117 disk or installer media is accepted.
"""
from __future__ import annotations

import binascii
from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import subprocess
import time
import uuid

from . import windows_parallel_vm_prepare as prepare
from . import windows_parallel_vm_source_inventory as inventory
from . import windows_parallel_vm_prepare_transport as transport
from scripts import native_fixture_qga as qga

PREFIX_BYTES = 1024 * 1024
SECTOR_BYTES = 512
ESP_GUID = uuid.UUID('c12a7328-f81f-11d2-ba4b-00a0c93ec93b')
UEFI_CODE = Path('/usr/share/edk2/x64/OVMF_CODE.4m.fd')
UEFI_VARS = Path('/usr/share/edk2/x64/OVMF_VARS.4m.fd')
MEMORY_BYTES = 4 * 1024 ** 3
HEADROOM_BYTES = 8 * 1024 ** 3
LIVE_LAUNCHES = {}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


@dataclass(frozen=True)
class Guest:
    slot: str
    root: Path
    ssh_port: int
    vnc_port: int
    mac: str


def fixed_guest(slot):
    need(type(slot) is str and slot in ('secondary', 'tertiary'), 'guest-slot')
    index = ('secondary', 'tertiary').index(slot)
    return Guest(slot, Path(inventory.DESTINATIONS[index]), (2339, 2338)[index],
                 (5939, 5938)[index], inventory.MACS[index])


def boot_layout(raw, virtual_bytes):
    """Validate actual virtual-sector bytes, never infer UEFI from a filename.

    A primary GPT requires both header and entry-array CRCs and exactly one ESP.
    Legacy boot requires a valid active partition and executable MBR bytes.
    Ambiguous, truncated and unsupported layouts remain refused.
    """
    need(type(raw) is bytes and len(raw) == PREFIX_BYTES and type(virtual_bytes) is int
         and virtual_bytes > PREFIX_BYTES and virtual_bytes % SECTOR_BYTES == 0, 'boot-prefix-size')
    need(raw[510:512] == b'\x55\xaa', 'boot-mbr-signature')
    sectors = virtual_bytes // SECTOR_BYTES
    entries = [raw[446 + 16*i:462 + 16*i] for i in range(4)]
    protective = [row for row in entries if row[4] == 0xee]
    if protective:
        need(len(protective) == 1 and all(row[4] in (0, 0xee) for row in entries), 'boot-hybrid-mbr')
        header = raw[512:1024]
        need(header[:8] == b'EFI PART', 'boot-gpt-signature')
        revision, size, crc, reserved = struct.unpack_from('<IIII', header, 8)
        need(revision == 0x10000 and 92 <= size <= 512 and reserved == 0, 'boot-gpt-header')
        checked = bytearray(header[:size]);checked[16:20] = b'\0' * 4
        need(binascii.crc32(checked) & 0xffffffff == crc, 'boot-gpt-header-crc')
        current, backup, first, last = struct.unpack_from('<QQQQ', header, 24)
        table_lba, count, row_size, table_crc = struct.unpack_from('<QIII', header, 72)
        need(current == 1 and backup == sectors - 1 and 2 <= first <= last < backup
             and 1 <= count <= 128 and row_size == 128 and table_lba >= 2,
             'boot-gpt-bounds')
        start = table_lba * SECTOR_BYTES;end = start + count * row_size
        need(end <= len(raw) and end <= first * SECTOR_BYTES, 'boot-gpt-table-bounds')
        table = raw[start:end]
        need(binascii.crc32(table) & 0xffffffff == table_crc, 'boot-gpt-table-crc')
        partitions, identifiers = [], set()
        for offset in range(0, len(table), row_size):
            row = table[offset:offset+row_size]
            if row[:16] == b'\0' * 16:
                need(row == b'\0' * row_size, 'boot-gpt-empty-entry')
                continue
            kind, identifier = uuid.UUID(bytes_le=row[:16]), uuid.UUID(bytes_le=row[16:32])
            lo, hi = struct.unpack_from('<QQ', row, 32)
            need(identifier.int != 0 and identifier not in identifiers and first <= lo <= hi <= last,
                 'boot-gpt-partition')
            need(all(hi < p['firstLba'] or lo > p['lastLba'] for p in partitions), 'boot-gpt-overlap')
            identifiers.add(identifier)
            partitions.append({'typeGuid': str(kind), 'partitionGuid': str(identifier),
                               'firstLba': lo, 'lastLba': hi})
        esp = [row for row in partitions if row['typeGuid'] == str(ESP_GUID)]
        need(len(esp) == 1, 'boot-esp-ambiguous')
        return {'bootMode': 'uefi', 'esp': esp[0], 'diskGuid': str(uuid.UUID(bytes_le=header[56:72])),
                'partitionCount': len(partitions), 'prefixSha256': hashlib.sha256(raw).hexdigest(),
                'tpmDependency': 'unverified', 'guestOperatingSystemVerified': False}
    active = []
    for row in entries:
        need(row[0] in (0, 0x80), 'boot-mbr-active')
        lo, size = struct.unpack_from('<II', row, 8)
        if row[4] == 0:
            need(lo == size == 0 and row[0] == 0, 'boot-mbr-empty')
            continue
        need(lo > 0 and size > 0 and lo + size <= sectors, 'boot-mbr-bounds')
        if row[0] == 0x80:
            active.append({'partitionType': row[4], 'firstLba': lo, 'sectorCount': size})
    need(len(active) == 1 and any(raw[:440]), 'boot-legacy-ambiguous')
    return {'bootMode': 'bios', 'activePartition': active[0],
            'prefixSha256': hashlib.sha256(raw).hexdigest(), 'tpmDependency': 'unverified',
            'guestOperatingSystemVerified': False}


def held_virtual_prefix(template_fd, destination_fd, qemu_img='/usr/bin/qemu-img', *, binary_fd=None, binary_pin=None):
    """Internal fixed owned-template reader; raw goes only to original private FD."""
    before = inventory.generation(os.fstat(template_fd))
    target = inventory.generation(os.fstat(destination_fd))
    need(stat.S_ISREG(before[2]) and before[5] == 1 and stat.S_IMODE(before[2]) == 0o440,
         'boot-template-not-sealed')
    need(stat.S_ISREG(target[2]) and target[5] == 1 and target[6] == 0
         and stat.S_IMODE(target[2]) == 0o600, 'boot-private-prefix')
    need((binary_fd is None) == (binary_pin is None), 'boot-preexec-binary')
    pass_fds = (template_fd, destination_fd)
    if binary_fd is not None:
        need(inventory.generation(os.fstat(binary_fd)) == binary_pin
             == inventory.generation(Path(qemu_img).lstat()), 'boot-preexec-binary')
        executable = binary_alias(binary_fd)
        pass_fds += (binary_fd,)
    else:
        executable = qemu_img
    command = [executable, 'dd', '-f', 'qcow2', 'if=' + fd_alias(template_fd),
               'of=' + fd_alias(destination_fd), 'bs=512', 'count=2048']
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, pass_fds=pass_fds,
                            timeout=30, check=False, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
    os.fsync(destination_fd)
    need(result.returncode == 0 and inventory.generation(os.fstat(template_fd)) == before,
         'boot-read-unknown')
    need(os.fstat(destination_fd).st_size == PREFIX_BYTES, 'boot-read-prefix-bound')
    os.lseek(destination_fd, 0, os.SEEK_SET)
    raw = bytearray()
    while len(raw) <= PREFIX_BYTES:
        block = os.read(destination_fd, min(65536, PREFIX_BYTES + 1 - len(raw)))
        if not block:
            break
        raw.extend(block)
    need(len(raw) == PREFIX_BYTES, 'boot-read-prefix-bound')
    return bytes(raw)


def fd_alias(fd):
    return '/proc/self/fd/' + str(fd)


def binary_alias(fd):
    return '/proc/self/fd/' + str(fd)


def file_hash(fd, maximum):
    before = inventory.generation(os.fstat(fd))
    need(stat.S_ISREG(before[2]) and before[5] == 1 and 0 < before[6] <= maximum, 'boot-file-shape')
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    count = 0
    while count <= maximum:
        raw = os.read(fd, min(1048576, maximum + 1 - count))
        if not raw:
            break
        count += len(raw);digest.update(raw)
    need(count == before[6] and inventory.generation(os.fstat(fd)) == before, 'boot-file-generation')
    return {'generation': before, 'sha256': digest.hexdigest()}


def observed_boot(scope, expected, correlation):
    """Internal held-image native reader; never launch or modify a guest.

    Scope is fixed by the native builder; only local tests project directories
    and Linux /proc. Raw boot sectors remain in a private owned diagnostic leaf.
    """
    need(str(uuid.UUID(correlation)) == correlation, 'boot-correlation')
    template, guests, proc, binary, source_root, trusted_uid = scope
    need(expected['template'] == str(template) and len(expected['overlays']) == len(guests) == 2,
         'boot-copy-binding')
    parents = inventory.parent_pins(template, source_root)
    fds, binaries, evidence_fd, raw_fd = [], [], None, None
    evidence = template.parent / ('boot-read-' + correlation)
    try:
        for path, pin in [(template, expected['templateGeneration'])] + [
                (guest / 'disk.qcow2', row['generation']) for guest, row in zip(guests, expected['overlays'])]:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK);fds.append((path, fd, pin))
            need(inventory.generation(os.fstat(fd)) == pin == inventory.generation(path.lstat()), 'boot-image-generation')
            census = inventory.holder_census(proc, tuple(pin[:2]), (os.getpid(), str(fd)),
                                             time.monotonic() + 30, str(path))
            need(census['complete'] and not census['holders'] and not census['argvUsers'], 'boot-image-holder')
        for guest, row in zip(guests, expected['overlays']):
            need(inventory.parent_identity(guest.lstat()) == row['guestGeneration'], 'boot-guest-generation')
            need(not os.path.lexists(guest / 'vm-state'), 'boot-guest-already-submitted')
        need(not inventory.tcp_conflicts(proc, inventory.PORTS)
             and not set(inventory.MACS) & set(census['macs']), 'boot-resource-conflict')
        binary_fd = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        binaries.append((binary, binary_fd, None))
        binary_pin = file_hash(binary_fd, 33554432)
        binaries[-1] = (binary, binary_fd, binary_pin['generation'])
        need(binary_pin['generation'][3] == trusted_uid and not binary_pin['generation'][2] & 0o022
             and os.access(binary, os.X_OK), 'boot-binary-trust')
        need(os.path.realpath(binary) == str(binary)
             and inventory.generation(binary.lstat()) == binary_pin['generation'], 'boot-binary-name')
        evidence.mkdir(mode=0o700)
        evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        evidence_pin = inventory.parent_identity(os.fstat(evidence_fd))
        prepare.record_at(evidence_fd, 'intent.json', {'correlationId': correlation,
            'copyCorrelationId': expected['correlationId'], 'templateGeneration': expected['templateGeneration'],
            'templateSha256': expected['templateSha256'], 'qemuImg': binary_pin,
            'nativeGuestStarted': False, 'launchAdmitted': False})
        raw_fd = os.open('boot-prefix.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=evidence_fd)
        # Journal and output creation cannot release a stale image/binary pin.
        for path, fd, pin in fds:
            need(inventory.generation(os.fstat(fd)) == pin
                 == inventory.generation(path.lstat()), 'boot-preexec-image')
        raw = held_virtual_prefix(fds[0][1], raw_fd, str(binary),
                                  binary_fd=binary_fd, binary_pin=binary_pin['generation'])
        raw_pin = inventory.generation(os.fstat(raw_fd))
        need(raw_pin == inventory.generation(os.stat('boot-prefix.private',dir_fd=evidence_fd,
                                                    follow_symlinks=False)), 'boot-prefix-generation')
        boot = boot_layout(raw, 96 * 1024 ** 3)
        firmware = []
        for path in (UEFI_CODE, UEFI_VARS) if boot['bootMode'] == 'uefi' else ():
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK);binaries.append((path, fd, None))
                pin = file_hash(fd, 16777216)
                binaries[-1] = (path, fd, pin['generation'])
                need(pin['generation'][3] == trusted_uid and not pin['generation'][2] & 0o022
                     and pin['generation'] == inventory.generation(path.lstat()), 'boot-firmware-trust')
                firmware.append({'path': str(path), 'available': True, **pin})
            except FileNotFoundError:
                firmware.append({'path': str(path), 'available': False})
        # Body/native metadata reads complete before final pure group closure.
        need(raw_pin == inventory.generation(os.fstat(raw_fd))
             == inventory.generation(os.stat('boot-prefix.private',dir_fd=evidence_fd,
                                             follow_symlinks=False)), 'boot-closing-prefix')
        for path, fd, pin in fds:
            need(inventory.generation(os.fstat(fd)) == pin == inventory.generation(path.lstat()), 'boot-closing-image')
        for path, fd, pin in binaries:
            need(inventory.generation(os.fstat(fd)) == pin == inventory.generation(path.lstat()), 'boot-closing-binary')
        for path, pin in parents:
            need(inventory.parent_identity(path.lstat()) == pin, 'boot-closing-parent')
        for guest, row in zip(guests, expected['overlays']):
            need(inventory.parent_identity(guest.lstat()) == row['guestGeneration']
                 and not os.path.lexists(guest / 'vm-state'), 'boot-closing-guest')
        need(os.path.realpath(evidence) == str(evidence) and inventory.parent_identity(evidence.lstat())
             == evidence_pin == inventory.parent_identity(os.fstat(evidence_fd)), 'boot-closing-evidence')
        value = {'state': 'boot-observed', 'correlationId': correlation, 'copyCorrelationId': expected['correlationId'],
                 'boot': boot, 'firmwareCandidates': firmware, 'prefixGeneration': raw_pin,
                 'templateGeneration': expected['templateGeneration'], 'overlays': expected['overlays'],
                 'qemuImg': binary_pin, 'nativeGuestStarted': False, 'launchAdmitted': False,
                 'productAcceptance': False}
        prepare.record_at(evidence_fd, 'result.json', value)
        return value
    except BaseException as error:
        if evidence_fd is not None:
            prepare.record_at(evidence_fd, 'unknown.json', {'state': 'unknown',
                'reason': str(error) if isinstance(error, ValueError) else type(error).__name__,
                'correlationId': correlation, 'nativeGuestStarted': False, 'launchAdmitted': False})
        raise
    finally:
        if raw_fd is not None:
            os.close(raw_fd)
        for _, fd, _ in fds:
            os.close(fd)
        for _, fd, _ in binaries:
            os.close(fd)
        if evidence_fd is not None:
            os.close(evidence_fd)


def prepared_binding(prepared):
    """Retained copy producer DTO binding; grants no live launch authority."""
    need(type(prepared) is dict and prepared.get('state') == 'prepared'
         and prepared.get('template') == str(prepare.TEMPLATE_ROOT / 'template.qcow2')
         and all(prepared.get(key) is False for key in ('nativeGuestStarted', 'launchAdmitted', 'productAcceptance'))
         and prepared.get('ordinaryQemuReadAccessConfigured') is True, 'boot-prepared-source')
    correlation = prepared.get('correlationId')
    need(type(correlation) is str and str(uuid.UUID(correlation)) == correlation, 'boot-copy-correlation')
    sha = prepared.get('templateSha256')
    need(type(sha) is str and len(sha) == 64 and all(c in '0123456789abcdef' for c in sha), 'boot-copy-hash')
    template = prepared.get('templateGeneration')
    need(type(template) is list and len(template) == 9 and all(type(v) is int and v >= 0 for v in template)
         and stat.S_ISREG(template[2]) and stat.S_IMODE(template[2]) == 0o440 and template[3:6] == [0,1000,1]
         and template[6] > 0, 'boot-copy-template-pin')
    overlays = prepared.get('overlays')
    need(type(overlays) is list and len(overlays) == 2 and all(type(row) is dict for row in overlays)
         and [row.get('path') for row in overlays] == [str(Path(p) / 'disk.qcow2') for p in inventory.DESTINATIONS],
         'boot-prepared-guests')
    for row in overlays:
        image, guest = row.get('generation'), row.get('guestGeneration')
        need(type(image) is list and len(image) == 9 and all(type(v) is int and v >= 0 for v in image)
             and stat.S_ISREG(image[2]) and stat.S_IMODE(image[2]) == 0o600 and image[3:6] == [1000,1000,1]
             and image[6] > 0 and type(guest) is list and len(guest) == 5
             and all(type(v) is int and v >= 0 for v in guest) and stat.S_ISDIR(guest[2])
             and stat.S_IMODE(guest[2]) == 0o700 and guest[3:5] == [1000,1000], 'boot-copy-overlay-pin')


def boot_program(prepared, correlation):
    """Only fixed prepared-template observation, no caller path/command choice."""
    prepared_binding(prepared)
    need(type(correlation) is str and str(uuid.UUID(correlation)) == correlation, 'boot-correlation')
    header = 'from pathlib import Path\nimport os,stat,subprocess,time,json,hashlib,re,selectors,uuid,struct,binascii\nfrom types import SimpleNamespace\n'
    header += 'FIELDS=' + repr(inventory.FIELDS) + '\nPREFIX_BYTES=' + repr(PREFIX_BYTES) + '\nSECTOR_BYTES=512\n'
    header += 'ESP_GUID=uuid.UUID(' + repr(str(ESP_GUID)) + ')\nUEFI_CODE=Path(' + repr(str(UEFI_CODE)) + ')\nUEFI_VARS=Path(' + repr(str(UEFI_VARS)) + ')\n'
    for fn in (need, inventory.generation, inventory.parent_identity, inventory.parent_pins, inventory.process_birth,
               inventory.holder_census, inventory.tcp_conflicts):
        header += inspect.getsource(fn) + '\n'
    header += 'inventory=SimpleNamespace(generation=generation,parent_identity=parent_identity,parent_pins=parent_pins,holder_census=holder_census,tcp_conflicts=tcp_conflicts,PORTS=' + repr(inventory.PORTS) + ',MACS=' + repr(inventory.MACS) + ')\n'
    header += inspect.getsource(prepare.record_at) + '\nprepare=SimpleNamespace(record_at=record_at)\n'
    for fn in (fd_alias, binary_alias, held_virtual_prefix, file_hash, boot_layout, observed_boot):
        header += inspect.getsource(fn) + '\n'
    scope = "(Path(" + repr(prepared['template']) + "),tuple(Path(p) for p in " + repr(inventory.DESTINATIONS) + "),Path('/proc'),Path('/usr/bin/qemu-img'),Path('/home/kardinal'),0)"
    header += '\ntry:\n need(os.geteuid()==0,"boot-privilege")\n value=observed_boot(' + scope + ',' + repr(prepared) + ',' + repr(correlation) + ')\nexcept Exception:\n value={"state":"unknown","reason":"boot-observation-refused","nativeGuestStarted":False,"launchAdmitted":False,"productAcceptance":False}\nprint(json.dumps(value,sort_keys=True))\n'
    compile(header, 'fixed owned-template boot observer', 'exec')
    return header


def source_disk_controller(raw):
    """Parse the fixed source recipe; never execute or borrow its state."""
    need(type(raw) is bytes and 0 < len(raw) <= 16384, 'launch-source-recipe-bound')
    argv=json.loads(raw)
    need(type(argv) is list and 2 <= len(argv) <= 256 and all(type(v) is str and len(v)<=4096 for v in argv), 'launch-source-recipe-shape')
    def values(flag):
        indexes=[i for i,v in enumerate(argv) if v==flag]
        need(all(i+1<len(argv) for i in indexes),'launch-source-recipe-argument')
        return [argv[i+1] for i in indexes]
    source='/home/kardinal/vpn-control-windows-native-20260907/task.qcow2'
    need(values('-machine')==['q35,accel=kvm,smm=on'],'launch-source-machine')
    drives=[v for v in values('-drive') if 'task.qcow2' in v or ',id=disk,' in v]
    need(drives==['file='+source+',if=none,id=disk,format=qcow2'],'launch-source-disk')
    devices=values('-device')
    need([v for v in devices if ',drive=disk' in v]==['ide-hd,drive=disk,bus=ide.0'],'launch-source-controller')
    need([v for v in devices if ',netdev=' in v]==['e1000e,netdev=net'],'launch-source-network')
    need(devices.count('virtio-serial-pci')==1 and devices.count('virtserialport,chardev=qga0,name=org.qemu.guest_agent.0')==1,'launch-source-qga')
    return {'kind':'ide-hd','bus':'ide.0','source':source,'nic':'e1000e','qga':'virtio-serial-pci',
            'recipeSha256':hashlib.sha256(raw).hexdigest()}


def validate_disk_controller(boot):
    value=boot.get('diskController')
    need(type(value) is dict and set(value)=={'kind','bus','source','nic','qga','recipeSha256'}
         and value['kind']=='ide-hd' and value['bus']=='ide.0'
         and value['source']=='/home/kardinal/vpn-control-windows-native-20260907/task.qcow2'
         and value['nic']=='e1000e' and value['qga']=='virtio-serial-pci'
         and type(value['recipeSha256']) is str and re.fullmatch('[0-9a-f]{64}',value['recipeSha256']), 'launch-disk-controller')
    return value


def held_source_disk_recipe(source_root, observed, run):
    """Source image and actual recipe FD pins close with all launch inputs."""
    expected=observed.get('sourceDiskRecipe')
    need(type(expected) is dict and set(expected)=={'generation','sha256','sourceGeneration'},'launch-source-recipe-pin')
    for key in ('generation','sourceGeneration'):
        pin=expected[key]
        need(type(pin) is list and len(pin)==9 and all(type(v) is int and v>=0 for v in pin)
             and stat.S_ISREG(pin[2]) and pin[5]==1,'launch-source-recipe-generation')
    need(type(expected['sha256']) is str and re.fullmatch('[0-9a-f]{64}',expected['sha256']),'launch-source-recipe-sha')
    root=source_root/'vpn-control-windows-native-20260907';recipe=root/'qemu-command.json';source=root/'task.qcow2'
    directories=inventory.parent_pins(recipe,source_root)
    inputs=set()
    for path,key in ((source,'sourceGeneration'),(recipe,'generation')):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);pin=expected[key]
        run['files'].append((path,fd,pin));inputs.add(path)
        need(inventory.generation(os.fstat(fd))==pin==inventory.generation(path.lstat()),'launch-source-recipe-current')
        if path==recipe:
            hashed=file_hash(fd,16384)
            need(hashed['generation']==pin and hashed['sha256']==expected['sha256'],'launch-source-recipe-current')
            os.lseek(fd,0,os.SEEK_SET);raw=os.read(fd,16385)
            descriptor=source_disk_controller(raw)
            need(descriptor==validate_disk_controller(observed['boot']) and descriptor['recipeSha256']==expected['sha256'],'launch-source-controller-binding')
    for parent,pin in directories:need(inventory.parent_identity(parent.lstat())==pin,'launch-source-recipe-parent')
    run['controllerParents']=directories;run['controllerInputs']=inputs
    return descriptor


def observed_process(proc, row, program_sha=None):
    pid=row['pid'];root=proc/str(pid)
    need(inventory.process_birth(proc,pid)==row['startTicks'],'repair-original-process')
    raw=(root/'cmdline').read_bytes();need(0<len(raw)<=131072,'repair-original-argv-bound')
    argv=[os.fsdecode(v) for v in raw.rstrip(b'\0').split(b'\0')]
    if program_sha is None:need(argv==row['argv'],'repair-original-argv')
    else:need(len(argv)==3 and argv[:2]==['/usr/bin/python3','-c'] and hashlib.sha256(os.fsencode(argv[2])).hexdigest()==program_sha,'repair-original-program')
    pin=row.get('binary');pin=pin['generation'] if type(pin) is dict else pin
    need(inventory.generation((root/'exe').stat())==pin,'repair-original-binary')
    raw_status=(root/'status').read_text();need(len(raw_status)<=65536,'repair-original-status-bound')
    uid=next(v.split()[1:3] for v in raw_status.splitlines() if v.startswith('Uid:'))
    need(all(int(v)==row['uid'] for v in uid) and inventory.process_birth(proc,pid)==row['startTicks'],'repair-original-closing')


def repair_phase(proc, proof, require_off=True):
    """Only this consumed original job's inert wait phase may retain FDs."""
    import base64
    need(type(proof) is dict and set(proof)=={'unknownBase64','supervisor'},'repair-original-proof')
    raw=base64.b64decode(proof['unknownBase64'],validate=True)
    need(hashlib.sha256(raw).hexdigest()=='cb7e4aece6b5d0ec4b0ea409677811172dc6616d3e40162963ede85ec1e57681','repair-original-phase')
    old=json.loads(raw);need(old['state']=='unknown' and old['nativeGuestStarted'] is True and old['originalPids']==[3474305,3474306],'repair-original-phase')
    parent=proof['supervisor'];need(parent['pid']==3474300 and parent['startTicks']==21163499 and parent['uid']==0
        and parent['programSha256']=='f3bcd78753ac455926a68e5629beb3fea83acacab6d3b2d077434efc28b49ac6','repair-original-supervisor')
    observed_process(proc,parent,parent['programSha256'])
    need(type(require_off) is bool,'repair-phase-mode')
    if require_off:need(not os.path.lexists(proc/'3474305'),'repair-secondary-not-terminal')
    else:observed_process(proc,old['identities'][0])
    tertiary=old['identities'][1];observed_process(proc,tertiary)
    tail=(proc/'3474306/stat').read_text().rsplit(')',1)[1].split()
    need(int(tail[1])==parent['pid'],'repair-original-parent')
    # Authenticated f3bcd prints this immutable UNKNOWN then executes only
    # child.poll/time.sleep until termination: no image write, exec or respawn.
    return {'parent':parent,'tertiary':tertiary}


def repair_census(proc, path, census, authority):
    need(census['complete'] and not census['argvUsers'],'repair-image-census')
    parent,tertiary=authority['parent'],authority['tertiary']
    for holder in census['holders']:
        pid=holder['pid'];fd=holder['fd'];root=proc/str(pid)
        info=(root/'fdinfo'/fd).read_text();flags=int(next(v.split()[1] for v in info.splitlines() if v.startswith('flags:')),8)&os.O_ACCMODE
        need(os.readlink(root/'fd'/fd)==str(path),'repair-image-holder-path')
        if pid==parent['pid']:
            observed_process(proc,parent,parent['programSha256'])
            expected=next((v for v in parent['imageFiles'] if v['fd']==fd and v['path']==str(path)),None)
            need(expected is not None and holder['startTicks']==parent['startTicks'] and flags==expected['accessMode']
                 and flags==(os.O_RDONLY if path.name=='template.qcow2' else os.O_RDWR)
                 and inventory.generation((root/'fd'/fd).stat())[:6]==expected['generation'][:6],'repair-inert-holder-role')
        else:
            need(pid==tertiary['pid'] and holder['startTicks']==tertiary['startTicks']
                 and path.name=='template.qcow2' and flags==os.O_RDONLY,'repair-foreign-image-holder')
            observed_process(proc,tertiary)


def fresh_secondary_repair(scope, prepared, observed, proof):
    template,guests,proc,*_=scope
    authority=repair_phase(proc,proof);need(len(guests)==1 and guests[0].slot=='secondary','repair-only-secondary')
    old=prepared['overlays'][0];guest=guests[0];overlay=guest.root/'disk.qcow2';vars_path=guest.root/'vm-state/vars.fd'
    need(str(overlay)==old['path'] and inventory.generation(overlay.lstat())[:6]==old['generation'][:6]
         and inventory.parent_identity(guest.root.lstat())==old['guestGeneration'],'repair-owned-overlay')
    expected=next((v for v in authority['parent']['imageFiles'] if v['path']==str(vars_path)),None)
    need(expected is not None and inventory.generation(vars_path.lstat())[:6]==expected['generation'][:6]
         and expected['generation'][3:6]==[scope[7],scope[8],1] and stat.S_IMODE(expected['generation'][2])==0o600,'repair-owned-vars')
    row=dict(old,generation=inventory.generation(overlay.lstat()))
    current=dict(prepared,overlays=[row]);binding=dict(observed,overlays=[row],repair={'proof':proof,'varsGeneration':inventory.generation(vars_path.lstat())})
    return current,binding


def fixed_argv(guest, boot, *, overlay_fd, template_fd, code_fd=None, vars_fd=None, repair_correlation=None):
    """Fixed recipe only; actual launch admission/handles remain separate.

    Primary/backing drives refer to held inherited descriptors. Firmware is
    selected only by validated virtual boot facts; fresh private vars required.
    A new TPM is not guessed from GPT, and no original TPM is borrowed.
    """
    need(guest == fixed_guest(guest.slot) and boot.get('bootMode') in ('bios', 'uefi'), 'launch-recipe')
    controller=validate_disk_controller(boot)
    need(all(type(v) is int and v >= 3 for v in (overlay_fd, template_fd)), 'launch-image-fds')
    need(repair_correlation is None or (guest.slot=='secondary' and str(uuid.UUID(repair_correlation))==repair_correlation),'repair-recipe-scope')
    root = guest.root / ('vm-state' if repair_correlation is None else 'vm-r-'+repair_correlation[:8])
    need(all(len(os.fsencode(root / name)) <= 107 for name in ('qmp.sock', 'qga.sock')), 'launch-socket-length')
    blocks = [
        {'driver': 'file', 'filename': '/proc/self/fd/' + str(template_fd), 'node-name': 'template-file', 'read-only': True, 'locking': 'on'},
        {'driver': 'qcow2', 'file': 'template-file', 'node-name': 'template', 'read-only': True},
        {'driver': 'file', 'filename': '/proc/self/fd/' + str(overlay_fd), 'node-name': 'overlay-file', 'locking': 'on'},
        {'driver': 'qcow2', 'file': 'overlay-file', 'backing': 'template', 'node-name': 'owned-disk'},
    ]
    argv = ['/usr/bin/qemu-system-x86_64', '-machine', 'q35,accel=kvm', '-cpu', 'host', '-smp', '2',
            '-m', '4096', '-name', 'vpn-control-windows-parallel-' + guest.slot]
    for block in blocks:
        argv += ['-blockdev', json.dumps(block, sort_keys=True, separators=(',', ':'))]
    argv += ['-device', 'ide-hd,drive=owned-disk,bus=ide.0,bootindex=0',
             '-device', 'virtio-serial-pci', '-chardev', 'socket,path=' + str(root / 'qga.sock') + ',server=on,wait=off,id=owned-qga',
             '-device', 'virtserialport,chardev=owned-qga,name=org.qemu.guest_agent.0',
             '-netdev', 'user,id=owned-net,hostfwd=tcp:127.0.0.1:' + str(guest.ssh_port) + '-:22',
             '-device', 'e1000e,netdev=owned-net,mac=' + guest.mac,
             '-display', 'none', '-vnc', '127.0.0.1:' + str(guest.vnc_port - 5900),
             '-qmp', 'unix:' + str(root / 'qmp.sock') + ',server=on,wait=off', '-rtc', 'base=localtime']
    if boot['bootMode'] == 'uefi':
        need(all(type(v) is int and v >= 3 for v in (code_fd, vars_fd)), 'launch-firmware-fds')
        argv += ['-drive', 'if=pflash,format=raw,readonly=on,file=/proc/self/fd/' + str(code_fd),
                 '-drive', 'if=pflash,format=raw,file=/proc/self/fd/' + str(vars_fd)]
    else:
        need(code_fd is None and vars_fd is None, 'launch-bios-firmware')
    return argv


class PairUnknown(ValueError):
    """Original submitted processes remain reachable; no cleanup or replay."""
    def __init__(self, reason, run):
        super().__init__(reason)
        self.run = run


def launch_resources(proc, filesystem):
    raw = (proc / 'meminfo').read_bytes()
    need(len(raw) <= 65536, 'launch-memory-bound')
    available = re.search(rb'^MemAvailable:\s+(\d+) kB$', raw, re.M)
    need(available is not None, 'launch-memory-unavailable')
    memory = int(available[1]) * 1024
    pressure = (proc / 'pressure' / 'memory').read_bytes()
    need(len(pressure) <= 4096 and len(re.findall(rb'avg10=0\.00(?: |$)', pressure)) == 2,
         'launch-memory-pressure')
    space = os.statvfs(filesystem)
    free = space.f_bavail * space.f_frsize
    need(memory >= 2 * MEMORY_BYTES + HEADROOM_BYTES and free >= 8 * 1024 ** 3,
         'launch-resource-headroom')
    return {'availableMemoryBytes': memory, 'diskFreeBytes': free}


def native_identity(proc, child, argv, binary_pin, uid):
    ticks = inventory.process_birth(proc, child.pid)
    need(type(ticks) is int and ticks > 0 and child.poll() is None, 'launch-process-birth')
    directory = proc / str(child.pid)
    actual = (directory / 'cmdline').read_bytes()
    need(len(actual) <= 131072 and actual.split(b'\0')[:-1] == [os.fsencode(v) for v in argv],
         'launch-process-argv')
    executable = inventory.generation((directory / 'exe').stat())
    need(executable == binary_pin['generation'], 'launch-process-executable')
    status = (directory / 'status').read_bytes()
    need(len(status) <= 65536 and re.search(rb'^Uid:\s+' + str(uid).encode() + rb'\s+' + str(uid).encode() + rb'\s', status, re.M),
         'launch-process-principal')
    need(inventory.process_birth(proc, child.pid) == ticks, 'launch-process-closing-birth')
    return {'pid': child.pid, 'startTicks': ticks, 'uid': uid, 'binary': binary_pin, 'argv': argv}


def launch_pair(scope, prepared, observed, correlation):
    """Internal fixed pair producer. Tests project OS/Popen boundaries only.

    All ordinary guards precede submission. Every post-submission failure retains
    the same original Popen objects, held raw FDs and immutable UNKNOWN journal.
    This starts infrastructure only and never claims Windows/product acceptance.
    """
    template, guests, proc, binary, code, seed, source_root, uid, gid, kvm_gid, trusted_uid = scope
    need(str(uuid.UUID(correlation)) == correlation and tuple(g.slot for g in guests) in (('secondary','tertiary'),('secondary',)), 'launch-correlation')
    repair=observed.get('repair')
    need((repair is None and len(guests)==2) or (type(repair) is dict and set(repair)=={'proof','varsGeneration'} and len(guests)==1),'repair-only-secondary')
    need(observed['state'] == 'boot-observed' and observed['boot']['bootMode'] == 'uefi'
         and observed['templateGeneration'] == prepared['templateGeneration']
         and observed['overlays'] == prepared['overlays'], 'launch-boot-binding')
    need(correlation not in LIVE_LAUNCHES,'launch-original-run-exists')
    parents = inventory.parent_pins(template, source_root)
    run = {'correlationId': correlation, 'handles': [], 'files': [], 'directories': [],
           'identities': [], 'rootFd': None, 'nativeGuestStarted': False}
    LIVE_LAUNCHES[correlation] = run
    try:
        authority=repair_phase(proc,repair['proof']) if repair is not None else None
        run['repairAuthority']=authority
        run['repairProof']=repair['proof'] if repair is not None else None
        image_pins = [(template, prepared['templateGeneration'])] + [
            (guest.root / 'disk.qcow2', row['generation']) for guest, row in zip(guests, prepared['overlays'])]
        for path, pin in image_pins:
            fd = os.open(path, (os.O_RDONLY if path == template else os.O_RDWR) | os.O_NOFOLLOW | os.O_NONBLOCK)
            run['files'].append((path, fd, pin))
            need(inventory.generation(os.fstat(fd)) == pin == inventory.generation(path.lstat()), 'launch-image-generation')
            census = inventory.holder_census(proc, tuple(pin[:2]), (os.getpid(), str(fd)), time.monotonic()+30, str(path))
            if authority is not None:repair_census(proc,path,census,authority)
            else:need(census['complete'] and not census['holders'] and not census['argvUsers'], 'launch-image-holder')
        need(not inventory.tcp_conflicts(proc,tuple(v for g in guests for v in (g.ssh_port,g.vnc_port)))
             and not set(census['macs']) & {g.mac for g in guests}, 'launch-port-or-mac')
        controller=held_source_disk_recipe(source_root,observed,run)
        parents += run['controllerParents']
        resources = launch_resources(proc, source_root)
        binaries = []
        for path, cap in ((binary, 134217728), (code, 16777216), (seed, 16777216)):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            pin = file_hash(fd, cap)
            run['files'].append((path, fd, pin['generation']));binaries.append((fd, pin))
            need(pin['generation'][3] == trusted_uid and not pin['generation'][2] & 0o022
                 and os.path.realpath(path) == str(path)
                 and inventory.generation(path.lstat()) == pin['generation'], 'launch-binary-trust')
        need(os.access(binary,os.X_OK), 'launch-binary-not-executable')
        for path, (_, pin) in zip((code, seed), binaries[1:]):
            candidate = next(v for v in observed['firmwareCandidates'] if v['path'] == str(path))
            need(candidate['available'] is True and candidate['generation'] == pin['generation']
                 and candidate['sha256'] == pin['sha256'], 'launch-firmware-generation')
        root = template.parent / ('launch-' + correlation)
        root.mkdir(mode=0o700)
        run['root'] = root
        run['rootFd'] = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        root_pin = inventory.parent_identity(os.fstat(run['rootFd']))
        run.update(proc=proc,uid=uid,guests=guests,prepared=prepared,parents=parents,rootPin=root_pin,immutable={template,binary,code,seed}|run['controllerInputs'])
        prepare.record_at(run['rootFd'], 'intent.json', {'correlationId': correlation,
            'templateGeneration': prepared['templateGeneration'], 'templateSha256': prepared['templateSha256'],
            'overlays': prepared['overlays'], 'resources': resources,
            'sourceDiskRecipe':observed['sourceDiskRecipe'],'diskController':controller,
            'binary': binaries[0][1], 'firmware': [v[1] for v in binaries[1:]],
            'nativeGuestStarted': False, 'productAcceptance': False})
        for guest, row in zip(guests, prepared['overlays']):
            need(inventory.parent_identity(guest.root.lstat()) == row['guestGeneration'], 'launch-guest-generation')
            state_name='vm-state' if repair is None else 'vm-r-'+correlation[:8]
            run.setdefault('stateNames',{})[guest.slot]=state_name
            state = guest.root / state_name
            state.mkdir(mode=0o700)
            os.chown(state, uid, gid)
            directory = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            state_pin = inventory.parent_identity(os.fstat(directory));run['directories'].append((state, directory, state_pin))
            if repair is not None:
                vars_path=guest.root/'vm-state/vars.fd';var_fd=os.open(vars_path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK)
                var_pin=file_hash(var_fd,16777216)
                need(var_pin['generation']==repair['varsGeneration']==inventory.generation(vars_path.lstat()),'repair-vars-current')
                run['files'].append((vars_path,var_fd,var_pin['generation']))
                original_vars=next(v for v in authority['parent']['imageFiles'] if v['path']==str(vars_path))
                prepare.record_at(run['rootFd'],'secondary-vars-transition.json',{'sameOwnedIdentity':var_pin['generation'][:6],
                    'beforeShutdownGeneration':original_vars['generation'],'afterTerminal':var_pin,'copiedOrRewound':False})
            else:
                var_fd = os.open('vars.fd', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                os.fchown(var_fd, uid, gid)
                os.lseek(binaries[2][0], 0, os.SEEK_SET)
                data = os.read(binaries[2][0], 16777217)
                need(len(data) == binaries[2][1]['generation'][6], 'launch-vars-seed')
                offset = 0
                while offset < len(data):offset += os.write(var_fd, data[offset:])
                os.fsync(var_fd)
                var_pin = file_hash(var_fd, 16777216)
                need(var_pin['sha256'] == binaries[2][1]['sha256'], 'launch-vars-copy')
                run['files'].append((state/'vars.fd', var_fd, var_pin['generation']))
            log_fd = os.open(guest.slot + '-qemu.private', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=run['rootFd'])
            run.setdefault('logs', []).append((guest.slot, log_fd, inventory.generation(os.fstat(log_fd))))
            argv = fixed_argv(guest, observed['boot'], overlay_fd=run['files'][1 + len(run['handles'])][1],
                              template_fd=run['files'][0][1], code_fd=binaries[1][0], vars_fd=var_fd,repair_correlation=correlation if repair is not None else None)
            argv[0] = binary_alias(binaries[0][0])
            # Earlier guest overlays may now legitimately change. All common
            # immutable inputs plus this still-stopped selected overlay close.
            selected = {template, binary, code, seed, guest.root/'disk.qcow2', (guest.root/'vm-state/vars.fd' if repair is not None else state/'vars.fd')} | run['controllerInputs']
            for path, fd, pin in run['files']:
                if path in selected:
                    need(inventory.generation(os.fstat(fd)) == pin == inventory.generation(path.lstat()), 'launch-preexec-generation')
            for parent, pin in parents:need(inventory.parent_identity(parent.lstat()) == pin, 'launch-preexec-parent')
            for path, fd, pin in run['directories']:
                need(inventory.parent_identity(os.fstat(fd)) == pin == inventory.parent_identity(path.lstat()), 'launch-preexec-directory')
            need(root_pin == inventory.parent_identity(os.fstat(run['rootFd'])) == inventory.parent_identity(root.lstat()), 'launch-preexec-root')
            need(not inventory.tcp_conflicts(proc,(guest.ssh_port,guest.vnc_port)), 'launch-preexec-port')
            if repair is not None:repair_phase(proc,repair['proof'])
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log_fd, stderr=log_fd,
                 pass_fds=tuple({binaries[0][0], binaries[1][0], var_fd, run['files'][0][1], run['files'][1+len(run['handles'])][1]}),
                 start_new_session=True, user=uid, group=gid, extra_groups=[kvm_gid],
                 env={'PATH':'/usr/bin:/bin', 'LC_ALL':'C'})
            run['handles'].append(child)
            run['nativeGuestStarted'] = True
            identity = native_identity(proc, child, argv, binaries[0][1], uid)
            run['identities'].append(identity)
            prepare.record_at(run['rootFd'], guest.slot + '-started.json', identity)
        close_pair(run)
        value = {'state':'pair-started', 'correlationId':correlation, 'guests':run['identities'],
                 'journal':str(root), 'nativeGuestStarted':True, 'guestAccessVerified':False,
                 'installedProductVerified':False, 'productAcceptance':False, 'replayAllowed':False}
        prepare.record_at(run['rootFd'], 'result.json', value)
        return value, run
    except BaseException as error:
        if run['rootFd'] is not None:
            try:
                prepare.record_at(run['rootFd'], 'unknown.json', {'state':'unknown', 'correlationId':correlation,
                    'reason':str(error) if isinstance(error,ValueError) and re.fullmatch('[a-z-]{1,80}',str(error)) else type(error).__name__,
                    'originalPids':[child.pid for child in run['handles']], 'identities':run['identities'],
                    'nativeGuestStarted':bool(run['handles']), 'replayAllowed':False, 'productAcceptance':False})
            except BaseException:pass
        raise PairUnknown('launch-pair-unknown', run) from error


def close_pair(run):
    need(LIVE_LAUNCHES.get(run['correlationId']) is run, 'launch-original-run')
    if run.get('repairAuthority') is not None:repair_phase(run['proc'],run['repairProof'])
    # Finish all process-body observations before final pure group closing.
    for child, identity in zip(run['handles'],run['identities']):
        need(native_identity(run['proc'],child,identity['argv'],identity['binary'],run['uid'])==identity, 'launch-closing-process')
    immutable = run['immutable']
    for path, fd, pin in run['files']:
        held,named = inventory.generation(os.fstat(fd)),inventory.generation(path.lstat())
        need((held == pin == named) if path in immutable else (held[:6] == pin[:6] == named[:6]),
         'launch-closing-file')
    for slot, fd, pin in run['logs']:
        need(inventory.generation(os.fstat(fd))[:6] == pin[:6]
         == inventory.generation((run['root']/(slot+'-qemu.private')).lstat())[:6], 'launch-closing-log')
    for guest,row in zip(run['guests'],run['prepared']['overlays']):
        need(inventory.parent_identity(guest.root.lstat())==row['guestGeneration'], 'launch-closing-guest')
    for path,fd,pin in run['directories']:
        need(inventory.parent_identity(os.fstat(fd))==pin==inventory.parent_identity(path.lstat()), 'launch-closing-directory')
    for parent,pin in run['parents']:need(inventory.parent_identity(parent.lstat())==pin, 'launch-closing-parent')
    need(run['rootPin']==inventory.parent_identity(os.fstat(run['rootFd']))==inventory.parent_identity(run['root'].lstat()), 'launch-closing-root')


CONTEXT_SCRIPT = r'''$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$name=(Get-CimInstance Win32_ComputerSystem).UserName;$sid=$null;if($name){$sid=(New-Object System.Security.Principal.NTAccount($name)).Translate([System.Security.Principal.SecurityIdentifier]).Value};$sessions=@(Get-Process -Name explorer -ErrorAction SilentlyContinue|Select-Object -ExpandProperty SessionId -Unique);[ordered]@{interactiveUser=$name;interactiveSid=$sid;sessionIds=$sessions;architecture=$env:PROCESSOR_ARCHITECTURE;windowsVersion=[Environment]::OSVersion.Version.ToString()}|ConvertTo-Json -Compress'''


class AccessClient(qga.QgaReadOnlyClient):
    def bind(self, run, guest, identity):
        self.run, self.guest, self.identity = run, guest, identity
        self.frames = 0
        return self

    def _synchronize(self, connection, deadline):
        peer = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        need(peer[0] == self.identity['pid'] and peer[1] == self.identity['uid'], 'access-qga-peer')
        return super()._synchronize(connection, deadline)

    def _read_response(self, connection, deadline):
        # Retain bytes at the socket boundary while the existing SDK keeps
        # its framing, deadline and response cap. It can raise before returning
        # a frame; that prefix is still evidence, never a complete response.
        received=bytearray()
        class CapturingSocket:
            def __getattr__(self, name):return getattr(connection,name)
            def recv(self, size):
                chunk=connection.recv(size)
                received.extend(chunk[:max(0,self_limit+1-len(received))])
                return chunk
        self_limit=self.max_response_bytes
        complete=False;reason='unknown';raw=None
        try:
            raw=super()._read_response(CapturingSocket(),deadline)
            complete=True;reason='complete'
        except EOFError:
            reason='eof';raise
        except TimeoutError:
            reason='deadline';raise
        except qga.QgaProtocolError:
            reason='overflow';raise
        finally:
            self._retain_response(bytes(received),complete,reason)
        return raw

    def _read_qmp_response(self, connection, deadline):
        # QMP can coalesce an event and its reply in one recv. Restrict this
        # protocol to one byte reads so the existing SDK stops at its newline
        # without consuming the next frame. Prefix/cap/deadline journals stay
        # with the same original socket and collector.
        class SingleFrameSocket:
            def __getattr__(self, name):return getattr(connection,name)
            def recv(self, size):return connection.recv(min(size,1))
        return self._read_response(SingleFrameSocket(),deadline)

    def _retain_response(self, raw, complete, reason):
        self.frames += 1
        name = 'qga-' + self.guest.slot + '-' + str(self.frames) + '.private'
        fd = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.run['rootFd'])
        try:
            offset = 0
            while offset < len(raw):offset += os.write(fd,raw[offset:])
            os.fsync(fd)
        finally:os.close(fd)
        metadata=json.dumps({
            'complete':complete,'reason':reason,'retainedBytes':len(raw),
            'responseLimit':self.max_response_bytes,'replayAllowed':False},sort_keys=True).encode()
        fd=os.open(name[:-8]+'.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.run['rootFd'])
        try:
            offset=0
            while offset<len(metadata):offset+=os.write(fd,metadata[offset:])
            os.fsync(fd)
        finally:os.close(fd)


def guest_access(run, guests, proc, deadline_seconds=180):
    """Only original pair and fixed read-only Windows context process.

    Guest-exec is issued once per guest; only that returned original PID is
    subsequently observed. No installers, owner actions or guest credentials.
    """
    import base64
    need(LIVE_LAUNCHES.get(run['correlationId']) is run and len(guests)==len(run['handles'])==len(run['identities'])
         and (len(guests)==2 or (len(guests)==1 and guests[0].slot=='secondary' and run.get('repairAuthority') is not None)), 'access-original-pair')
    observations = []
    for guest, child, identity in zip(guests,run['handles'],run['identities']):
        deadline = time.monotonic()+deadline_seconds
        client = AccessClient(str(guest.root/run.get('stateNames',{}).get(guest.slot,'vm-state')/'qga.sock'),timeout_seconds=3).bind(run,guest,identity)
        while True:
            native_identity(proc,child,identity['argv'],identity['binary'],identity['uid'])
            need(time.monotonic()<deadline,'access-qga-deadline')
            try:
                client._exchange('guest-ping',{})
                break
            except qga.QgaObservationError:
                # New read-only observation; never another VM/exec submission.
                time.sleep(.5)
        osinfo = client._exchange('guest-get-osinfo',{})
        need(type(osinfo) is dict and osinfo.get('id')=='mswindows' and osinfo.get('machine')=='x86_64',
             'access-windows-identity')
        created = client._exchange('guest-exec',{'path':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'arg':['-NoLogo','-NoProfile','-NonInteractive','-Command',CONTEXT_SCRIPT],'capture-output':True})
        need(type(created) is dict and type(created.get('pid')) is int and created['pid']>0,'access-context-pid')
        prepare.record_at(run['rootFd'],guest.slot+'-context-started.json',created)
        while True:
            need(time.monotonic()<deadline,'access-context-deadline')
            result = client.guest_exec_status(created['pid'])
            if result.get('exited') is True:break
            time.sleep(.25)
        need(type(result.get('exitcode')) is int and result['exitcode']==0 and result.get('out-truncated') is not True,'access-context-exit')
        raw = base64.b64decode(result['out-data'],validate=True)
        need(len(raw)<=65536,'access-context-bound')
        context = json.loads(raw.decode('utf-8-sig'))
        need(type(context) is dict and type(context.get('interactiveUser')) is str
             and 0<len(context['interactiveUser'])<=256 and type(context.get('interactiveSid')) is str
             and re.fullmatch(r'S-1-5-21-\d+-\d+-\d+-\d+',context['interactiveSid'])
             and type(context.get('sessionIds')) is list and 1<=len(context['sessionIds'])<=16
             and all(type(v) is int and v>0 for v in context['sessionIds'])
             and context.get('architecture')=='AMD64','access-interactive-context')
        banner = b''
        try:
            with socket.create_connection(('127.0.0.1',guest.ssh_port),timeout=3) as connection:
                banner=connection.recv(256)
        except OSError:pass
        native_identity(proc,child,identity['argv'],identity['binary'],identity['uid'])
        observation={'slot':guest.slot,'qemu':identity,'osinfo':osinfo,'contextPid':created['pid'],
                     'context':context,'sshBanner':banner.decode('ascii',errors='replace'),
                     'sshAuthenticated':False,'qgaAccessVerified':True,'productAcceptance':False}
        prepare.record_at(run['rootFd'],guest.slot+'-access.json',observation)
        observations.append(observation)
    close_pair(run)
    value={'state':'access-ready','correlationId':run['correlationId'],'guests':observations,
           'journal':str(run['root']),'nativeGuestStarted':True,'guestAccessVerified':True,
           'installedProductVerified':False,'productAcceptance':False,'replayAllowed':False}
    prepare.record_at(run['rootFd'],'access-result.json',value)
    return value


def launch_program(prepared, observed, correlation):
    """Fixed two guest producer and existing QGA access; no path selectors."""
    prepared_binding(prepared)
    need(observed.get('state')=='boot-observed' and observed.get('nativeGuestStarted') is False
         and observed.get('productAcceptance') is False and observed.get('boot',{}).get('bootMode')=='uefi',
         'launch-observed-source')
    need(str(uuid.UUID(correlation))==correlation,'launch-correlation')
    header='from __future__ import annotations\nimport os,stat,subprocess,time,json,hashlib,re,selectors,uuid,struct,binascii,socket,inspect,grp,pwd\nfrom pathlib import Path\nfrom dataclasses import dataclass\nfrom types import SimpleNamespace\n'
    header+='FIELDS='+repr(inventory.FIELDS)+'\nMEMORY_BYTES='+repr(MEMORY_BYTES)+'\nHEADROOM_BYTES='+repr(HEADROOM_BYTES)+'\nLIVE_LAUNCHES={}\n'
    for fn in (need,inventory.generation,inventory.parent_identity,inventory.parent_pins,inventory.process_birth,
               inventory.holder_census,inventory.tcp_conflicts):header+=inspect.getsource(fn)+'\n'
    header+='inventory=SimpleNamespace(generation=generation,parent_identity=parent_identity,parent_pins=parent_pins,process_birth=process_birth,holder_census=holder_census,tcp_conflicts=tcp_conflicts,PORTS='+repr(inventory.PORTS)+',MACS='+repr(inventory.MACS)+',DESTINATIONS='+repr(inventory.DESTINATIONS)+')\n'
    header+=inspect.getsource(prepare.record_at)+'\nprepare=SimpleNamespace(record_at=record_at)\n'
    for fn in (Guest,fixed_guest,fd_alias,binary_alias,file_hash,source_disk_controller,validate_disk_controller,held_source_disk_recipe,observed_process,repair_phase,repair_census,fresh_secondary_repair,fixed_argv,PairUnknown,launch_resources,native_identity,close_pair,launch_pair):
        header+=inspect.getsource(fn)+'\n'
    module=inspect.getsource(qga).replace('from __future__ import annotations\n','')
    header+=module+'\nqga=SimpleNamespace(QgaReadOnlyClient=QgaReadOnlyClient,QgaObservationError=QgaObservationError,QgaProtocolError=QgaProtocolError)\n'
    header+='CONTEXT_SCRIPT='+repr(CONTEXT_SCRIPT)+'\n'+inspect.getsource(AccessClient)+'\n'+inspect.getsource(guest_access)+'\n'
    scope="(Path("+repr(prepared['template'])+"),tuple(fixed_guest(s) for s in ('secondary','tertiary')),Path('/proc'),Path('/usr/bin/qemu-system-x86_64'),Path("+repr(str(UEFI_CODE))+"),Path("+repr(str(UEFI_VARS))+"),Path('/home/kardinal'),1000,1000,kvm_gid,0)"
    header+='''
run=None
try:
 need(os.geteuid()==0,'launch-privilege')
 account=pwd.getpwnam('kardinal')
 need(account.pw_uid==1000 and account.pw_gid==1000,'launch-account')
 kvm=Path('/dev/kvm').lstat()
 kvm_gid=grp.getgrnam('kvm').gr_gid
 need(stat.S_ISCHR(kvm.st_mode) and kvm.st_uid==0 and kvm_gid==kvm.st_gid and kvm_gid>0,'launch-kvm')
'''
    header+=' started,run=launch_pair('+scope+','+repr(prepared)+','+repr(observed)+','+repr(correlation)+')\n value=guest_access(run,tuple(fixed_guest(s) for s in ("secondary","tertiary")),Path("/proc"))\n'
    header+='''except BaseException as error:
 if isinstance(error,PairUnknown):run=error.run
 value={'state':'unknown','reason':'pair-launch-or-access','nativeGuestStarted':bool(run and run['handles']),'productAcceptance':False,'replayAllowed':False,'originalPids':[child.pid for child in run['handles']] if run else [],'identities':run['identities'] if run else []}
print(json.dumps(value,sort_keys=True),flush=True)
# UNKNOWN with live originals keeps its parent/Popen/FDs reachable. The caller
# follows this same SSH process; never launch another pair to resolve UNKNOWN.
if value['state']=='unknown' and run:
 while any(child.poll() is None for child in run['handles']):time.sleep(1)
'''
    compile(header,'fixed two owned guest launch/access','exec')
    return header


def secondary_repair_program(prepared, observed, proof, correlation):
    """Single new boot only after positive terminal proof of original secondary."""
    prepared,observed,proof=json.loads(json.dumps([prepared,observed,proof],sort_keys=True))
    prepared_binding(prepared);validate_disk_controller(observed['boot'])
    need(type(proof) is dict and set(proof)=={'unknownBase64','supervisor'},'repair-original-proof')
    source=launch_program(prepared,observed,correlation)
    header=source.split('\nrun=None\n',1)[0]
    scope="(Path("+repr(prepared['template'])+"),(fixed_guest('secondary'),),Path('/proc'),Path('/usr/bin/qemu-system-x86_64'),Path("+repr(str(UEFI_CODE))+"),Path("+repr(str(UEFI_VARS))+"),Path('/home/kardinal'),1000,1000,kvm_gid,0)"
    prefix=source.split('\nrun=None\n',1)[1].split(' started,run=launch_pair',1)[0]
    effect=' current,binding=fresh_secondary_repair('+scope+','+repr(prepared)+','+repr(observed)+','+repr(proof)+')\n started,run=launch_pair('+scope+',current,binding,'+repr(correlation)+')\n value=guest_access(run,(fixed_guest("secondary"),),Path("/proc"))\n'
    suffix=source.split('\nrun=None\n',1)[1].split('except BaseException as error:',1)[1]
    program=header+'\nrun=None\n'+prefix+effect+'except BaseException as error:'+suffix.replace('pair-launch-or-access','secondary-repair-or-access')
    compile(program,'fixed original secondary storage repair','exec')
    return program


def ordinary_secondary_shutdown_program(prepared, observed, proof, correlation):
    """One ACPI guest shutdown of the exact original secondary; no signal."""
    prepared,observed,proof=json.loads(json.dumps([prepared,observed,proof],sort_keys=True))
    source=secondary_repair_program(prepared,observed,proof,correlation)
    header=source.split('\nrun=None\n',1)[0]
    body="""
value={'state':'unknown','reason':'secondary-ordinary-shutdown','newGuestStarted':False,'productAcceptance':False,'replayAllowed':False}
fd=None
try:
 need(os.geteuid()==0,'shutdown-privilege')
 original=repair_phase(Path('/proc'),PROOF,require_off=False)
 guest=fixed_guest('secondary');old=json.loads(__import__('base64').b64decode(PROOF['unknownBase64']))['identities'][0]
 template=Path(PREPARED['template']);need(generation(template.lstat())==PREPARED['templateGeneration'],'shutdown-template')
 need(parent_identity(guest.root.lstat())==PREPARED['overlays'][0]['guestGeneration'],'shutdown-owned-guest')
 resources=launch_resources(Path('/proc'),Path('/home/kardinal'))
 root=template.parent/('shutdown-'+CORRELATION);root.mkdir(mode=0o700)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);root_pin=parent_identity(os.fstat(fd))
 prepare.record_at(fd,'intent.json',{'correlationId':CORRELATION,'originalSecondary':old,'responseProtocol':'qmp','resources':resources,'replayAllowed':False})
 framer=AccessClient('/fixed-qmp',max_response_bytes=4096).bind({'rootFd':fd},guest,old)
 sock=guest.root/'vm-state/qmp.sock';need(stat.S_ISSOCK(sock.lstat().st_mode) and sock.lstat().st_uid==1000,'shutdown-qmp-socket')
 with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
  connection.settimeout(3);connection.connect(str(sock));peer=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
  need(peer[:2]==(3474305,1000),'shutdown-qmp-peer')
  def receive():return json.loads(framer._read_qmp_response(connection,time.monotonic()+3))
  need('QMP' in receive(),'shutdown-qmp-greeting')
  def command(name,arguments=None):
   request={'execute':name,'id':CORRELATION+'-'+name}
   if arguments is not None:request['arguments']=arguments
   connection.sendall(json.dumps(request).encode()+b'\\n')
   for _ in range(16):
    answer=receive()
    if answer.get('id')==request['id']:
     need('return' in answer,'shutdown-qmp-refusal');return answer
   raise ValueError('shutdown-qmp-response')
  command('qmp_capabilities');status=command('query-status');need(status['return']['status']=='running','shutdown-qmp-state')
  screen=guest.root/'vm-state'/('shutdown-'+CORRELATION[:8]+'.png');need(not os.path.lexists(screen),'shutdown-screen-exists')
  command('screendump',{'filename':str(screen),'format':'png'})
  screen_fd=os.open(screen,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   snapshot=file_hash(screen_fd,1048576);need(snapshot['generation']==generation(screen.lstat())
    and snapshot['generation'][3:6]==[1000,1000,1]
    and snapshot['sha256']=='ce0ef484e2beb44167c41e4db453db7ea464ee95e88d2aa8a6f26286f4271a71','shutdown-current-recovery-screen')
  finally:os.close(screen_fd)
  repair_phase(Path('/proc'),PROOF,require_off=False)
  prepare.record_at(fd,'submission.json',{'effect':'system_powerdown','originalPid':3474305,'startTicks':21163511,'screen':snapshot,'replayAllowed':False})
  answer=command('system_powerdown');prepare.record_at(fd,'acknowledged.json',answer)
 deadline=time.monotonic()+90
 while os.path.lexists(Path('/proc/3474305')):
  need(process_birth(Path('/proc'),3474305)==21163511,'shutdown-original-generation')
  need(time.monotonic()<deadline,'shutdown-terminal-deadline');time.sleep(.2)
 repair_phase(Path('/proc'),PROOF)
 need(root_pin==parent_identity(os.fstat(fd))==parent_identity(root.lstat()) and generation(template.lstat())==PREPARED['templateGeneration'],'shutdown-closing')
 value={'state':'shutdown-observed','correlationId':CORRELATION,'originalSecondaryPid':3474305,'originalSecondaryStartTicks':21163511,'originalSecondaryTerminal':True,'journal':str(root),'newGuestStarted':False,'productAcceptance':False,'replayAllowed':False}
 prepare.record_at(fd,'result.json',value)
except BaseException as error:
 value['errorType']=type(error).__name__
 if isinstance(error,ValueError) and re.fullmatch('[a-z-]{1,80}',str(error)):value['reason']=str(error)
 if fd is not None:
  try:prepare.record_at(fd,'unknown.json',value)
  except BaseException:pass
print(json.dumps(value,sort_keys=True),flush=True)
"""
    body='PROOF='+repr(proof)+'\nPREPARED='+repr(prepared)+'\nCORRELATION='+repr(correlation)+'\n'+body
    program=header+'\n'+body
    compile(program,'exact original secondary ordinary shutdown','exec')
    return program
