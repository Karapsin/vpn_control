"""Reviewed immutable Android installer tooling, separate from product provenance.

This is a fixed seven-file fixture snapshot. It does not build, install, admit an
APK, or claim that these tooling bytes came from the product source commit.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import uuid4

FILES = (
    'agent_tools/android_installer_target.py',
    'scripts/android_installer_lifecycle.py',
    'scripts/android_no_update_tls_preflight.py',
    'scripts/android_fixture_preflight.py',
    'scripts/android_fixture_transport.py',
    'scripts/android_fixture_trust.py',
    'scripts/integration/android_update_fixture.py',
)
LIMIT = 8_388_608
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_ID = re.compile(r'sha256-[0-9a-f]{64}\Z')


def _bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'))+'\n').encode()


def _fp(info):
    return [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, stat.S_IMODE(info.st_mode), info.st_uid, info.st_nlink]


def _read(path, *, private=True, limit=LIMIT):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or
            before.st_size > limit or (private and
            (before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) != 0o600))):
        raise ValueError('Installer tool file unsafe')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        opened = os.fstat(fd)
        if _fp(opened) != _fp(before):
            raise ValueError('Installer tool file changed')
        data = bytearray()
        while chunk := os.read(fd, min(65536, limit+1-len(data))):
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError('Installer tool file exceeds bound')
        if _fp(os.fstat(fd)) != _fp(before) or _fp(path.lstat()) != _fp(before):
            raise ValueError('Installer tool file changed')
    finally:
        os.close(fd)
    return bytes(data), {'sha256': hashlib.sha256(data).hexdigest(), 'fingerprint': _fp(before)}


def _dir(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Installer tool directory unsafe')
    return _fp(info)


def _source(root, name):
    current = root
    root_info = root.lstat()
    parents = {}
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('Installer tool source root unsafe')
    for part in Path(name).parts[:-1]:
        current /= part
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError('Installer tool source ancestry unsafe')
        parents[str(current)] = _fp(current.lstat())
    raw, pin = _read(root/name, private=False)
    if (root.lstat().st_dev,root.lstat().st_ino,root.lstat().st_mode)!=(root_info.st_dev,root_info.st_ino,root_info.st_mode) or parents != {path: _fp(Path(path).lstat()) for path in parents}:
        raise ValueError('Installer tool source ancestry changed')
    return raw, {**pin, 'parents': parents}


def _tree(files):
    return {'schema': 1, 'kind': 'android-installer-reviewed-tools',
            'files': [{'path': name, 'size': len(files[name][0]),
                       'sha256': files[name][1]['sha256']} for name in FILES]}


def reviewed_tree(root):
    """Read-only digest for explicit review; preparation requires this digest."""
    root = Path(root).absolute()
    files = {name: _source(root, name) for name in FILES}
    tree = _tree(files)
    return {'treeSha256': hashlib.sha256(_bytes(tree)).hexdigest(), 'manifest': tree}


def _registry(root):
    current = root
    for part in ('.rag_index', 'android-installer-tool-bundles'):
        current /= part
        if not os.path.lexists(current):
            current.mkdir(mode=0o700)
        _dir(current)
    return current


def _write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as output:
            output.write(raw); output.flush(); os.fsync(fd)
    finally:
        os.close(fd)


def _inventory(folder):
    result = set()
    directories = set()
    def walk(path, prefix=''):
        _dir(path)
        for entry in path.iterdir():
            name = prefix+entry.name
            info = entry.lstat()
            if stat.S_ISDIR(info.st_mode):
                directories.add(name)
                walk(entry, name+'/')
            elif stat.S_ISREG(info.st_mode):
                result.add(name)
            else:
                raise ValueError('Installer tool inventory unsafe')
    walk(folder)
    if result != {*FILES, 'manifest.json'} or directories != {'agent_tools','scripts','scripts/integration'}:
        raise ValueError('Installer tool inventory changed')


def prepare(root, expected_reviewed_tree_sha256):
    """Freeze exactly reviewed bytes. A caller must supply the reviewed digest."""
    root = Path(root).absolute()
    if not isinstance(expected_reviewed_tree_sha256, str) or not _SHA.fullmatch(expected_reviewed_tree_sha256):
        raise ValueError('Explicit reviewed installer tool digest required')
    sources = {name: _source(root, name) for name in FILES}
    tree = _tree(sources)
    digest = hashlib.sha256(_bytes(tree)).hexdigest()
    if digest != expected_reviewed_tree_sha256:
        raise ValueError('Installer tool tree differs from reviewed bytes')
    registry = _registry(root)
    folder = registry/('snapshot-'+str(uuid4()))
    folder.mkdir(mode=0o700)
    for name, (raw, _) in sources.items():
        target = folder/name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write(target, raw)
    _write(folder/'manifest.json', _bytes(tree))
    if sources != {name: _source(root, name) for name in FILES}:
        raise ValueError('Installer tool source changed during freeze')
    _inventory(folder)
    pins = {name: _read(folder/name)[1] for name in (*FILES, 'manifest.json')}
    directories = {str(p.relative_to(folder)): _dir(p) for p in
                   (folder, folder/'agent_tools', folder/'scripts', folder/'scripts/integration')}
    binding = {'schema': 1, 'kind': 'android-installer-tool-bundle', 'treeSha256': digest,
               'directory': folder.name, 'files': pins, 'directories': directories}
    bundle_id = 'sha256-'+hashlib.sha256(_bytes(binding)).hexdigest()
    anchor = registry/(bundle_id+'.json')
    _write(anchor, _bytes(binding))
    _write(registry/(bundle_id+'.seal.json'), _bytes({'schema': 1, 'bundleId': bundle_id,
                                                   'anchor': _read(anchor)[1]}))
    load(root, bundle_id)
    return {'toolBundleId': bundle_id, 'reviewedTreeSha256': digest}


def load(root, tool_bundle_id):
    """Load exact frozen tooling; every call rechecks inventory and generations."""
    root = Path(root).absolute()
    if not isinstance(tool_bundle_id, str) or not _ID.fullmatch(tool_bundle_id):
        raise ValueError('Installer tool bundle ID invalid')
    registry = root/'.rag_index/android-installer-tool-bundles'
    _dir(root/'.rag_index'); _dir(registry)
    raw, anchor_pin = _read(registry/(tool_bundle_id+'.json'), limit=16384)
    seal_raw, _ = _read(registry/(tool_bundle_id+'.seal.json'), limit=2048)
    if json.loads(seal_raw) != {'schema': 1, 'bundleId': tool_bundle_id, 'anchor': anchor_pin}:
        raise ValueError('Installer tool anchor generation changed')
    if 'sha256-'+hashlib.sha256(raw).hexdigest() != tool_bundle_id:
        raise ValueError('Installer tool anchor changed')
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {'schema','kind','treeSha256','directory','files','directories'} or
            type(value['schema']) is not int or value['schema'] != 1 or value['kind'] != 'android-installer-tool-bundle' or
            not isinstance(value['directory'], str) or not re.fullmatch(r'snapshot-[0-9a-f-]{36}', value['directory']) or
            not isinstance(value['files'], dict) or set(value['files']) != {*FILES, 'manifest.json'}):
        raise ValueError('Installer tool binding invalid')
    folder = registry/value['directory']
    _inventory(folder)
    actual_dirs = {str(p.relative_to(folder)): _dir(p) for p in
                   (folder, folder/'agent_tools', folder/'scripts', folder/'scripts/integration')}
    if actual_dirs != value['directories']:
        raise ValueError('Installer tool directory generation changed')
    files = {name: _read(folder/name) for name in (*FILES, 'manifest.json')}
    if {name: pin for name, (_, pin) in files.items()} != value['files']:
        raise ValueError('Installer tool file generation changed')
    tree = _tree(files)
    if files['manifest.json'][0] != _bytes(tree) or hashlib.sha256(_bytes(tree)).hexdigest() != value['treeSha256']:
        raise ValueError('Installer tool reviewed tree changed')
    # Recheck every earlier path after all reads; a same-byte rewrite of an
    # already-read file must not escape its recorded generation.
    _inventory(folder)
    if {name: _read(folder/name)[1] for name in (*FILES, 'manifest.json')} != value['files']:
        raise ValueError('Installer tool file changed while loading')
    if {str(p.relative_to(folder)): _dir(p) for p in (folder, folder/'agent_tools', folder/'scripts', folder/'scripts/integration')} != value['directories']:
        raise ValueError('Installer tool directory changed while loading')
    # Recheck anchor after all file reads; snapshot bytes returned are immutable.
    if _read(registry/(tool_bundle_id+'.json'), limit=16384) != (raw, anchor_pin):
        raise ValueError('Installer tool anchor changed while loading')
    return {'toolBundleId': tool_bundle_id, 'reviewedTreeSha256': value['treeSha256'],
            'manifest': tree, 'files': {name: files[name][0] for name in FILES}}
