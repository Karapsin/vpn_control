"""Authenticate explicitly named local review SOURCE artifacts; never grant native GO.

All input paths are lexical absolute paths (no resolve/symlink following). Archives
are read only when explicitly listed. Archive-only reviews need an explicit current
packet manifest or an authenticated listed proof carrying sourcePins. No filename
is discovered, guessed, or inferred from a verdict string.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat


def generation(info):
    """The complete nine-field file generation used by review packets."""
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _structural(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


def _sha(value):
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('A full lowercase SHA256 is required')
    return value


def _path(value):
    if not isinstance(value, str) or not value.startswith('/') or '\\' in value or '\x00' in value:
        raise ValueError('An explicit absolute POSIX path is required')
    parts = value.split('/')[1:]
    if not parts or any(part in ('', '.', '..') for part in parts):
        raise ValueError('Noncanonical path')
    # Observations of credential metadata are source evidence. Actual credential
    # and private-binding files must never be opened, including numbered copies.
    name = parts[-1].lower()
    private_base = r'(?:credentials?|binding)(?:[-_.]\d+)?\.json|arch-sudo(?:[-_.]\d+)?\.local'
    backup_suffix = r'(?:[-_.](?:\d+|bak|backup|old|orig|save|tmp|swp|swo))*~?'
    if re.search(r'(^|[-_.])(?:' + private_base + ')' + backup_suffix + r'$', name):
        raise ValueError('Credential/private binding contents are outside source scope')
    return value


def _relative(base, value):
    if not isinstance(value, str) or '\\' in value or '\x00' in value:
        raise ValueError('Unsafe relative artifact name')
    if value.startswith('/') or any(p in ('', '.', '..') for p in value.split('/')):
        raise ValueError('Unsafe relative artifact name')
    return _path(str(Path(base).parent / PurePosixPath(value)))


def _pin(value):
    if not isinstance(value, dict) or set(value) != {'generation', 'sha256'}:
        raise ValueError('Malformed source pin')
    gen = value['generation']
    if not isinstance(gen, list) or len(gen) != 9 or any(type(x) is not int or x < 0 for x in gen):
        raise ValueError('A complete generation9 pin is required')
    if not stat.S_ISREG(gen[2]) or gen[3] != os.getuid() or gen[5] != 1:
        raise ValueError('Source pin requires regular/current UID/single link')
    return tuple(gen), _sha(value['sha256'])


def _read_all(fd, max_bytes=None):
    if max_bytes is not None:
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError('Source byte bound requires a positive exact integer')
        if os.fstat(fd).st_size > max_bytes:
            raise ValueError('Source byte bound exceeded')
    os.lseek(fd, 0, os.SEEK_SET)
    chunks = []
    total = 0
    while True:
        requested = (1024 * 1024 if max_bytes is None else
                     min(1024 * 1024, max_bytes + 1 - total))
        chunk = os.read(fd, requested)
        if not chunk:
            return b''.join(chunks)
        total += len(chunk)
        if max_bytes is not None and total > max_bytes:
            raise ValueError('Source byte bound exceeded')
        chunks.append(chunk)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


class _Held:
    """Retain every opened file and directory through the final pure stat pass."""
    def __init__(self):
        self.fds = []
        self.parents = {}
        self.files = {}
        self.bounds = {}

    def directory(self, path):
        if path in self.parents:
            return self.parents[path][0]
        if path == '/':
            fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        else:
            parent, name = os.path.split(path)
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=self.directory(parent or '/'))
        self.fds.append(fd)
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('Non-directory ancestor')
        self.parents[path] = fd, _structural(info)
        return fd

    def read(self, path, digest, gen=None, *, max_bytes=None):
        if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 1):
            raise ValueError('Source byte bound requires a positive exact integer')
        path = _path(path)
        digest = _sha(digest)
        if path in self.files:
            entry = self.files[path]
            if entry[2] != digest or (gen is not None and entry[1] != gen):
                raise ValueError('Conflicting artifact pins')
            previous = self.bounds.get(path)
            bound = previous if max_bytes is None else (
                max_bytes if previous is None else min(previous, max_bytes))
            if bound is not None:
                if len(entry[3]) > bound or os.fstat(entry[0]).st_size > bound:
                    raise ValueError('Source byte bound exceeded')
                self.bounds[path] = bound
            return entry[3]
        parent, name = os.path.split(path)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=self.directory(parent))
        self.fds.append(fd)
        info = os.fstat(fd)
        actual = generation(info)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise ValueError('Artifact requires regular/current UID/single link')
        if gen is not None and actual != gen:
            raise ValueError('Source generation drift')
        raw = _read_all(fd) if max_bytes is None else _read_all(fd, max_bytes)
        if hashlib.sha256(raw).hexdigest() != digest or generation(os.fstat(fd)) != actual:
            raise ValueError('Artifact bytes/generation drift')
        self.files[path] = fd, actual, digest, raw
        if max_bytes is not None:
            self.bounds[path] = max_bytes
        return raw

    def json(self, path, digest):
        obj = json.loads(self.read(path, digest), object_pairs_hook=_pairs)
        if not isinstance(obj, dict):
            raise ValueError('Manifest must be an object')
        return obj

    def finish(self):
        # Rehash all retained file descriptors only after every artifact read.
        for path, (fd, gen, digest, _) in self.files.items():
            bound = self.bounds.get(path)
            raw = _read_all(fd) if bound is None else _read_all(fd, bound)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('Final source SHA drift')
        self.final_identity_pass()

    def final_identity_pass(self):
        # Parent observations can expose a late unlink or file replacement.
        # Complete them before the final pure held/named file generation pass.
        for path, (fd, identity) in self.parents.items():
            if path == '/':
                named = os.lstat('/')
            else:
                parent, name = os.path.split(path)
                named = os.stat(name, dir_fd=self.parents[parent or '/'][0], follow_symlinks=False)
            if _structural(os.fstat(fd)) != identity or _structural(named) != identity:
                raise ValueError('Final parent structural identity drift')
        for path, (fd, gen, _, _) in self.files.items():
            parent, name = os.path.split(path)
            named = os.stat(name, dir_fd=self.parents[parent][0], follow_symlinks=False)
            if generation(os.fstat(fd)) != gen or generation(named) != gen:
                raise ValueError('Final file FD/name generation drift')

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)


def _schema(obj):
    candidates = [key for key in ('files', 'pins', 'inputs') if key in obj]
    absolute_keys = [key for key in obj if isinstance(key, str) and key.startswith('/')]
    if not candidates and obj and len(absolute_keys) == len(obj):
        for path, pin in obj.items():
            _path(path)
            _pin(pin)
        return 'absolute', obj
    if len(candidates) != 1 or absolute_keys:
        raise ValueError('Missing or ambiguous manifest schema')
    value = obj[candidates[0]]
    if candidates[0] in ('pins', 'inputs'):
        if not isinstance(value, dict) or not value:
            raise ValueError('Empty/malformed pins mapping')
        return 'absolute', value
    if isinstance(value, list) and value:
        return 'list', value
    if isinstance(value, dict) and value:
        kinds = {type(v) for v in value.values()}
        if kinds == {str}:
            return 'archives', value
        if kinds == {dict}:
            return 'relative', value
    raise ValueError('Malformed or mixed files schema')


def close_review_sources(manifest_path, manifest_sha256, *, packet_manifest_path=None,
                         packet_manifest_sha256=None, proof_path=None, proof_sha256=None):
    """Return content hashes only after a stable SOURCE closure of explicit inputs.

    A successful receipt grants no native execution or product acceptance. All
    descriptors close on either success or failure; no evidence files are written.
    """
    if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'getuid'):
        raise ValueError('Strict source closure requires POSIX nofollow/UID support')
    held = _Held()
    sources = {}
    archives = {}
    try:
        manifest_path = _path(manifest_path)
        obj = held.json(manifest_path, manifest_sha256)
        kind, entries = _schema(obj)
        def source(path, pin):
            gen, digest = _pin(pin)
            held.read(path, digest, gen)
            sources[path] = digest
        if kind == 'list':
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {'path', 'pin', 'archive', 'archiveSha256'}:
                    raise ValueError('Malformed source/archive entry')
                source(_path(entry['path']), entry['pin'])
                path = _path(entry['archive'])
                digest = _sha(entry['archiveSha256'])
                if digest != entry['pin']['sha256']:
                    raise ValueError('Archive/source SHA mismatch')
                held.read(path, digest)
                archives[path] = digest
        elif kind in ('relative', 'absolute'):
            for name, pin in entries.items():
                source(_relative(manifest_path, name) if kind == 'relative' else _path(name), pin)
        else:
            for name, digest in entries.items():
                path = _relative(manifest_path, name)
                held.read(path, digest)
                archives[path] = digest
        if (packet_manifest_path is None) != (packet_manifest_sha256 is None):
            raise ValueError('Packet manifest path and full SHA are both required')
        if (proof_path is None) != (proof_sha256 is None):
            raise ValueError('Proof path and full SHA are both required')
        if packet_manifest_path is not None and proof_path is not None:
            raise ValueError('Ambiguous current source authority')
        if packet_manifest_path is not None:
            packet = held.json(packet_manifest_path, packet_manifest_sha256)
            packet_kind, pins = _schema(packet)
            if packet_kind not in ('relative', 'absolute'):
                raise ValueError('Current packet must contain source pins')
            for name, pin in pins.items():
                source(_relative(packet_manifest_path, name) if packet_kind == 'relative' else _path(name), pin)
        if proof_path is not None:
            proof_path = _path(proof_path)
            if archives.get(proof_path) != _sha(proof_sha256):
                raise ValueError('Proof must be an authenticated listed archive')
            proof = held.json(proof_path, proof_sha256)
            pins = proof.get('sourcePins')
            if not isinstance(pins, dict) or not pins:
                raise ValueError('Proof lacks sourcePins')
            for name, pin in pins.items():
                source(_path(name), pin)
        if not sources:
            raise ValueError('Archive-only review requires explicit current packet or proof sourcePins')
        receipt = {'scope':'SOURCE_ONLY', 'nativeActionAllowed':False,
                   'productAcceptance':False, 'manifestSha256':_sha(manifest_sha256),
                   'sourceCount':len(sources), 'archiveCount':len(archives),
                   'sourceHashes':sources, 'archiveHashes':archives}
        held.finish()
        return receipt
    finally:
        held.close()
