"""Read-only collection of the sealed post-frame from the fixed third Windows VM attempt."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import selectors
import stat
import struct
import subprocess
import time
from typing import Any
import zlib
from contextlib import contextmanager

try:
    from . import windows_vm_optical_boot as boot
    from . import windows_vm_optical_boot_attempt3 as third
except ImportError:
    import windows_vm_optical_boot as boot  # type: ignore[no-redef]
    import windows_vm_optical_boot_attempt3 as third  # type: ignore[no-redef]


MAX_PPM = 8_388_608
EVIDENCE = Path(".runtime/parity-evidence/optical-boot-20260929/attempt3-frame")


def _program(correlation_id: str, closure_correlation_id: str,
             owner: dict[str, int]) -> str:
    base = boot._program(correlation_id, "status", attempt=3,
                         expected_closure=closure_correlation_id)
    prefix = base.split("\ntry:\n owner=claim()", 1)[0]
    if prefix == base:
        raise ValueError("Windows optical source has no fixed observation boundary")
    return prefix + "\nEXPECTED_OWNER=" + repr(owner) + r'''
try:
 owner=claim();media=source()
 if owner!=EXPECTED_OWNER or (owner['isoDevice'],owner['isoInode'])!=(media['device'],media['inode']):raise ValueError('owner-changed')
 intent=read(INTENT);disk=intent.get('blankDisk')
 if not isinstance(disk,dict) or disk!={'device':owner['diskDevice'],'inode':owner['diskInode'],'virtualSizeBytes':96*1024**3,'allocatedGuestClusters':0}:raise ValueError('intent-disk')
 historical_closures(owner,media,disk)
 observed=validate_receipts(owner,media,disk)
 if observed.get('state')!='post-screen-observed':raise ValueError('post-frame-not-sealed')
 sealed=frame(POST_FRAME,False)
 if observed.get('frameHashes',{}).get('after')!=sealed['sha256']:raise ValueError('post-frame-hash')
 fd=os.open(POST_FRAME,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
 try:
  before=os.fstat(fd);raw=os.read(fd,8388609);after=os.fstat(fd);named=os.stat(POST_FRAME,follow_symlinks=False)
  keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
  if (not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid() or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o600 or
      len(raw)!=sealed['sizeBytes'] or any(getattr(before,k)!=getattr(after,k) or getattr(before,k)!=getattr(named,k) for k in keys) or
      hashlib.sha256(raw).hexdigest()!=sealed['sha256']):raise ValueError('post-frame-changed')
 finally:os.close(fd)
 if claim()!=owner or not same_media(media):raise ValueError('owner-changed')
 write_all(1,raw)
except Exception:
 raise SystemExit(3)
'''


def _bounded_ssh(root: str | Path, program: str, timeout_seconds: int) -> bytes:
    config = boot.ssh_transport.load_config(root)
    if (boot.HOST not in config.hosts
            or boot.ssh_transport.connection_host(config, boot.HOST).password is not None):
        raise ValueError("Configured Arch transport is unavailable")
    argv = boot.ssh_transport.build_ssh_argv(
        config, boot.HOST, min(timeout_seconds, 30),
        command=("python3", "-c", "exec(" + repr(program) + ")"))
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL)
    selector = selectors.DefaultSelector()
    try:
        assert process.stdout is not None
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        output = bytearray()
        while selector.get_map():
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("Windows optical post-frame transport timed out")
            if not selector.select(left):
                raise TimeoutError("Windows optical post-frame transport timed out")
            data = os.read(process.stdout.fileno(), min(65_536, MAX_PPM + 1 - len(output)))
            if not data:
                selector.unregister(process.stdout)
                break
            output.extend(data)
            if len(output) > MAX_PPM:
                raise ValueError("Windows optical post-frame exceeds fixed limit")
        if process.wait(timeout=max(0.1, deadline - time.monotonic())) != 0:
            raise ValueError("Windows optical post-frame transport failed")
        return bytes(output)
    finally:
        selector.close()
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdout is not None:
            process.stdout.close()


def _ppm(raw: bytes, expected_sha256: str) -> tuple[int, int, bytes]:
    if not 64 <= len(raw) <= MAX_PPM or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("Windows optical post-frame digest or size changed")
    parts = raw.split(b"\n", 3)
    if len(parts) != 4 or parts[0] != b"P6" or parts[2] != b"255":
        raise ValueError("Windows optical post-frame PPM header changed")
    try:
        dimensions = parts[1].split()
        if len(dimensions) != 2:
            raise ValueError("PPM dimensions")
        width, height = (int(value) for value in dimensions)
    except ValueError as error:
        raise ValueError("Windows optical post-frame dimensions changed") from error
    if not 320 <= width <= 3840 or not 240 <= height <= 2160 or len(parts[3]) != width * height * 3:
        raise ValueError("Windows optical post-frame dimensions changed")
    return width, height, parts[3]


def _png(width: int, height: int, rgb: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xffffffff)
    stride = width * 3
    rows = b"".join(b"\0" + rgb[index:index + stride] for index in range(0, len(rgb), stride))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(rows, level=6)) + chunk(b"IEND", b""))


@contextmanager
def _anchor(root: str | Path, private_name: str = "attempt3-frame"):
    if private_name not in ("attempt3-frame", "attempt3-current-frame"):
        raise ValueError("Windows optical evidence directory is not fixed")
    workspace = Path(root).resolve()
    directory = workspace / EVIDENCE.parent / private_name
    names = (".runtime", "parity-evidence", "optical-boot-20260929", private_name)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fds: list[int] = []
    paths: list[Path] = []
    try:
        fd = os.open(workspace, flags)
        fds.append(fd)
        paths.append(workspace)
        for name in names:
            if name == private_name:
                try:
                    os.mkdir(name, 0o700, dir_fd=fd)
                    os.fsync(fd)
                except FileExistsError:
                    pass
            child = os.open(name, flags, dir_fd=fd)
            fd = child
            fds.append(fd)
            paths.append(paths[-1] / name)
        for index, (path, item_fd) in enumerate(zip(paths, fds)):
            info = os.fstat(item_fd)
            named = os.lstat(path)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o022
                    or (index == len(fds) - 1 and stat.S_IMODE(info.st_mode) != 0o700)
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise ValueError("Windows optical local evidence path is unsafe")
        yield directory, tuple(zip(paths, fds))
    finally:
        for item_fd in reversed(fds):
            os.close(item_fd)


def _verify_anchor(chain: tuple[tuple[Path, int], ...]) -> None:
    for path, fd in chain:
        item = os.fstat(fd)
        named = os.lstat(path)
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid()
                or (item.st_dev, item.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISDIR(named.st_mode)):
            raise ValueError("Windows optical local evidence ancestor changed")


def _publish(directory: Path, chain: tuple[tuple[Path, int], ...],
             correlation_id: str, png: bytes, leaf_prefix: str = "post") -> Path:
    if leaf_prefix not in ("post", "current"):
        raise ValueError("Windows optical image name is not fixed")
    _verify_anchor(chain)
    parent_fd = chain[-1][1]
    leaf = leaf_prefix + "-" + correlation_id + ".png"
    destination = directory / leaf
    fd = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                 0o600, dir_fd=parent_fd)
    try:
        view = memoryview(png)
        while view:
            count = os.write(fd, view)
            if count <= 0 or count > len(view):
                raise OSError("Windows optical local post-frame short write")
            view = view[count:]
        os.fsync(fd)
        published = os.fstat(fd)
    finally:
        os.close(fd)
    os.fsync(parent_fd)
    _verify_anchor(chain)
    read_fd = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    try:
        before = os.fstat(read_fd)
        readback = os.read(read_fd, len(png) + 1)
        after = os.fstat(read_fd)
    finally:
        os.close(read_fd)
    named = os.lstat(destination)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) != 0o600
            or (before.st_dev, before.st_ino) != (published.st_dev, published.st_ino)
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
            or before.st_size != len(png) or len(readback) != len(png)
            or hashlib.sha256(readback).digest() != hashlib.sha256(png).digest()):
        raise ValueError("Windows optical local post-frame readback changed")
    _verify_anchor(chain)
    return destination


def collect(root: str | Path, *, host: str, correlation_id: str,
            closure_correlation_id: str, timeout_seconds: int = 90) -> dict[str, Any]:
    boot._check(host, correlation_id, timeout_seconds)
    boot._check(host, closure_correlation_id, timeout_seconds)
    observed = third.status(root, host=host, correlation_id=correlation_id,
                            closure_correlation_id=closure_correlation_id,
                            timeout_seconds=timeout_seconds)
    if (observed.get("state") != "post-screen-observed"
            or not isinstance(observed.get("owner"), dict)
            or not isinstance(observed.get("frameHashes"), dict)
            or not isinstance(observed["frameHashes"].get("after"), str)
            or not boot.SHA.fullmatch(observed["frameHashes"]["after"])):
        raise ValueError("Windows optical third post-frame is not sealed")
    with _anchor(root) as (directory, chain):
        leaf = "post-" + correlation_id + ".png"
        try:
            os.stat(leaf, dir_fd=chain[-1][1], follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("Windows optical local post-frame already exists")
        try:
            raw = _bounded_ssh(root, _program(correlation_id, closure_correlation_id,
                                              dict(observed["owner"])), timeout_seconds)
            width, height, rgb = _ppm(raw, observed["frameHashes"]["after"])
            png = _png(width, height, rgb)
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired):
            return {"correlationId": correlation_id, "state": "unknown", "replayAllowed": False,
                    "nativeActionAllowed": False}
        destination = _publish(directory, chain, correlation_id, png)
    return {"correlationId": correlation_id, "state": "collected", "imagePath": str(destination),
            "ppmSha256": hashlib.sha256(raw).hexdigest(), "pngSha256": hashlib.sha256(png).hexdigest(),
            "width": width, "height": height, "nativeActionAllowed": False, "replayAllowed": False}
