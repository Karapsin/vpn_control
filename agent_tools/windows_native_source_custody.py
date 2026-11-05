"""Read explicit public Windows helper sources and one private registration.

Public source files may use the normal 0644 checkout mode. The selected private
registration still requires 0600; this helper never reads a credential file or
submits a native operation.
"""
import hashlib
import os
from pathlib import Path
import stat

from . import readiness_fixture_registry as registry

_SOURCE_LIMIT = 1_048_576


def _public_source_pin(path):
    presented = registry.private.PresentedPath(path.parent)
    with registry.private.Directory(presented.canonical) as directory:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory.fd)
        try:
            info = os.fstat(descriptor)
            registry._need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                           and info.st_nlink == 1 and not info.st_mode & 0o022
                           and 0 < info.st_size <= _SOURCE_LIMIT, "fixture_file_unsafe")
            raw = bytearray()
            while len(raw) <= _SOURCE_LIMIT:
                part = os.read(descriptor, min(65536, _SOURCE_LIMIT + 1 - len(raw)))
                if not part:
                    break
                raw.extend(part)
            generation = registry.private._generation(info)
            registry._need(len(raw) == info.st_size
                           and registry.private._generation(os.fstat(descriptor)) == generation
                           == registry.private._generation(os.stat(path.name, dir_fd=directory.fd,
                                                                   follow_symlinks=False)),
                           "fixture_file_changed")
            presented.guard()
            directory.guard()
            return {"generation": list(generation), "sha256": hashlib.sha256(raw).hexdigest()}
        finally:
            os.close(descriptor)


def source_pins(public_sources, registration):
    """Return physical file pins without applying private-data mode to code."""
    if type(public_sources) is not tuple or not public_sources:
        raise ValueError("windows_native_source_inputs")
    paths = (*public_sources, registration)
    if any(type(path) is not type(Path()) or not path.is_absolute()
           or path != path.resolve(strict=True) for path in paths):
        raise ValueError("windows_native_source_path")
    if (any(path.suffix != ".py" for path in public_sources)
            or registration.suffix != ".json" or len(set(paths)) != len(paths)):
        raise ValueError("windows_native_source_inputs")
    result = {str(path): _public_source_pin(path) for path in public_sources}
    result[str(registration)] = registry._body(registration)[1]
    return result
