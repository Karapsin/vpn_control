"""Finite configured baseline metadata, without observing or admitting any VM.

Source IDs and generations are expressly public configuration labels chosen by
the data owner and must not contain secrets; no string heuristic classifies them.
The existing trusted provider adapter reads and validates private configuration.
This wrapper holds its inventory identity across that call without rereading,
retaining, hashing or projecting the inventory contents.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat

try:
    from . import native_vm_baseline_config as config
except ImportError:  # MCP script import
    import native_vm_baseline_config as config


class BaselineInventoryError(ValueError):
    def __init__(self, *, reason='metadata_unavailable'):
        super().__init__('Configured baseline source metadata is unavailable.')
        self.reason = reason


def _reason(error):
    # Match only finite messages emitted by the trusted loader, never paths or
    # arbitrary exception text. Missing/empty/malformed sections share its gate.
    if not isinstance(error, config.baseline.VmBaselineError):
        return 'metadata_unavailable'
    message = str(error)
    if message == 'native baselines are not configured':
        return 'baselines_not_configured'
    if message in ('private VM inventory schema is invalid',
                   'baseline proof is invalid JSON', 'baseline proof must be an object'):
        return 'invalid_inventory'
    if message in ('baseline source config is malformed', 'baseline provider is unsupported',
                   'configured baseline path is unsafe', 'configured baseline path contains traversal',
                   'configured baseline path contains a symlink',
                   'baseline source must be a direct child of its owned root',
                   'baseline provider name is unsafe', 'Tart source path and VM name disagree',
                   'one provider must use one owned source root', 'unsafe VM baseline identity',
                   'owned VM root is unsafe', 'provider source root is writable by another user',
                   'VM path must be absolute', 'VM path traversal is unsafe',
                   'VM path escapes owned root', 'VM path contains a symlink',
                   'VM path is missing', 'VM path is not a directory'):
        return 'invalid_source_configuration'
    return 'metadata_unavailable'


def _generation(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _structure(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)


class _InventoryHold:
    def __init__(self):
        self.fds = []
        self.parents = {}
        self.fd = None

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
        self.parents[path] = (fd, _structure(os.fstat(fd)))
        return fd

    def open(self, path):
        self.parent, self.name = os.path.split(path)
        self.fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                          dir_fd=self.directory(self.parent))
        self.fds.append(self.fd)
        info = os.fstat(self.fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or
                info.st_size > config._MAX_FILE):
            raise BaselineInventoryError()
        self.generation = _generation(info)

    def finish(self):
        # Finish parent observations before the terminal original file pass.
        # Inventory contents/digest are never copied by this metadata wrapper.
        for path, (fd, identity) in self.parents.items():
            if path == '/':
                named = os.lstat('/')
            else:
                parent, name = os.path.split(path)
                named = os.stat(name, dir_fd=self.parents[parent or '/'][0], follow_symlinks=False)
            if _structure(os.fstat(fd)) != identity or _structure(named) != identity:
                raise BaselineInventoryError()
        named = os.stat(self.name, dir_fd=self.parents[self.parent][0], follow_symlinks=False)
        if _generation(os.fstat(self.fd)) != self.generation or _generation(named) != self.generation:
            raise BaselineInventoryError()

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)


def configured_source_metadata(root: Path | str) -> dict:
    """List validated configuration labels only; no native/readiness authority.

    The root is the trusted checkout supplied by MCP, never a public path input.
    Errors are finite and omit private parser/path details.
    """
    hold = _InventoryHold()
    try:
        if os.name != 'posix' or not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'getuid'):
            raise BaselineInventoryError()
        checkout = Path(root).resolve(strict=True)
        hold.open(str(checkout / config.ssh_transport.CONFIG_FILENAME))
        _, providers = config._configured_providers(checkout)
        sources = []
        for kind, provider in providers.items():
            if kind not in ('tart', 'qemu') or provider.kind != kind:
                raise BaselineInventoryError()
            for source_id, binding in provider.sources.items():
                config.baseline._name(source_id)
                config.baseline._name(binding.generation)
                if binding.source_id != source_id:
                    raise BaselineInventoryError()
                sources.append({'sourceId': source_id, 'provider': kind, 'generation': binding.generation})
        result = {'schemaVersion': 1, 'scope': 'CONFIGURATION_METADATA_ONLY',
                  'sources': sorted(sources, key=lambda item: item['sourceId']),
                  'nativeActionAllowed': False, 'readinessVerified': False}
        hold.finish()
        return result
    except (ValueError, OSError, TypeError, KeyError, config.baseline.VmBaselineError) as error:
        raise BaselineInventoryError(reason=_reason(error)) from None
    finally:
        hold.close()
