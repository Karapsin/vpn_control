"""Current CP117 download-failure retirement, isolated from historical recovery.

The implementation is loaded into a private module instance so its fixed
correlation and lease cannot alter the completed historical adapter.  It reads
the immutable HTTP record for the current artifact; callers cannot choose an
artifact, task, VM, or host path.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Mapping

from . import windows_update_fixture_download_abort as _template

_CORRELATION = "07708dc7-6884-40a5-9a78-c75dbb391dbd"
_LEASE = "9b4cf4c7-791a-4e51-93ac-0b8db4ac4409"
_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"


def _load():
    """Load a separate copy; never mutate the historical module globals."""
    spec = importlib.util.spec_from_file_location(__package__ + "._download_abort_current_impl",
                                                   Path(_template.__file__).resolve())
    if spec is None or spec.loader is None:
        raise RuntimeError("Current download abort implementation is unavailable.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module._CORRELATION = _CORRELATION
    module._LEASE = _LEASE
    module._SOURCE = _SOURCE
    return module


_impl = _load()


def _request(value: Mapping[str, Any]) -> None:
    if not isinstance(value, Mapping) or value != {"correlationId": _CORRELATION}:
        raise ValueError("Current download abort requires its exact correlationId.")


def task_cleanup_status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value)
    return _impl.task_cleanup_status(root, value)


def task_cleanup(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value)
    return _impl.task_cleanup(root, value)


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value)
    return _impl.status(root, value)


def abort(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value)
    return _impl.abort(root, value)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "task-cleanup-status": return task_cleanup_status(root, inputs)
    if action == "task-cleanup": return task_cleanup(root, inputs)
    if action == "status": return status(root, inputs)
    if action == "abort": return abort(root, inputs)
    raise ValueError("Unknown current download abort action.")
