"""Isolated successor campaign after current CP117 failed-download retirement.

It reuses the reviewed terminal-handoff state machine in a private module
instance.  The old guest-create handoff and its globals remain immutable.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Mapping

from . import windows_cp117_download_abort_successor as _template
from . import windows_update_fixture_download_abort_current as abort

_OLD = "9b4cf4c7-791a-4e51-93ac-0b8db4ac4409"
_CORRELATION = "07708dc7-6884-40a5-9a78-c75dbb391dbd"
_SOURCE = "19be9df22cbab8086c26e5ca907d9569a5a28a08"
_DIR = ".rag_index/windows-cp117-download-abort-current-successor"


def _load():
    spec = importlib.util.spec_from_file_location(__package__ + "._download_abort_current_successor_impl",
                                                   Path(_template.__file__).resolve())
    if spec is None or spec.loader is None: raise RuntimeError("Successor implementation unavailable.")
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    # The copied implementation resolves all receipt helpers via this private
    # abort instance, never by mutating either historical module.
    module.abort = abort._impl
    module._OLD = _OLD; module._CORRELATION = _CORRELATION; module._SOURCE = _SOURCE; module._DIR = _DIR
    return module


_impl = _load()


def _request(value: Mapping[str, Any]) -> dict[str, str]:
    result = _impl._request(value)
    if result.get("oldLeaseId") != _OLD or result.get("sourceSha") != _SOURCE:
        raise ValueError("Current successor is bound to its exact retired campaign.")
    return result


def status(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value); return _impl.status(root, value)


def reconcile(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value); return _impl.reconcile(root, value)


def resume_close(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value); return _impl.resume_close(root, value)


def resume_begin(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value); return _impl.resume_begin(root, value)


def start(root: Path | str, value: Mapping[str, Any]) -> dict[str, Any]:
    _request(value); return _impl.start(root, value)


def workflow(root: Path | str, action: str, inputs: Mapping[str, Any]) -> dict[str, Any]:
    if action == "status": return status(root, inputs)
    if action == "reconcile": return reconcile(root, inputs)
    if action == "resume-close": return resume_close(root, inputs)
    if action == "resume-begin": return resume_begin(root, inputs)
    if action == "start": return start(root, inputs)
    raise ValueError("Unknown current download-abort successor action.")
