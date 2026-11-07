"""One authentic FIFO oracle with a declared normal-registration import peer.

All filesystem operations are real and confined to the caller's owned temporary
tree.  The complete historical qualifier supplies its original worker, actual
FIFO open, writer release, join, descriptor checks, and final assertion.
"""
from __future__ import annotations

import hashlib
import importlib.util
from importlib.machinery import SourceFileLoader
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock
import uuid


HERE = Path(__file__).parent
QUALIFIER_PIN = "0bb83f1aba8d1742f969dad39534642d3bd310e4cc0572ef5b10905383da0e1d"
BEFORE_PIN = "5ad9c4fc86ae47bbb4e69a2b365334509e7edbe7f991ca9c5d2366e18d5cc7eb"
CURRENT_PIN = "b1092da71d6688aa4cb90ed910a62ed3dad1572888db30f357fb4f373f46a279"
CASE = "test_fifo_replacement_at_real_open_is_nonblocking_and_refused"


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _stage(path, raw):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as target:
            target.write(raw)
    finally:
        os.close(descriptor)


def _one(raw, qualifier_raw, directory):
    directory.mkdir(mode=0o700)
    prefix_path = directory / "pending_prefix.py"
    qualifier_path = directory / "qualify_pending_prefix.py"
    _stage(prefix_path, raw)
    _stage(qualifier_path, qualifier_raw)
    original_spec = importlib.util.spec_from_file_location
    prefix_name = "private_pending_prefix"
    missing = object()
    previous = sys.modules.get(prefix_name, missing)
    registrations = []

    class RegisteredPrefixLoader(SourceFileLoader):
        def exec_module(self, module):
            # The authentic qualifier explicitly constructs its pending module.
            # This import peer adds ordinary registration before complete exec;
            # it does not change either module's globals or function bodies.
            sys.modules[module.__name__] = module
            registrations.append((module, _sha(prefix_path.read_bytes())))
            super().exec_module(module)

    def prefix_spec(name, location, *args, **kwargs):
        if Path(location) == prefix_path:
            if name != prefix_name or args or kwargs:
                raise ValueError("fifo_prefix_import_boundary")
            return original_spec(name, location,
                loader=RegisteredPrefixLoader(name, str(location)))
        return original_spec(name, location, *args, **kwargs)

    name = "_authentic_fifo_qualifier_" + uuid.uuid4().hex
    spec = original_spec(name, qualifier_path,
        loader=SourceFileLoader(name, str(qualifier_path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    capture = io.StringIO()
    try:
        with mock.patch.object(importlib.util, "spec_from_file_location", side_effect=prefix_spec):
            spec.loader.exec_module(module)
        registered = (len(registrations) == 1
            and registrations[0] == (module.pending, _sha(raw))
            and sys.modules.get(prefix_name) is module.pending)
        module.RUN.parent.mkdir(mode=0o700)
        module.RUN.mkdir(mode=0o700)
        suite = unittest.TestSuite([module.Qualification(CASE)])
        result = unittest.TextTestRunner(stream=capture, verbosity=2).run(suite)
        proof = json.loads((module.RUN / CASE / "fifo-open-proof.json").read_bytes())
        unchanged = (prefix_path.read_bytes() == raw
            and qualifier_path.read_bytes() == qualifier_raw)
        return {
            "testsRun": result.testsRun,
            "failures": len(result.failures),
            "errors": len(result.errors),
            "skipped": len(result.skipped),
            "output": capture.getvalue(),
            "proof": proof,
            "prefixSha256": _sha(raw),
            "qualifierSha256": _sha(qualifier_raw),
            "completeNormallyRegisteredPrefix": registered,
            "completeNormallyRegisteredQualifier": sys.modules.get(name) is module,
            "sourcesUnchanged": unchanged,
            "noFunctionReplacement": True,
            "noInjectedModuleGlobals": True,
            "boundary": "importlib SourceFileLoader registration peer only; original FIFO os.open peer from authentic qualifier",
            "remoteActions": False,
            "nativeWindowsActions": False,
        }
    finally:
        sys.modules.pop(name, None)
        if previous is missing:
            sys.modules.pop(prefix_name, None)
        else:
            sys.modules[prefix_name] = previous


def run_fifo_pair(before, current, directory):
    """Execute only the original single FIFO oracle, once per complete source."""
    if _sha(before) != BEFORE_PIN or _sha(current) != CURRENT_PIN:
        raise ValueError("fifo_prefix_source_pin")
    qualifier = (HERE / "qualify-pending-prefix.source").read_bytes()
    if _sha(qualifier) != QUALIFIER_PIN:
        raise ValueError("fifo_qualifier_source_pin")
    directory = Path(directory).resolve()
    return {
        "before": _one(before, qualifier, directory / "before"),
        "after": _one(current, qualifier, directory / "after"),
    }
