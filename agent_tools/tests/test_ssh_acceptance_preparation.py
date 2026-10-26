"""Authenticated fixed local source regressions; no SSH, VM or private inputs."""
import hashlib
import json
import os
from pathlib import Path
import sys
from types import ModuleType
import unittest

FIXTURE = Path(__file__).parent / 'fixtures/ssh_acceptance_preparation'
PROVENANCE_SHA = 'aca4e88787264298e02f33c6f12c030d0a402a02f077d1ab0eb25090890c7386'
FILES = ['audit_prepared_sources.py', 'audit_prepared_sources.remote-path.before.source', 'build_controller_program.generation-before.source', 'build_controller_program_v2.py', 'controller.4674.before.source', 'controller.edc5.before.source', 'controller.py', 'controller14d.before.source', 'local-owner-source/local_owner.pre-deadline.before.source', 'local-owner-source/local_owner.py', 'local-owner-source/local_owner_v2.py', 'local-owner-source/test_local_owner.missing-binding.before.source', 'local-owner-source/test_local_owner_v2.py', 'ordinary-controller-direct-v2.source', 'ordinary-controller-direct-v3.source', 'ordinary-controller-nested-v2.source', 'ordinary-controller-nested-v3.source', 'ordinary_retention.py', 'prepare_absolute_epoch.py', 'prepare_absolute_epoch.syntax-before.source', 'prepare_sources.c141.before.source', 'prepare_sources.py', 'relocated-wrapper-key.failure.txt', 'test_controller.py', 'test_generic_bootstrap_program_path.port-before.source', 'test_generic_bootstrap_program_path.py', 'test_preparation_causals.before.source', 'test_preparation_causals.py', 'test_prepare_private_roots.py', 'test_program_builder_v2.py']


def load_fixture(name, alias):
    raw = (FIXTURE / 'provenance.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != PROVENANCE_SHA:
        raise AssertionError('fixture provenance changed')
    record = json.loads(raw)
    if record['schemaVersion'] != 1 or set(record['files']) != set(FILES):
        raise AssertionError('finite fixture scope changed')
    for leaf in FILES:
        if hashlib.sha256((FIXTURE / leaf).read_bytes()).hexdigest() != record['files'][leaf]:
            raise AssertionError('fixture bytes changed: ' + leaf)
    module = ModuleType(alias)
    module.__file__ = str((FIXTURE / name).resolve())
    module.__package__ = None
    sys.modules[alias] = module
    exec(compile((FIXTURE / name).read_bytes(), module.__file__, 'exec'), module.__dict__)
    return module


SUPPORTED = os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'pread')

if SUPPORTED:
    roots = load_fixture('test_prepare_private_roots.py', '_routine_private_root_tests')
    builders = load_fixture('test_program_builder_v2.py', '_routine_source_builder_tests')
    harness = load_fixture('test_preparation_causals.py', '_routine_preparation_harness_tests')
    bootstrap = load_fixture('test_generic_bootstrap_program_path.py', '_routine_generic_bootstrap_tests')
    PreparationDirectoryTests = roots.PreparationDirectoryTests
    SourceBuilderTests = builders.SourceBuilderTests
    PreparationCausals = harness.PreparationCausals
    GenericBootstrapProgramPathTests = bootstrap.GenericBootstrapProgramPathTests
else:
    @unittest.skip('requires POSIX process generation and private file descriptors')
    class PreparationDirectoryTests(unittest.TestCase):
        def test_supported_platform(self):
            pass
