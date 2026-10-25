"""Finite normal HOST integration; historical completion is never current Ready."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest
from uuid import UUID,uuid5

from agent_tools import durable_remote_job as jobs
from agent_tools import readiness_windows_host_jobs as host
from agent_tools import readiness_windows_creator_registry as registry
from agent_tools import readiness_windows_bootstrap_durable as durable
from agent_tools.tests.test_windows_bootstrap_durable import with_original
from agent_tools.tests import test_windows_host_jobs as host_fixtures

FIXTURE=Path(__file__).with_name('fixtures')/'windows_bootstrap_integration'


def before_host():
    path=FIXTURE/'host.before.source';raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!='b1ad8236004908ceee969f54a33958b652f3efec8453e48a53b4a53f420df383':raise AssertionError('whole HOST before changed')
    name='agent_tools._bootstrap_integration_host_before';spec=importlib.util.spec_from_loader(name,loader=None,origin=str(path))
    module=importlib.util.module_from_spec(spec);module.__file__=str(path);sys.modules[name]=module
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


class IntegrationShapeTests(unittest.TestCase):
    def test_exact_before_sources_and_no_dto_historical_authority(self):
        expected={'host.before.source':'b1ad8236004908ceee969f54a33958b652f3efec8453e48a53b4a53f420df383',
            'registry.before.source':'cc4b0b1213ff87d3a7d038089cc163ec76749adaf0c7c85cda7494fe5fec7638',
            'provenance.json':'8a9f3ffce16585e7cb55bf2c463e2db2259424bef6db3de3cb8de9dbc157cc17'}
        self.assertEqual({p.name for p in FIXTURE.iterdir()},set(expected))
        for name,digest in expected.items():self.assertEqual(hashlib.sha256((FIXTURE/name).read_bytes()).hexdigest(),digest)
        with self.assertRaises(TypeError):registry.HistoricalCreatorBootstrap()
        with self.assertRaises(ValueError):object.__new__(registry.HistoricalCreatorBootstrap).as_dict()
        with self.assertRaises(ValueError):registry.historical_bootstrap({}, {'historicalBootstrapComplete':True})
        self.assertEqual(host._PURPOSES,before_host()._PURPOSES|{'windows-bootstrap-finalize'})


@unittest.skipIf(os.name!='posix'or os.geteuid()==0,'ordinary actual private original packets')
class BootstrapHostIntegrationTests(unittest.TestCase):
    def test_full_original_finalizer_before_rejected_current_retained_observe_only(self):
        old=before_host()
        def action(original,witness,packet,repo):
            value=durable.retain(repo,original,witness);record,source,_,_=durable._load(value)
            program=jobs.Program(durable.PURPOSE,source)
            with self.assertRaises(ValueError):old.retain(repo,record['namespace'],record['operationId'],record['recoveryId'],program)
            retained=host.retain(repo,record['namespace'],record['operationId'],record['recoveryId'],program)
            self.assertEqual(host._load(retained)[1],source)
            fresh=host.reopen(repo,record['namespace']['binding']['target'],record['namespace']['binding']['machine'],record['operationId'])
            self.assertEqual(fresh.as_dict(),retained.as_dict())
            remote=Path(record['namespace']['root'])/record['operationId'];self.assertFalse(remote.exists())
            reply=host_fixtures.WindowsHostOwnerTests('runTest').run_source(host.operation_program(fresh))
            self.assertEqual(host.validate_result(fresh,reply)['status']['state'],'unsubmitted')
            self.assertFalse(remote.exists())
        with_original(self,action)

    def test_normal_inventory_sees_bootstrap_pending_unknown_and_terminal(self):
        fixture=host_fixtures.WindowsHostOwnerTests('runTest');fixture.setUp();self.addCleanup(fixture.doCleanups)
        rid='e'*64;op=str(uuid5(UUID(fixture.bound['spec']['deploymentId']),rid));marker=fixture.vm/'bootstrap-marker'
        source=('from pathlib import Path\nimport time\nPath('+repr(str(marker))+').write_text("once")\ntime.sleep(.2)\nprint("bootstrap-terminal",flush=True)\n').encode()
        program=host.sealed_program(jobs.Program(durable.PURPOSE,source));retained=host.retain(fixture.root,fixture.namespace,op,rid,program)
        first=fixture.run_source(host.operation_program(retained,submit=True))
        self.assertIn(first['status']['state'],{'running','unknown','terminal'})
        terminal=fixture.terminal(retained);self.assertEqual(terminal['status']['terminal']['exitCode'],0)
        observed=host.validate_inventory(retained,fixture.run_source(host.inventory_program(retained)))
        self.assertTrue(observed['idle']);self.assertEqual(len(observed['jobs']),1)
        self.assertEqual(observed['jobs'][0]['purpose'],durable.PURPOSE)
        # Missing original terminal never makes the new purpose invisible/idle.
        job=Path(fixture.namespace['root'])/op
        terminal_path=job/'terminal.json';saved=terminal_path.with_suffix('.retained');terminal_path.rename(saved)
        try:
            unknown=host.validate_inventory(retained,fixture.run_source(host.inventory_program(retained)))
            self.assertFalse(unknown['idle']);self.assertEqual(len(unknown['jobs']),1)
            self.assertEqual(unknown['jobs'][0]['status']['state'],'unknown')
        finally:saved.rename(terminal_path)
        self.assertEqual(marker.read_text(),'once')


if __name__=='__main__':unittest.main()
