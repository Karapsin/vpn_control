"""One finite final-stage oracle; no native or imported action beyond pure modules."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
B = _fixture_root

def module(name, path, expected=None):
    return _load_source(path, expected)
A = module('_final_stage_current_fixture', _fixture_root / 'current_collector_body.py')
BEFORE=False

class FinalStageHoldTests(unittest.TestCase):
    def test_final_update_cleanup_refuses_missing_hold_before_effect(self):
        contract=A.C if not BEFORE else module('_preserved_v3_final_stage_contract',
            _fixture_root/'before/v3/collector_contract.py','4633fcb10e815868c5d112e47a7a78053412435744242aabbfc18b8b8c10f619')
        r,p,g=A.inputs();r['collectorRequest']['stage']='returned-cleanup'
        with self.assertRaisesRegex(ValueError,'final-stage-caller-hold-required'):
            contract.validate(r,{'contract':A.W.CONTRACT_SHA,'worker':A.W.WORKER_SHA},g)

    def test_intermediate_terminal_snapshot_remains_finite_without_hold(self):
        r,p,g=A.inputs();r['collectorRequest']['stage']='terminal-actors'
        A.C.validate(r,{'contract':A.W.CONTRACT_SHA,'worker':A.W.WORKER_SHA},g)

    def test_final_cleanup_with_current_hold_and_source_validates(self):
        r,p,g=A.inputs(with_hold=True);r['collectorRequest']['stage']='returned-cleanup';r['closeHold']['stage']='returned-cleanup'
        A.C.validate(r,{'contract':A.W.CONTRACT_SHA,'worker':A.W.WORKER_SHA},g)

if __name__=='__main__':
    if '--before' in sys.argv:sys.argv.remove('--before');BEFORE=True
    unittest.main()
