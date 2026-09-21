#!/usr/bin/env python3
"""Causal regressions for the scheduled-refresh evidence observer."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from integration import desktop_scheduled_refresh_fixture as subject

def response(document, returncode=0, args=None):
    return type("Response", (), {"returncode": returncode, "stdout": json.dumps(document), "stderr": "", "args": args or []})()

class Clock:
    def __init__(self): self.value = 100.0
    def now(self): self.value += .1; return self.value
    def sleep(self, seconds): self.value += seconds

class ScheduledRefreshFixtureTest(unittest.TestCase):
    def test_rejects_empty_wrong_and_ipv6_proxy_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            for document in ({}, {"inbounds":[{"type":"mixed","tag":"other","listen":"127.0.0.1","listen_port":1}]}, {"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"::1","listen_port":1}]}):
                (state / "runtime-config.json").write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaises(subject.ObservationError): subject.mixed_loopback_port(state)

    def test_missing_sampler_makes_zero_cli_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); calls = []
            receipt = subject.observe(self.args(root, root / "missing-curl"), run=lambda *a, **k: calls.append(a) or response({}))
            self.assertIn("curl executable", receipt["failure"]); self.assertEqual([], calls)

    @unittest.skipIf(os.name == "nt", "Windows does not enforce POSIX executable mode bits")
    def test_nonexecutable_sampler_makes_zero_cli_calls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); curl = root / "curl"; curl.write_text("x", encoding="utf-8"); calls = []
            receipt = subject.observe(self.args(root, curl), run=lambda *a, **k: calls.append(a) or response({}))
            self.assertIn("curl executable", receipt["failure"]); self.assertEqual([], calls)

    def test_fresh_evidence_directory_refuses_to_overwrite(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); evidence = root / "evidence"; evidence.mkdir(); (evidence / "old").write_text("keep", encoding="utf-8")
            receipt = subject.observe(self.args(root, self.executable(root / "curl")))
            self.assertIn("already exists", receipt["failure"]); self.assertEqual("keep", (evidence / "old").read_text(encoding="utf-8"))

    def test_continuous_samples_bracket_fast_terminal_event_and_keep_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); curl = self.executable(root / "curl"); self.setup(root); clock = Clock(); listed = 0; calls = []
            def run(argv, **_):
                nonlocal listed
                calls.append(argv)
                if argv[0] == str(curl): self.hit(root, clock.value, "curl/8.0"); return response({}, args=argv)
                if argv[-1] == "status": return response(self.status(), args=argv)
                if argv[-2:] == ["operations", "list"]:
                    listed += 1
                    if listed == 2: self.hit(root, clock.value, subject.PRODUCT_USER_AGENT)
                    return response(self.operations([] if listed == 1 else [self.operation("new", True)]), args=argv)
                if argv[-3:-1] == ["operations", "wait"]: return response({"ok":False,"final":True,"code":"RUNTIME_FAILED","controllerId":"owner","operationId":"new"}, 2, argv)
                return response({}, args=argv)
            receipt = subject.observe(self.args(root, curl), run=run, now=clock.now, sleep=clock.sleep)
            self.assertEqual("passed", receipt["result"]); self.assertEqual("RUNTIME_FAILED", receipt["operationOutcome"]["code"])
            self.assertGreaterEqual(len(receipt["samples"]), 2); self.assertTrue((root / "evidence" / "http-ledger-final.jsonl").is_file())
            self.assertGreaterEqual(receipt["continuityWindow"]["maxObservedGapSeconds"], receipt["continuityWindow"]["finalUnsampledGapSeconds"])
            curl_argv = next(x for x in calls if x[0] == str(curl)); self.assertEqual("", curl_argv[curl_argv.index("--noproxy") + 1])

    def test_controller_runtime_change_fails_even_with_traffic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); curl = self.executable(root / "curl"); self.setup(root); clock = Clock(); listed = statuses = 0
            def run(argv, **_):
                nonlocal listed, statuses
                if argv[0] == str(curl): self.hit(root, clock.value, "curl/8.0"); return response({}, args=argv)
                if argv[-1] == "status": statuses += 1; return response(self.status("changed" if statuses > 1 else "runtime"), args=argv)
                if argv[-2:] == ["operations", "list"]:
                    listed += 1
                    if listed == 2: self.hit(root, clock.value, subject.PRODUCT_USER_AGENT)
                    return response(self.operations([] if listed == 1 else [self.operation("new", True)]), args=argv)
                return response({"ok":True,"final":True,"code":"OK","controllerId":"owner","operationId":"new"}, args=argv)
            receipt = subject.observe(self.args(root, curl), run=run, now=clock.now, sleep=clock.sleep)
            self.assertEqual("failed", receipt["result"]); self.assertIn("identity changed", receipt["failure"])

    def test_failed_probe_during_scheduled_window_cannot_be_hidden_by_successful_edges(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); curl = self.executable(root / "curl"); self.setup(root); clock = Clock(); listed = sampled = 0
            def run(argv, **_):
                nonlocal listed, sampled
                if argv[0] == str(curl):
                    sampled += 1
                    if sampled != 2: self.hit(root, clock.value, "curl/8.0")
                    return response({}, 7 if sampled == 2 else 0, argv)
                if argv[-1] == "status": return response(self.status(), args=argv)
                if argv[-2:] == ["operations", "list"]:
                    listed += 1
                    if listed == 2: self.hit(root, clock.value, subject.PRODUCT_USER_AGENT)
                    rows = [] if listed == 1 else [self.operation("new", listed >= 3)]
                    return response(self.operations(rows), args=argv)
                return response({"ok":False,"final":True,"code":"RUNTIME_FAILED","controllerId":"owner","operationId":"new"}, 2, argv)
            receipt = subject.observe(self.args(root, curl), run=run, now=clock.now, sleep=clock.sleep)
            self.assertEqual("failed", receipt["result"])
            self.assertFalse(receipt["continuityWindow"]["allSamplesSucceeded"])
            self.assertEqual(7, receipt["samples"][1]["returncode"])

    def test_wait_operation_id_mismatch_fails_and_preserves_raw_wait_response(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); curl = self.executable(root / "curl"); self.setup(root); clock = Clock(); listed = 0
            def run(argv, **_):
                nonlocal listed
                if argv[0] == str(curl): self.hit(root, clock.value, "curl/8.0"); return response({}, args=argv)
                if argv[-1] == "status": return response(self.status(), args=argv)
                if argv[-2:] == ["operations", "list"]:
                    listed += 1
                    if listed == 2: self.hit(root, clock.value, subject.PRODUCT_USER_AGENT)
                    return response(self.operations([] if listed == 1 else [self.operation("new", True)]), args=argv)
                return response({"ok":True,"final":True,"code":"OK","controllerId":"owner","operationId":"other"}, args=argv)
            receipt = subject.observe(self.args(root, curl), run=run, now=clock.now, sleep=clock.sleep)
            self.assertEqual("failed", receipt["result"]); self.assertIn("did not return", receipt["failure"])
            self.assertIn("other", (root / "evidence" / "scheduled-operation-wait.json").read_text(encoding="utf-8"))

    def test_sampler_timeout_keeps_raw_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); curl = self.executable(root / "curl"); self.setup(root)
            def run(argv, **_):
                if argv[0] == str(curl): raise subprocess.TimeoutExpired(argv, 1, output=b"partial", stderr=b"late")
                return response(self.status() if argv[-1] == "status" else self.operations([]), args=argv)
            subject.observe(self.args(root, curl), run=run)
            saved = json.loads((root / "evidence" / "traffic-samples.json").read_text(encoding="utf-8"))[0]
            self.assertEqual("partial", saved["stdout"]); self.assertEqual("late", saved["stderr"])

    def args(self, root, curl): return argparse.Namespace(launcher="launcher",state_dir=str(root/"state"),ready_file=str(root/"ready.json"),ca_file=str(root/"ca.pem"),ledger=str(root/"ledger.jsonl"),evidence_dir=str(root/"evidence"),curl=str(curl),max_duration=3.0,poll_interval=.1,curl_timeout=1.0,command_timeout=1.0)
    def setup(self, root):
        state=root/"state"; state.mkdir(); (state/"runtime-config.json").write_text('{"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":50123}]}',encoding="utf-8"); (root/"ready.json").write_text('{"httpsHost":"localhost","httpsPort":4443}',encoding="utf-8"); (root/"ca.pem").write_text("ca",encoding="utf-8"); (root/"ledger.jsonl").write_text("",encoding="utf-8")
    def hit(self, root, stamp, agent):
        with (root/"ledger.jsonl").open("a",encoding="utf-8") as out: out.write(json.dumps({"timestamp":stamp,"path":"/subscription","userAgent":agent})+"\n")
    def executable(self,path): path.write_text("#!/bin/sh\nexit 0\n",encoding="utf-8"); os.chmod(path,0o700); return path
    def operation(self,identifier,final): return {"id":identifier,"requestId":"scheduled-refresh:x","operation":"subscriptions.refresh","final":final}
    def operations(self,rows): return {"ok":True,"controllerId":"owner","data":{"operations":rows}}
    def status(self,runtime="runtime"): return {"ok":True,"controllerId":"owner","data":{"runtimeRunning":True,"runtimeId":runtime,"activeLocationId":"location"}}

if __name__ == "__main__": unittest.main()
