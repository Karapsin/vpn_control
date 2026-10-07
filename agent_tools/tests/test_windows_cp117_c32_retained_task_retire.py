"""Causal no-replay regressions for the fixed c32 retained-task retirement."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from agent_tools import windows_cp117_c32_retained_task_retire as retire

DESC = ("windows-cp117", "/qga", 19, 29, "S-1-5-21-1-2-3-1002")
BINDING = {"retirementCorrelationId": retire._RETIREMENT, "c32CorrelationId": retire._C32,
           "generation": {"socketPath": DESC[1], "qemuPid": DESC[2], "startTicks": DESC[3], "sid": DESC[4]},
           "actionSha256": "a" * 64}


class C32RetainedTaskRetireTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(retire, "_ready", return_value=(object(), DESC, BINDING, "ready")))
        self.stack.enter_context(mock.patch.object(retire.base, "_descriptor", return_value=(object(), object(), DESC)))
        self.stack.enter_context(mock.patch.object(retire, "_binding", return_value=BINDING))
        self.stack.enter_context(mock.patch.object(retire, "_lease_lock", return_value=contextlib.nullcontext(self.root)))
        self.stack.enter_context(mock.patch.object(retire.lease, "_active", return_value=None))
        self.stack.enter_context(mock.patch.object(retire, "_no_lease", return_value=True))
        self.stack.enter_context(mock.patch.object(retire, "_parse", return_value=True))

    def test_mutation_snapshots_and_readbacks_before_unregister(self):
        source = retire._mutation_script(BINDING)
        self.assertLess(len(source.encode("utf-16le").hex()) // 2 * 4 // 3 + 4, 30000)
        self.assertIn("Write-SecureJsonCreate 'archive.json'", source)
        self.assertIn("Read-SecureJson 'archive.json'", source)
        self.assertLess(source.index("Read-SecureJson 'archive.json'"), source.index("Unregister-ScheduledTask"))
        self.assertLess(source.index("Task-Proof $true|Out-Null;No-ActiveWork", source.index("ARCHIVE_HASH")), source.index("Unregister-ScheduledTask"))
        self.assertIn("TASK_CHANGED", source)
        self.assertNotIn("Remove-Item", source)
        self.assertNotIn("Stop-Process", source)

    def test_parser_only_uses_parseinput_without_invoking_mutation(self):
        parser = retire._parse_script(retire._mutation_script(BINDING))
        self.assertIn("Parser]::ParseInput", parser)
        self.assertNotIn("Unregister-ScheduledTask", parser)
        self.assertLess(len(base64.b64encode(parser.encode("utf-16le"))), 30000)

    def test_unadmitted_preflight_creates_no_local_intent(self):
        with mock.patch.object(retire, "_ready", return_value=(None, None, None, "terminal")):
            answer = retire.preflight(self.root, {})
        self.assertEqual(("blocked", "terminal"), (answer["state"], answer["phase"]))
        self.assertFalse(retire._intent_path(self.root).exists())

    def test_lost_dispatch_response_is_unknown_and_second_start_never_replays(self):
        with mock.patch.object(retire, "_dispatch", return_value=None) as dispatch, \
             mock.patch.object(retire, "_run", return_value=None):
            first = retire.start(self.root, {})
            second = retire.start(self.root, {})
        self.assertEqual("unknown", first["state"])
        self.assertEqual("unknown", second["state"])
        self.assertTrue(retire._intent_path(self.root).exists())
        # The second call only observes journal state through status; it does not redispatch mutation.
        mutation = retire._mutation_script(BINDING)
        self.assertEqual(1, sum(c.args[3] == mutation for c in dispatch.call_args_list))

    def test_status_requires_remote_terminal_and_never_dispatches_mutation(self):
        intent = {"retirementCorrelationId": retire._RETIREMENT, "binding": BINDING,
                  "bindingSha256": retire._sha(BINDING),
                  "mutationSha256": hashlib.sha256(retire._mutation_script(BINDING).encode()).hexdigest()}
        retire.guards.secure_write_create(retire._intent_path(self.root), intent)
        with mock.patch.object(retire, "_run", return_value=None) as run:
            answer = retire.status(self.root, {})
        self.assertEqual("unknown", answer["state"])
        self.assertEqual("remote", answer["phase"])
        self.assertFalse(any(c.args[2] == retire._mutation_script(BINDING) for c in run.call_args_list))

    def test_changed_generation_and_existing_intent_never_dispatch(self):
        retire.guards.secure_write_create(retire._intent_path(self.root), {"foreign": "preserved"})
        with mock.patch.object(retire, "_run") as run:
            answer = retire.start(self.root, {})
        self.assertEqual("unknown", answer["state"])
        run.assert_not_called()

    def test_status_rejects_tampered_persisted_mutation_digest_before_remote_read(self):
        intent = {"retirementCorrelationId": retire._RETIREMENT, "binding": BINDING,
                  "bindingSha256": retire._sha(BINDING), "mutationSha256": "0" * 64}
        retire.guards.secure_write_create(retire._intent_path(self.root), intent)
        with mock.patch.object(retire, "_run") as remote:
            answer = retire.status(self.root, {})
        self.assertEqual(("unknown", "generation"), (answer["state"], answer["phase"]))
        remote.assert_not_called()

    def test_active_lease_transition_after_ready_prevents_reservation_and_dispatch(self):
        active = iter((None, {"state": "active"}))
        with mock.patch.object(retire.lease, "_active", side_effect=lambda _d: next(active)), \
             mock.patch.object(retire, "_dispatch") as dispatch:
            answer = retire.start(self.root, {})
        self.assertEqual(("blocked", "lease"), (answer["state"], answer["phase"]))
        self.assertFalse(retire._intent_path(self.root).exists())
        dispatch.assert_not_called()

    def test_remote_dispatch_active_after_child_is_unknown(self):
        """Execute the remote wrapper: a lease appearing during child work wins."""
        marker = "import base64,fcntl,json,os,stat,sys,time"
        body = marker + retire._REMOTE_DISPATCH.split(marker, 1)[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); env = root / "windows-cp117"; group = env / "windows-cp117-campaign"
            env.mkdir(mode=0o700); group.mkdir(mode=0o700)
            os.chmod(root, 0o700); os.chmod(env, 0o700); os.chmod(group, 0o700)
            lock = group / ".environment.lock"; lock.write_bytes(b""); os.chmod(lock, 0o600)
            active = group / "active.json"; output = io.StringIO()
            def call(_socket, method, _payload):
                if method == "guest-exec":
                    return {"pid": 71}
                active.write_bytes(b"became-active")
                return {"exited": True, "exitcode": 0,
                        "out-data": base64.b64encode(b'{"state":"terminal"}').decode(),
                        "out-truncated": False, "err-truncated": False}
            with mock.patch.object(sys, "argv", ["remote", str(root), "windows-cp117", "/qga", "19", "29", "encoded"]), \
                 contextlib.redirect_stdout(output):
                exec(body, {"live": lambda *_: True, "call": call, "decode": lambda raw: raw.decode("utf-8")})
            self.assertEqual({"state": "unknown"}, json.loads(output.getvalue()))

    def test_remote_dispatch_is_locked_and_rechecks_active_generation(self):
        source = retire._REMOTE_DISPATCH
        self.assertIn("fcntl.flock(fd,fcntl.LOCK_SH)", source)
        self.assertIn("active.json", source)
        self.assertGreaterEqual(source.count("live(sock,pid,ticks)"), 2)
        self.assertLess(source.index("fcntl.flock(fd,fcntl.LOCK_SH)"), source.index("guest-exec"))
        self.assertLess(source.index("guest-exec-status"), source.rindex("active.json"))

    def test_post_state_explicitly_needs_archive_projection(self):
        self.assertEqual({"state": "blocked", "phase": "archive-post-state", "baseTask": "absent", "guestLeaf": "present"},
                         {k: retire.post_state_requires_archive_projection()[k] for k in ("state", "phase", "baseTask", "guestLeaf")})

    def test_fixed_inputs_and_fixed_retirement_identity(self):
        with self.assertRaises(retire.C32RetainedTaskRetireError):
            retire.preflight(self.root, {"task": "other"})
        self.assertIn(retire._RETIREMENT, retire._mutation_script(BINDING))
        self.assertIn(retire._TASK, retire._mutation_script(BINDING))


if __name__ == "__main__":
    unittest.main()
