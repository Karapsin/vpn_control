"""Causal checks for the fixed one-shot Mac fixture-server stop."""
import tempfile
import unittest
from pathlib import Path

from agent_tools import macos_machine_server_stop as stop
from agent_tools import macos_machine_acceptance as acceptance


SOURCE = "a" * 40
CORRELATION = "11111111-1111-4111-8111-111111111111"
INSTANCE = "22222222-2222-4222-8222-222222222222"
JOB = "33333333-3333-4333-8333-333333333333"
OPERATION = "44444444-4444-4444-8444-444444444444"
BOOT = "55555555-5555-4555-8555-555555555555"
REQUEST = {"schemaVersion": 1, "sourceSha": SOURCE, "correlationId": CORRELATION,
           "scenario": "install", "jobId": JOB, "operationId": OPERATION,
           "bootSessionUuid": BOOT, "reservationId": "env-1234",
           "fixtureReceiptArtifactId": "sha256-" + "b" * 64,
           "serverInstanceId": INSTANCE, "serverPid": 1234,
           "serverProcessStartIdentity": "darwin:123456:123",
           "readySha256": "c" * 64}


def campaign(root: Path, *, source=SOURCE, operation=OPERATION):
    directory = acceptance._private_group(root)
    acceptance._save(directory / (CORRELATION + ".json"), {
        "request": {"sourceSha": source, "correlationId": CORRELATION,
                    "scenario": "install", "fixtureReceiptArtifactId": REQUEST["fixtureReceiptArtifactId"]},
        "admission": {"bootSessionUuid": BOOT, "reservationId": "env-1234"},
        "operationId": operation, "jobId": JOB, "state": "unknown"})


class Boundary:
    def __init__(self):
        self.calls = 0
        self.fail = False
        self.receipt = None

    def request_stop(self, request):
        self.calls += 1
        if self.fail:
            raise OSError("lost response")
        return None

    def observe_stop(self, request):
        return self.receipt


class MacServerStopTest(unittest.TestCase):
    def test_unknown_stop_is_durable_and_never_resignaled(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign(Path(directory))
            boundary = Boundary()
            boundary.fail = True
            first = stop.start(Path(directory), REQUEST, boundary)
            self.assertEqual("unknown", first["state"])
            self.assertFalse(first["replayAllowed"])
            self.assertEqual(1, boundary.calls)
            self.assertEqual(first, stop.start(Path(directory), REQUEST, boundary))
            self.assertEqual(1, boundary.calls)
            self.assertEqual("unknown", stop.status(Path(directory), CORRELATION, boundary)["state"])

    def test_correlation_cannot_be_rebound_to_a_different_generation(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign(Path(directory))
            boundary = Boundary()
            stop.start(Path(directory), REQUEST, boundary)
            with self.assertRaises(ValueError):
                stop.start(Path(directory), {**REQUEST, "serverPid": 1235}, boundary)
            self.assertEqual(1, boundary.calls)

    def test_new_correlation_cannot_signal_while_prior_stop_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign(Path(directory))
            boundary = Boundary()
            stop.start(Path(directory), REQUEST, boundary)
            with self.assertRaises(ValueError):
                stop.start(Path(directory), {**REQUEST,
                    "correlationId": "66666666-6666-4666-8666-666666666666"}, boundary)
            self.assertEqual(1, boundary.calls)

    def test_status_only_promotes_a_new_observation_and_does_not_resignal(self):
        with tempfile.TemporaryDirectory() as directory:
            campaign(Path(directory))
            boundary = Boundary()
            stop.start(Path(directory), REQUEST, boundary)
            self.assertEqual("unknown", stop.status(Path(directory), CORRELATION, boundary)["state"])
            self.assertEqual(1, boundary.calls)
            boundary.receipt = {"serverExitCode": 0, "stopReceiptFinal": True}
            final = stop.status(Path(directory), CORRELATION, boundary)
            self.assertEqual("complete", final["state"])
            self.assertEqual(boundary.receipt, stop.collect(Path(directory), CORRELATION)["receipt"])
            self.assertEqual("historical-receipt", stop.collect(Path(directory), CORRELATION)["state"])
            boundary.receipt = None  # Fresh kernel proof has become unavailable.
            self.assertEqual("unknown", stop.status(Path(directory), CORRELATION, boundary)["state"])
            self.assertEqual("historical-receipt", stop.collect(Path(directory), CORRELATION)["state"])
            self.assertEqual("unverified", stop.collect(Path(directory), CORRELATION)["currentState"])
            self.assertEqual(1, boundary.calls)

    def test_same_prefix_source_or_different_operation_cannot_signal(self):
        for altered in ({"sourceSha": "a" * 7 + "f" * 33},
                        {"operationId": "77777777-7777-4777-8777-777777777777"}):
            with self.subTest(altered=altered), tempfile.TemporaryDirectory() as directory:
                campaign(Path(directory))
                boundary = Boundary()
                with self.assertRaisesRegex(ValueError, "campaign"):
                    stop.start(Path(directory), {**REQUEST, **altered}, boundary)
                self.assertEqual(0, boundary.calls)
                self.assertFalse((Path(directory) / ".rag_index/macos-machine-server-stop" /
                                  (CORRELATION + ".json")).exists())


if __name__ == "__main__":
    unittest.main()
