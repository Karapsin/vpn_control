"""Actual preserved public setup caller over complete authenticated TCP RFB.

No VM, native GUI, ordinary-account credential or private runtime path is used.
The unchanged whole functions are extracted from the original failed helper and
its keyword-only fix; the host-only fixture supplies their ambient custody.
"""
import json
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from agent_tools import readiness_tart_vnc as rfb
from agent_tools.tests.test_readiness_tart_vnc import RfbEndpoint


@unittest.skipUnless(os.name == "posix", "protected RFB credential FD")
class PublicMouseCallerTests(unittest.TestCase):
    def test_actual_whole_before_caller_zero_input_red_fixed_caller_green(self):
        fixture = Path(__file__).parent / "fixtures/tart_public_mouse_signature"
        provenance = json.loads((fixture / "provenance.json").read_text())
        sources = {"before": fixture / "before.source", "fixed": fixture / "fixed.source"}
        self.assertEqual("c87fcf00ad5bc103b886a23b43a6a8fd334078948ef5fe92cc3c5da26eb2a39a", provenance["sources"]["before"]["wholeHelperSha256"])
        self.assertEqual("d38c7b9a5354de3e512bd11483659651df5d8720897dbbcd8e0cf84d3eace584", provenance["sources"]["fixed"]["wholeHelperSha256"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            root.chmod(0o700)
            for version in ("before", "fixed"):
                with self.subTest(source=version):
                    directory = root / version
                    directory.mkdir(mode=0o700)
                    endpoint = RfbEndpoint()
                    self.addCleanup(endpoint.close)
                    checks = []
                    original_run = str(uuid.uuid4())
                    actor = {"pid": 999999, "birth": "controlled:original"}

                    def guard():
                        checks.append(True)
                        return {"operationId": original_run}, {"child": actor}

                    def record(path, value):
                        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                        with os.fdopen(fd, "w") as stream:
                            json.dump(value, stream, sort_keys=True)

                    def session():
                        reader, writer = os.pipe()
                        os.write(writer, b"controlled-rfb-auth")
                        os.close(writer)
                        return rfb.ProtectedVncSession(port=endpoint.port, credential_fd=reader, guard=guard), reader

                    self.assertEqual(sources[version].name, provenance["sources"][version]["artifact"])
                    source = sources[version].read_bytes()
                    self.assertEqual(provenance["sources"][version]["functionSha256"], hashlib.sha256(source).hexdigest())
                    namespace = {"ROOT": directory, "guard": guard, "record": record, "session": session,
                                 "os": os, "uuid": uuid}
                    exec(compile(source, "<preserved-public-transition>", "exec"), namespace)
                    endpoint.receipt_probe = lambda: any((directory / "public-transitions").glob("*.json"))
                    commands = [["mouse", 1, 0, 1], ["mouse", 1, 0, 0]]
                    if version == "before":
                        with self.assertRaises(TypeError):
                            namespace["public_transition"]("public-language-selection", commands)
                        self.assertEqual([], endpoint.events)
                        records = list((directory / "public-transitions").glob("*.json"))
                        self.assertEqual(1, len(records))
                        self.assertEqual("unknown", json.loads(records[0].read_text())["state"])
                    else:
                        operation = namespace["public_transition"]("public-language-selection", commands)
                        self.assertEqual([("mouse", 1, 1, 0), ("mouse", 0, 1, 0)], endpoint.wait_events(2))
                        pending = json.loads((directory / "public-transitions" / (operation + ".json")).read_text())
                        receipt = json.loads((directory / "public-transitions" / (operation + "-transport-closed.json")).read_text())
                        self.assertEqual("unknown", pending["state"])
                        self.assertEqual("submitted_awaiting_independent_screen_observation", receipt["state"])
                        self.assertEqual(original_run, receipt["originalRun"])
                        self.assertEqual(actor, receipt["child"])
                        self.assertFalse(endpoint.missing_receipt)
                        self.assertGreaterEqual(len(checks), 5)
                    endpoint.close()
