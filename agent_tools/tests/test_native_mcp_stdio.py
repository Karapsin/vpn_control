"""Real stdio public-MCP contract coverage for native workflow safety routes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

try:
    import anyio
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.types import TextContent
except ImportError:  # The normal unit-test interpreter intentionally need not install MCP.
    anyio = None


REPO_ROOT = Path(__file__).resolve().parents[2]
CHILD_SERVER = """
import sys
from pathlib import Path
from agent_tools import mcp_server

mcp_server.REPO_ROOT = Path(sys.argv[1]).resolve()
if mcp_server.MCP_SERVER is None:
    raise SystemExit("FastMCP is unavailable")
mcp_server.MCP_SERVER.run(transport="stdio")
"""


@unittest.skipIf(anyio is None, "MCP client dependency is unavailable; install agent_tools/requirements-mcp.txt")
@unittest.skipIf(os.name == "nt", "private artifact registry writes require POSIX ownership admission")
class NativeMcpStdioTest(unittest.TestCase):
    maxDiff = None

    def test_registered_stdio_tools_serialize_safe_native_results(self) -> None:
        anyio.run(self._exercise_stdio_contract)

    async def _exercise_stdio_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "desktop.tar.gz"
            payload = b"actual artifact bytes"
            artifact.write_bytes(payload)
            record = {
                "platform": "linux",
                "artifactKind": "desktop-package",
                "localPath": str(artifact),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
                "evidenceClass": "local-verified",
                "sourceSha": "a" * 40,
            }
            parameters = StdioServerParameters(
                command=sys.executable,
                args=["-c", CHILD_SERVER, str(root)],
                cwd=REPO_ROOT,
                env={**os.environ, "PYTHONPATH": str(REPO_ROOT)},
            )
            with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8") as stderr:
                async with stdio_client(parameters, errlog=stderr) as (read_stream, write_stream):
                    async with ClientSession(read_stream, write_stream) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        self.assertIn("vm_workflow", {tool.name for tool in tools.tools})

                        registered = await self._call(session, "artifact-register", record)
                        self.assertTrue(registered["ok"])
                        artifact_id = registered["artifactId"]
                        self.assertEqual("sha256-" + record["sha256"], artifact_id)

                        found = await self._call(session, "artifact-find", {"artifactId": artifact_id})
                        self.assertTrue(found["ok"])
                        self.assertEqual([artifact_id], [item["artifactId"] for item in found["matches"]])

                        verified = await self._call(session, "artifact-verify", {"artifactId": artifact_id})
                        self.assertTrue(verified["ok"])
                        self.assertEqual("verified", verified["verification"])
                        self.assertEqual("complete", verified["nextAction"]["kind"])
                        self.assertFalse(verified["nextAction"]["replayAllowed"])
                        artifact.write_bytes(b"tampered bytes")
                        mismatched = await self._call(session, "artifact-verify", {"artifactId": artifact_id})
                        self.assertFalse(mismatched["ok"])
                        self.assertEqual("mismatch", mismatched["verification"])
                        self.assertEqual("missing-dependency", mismatched["nextAction"]["kind"])
                        self._assert_private_failure_evidence(root, mismatched, "terminalFailure")

                        bundle_path = root / "invalid-bundle"
                        bundle = await self._call(session, "bundle-prepare", {
                            "scenarioId": "not-approved", "outputDirectory": str(bundle_path),
                        })
                        self.assertFalse(bundle["ok"])
                        self.assertFalse(bundle_path.exists())
                        unknown = await self._call(session, "not-a-vm-action", {
                            "secret": "must-not-escape", "command": "must-not-run",
                        })
                        self.assertFalse(unknown["ok"])
                        self.assertEqual("inspect-evidence", unknown["nextAction"]["kind"])
                        self.assertFalse(unknown["nextAction"]["replayAllowed"])
                        self._assert_private_failure_evidence(root, unknown, "terminalFailure")
                        environment = await self._call(session, "environment-status", {"observations": []})
                        self.assertTrue(environment["ok"])
                        self.assertFalse(environment["ready"])
                        unknown_scenario = await self._call(session, "scenario-status", {"correlationId": "missing-17"})
                        self.assertFalse(unknown_scenario["ok"])
                        self.assertIn(unknown_scenario["nextAction"]["kind"], {"inspect-evidence", "observe-scenario"})
                        self.assertFalse(unknown_scenario["nextAction"]["replayAllowed"])
                        self._assert_private_failure_evidence(root, unknown_scenario, "terminalFailure")

    async def _call(self, session: ClientSession, action: str, inputs: dict[str, object]) -> dict[str, object]:
        result = await session.call_tool("vm_workflow", {"action": action, "inputs": inputs})
        self.assertFalse(result.isError, result.content)
        self.assertEqual(1, len(result.content))
        self.assertIsInstance(result.content[0], TextContent)
        value = json.loads(result.content[0].text)
        self.assertIsInstance(value, dict)
        self.assertEqual("vm_workflow", value["tool"])
        return value

    def _assert_private_failure_evidence(self, root: Path, result: dict[str, object], classification: str) -> None:
        evidence = result["failureEvidence"]
        self.assertIsInstance(evidence, dict)
        self.assertEqual({"evidenceId", "evidencePath", "classification", "summaryCounts"}, set(evidence))
        self.assertEqual(classification, evidence["classification"])
        self.assertRegex(evidence["evidenceId"], r"^native-failure-[0-9a-f]{32}$")
        path = Path(evidence["evidencePath"])
        self.assertTrue(path.is_file())
        self.assertTrue(path.is_relative_to(root.resolve() / ".rag_index" / "native-failures"), (path, root))
        self.assertEqual(0o700, path.parent.stat().st_mode & 0o777)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        receipt = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(evidence["evidenceId"], receipt["evidenceId"])
        self.assertEqual(classification, receipt["classification"])
        self.assertEqual(evidence["summaryCounts"], receipt["summaryCounts"])
        self.assertFalse({"secret", "command"} & set(receipt))
        self.assertNotIn("must-not-escape", json.dumps(receipt))
        self.assertNotIn("must-not-run", json.dumps(receipt))


if __name__ == "__main__":
    unittest.main()
