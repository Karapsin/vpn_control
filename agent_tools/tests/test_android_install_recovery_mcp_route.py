"""MCP admission for the exact Android unknown-install recovery boundary."""

import unittest
from unittest.mock import Mock, patch

from agent_tools import mcp_server


class AndroidInstallRecoveryRouteTest(unittest.TestCase):
    correlation = "11111111-1111-4111-8111-111111111111"
    readback = "22222222-2222-4222-8222-222222222222"
    owner = "33333333-3333-4333-8333-333333333333"
    proof_sha = "a" * 64

    def request(self):
        return {
            "installCorrelationId": self.correlation,
            "currentReadbackCorrelationId": self.readback,
            "expectedCurrentOwner": self.owner,
            "expectedCurrentRevision": 0,
        }

    def test_proof_and_release_require_exact_reviewed_inputs(self):
        adapter = Mock()
        adapter.prove_unknown_install.return_value = {
            "ok": True, "state": "proved", "correlationId": self.correlation,
            "proofSha256": self.proof_sha,
            "replayAllowed": False, "leaseReleased": False,
        }
        adapter.release_unknown_install_lease.return_value = {
            "ok": True, "state": "complete", "correlationId": self.correlation,
            "reviewedProofSha256": self.proof_sha,
            "leaseReleased": True, "replayAllowed": False,
        }
        with patch.object(mcp_server, "_agent_module", return_value=adapter):
            proof = mcp_server._vm_workflow_impl("android-package-install-unknown-proof", self.request())
            release = mcp_server._vm_workflow_impl(
                "android-package-install-unknown-release",
                {**self.request(), "reviewedProofSha256": self.proof_sha},
            )
        self.assertTrue(proof["ok"])
        self.assertTrue(release["ok"])
        self.assertFalse(proof["productAction"])
        self.assertFalse(release["productAction"])
        adapter.prove_unknown_install.assert_called_once_with(
            mcp_server.REPO_ROOT, self.correlation, self.readback, self.owner, 0,
        )
        adapter.release_unknown_install_lease.assert_called_once_with(
            mcp_server.REPO_ROOT, self.correlation, self.readback, self.owner, 0, self.proof_sha,
        )

    def test_uncertain_replayable_or_malformed_response_never_passes(self):
        adapter = Mock()
        with patch.object(mcp_server, "_agent_module", return_value=adapter):
            for state, replay, released in (
                ("unknown", False, False),
                ("proved", True, False),
                ("proved", False, True),
            ):
                adapter.prove_unknown_install.return_value = {
                    "state": state, "proofSha256": self.proof_sha,
                    "replayAllowed": replay, "leaseReleased": released,
                }
                result = mcp_server._vm_workflow_impl("android-package-install-unknown-proof", self.request())
                self.assertFalse(result["ok"])
            adapter.release_unknown_install_lease.return_value = {
                "state": "complete", "leaseReleased": True, "replayAllowed": True,
            }
            result = mcp_server._vm_workflow_impl(
                "android-package-install-unknown-release",
                {**self.request(), "reviewedProofSha256": self.proof_sha},
            )
            self.assertFalse(result["ok"])
            adapter.prove_unknown_install.return_value = {
                "ok": False, "state": "proved", "proofSha256": self.proof_sha,
                "replayAllowed": False, "leaseReleased": False,
            }
            self.assertFalse(mcp_server._vm_workflow_impl(
                "android-package-install-unknown-proof", self.request(),
            )["ok"])
            adapter.prove_unknown_install.return_value = {
                "ok": True, "state": "proved", "proofSha256": "not-a-digest",
                "replayAllowed": False, "leaseReleased": False,
            }
            self.assertFalse(mcp_server._vm_workflow_impl(
                "android-package-install-unknown-proof", self.request(),
            )["ok"])
            adapter.release_unknown_install_lease.return_value = {
                "ok": False, "state": "complete", "leaseReleased": True, "replayAllowed": False,
            }
            self.assertFalse(mcp_server._vm_workflow_impl(
                "android-package-install-unknown-release",
                {**self.request(), "reviewedProofSha256": self.proof_sha},
            )["ok"])
            adapter.prove_unknown_install.return_value = {
                "ok": True, "state": "proved", "correlationId": self.readback,
                "proofSha256": self.proof_sha, "replayAllowed": False, "leaseReleased": False,
            }
            self.assertFalse(mcp_server._vm_workflow_impl(
                "android-package-install-unknown-proof", self.request(),
            )["ok"])
            adapter.release_unknown_install_lease.return_value = {
                "ok": True, "state": "complete", "correlationId": self.correlation,
                "reviewedProofSha256": "b" * 64, "leaseReleased": True, "replayAllowed": False,
            }
            self.assertFalse(mcp_server._vm_workflow_impl(
                "android-package-install-unknown-release",
                {**self.request(), "reviewedProofSha256": self.proof_sha},
            )["ok"])
            malformed = mcp_server._vm_workflow_impl(
                "android-package-install-unknown-release",
                {**self.request(), "reviewedProofSha256": self.proof_sha, "command": "adb install"},
            )
            self.assertFalse(malformed["ok"])


if __name__ == "__main__":
    unittest.main()
