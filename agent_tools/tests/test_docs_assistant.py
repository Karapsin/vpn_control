from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_tools import docs_assistant


class DocsAssistantTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        (self.root / "docs").mkdir()
        (self.root / "agent_docs").mkdir()
        (self.root / "agent_tools").mkdir()
        (self.root / "AGENTS.md").write_text(
            "# Rules\n\nNever stop the VPN without approval.\n", encoding="utf-8"
        )
        (self.root / "README.md").write_text("# Public\n\nInstall the app.\n", encoding="utf-8")
        (self.root / "agent_docs" / "testing.md").write_text(
            "# Testing\n\nRun the desktop lifecycle tests before pushing.\n",
            encoding="utf-8",
        )
        (self.root / "docs" / "ssh.md").write_text(
            "# SSH Routing\n\nUse a pinned host key.\n", encoding="utf-8"
        )
        (self.root / "agent_tools" / "README.md").write_text(
            "# Tools\n\nCall prepare_start first.\n", encoding="utf-8"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_discovery_and_grounded_search(self) -> None:
        index = self.root / ".rag_index"
        built = docs_assistant.build_docs_index(self.root, index)

        self.assertEqual(5, built.file_count)
        matches = docs_assistant.search_docs("desktop lifecycle tests", index, top_k=2)
        self.assertTrue(matches)
        self.assertEqual("agent_docs/testing.md", matches[0].chunk.path)
        self.assertRegex(matches[0].chunk.citation, r"agent_docs/testing\.md:L\d+")

    def test_stale_source_rebuilds_index(self) -> None:
        index = self.root / ".rag_index"
        docs_assistant.build_docs_index(self.root, index)
        self.assertEqual([], docs_assistant.index_freshness_warnings(self.root, index))

        with (self.root / "docs" / "ssh.md").open("a", encoding="utf-8") as handle:
            handle.write("\nThe relay is optional.\n")
        self.assertTrue(docs_assistant.index_freshness_warnings(self.root, index))

        rebuilt, warnings = docs_assistant.ensure_docs_index(self.root, index)
        self.assertIsNotNone(rebuilt)
        self.assertTrue(warnings)
        self.assertEqual([], docs_assistant.index_freshness_warnings(self.root, index))


if __name__ == "__main__":
    unittest.main()
