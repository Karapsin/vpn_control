#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "check_user_facing_terminology",
    Path(__file__).with_name("check_user_facing_terminology.py"),
)
assert SPEC is not None and SPEC.loader is not None
terminology = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(terminology)


class UserFacingTerminologyTest(unittest.TestCase):
    def test_case_insensitive_forbidden_wording_is_detected_in_ui_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            catalog = repository / "shared/ui/src/commonMain/resources/i18n/en.json"
            catalog.parent.mkdir(parents=True)
            catalog.write_text(
                '{"description":"Connect to your ' + "Home" + ' Relay"}\n',
                encoding="utf-8",
            )

            self.assertEqual(
                ["shared/ui/src/commonMain/resources/i18n/en.json:1"],
                terminology.violations(repository),
            )

    def test_ssh_relay_wording_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            document = repository / "docs/ssh-routing.md"
            document.parent.mkdir(parents=True)
            document.write_text("Connect through the configured SSH relay.\n", encoding="utf-8")

            self.assertEqual([], terminology.violations(repository))


if __name__ == "__main__":
    unittest.main()
