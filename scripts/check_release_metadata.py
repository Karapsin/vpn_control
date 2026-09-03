#!/usr/bin/env python3
"""Validate canonical version, README, and changelog alignment."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re


REPOSITORY = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("version_metadata", Path(__file__).with_name("version_metadata.py"))
assert SPEC is not None and SPEC.loader is not None
version_metadata = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(version_metadata)

README_VERSION = re.compile(r"\*\*Version:\*\*\s+`([^`]+)`")
UNRELEASED = re.compile(r"^##\s+Unreleased\s*$", re.IGNORECASE | re.MULTILINE)
RELEASE_HEADING = re.compile(r"^##\s+([0-9]+(?:\.[0-9]+){2})\s+-", re.MULTILINE)


def unreleased_bullets(text: str) -> list[str]:
    match = UNRELEASED.search(text)
    if match is None:
        return []
    next_heading = re.search(r"^##\s+", text[match.end():], re.MULTILINE)
    end = len(text) if next_heading is None else match.end() + next_heading.start()
    return [line for line in text[match.end():end].splitlines() if line.startswith("- ")]


def validate(repository: Path, require_release_ready: bool) -> None:
    version = version_metadata.read_version(repository)
    readme = (repository / "README.md").read_text(encoding="utf-8")
    changelog = (repository / "docs" / "CHANGELOG.md").read_text(encoding="utf-8")
    readme_match = README_VERSION.search(readme)
    if readme_match is None or readme_match.group(1) != version:
        raise SystemExit("README version does not match gradle.properties")
    release_match = RELEASE_HEADING.search(changelog)
    if release_match is None:
        raise SystemExit("Changelog has no three-part release section")
    if require_release_ready:
        bullets = unreleased_bullets(changelog)
        if bullets:
            raise SystemExit("Unreleased changelog entries must be rolled before publishing")
        if release_match.group(1) != version:
            raise SystemExit("Latest changelog release does not match the canonical version")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--require-release-ready", action="store_true")
    args = parser.parse_args()
    validate(args.repository.resolve(), args.require_release_ready)
    print("[vpn-control] release metadata passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
