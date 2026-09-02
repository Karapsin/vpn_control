#!/usr/bin/env python3
"""Extract one version section from docs/CHANGELOG.md."""

from __future__ import annotations

import argparse
from pathlib import Path
import re


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--changelog", type=Path, default=Path(__file__).resolve().parent.parent / "docs" / "CHANGELOG.md")
    args = parser.parse_args()
    text = args.changelog.read_text(encoding="utf-8")
    heading = re.compile(rf"^##\s+{re.escape(args.version)}\s+-[^\n]*$", re.MULTILINE).search(text)
    if heading is None:
        raise SystemExit(f"Changelog section not found for {args.version}")
    next_heading = re.search(r"^##\s+", text[heading.end():], re.MULTILINE)
    end = len(text) if next_heading is None else heading.end() + next_heading.start()
    body = text[heading.end():end].strip()
    if not body:
        raise SystemExit(f"Changelog section is empty for {args.version}")
    print(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
