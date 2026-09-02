#!/usr/bin/env python3
"""Prevent misleading relay wording from returning to user-facing surfaces."""

from __future__ import annotations

from pathlib import Path


REPOSITORY = Path(__file__).resolve().parent.parent
FORBIDDEN = "home" + " relay"
SCOPES = (
    Path("README.md"),
    Path("docs"),
    Path("agent_docs"),
    Path("shared/ui/src"),
    Path("shared/core/src"),
    Path("app/src/main"),
    Path("desktopApp/src/main"),
)
TEXT_SUFFIXES = {".json", ".kt", ".kts", ".md", ".txt"}


def scanned_files(repository: Path) -> list[Path]:
    files: list[Path] = []
    for scope in SCOPES:
        target = repository / scope
        if target.is_file():
            files.append(target)
        elif target.is_dir():
            files.extend(path for path in target.rglob("*") if path.is_file() and path.suffix in TEXT_SUFFIXES)
    return sorted(set(files))


def violations(repository: Path) -> list[str]:
    findings: list[str] = []
    for path in scanned_files(repository):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if FORBIDDEN in line.casefold():
                relative = path.relative_to(repository).as_posix()
                findings.append(f"{relative}:{line_number}")
    return findings


def main() -> int:
    findings = violations(REPOSITORY)
    if findings:
        print("Forbidden relay wording appears in user-facing documentation or UI text:")
        for finding in findings:
            print(f" - {finding}")
        return 1
    print("[vpn-control] user-facing terminology passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
