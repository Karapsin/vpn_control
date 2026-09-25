#!/usr/bin/env python3
"""Check tracked and untracked source text, without printing file contents."""
from pathlib import Path
import subprocess
import sys

EXCLUDED = {'.png', '.jpg', '.jpeg', '.webp', '.ico', '.aar', '.so', '.exe', '.msi', '.dmg'}


def violations(root: Path) -> list[str]:
    paths = subprocess.check_output(['git', 'ls-files', '-c', '-o', '--exclude-standard', '-z'], cwd=root)
    failures = []
    for raw in sorted(set(filter(None, paths.split(b'\0')))):
        name = raw.decode('utf-8', errors='surrogateescape')
        path = root / name
        if path.suffix.lower() in EXCLUDED or not path.exists() or path.is_dir():
            continue
        if path.is_symlink():
            continue  # Do not inspect targets outside the checkout.
        with path.open('rb') as stream:
            tail = b''
            bad = False
            binary = False
            while chunk := stream.read(65536):
                if b'\0' in chunk:
                    binary = True
                    break
                data = tail + chunk
                if any(part.endswith((b' ', b'\t', b' \r', b'\t\r')) for part in data.split(b'\n')[:-1]):
                    bad = True
                tail = data[-2:]
            if not binary and (bad or tail.endswith((b' ', b'\t', b' \r', b'\t\r'))):
                failures.append(name)
    return failures


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    failures = violations(root)
    if failures:
        print('Trailing whitespace in source files:', file=sys.stderr)
        for name in failures:
            print(name, file=sys.stderr)
        return 1
    print('Tracked and untracked source whitespace passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
