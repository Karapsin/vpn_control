#!/usr/bin/env python3
"""Check tracked and untracked source text, without printing file contents."""
import hashlib
from pathlib import Path
import subprocess
import sys

# These are authenticated historical bytes, not editable source. Every other
# path, and any changed byte at these paths, remains subject to normal checks.
HISTORICAL_BYTE_ARCHIVES = {
    "agent_tools/tests/fixtures/windows_cp117_historical_factory/provider_f54029cf.source":
        "f54029cf3259011d71df93c51f15b3c2b7a886470008427cf85c8e127c567a72",
    "agent_tools/tests/fixtures/android_api35_historical_arm.source":
        "4f1c26526a29d0326febc196267b4c10f46bfdbc54df94d43b8071976f49b838",
    "agent_tools/tests/fixtures/android_api35_historical_metadata.source":
        "7845714ffd2ab52e46b490c182d8505750ece842eaf49d98d12bdfe9920e8ef4",
    "agent_tools/tests/fixtures/android_api35_historical_readmission.source":
        "532b8df2fa94f1a78f40a596d33d1cda3b036abc4f81664ae3a1a7dbd8a450e0",
}

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
        if (name in HISTORICAL_BYTE_ARCHIVES
                and hashlib.sha256(path.read_bytes()).hexdigest() == HISTORICAL_BYTE_ARCHIVES[name]):
            continue
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
