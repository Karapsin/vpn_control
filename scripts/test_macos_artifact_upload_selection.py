#!/usr/bin/env python3
"""Run real YAML/action-glob selection and scoped macOS sealed-bundle controls."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = ROOT / "scripts/testdata/macos-artifact-upload-glob"
INPUTS = (
    "resolved-action.yml",
    "causal-glob/package.json",
    "causal-glob/package-lock.json",
    "causal-glob/test_workflow_upload_selection.mjs",
)


def main() -> int:
    node, npm = shutil.which("node"), shutil.which("npm")
    if not node or not npm:
        raise SystemExit("macOS artifact upload selection requires Node.js and npm; portable checks cannot be skipped")
    npm_entry = Path(npm).resolve()
    if npm_entry.suffix.lower() in {".cmd", ".bat"}:
        # Use the installed npm JavaScript entrypoint without a Windows shell.
        npm_entry = Path(npm).parent / "node_modules/npm/bin/npm-cli.js"
        if not npm_entry.is_file():
            raise SystemExit("installed npm JavaScript entrypoint is missing")
    npm_command = [node, str(npm_entry)] if npm_entry.suffix == ".js" else [npm]
    runtime = ROOT / ".runtime"
    runtime.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="macos-upload-selection-", dir=runtime) as owned:
        work = Path(owned)
        for relative in INPUTS:
            source, target = FIXTURE / relative, work / relative
            if source.is_symlink() or not source.is_file():
                raise SystemExit(f"missing regular upload-selection fixture: {relative}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        # Test-only locked dependencies stay in the owned runtime, never canonical node_modules.
        install = subprocess.run(
            [*npm_command, "ci", "--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(work / "npm-cache")],
            cwd=work / "causal-glob", timeout=180, check=False,
        )
        if install.returncode:
            return install.returncode
        result = subprocess.run(
            [node, str(work / "causal-glob/test_workflow_upload_selection.mjs"),
             str(ROOT / ".github/workflows/macos-update-fixture.yml"), str(work / "scratch")],
            cwd=ROOT, timeout=60, check=False,
        )
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
