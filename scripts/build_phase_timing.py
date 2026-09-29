"""Standalone import for the fixture builder's source-bound phase recorder."""

import argparse
import json
from pathlib import Path
import subprocess
import sys

from prepare_desktop_update_fixture import PhaseRecorder


__all__ = ("PhaseRecorder",)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--pipeline-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--host-alias", required=True)
    parser.add_argument("--phase", choices=("gradle", "runtime-prep", "packaging", "upload", "guest-staging"), required=True)
    parser.add_argument("--sample", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("A direct command is required after --")
    recorder = PhaseRecorder(args.directory, args.source_sha, args.pipeline_id,
                             args.run_id, args.host_alias)
    started = recorder.start()
    result = subprocess.run(command, check=False)
    if result.returncode == 0:
        reference = recorder.finish(args.phase, args.sample, started)
        print(json.dumps(reference, sort_keys=True), file=sys.stderr)
    return result.returncode if result.returncode >= 0 else 128 - result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
