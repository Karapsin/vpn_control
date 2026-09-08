#!/usr/bin/env python3
"""Launch instrumentation on one explicitly selected device."""
import argparse
import os
from pathlib import Path
import re
import subprocess


def run_tests(serial, test_class=None, *, repository=None, environment=None, runner=subprocess.run):
    if not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]*", serial):
        raise ValueError("Exactly one Android device serial is required")
    if test_class is not None and not re.fullmatch(r"[A-Za-z0-9_.$]+(?:#[A-Za-z0-9_$]+)?", test_class):
        raise ValueError("Use one instrumentation class or class#method selector")
    root = Path(repository) if repository is not None else Path(__file__).resolve().parent.parent
    child_environment = dict(os.environ if environment is None else environment)
    # AGP 8.7.3's --serial path mutates an immutable device list. Its provider
    # filters this environment variable before that path, preserving other devices.
    child_environment["ANDROID_SERIAL"] = serial
    launcher = root / ("gradlew.bat" if os.name == "nt" else "gradlew")
    command = [str(launcher), ":app:connectedDebugAndroidTest", "--stacktrace"]
    if test_class is not None:
        command.append("-Pandroid.testInstrumentationRunnerArguments.class=" + test_class)
    return runner(command, cwd=root, env=child_environment, check=False).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--class", dest="test_class")
    args = parser.parse_args()
    try:
        return run_tests(args.serial, args.test_class)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
