#!/usr/bin/env python3
"""Fail early when a selected macOS packaging JDK is known incompatible."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import subprocess


_JAVA_OPTION_ENV = ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS")
_ARCHITECTURES = {"arm64": "aarch64", "x86_64": "x86_64"}


def require(value, message):
    if not value:
        raise ValueError(message)


def java_properties(java_home, run=subprocess.run, environment=None):
    home = Path(java_home)
    java = home / "bin" / "java"
    require(home.is_dir() and java.is_file() and not java.is_symlink(), "Selected JDK java launcher is invalid")
    child = dict(os.environ if environment is None else environment)
    for name in _JAVA_OPTION_ENV:
        child.pop(name, None)
    result = run([str(java), "-XshowSettings:properties", "-version"], text=True,
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=child, check=False)
    require(result.returncode == 0, "Selected JDK property probe failed")
    values = {}
    for line in result.stdout.splitlines():
        match = re.fullmatch(r"\s*(java\.vendor|java\.version|os\.arch)\s*=\s*(.+?)\s*", line)
        if match:
            values[match.group(1)] = match.group(2)
    require(set(values) == {"java.vendor", "java.version", "os.arch"}, "Selected JDK properties are incomplete")
    return {"java": str(java.resolve()), "vendor": values["java.vendor"],
            "version": values["java.version"], "architecture": values["os.arch"]}


def preflight(java_home, expected_architecture, *, run=subprocess.run, environment=None, system=platform.system):
    require(system() == "Darwin", "macOS packaging JDK preflight requires Darwin")
    require(expected_architecture in _ARCHITECTURES, "Unsupported expected macOS architecture")
    observed = java_properties(java_home, run=run, environment=environment)
    require("homebrew" not in observed["vendor"].casefold(),
            "Homebrew JDK is rejected for Compose macOS packaging; select a supported vendor JDK")
    require(re.fullmatch(r"17(?:\.|$).*", observed["version"]) is not None,
            "macOS packaging requires JDK 17")
    require(observed["architecture"] == _ARCHITECTURES[expected_architecture],
            "Selected JDK architecture disagrees with native package architecture")
    return {**observed, "expectedArchitecture": expected_architecture}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--java-home", type=Path, required=True)
    parser.add_argument("--expected-architecture", choices=sorted(_ARCHITECTURES), required=True)
    args = parser.parse_args()
    try:
        result = preflight(args.java_home, args.expected_architecture)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
