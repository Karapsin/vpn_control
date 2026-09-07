#!/usr/bin/env python3
"""Build and strictly smoke-test an isolated JDK jpackage launcher.

The caller supplies a JDK 17 directory.  This script never downloads a JDK or
uses application inputs; it creates a tiny HelloMain jar in a private temporary
directory and removes it on completion.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile

COMMAND_TIMEOUT_SECONDS = 60


class LauncherPreflightError(AssertionError):
    """The supplied JDK cannot produce a clean native launcher."""


def _command_error(command: list[str], error: OSError) -> LauncherPreflightError:
    return LauncherPreflightError(f"Cannot execute {' '.join(command)}: {error}")


def run_command(command: list[str], *, runner=None) -> subprocess.CompletedProcess[str]:
    runner = subprocess.run if runner is None else runner
    try:
        return runner(command, check=False, capture_output=True, text=True,
                      timeout=COMMAND_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise LauncherPreflightError(f"Timed out after {COMMAND_TIMEOUT_SECONDS}s: {' '.join(command)}") from error
    except OSError as error:
        raise _command_error(command, error) from error


def require_linux_jdk17(jdk: Path, *, runner=None) -> None:
    if not sys.platform.startswith("linux"):
        raise LauncherPreflightError("jpackage launcher preflight is Linux-only")
    result = run_command([str(executable(jdk, "java")), "-version"], runner=runner)
    version = result.stdout + result.stderr
    if result.returncode != 0 or 'version "17.' not in version:
        raise LauncherPreflightError(
            f"Supplied JDK must be an actual JDK 17; exit={result.returncode}, output={version!r}")


def require_clean_launcher(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode != 0 or result.stdout != "JPACKAGE_LAUNCHER_OK\n" or result.stderr:
        raise LauncherPreflightError(
            "Minimal jpackage launcher must exit 0 with exact stdout and empty stderr; "
            f"exit={result.returncode}, stdout={result.stdout!r}, stderr={result.stderr!r}"
        )


def executable(jdk: Path, name: str) -> Path:
    path = jdk / "bin" / name
    if not path.is_file():
        raise LauncherPreflightError(f"Supplied JDK is missing {path}")
    return path


def run_preflight(jdk: Path, *, runner=None) -> None:
    jdk = jdk.resolve()
    require_linux_jdk17(jdk, runner=runner)
    javac = executable(jdk, "javac")
    jar = executable(jdk, "jar")
    jpackage = executable(jdk, "jpackage")
    with tempfile.TemporaryDirectory(prefix="vpn-control-jpackage-launcher-") as temporary:
        root = Path(temporary)
        source = root / "HelloMain.java"
        classes = root / "classes"
        input_dir = root / "input"
        output = root / "image"
        source.write_text(
            "public final class HelloMain { public static void main(String[] args) { "
            "System.out.println(\"JPACKAGE_LAUNCHER_OK\"); } }\n",
            encoding="utf-8",
        )
        classes.mkdir()
        input_dir.mkdir()
        for command in (
            [str(javac), "-d", str(classes), str(source)],
            [str(jar), "--create", "--file", str(input_dir / "hello.jar"), "--main-class", "HelloMain", "-C", str(classes), "."],
            [str(jpackage), "--type", "app-image", "--dest", str(output), "--name", "launcher-preflight", "--input", str(input_dir), "--main-jar", "hello.jar", "--main-class", "HelloMain", "--add-modules", "java.base"],
        ):
            result = run_command(command, runner=runner)
            if result.returncode != 0:
                raise LauncherPreflightError(
                    f"JDK command failed: {' '.join(command)}; exit={result.returncode}, "
                    f"stdout={result.stdout!r}, stderr={result.stderr!r}"
                )
        launcher = output / "launcher-preflight" / "bin" / "launcher-preflight"
        if not launcher.is_file():
            raise LauncherPreflightError(f"jpackage did not create launcher {launcher}")
        require_clean_launcher(run_command([str(launcher)], runner=runner))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, required=True, help="JDK 17 home supplied by the fixture or CI")
    args = parser.parse_args()
    run_preflight(args.jdk)


if __name__ == "__main__":
    main()
