"""Run a frozen JVM test selection in an explicitly owned native environment.

The caller verifies Java, probe and dependency hashes and chooses the intended
user before calling. This helper never provisions tools or changes permissions.
Compile NativeJvmPreflight.java into the frozen probe classpath with --release 17.
"""

import os
import re
import subprocess


def _argument(value):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("Native JVM arguments must be nonempty text without control characters")
    return value


def run_native_jvm_tests(java, probe_classpath, classpath, tests, *, runner=subprocess.run):
    java = _argument(java)
    probe = [_argument(p) for p in probe_classpath]
    dependencies = [_argument(p) for p in classpath]
    selected = [_argument(name) for name in tests]
    if not probe or not dependencies or not selected or any(
        not re.fullmatch(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*", name, re.ASCII) for name in selected
    ):
        raise ValueError("Explicit probe, dependencies and JVM test classes are required")
    preflight = runner([java, "-cp", os.pathsep.join(probe), "NativeJvmPreflight", java, *dependencies],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    admission = {"exitCode": preflight.returncode, "stdout": preflight.stdout, "stderr": preflight.stderr}
    if preflight.returncode != 0 or preflight.stdout.strip() != "VPN_CONTROL_JVM_PREFLIGHT_OK":
        return {"phase": "preflight", **admission, "exitCode": preflight.returncode or 2}
    result = runner([java, "-Djava.awt.headless=true", "-cp", os.pathsep.join(dependencies),
                     "org.junit.runner.JUnitCore", *selected], capture_output=True, text=True,
                    encoding="utf-8", errors="replace", check=False)
    return {"phase": "tests", "exitCode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
            "preflight": admission}
