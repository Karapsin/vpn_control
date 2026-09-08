#!/usr/bin/env python3
"""Isolated bytecode coverage for android_instrumentation_signatures.gradle."""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "android_instrumentation_signatures.gradle"
GRADLE = ROOT / "gradlew"


class AndroidInstrumentationSignaturesTest(unittest.TestCase):
    def run_fixture(self, source: str, expected_exit: int) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="vpn-control-android-test-signatures-") as temp:
            project = Path(temp)
            (project / "settings.gradle").write_text("rootProject.name = 'signature-fixture'\n", encoding="utf-8")
            script_path = str(SCRIPT).replace("\\", "/").replace("'", "\\'")
            (project / "build.gradle").write_text(
                "apply from: '" + script_path + "'\n" + "tasks.register('compileDebugAndroidTestKotlin')\n" + "tasks.register('compileDebugAndroidTestJavaWithJavac')\n",
                encoding="utf-8",
            )
            annotation_source, fixture_source = source.split("\n// FIXTURE\n", maxsplit=1)
            annotation_path = project / "org/junit/Test.java"
            annotation_path.parent.mkdir(parents=True)
            annotation_path.write_text(annotation_source, encoding="utf-8")
            source_path = project / "Fixture.java"
            source_path.write_text(fixture_source, encoding="utf-8")
            javac_name = "javac.exe" if os.name == "nt" else "javac"
            javac = Path(os.environ["JAVA_HOME"]) / "bin" / javac_name
            javac_path = str(javac).replace("\\", "/").replace("'", "\\'")
            annotation_arg = str(annotation_path).replace("\\", "/").replace("'", "\\'")
            fixture_arg = str(source_path).replace("\\", "/").replace("'", "\\'")
            build = project / "build.gradle"
            build.write_text(
                "apply from: '" + script_path + "'\n"
                + "tasks.register('compileDebugAndroidTestKotlin') { outputs.dir(layout.buildDirectory.dir('tmp/kotlin-classes/debugAndroidTest')); doLast { def out = file(\"$buildDir/tmp/kotlin-classes/debugAndroidTest\"); out.mkdirs(); exec { commandLine '" + javac_path + "', '-d', out, '" + annotation_arg + "', '" + fixture_arg + "' } } }\n"
                + "tasks.register('compileDebugAndroidTestJavaWithJavac')\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.pop("DYLD_INSERT_LIBRARIES", None)
            result = subprocess.run(
                [str(GRADLE.with_suffix(".bat") if os.name == "nt" else GRADLE), "--offline", "-p", str(project), "verifyDebugAndroidTestSignatures"],
                text=True,
                capture_output=True,
                env=env,
                timeout=120,
            )
            self.assertEqual(expected_exit, result.returncode, result.stdout + result.stderr)
            return result

    def test_rejects_invalid_junit_method_and_accepts_valid_and_non_test_methods(self) -> None:
        annotation = """
            package org.junit;
            import java.lang.annotation.*;
            @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
            public @interface Test {}
            // FIXTURE
        """
        invalid = annotation + """
            class Fixture {
              @org.junit.Test public void valid() {}
              @org.junit.Test public static void invalidStatic() {}
              @org.junit.Test public int invalidValue() { return 1; }
              public int ordinaryValue() { return 7; }
            }
        """
        # The single fixture covers both the accepted ordinary/value cases and
        # the causal invalid static @Test descriptor.
        result = self.run_fixture(textwrap.dedent(invalid), 1)
        self.assertIn("Fixture.invalidStatic()V", result.stdout + result.stderr)
        self.assertIn("Fixture.invalidValue()I", result.stdout + result.stderr)

        only_valid = annotation + """
            class Fixture {
              @org.junit.Test public void valid() {}
              public int ordinaryValue() { return 7; }
            }
        """
        self.run_fixture(textwrap.dedent(only_valid), 0)


if __name__ == "__main__":
    unittest.main()
