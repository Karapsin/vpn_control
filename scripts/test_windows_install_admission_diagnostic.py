#!/usr/bin/env python3
"""Fast behavior checks for the exact Java admission diagnostic; requires JDK 17."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from unittest.mock import patch

import windows_install_admission_diagnostic as diagnostic


class WindowsInstallAdmissionDiagnosticTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="vpn-admission-diagnostic-test-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        suffix = ".exe" if os.name == "nt" else ""
        java_home = os.environ.get("JAVA_HOME")
        cls.java = Path(java_home) / "bin" / ("java" + suffix) if java_home else Path(shutil.which("java") or "")
        javac = Path(java_home) / "bin" / ("javac" + suffix) if java_home else Path(shutil.which("javac") or "")
        if not cls.java.is_file() or not javac.is_file():
            raise RuntimeError("These diagnostic behavior checks require JDK 17")
        package = cls.root / "com" / "kardinal" / "vpncontrol" / "desktop"
        package.mkdir(parents=True)
        sources = {
            'WindowsAdmissionNative.java': r'''package com.kardinal.vpncontrol.desktop;
public interface WindowsAdmissionNative { Object openDirectory(String path); String currentSid(); String programData(); }
''',
            'WindowsInstallNativeFailure.java': r'''package com.kardinal.vpncontrol.desktop;
public final class WindowsInstallNativeFailure extends java.io.IOException {
  private final int code; public WindowsInstallNativeFailure(int code) {super("Native operation failed");this.code=code;}
  public int getCode(){return code;}
}
''',
            'JnaWindowsInstallAdmission.java': r'''package com.kardinal.vpncontrol.desktop;
public final class JnaWindowsInstallAdmission implements WindowsAdmissionNative {
  public static <E extends Throwable> RuntimeException propagate(Throwable error) throws E {throw (E)error;}
  public Object openDirectory(String path){throw propagate(new WindowsInstallNativeFailure(2));}
  public String currentSid(){return "S-1-5-21-1-2-3-4";}
  public String programData(){return "C:/ProgramData";}
}
''',
            'DesktopWindowsInstallAdmission.java': r'''package com.kardinal.vpncontrol.desktop;
import java.nio.file.Path;
public final class DesktopWindowsInstallAdmission {
  public static final DesktopWindowsInstallAdmission INSTANCE=new DesktopWindowsInstallAdmission();
  public static AutoCloseable enter$default(DesktopWindowsInstallAdmission owner,Path launcher,WindowsAdmissionNative nativeApi,
      boolean pending,Object callback,int mask,Object marker){
    switch(launcher.toString()) {
      case "missing":
        try {nativeApi.openDirectory("missing-gate");}catch(Throwable error){
          if(error instanceof WindowsInstallNativeFailure && ((WindowsInstallNativeFailure)error).getCode()==2)return ()->{};
          throw JnaWindowsInstallAdmission.propagate(error);
        }
        throw new AssertionError("Expected the injected missing native gate");
      case "trust": throw new IllegalArgumentException("Unsupported installer access mask");
      case "denied": throw JnaWindowsInstallAdmission.propagate(new WindowsInstallNativeFailure(5));
      case "null-message": throw JnaWindowsInstallAdmission.propagate(new java.io.IOException());
      default: throw new IllegalArgumentException("synthetic-secret-must-not-escape");
    }
  }
}
''',
        }
        paths = []
        for name, source in sources.items():
            path = package / name
            path.write_text(source, encoding="utf-8")
            paths.append(str(path))
        compiled = subprocess.run([str(javac), "--release", "17", "-d", str(cls.root), *paths],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if compiled.returncode:
            raise AssertionError(compiled.stderr.decode("utf-8", errors="replace"))

    def test_checked_missing_gate_remains_accepted(self):
        result = diagnostic.run_probe(self.java, self.root, "missing")
        self.assertEqual("accepted", result["admission"])
        self.assertTrue(result["leaseClosed"])
        self.assertNotIn("failure", result)

    def test_true_trust_rejection_preserves_original_class_and_safe_reason(self):
        result = diagnostic.run_probe(self.java, self.root, "trust")
        self.assertEqual("rejected", result["admission"])
        self.assertEqual("java.lang.IllegalArgumentException", result["failure"]["class"])
        self.assertEqual("Unsupported installer access mask", result["failure"]["message"])

    def test_native_access_denial_preserves_numeric_code(self):
        result = diagnostic.run_probe(self.java, self.root, "denied")
        self.assertEqual("rejected", result["admission"])
        self.assertEqual("com.kardinal.vpncontrol.desktop.WindowsInstallNativeFailure", result["failure"]["class"])
        self.assertEqual(5, result["failure"]["nativeCode"])

    def test_unknown_exception_text_is_never_printed(self):
        result = diagnostic.run_probe(self.java, self.root, "unsafe-message")
        self.assertEqual("rejected", result["admission"])
        self.assertIsNone(result["failure"]["message"])
        self.assertNotIn("synthetic-secret-must-not-escape", json.dumps(result))

    def test_unicode_ancestry_survives_non_utf8_default_charset(self):
        marker = "unicode-логи-🌐"
        with patch.dict(os.environ, {"JAVA_TOOL_OPTIONS": "-Dfile.encoding=windows-1252"}):
            result = diagnostic.run_probe(self.java, self.root, marker + "/missing")
        paths = [entry.get("path", "") for entry in result["ancestrySnapshot"]]
        self.assertTrue(any(marker in path for path in paths), paths)

    def test_unicode_classpath_is_loaded_from_the_private_request(self):
        directory = self.root / "classes-логи-🌐"
        shutil.copytree(self.root / "com", directory / "com")
        with patch.dict(os.environ, {"JAVA_TOOL_OPTIONS": "-Dfile.encoding=windows-1252"}):
            result = diagnostic.run_probe(self.java, directory, "missing")
        self.assertEqual("accepted", result["admission"])
        self.assertEqual("S-1-5-21-1-2-3-4", result["principalSid"])

    def test_null_exception_message_does_not_hide_original_failure(self):
        result = diagnostic.run_probe(self.java, self.root, "null-message")
        self.assertEqual("java.io.IOException", result["failure"]["class"])
        self.assertIsNone(result["failure"]["message"])

    def test_late_jar_cannot_enter_the_captured_classpath(self):
        architecture = diagnostic.run_probe(self.java, self.root, "missing")["processArchitecture"]
        machine = 0xAA64 if architecture in ("aarch64", "arm64") else 0x8664
        fixture = self.root / "captured-classpath"
        app = fixture / "app"
        app.mkdir(parents=True)
        launcher = fixture / "vpn-control-cli.exe"
        launcher.write_bytes(b"fixture launcher")
        java_home = fixture / "jdk"
        (java_home / "bin").mkdir(parents=True)
        (java_home / "bin" / "java.exe").write_bytes(b"fixture java")
        captured = app / "captured.jar"
        with zipfile.ZipFile(captured, "w"):
            pass
        actual_probe = diagnostic.run_probe

        def added_after_inventory(java, classpath, requested_launcher, timeout_seconds):
            with zipfile.ZipFile(app / "late.jar", "w") as archive:
                for path in (self.root / "com").rglob("*.class"):
                    archive.write(path, path.relative_to(self.root).as_posix())
            return actual_probe(self.java, classpath, "missing", timeout_seconds)

        with patch.object(diagnostic, "os", SimpleNamespace(name="nt")), \
                patch.object(diagnostic, "pe_machine", return_value=machine), \
                patch.object(diagnostic, "run_probe", side_effect=added_after_inventory):
            result = diagnostic.diagnose(launcher, java_home)
        self.assertEqual("rejected", result["admission"], "An uncaptured JAR supplied the native admission implementation")
        self.assertEqual("java.lang.ClassNotFoundException", result["failure"]["class"])
        self.assertEqual(["captured.jar"], [entry["name"] for entry in result["artifact"]["jars"]])

    def test_manifest_cannot_expand_the_captured_classpath(self):
        fixture = self.root / "manifest-classpath"
        fixture.mkdir()
        extra = fixture / "extra.jar"
        with zipfile.ZipFile(extra, "w") as archive:
            for path in (self.root / "com").rglob("*.class"):
                archive.write(path, path.relative_to(self.root).as_posix())
        for name, value in (("relative", "ex\r\n tra.jar"), ("remote", "https://invalid.example/unused.jar")):
            with self.subTest(name=name):
                captured = fixture / (name + ".jar")
                with zipfile.ZipFile(captured, "w") as archive:
                    archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\ncLaSs-PaTh: " + value + "\r\n\r\n")
                    if name == "remote":
                        # All required classes are local even before the fix;
                        # this fixture never needs to contact the remote URL.
                        for path in (self.root / "com").rglob("*.class"):
                            archive.write(path, path.relative_to(self.root).as_posix())
                result = diagnostic.run_probe(self.java, captured, "missing")
                self.assertEqual("rejected", result["admission"])
                self.assertEqual("Implicit diagnostic classpath expansion", result["failure"]["message"])

    def test_jar_index_cannot_expand_the_captured_classpath(self):
        fixture = self.root / "indexed-classpath"
        fixture.mkdir()
        with zipfile.ZipFile(fixture / "extra.jar", "w") as archive:
            for path in (self.root / "com").rglob("*.class"):
                archive.write(path, path.relative_to(self.root).as_posix())
        captured = fixture / "indexed.jar"
        with zipfile.ZipFile(captured, "w") as archive:
            archive.writestr("META-INF/INDEX.LIST", "JarIndex-Version: 1.0\n\nextra.jar\ncom/kardinal/vpncontrol/desktop\n\n")
        result = diagnostic.run_probe(self.java, captured, "missing")
        self.assertEqual("rejected", result["admission"])
        self.assertEqual("Implicit diagnostic classpath expansion", result["failure"]["message"])


if __name__ == "__main__":
    unittest.main()
