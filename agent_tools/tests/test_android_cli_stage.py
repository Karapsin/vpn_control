"""Fixed current-source Android CLI staging admission tests."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from agent_tools import android_cli_stage as subject


def inventory() -> tuple[list[str], list[str]]:
    names = ["./opt", "./opt/vpn-control", "./opt/vpn-control/bin",
             "./opt/vpn-control/bin/vpn-control", "./opt/vpn-control/lib",
             "./opt/vpn-control/lib/app",
             "./opt/vpn-control/lib/app/desktopApp-a48086cde94c36db7428298e5e0bdba.jar"]
    names += [f"./opt/vpn-control/lib/app/library-{i}.jar" for i in range(14)]
    detail = ["d" if name in names[:3] or name in names[4:6] else "-" for name in names]
    return names, detail


class AndroidCliStageTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("bsdtar") and shutil.which("rpm2archive") and shutil.which("rpmbuild"),
                         "RPM archive fixture tools unavailable")
    def test_rpm6_payload_uses_bounded_archive_when_host_bsdtar_cannot_open_rpm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            top = root / "rpmbuild"
            (top / "SPECS").mkdir(parents=True)
            spec = top / "SPECS/fixture.spec"
            spec.write_text("""Name: vpn-control-stage-fixture
Version: 1.0
Release: 1
Summary: Android CLI stage test fixture
License: MIT
BuildArch: noarch
%description
Android CLI stage test fixture.
%prep
%build
%install
mkdir -p %{buildroot}/opt/vpn-control/bin %{buildroot}/opt/vpn-control/lib/app
printf '#!/bin/sh\\n' > %{buildroot}/opt/vpn-control/bin/vpn-control
chmod 755 %{buildroot}/opt/vpn-control/bin/vpn-control
printf 'app' > %{buildroot}/opt/vpn-control/lib/app/desktopApp-aaaaaaaaaaaaaaaa.jar
for i in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19; do
  printf 'library' > %{buildroot}/opt/vpn-control/lib/app/library-$i.jar
done
%files
%dir /opt
/opt/vpn-control
""")
            built = subprocess.run(["rpmbuild", "-bb", "--define", f"_topdir {top}",
                                    "--define", "_binary_payload w9.zstdio", str(spec)],
                                   capture_output=True, timeout=60)
            self.assertEqual(built.returncode, 0, built.stderr.decode("utf-8", "replace"))
            rpm = next((top / "RPMS").rglob("*.rpm"))
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            original_run = subprocess.run

            def host_without_rpm_zstd(argv, *args, **kwargs):
                if argv[:2] in (["bsdtar", "-tf"], ["bsdtar", "-tvf"]) and argv[2] == str(rpm):
                    raise subprocess.CalledProcessError(1, argv, stderr=b"Child process exited with status 70")
                return original_run(argv, *args, **kwargs)

            with mock.patch.object(subject.subprocess, "run", side_effect=host_without_rpm_zstd):
                manifest = subject._manifest(rpm, stage)
            paths = {item["path"] for item in manifest["files"]}
            self.assertIn("opt/vpn-control/bin/vpn-control", paths)
            self.assertIn("opt/vpn-control/lib/app/desktopApp-" + "a" * 16 + ".jar", paths)
            remote = root / "remote"
            remote.mkdir(mode=0o700)
            correlation = "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"
            canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            header = {"correlationId": correlation, "rpmSha256": hashlib.sha256(rpm.read_bytes()).hexdigest(),
                      "rpmSize": rpm.stat().st_size, "manifest": manifest,
                      "manifestSha256": hashlib.sha256(canonical).hexdigest()}
            received = subprocess.run([sys.executable, "-I", "-B", "-c", "exec(" + repr(subject._RECEIVE) + ")",
                                       str(remote), correlation, json.dumps(header)], input=rpm.read_bytes(),
                                      capture_output=True, timeout=30, check=True)
            self.assertEqual(json.loads(received.stdout)["state"], "published", received.stdout.decode())

    def test_real_packaged_31_hex_jar_is_admitted(self) -> None:
        names, details = inventory()
        result = subject._validate_entries(names, details)
        self.assertEqual(len(result), len(names))
        self.assertIn(("opt/vpn-control/bin/vpn-control", "-"), result)

    def test_link_and_traversal_are_rejected_before_extract(self) -> None:
        names, details = inventory()
        details[names.index("./opt/vpn-control/bin/vpn-control")] = "l"
        with self.assertRaisesRegex(ValueError, "nonregular"):
            subject._validate_entries(names, details)
        names, details = inventory()
        names[8] = "./opt/vpn-control/lib/app/../escape"
        with self.assertRaisesRegex(ValueError, "unsafe"):
            subject._validate_entries(names, details)

    def test_missing_or_duplicate_jar_is_rejected(self) -> None:
        names, details = inventory()
        names[6] = "./opt/vpn-control/lib/app/not-the-app.jar"
        with self.assertRaisesRegex(ValueError, "unique launcher/JAR"):
            subject._validate_entries(names, details)
        names, details = inventory()
        names[7] = names[6]
        with self.assertRaisesRegex(ValueError, "unsafe"):
            subject._validate_entries(names, details)

    def test_start_rejects_wrong_source_before_snapshot_or_remote(self) -> None:
        for kind in ("package", "desktop-package-target"):
            with self.subTest(kind=kind):
                artifact = {"verification": "verified", "artifact": {"platform": "linux", "artifactKind": kind,
                            "sourceSha": "a" * 40, "sha256": "b" * 64, "size": 123},
                            "location": {"localPath": "/some/vpn-control-2.2.0-1.x86_64.rpm"}}
                with mock.patch.object(subject.native_artifact_registry, "verify_artifact", return_value=artifact), \
                        mock.patch.object(subject.subprocess, "run", return_value=SimpleNamespace(stdout="c" * 40 + "\n")), \
                        mock.patch.object(subject.ssh_transport, "load_config", side_effect=AssertionError("remote reached")):
                    with self.assertRaisesRegex(ValueError, "source differs"):
                        subject.start("/unused", "archlinux", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3", "sha256-" + "b" * 64)

    def test_start_rejects_unrelated_linux_kind_before_source_or_remote(self) -> None:
        artifact = {"verification": "verified", "artifact": {"platform": "linux", "artifactKind": "apk"}}
        with mock.patch.object(subject.native_artifact_registry, "verify_artifact", return_value=artifact), \
                mock.patch.object(subject.subprocess, "run") as source:
            with self.assertRaisesRegex(ValueError, "verified Linux RPM"):
                subject.start("/unused", "archlinux", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3", "sha256-" + "b" * 64)
            source.assert_not_called()

    def test_local_archive_failure_preserves_correlation_without_remote_submission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            rpm = root / "vpn-control-2.2.1-1.x86_64.rpm"
            rpm.write_bytes(b"verified-rpm")
            digest = hashlib.sha256(rpm.read_bytes()).hexdigest()
            artifact = {"verification": "verified", "artifact": {"platform": "linux", "artifactKind": "package",
                        "sourceSha": "a" * 40, "sha256": digest, "size": rpm.stat().st_size},
                        "location": {"localPath": str(rpm)}}
            config = SimpleNamespace(hosts={"archlinux": SimpleNamespace(fixture_transfer_root=Path("/private/fixture"))})
            correlation = "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"
            with mock.patch.object(subject.native_artifact_registry, "verify_artifact", return_value=artifact), \
                    mock.patch.object(subject.subprocess, "run", return_value=SimpleNamespace(stdout="a" * 40 + "\n")), \
                    mock.patch.object(subject.ssh_transport, "load_config", return_value=config), \
                    mock.patch.object(subject.ssh_transport, "connection_host", return_value=SimpleNamespace(password=None)), \
                    mock.patch.object(subject, "_manifest", side_effect=subprocess.CalledProcessError(1, ["bsdtar"])), \
                    mock.patch.object(subject.ssh_transport, "build_ssh_argv", side_effect=AssertionError("remote reached")):
                result = subject.start(root, "archlinux", correlation, "sha256-" + digest)
            self.assertEqual(result["state"], "unknown")
            self.assertFalse(result["replayAllowed"])
            state = root / ".rag_index/android-cli-stages" / correlation
            self.assertTrue((state / "package.rpm").is_file())
            self.assertFalse((state / "intent.json").exists())

    def test_status_missing_local_intent_has_no_remote_side_effect(self) -> None:
        with mock.patch.object(subject.ssh_transport, "load_config", side_effect=AssertionError("remote reached")):
            result = subject.status("/unused", "b68a93e0-445d-4cf5-8fee-2f5d90065bd3")
        self.assertFalse(result["ok"])
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(result["replayAllowed"])

    def test_executable_stage_status_rejects_tampered_tree_and_rpm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); root.chmod(0o700)
            correlation = "b68a93e0-445d-4cf5-8fee-2f5d90065bd3"
            job = root / ("android-cli-stage-" + correlation); job.mkdir(mode=0o700)
            tree = job / "tree"; tree.mkdir(mode=0o700)
            directory = tree / "opt"; directory.mkdir(mode=0o700)
            package = job / "package.rpm"; package.write_bytes(b"rpm"); package.chmod(0o600)
            payload = tree / "opt" / "launcher"; payload.write_bytes(b"code"); payload.chmod(0o700)
            digest = lambda data: hashlib.sha256(data).hexdigest()
            manifest = {"files": [{"path": "opt/launcher", "size": 4, "sha256": digest(b"code"), "mode": 0o700}],
                        "directories": [{"path": "opt", "mode": 0o700}]}
            manifest_hash = digest(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
            intent = {"correlationId": correlation, "rpmSha256": digest(b"rpm"),
                      "rpmSize": 3, "manifestSha256": manifest_hash, "manifest": manifest}
            receipt = {"state": "published", "manifestSha256": manifest_hash, "rpmSha256": digest(b"rpm")}
            for name, value in (("intent.json", intent), ("receipt.json", receipt)):
                path = job / name; path.write_text(json.dumps(value)); path.chmod(0o600)
            command = [sys.executable, "-I", "-B", "-c", "exec(" + repr(subject._STATUS) + ")",
                       str(root), correlation, manifest_hash]
            observe = lambda: json.loads(subprocess.run(command, capture_output=True, check=True, timeout=10).stdout)
            self.assertEqual(observe()["state"], "published")
            payload.write_bytes(b"evil")
            self.assertEqual(observe()["reason"], "tree_hash_mismatch")
            payload.write_bytes(b"code")
            package.write_bytes(b"bad")
            self.assertEqual(observe()["reason"], "rpm_hash_changed")


if __name__ == "__main__":
    unittest.main()
