import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from prepare_desktop_update_fixture import (
    MAIN_CLASS, MANIFEST_PATH, VERSION_RESOURCE, file_hash, image_identity, load_resources,
    native_build, package_asset, prepare, runtime_identity, select_resource, source_entries,
    verify_sources, version_build, require_install_ready,
)


class DesktopUpdateFixtureTest(unittest.TestCase):
    def test_public_ready_phase_admits_only_expected_downloaded_update(self):
        # Public installed-DMG status observed during the native coordinator run.
        status = {"ok": True, "final": True, "data": {
            "phase": "ready", "availableVersion": "2.1.16"}}
        require_install_ready(status, "2.1.16")
        for phase in ("downloading", "installing", "failed", "ready_to_install"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                require_install_ready({**status, "data": {**status["data"], "phase": phase}}, "2.1.16")
        with self.assertRaises(ValueError):
            require_install_ready(status, "2.1.17")
        with self.assertRaises(ValueError):
            require_install_ready({**status, "ok": False}, "2.1.16")

    def source(self, root):
        repository = root / "repo"
        repository.mkdir()
        subprocess.run(["git", "init", "--quiet", str(repository)], check=True, capture_output=True)
        (repository / "gradle.properties").write_text("vpnControlVersion=2.1.3\n")
        (repository / "gradlew").write_text("#!/bin/sh\nexit 99 # fixture, never executed\n")
        (repository / "gradlew").chmod(0o755)
        (repository / ".gitignore").write_text("build/\nignored-secret\n")
        (repository / "ignored-secret").write_text("not-a-source-input")
        (repository / "build").mkdir()
        (repository / "build/generated").write_text("ignored")
        (repository / "scripts").mkdir()
        (repository / "scripts/install_arch_desktop_update.sh").write_text("# inert fixture installer, never executed\n")
        runtime = root / "runtime"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        header[18:20] = (62).to_bytes(2, "little")
        runtime.write_bytes(header + b"frozen-runtime-not-executed")
        return repository, runtime

    def prepared(self, root):
        repository, runtime = self.source(root)
        output = root / "fixture"
        plan = prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
        return repository, runtime, output, plan

    def make_image(self, image, version, changed=False, short_hash=False):
        jars = image / "lib/app"
        jars.mkdir(parents=True)
        (image / "bin").mkdir()
        (image / "bin/vpn-control").write_bytes(b"\x7fELFpublic-launcher-not-executed")
        (image / "bin/vpn-control").chmod(0o755)
        target = jars / "desktopApp.jar"
        with zipfile.ZipFile(target, "w") as jar:
            jar.writestr(MAIN_CLASS, b"different-executable" if changed else b"same-frozen-executable")
            jar.writestr(VERSION_RESOURCE, f"displayVersion={version}\nbuildNumber={version_build(version)}\n")
            jar.writestr("linux-install-user.sh", "fixed-captured-worker")
        if short_hash:
            # Compose formats each MD5 byte without zero padding. Keep the ZIP
            # contents identical while deterministically obtaining such a name.
            for attempt in range(1024):
                with zipfile.ZipFile(target, "a") as jar:
                    jar.comment = str(attempt).encode()
                digest = hashlib.md5(target.read_bytes()).digest()
                suffix = "".join(format(value, "x") for value in digest)
                if len(suffix) < 32:
                    break
            self.assertLess(len(suffix), 32)
        else:
            suffix = hashlib.md5(target.read_bytes()).hexdigest()
        name = "desktopApp-" + suffix + ".jar"
        target.rename(jars / name)
        (jars / "vpn-control.cfg").write_text("[Application]\napp.classpath=$APPDIR/" + name +
            "\napp.mainclass=com.kardinal.vpncontrol.desktop.MainKt\n")
        return image

    def fake_gradle(self, changed_target=False):
        calls = []

        def run(command, *, cwd, stdout, stderr, check):
            calls.append((command, cwd))
            version = next(value.split("=", 1)[1] for value in command if value.startswith("-PvpnControlVersion="))
            root = cwd / "desktopApp/build/compose/binaries/main"
            self.make_image(root / "app/vpn-control", version, changed=changed_target and version == "2.1.3")
            for extension in ("deb", "rpm"):
                destination = root / extension
                destination.mkdir()
                (destination / ("vpn-control-" + version + "." + extension)).write_bytes(b"synthetic-" + extension.encode())
            stdout.write(b"synthetic Gradle fixture; no native package was built\n")
            return subprocess.CompletedProcess(command, 0)

        return calls, run

    def test_base20_versions_remain_exact_and_monotonic(self):
        self.assertEqual(16460, version_build("2.1.3"))
        self.assertEqual(version_build("2.0.19") + 20, version_build("2.1.0"))
        for invalid in ("0.1.1", "1.20.0", "20.0.0", "01.0.0", "1.01.0", "1.0", "1.0.0-extra"):
            with self.assertRaises(ValueError):
                version_build(invalid)

    def test_snapshot_keeps_dirty_and_untracked_source_but_no_ignored_data_or_source_edits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime, output, plan = self.prepared(root)
            snapshot = json.loads((output / "snapshot.json").read_text())
            self.assertEqual("2.1.3", snapshot["canonicalVersion"])
            self.assertEqual("vpnControlVersion=2.1.3\n", (repository / "gradle.properties").read_text())
            self.assertEqual({".gitignore", "gradle.properties", "gradlew", "scripts/install_arch_desktop_update.sh"},
                             {entry["path"] for entry in snapshot["files"]})
            self.assertFalse((output / "source/ignored-secret").exists())
            self.assertEqual(file_hash(runtime), plan["runtime"]["sha256"])
            self.assertEqual(["2.1.2", "2.1.3"], [stage["version"] for stage in plan["stages"]])
            for stage in plan["stages"]:
                self.assertIn("-PvpnControlVersion=" + stage["version"], stage["command"])
            self.assertEqual(0, (output / "source/gradle.properties").stat().st_mode & 0o222)
            verify_sources(output / "source", snapshot["files"])

    def test_rejects_generated_android_native_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository, _ = self.source(Path(temporary))
            cache = repository / "app/.cxx/build-state.json"
            cache.parent.mkdir(parents=True)
            cache.write_text("generated native cache")
            with self.assertRaisesRegex(ValueError, "Generated"):
                source_entries(repository)

    def test_rejects_external_symlink_and_generated_tracked_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            (repository / "escape").symlink_to(runtime)
            with self.assertRaisesRegex(ValueError, "escapes"):
                source_entries(repository)
            (repository / "escape").unlink()
            (repository / ".gitignore").write_text("")
            with self.assertRaisesRegex(ValueError, "Generated"):
                source_entries(repository)

    def test_excluded_gitlink_records_pin_and_empty_uninitialized_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            pin = "d09182614c7778c1e0f51d990635c5d4249c437e"
            subprocess.run(["git", "-C", str(repository), "update-index", "--add", "--cacheinfo",
                            "160000," + pin + ",native-source"], check=True, capture_output=True)
            (repository / "native-source").mkdir()
            output = root / "fixture"
            prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            snapshot = json.loads((output / "snapshot.json").read_text())
            entry = next(value for value in snapshot["files"] if value["path"] == "native-source")
            self.assertEqual(pin, entry["gitlink"]["indexCommit"])
            self.assertFalse(entry["gitlink"]["initialized"])
            self.assertIsNone(entry["gitlink"]["headCommit"])
            self.assertIsNone(entry["gitlink"]["dirty"])
            self.assertTrue(entry["excludedFromBuild"])
            self.assertFalse((output / "source/native-source").exists())
            verify_sources(output / "source", snapshot["files"])

    def test_excluded_initialized_gitlink_records_dirty_content_without_copying_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _ = self.source(root)
            submodule = repository / "native-source"
            subprocess.run(["git", "init", "--quiet", str(submodule)], check=True, capture_output=True)
            (submodule / "runtime.go").write_text("committed source\n")
            subprocess.run(["git", "-C", str(submodule), "add", "runtime.go"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(submodule), "-c", "user.name=Fixture", "-c",
                            "user.email=fixture@example.invalid", "commit", "--quiet", "-m", "fixture"],
                           check=True, capture_output=True)
            pin = subprocess.run(["git", "-C", str(submodule), "rev-parse", "HEAD"],
                                 check=True, capture_output=True, text=True).stdout.strip()
            subprocess.run(["git", "-C", str(repository), "update-index", "--add", "--cacheinfo",
                            "160000," + pin + ",native-source"], check=True, capture_output=True)
            def captured():
                return next(value["gitlink"] for value in source_entries(repository)
                            if value["path"] == "native-source")
            clean = captured()
            self.assertEqual(pin, clean["headCommit"])
            self.assertFalse(clean["dirty"])
            (submodule / "runtime.go").write_text("first dirty source\n")
            first = captured()
            self.assertTrue(first["dirty"])
            (submodule / "runtime.go").write_text("second dirty source\n")
            second = captured()
            self.assertNotEqual(first["workingTreeFingerprint"], second["workingTreeFingerprint"])
            self.assertEqual(pin, second["indexCommit"])

    def test_runtime_architecture_is_checked_from_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, runtime = self.source(root)
            self.assertEqual(runtime.stat().st_size, runtime_identity(runtime, "linux", "x86_64")["sizeBytes"])
            with self.assertRaisesRegex(ValueError, "architecture"):
                runtime_identity(runtime, "linux", "arm64")
            runtime.write_bytes(b"not an ELF")
            with self.assertRaisesRegex(ValueError, "ELF"):
                runtime_identity(runtime, "linux", "x86_64")

    def test_real_compose_unpadded_digest_names_preserve_code_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self.make_image(root / "base", "2.1.2")
            target = self.make_image(root / "target", "2.1.3", short_hash=True)
            self.assertEqual(image_identity(base, "2.1.2")["codeFingerprint"],
                             image_identity(target, "2.1.3")["codeFingerprint"])

    def test_jpackage_repacked_jars_keep_logical_identity_after_filename_hash_was_chosen(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base = self.make_image(root / "base", "2.1.2")
            target = self.make_image(root / "target", "2.1.3")
            # macOS jpackage rewrites ZIP metadata after Compose chose names.
            # Every class/resource byte and the launcher's classpath stay intact.
            for index, image in enumerate((base, target)):
                path = next((image / "lib/app").glob("*.jar"))
                with zipfile.ZipFile(path, "a") as jar:
                    jar.comment = ("repacked-" + str(index)).encode()
            self.assertEqual(image_identity(base, "2.1.2")["codeFingerprint"],
                             image_identity(target, "2.1.3")["codeFingerprint"])

    def test_declared_classpath_order_and_membership_are_part_of_executable_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = self.make_image(Path(temporary) / "app", "2.1.3")
            app = image / "lib/app"
            dependency = app / "dependency.jar"
            with zipfile.ZipFile(dependency, "w") as jar:
                jar.writestr("example/Duplicate.class", b"dependency-priority")
            config = app / "vpn-control.cfg"
            original = config.read_text()
            entry = "app.classpath=$APPDIR/dependency.jar\n"
            config.write_text(original + entry)
            first = image_identity(image, "2.1.3")["codeFingerprint"]
            config.write_text(original.replace("[Application]\n", "[Application]\n" + entry))
            self.assertNotEqual(first, image_identity(image, "2.1.3")["codeFingerprint"])
            for invalid in (original, original + entry + entry, original + "app.classpath=$APPDIR/../dependency.jar\n"):
                config.write_text(invalid)
                with self.assertRaisesRegex(ValueError, "classpath"):
                    image_identity(image, "2.1.3")

    def test_native_build_requires_confirmation_before_reading_any_input(self):
        with self.assertRaisesRegex(ValueError, "confirmation"):
            native_build(Path("/never-read"), False)

    @unittest.skipUnless(os.name == "posix", "Physical Linux tar fixture requires POSIX file modes")
    def test_two_property_builds_capture_equal_code_and_original_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _, output, _ = self.prepared(root)
            calls, runner = self.fake_gradle()
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                receipt = native_build(output, True, runner)
            self.assertEqual(2, len(calls))
            for _, checkout in calls:
                self.assertEqual("vpnControlVersion=2.1.3\n", (checkout / "gradle.properties").read_text())
            self.assertEqual("vpnControlVersion=2.1.3\n", (repository / "gradle.properties").read_text())
            base, target = receipt["builds"]
            self.assertEqual(base["codeFingerprint"], target["codeFingerprint"])
            self.assertNotEqual(base["mainJarSha256"], target["mainJarSha256"])
            manifest, resources = load_resources(output)
            self.assertEqual(16460, manifest["buildNumber"])
            self.assertEqual({"deb", "rpm", "arch-bundle"}, {asset["packageType"] for asset in manifest["assets"]})
            self.assertTrue(all(path.is_file() and not path.stat().st_mode & 0o222 for path in resources.values()))
            arch = next(asset for asset in manifest["assets"] if asset["packageType"] == "arch-bundle")
            with tarfile.open(resources[arch["fileName"]]) as archive:
                self.assertEqual(b"2.1.3\n", archive.extractfile("vpn-control-arch-update/VERSION").read())
                self.assertEqual(b"# inert fixture installer, never executed\n",
                                 archive.extractfile("vpn-control-arch-update/install.sh").read())
                self.assertTrue(archive.getmember("vpn-control-arch-update/app/bin/vpn-control").mode & 0o111)
            asset = manifest["assets"][0]
            path = resources[asset["fileName"]]
            path.chmod(0o600)
            path.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "changed"):
                load_resources(output)

    def test_windows_build_resolves_wrapper_to_its_own_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, runtime = self.source(root)
            (repository / "gradlew.bat").write_text("@exit /b 99\r\n")  # Never executed by this test.
            header = bytearray(256)
            header[:2] = b"MZ"
            header[0x3c:0x40] = (128).to_bytes(4, "little")
            header[128:132] = b"PE\0\0"
            header[132:134] = (0x8664).to_bytes(2, "little")
            runtime.write_bytes(header)
            output = root / "fixture"
            prepare(repository, output, "2.1.2", "2.1.3", runtime, "windows", "x86_64")
            calls = []

            def run(command, *, cwd, stdout, stderr, check):
                # Windows CreateProcess resolves a bare executable against the caller's
                # working directory/PATH, rather than the subprocess cwd parameter.
                self.assertEqual(str(cwd / "gradlew.bat"), command[0])
                self.assertTrue(Path(command[0]).is_file())
                calls.append(cwd)
                version = next(value.split("=", 1)[1] for value in command if value.startswith("-PvpnControlVersion="))
                binaries = cwd / "desktopApp/build/compose/binaries/main"
                self.make_image(binaries / "app/vpn-control", version)
                (binaries / "msi").mkdir()
                (binaries / "msi" / ("vpn-control-" + version + ".msi")).write_bytes(b"synthetic-msi-not-executed")
                return subprocess.CompletedProcess(command, 0)

            with patch("platform.system", return_value="Windows"), patch("platform.machine", return_value="AMD64"):
                receipt = native_build(output, True, run)
            self.assertEqual([output.resolve() / "build-base", output.resolve() / "build-target"], calls)
            self.assertEqual(receipt["builds"][0]["codeFingerprint"], receipt["builds"][1]["codeFingerprint"])

    def test_changed_target_code_never_receives_same_source_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, _ = self.prepared(root)
            _, runner = self.fake_gradle(changed_target=True)
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "executable content differ"):
                    native_build(output, True, runner)
            self.assertFalse((output / "fixture-receipt.json").exists())

    def test_frozen_source_tampering_or_architecture_mismatch_never_builds(self):
        for wrong_arch in (True, False):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _, _, output, _ = self.prepared(root)
                if not wrong_arch:
                    source = output / "source/gradle.properties"
                    source.chmod(0o600)
                    source.write_text("changed-source")
                calls, runner = self.fake_gradle()
                with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="arm64" if wrong_arch else "x86_64"):
                    with self.assertRaises(ValueError):
                        native_build(output, True, runner)
                self.assertEqual([], calls)

    def test_resource_selector_keeps_exact_production_hosts_paths_and_methods(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "fixture.deb"
            package.write_bytes(b"abc")
            asset = package_asset(package, "linux", "x86_64", "2.1.3")
            manifest = {"assets": [asset]}
            path = asset["downloadUrl"].removeprefix("https://github.com")
            self.assertEqual("manifest", select_resource("GET", MANIFEST_PATH, "github.com", manifest))
            self.assertEqual("fixture.deb", select_resource("GET", path, "github.com:443", manifest))
            for method, target, host in (("POST", path, "github.com"), ("GET", "/", "github.com"),
                                         ("GET", path, "github.com.evil.invalid"),
                                         ("GET", path + "?anything", "github.com")):
                self.assertIsNone(select_resource(method, target, host, manifest))
            self.assertEqual("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", asset["sha256"])


if __name__ == "__main__":
    unittest.main()
