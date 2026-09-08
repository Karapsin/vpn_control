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
    verify_sources, version_build, require_install_ready, discard_completed_stage_directory,
    desktop_install_arguments,
)
from test_fixture_environment import symlink_probe_available


class DesktopUpdateFixtureTest(unittest.TestCase):
    def setUp(self):
        # These tests create inert images with a fake Gradle executor. JVM
        # selection is exercised separately without starting a host build.
        jdk_patch = patch("prepare_desktop_update_fixture.require_jdk17")
        self.jdk_check = jdk_patch.start()
        self.addCleanup(jdk_patch.stop)

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

    def test_desktop_install_uses_owner_guard_without_android_interaction_flag(self):
        status = {"ok": True, "final": True, "controllerId": "observed-owner",
                  "configurationRevision": 9,
                  "data": {"phase": "ready", "availableVersion": "2.2.0"}}
        # The native macOS run rejected the Android-only switch before admission.
        self.assertEqual(["--json", "--controller-id", "observed-owner", "--if-revision", "9",
                          "updates", "install"], desktop_install_arguments(status, "2.2.0"))
        self.assertEqual(["--json", "--controller-id", "observed-owner", "--if-revision", "9",
                          "--async", "updates", "install"],
                         desktop_install_arguments(status, "2.2.0", asynchronous=True))
        for changes in ({"controllerId": None}, {"configurationRevision": True},
                        {"configurationRevision": -1}, {"final": False}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                desktop_install_arguments({**status, **changes}, "2.2.0")

    def test_wrong_jvm_fails_before_creating_build_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            _, _, output, _ = self.prepared(Path(temporary))
            calls, runner = self.fake_gradle()
            self.jdk_check.side_effect = ValueError("Native fixture build requires JDK 17")
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "JDK 17"):
                    native_build(output, True, runner)
            self.assertFalse((output / "packages").exists())
            self.assertEqual([], calls)

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

    def test_rejects_generated_tracked_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository, _ = self.source(root)
            (repository / ".gitignore").write_text("")
            with self.assertRaisesRegex(ValueError, "Generated"):
                source_entries(repository)

    def test_rejects_external_symlink_when_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            if not symlink_probe_available(root):
                self.skipTest("ordinary user cannot create fixture symlinks")
            repository, runtime = self.source(root)
            (repository / "escape").symlink_to(runtime)
            with self.assertRaisesRegex(ValueError, "escapes"):
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
            # Default fixture builds retain their generated trees for diagnosis;
            # this was the storage accumulation that the explicit opt-in fixes.
            self.assertTrue((output / "build-base").is_dir())
            self.assertTrue((output / "build-target").is_dir())
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
                    native_build(output, True, runner, discard_completed_builds=True)
            # The completed base may be reclaimed, but a target rejected by the
            # same-source comparison remains available for diagnosis.
            self.assertFalse((output / "build-base").exists())
            self.assertTrue((output / "build-target").is_dir())
            self.assertFalse((output / "fixture-receipt.json").exists())

    def test_opt_in_discards_only_completed_generated_build_trees_after_verified_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, _ = self.prepared(root)
            _, runner = self.fake_gradle()
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                receipt = native_build(output, True, runner, discard_completed_builds=True)
            self.assertFalse((output / "build-base").exists())
            self.assertFalse((output / "build-target").exists())
            for label, record in zip(("base", "target"), receipt["builds"]):
                evidence = json.loads((output / ("completed-" + label + ".json")).read_text())
                self.assertEqual({"schemaVersion": 1, "record": record}, evidence)
                self.assertTrue((output / record["image"]).is_dir())
            self.assertTrue((output / "source").is_dir())
            self.assertTrue((output / "packages/base").is_dir())
            self.assertTrue((output / "packages/target").is_dir())

    def test_opt_in_retains_failed_target_build_tree_and_never_writes_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, _ = self.prepared(root)
            _, successful = self.fake_gradle()

            def fail_target(command, **kwargs):
                result = successful(command, **kwargs)
                if any(value == "-PvpnControlVersion=2.1.3" for value in command):
                    return subprocess.CompletedProcess(command, 1)
                return result

            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "Native build failed"):
                    native_build(output, True, fail_target, discard_completed_builds=True)
            self.assertFalse((output / "build-base").exists())
            self.assertTrue((output / "build-target").is_dir())
            self.assertTrue((output / "completed-base.json").is_file())
            self.assertFalse((output / "completed-target.json").exists())
            self.assertFalse((output / "fixture-receipt.json").exists())

    def test_cleanup_path_defense_rejects_noncanonical_stage(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, plan = self.prepared(root)
            plan["stages"][0]["directory"] = "source"
            (output / "build-plan.json").unlink()
            (output / "build-plan.json").write_text(json.dumps(plan))
            calls, runner = self.fake_gradle()
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"):
                with self.assertRaisesRegex(ValueError, "Unexpected generated stage directory"):
                    native_build(output, True, runner, discard_completed_builds=True)
            self.assertEqual([], calls)
            self.assertTrue((output / "source").is_dir())

    def test_cleanup_path_defense_rejects_stage_symlink_when_supported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _, _, output, plan = self.prepared(root)
            protected = output / "source"
            checkout = output / "build-base"
            try:
                checkout.symlink_to(protected, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest("ordinary user cannot create directory symlinks: " + str(error))
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                discard_completed_stage_directory(output.resolve(), plan["stages"][0])
            self.assertTrue(protected.is_dir())
            self.assertTrue(checkout.is_symlink())

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


class ArchFixturePlanTest(unittest.TestCase):
    def test_explicit_arch_plan_omits_deb_rpm_while_default_retains_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = DesktopUpdateFixtureTest()
            repository, runtime = helper.source(root)
            default = prepare(repository, root / "default", "2.1.2", "2.1.3", runtime, "linux", "x86_64")
            arch = prepare(repository, root / "arch", "2.1.2", "2.1.3", runtime, "linux", "x86_64", "arch")
            default_tasks = default["stages"][0]["command"]
            arch_tasks = arch["stages"][0]["command"]
            self.assertIn(":desktopApp:packageDeb", default_tasks, "former plan reaches unsupported Arch DEB task")
            self.assertIn(":desktopApp:packageRpm", default_tasks)
            self.assertNotIn(":desktopApp:packageDeb", arch_tasks)
            self.assertNotIn(":desktopApp:packageRpm", arch_tasks)
            self.assertEqual("arch", arch["packageFamily"])
            self.assertEqual("default", default["packageFamily"])


class ArchFixtureEmissionTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "physical arch bundle modes require POSIX")
    def test_arch_family_emits_only_arch_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            helper = DesktopUpdateFixtureTest()
            root=Path(temporary); repository, runtime=helper.source(root)
            output=root/"fixture"; prepare(repository, output, "2.1.2", "2.1.3", runtime, "linux", "x86_64", "arch")
            calls, runner=helper.fake_gradle()
            with patch("platform.system", return_value="Linux"), patch("platform.machine", return_value="x86_64"), \
                    patch("prepare_desktop_update_fixture.require_jdk17") as jdk_check:
                receipt=native_build(output, True, runner)
            jdk_check.assert_called_once_with()
            self.assertTrue(all(":desktopApp:packageDeb" not in c[0] and ":desktopApp:packageRpm" not in c[0] for c in calls))
            self.assertEqual({"arch-bundle"}, {a["packageType"] for a in receipt["manifest"]["assets"]})


class FixtureArchiveExtractionTest(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "readonly archive permissions require POSIX")
    def test_delayed_extraction_handles_real_readonly_directory(self):
        from fixture_environment import extract_readonly_archive
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); source=root/"source"; source.mkdir(); (source/"child").write_text("ok")
            (source/"child").chmod(0o400)
            source.chmod(0o500)
            archive=root/"fixture.tar.gz"; subprocess.run(["tar", "-C", str(root), "-czf", str(archive), "source"], check=True)
            output=root/"out"; extract_readonly_archive(archive, output)
            self.assertEqual("ok", (output/"source/child").read_text())
            self.assertEqual(0o500, (output/"source").stat().st_mode & 0o777)
            self.assertEqual(0o400, (output/"source/child").stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
