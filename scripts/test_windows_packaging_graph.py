"""Run the Windows packaging init script against an isolated Gradle task graph.

The fixture uses no platform plugins, SDK, packager, installer, or native runtime.
It exercises task selection and producer/output ordering with real Gradle.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


FIXTURE_BUILD = """
def registerPackagingTasks = {
def imageReady = layout.buildDirectory.file('image-ready').get().asFile
def app = tasks.register('createDistributable') {
    ext.destinationDir = objects.directoryProperty()
    destinationDir.set(layout.buildDirectory.dir('prepared image'))
    ext.packageName = objects.property(String)
    packageName.set('vpn-control')
    doLast {
        new File(destinationDir.get().asFile, packageName.get()).mkdirs()
        imageReady.text = 'ready'
        println 'FIXTURE_IMAGE_READY'
    }
}
def installers = ['packageExe', 'packageMsi'].collect { name ->
    tasks.register(name) {
        if (providers.gradleProperty('missingImageDependency').orNull != name) {
            dependsOn(app)
        }
        ext.appImage = objects.directoryProperty()
        appImage.set(providers.provider {
            if (!imageReady.isFile()) {
                throw new GradleException('App image was read before its producer completed')
            }
            def source = app.get()
            def imageName = providers.gradleProperty('wrongImage').orNull == name ?
                'unpatched-image' : source.packageName.get()
            source.destinationDir.get().dir(imageName)
        })
        doLast { println "FIXTURE_PACKAGED_${name}" }
    }
}
tasks.register('packageDistributionForCurrentOS') { dependsOn(installers) }
}
if (providers.gradleProperty('lateTaskRegistration').orNull == 'true') {
    afterEvaluate { registerPackagingTasks() }
} else {
    registerPackagingTasks()
}
"""


class WindowsPackagingGraphTest(unittest.TestCase):
    def setUp(self):
        self.repository = Path(__file__).resolve().parent.parent
        temporary = tempfile.TemporaryDirectory(prefix="vpn-windows-package-graph-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("gradlew", "gradlew.bat"):
            shutil.copy2(self.repository / name, self.root / name)
        shutil.copytree(self.repository / "gradle" / "wrapper", self.root / "gradle" / "wrapper")
        self.init_script = self.root / "windows-packaging.init.gradle"
        shutil.copy2(self.repository / "scripts" / "test_windows_packaging_graph.init.gradle", self.init_script)
        (self.root / "settings.gradle").write_text(
            "rootProject.name = 'packaging-graph-fixture'\ninclude(':desktopApp', ':unrelated')\n",
            encoding="utf-8")
        (self.root / "gradle.properties").write_text("org.gradle.configureondemand=true\n", encoding="utf-8")
        (self.root / "desktopApp").mkdir()
        (self.root / "desktopApp" / "build.gradle").write_text(FIXTURE_BUILD, encoding="utf-8")
        (self.root / "unrelated").mkdir()
        (self.root / "unrelated" / "build.gradle").write_text(
            "throw new GradleException('The unrelated project must remain unconfigured')\n", encoding="utf-8")

    def run_gradle(self, task, *properties):
        launcher = self.root / ("gradlew.bat" if os.name == "nt" else "gradlew")
        result = subprocess.run(
            [str(launcher), "--console=plain", "--offline", "--max-workers=1", "-I", str(self.init_script),
             task, *properties], cwd=self.root, capture_output=True, text=True, timeout=180)
        return result, (result.stdout + result.stderr)[-16000:]

    def test_verification_task_is_selectable_with_configuration_on_demand(self):
        result, output = self.run_gradle(":desktopApp:verifyWindowsPackageInputs")
        self.assertEqual(0, result.returncode, output)
        self.assertIn("Windows installer app-image dependency regressions passed", output)
        self.assertNotIn("FIXTURE_IMAGE_READY", output)
        self.assertNotIn("FIXTURE_PACKAGED_", output)
        self.assertFalse((self.root / "desktopApp" / "build").exists())

    def test_verification_rejects_installer_without_image_dependency(self):
        result, output = self.run_gradle(":desktopApp:verifyWindowsPackageInputs",
                                         "-PmissingImageDependency=packageMsi")
        self.assertNotEqual(0, result.returncode, output)
        self.assertIn("packageMsi must depend on createDistributable before packaging", output)
        self.assertNotIn("FIXTURE_IMAGE_READY", output)

    def test_verification_waits_for_plugin_task_registration(self):
        result, output = self.run_gradle(":desktopApp:verifyWindowsPackageInputs", "-PlateTaskRegistration=true")
        self.assertEqual(0, result.returncode, output)
        self.assertIn("Windows installer app-image dependency regressions passed", output)
        self.assertNotIn("FIXTURE_IMAGE_READY", output)

    def test_packaging_reads_both_images_only_after_producer_completes(self):
        result, output = self.run_gradle(":desktopApp:packageDistributionForCurrentOS")
        self.assertEqual(0, result.returncode, output)
        self.assertIn("FIXTURE_PACKAGED_packageExe", output)
        self.assertIn("FIXTURE_PACKAGED_packageMsi", output)
        for name in ("packageExe", "packageMsi"):
            self.assertLess(output.index("FIXTURE_IMAGE_READY"), output.index("FIXTURE_PACKAGED_" + name))

    def test_packaging_rejects_image_that_bypasses_prepared_application(self):
        result, output = self.run_gradle(":desktopApp:packageDistributionForCurrentOS", "-PwrongImage=packageMsi")
        self.assertNotEqual(0, result.returncode, output)
        self.assertIn("packageMsi must consume the patched createDistributable app image", output)
        self.assertIn("FIXTURE_IMAGE_READY", output)
        self.assertNotIn("FIXTURE_PACKAGED_packageMsi", output)


if __name__ == "__main__":
    unittest.main()
