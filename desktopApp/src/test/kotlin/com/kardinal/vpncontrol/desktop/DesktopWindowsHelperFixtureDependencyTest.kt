package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertTrue

class DesktopWindowsHelperFixtureDependencyTest {
    @Test fun nativeFixtureCompilationsIncludeTheOriginalUserLauncherWhenTheyIncludeSessions() {
        val fixtureTests = listOf(
            "DesktopWindowsOriginalUserAdapterTest.kt",
            "DesktopWindowsCoordinatorAdapterTest.kt",
            "DesktopWindowsInstallHelperEntrypointTest.kt",
            "DesktopWindowsCoordinatorNativeAdmissionTest.kt",
        )
        fixtureTests.forEach { name ->
            val relative = "src/test/kotlin/com/kardinal/vpncontrol/desktop/$name"
            val sourcePath = listOf(Path.of(relative), Path.of("desktopApp").resolve(relative))
                .firstOrNull(Files::isRegularFile)
                ?: error("Missing Windows fixture source $name")
            val compileInputs = compiledSourceNames(Files.readString(sourcePath))
            if ("windows-install-helper-sessions.cs" in compileInputs) {
                assertTrue(
                    "windows-install-original-user-launch.cs" in compileInputs,
                    "$name compiles helper sessions without its original-user launcher dependency",
                )
            }
        }
    }

    private fun compiledSourceNames(source: String): Set<String> =
        Regex("""listOf\((.*?)\)\s*\.(?:forEach|map)""", setOf(RegexOption.DOT_MATCHES_ALL))
            .findAll(source)
            .flatMap { list -> Regex("\"([^\"]+\\.cs)\"").findAll(list.groupValues[1]).map { it.groupValues[1] } }
            .toSet()
}
