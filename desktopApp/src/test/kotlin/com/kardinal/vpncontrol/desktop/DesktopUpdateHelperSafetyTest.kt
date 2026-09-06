package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.*

class DesktopUpdateHelperSafetyTest {
    @Test fun linuxTimeoutWithoutInstalledReceiptDoesNotRelaunch() {
        if (!Files.isExecutable(Path.of("/bin/sh"))) return
        val directory = Files.createTempDirectory("linux-update-wait")
        try {
            val tools = Files.createDirectory(directory.resolve("tools"))
            val sleep = tools.resolve("sleep")
            Files.writeString(sleep, "#!/bin/sh\nexit 0\n")
            assertTrue(sleep.toFile().setExecutable(true))
            val launcher = directory.resolve("launcher")
            val launched = directory.resolve("launched")
            Files.writeString(launcher, "#!/bin/sh\n: > '${launched}'\n")
            assertTrue(launcher.toFile().setExecutable(true))
            val owner = ProcessBuilder("/bin/sh", "-c", "exit 0").start()
            assertTrue(owner.waitFor(5, TimeUnit.SECONDS))
            val service = DesktopUpdateService({ MainUiState() }, {}, directory)
            val builder = ProcessBuilder(service.linuxRelaunchCommand(owner.pid(), launcher.toString(),
                directory.resolve("not-installed"), directory.resolve("error"), directory.resolve("cancel")))
            builder.environment()["PATH"] = tools.toString() + java.io.File.pathSeparator + System.getenv("PATH").orEmpty()
            val watcher = builder.start()
            try {
                assertTrue(watcher.waitFor(10, TimeUnit.SECONDS))
                assertEquals(1, watcher.exitValue())
                assertFalse(Files.exists(launched))
            } finally { stopTestProcess(watcher) }
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test fun macDeniedAuthorizationNeverSignalsReadyOrStartsReplacement() = macFixture(deny = true)
    @Test fun macChangedPayloadNeverSignalsReadyOrStartsReplacement() = macFixture(badHash = true)
    @Test fun macAuthorizationPrecedesReadyAndReplacementStillWaitsForOwnerExit() = macFixture()
    @Test fun macFailedCopyRestoresOriginalBundleWithoutNestingInsidePartialCopy() = macFixture(badCopy = true)

    private fun macFixture(deny: Boolean = false, badHash: Boolean = false, badCopy: Boolean = false) {
        if (!Files.isExecutable(Path.of("/bin/sh"))) return
        val directory = Files.createTempDirectory("mac-update-authorization")
        val owner = ProcessBuilder("/bin/sh", "-c", "read token").start()
        var helperProcess: Process? = null
        try {
            val ready = directory.resolve("ready")
            val error = directory.resolve("error")
            val events = directory.resolve("events")
            val authorization = directory.resolve("mock-osascript")
            Files.writeString(authorization, """
                #!/bin/sh
                set -eu
                printf '%s\n' authorization-requested >> "${'$'}HELPER_TEST_LOG"
                if [ "${'$'}HELPER_TEST_DENY" = 1 ]; then exit 1; fi
                printf '%s\n' authorization-granted >> "${'$'}HELPER_TEST_LOG"
                while [ "${'$'}1" = -e ]; do shift 2; done
                [ "${'$'}1" = -- ] && shift
                # Prove execution uses script bytes captured before authorization, not this now-mutated path.
                printf 'exit 99\n' > "${'$'}HELPER_TEST_SCRIPT"
                exec /bin/sh "${'$'}@"
            """.trimIndent())
            assertTrue(authorization.toFile().setExecutable(true))
            val mockNativeTools = """
                #!/bin/sh
                id() { printf '0\n'; }
                hdiutil() { :; }
                mktemp() { printf '%s\n' "${'$'}HELPER_TEST_MOUNT"; }
                find() { printf '%s\n' "${'$'}HELPER_TEST_MOUNT/source.app"; }
                cp() { :; }
                shasum() { printf '%s  package\n' "${'$'}HELPER_TEST_HASH"; }
                mv() { if [ "${'$'}HELPER_TEST_BAD_COPY" = 1 ]; then /bin/mv "${'$'}@"; fi; }
                rm() { if [ "${'$'}HELPER_TEST_BAD_COPY" = 1 ]; then /bin/rm "${'$'}@"; fi; }
                ditto() {
                  printf '%s\n' replacement >> "${'$'}HELPER_TEST_LOG"
                  if [ "${'$'}HELPER_TEST_BAD_COPY" = 1 ]; then
                    mkdir -p "${'$'}2/partial-copy"
                    return 1
                  fi
                }
                open() { printf '%s\n' relaunch >> "${'$'}HELPER_TEST_LOG"; }
            """.trimIndent() + "\n"
            val service = DesktopUpdateService({ MainUiState() }, {}, directory)
            val script = service.macHelper()
                .replace("/usr/bin/osascript", "'$authorization'")
                // Force the authorization branch without changing real permissions or requesting elevation.
                .replace("[ -w \"${'$'}(dirname \"${'$'}app_path\")\" ]", "false")
            val helper = directory.resolve("helper 東京 owner's.sh")
            Files.writeString(helper, mockNativeTools + script)
            val mount = Files.createDirectory(directory.resolve("mock-mount"))
            val launcher = directory.resolve("東京 owner's.app/Contents/MacOS/vpn-control")
            val application = directory.resolve("東京 owner's.app")
            if (badCopy) {
                Files.createDirectory(application)
                Files.writeString(application.resolve("original"), "original bundle")
            }
            val digest = "a".repeat(64)
            val builder = ProcessBuilder("/bin/sh", helper.toString(), directory.resolve("package.dmg").toString(),
                launcher.toString(), owner.pid().toString(), ready.toString(), error.toString(),
                directory.resolve("cancel").toString(), directory.resolve("workspace").toString(), digest)
                .redirectErrorStream(true).redirectOutput(directory.resolve("output").toFile())
            builder.environment()["HELPER_TEST_LOG"] = events.toString()
            builder.environment()["HELPER_TEST_DENY"] = if (deny) "1" else "0"
            builder.environment()["HELPER_TEST_HASH"] = if (badHash) "b".repeat(64) else digest
            builder.environment()["HELPER_TEST_MOUNT"] = mount.toString()
            builder.environment()["HELPER_TEST_SCRIPT"] = helper.toString()
            builder.environment()["HELPER_TEST_BAD_COPY"] = if (badCopy) "1" else "0"
            val process = builder.start().also { helperProcess = it }
            if (deny || badHash) {
                assertTrue(process.waitFor(5, TimeUnit.SECONDS))
                assertEquals(1, process.exitValue())
                assertFalse(Files.exists(ready))
                assertTrue(Files.exists(error))
                assertFalse(Files.readString(events).contains("replacement"))
                assertFalse(Files.readString(events).contains("relaunch"))
                assertTrue(owner.isAlive)
            } else {
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                while (!Files.exists(ready) && process.isAlive && System.nanoTime() < deadline) Thread.sleep(10)
                assertTrue(Files.exists(ready), Files.readString(directory.resolve("output")))
                assertEquals(listOf("authorization-requested", "authorization-granted"), Files.readAllLines(events))
                assertTrue(owner.isAlive)
                owner.outputStream.write("\n".toByteArray())
                owner.outputStream.close()
                assertTrue(owner.waitFor(5, TimeUnit.SECONDS))
                assertTrue(process.waitFor(5, TimeUnit.SECONDS))
                if (badCopy) {
                    assertEquals(1, process.exitValue(), Files.readString(directory.resolve("output")))
                    assertTrue(Files.exists(application.resolve("original")), "Original bundle was not restored at its exact target")
                    assertFalse(Files.exists(application.resolve("partial-copy")))
                    assertFalse(Files.readString(events).contains("relaunch"))
                } else {
                    assertEquals(0, process.exitValue(), Files.readString(directory.resolve("output")))
                    assertEquals(listOf("authorization-requested", "authorization-granted", "replacement", "relaunch"),
                        Files.readAllLines(events))
                }
            }
        } finally {
            helperProcess?.let(::stopTestProcess)
            stopTestProcess(owner)
            directory.toFile().deleteRecursively()
        }
    }

    private fun stopTestProcess(process: Process) {
        if (process.isAlive) {
            process.descendants().use { children -> children.forEach { it.destroyForcibly() } }
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
        }
    }
}
