package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.MainUiState
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.file.Files
import java.security.MessageDigest
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.async
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopUpdateServiceTest {
    @Test
    fun windowsPowerShellHelperRelaunchUsesWorkspaceWithMockedProcessLaunches() {
        if (!System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) return
        val directory = Files.createTempDirectory("vpn-control-update-helper")
        try {
            val workspace = directory.resolve("東京 owner's workspace")
            var state = MainUiState()
            val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
                workspaceDirectory = workspace)
            val helper = directory.resolve("update helper.ps1")
            Files.writeString(helper, service.windowsHelper())
            val log = directory.resolve("relaunch.txt")
            val elevationLog = directory.resolve("elevation.txt")
            fun literal(value: String) = "'" + value.replace("'", "''") + "'"
            val command = service.windowsHelperCommand(helper, directory.resolve("update package.msi"),
                directory.resolve("fake launcher.exe").toString(), 123,
                directory.resolve("ready"), directory.resolve("error"), directory.resolve("cancel"))
            val invocation = command.drop(command.indexOf("-File") + 1).joinToString(" ", transform = ::literal)
            val wrapper = directory.resolve("test-wrapper.ps1")
            Files.writeString(wrapper, "\uFEFF" + """
                function Start-Process {
                  param([string]§FilePath, [string[]]§ArgumentList, [string]§Verb, [switch]§Wait, [switch]§PassThru)
                  if (§FilePath -eq 'powershell.exe') {
                    if (§Verb -ne 'RunAs') { throw 'Missing required authorization request' }
                    [IO.File]::WriteAllLines(${literal(elevationLog.toString())}, §ArgumentList)
                    return [pscustomobject]@{ ExitCode = 0 }
                  }
                  if (§FilePath -ne ${literal(directory.resolve("fake launcher.exe").toString())}) { throw 'Unexpected process launch' }
                  [IO.File]::WriteAllLines(${literal(log.toString())}, §ArgumentList)
                }
                & $invocation
            """.trimIndent().replace('§', '$'))
            val output = directory.resolve("powershell-output.txt")
            val process = ProcessBuilder("powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", wrapper.toString())
                .redirectErrorStream(true).redirectOutput(output.toFile()).start()
            try {
                assertTrue(process.waitFor(15, java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(0, process.exitValue(), Files.readString(output))
                assertEquals(listOf("--state-dir", "\"$workspace\""), Files.readAllLines(log))
                assertTrue(Files.readString(elevationLog).contains("\"${directory.resolve("update package.msi")}\""))
                assertFalse(Files.exists(workspace))
            } finally {
                if (process.isAlive) process.destroyForcibly()
            }
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun windowsUpdateHelperPreservesWorkspaceAndDoesNotBindAutomaticPidVariable() {
        val directory = java.nio.file.Path.of("update fixtures")
        val workspace = java.nio.file.Path.of("C:\\東京 user's workspace\\")
        var state = MainUiState()
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
            workspaceDirectory = workspace)
        val command = service.windowsHelperCommand(directory.resolve("helper.ps1"), directory.resolve("package.msi"),
            "C:\\Program Files\\vpn-control\\vpn-control.exe", 123,
            directory.resolve("ready"), directory.resolve("error"), directory.resolve("cancel"))
        assertEquals(workspace.toString(), String(java.util.Base64.getDecoder().decode(command.last()), Charsets.UTF_8))
        assertFalse(Regex(Regex.escape("\$Pid") + "\\b", RegexOption.IGNORE_CASE).containsMatchIn(service.windowsHelper()))
        assertTrue(service.windowsHelper().contains("[long]\$ParentProcessId"))
        assertTrue(service.windowsHelper().contains("--state-dir"))
    }

    @Test
    fun linuxUpdateWatcherRelaunchesTheSameWorkspaceWithoutInstallingAnything() {
        if (!Files.isExecutable(java.nio.file.Path.of("/bin/sh"))) return
        val directory = Files.createTempDirectory("vpn-control-update-relaunch")
        try {
            val workspace = directory.resolve("東京 owner's \$state & space")
            val launcher = directory.resolve("fake launcher")
            Files.writeString(launcher, "#!/bin/sh\nprintf '%s\\n' \"\$@\" > arguments.txt\n")
            assertTrue(launcher.toFile().setExecutable(true))
            var state = MainUiState()
            val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
                workspaceDirectory = workspace)
            val terminated = ProcessBuilder("/bin/sh", "-c", "exit 0").start()
            assertTrue(terminated.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
            val installed = Files.createFile(directory.resolve("installed"))
            val command = service.linuxRelaunchCommand(terminated.pid(), launcher.toString(), installed,
                directory.resolve("error"), directory.resolve("cancel"))
            assertEquals(workspace.toString(), command.last())
            val watcher = ProcessBuilder(command).directory(directory.toFile()).start()
            try {
                assertTrue(watcher.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(0, watcher.exitValue())
                val arguments = directory.resolve("arguments.txt")
                val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5)
                while ((!Files.exists(arguments) || Files.size(arguments) == 0L) && System.nanoTime() < deadline)
                    Thread.sleep(10)
                assertEquals(listOf("--state-dir", workspace.toString()), Files.readAllLines(arguments))
                assertFalse(Files.exists(workspace))
            } finally {
                if (watcher.isAlive) watcher.destroyForcibly()
            }
            // Parse only: never execute the macOS installer's package replacement commands.
            val macScript = directory.resolve("mac-helper.sh")
            Files.writeString(macScript, service.macHelper())
            val syntax = ProcessBuilder("/bin/sh", "-n", macScript.toString()).start()
            assertTrue(syntax.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(0, syntax.exitValue())
            assertTrue(service.macHelper().contains("open \"\$app_path\" --args --state-dir \"\$state_dir\""))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun checkingNeverDownloadsAndDownloadRequiresVerifiedManifestSelection() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-update-test")
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val base = "http://127.0.0.1:${server.address.port}"
        val bytes = "synthetic package, not an installer".toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        var requests = 0
        var badChecksum = false
        var declaredSize = bytes.size
        var blockManifest = false
        val manifestStarted = java.util.concurrent.CountDownLatch(1)
        val releaseManifest = java.util.concurrent.CountDownLatch(1)
        server.createContext("/manifest") { exchange ->
            if (blockManifest) {
                manifestStarted.countDown()
                check(releaseManifest.await(5, java.util.concurrent.TimeUnit.SECONDS))
            }
            val manifest = """{"schemaVersion":1,"buildNumber":2,"releaseTag":"v1.0.2",
                "releaseNotesUrl":"$base/notes","assets":[{"platform":"macos","architecture":"arm64",
                "packageType":"dmg","displayVersion":"1.0.2","fileName":"test.dmg",
                "downloadUrl":"$base/package","sha256":"${if (badChecksum) "0".repeat(64) else digest}","sizeBytes":$declaredSize}]}""".toByteArray()
            exchange.sendResponseHeaders(200, manifest.size.toLong())
            exchange.responseBody.use { it.write(manifest) }
        }
        server.createContext("/package") { exchange ->
            requests++
            exchange.sendResponseHeaders(200, bytes.size.toLong())
            exchange.responseBody.use { it.write(bytes) }
        }
        server.start()
        var state = MainUiState(isVpnRunning = true)
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
            buildInfo = DesktopBuildInfo(1, "1.0.1"), osName = "macOS", osArchitecture = "arm64",
            currentCommand = null, manifestUrl = "$base/manifest", trustUrl = { it.startsWith("$base/") })
        try {
            assertEquals("NO_UPDATE_AVAILABLE", service.downloadChecked().exceptionOrNull()?.message)
            assertTrue(service.check().getOrThrow().updateAvailable)
            assertEquals(0, requests)
            assertFalse(Files.exists(directory.resolve("test.dmg")))
            assertTrue(service.downloadChecked().isSuccess)
            assertEquals(1, requests)
            assertEquals(AppUpdatePhase.READY, state.appUpdate.phase)
            assertTrue(state.isVpnRunning)
            service.check().getOrThrow()
            assertEquals(null, state.appUpdate.preparedAsset)
            assertEquals(AppUpdatePhase.IDLE, state.appUpdate.phase)
            assertTrue(service.downloadChecked().isSuccess)
            Files.writeString(directory.resolve("test.dmg"), "tampered package")
            assertEquals("UPDATE_PACKAGE_CHANGED", service.authorizeInstallerAndWaitUntilReady(1).exceptionOrNull()?.message)
            assertEquals(AppUpdatePhase.FAILED, state.appUpdate.phase)
            assertTrue(state.isVpnRunning)
            service.dismiss()
            assertEquals("NO_UPDATE_AVAILABLE", service.downloadChecked().exceptionOrNull()?.message)
            badChecksum = true
            service.check().getOrThrow()
            assertEquals("UPDATE_DOWNLOAD_FAILED", service.downloadChecked().exceptionOrNull()?.message)
            assertEquals(AppUpdatePhase.FAILED, state.appUpdate.phase)
            assertEquals(null, state.appUpdate.preparedAsset)
            assertTrue(state.isVpnRunning)
            badChecksum = false
            declaredSize = 1
            service.check().getOrThrow()
            assertEquals("UPDATE_DOWNLOAD_FAILED", service.downloadChecked().exceptionOrNull()?.message)
            assertFalse(Files.exists(directory.resolve("test.dmg.part")))
            assertFalse(Files.exists(directory.resolve("test.dmg")))
            blockManifest = true
            val checking = async(Dispatchers.Default) { service.check() }
            assertTrue(manifestStarted.await(5, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals("BUSY", service.check().exceptionOrNull()?.message)
            assertEquals("BUSY", service.downloadChecked().exceptionOrNull()?.message)
            assertEquals("BUSY", service.dismiss().exceptionOrNull()?.message)
            releaseManifest.countDown()
            assertTrue(checking.await().isSuccess)
        } finally { releaseManifest.countDown(); server.stop(0); directory.toFile().deleteRecursively() }
    }
}
