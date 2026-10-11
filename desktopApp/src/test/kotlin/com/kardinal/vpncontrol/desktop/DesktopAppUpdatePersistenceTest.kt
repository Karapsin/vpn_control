package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.AppUpdatePhase
import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.model.AppLanguage
import com.kardinal.vpncontrol.model.PersistedState
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.FileTime
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class DesktopAppUpdatePersistenceTest {
    @Test
    fun downloadProgressPreservesDurableWorkspaceAndConfiguration() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-update-persistence")
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val base = "http://127.0.0.1:${server.address.port}"
        // Finite data exercises at least seventeen real 8 KiB progress reads; no installer is invoked.
        val payload = ByteArray(16 * 8192 + 37) { (it % 251).toByte() }
        val digest = MessageDigest.getInstance("SHA-256").digest(payload)
            .joinToString("") { "%02x".format(it) }
        val packageRequests = AtomicInteger()
        server.createContext("/manifest") { exchange ->
            val manifest = """{"schemaVersion":1,"buildNumber":2,"releaseTag":"v1.0.2",
                "releaseNotesUrl":"$base/notes","assets":[{"platform":"macos","architecture":"arm64",
                "packageType":"dmg","displayVersion":"1.0.2","fileName":"fixture.dmg",
                "downloadUrl":"$base/package","sha256":"$digest","sizeBytes":${payload.size}}]}""".toByteArray()
            exchange.sendResponseHeaders(200, manifest.size.toLong())
            exchange.responseBody.use { it.write(manifest) }
        }
        server.createContext("/package") { exchange ->
            packageRequests.incrementAndGet()
            exchange.sendResponseHeaders(200, payload.size.toLong())
            exchange.responseBody.use { it.write(payload) }
        }
        server.start()
        try {
            val store = DesktopStateStore(directory)
            store.writeWorkspace(DesktopWorkspace(PersistedState(appLanguage = AppLanguage.RUSSIAN), emptyList())).getOrThrow()
            val service = DesktopAppServiceFactory.createForTesting(store = store)
            val originalPersisted = store.snapshot()
            val originalMetadata = service.controlMetadata()
            val originalLocations = service.desktopLocations.toList()
            val workspace = directory.resolve("workspace.json")
            val originalBytes = Files.readAllBytes(workspace)
            val originalFileKey = Files.readAttributes(workspace, BasicFileAttributes::class.java).fileKey()
            val marker = FileTime.fromMillis(1_000)
            var progressPublications = 0
            var progressWorkspaceReplacements = 0
            var totalWorkspaceReplacements = 0
            val observedBytes = mutableListOf<Long>()

            // Replace only the external HTTP/build/platform setup. Retain the bound callback from
            // the actual constructed DesktopAppService, so this covers its production wiring too.
            val field = DesktopAppService::class.java.getDeclaredField("updateService").apply { isAccessible = true }
            val originalUpdates = field.get(service) as DesktopUpdateService
            val callbackField = DesktopUpdateService::class.java.getDeclaredField("updateState").apply { isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            val publish = callbackField.get(originalUpdates) as ((MainUiState) -> MainUiState) -> Unit
            val updates = DesktopUpdateService(
                stateProvider = { service.state },
                updateState = { transform ->
                    // The real store atomically replaces the file on each write. A fixed old
                    // mtime detects that actual write even on filesystems without fileKey support.
                    Files.setLastModifiedTime(workspace, marker)
                    assertEquals(marker, Files.getLastModifiedTime(workspace))
                    publish(transform)
                    val replaced = Files.getLastModifiedTime(workspace) != marker
                    if (replaced) totalWorkspaceReplacements++
                    val current = service.state.appUpdate
                    if (current.phase == AppUpdatePhase.DOWNLOADING && current.downloadedBytes > 0) {
                        progressPublications++
                        if (replaced) progressWorkspaceReplacements++
                        observedBytes += current.downloadedBytes
                    }
                },
                updateDirectory = store.updateDirectory(),
                buildInfo = DesktopBuildInfo(1, "1.0.1"),
                osName = "macOS",
                osArchitecture = "arm64",
                currentCommand = null,
                manifestUrl = "$base/manifest",
                trustUrl = { it.startsWith("$base/") },
                workspaceDirectory = directory,
            )
            field.set(service, updates)

            assertTrue(service.checkControlUpdate().getOrThrow().updateAvailable)
            assertEquals(0, packageRequests.get())
            assertTrue(service.downloadControlUpdate().isSuccess)
            assertEquals(1, packageRequests.get())
            assertEquals(AppUpdatePhase.READY, service.state.appUpdate.phase)
            assertEquals(payload.size.toLong(), service.state.appUpdate.downloadedBytes)
            assertEquals(payload.size.toLong(), service.state.appUpdate.totalBytes)
            assertEquals(digest, service.state.appUpdate.preparedAsset?.sha256)
            assertTrue(payload.contentEquals(Files.readAllBytes(store.updateDirectory().resolve("fixture.dmg"))))
            assertTrue(progressPublications >= 17)
            assertEquals(payload.size.toLong(), observedBytes.last())
            assertTrue(observedBytes.zipWithNext().all { (first, second) -> first < second })
            assertEquals(originalMetadata, service.controlMetadata())
            assertEquals(originalLocations, service.desktopLocations)
            assertEquals(AppLanguage.RUSSIAN, service.state.appLanguage)
            assertEquals(originalPersisted, store.snapshot())
            assertTrue(originalBytes.contentEquals(Files.readAllBytes(workspace)))
            println("progress-persistence publications=$progressPublications progressWrites=$progressWorkspaceReplacements totalWrites=$totalWorkspaceReplacements bytes=${payload.size}")
            assertEquals(0, progressWorkspaceReplacements, "Ephemeral download progress must not replace the durable workspace")
            assertEquals(0, totalWorkspaceReplacements, "App-update state must not replace the durable workspace")
            assertEquals(marker, Files.getLastModifiedTime(workspace))
            assertEquals(originalFileKey, Files.readAttributes(workspace, BasicFileAttributes::class.java).fileKey())
        } finally {
            server.stop(0)
            directory.toFile().deleteRecursively()
        }
    }
}
