package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.UpdatePackageType
import com.kardinal.vpncontrol.UpdatePlatform
import java.io.ByteArrayInputStream
import java.io.InputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.security.MessageDigest
import java.security.PublicKey
import java.security.cert.Certificate
import java.util.Optional
import java.util.concurrent.CompletableFuture
import javax.net.ssl.SSLSession
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DesktopUpdateTransportProbeTest {
    private val uri = URI.create("https://github.com/Karapsin/vpn_control/releases/latest/download/update-manifest.json")
    private val correlation = "11111111-1111-4111-8111-111111111111"
    private val certificateBytes = byteArrayOf(1, 2, 3, 4, 5)
    private val manifest = """{"schemaVersion":1,"buildNumber":2,"releaseTag":"v1.0.2",
        "releaseNotesUrl":"https://github.com/Karapsin/vpn_control/releases/tag/v1.0.2",
        "assets":[{"platform":"windows","architecture":"x86_64","packageType":"msi",
        "displayVersion":"1.0.2","fileName":"target.msi",
        "downloadUrl":"https://github.com/Karapsin/vpn_control/releases/download/v1.0.2/target.msi",
        "sha256":"${"a".repeat(64)}","sizeBytes":1234}]}""".toByteArray()

    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it) }

    private fun session(): SSLSession {
        val certificate = object : Certificate("X.509") {
            override fun getEncoded(): ByteArray = certificateBytes
            override fun verify(key: PublicKey?) = Unit
            override fun verify(key: PublicKey?, sigProvider: String?) = Unit
            override fun toString() = "<test certificate>"
            override fun getPublicKey(): PublicKey = error("unused")
        }
        return java.lang.reflect.Proxy.newProxyInstance(SSLSession::class.java.classLoader,
            arrayOf(SSLSession::class.java)) { _, method, _ ->
            if (method.name == "getPeerCertificates") arrayOf(certificate) else error("Unexpected SSL method")
        } as SSLSession
    }

    private fun response(request: HttpRequest, body: ByteArray = manifest, status: Int = 200,
        finalUri: URI = uri, tls: Boolean = true, peer: Boolean = true,
        hadRedirect: Boolean = false): HttpResponse<InputStream> =
        object : HttpResponse<InputStream> {
            override fun statusCode() = status
            override fun request() = request
            override fun previousResponse(): Optional<HttpResponse<InputStream>> = if (hadRedirect)
                Optional.of(response(request, status = 302)) else Optional.empty()
            override fun headers(): HttpHeaders = HttpHeaders.of(emptyMap()) { _, _ -> true }
            override fun body(): InputStream = ByteArrayInputStream(body)
            override fun sslSession(): Optional<SSLSession> = when {
                !tls -> Optional.empty()
                peer -> Optional.of(session())
                else -> Optional.of(java.lang.reflect.Proxy.newProxyInstance(SSLSession::class.java.classLoader,
                    arrayOf(SSLSession::class.java)) { _, method, _ ->
                    if (method.name == "getPeerCertificates") emptyArray<Certificate>() else error("Unexpected SSL method")
                } as SSLSession)
            }
            override fun uri() = finalUri
            override fun version() = HttpClient.Version.HTTP_1_1
        }

    private suspend fun read(response: HttpResponse<InputStream>): DesktopUpdateTransportProbe =
        readDesktopUpdateTransportProbe(CompletableFuture.completedFuture(response), uri, correlation,
            { it.startsWith("https://github.com/Karapsin/vpn_control/") }, 1,
            UpdatePlatform.WINDOWS, listOf(UpdatePackageType.MSI), "amd64")

    @Test
    fun ownerProbeReturnsExactPeerAndManifestHashesWithoutChangingStateOrCache() = runBlocking {
        val directory = Files.createTempDirectory("vpn-control-transport-probe")
        var state = MainUiState(isVpnRunning = true)
        var captured: HttpRequest? = null
        var tls = true
        val service = DesktopUpdateService({ state }, { state = it(state) }, directory,
            buildInfo = DesktopBuildInfo(1, "1.0.1"), osName = "Windows 11", osArchitecture = "amd64",
            probeResponseFactory = { request ->
                captured = request
                CompletableFuture.completedFuture(response(request, tls = tls))
            })
        try {
            val before = state
            val result = service.probeTransport(correlation).getOrThrow()
            assertEquals(correlation, result.correlationId)
            assertEquals(sha(manifest), result.manifestSha256)
            assertEquals(sha(certificateBytes), result.peerCertificateSha256)
            assertEquals(2, result.manifestBuildNumber)
            assertEquals("1.0.2", result.availableVersion)
            assertEquals("a".repeat(64), result.assetSha256)
            assertEquals(1234L, result.assetSizeBytes)
            assertEquals(correlation, captured?.headers()?.firstValue("X-VPN-Control-Probe-Id")?.orElse(null))
            assertEquals(uri, captured?.uri())
            assertEquals(before, state)
            assertEquals(null, service.checkedStatus())
            assertFalse(Files.exists(directory.resolve("target.msi")))
            assertTrue(Files.list(directory).use { it.findAny().isEmpty })
            assertEquals("INVALID_ARGUMENT", service.probeTransport("not-a-uuid").exceptionOrNull()?.message)
            tls = false
            assertEquals("UPDATE_TRANSPORT_PROBE_FAILED", service.probeTransport(
                "22222222-2222-4222-8222-222222222222").exceptionOrNull()?.message)
            assertEquals(before, state)
            assertEquals(null, service.checkedStatus())
            assertTrue(Files.list(directory).use { it.findAny().isEmpty })
        } finally { directory.toFile().deleteRecursively() }
    }

    @Test
    fun probeFailsClosedForMissingTlsPeerRedirectHttpAndOversize() = runBlocking {
        val request = HttpRequest.newBuilder(uri).GET().build()
        val redirected = URI.create("https://github.com/Karapsin/vpn_control/releases/other")
        for (item in listOf(
            response(request, tls = false), response(request, peer = false),
            response(request, finalUri = redirected), response(request, hadRedirect = true),
            response(request, status = 302),
            response(request, body = ByteArray(1024 * 1024 + 1)),
        )) assertFailsWith<Exception> { read(item) }
        val plain = URI.create("http://github.com/Karapsin/vpn_control/releases/latest/download/update-manifest.json")
        assertFailsWith<Exception> {
            readDesktopUpdateTransportProbe(CompletableFuture.completedFuture(response(
                HttpRequest.newBuilder(plain).GET().build(), finalUri = plain)), plain, correlation,
                { true }, 1, UpdatePlatform.WINDOWS, listOf(UpdatePackageType.MSI), "amd64")
        }
        Unit
    }
}
