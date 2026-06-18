package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProfileBenchmark
import com.kardinal.vpncontrol.model.ProfileSelection
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidActiveConnectionVerifierTest {
    @Test
    fun activeVerificationTimesOutAndCancelsHangingProxyCall() = runBlocking {
        val server = ServerSocket(0)
        val acceptedSocket = AtomicReference<Socket?>()
        val serverThread = Thread {
            runCatching {
                val socket = server.accept()
                acceptedSocket.set(socket)
                while (!Thread.currentThread().isInterrupted) {
                    Thread.sleep(50L)
                }
            }
        }.apply {
            start()
        }
        val logs = mutableListOf<String>()

        try {
            val verifier = AndroidActiveConnectionVerifier(
                browserUserAgent = "test-agent",
                genericSecondaryBlockedMarkers = emptyList(),
                chatGptBlockedMarkers = emptyList(),
                diagnosticsLogger = { logs += it },
            )

            val benchmark = verifier.verify(
                attempt = activeAttempt(server.localPort),
                url = "https://chatgpt.com/sensitive-path?token=secret",
                settings = ValidationRuntimeSettings(
                    profileTimeoutMillis = 100L,
                    connectTimeoutSeconds = 5,
                    maxTimeSeconds = 5,
                ),
            ).getOrThrow()

            assertEquals("timeout", benchmark.testStatus)
            assertTrue(benchmark.detail.contains("active_verification_timeout"))
            assertTrue(logs.any { it.contains("Active verification started") })
            assertTrue(logs.any { it.contains("Active verification timed out") })
            assertTrue(logs.all { it.contains("targetHost=chatgpt.com") || !it.contains("targetHost=") })
            assertFalse(logs.joinToString("\n").contains("secret"))
        } finally {
            acceptedSocket.get()?.close()
            server.close()
            serverThread.interrupt()
            serverThread.join(500L)
        }
    }

    private fun activeAttempt(port: Int): ProfileSelectionAttempt {
        val selection = profileSelection("Timeout Candidate")
        val preflight = PreflightResult(
            profile = selection.profile,
            connectMillis = 50.0,
            detail = "Timeout Candidate: tcp=50.0ms country=DE",
            candidateCountryCode = "DE",
        )
        return ProfileSelectionAttempt(
            selection = selection,
            preflight = preflight,
            activeVerificationPort = port,
        )
    }

    private fun profileSelection(name: String): ProfileSelection {
        val profile = ProxyProfile(
            protocol = ProxyProtocol.VLESS,
            remarks = name,
            server = "test.example.net",
            serverPort = 443,
            uuid = "11111111-1111-4111-8111-111111111111",
            network = "tcp",
            flow = "",
            security = "tls",
            sni = "test.example.net",
            fingerprint = "",
            publicKey = "",
            shortId = "",
            path = "",
            hostHeader = "",
            serviceName = "",
            headerType = "",
            rawLink = "vless://test#$name",
        )
        return ProfileSelection(
            profile = profile,
            benchmark = ProfileBenchmark(
                profile = profile,
                primaryStatus = "manual",
                secondaryStatus = "manual",
                primaryTotal = null,
                secondaryTotal = null,
                score = 50.0,
                detail = "$name: tcp=50.0ms country=DE",
            ),
            runtimeConfigJson = "{}",
        )
    }
}
