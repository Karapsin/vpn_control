package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProfile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest

class SelectionWorkflowServiceTest {
    @Test
    fun loadProfilesForTargetsHonorsConcurrencyAndPreservesTargetOrder() = runTest {
        val targets = listOf(
            SubscriptionSearchTarget("sub-1", "one", "One"),
            SubscriptionSearchTarget("sub-2", "two", "Two"),
            SubscriptionSearchTarget("sub-3", "three", "Three"),
        )
        var running = 0
        var maxRunning = 0

        val loaded = SelectionWorkflowService.loadProfilesForTargets(
            targets = targets,
            onStatus = {},
            concurrency = 2,
            loadProfiles = { source ->
                running += 1
                maxRunning = maxOf(maxRunning, running)
                delay(
                    when (source) {
                        "one" -> 30
                        "two" -> 10
                        else -> 1
                    },
                )
                running -= 1
                listOf(profile(source))
            },
        )

        assertEquals(2, maxRunning)
        assertEquals(listOf("sub-1", "sub-2", "sub-3"), loaded.profilesById.keys.toList())
    }
}

private fun profile(name: String): ProxyProfile = ProxyProfile(
    remarks = name,
    server = "$name.example.com",
    serverPort = 443,
    network = "tcp",
    flow = "",
    security = "tls",
    sni = "$name.example.com",
    fingerprint = "chrome",
    publicKey = "",
    shortId = "",
    path = "",
    hostHeader = "",
    serviceName = "",
    headerType = "none",
    rawLink = "vless://$name",
)
