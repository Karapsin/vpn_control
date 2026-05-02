package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.shared.storageapi.FetchedSubscriptionContent
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class SelectionWorkflowServiceTest {
    @Test
    fun parseRemoteSourceLocationsRejectsDeviceBindingPlaceholder() = runTest {
        val error = assertFailsWith<IllegalArgumentException> {
            SelectionWorkflowService.parseRemoteSourceLocations(
                rawSource = "https://example.com/sub",
                resolveSource = {
                    ResolvedRemoteSource(
                        preview = RemoteSourcePreview(
                            kindLabel = "Subscription URL",
                            title = "example.com",
                            detail = "Direct remote source",
                            supported = true,
                        ),
                        fetchUrl = "https://example.com/sub",
                    )
                },
                fetchedContent = {
                    FetchedSubscriptionContent(
                        body = "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&type=tcp&security=none#placeholder",
                        contentType = "text/plain",
                        headers = mapOf(
                            "x-hwid-active" to "true",
                            "x-hwid-limit" to "true",
                            "x-hwid-max-devices-reached" to "true",
                        ),
                    )
                },
            )
        }

        assertTrue(error.message.orEmpty().contains("device limit reached"))
    }
}
