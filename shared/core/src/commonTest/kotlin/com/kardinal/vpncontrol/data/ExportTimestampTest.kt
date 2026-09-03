package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import kotlin.test.Test
import kotlin.test.assertContains

class ExportTimestampTest {
    @Test
    fun locationExportUsesAnExplicitFixtureTimestamp() {
        val document = LocationConfigs.export(
            listOf("vless://00000000-0000-0000-0000-000000000001@example.invalid:443#Berlin"),
            exportedAt = "2023-11-14T22:13:20Z",
        )

        assertContains(document.content, "\"exported_at\": \"2023-11-14T22:13:20Z\"")
        assertContains(document.fileName, "2023-11-14T22-13-20Z")
    }

    @Test
    fun routingRulesExportUsesAnExplicitFixtureTimestamp() {
        val document = RoutingRulesTransfer.export(
            RoutingRules(),
            exportedAt = "2023-11-14T22:13:20Z",
        )

        assertContains(document.content, "\"exported_at\": \"2023-11-14T22:13:20Z\"")
        assertContains(document.fileName, "2023-11-14T22-13-20Z")
    }
}
