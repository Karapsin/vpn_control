package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.ProxyProtocol
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidPublicSubscriptionFixtureTest {
    @Test fun publicRefreshFixtureHasOneDeterministicLoopbackSocksLocation() {
        val body = checkNotNull(javaClass.classLoader?.getResourceAsStream("android-refresh-public-subscription.txt")) {
            "Missing public refresh subscription fixture"
        }.bufferedReader().use { it.readText() }

        val profiles = ProxyParser.parseSubscription(body)

        assertEquals(1, profiles.size)
        assertEquals(ProxyProtocol.SOCKS, profiles.single().protocol)
        assertEquals("127.0.0.1", profiles.single().server)
        assertEquals(18081, profiles.single().serverPort)
        assertEquals("Android Refresh Public Fixture", profiles.single().remarks)
        assertEquals("", profiles.single().username)
        assertEquals("", profiles.single().password)
        assertEquals("socks://127.0.0.1:18081#Android%20Refresh%20Public%20Fixture", profiles.single().rawLink)
    }
}
