package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.AppMode
import com.kardinal.vpncontrol.model.DnsMode
import com.kardinal.vpncontrol.model.DnsSettings
import com.kardinal.vpncontrol.model.ProxyProfile
import com.kardinal.vpncontrol.model.ProxyProtocol
import com.kardinal.vpncontrol.model.RoutingRules
import java.nio.file.Files
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidRuntimeConfigBuilderTest {
    @Test fun vpnConfigUsesSmallLocalAssetContainingAllCanonicalDomains() = temporaryBuilder { builder, _, directory ->
        val built = builder.build(profile(), DnsSettings(), RoutingRules(directDomainSuffixes = listOf(
            "*.Example.test.", ".example.test", "東京.test",
        )), AppMode.VPN, 2091, null)
        try {
            val root = JSONObject(built.json)
            val definition = root.getJSONObject("route").getJSONArray("rule_set").getJSONObject(0)
            val asset = java.io.File(definition.getString("path"))
            val values = JSONObject(asset.readText()).getJSONArray("rules").getJSONObject(0).getJSONArray("domain_suffix")

            assertEquals("local", definition.getString("type"))
            assertEquals("source", definition.getString("format"))
            assertEquals(listOf(".example.test", ".東京.test"), (0 until values.length()).map(values::getString))
            assertFalse(root.getJSONObject("route").getJSONArray("rules").toString().contains("domain_suffix"))
            assertTrue(built.json.length < 8_000)
            assertTrue(requireNotNull(asset.parentFile).canonicalFile == directory.canonicalFile)
        } finally {
            built.close()
        }
    }

    @Test fun ignoredRulesSkipAssetAndPreserveTunConfiguration() = temporaryBuilder { builder, _, directory ->
        val built = builder.build(profile(), DnsSettings(), RoutingRules(ignoreRules = true,
            directDomainSuffixes = listOf("ignored.test")), AppMode.VPN, null, null)
        try {
            val root = JSONObject(built.json)
            assertEquals("tun", root.getJSONArray("inbounds").getJSONObject(0).getString("type"))
            assertFalse(root.getJSONObject("route").has("rule_set"))
            assertTrue(directory.listFiles().isNullOrEmpty())
        } finally {
            built.close()
        }
    }

    @Test fun proxyConfigRetainsPortsAndLocalDirectDomainReference() = temporaryBuilder { builder, _, _ ->
        val built = builder.build(profile(), DnsSettings(), RoutingRules(directDomainSuffixes = listOf("proxy.test")),
            AppMode.PROXY_ONLY, 2199, null)
        try {
            val root = JSONObject(built.json)
            val inbounds = root.getJSONArray("inbounds")
            assertEquals(2080, inbounds.getJSONObject(0).getInt("listen_port"))
            assertEquals(2199, inbounds.getJSONObject(1).getInt("listen_port"))
            assertEquals("local", root.getJSONObject("route").getJSONArray("rule_set").getJSONObject(0).getString("type"))
        } finally {
            built.close()
        }
    }

    @Test fun factoryFailureClosesStagedAssetForStoppedOnlyCleanup() = temporaryBuilder { builder, store, directory ->
        assertFails {
            builder.build(profile(), DnsSettings(mode = DnsMode.CUSTOM_DOH, endpoint = "not a dns endpoint"),
                RoutingRules(directDomainSuffixes = listOf("failure.test")), AppMode.VPN, null, null)
        }
        store.prune(emptySet())
        assertTrue(directory.listFiles().isNullOrEmpty())
    }

    private fun temporaryBuilder(block: (AndroidRuntimeConfigBuilder, AndroidDirectDomainRuleSetStore, java.io.File) -> Unit) {
        val directory = Files.createTempDirectory("runtime-config-builder-").toFile()
        try {
            val store = AndroidDirectDomainRuleSetStore(directory)
            block(AndroidRuntimeConfigBuilder(store), store, directory)
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun assertFails(block: () -> Unit) {
        try {
            block()
            throw AssertionError("Expected build failure")
        } catch (_: Exception) {
        }
    }

    private fun profile() = ProxyProfile(
        protocol = ProxyProtocol.SOCKS,
        remarks = "Fixture",
        server = "socks.example.test",
        serverPort = 1080,
        username = "user",
        password = "pass",
        network = "tcp",
        flow = "",
        security = "",
        sni = "",
        fingerprint = "chrome",
        publicKey = "",
        shortId = "",
        path = "",
        hostHeader = "",
        serviceName = "",
        headerType = "none",
        rawLink = "",
    )
}
