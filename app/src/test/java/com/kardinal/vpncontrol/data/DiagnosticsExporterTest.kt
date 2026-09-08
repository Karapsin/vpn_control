package com.kardinal.vpncontrol.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class DiagnosticsExporterTest {
    @Test fun routingDiagnosticsDoNotExposePrivateSuffixes() {
        val privateSuffix = "internal-customer.example"
        val line = diagnosticsDirectDomainSuffixesLine(listOf(privateSuffix, "vpn.private.example"))

        assertEquals("direct_domain_suffixes_count=2", line)
        assertFalse(line.contains(privateSuffix))
        assertFalse(line.contains("vpn.private.example"))
    }

    @Test fun routingDiagnosticsCountLazyDomainsWithoutEnumeratingThem() {
        val domains = object : AbstractList<String>() {
            override val size: Int = 56_008
            override fun get(index: Int): String = throw AssertionError("Diagnostics must not enumerate domains")
        }

        assertEquals("direct_domain_suffixes_count=56008", diagnosticsDirectDomainSuffixesLine(domains))
    }
}
