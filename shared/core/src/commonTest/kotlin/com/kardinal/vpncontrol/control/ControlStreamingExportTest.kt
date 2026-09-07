package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.MainUiState
import com.kardinal.vpncontrol.data.PrettyJson
import com.kardinal.vpncontrol.data.RoutingRulesTransfer
import com.kardinal.vpncontrol.model.*
import kotlinx.serialization.json.*
import kotlin.test.*

class ControlStreamingExportTest {
    @Test fun routingWriterMatchesExistingPrettyJsonIncludingEmptyArraysAndEveryUtf16Unit() {
        val units = buildString { for (value in 0..65535) append(value.toChar()) }
        for (rules in listOf(RoutingRules(), RoutingRules(ignoreRules = true, blockQuicUdp443 = true,
            proxyPackages = listOf("a", units), directDomainSuffixes = listOf("東京.example", "\\\"\n")))) {
            val timestamp = "2026-09-06T12:34:56Z"
            val expected = PrettyJson.encodeToString(JsonObject.serializer(), buildJsonObject {
                put("type", "vpn_control_routing_rules"); put("version", 7); put("exported_at", timestamp)
                put("rules", buildJsonObject {
                    put("ignore_rules", rules.ignoreRules); put("block_quic_udp_443", rules.blockQuicUdp443)
                    put("proxy_packages", JsonArray(rules.proxyPackages.map(::JsonPrimitive)))
                    put("direct_domain_suffixes", JsonArray(rules.directDomainSuffixes.map(::JsonPrimitive)))
                })
            })
            assertEquals(expected, buildString { RoutingRulesTransfer.writeExport(rules, timestamp, this) })
            assertEquals(expected, RoutingRulesTransfer.export(rules, timestamp).content)
        }
    }

    @Test fun externalContentIsExactlyOneEscapedStringInCanonicalResultOrder() {
        val units = buildString { for (value in 0..65535) append(value.toChar()) }
        val result = ControlResult("controller", "request", ControlCode.OK, 17, message = "東京\n",
            data = linkedMapOf("before" to ControlValue.ArrayValue(listOf(ControlValue.Null))))
        val expected = ControlDocumentCodec.encodeResult(result.copy(data = result.data + ("content" to ControlValue.Text(units))))
        val actual = buildString {
            ControlDocumentCodec.writeResultWithContent(result, this) { output ->
                output.append(units, 0, 256)
                for (index in 256 until units.length) output.append(units[index])
            }
        }
        assertEquals(expected, actual)
        assertFails { ControlDocumentCodec.writeResultWithContent(result.copy(data = mapOf("content" to ControlValue.Null)), StringBuilder()) {} }
    }

    @Test fun largeRoutingContentStreamsThroughEnvelopeWithoutWholeStringAppend() {
        val repeated = "example.test"
        val rules = RoutingRules(directDomainSuffixes = object : AbstractList<String>() {
            override val size = 100_000
            override fun get(index: Int): String { require(index in indices); return repeated }
        })
        var count = 0L
        val output = object : Appendable {
            override fun append(value: Char): Appendable { count++; return this }
            override fun append(value: CharSequence?): Appendable = append(value, 0, value?.length ?: 4)
            override fun append(value: CharSequence?, startIndex: Int, endIndex: Int): Appendable {
                check(endIndex - startIndex <= 256) { "Whole export was materialized" }
                count += endIndex - startIndex
                return this
            }
        }
        ControlDocumentCodec.writeResultWithContent(ControlResult("owner", "request", ControlCode.OK, 0), output) {
            RoutingRulesTransfer.writeExport(rules, "fixed", it)
        }
        assertTrue(count > 2_000_000)
    }

    @Test fun externalWriterFailurePropagatesAndNeverWritesACompletedSuccessEnvelope() {
        val failure = IllegalStateException("synthetic sink failure")
        val output = StringBuilder()
        val caught = assertFails {
            ControlDocumentCodec.writeResultWithContent(ControlResult("owner", "request", ControlCode.OK, 0), output) {
                it.append("prefix"); throw failure
            }
        }
        assertSame(failure, caught)
        assertFalse(output.endsWith("}"))
    }

    @Test fun inspectionDoesNotMisclassifyFatalResourceFailureAsInvalidArgument() {
        val fatal = AssertionError("synthetic resource failure")
        val rules = RoutingRules(proxyPackages = object : AbstractList<String>() {
            override val size get(): Int = throw fatal
            override fun get(index: Int): String = throw fatal
        })
        val caught = assertFails {
            ControlConfigurationInspection.read(MainUiState(routingRules = rules), ControlCommand(ControlOperationId.ROUTING_EXPORT), 0)
                .getOrThrow()
        }
        assertSame(fatal, caught)
        // The fatal must escape read itself, not be captured in a Result for callers to relabel.
        assertSame(fatal, assertFails {
            ControlConfigurationInspection.read(MainUiState(routingRules = rules), ControlCommand(ControlOperationId.ROUTING_EXPORT), 0)
        })
        assertTrue(ControlConfigurationInspection.read(MainUiState(), ControlCommand(ControlOperationId.ROUTING_EXPORT,
            mapOf("unexpected" to ControlValue.Text("x"))), 0).isFailure)
    }
}
