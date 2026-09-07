package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlValue
import com.kardinal.vpncontrol.model.PersistedState
import org.junit.Assert.*
import org.junit.Test

class AndroidPersistedDomainSuffixesTest {
    @Test fun existingPreferenceSyntaxAndNormalizationRemainCompatible() {
        val samples = listOf(null, "", " \t\r\n,", "first.test\nsecond.test", "a.test\ra.test\r\nb.test",
            "  *.EXAMPLE.TEST., ..example.test\t*.Other.TEST. \n .OTHER.test. ",
            "\u00a0*.I\u0130.TEST.\u2002\n\u2002i\u0069\u0307.test.\u00a0",
            "\uD800.test\n\uDC00.test\n\uD800.test\n\uD83D\uDE03.test",
            "*. , .., .\u2002., *.*.a.test, \u000b*.A.TEST.\u000c", "İ.TEST\ni\u0307.test\nΣ.TEST\nσ.test")
        for (raw in samples) assertCompatible(raw)
        val random = kotlin.random.Random(94129)
        val alphabet = "abIİΣσＡ.*\uD800\uDC00,\n\r\t \u00a0\u2002\u000b"
        repeat(300) {
            assertCompatible(buildString { repeat(random.nextInt(512)) { append(alphabet[random.nextInt(alphabet.length)]) } })
        }
    }

    @Test fun previousSnapshotsStayImmutableAcrossNewDecodesAndListOperations() {
        val first = AndroidPersistedDomainSuffixes.decode("*.First.TEST\nsecond.test\nfirst.test")
        val second = AndroidPersistedDomainSuffixes.decode("changed.test\nsecond.test")
        assertEquals(listOf("first.test", "second.test"), first)
        assertEquals(listOf("changed.test", "second.test"), second)
        assertEquals(listOf("second.test", "first.test"), first.asReversed())
        assertEquals(listOf("second.test"), first.subList(1, 2))
        assertEquals(listOf("first.test", "second.test").hashCode(), first.hashCode())
        assertTrue(runCatching { first[-1] }.exceptionOrNull() is IndexOutOfBoundsException)
        assertTrue(runCatching { first[first.size] }.exceptionOrNull() is IndexOutOfBoundsException)
        assertTrue(runCatching { (first as MutableList<String>)[0] = "retargeted.test" }.isFailure)
        assertEquals("first.test", first[0])
    }

    @Test fun retainedRoutingResultKeepsItsOriginalValuesAcrossReplacement() {
        val first = AndroidPersistedDomainSuffixes.decode("*.First.TEST\nsecond.test")
        val retained = AndroidRoutingControl.result(PersistedState(routingRules =
            RoutingRules(directDomainSuffixes = first)), ControlOperationId.ROUTING_IMPORT, emptyMap())
        val replacement = AndroidPersistedDomainSuffixes.decode("changed.test\nsecond.test")
        assertEquals("changed.test", replacement[0])
        val values = (retained.getValue("direct-domains") as ControlValue.ArrayValue).values
        assertEquals(listOf(ControlValue.Text("first.test"), ControlValue.Text("second.test")), values)
        assertTrue(runCatching { (values as MutableList<ControlValue>)[0] = ControlValue.Text("retargeted") }.isFailure)
        assertEquals(ControlValue.Text("first.test"), values[0])
    }

    @Test fun separatorsAndDuplicatesDoNotPreallocateAnIndexFromTokenCount() {
        val separators = AndroidPersistedDomainSuffixes.decode(" ".repeat(1_000_000))
        assertTrue(separators.isEmpty())
        val duplicates = AndroidPersistedDomainSuffixes.decode(("same.test\n").repeat(200_000))
        assertEquals(listOf("same.test"), duplicates)
        val chunks = duplicates.javaClass.getDeclaredField("rangeChunks").apply { isAccessible = true }
            .get(duplicates) as Array<LongArray>
        assertEquals(1, chunks.size)
        assertEquals(1_024, chunks.single().size)
    }

    @Test fun collidingDomainHashesPreserveEveryDistinctValueAndEncounterOrder() {
        val values = (0 until 4096).map { index -> buildString {
            repeat(12) { bit -> append(if ((index and (1 shl bit)) == 0) "an" else "c0") }
            append(".test")
        } }
        assertEquals(1, values.map(String::hashCode).toSet().size)
        assertEquals(values, AndroidPersistedDomainSuffixes.decode((values + values.reversed()).joinToString("\n")))
    }

    private fun assertCompatible(raw: String?) {
        val legacy = RoutingRules.parseDirectDomainSuffixes(raw.orEmpty().lineSequence()
            .map { it.trim() }.filter { it.isNotBlank() }.asIterable())
        val actual = AndroidPersistedDomainSuffixes.decode(raw)
        assertEquals(legacy, actual)
        assertEquals(legacy.hashCode(), actual.hashCode())
        assertEquals(legacy, actual.toList())
    }
}
