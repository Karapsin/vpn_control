package com.kardinal.vpncontrol

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.ControlValue
import java.security.MessageDigest
import org.junit.Test
import org.junit.Assert.assertEquals

class AndroidControlRequestFingerprintTest {
    @Test fun streamingFingerprintMatchesRetainedLegacyBytesIncludingMalformedUnicode() {
        val units = buildString { for (code in 0..65535) append(code.toChar()) }
        val values = linkedMapOf("z" to ControlValue.Text(units), "a\"\n" to ControlValue.ObjectValue(
            linkedMapOf("last" to ControlValue.Text("x".repeat(8189) + "😀\uD800x\uDC00"),
                "first" to ControlValue.ArrayValue(listOf(ControlValue.Null, ControlValue.IntegerValue(Long.MIN_VALUE),
                    ControlValue.DecimalValue(-0.0), ControlValue.DecimalValue(1.0e100), ControlValue.BooleanValue(true))))))
        for (revision in listOf(null, 0L, Long.MAX_VALUE)) for (interactive in listOf(false, true)) for (scheduled in listOf(false, true)) {
            val legacy = ControlDocumentCodec.encodeValues(values.toSortedMap()) + "\u0000" + revision + "\u0000" + interactive + "\u0000scheduled=" + scheduled
            val expected = MessageDigest.getInstance("SHA-256").digest(legacy.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            assertEquals(expected, androidControlRequestFingerprint(values, revision, interactive, scheduled))
        }
    }
}
