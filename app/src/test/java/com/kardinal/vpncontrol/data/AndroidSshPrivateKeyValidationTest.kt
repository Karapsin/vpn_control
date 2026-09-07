package com.kardinal.vpncontrol.data

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.*
import org.junit.Test

class AndroidSshPrivateKeyValidationTest {
    @Test fun bundledParserReceivesOnlyAnUnstartedPrivateSshConfiguration() {
        val key = "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----\n"
        var calls = 0
        AndroidSshPrivateKeyValidation.validateRuntime(key) { configuration ->
            calls++
            val root = Json.parseToJsonElement(configuration).jsonObject
            assertEquals(setOf("log", "outbounds"), root.keys)
            assertEquals("true", root.getValue("log").jsonObject.getValue("disabled").jsonPrimitive.content)
            val outbound = root.getValue("outbounds").jsonArray.single().jsonObject
            assertEquals("ssh", outbound.getValue("type").jsonPrimitive.content)
            assertEquals(key, outbound.getValue("private_key").jsonArray.single().jsonPrimitive.content)
            assertFalse("private_key_path" in outbound)
        }
        assertEquals(1, calls)
    }

    @Test fun parserFailureCannotExposeItsMessageOrCauseButResourceFailureRemainsDistinct() {
        val error = runCatching {
            AndroidSshPrivateKeyValidation.validateRuntime("PRIVATE_FIXTURE") {
                throw java.io.IOException("PRIVATE_FIXTURE native parser detail")
            }
        }.exceptionOrNull()
        assertTrue(error is IllegalArgumentException)
        assertEquals("Invalid SSH private key", error?.message)
        assertNull(error?.cause)
        val exhausted = OutOfMemoryError("private allocation")
        assertSame(exhausted, runCatching {
            AndroidSshPrivateKeyValidation.validateRuntime("PRIVATE_FIXTURE") { throw exhausted }
        }.exceptionOrNull())
    }

    @Test fun pemEnvelopeRejectsMalformedPayloadAndPreservesSupportedWhitespace() {
        val valid = "-----BEGIN RSA PRIVATE KEY-----\r\n U1lO\tVEhFVElD \r\n-----END RSA PRIVATE KEY-----"
        assertEquals(valid + "\n", AndroidSshPrivateKeyValidation.normalize("  $valid  "))
        for (invalid in listOf(
            "-----BEGIN OPENSSH PRIVATE KEY-----\nINVALID_FIXTURE_CONTENT\n-----END OPENSSH PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nU1lOVEhFVElD\n-----END RSA PRIVATE KEY-----",
        )) assertTrue(runCatching { AndroidSshPrivateKeyValidation.normalize(invalid) }.exceptionOrNull() is IllegalArgumentException)
    }
}
