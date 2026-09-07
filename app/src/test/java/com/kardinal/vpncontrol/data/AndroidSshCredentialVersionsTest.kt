package com.kardinal.vpncontrol.data

import java.io.File
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class AndroidSshCredentialVersionsTest {
    @get:Rule val temporary = TemporaryFolder()
    private fun key(value: String) = "-----BEGIN PRIVATE KEY-----\n${java.util.Base64.getEncoder().encodeToString(value.toByteArray())}\n-----END PRIVATE KEY-----\n"
    private fun AndroidSshCredentialVersions.stageFixture(content: String, version: Long) = stage(content, version) {}

    @Test fun stagingPreservesOldVersionAndNeverReusesAnUncommittedPayload() {
        val root = temporary.newFolder()
        val legacy = File(root, "home-ssh-private-key").apply { writeText(key("old")) }
        val store = AndroidSshCredentialVersions(root)
        assertEquals(legacy.absolutePath, store.path(7))
        val first = store.stageFixture(key("new"), 7)
        assertEquals(8, first)
        assertEquals(key("old"), File(store.path(7)!!).readText())
        assertEquals(key("new"), File(store.path(first)!!).readText())
        // Simulate failed metadata commit: the next transaction still observes 7.
        val second = AndroidSshCredentialVersions(root).stageFixture(key("retry"), 7)
        assertEquals(9, second)
        assertEquals(key("new"), File(store.path(first)!!).readText())
        assertEquals(key("old"), legacy.readText())
        assertEquals(key("retry"), File(store.path(second)!!).readText())
    }

    @Test fun missingVersionNeverFallsBackToUnrelatedLegacyKeyAfterMigration() {
        val root = temporary.newFolder()
        File(root, "home-ssh-private-key").writeText(key("old"))
        val store = AndroidSshCredentialVersions(root)
        store.stageFixture(key("new"), 2)
        assertNull(store.path(99))
        assertNotNull(store.path(2))
        assertEquals(3, store.stageFixture(key("new"), 3))
        assertFalse(File(root, "home-ssh-key-versions/4.key").exists())
    }

    @Test fun invalidImportDoesNotChangeLegacyResolutionOrCreateStagingState() {
        val root = temporary.newFolder()
        val legacy = File(root, "home-ssh-private-key").apply { writeText(key("old")) }
        val store = AndroidSshCredentialVersions(root)
        for (value in listOf("", "SECRET", "-----BEGIN ENCRYPTED PRIVATE KEY-----\nSECRET",
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED")) {
            assertTrue(runCatching { store.stageFixture(value, 0) }.isFailure)
            assertEquals(legacy.absolutePath, store.path(0))
            assertFalse(File(root, "home-ssh-key-versions").exists())
        }
    }

    @Test fun malformedOpenSshBodyCannotReplaceTheCommittedCredential() {
        val root = temporary.newFolder()
        val legacy = File(root, "home-ssh-private-key").apply { writeText(key("old")) }
        val store = AndroidSshCredentialVersions(root)
        val malformed = "-----BEGIN OPENSSH PRIVATE KEY-----\nINVALID_FIXTURE_CONTENT\n-----END OPENSSH PRIVATE KEY-----\n"

        val failure = runCatching { store.stage(malformed, 7) }.exceptionOrNull()

        assertTrue("Malformed private-key bytes must be rejected before publication", failure is IllegalArgumentException)
        assertEquals(legacy.absolutePath, store.path(7))
        assertEquals(key("old"), legacy.readText())
        assertFalse(File(root, "home-ssh-key-versions").exists())
    }

    @Test fun runtimeKeyRejectionAndResourceFailureRunBeforeAnyPublicationIncludingNoOp() {
        val root = temporary.newFolder()
        val legacy = File(root, "home-ssh-private-key").apply { writeText(key("old")) }
        val store = AndroidSshCredentialVersions(root)
        val exhausted = OutOfMemoryError("synthetic resource failure")
        for (failure in listOf(IllegalArgumentException("invalid key"), exhausted)) {
            var validated = false
            assertSame(failure, runCatching {
                store.stage(key("old"), 7) { validated = true; throw failure }
            }.exceptionOrNull())
            assertTrue(validated)
            assertEquals(legacy.absolutePath, store.path(7))
            assertEquals(key("old"), legacy.readText())
            assertFalse(File(root, "home-ssh-key-versions").exists())
        }
    }

    @Test fun directorySyncFailureCannotPublishNewConfigurationOrReplaceLegacyKey() {
        val root = temporary.newFolder()
        val legacy = File(root, "home-ssh-private-key").apply { writeText(key("old")) }
        val store = AndroidSshCredentialVersions(root) { throw java.io.IOException("fixture sync failure") }
        assertTrue(runCatching { store.stageFixture(key("new"), 3) }.isFailure)
        assertEquals(legacy.absolutePath, store.path(3))
        assertEquals(key("old"), legacy.readText())
        assertFalse(File(root, "home-ssh-key-versions/versioned").exists())
    }
}
