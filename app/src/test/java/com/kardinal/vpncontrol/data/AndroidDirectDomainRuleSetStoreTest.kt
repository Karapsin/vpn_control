package com.kardinal.vpncontrol.data

import com.kardinal.vpncontrol.model.RoutingRules
import java.io.IOException
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class AndroidDirectDomainRuleSetStoreTest {
    @Suppress("DEPRECATION")
    @Test fun stagingDoesNotRequireHardLinkPermission() = temporaryStore { store ->
        // API29 denied createLink in the private app directory. Reproduce the
        // unavailable primitive on the host without changing filesystem access.
        val previous = System.getSecurityManager()
        System.setSecurityManager(object : SecurityManager() {
            override fun checkPermission(permission: java.security.Permission) {
                if (permission is java.nio.file.LinkPermission && permission.name == "hard") {
                    throw SecurityException("Synthetic Android hard-link denial")
                }
                previous?.checkPermission(permission)
            }
        })
        try {
            requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("android.test")))).use {
                assertTrue(java.io.File(it.path).isFile)
            }
        } finally {
            System.setSecurityManager(previous)
        }
    }

    @Test fun entirelyEmptyNormalizedDomainsDoNotCreateAMatchingRuleSet() = temporaryStore { store, directory ->
        assertNull(store.stage(RoutingRules(directDomainSuffixes = listOf(" ", "", "...", "*."))))
        assertTrue(directory.listFiles().isNullOrEmpty())
    }

    @Test fun stageWritesCanonicalSingBoxSourceRuleSet() = temporaryStore { store ->
        val lease = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf(
            "*.Example.COM.", ".example.com", "東京.jp", " ",
        ))))
        val document = JSONObject(java.io.File(lease.path).readText())
        val domains = document.getJSONArray("rules").getJSONObject(0).getJSONArray("domain_suffix")

        assertEquals(1, document.getInt("version"))
        assertEquals(listOf(".example.com", ".東京.jp"), (0 until domains.length()).map(domains::getString))
        lease.close()
    }

    @Test fun ignoredOrEmptyRoutingDoesNotCreateAnAsset() = temporaryStore { store, directory ->
        assertNull(store.stage(RoutingRules(ignoreRules = true, directDomainSuffixes = listOf("example.test"))))
        assertNull(store.stage(RoutingRules(directDomainSuffixes = emptyList())))
        assertTrue(directory.listFiles().isNullOrEmpty())
    }

    @Test fun repeatedStageSharesAssetAndLeasesProtectAThroughBPruning() = temporaryStore { store, directory ->
        val a = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("a.test"))))
        val sameA = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("a.test"))))
        assertEquals(a.path, sameA.path)
        val b = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("b.test"))))
        sameA.close()
        b.close()

        store.prune(setOf(a.path))
        assertTrue(java.io.File(a.path).isFile)
        assertFalse(java.io.File(b.path).exists())
        a.close()
        store.prune(emptySet())
        assertTrue(directory.listFiles().isNullOrEmpty())
    }

    @Test fun acquireRejectsMissingCorruptAndForeignPaths() = temporaryStore { store, directory ->
        val lease = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("a.test"))))
        val path = java.io.File(lease.path)
        lease.close()
        path.writeText("corrupt")
        assertFails { store.acquire(path.path) }
        assertFails { store.acquire(java.io.File(directory, "${"0".repeat(64)}.json").path) }
        val foreign = Files.createTempDirectory("foreign-direct-rule-set-").toFile()
        try {
            val file = java.io.File(foreign, "${"0".repeat(64)}.json").apply { writeText("{}") }
            assertFails { store.acquire(file.path) }
        } finally {
            foreign.deleteRecursively()
        }
    }

    @Test fun writeFailureDeletesOnlyTheTemporaryAsset() {
        val directory = Files.createTempDirectory("direct-rule-set-write-failure-").toFile()
        try {
            val store = AndroidDirectDomainRuleSetStore(directory) { throw IOException("synthetic write failure") }
            assertFails { store.stage(RoutingRules(directDomainSuffixes = listOf("a.test"))) }
            assertTrue(directory.listFiles().isNullOrEmpty())
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test fun replacedDirectoryIsRejectedBeforeWritingAnotherAsset() {
        val directory = Files.createTempDirectory("direct-rule-set-replaced-").toFile()
        val displaced = java.io.File(directory.parentFile, "${directory.name}-old")
        try {
            val store = AndroidDirectDomainRuleSetStore(directory)
            require(directory.renameTo(displaced))
            Files.createDirectory(directory.toPath(), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))

            assertFails { store.stage(RoutingRules(directDomainSuffixes = listOf("replacement.test"))) }
            assertTrue(directory.listFiles().isNullOrEmpty())
        } finally {
            directory.deleteRecursively()
            displaced.deleteRecursively()
        }
    }

    @Test fun protectedCorruptAssetIsNeverPruned() = temporaryStore { store ->
        val lease = requireNotNull(store.stage(RoutingRules(directDomainSuffixes = listOf("a.test"))))
        val file = java.io.File(lease.path)
        lease.close()
        file.writeText("corrupt")

        store.prune(setOf(lease.path))

        assertTrue(file.exists())
    }

    @Test fun prunePreservesMalformedChildrenEvenWithAssetShapedNames() = temporaryStore { store, directory ->
        val emptyDirectory = java.io.File(directory, "${"0".repeat(64)}.json").apply { mkdir() }
        val corruptFile = java.io.File(directory, "${"1".repeat(64)}.json").apply { writeText("foreign evidence") }
        Files.setPosixFilePermissions(corruptFile.toPath(), PosixFilePermissions.fromString("rw-------"))

        store.prune(emptySet())

        assertTrue(emptyDirectory.isDirectory)
        assertEquals("foreign evidence", corruptFile.readText())
    }

    @Test fun foreignDefinitionsUsingTheGeneratedTagRemainCustomResources() = temporaryStore { store ->
        val foreignLocal = """
            {"route":{"rule_set":[{"tag":"runtime-direct-domains","type":"local","format":"source","path":"/ordinary/custom-rules.json"}]}}
        """.trimIndent()
        val remote = """
            {"route":{"rule_set":[{"tag":"runtime-direct-domains","type":"remote","format":"binary","url":"https://example.test/rules.srs"}]}}
        """.trimIndent()

        assertNull(store.acquireFromConfig(foreignLocal))
        assertNull(store.acquireFromConfig(remote))
    }

    private fun temporaryStore(block: (AndroidDirectDomainRuleSetStore, java.io.File) -> Unit) {
        val directory = Files.createTempDirectory("direct-rule-set-").toFile()
        try {
            block(AndroidDirectDomainRuleSetStore(directory), directory)
        } finally {
            directory.deleteRecursively()
        }
    }

    private fun temporaryStore(block: (AndroidDirectDomainRuleSetStore) -> Unit) = temporaryStore { store, _ -> block(store) }

    private fun assertFails(block: () -> Unit) {
        try {
            block()
            fail("Expected failure")
        } catch (_: IllegalArgumentException) {
        } catch (_: IllegalStateException) {
        } catch (_: IOException) {
        }
    }
}
