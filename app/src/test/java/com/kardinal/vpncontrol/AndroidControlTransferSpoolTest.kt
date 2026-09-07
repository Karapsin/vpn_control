package com.kardinal.vpncontrol

import java.nio.file.Files
import java.security.MessageDigest
import org.junit.Assert.*
import org.junit.Test

class AndroidControlTransferSpoolTest {
    @Test fun largeDocumentsUseUnlinkedPrivateStorageAndBoundedReads() {
        val cache = Files.createTempDirectory("android-control-cache-東京")
        try {
            val spool = AndroidControlTransferSpool.create(cache)
            try {
                Files.list(cache).use { assertEquals(0L, it.count()) }
                val chunk = ByteArray(65536) { 65 }
                val digest = MessageDigest.getInstance("SHA-256")
                repeat(161) { spool.append(chunk); digest.update(chunk) }
                assertArrayEquals(ByteArray(32) { 65 }, spool.read(65530, 32))
                assertEquals(digest.digest().joinToString("") { "%02x".format(it) }, spool.sha256())
                assertThrows(IllegalArgumentException::class.java) { spool.read(0, 65537) }
                assertThrows(IllegalArgumentException::class.java) { spool.read(Long.MAX_VALUE, 1) }
                assertThrows(IllegalArgumentException::class.java) { spool.append(ByteArray(65537)) }
                assertEquals(0, spool.read(161L * 65536, 0).size)
                assertFalse(spool.toString().contains(cache.toString()))
            } finally { spool.erase(); spool.erase() }
            assertThrows(IllegalStateException::class.java) { spool.read(0, 0) }
        } finally { cache.toFile().deleteRecursively() }
    }

    @Test fun callerCannotRedirectStorageThroughASymlinkCache() {
        val root = Files.createTempDirectory("android-control-parent")
        try {
            val target = Files.createDirectory(root.resolve("actual"))
            val alias = Files.createSymbolicLink(root.resolve("alias"), target)
            assertThrows(IllegalArgumentException::class.java) { AndroidControlTransferSpool.create(alias) }
            Files.list(target).use { assertEquals(0L, it.count()) }
        } finally { root.toFile().deleteRecursively() }
    }
}
