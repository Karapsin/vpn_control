package com.kardinal.vpncontrol.data

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Test

class AndroidNativePublicationTest {
    @Test fun existingDestinationPreservesBothFilesAndSamePathIsNotReplaced() = temporaryDirectory { directory ->
        val source = File(directory, "source")
        val target = File(directory, "target")
        source.writeBytes(byteArrayOf(1, 2, 3))
        target.writeBytes(byteArrayOf(4, 5, 6))

        assertFalse(AndroidNativePublication.publishNew(source, target))
        assertArrayEquals(byteArrayOf(1, 2, 3), source.readBytes())
        assertArrayEquals(byteArrayOf(4, 5, 6), target.readBytes())
        assertFalse(AndroidNativePublication.publishNew(source, source))
        assertArrayEquals(byteArrayOf(1, 2, 3), source.readBytes())
    }

    @Test fun hardLinkAliasesRemainUnchanged() = temporaryDirectory { directory ->
        val source = File(directory, "source").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        val alias = File(directory, "source-alias")
        Files.createLink(alias.toPath(), source.toPath())
        assertFalse(AndroidNativePublication.publishNew(source, alias))
        assertArrayEquals(byteArrayOf(1, 2, 3), source.readBytes())
        assertArrayEquals(byteArrayOf(1, 2, 3), alias.readBytes())
    }

    @Test fun publishMovesTheWholeFileAndPreservesUnicodePaths() = temporaryDirectory { directory ->
        val source = File(directory, "東京-source-🚀")
        val target = File(directory, "東京-target-🚀")
        val bytes = ByteArray(32_769) { (it * 31).toByte() }
        source.writeBytes(bytes)

        assertTrue(AndroidNativePublication.publishNew(source, target))
        assertFalse(source.exists())
        assertArrayEquals(bytes, target.readBytes())
    }

    @Test fun existingDirectoryIsNeverReplaced() = temporaryDirectory { directory ->
        val target = File(directory, "existing-directory").apply { mkdir() }
        val source = File(directory, "directory-source").apply { writeText("source") }
        val result = runCatching { AndroidNativePublication.publishNew(source, target) }
        result.exceptionOrNull()?.let { assertTrue(it is IOException) } ?: assertFalse(result.getOrThrow())
        assertTrue(source.isFile)
        assertTrue(target.isDirectory)
    }

    @Test fun danglingSymlinkIsNeverReplacedOnHostsThatSupportIt() = temporaryDirectory { directory ->
        assumeFalse(System.getProperty("os.name").startsWith("Windows"))
        val target = File(directory, "dangling-link")
        val source = File(directory, "link-source").apply { writeText("source") }
        Files.createSymbolicLink(target.toPath(), File(directory, "missing-target").toPath())
        assertFalse(AndroidNativePublication.publishNew(source, target))
        assertTrue(source.isFile)
        assertTrue(Files.isSymbolicLink(target.toPath()))
    }

    @Test fun missingAndInvalidPathsFailWithoutPublication() = temporaryDirectory { directory ->
        val target = File(directory, "target")
        assertIOException { AndroidNativePublication.publishNew(File(directory, "missing"), target) }
        assertIOException { AndroidNativePublication.publishNew(File(directory, "nul\u0000source"), target) }
        assertIOException { AndroidNativePublication.publishNew(File(directory, "unpaired-\uD800"), target) }
        val validSource = File(directory, "valid-source").apply { writeText("source") }
        assertIOException { AndroidNativePublication.publishNew(validSource, File(directory, "nul\u0000target")) }
        assertIOException { AndroidNativePublication.publishNew(validSource, File(directory, "unpaired-\uD800target")) }
        assertTrue(validSource.isFile)
        assertFalse(target.exists())
    }

    @Test fun concurrentPublishersHaveOneCompleteWinnerAndLeaveTheLoserSource() = temporaryDirectory { directory ->
        val first = File(directory, "first").apply { writeBytes(ByteArray(8_193) { 0x11 }) }
        val second = File(directory, "second").apply { writeBytes(ByteArray(12_289) { 0x22 }) }
        val target = File(directory, "target")
        val ready = CountDownLatch(2)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(2)
        try {
            val results = listOf(first, second).map { source -> pool.submit<Boolean> {
                ready.countDown()
                check(start.await(10, TimeUnit.SECONDS))
                AndroidNativePublication.publishNew(source, target)
            } }
            assertTrue(ready.await(10, TimeUnit.SECONDS))
            start.countDown()
            val published = results.map { it.get(10, TimeUnit.SECONDS) }
            assertEquals(1, published.count { it })
            val winner = if (published[0]) first else second
            val loser = if (published[0]) second else first
            assertArrayEquals(if (winner == first) ByteArray(8_193) { 0x11 } else ByteArray(12_289) { 0x22 }, target.readBytes())
            assertFalse(winner.exists())
            assertTrue(loser.isFile)
        } finally {
            pool.shutdownNow()
        }
    }

    private fun assertIOException(block: () -> Unit) {
        assertTrue(runCatching(block).exceptionOrNull() is IOException)
    }

    private fun temporaryDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("native-publication-").toFile()
        try {
            block(directory)
        } finally {
            directory.deleteRecursively()
        }
    }
}
