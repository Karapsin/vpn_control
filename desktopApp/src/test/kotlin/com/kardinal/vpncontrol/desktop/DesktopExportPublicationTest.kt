package com.kardinal.vpncontrol.desktop

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.ByteBuffer
import com.sun.jna.Platform
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopExportPublicationTest {
    @Test fun windowsRenameUsesNoReplaceNullRootAndExactUnicodeLeafForBothAbis() {
        val leaf = "published 東京 😀.json"
        val expected = leaf.toByteArray(Charsets.UTF_16LE)
        for (pointerSize in listOf(4, 8)) {
            windowsExportRenameInfo(leaf, pointerSize).use { info ->
                assertContentEquals(ByteArray(pointerSize * 2), info.getByteArray(0, pointerSize * 2))
                assertEquals(expected.size, info.getInt(pointerSize * 2L))
                assertContentEquals(expected, info.getByteArray(pointerSize * 2L + 4, expected.size))
            }
        }
        for (leafName in listOf("", ".", "..", "../other", "other\\file", "C:other", "bad\u0000name")) {
            assertFailsWith<IllegalArgumentException> { windowsExportRenameInfo(leafName, 8) }
        }
    }
    @Test fun windowsPublicationRenamesPrivateSiblingWhileParentPinsRemainHeld() {
        assumeTrue(Platform.isWindows())
        fixture { root ->
            val final = root.resolve("published 東京.json")
            DesktopPrivateExportWriter.writeChunks(final.toString()) { emit ->
                val partial = Files.list(root).use { it.toList().single() }
                assertTrue(Files.isRegularFile(partial))
                assertEquals(root, partial.parent)
                assertFalse(Files.exists(final))
                assertFails { Files.move(root, root.resolveSibling(root.fileName.toString() + "-moved")) }
                emit(byteArrayOf(1, 2, 3), 3)
            }.getOrThrow()
            assertContentEquals(byteArrayOf(1, 2, 3), Files.readAllBytes(final))
            assertEquals(listOf(final), Files.list(root).use { it.toList() })
        }
    }
    @Test fun nativeLinuxOpenFlagsRespectArchitectureAbi() {
        assertEquals(0x8c000, desktopLinuxExportOpenFlags("aarch64", true))
        assertEquals(0x88002, desktopLinuxExportOpenFlags("aarch64", false))
        assertEquals(0xb0000, desktopLinuxExportOpenFlags("x86-64", true))
        assertEquals(0xa0002, desktopLinuxExportOpenFlags("x86-64", false))
        assertTrue(runCatching { desktopLinuxExportOpenFlags("unknown", true) }.isFailure)
    }
    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("export-publication-東京")
        try { block(root) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun interruptedProducerLeavesNoFinalOrOwnedPartial() = fixture { root ->
        val final = root.resolve("result.json")
        val failure = IOException("synthetic write failure")
        val result = DesktopPrivateExportWriter.writeChunks(final.toString()) { emit ->
            emit(byteArrayOf(1, 2, 3), 3)
            throw failure
        }
        assertSame(failure, result.exceptionOrNull())
        assertFalse(Files.exists(final))
        assertEquals(0L, Files.list(root).use { it.count() })
    }

    @Test fun finalLeafIsAbsentUntilProducerSuccessfullyCompletes() = fixture { root ->
        val final = root.resolve("result.json")
        DesktopPrivateExportWriter.writeChunks(final.toString()) { emit ->
            assertFalse(Files.exists(final))
            emit(byteArrayOf(1, 2), 2)
            assertFalse(Files.exists(final))
            emit(byteArrayOf(3), 1)
        }.getOrThrow()
        assertContentEquals(byteArrayOf(1, 2, 3), Files.readAllBytes(final))
        assertEquals(1L, Files.list(root).use { it.count() })
    }

    @Test fun competingFinalCreationWinsWithoutOverwriteOrPartialLeak() = fixture { root ->
        val final = root.resolve("result.json")
        val result = DesktopPrivateExportWriter.writeChunks(final.toString()) { emit ->
            emit(byteArrayOf(1, 2), 2)
            Files.writeString(final, "competitor", CREATE_NEW)
        }
        assertTrue(result.isFailure)
        assertEquals("competitor", Files.readString(final))
        assertEquals(1L, Files.list(root).use { it.count() })
    }

    @Test fun contentCorruptionIsDetectedBeforePublication() = fixture { root ->
        val final = root.resolve("result.json")
        val result = DesktopPrivateExportWriter.writeChunks(final.toString(), backend = { parent ->
            val file = DesktopControlTransferParent.create(parent, export = true)
            object : DesktopControlTransferFile by file {
                override fun force() {
                    file.force()
                    file.channel.position(0)
                    file.channel.write(ByteBuffer.wrap(byteArrayOf(9)))
                }
            }
        }) { emit -> emit(byteArrayOf(1, 2, 3), 3) }
        assertTrue(result.isFailure)
        assertFalse(Files.exists(final))
        assertEquals(0L, Files.list(root).use { it.count() })
    }

    @Test fun failedExportCleanupCannotFollowReplacedParentToUnrelatedPayload() {
        assumeFalse(Platform.isWindows()) // Native no-delete ancestry handles prevent this rename on Windows.
        fixture { root ->
            val parent = Files.createDirectory(root.resolve("parent"))
            val moved = root.resolve("retained-parent")
            var decoy: Path? = null
            val result = DesktopPrivateExportWriter.writeChunks(parent.resolve("output.json").toString()) { emit ->
                emit(byteArrayOf(1, 2), 2)
                val privateName = Files.list(parent).use { it.findFirst().orElseThrow().fileName }
                Files.move(parent, moved)
                Files.createDirectory(parent)
                val replacement = Files.createDirectory(parent.resolve(privateName))
                decoy = Files.writeString(replacement.resolve("payload"), "unrelated")
                throw IOException("synthetic interruption after rename")
            }
            assertTrue(result.isFailure)
            assertEquals("unrelated", Files.readString(requireNotNull(decoy)))
            assertEquals(0L, Files.list(moved).use { it.count() })
        }
    }
}
