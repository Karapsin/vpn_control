package com.kardinal.vpncontrol.desktop

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.ByteBuffer
import com.sun.jna.Platform
import com.sun.jna.platform.win32.Advapi32
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import kotlin.test.*

class DesktopExportPublicationTest {
    private fun privateDirectory(parent: Path, name: String): Path {
        val target = parent.resolve(name)
        if (!Platform.isWindows()) return Files.createDirectory(
            target, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"),
            ),
        )
        val token = WinNT.HANDLEByReference()
        check(Advapi32.INSTANCE.OpenProcessToken(Kernel32.INSTANCE.GetCurrentProcess(), WinNT.TOKEN_QUERY, token))
        val sid = try { Advapi32Util.getTokenAccount(token.value).sidString }
        finally { Kernel32.INSTANCE.CloseHandle(token.value) }
        JnaWindowsInstallNative().createDirectory(
            target.toString(), "O:${sid}G:${sid}D:P(A;;FA;;;$sid)", allowExisting = false,
        )
        return target
    }

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

    @Test fun elevenPointFiveMiBTextPublishesFromNestedPrivateAncestry() = fixture { root ->
        val privateParent = privateDirectory(root, "private-parent")
        val target = privateParent.resolve("routing-export.json")
        val text = "a".repeat(11 * 1024 * 1024 + 512 * 1024)
        val result = DesktopPrivateExportWriter.writeText(target.toString(), text)
        result.getOrElse { failure ->
            throw AssertionError(
                "writeText publication stage failed with ${failure.javaClass.name}",
                failure,
            )
        }
        assertEquals(text.length.toLong(), Files.size(target))
        assertEquals(text, Files.readString(target))
        if (!Platform.isWindows()) assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"),
            Files.getPosixFilePermissions(privateParent))
    }

    @Test fun macWritableNonStickyAncestorRejectsNestedPrivateExport() {
        assumeTrue(Platform.isMac())
        fixture { root ->
            val unsafeAncestor = Files.createDirectory(root.resolve("unsafe-ancestor"))
            Files.setPosixFilePermissions(unsafeAncestor,
                java.nio.file.attribute.PosixFilePermissions.fromString("rwxrwxrwx"))
            val privateParent = privateDirectory(unsafeAncestor, "private")
            val target = privateParent.resolve("routing-export.json")
            val result = DesktopPrivateExportWriter.writeText(target.toString(), "private")
            assertIs<IllegalArgumentException>(result.exceptionOrNull())
            assertFalse(Files.exists(target))
        }
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
            val parent = privateDirectory(root, "parent")
            val moved = root.resolve("retained-parent")
            var decoy: Path? = null
            val result = DesktopPrivateExportWriter.writeChunks(parent.resolve("output.json").toString()) { emit ->
                emit(byteArrayOf(1, 2), 2)
                val privateName = Files.list(parent).use { it.findFirst().orElseThrow().fileName }
                Files.move(parent, moved)
                privateDirectory(root, "parent")
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
