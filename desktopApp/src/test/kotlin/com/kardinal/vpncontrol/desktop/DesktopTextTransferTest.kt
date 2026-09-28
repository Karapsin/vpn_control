package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DesktopTextTransferTest {
    @Test fun guiTextExportNeverOverwritesAnExistingDestination() {
        val directory = Files.createTempDirectory("gui-export-")
        try {
            val destination = directory.resolve("routing.json")
            Files.writeString(destination, "original")

            assertTrue(DesktopTextTransfer.writeTextFile(destination, "replacement").isFailure)
            assertEquals("original", Files.readString(destination))
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test fun guiTextExportPublishesPrivateBytesFromTheStart() {
        val directory = Files.createTempDirectory("gui-export-")
        try {
            val destination = directory.resolve("routing.json")
            val content = "routing-東\n".repeat(100_000)
            DesktopTextTransfer.writeTextFile(destination, content).getOrThrow()

            assertEquals(content, Files.readString(destination))
            if (Files.getFileStore(destination).supportsFileAttributeView("posix")) {
                assertEquals(setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
                    Files.getPosixFilePermissions(destination))
            }
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }
}
