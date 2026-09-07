package com.kardinal.vpncontrol.desktop

import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.*

class DesktopLinuxArchInstallTest {
    private val prefix = "vpn-control-arch-update"
    private fun source() = requireNotNull(javaClass.getResourceAsStream("/linux-install-arch.sh")).use { it.readBytes().decodeToString() }
    private fun entry(name: String, type: Char = '-', target: String? = null) =
        "${type}rwxr-xr-x 0/0 1 2026-09-06 00:00:00 $name${target?.let { " -> $it" }.orEmpty()}\n"
    private fun listing() = entry(prefix, 'd') + entry("$prefix/app", 'd') + entry("$prefix/app/bin", 'd') +
        entry("$prefix/app/bin/vpn-control") + entry("$prefix/sing-box") + entry("$prefix/install.sh") + entry("$prefix/VERSION")

    @Test fun manifestPreflightAcceptsCanonicalBundleAndContainedJlinkFileSymlink() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows", true))
        assertEquals(0, validate(listing()))
        val legal = entry("$prefix/app/legal", 'd') + entry("$prefix/app/legal/java.base", 'd') +
            entry("$prefix/app/legal/java.base/COPYRIGHT") + entry("$prefix/app/legal/java.xml", 'd') +
            entry("$prefix/app/legal/java.xml/COPYRIGHT", 'l', "../java.base/COPYRIGHT")
        assertEquals(0, validate(listing() + legal))
    }

    @Test fun manifestPreflightRejectsAmbiguityTraversalHardlinksAndEscapingOrChainedLinks() {
        assumeFalse(System.getProperty("os.name").startsWith("Windows", true))
        for (extra in listOf(entry("/outside"), entry("$prefix/../outside"), entry("$prefix/app//file"),
            entry("$prefix/app/space name"), entry("$prefix/app/escaped\\nname"), entry("$prefix/app/tab\tname"),
            entry("$prefix/app/bin/vpn-control"), entry("$prefix/app/device", 'c'),
            entry("$prefix/app/hard", 'h'), entry("$prefix/app/link", 'l', "/outside"),
            entry("$prefix/app/link", 'l', "../../outside"), entry("$prefix/app/link", 'l', "../sing-box"),
            entry("$prefix/app/link", 'l', "bin"),
            entry("$prefix/app/a", 'l', "bin/vpn-control") + entry("$prefix/app/b", 'l', "a"))) {
            assertNotEquals(0, validate(listing() + extra), extra)
        }
        assertNotEquals(0, validate(listing().replace(entry("$prefix/install.sh"), "")))
    }

    @Test fun nativeHostileArchivesFailBeforeExtractionAndSafeArchiveExtractsPrivately() {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        val directory = Files.createTempDirectory("vpn-arch-preflight-")
        try {
            val bundle = directory.resolve(prefix)
            Files.createDirectories(bundle.resolve("app/bin"))
            for (name in listOf("app/bin/vpn-control", "sing-box", "install.sh", "VERSION")) {
                val path = bundle.resolve(name)
                Files.writeString(path, if (name == "VERSION") "1.0.1\n" else "fixture, never executed\n")
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"))
            }
            fun archive(name: String): Path {
                val file = directory.resolve(name)
                val tar = ProcessBuilder("/usr/bin/tar", "-czf", file.toString(), "-C", directory.toString(), prefix)
                    .redirectErrorStream(true).start()
                assertTrue(tar.waitFor(10, TimeUnit.SECONDS))
                val diagnostics = tar.inputStream.use { it.readNBytes(4097).decodeToString().take(4096) }
                assertEquals(0, tar.exitValue(), diagnostics)
                return file
            }
            val safe = archive("safe.tar.gz")
            val safeResult = unpack(safe, directory.resolve("safe-output"))
            assertEquals(0, safeResult.first, safeResult.second)
            assertTrue(Files.isRegularFile(directory.resolve("safe-output/$prefix/app/bin/vpn-control")))
            Files.createSymbolicLink(bundle.resolve("app/escape"), Path.of("../../outside"))
            val hostile = archive("hostile.tar.gz")
            val hostileResult = unpack(hostile, directory.resolve("bad-output"))
            assertNotEquals(0, hostileResult.first, hostileResult.second)
            assertFalse(Files.exists(directory.resolve("outside")))
            assertFalse(Files.exists(directory.resolve("bad-output/$prefix")))
        } finally {
            Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).toList() }.forEach(Files::delete)
        }
    }

    @Test fun nativeReplacementAndRollbackNeverEraseUnrelatedFixedBackup() {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        for (failIcon in listOf(false, true)) transactionFixture { directory, target, stage, backup ->
            val fixedBackup = directory.resolve("vpn-control.update-backup")
            Files.createDirectory(fixedBackup); Files.writeString(fixedBackup.resolve("unrelated"), "keep")
            if (failIcon) {
                Files.createDirectory(stage.resolve("lib")); Files.writeString(stage.resolve("lib/vpn-control.png"), "icon")
            }
            val (exit, unknown) = transaction(target, stage, backup, directory.resolve("missing-parent/icon.png"))
            assertEquals(if (failIcon) 1 else 0, exit)
            assertEquals("0", unknown)
            assertTrue(Files.exists(target.resolve(if (failIcon) "old" else "new")))
            assertFalse(Files.exists(backup))
            assertEquals("keep", Files.readString(fixedBackup.resolve("unrelated")))
        }
    }

    @Test fun nativePreexistingJobBackupAndSubstitutedRollbackTargetAreNeverDeleted() {
        assumeTrue(System.getProperty("os.name").startsWith("Linux", true))
        transactionFixture { directory, target, stage, backup ->
            Files.createDirectory(backup); Files.writeString(backup.resolve("unrelated"), "keep")
            assertEquals(1, transaction(target, stage, backup, directory.resolve("icon.png")).first)
            assertEquals("keep", Files.readString(backup.resolve("unrelated")))
            assertTrue(Files.exists(target.resolve("old")))
        }
        transactionFixture { directory, target, stage, backup ->
            Files.createDirectory(stage.resolve("lib")); Files.writeString(stage.resolve("lib/vpn-control.png"), "icon")
            val substitute = """
                install() {
                    mv "${'$'}arch_target" "${'$'}arch_target.foreign"
                    mkdir "${'$'}arch_target"
                    printf keep > "${'$'}arch_target/unrelated"
                    return 1
                }
            """.trimIndent()
            val (exit, unknown) = transaction(target, stage, backup, directory.resolve("icon.png"), substitute)
            assertEquals(1, exit); assertEquals("1", unknown)
            assertEquals("keep", Files.readString(target.resolve("unrelated")))
            assertTrue(Files.exists(backup.resolve("old")))
        }
    }

    private fun transaction(target: Path, stage: Path, backup: Path, icon: Path, extra: String = ""): Pair<Int, String> {
        val script = "set -u\n" + source() + "\n" + extra + "\n" + """

            arch_target=${'$'}1; arch_stage=${'$'}2; arch_backup=${'$'}3; arch_icon=${'$'}4
            arch_original_id=${'$'}(arch_object_id "${'$'}arch_target")
            arch_stage_id=${'$'}(arch_object_id "${'$'}arch_stage")
            arch_install_unknown=0
            arch_install_prepared
            result=${'$'}?
            printf '%s' "${'$'}arch_install_unknown"
            exit "${'$'}result"
        """.trimIndent()
        val process = ProcessBuilder("/bin/sh", "-c", script, "fixture", target.toString(), stage.toString(), backup.toString(), icon.toString())
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        process.outputStream.close()
        assertTrue(process.waitFor(15, TimeUnit.SECONDS))
        return process.exitValue() to process.inputStream.bufferedReader().readText()
    }

    private fun transactionFixture(block: (Path, Path, Path, Path) -> Unit) {
        val directory = Files.createTempDirectory("vpn-arch-replacement-")
        try {
            val target = Files.createDirectory(directory.resolve("vpn-control"))
            val stage = Files.createDirectory(directory.resolve("job-stage"))
            Files.writeString(target.resolve("old"), "old"); Files.writeString(stage.resolve("new"), "new")
            block(directory, target, stage, directory.resolve("job-backup"))
        } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).toList() }.forEach(Files::delete) }
    }

    private fun validate(listing: String): Int {
        val process = ProcessBuilder("/bin/sh", "-c", "set -eu\nLC_ALL=C; export LC_ALL\n" + source() + "\narch_validate_listing\n")
            .redirectErrorStream(true).start()
        process.outputStream.use { it.write(listing.encodeToByteArray()) }
        assertTrue(process.waitFor(10, TimeUnit.SECONDS))
        val diagnostics = process.inputStream.use { it.readNBytes(4097).decodeToString() }
        assertTrue(process.exitValue() in 0..1, diagnostics.take(4096))
        return process.exitValue()
    }
    private fun unpack(archive: Path, destination: Path): Pair<Int, String> {
        val process = ProcessBuilder("/bin/sh", "-c", "set -eu\nLC_ALL=C; export LC_ALL\n" + source() +
            "\narch_unpack_archive \"${'$'}1\" \"${'$'}2\"\n", "fixture", archive.toString(), destination.toString())
            .redirectErrorStream(true).start()
        process.outputStream.close()
        assertTrue(process.waitFor(15, TimeUnit.SECONDS))
        val diagnostics = process.inputStream.use { it.readNBytes(4097).decodeToString().take(4096) }
        return process.exitValue() to diagnostics
    }
}
