package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import org.junit.Assume.assumeTrue
import kotlin.test.*

/** Opt-in owned macOS VM only. Creates no system gate and never runs a launcher/installer. */
class DesktopMacAdmissionNativeTest {
    @Test fun readOnlyDefaultAncestryAndPackagedLauncher() {
        val supplied = System.getProperty("vpn.control.native.macAdmissionLauncher")
        assumeTrue(System.getProperty("os.name").startsWith("Mac", true) && supplied != null)
        val launcher = Path.of(requireNotNull(supplied))
        require(launcher.isAbsolute && launcher == launcher.normalize())
        val native = JnaMacInstallAdmission()
        assertNotNull(native.adminGroupId(), "Native admin group lookup must resolve")
        // A JVM test cannot itself be the app executable. Substitute only its identity for
        // this explicitly supplied VM artifact; descriptor policy and default roots are real.
        val fixture = object : MacInstallAdmissionNative by native {
            override fun currentExecutable() = launcher.toString()
        }
        DesktopMacInstallAdmission.enter(launcher, fixture).close()
        val opened = mutableListOf<Int>()
        try {
            val root = native.openRoot().also { opened += it }
            val applications = requireNotNull(native.openChild(root, "Applications", true)).also { opened += it }
            val info = native.inspect(applications)
            assertEquals(0L, info.uid)
            assertEquals(native.adminGroupId(), info.gid)
            assertEquals(MacAdmissionAcl.EMPTY, info.acl)
            assertEquals(0x10, info.mode and 0x12, "Disposable VM must exercise admin-group writable Applications")
        } finally { opened.asReversed().forEach(native::close) }
    }

    @Test fun isolatedRealDarwinDescriptorsPendingAndSharedExclusiveInteroperate() {
        val supplied = System.getProperty("vpn.control.native.macAdmissionDirectory")
        assumeTrue(System.getProperty("os.name").startsWith("Mac", true) && supplied != null)
        val parent = Path.of(requireNotNull(supplied)).toRealPath()
        require(parent.startsWith(Path.of("/private/tmp")) && parent.nameCount > 2)
        val base = Files.createTempDirectory(parent, "admission-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val native = JnaMacInstallAdmission()
        val uid = native.currentUid()
        val binary = base.resolve("東京 app.app/Contents/MacOS/vpn-control")
        val jobs = base.resolve("jobs")
        try {
            Files.createDirectories(binary.parent)
            Files.writeString(binary, "isolated test fixture, never executed", StandardOpenOption.CREATE_NEW)
            Files.setPosixFilePermissions(binary, PosixFilePermissions.fromString("rwx------"))
            Files.createDirectory(jobs, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val gate = jobs.resolve("gate-" + DesktopMacInstallAdmission.installationId(binary.parent.parent.parent))
            Files.write(gate, ByteArray(17).apply { this[8] = 1 }, StandardOpenOption.CREATE_NEW)
            Files.setPosixFilePermissions(gate, PosixFilePermissions.fromString("rw-------"))
            // Only this explicit fixture substitutes executable identity. All descriptor,
            // ACL, metadata, canonical path and flock calls below are real Darwin calls.
            val fixtureNative = object : MacInstallAdmissionNative by native {
                override fun currentExecutable() = binary.toString()
            }
            assertEquals("BUSY", assertFails { DesktopMacInstallAdmission.enter(binary, fixtureNative,
                roots = listOf(MacAdmissionRoot(jobs, uid))) }.message)
            var pending = false
            val lease = DesktopMacInstallAdmission.enter(binary, fixtureNative, roots = listOf(MacAdmissionRoot(jobs, uid)),
                allowPendingControl = true, onPendingControl = { pending = true })
            val opened = mutableListOf<Int>()
            try {
                assertTrue(pending)
                var directory = native.openRoot().also { opened += it }
                for (part in jobs) directory = requireNotNull(native.openChild(directory, part.toString(), true)).also { opened += it }
                val exclusive = requireNotNull(native.openChild(directory, gate.fileName.toString(), false)).also { opened += it }
                assertFalse(native.lockExclusive(exclusive), "Retained shared lease must block replacement")
                lease.close()
                assertTrue(native.lockExclusive(exclusive))
                assertEquals("BUSY", assertFails { DesktopMacInstallAdmission.enter(binary, fixtureNative,
                    roots = listOf(MacAdmissionRoot(jobs, uid)), allowPendingControl = true) }.message)
            } finally { lease.close(); opened.asReversed().forEach(native::close) }
            Files.delete(gate) // Exact test-owned gate; exercise first install before any gate exists.
            val firstInstall = DesktopMacInstallAdmission.enter(binary, fixtureNative,
                roots = listOf(MacAdmissionRoot(jobs, uid)))
            val executableHandles = mutableListOf<Int>()
            try {
                var directory = native.openRoot().also { executableHandles += it }
                for (part in binary.parent) directory = requireNotNull(native.openChild(directory, part.toString(), true))
                    .also { executableHandles += it }
                val executable = requireNotNull(native.openChild(directory, binary.fileName.toString(), false))
                    .also { executableHandles += it }
                assertFalse(native.lockExclusive(executable), "A process predating the first gate must block replacement")
                firstInstall.close()
                assertTrue(native.lockExclusive(executable))
            } finally { firstInstall.close(); executableHandles.asReversed().forEach(native::close) }
            val actual = Path.of(native.currentExecutable()).toRealPath()
            assertEquals(Path.of(ProcessHandle.current().info().command().orElseThrow()).toRealPath(), actual)
        } finally {
            // Exact newly created test tree only; no app/system gates or unrelated files.
            check(base.toFile().deleteRecursively())
        }
    }
}
