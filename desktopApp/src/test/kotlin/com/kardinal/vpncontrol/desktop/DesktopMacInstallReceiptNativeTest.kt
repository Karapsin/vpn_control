package com.kardinal.vpncontrol.desktop

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import org.junit.Assume.assumeTrue
import kotlin.test.*

/** Owned-VM only, with an explicitly provisioned private parent outside sticky /tmp/home ACLs. */
class DesktopMacInstallReceiptNativeTest {
    @Test fun explicitLocalAuthorityPublishesPrivateReceiptsWithoutMachineFallback() {
        val supplied = System.getProperty("vpn.control.native.macReceiptDirectory")
        assumeTrue(System.getProperty("os.name").startsWith("Mac", true) && supplied != null)
        val parent = Path.of(requireNotNull(supplied)).toRealPath()
        require(parent.parent == Path.of("/private") && parent.fileName.toString().startsWith("vpn-mac-receipt-"))
        val base = Files.createTempDirectory(parent, "local-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val policy = DesktopMacReceiptAuthority(DesktopMacInstallAuthority.USER_LOCAL,
                JnaMacInstallAdmission().currentUid(), base.resolve("vpn-control-install-jobs"))
            val job = UUID.randomUUID().toString()
            policy.store().create(job, Files.getOwner(base).name).use { writer ->
                assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(policy.root))
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(policy.root.resolve(job).resolve("status.json")))
                policy.store().open(job).use { reader ->
                    writer.publish(DesktopInstallJobPhase.AUTHORIZED)
                    assertEquals(DesktopInstallJobPhase.AUTHORIZED, reader.read().phase)
                }
                assertFails { policy.copy(kind = DesktopMacInstallAuthority.MACHINE).store().open(job) }
            }
        } finally { check(base.toFile().deleteRecursively()) }
    }

    @Test fun nativeProcessGenerationMatchesCurrentJvmAndRemainsStable() {
        assumeTrue(System.getProperty("os.name").startsWith("Mac", true) &&
            System.getProperty("vpn.control.native.macReceiptDirectory") != null)
        val process = ProcessHandle.current()
        val identity = DesktopMacInstallProcesses.read(process.pid())
        assertEquals(identity, DesktopMacInstallProcesses.read(process.pid()))
        assertEquals(JnaMacInstallAdmission().currentUid(), identity.uid)
        assertEquals(Path.of(process.info().command().orElseThrow()).toRealPath(), Path.of(identity.executable).toRealPath())
        val expected = process.info().startInstant().orElseThrow()
        assertEquals(expected.epochSecond, identity.startSeconds)
        assertEquals(expected.nano / 1_000_000, (identity.startMicroseconds / 1_000).toInt())
    }

    @Test fun nativeReceiptPublicationReplacementAndRetainedCancellation() {
        val supplied = System.getProperty("vpn.control.native.macReceiptDirectory")
        assumeTrue(System.getProperty("os.name").startsWith("Mac", true) && supplied != null)
        val parent = Path.of(requireNotNull(supplied)).toRealPath()
        require(parent.parent == Path.of("/private") && parent.fileName.toString().startsWith("vpn-mac-receipt-"))
        val base = Files.createTempDirectory(parent, "job-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val uid = (Files.getAttribute(base, "unix:uid") as Number).toInt()
        val backend = DesktopMacInstallJobBackend { path, stat ->
            require(stat.uid == if (path.startsWith(parent)) uid else 0)
            require(stat.mode.toInt() and 0x12 == 0)
        }
        val jobId = UUID.randomUUID().toString()
        try {
            val root = base.resolve("jobs")
            val store = DesktopInstallJobStore(backend, root)
            store.create(jobId, Files.getOwner(base).name).use { writer ->
                store.open(jobId).use { reader ->
                    assertEquals(DesktopInstallJobPhase.PREPARING, reader.read().phase)
                    backend.openRoot(root, false).use { directory -> directory.openJob(jobId).use { job ->
                        job.openFile(DesktopInstallJobNames.STATUS).use { retained ->
                            writer.publish(DesktopInstallJobPhase.AUTHORIZED)
                            assertEquals(DesktopInstallJobPhase.PREPARING,
                                DesktopInstallJobReceipt.decode(retained.readBounded(4096)).phase)
                            assertEquals(DesktopInstallJobPhase.AUTHORIZED, reader.read().phase)
                        }
                    } }
                    reader.requestCancellation()
                    assertTrue(writer.cancellationRequested())
                    writer.publish(DesktopInstallJobPhase.CANCELLED, com.kardinal.vpncontrol.model.ControlCode.CANCELLED)
                    assertEquals(DesktopInstallJobPhase.CANCELLED, reader.read().phase)
                }
            }
        } finally { check(base.toFile().deleteRecursively()) }
    }
}
