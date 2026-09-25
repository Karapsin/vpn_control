package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import kotlin.test.*

class DesktopInstallJobStoreTest {
    private val id = UUID.randomUUID().toString()

    @Test fun nativeWindowsReceiptPhasesDecodeWithExactWireNames() {
        // The protected Windows helper encodes its C# Phase enum with ToString(). The
        // Cancelled spelling was captured from the second public install attempt.
        val nativePhases = listOf(
            "Preparing" to DesktopInstallJobPhase.PREPARING,
            "Authorized" to DesktopInstallJobPhase.AUTHORIZED,
            "WaitingForExit" to DesktopInstallJobPhase.WAITING_FOR_EXIT,
            "Installing" to DesktopInstallJobPhase.INSTALLING,
            "Succeeded" to DesktopInstallJobPhase.SUCCEEDED,
            "Failed" to DesktopInstallJobPhase.FAILED,
            "Cancelled" to DesktopInstallJobPhase.CANCELLED,
        )
        nativePhases.forEachIndexed { sequence, (wirePhase, phase) ->
            val code = when (phase) {
                DesktopInstallJobPhase.CANCELLED -> ControlCode.CANCELLED
                DesktopInstallJobPhase.FAILED -> ControlCode.RUNTIME_FAILED
                else -> ControlCode.OK
            }
            val bytes = """{"version":1,"jobId":"$id","sequence":$sequence,"phase":"$wirePhase","code":"${code.name}"}""".encodeToByteArray()
            assertEquals(DesktopInstallJobReceipt(id, sequence.toLong(), phase, code), DesktopInstallJobReceipt.decode(bytes))
        }

        val captured = """{"version":1,"jobId":"fb1c7d9e-de2b-462a-923b-d07b19818dad","sequence":2,"phase":"Cancelled","code":"CANCELLED"}"""
        assertEquals(DesktopInstallJobPhase.CANCELLED, DesktopInstallJobReceipt.decode(captured.encodeToByteArray()).phase)
    }

    @Test fun nativePhaseCompatibilityRejectsUnknownSpellingsAndKeepsCanonicalUppercaseWriter() {
        val receipt = DesktopInstallJobReceipt(id, 1, DesktopInstallJobPhase.AUTHORIZED, ControlCode.OK)
        assertEquals(receipt, DesktopInstallJobReceipt.decode(receipt.encode()))
        assertTrue(receipt.encode().decodeToString().contains("\"phase\":\"AUTHORIZED\""))
        val authorized = """{"version":1,"jobId":"$id","sequence":1,"phase":"Authorized","code":"OK"}"""
        for (phase in listOf("authorized", "AUTHORIZEDd", "Authorised", "Waiting_For_Exit", "WaitingForEXIT", "Unknown")) {
            assertFailsWith<Exception> {
                DesktopInstallJobReceipt.decode(authorized.replace("Authorized", phase).encodeToByteArray())
            }
        }
        val otherJob = UUID.randomUUID().toString()
        val tracker = DesktopInstallJobReceiptTracker(id)
        tracker.accept(DesktopInstallJobReceipt.decode(authorized.encodeToByteArray()))
        assertFailsWith<Exception> { tracker.accept(DesktopInstallJobReceipt.decode(authorized.replace(id, otherJob).encodeToByteArray())) }
        assertFailsWith<Exception> { tracker.accept(DesktopInstallJobReceipt.decode(authorized.replace("\"sequence\":1", "\"sequence\":0").encodeToByteArray())) }
    }

    @Test fun strictReceiptRejectsMalformedUnknownDuplicatedOversizedAndInvalidTypedValues() {
        val receipt = DesktopInstallJobReceipt(id, 0, DesktopInstallJobPhase.PREPARING, ControlCode.OK)
        assertEquals(receipt, DesktopInstallJobReceipt.decode(receipt.encode()))
        val text = receipt.encode().decodeToString()
        listOf(text.replace("\"version\":1", "\"version\":2"), text.replace("\"sequence\":0", "\"sequence\":-1"),
            text.replace("\"sequence\":0", "\"sequence\":9223372036854775808"),
            text.replace("\"code\":\"OK\"", "\"code\":\"BUSY\""),
            text.replace("\"version\":1", "\"version\":1,\"version\":1"),
            text.dropLast(1) + ",\"path\":\"private\"}", text.replace(id, "../not-an-id"),
            text.replace("PREPARING", "UNRECOGNIZED")).forEach {
            assertFails { DesktopInstallJobReceipt.decode(it.encodeToByteArray()) }
        }
        assertFails { DesktopInstallJobReceipt.decode(byteArrayOf(0xc3.toByte(), 0x28)) }
        assertFails { DesktopInstallJobReceipt.decode(ByteArray(4097)) }
    }

    @Test fun receiptTrackerAcceptsPollingSkipsButRejectsRollbackIdentityChangesAndTerminalRewrite() {
        val tracker = DesktopInstallJobReceiptTracker(id)
        val initial = DesktopInstallJobReceipt(id, 0, DesktopInstallJobPhase.PREPARING, ControlCode.OK)
        assertEquals(initial, tracker.accept(initial)); assertEquals(initial, tracker.accept(initial))
        val installing = initial.copy(sequence = 3, phase = DesktopInstallJobPhase.INSTALLING)
        tracker.accept(installing)
        assertFails { tracker.accept(initial) }
        assertFails { tracker.accept(installing.copy(sequence = 4, phase = DesktopInstallJobPhase.AUTHORIZED)) }
        assertFails { tracker.accept(installing.copy(jobId = UUID.randomUUID().toString(), sequence = 4)) }
        val done = installing.copy(sequence = 4, phase = DesktopInstallJobPhase.SUCCEEDED)
        tracker.accept(done)
        assertFails { tracker.accept(done.copy(sequence = 5)) }
    }

    @Test fun protectedStorePublishesAtomicallyAndCancellationUsesRetainedHandle() = fixture { base, backend ->
        val store = DesktopInstallJobStore(backend, base.resolve("jobs"))
        store.create(id, Files.getOwner(base).name).use { writer ->
            store.open(id).use { reader ->
                assertEquals(DesktopInstallJobPhase.PREPARING, reader.read().phase)
                assertFalse(writer.cancellationRequested())
                reader.requestCancellation()
                assertTrue(writer.cancellationRequested())
                Files.write(base.resolve("jobs/$id/cancel"), byteArrayOf(0))
                assertTrue(writer.cancellationRequested()) // Observed cancellation cannot be rolled back.
                assertFails { writer.publish(DesktopInstallJobPhase.INSTALLING) }
                writer.publish(DesktopInstallJobPhase.AUTHORIZED)
                writer.publish(DesktopInstallJobPhase.WAITING_FOR_EXIT)
                writer.publish(DesktopInstallJobPhase.INSTALLING)
                assertEquals(3L, reader.read().sequence)
                writer.publish(DesktopInstallJobPhase.SUCCEEDED)
                assertEquals(DesktopInstallJobPhase.SUCCEEDED, reader.read().phase)
                assertFails { writer.publish(DesktopInstallJobPhase.FAILED, ControlCode.RUNTIME_FAILED) }
            }
        }
        assertTrue(Files.exists(base.resolve("jobs/$id/status.json"))) // Receipts survive closing.
        assertEquals(PosixFilePermissions.fromString("rwxr-xr-x"), Files.getPosixFilePermissions(base.resolve("jobs")))
        assertEquals(PosixFilePermissions.fromString("rw-r--r--"), Files.getPosixFilePermissions(base.resolve("jobs/$id/status.json")))
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(base.resolve("jobs/$id/cancel")))
        assertFails { store.create(id, Files.getOwner(base).name) } // Never silently reuse a job.
    }

    @Test fun retainedCancellationCannotBeRedirectedAndClientCannotOverwriteStatusOrClearCancel() = fixture { base, backend ->
        val root = base.resolve("jobs")
        DesktopInstallJobStore(backend, root).create(id, Files.getOwner(base).name).use { writer ->
            backend.openRoot(root, false).use { rootHandle -> rootHandle.openJob(id).use { job ->
                assertFails { job.openFile("status.json", write = true) }
                job.openFile("cancel", write = true).use { assertFails { it.writeExact(byteArrayOf(0)) } }
                // Fixture owner simulates replacement impossible for an ordinary production client.
                val leaf = root.resolve("$id/cancel")
                Files.move(leaf, leaf.resolveSibling("original-cancel"))
                Files.write(leaf, byteArrayOf(1))
                assertFalse(writer.cancellationRequested())
                Files.write(leaf.resolveSibling("original-cancel"), byteArrayOf(1))
                assertTrue(writer.cancellationRequested())
            } }
        }
    }

    @Test fun rejectsLinksWritableDirectoriesOversizeCancelAndUntrustedProductionRoot() = fixture { base, backend ->
        val root = base.resolve("jobs")
        DesktopInstallJobStore(backend, root).create(id, Files.getOwner(base).name).use { writer ->
            val cancel = root.resolve("$id/cancel")
            Files.write(cancel, byteArrayOf(1, 0))
            assertFails { writer.cancellationRequested() }
            val status = root.resolve("$id/status.json")
            Files.move(status, status.resolveSibling("old-status"))
            Files.createSymbolicLink(status, status.resolveSibling("old-status"))
            DesktopInstallJobStore(backend, root).open(id).use { assertFails { it.read() } }
        }
        val link = base.resolve("link")
        Files.createSymbolicLink(link, root)
        assertFails { backend.openRoot(link, false) }
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxrwxrwx"))
        assertFails { backend.openRoot(root, false) }
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFails { DesktopPosixInstallJobBackend().openRoot(root, false) }
        assertFails { backend.openRoot(base.resolve("../escape"), true) }
    }

    private fun fixture(body: (Path, DesktopInstallJobBackend) -> Unit) {
        if (System.getProperty("os.name").startsWith("Windows", true)) return
        val base = Files.createTempDirectory("installer-store-test-").toRealPath()
        val owner = Files.getOwner(base)
        // Only this explicitly injected test policy trusts the test-owned subtree. Production never does.
        val backend = if (System.getProperty("os.name").startsWith("Mac", true)) DesktopMacInstallJobBackend { path, stat ->
            if (path.startsWith(base)) {
                require(stat.uid == Files.getAttribute(base, "unix:uid") as Int)
                require(stat.mode.toInt() and 0x12 == 0)
            }
        } else DesktopPosixInstallJobBackend(verifyTrust = { path, attributes ->
            if (path.startsWith(base)) {
                require(attributes.owner() == owner)
                require(PosixFilePermission.GROUP_WRITE !in attributes.permissions() &&
                    PosixFilePermission.OTHERS_WRITE !in attributes.permissions())
            }
        }, verifyExtendedAcl = {})
        try { body(base, backend) } finally { base.toFile().deleteRecursively() }
    }
}
