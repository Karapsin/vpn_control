package com.kardinal.vpncontrol.desktop

import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.security.MessageDigest
import java.util.UUID
import kotlin.test.*

class DesktopWindowsWorkspaceResourceScopeTest {
    private val workspace = Path.of("unused-scope-workspace")
    private val firstOwner = UUID.randomUUID().toString()
    private val nextOwner = UUID.randomUUID().toString()
    private val scopeId = UUID.randomUUID().toString()

    @Test fun bindingIsLazyAndReplacementOwnerReusesOnlyTheWorkspaceIdentity() {
        var bytes: ByteArray? = null
        var writes = 0
        var reads = 0
        fun provider(owner: String) = DesktopWindowsWorkspaceResourceScope(workspace, owner,
            read = { reads++; bytes ?: throw NoSuchFileException(it.toString()) },
            publish = { _, value -> writes++; bytes = value; Result.success(Unit) },
            admit = { path, id -> assertEquals(scopeId, id); proof(path, requireNotNull(bytes)) },
            newScopeId = { scopeId })
        val first = provider(firstOwner)
        assertEquals(0, reads)
        assertEquals(0, writes)
        val original = first.current()
        assertSame(original, first.current())
        val replacement = provider(nextOwner).current()
        assertEquals(scopeId, replacement.scopeId)
        assertEquals(nextOwner, replacement.controllerId)
        assertEquals(firstOwner, original.controllerId)
        assertEquals(1, writes)
    }

    @Test fun corruptOrInaccessibleRecordIsNeverReplaced() {
        for (bytes in listOf(byteArrayOf(), ByteArray(129), "{}".toByteArray(),
            DesktopWindowsRuntimeResourceScope.recordBytes(scopeId) + byteArrayOf(10))) {
            val provider = DesktopWindowsWorkspaceResourceScope(workspace, firstOwner,
                read = { bytes }, publish = { _, _ -> error("must not repair") }, admit = { _, _ -> error("must not admit") })
            assertFails { provider.current() }
        }
        val provider = DesktopWindowsWorkspaceResourceScope(workspace, firstOwner,
            read = { throw java.nio.file.AccessDeniedException(it.toString()) },
            publish = { _, _ -> error("must not repair") })
        assertFailsWith<java.nio.file.AccessDeniedException> { provider.current() }
    }

    @Test fun replacementOfEstablishedRecordFailsEvenWhenContentIsIdentical() {
        val bytes = DesktopWindowsRuntimeResourceScope.recordBytes(scopeId)
        var identity = "0".repeat(24)
        val provider = DesktopWindowsWorkspaceResourceScope(workspace, firstOwner, read = { bytes },
            admit = { path, _ -> proof(path, bytes, identity) })
        provider.current()
        identity = "1".repeat(24)
        assertEquals("CONFLICT", assertFails { provider.current() }.message)
    }

    @Test fun sameFileIdentityDoesNotAuthorizeChangedContentDigestOrLength() {
        val original = DesktopWindowsRuntimeResourceScope.recordBytes(scopeId)
        for (changed in listOf(original.copyOf().also { it[0] = '['.code.toByte() }, original + byteArrayOf(10))) {
            var admitted = original
            val provider = DesktopWindowsWorkspaceResourceScope(workspace, firstOwner, read = { original },
                admit = { path, _ -> proof(path, admitted) })
            provider.current()
            admitted = changed
            assertEquals("CONFLICT", assertFails { provider.current() }.message)
        }
    }

    private fun proof(path: Path, bytes: ByteArray, identity: String = "0".repeat(24)) = DesktopWindowsResourceScopeRecord(
        path.toString(), "a".repeat(24), identity, bytes.size.toLong(),
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) })
}
