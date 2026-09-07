package com.kardinal.vpncontrol.desktop

import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference
import kotlin.test.*

class DesktopMacAdmissionAclTest {
    @Test fun acceptsOnlyValidEmptyOrDenyOnlyAclAndReleasesDescriptorAcl() {
        for (tags in listOf(emptyList(), listOf(2), listOf(2, 2))) {
            val api = Fake(tags)
            assertEquals(if (tags.isEmpty()) MacAdmissionAcl.EMPTY else MacAdmissionAcl.DENY_ONLY,
                DesktopMacAdmissionAcl.inspect(19, api))
            assertEquals(1, api.freed)
            assertEquals(listOf(0) + List(tags.size) { -1 }, api.entryIds)
        }
    }
    @Test fun rejectsAllowUnknownInvalidAndUnboundedAclsWithoutLeaks() {
        for (api in listOf(Fake(listOf(1)), Fake(listOf(2, 1)), Fake(listOf(99)),
            Fake(listOf(2)).apply { valid = false }, Fake(List(4097) { 2 }),
            Fake(listOf(2)).apply { tagFailure = true }, Fake(emptyList()).apply { endError = 5 })) {
            assertFails { DesktopMacAdmissionAcl.inspect(19, api) }
            assertEquals(1, api.freed)
        }
    }
    private class Fake(val tags: List<Int>) : DesktopMacAdmissionAcl.Api {
        var valid = true
        var tagFailure = false
        var endError = 22
        var freed = 0
        var index = 0
        val entryIds = mutableListOf<Int>()
        override fun acl_get_fd_np(fd: Int, type: Int): Pointer { assertEquals(19, fd); assertEquals(0x100, type); return Pointer(1) }
        override fun acl_valid(acl: Pointer) = if (valid) 0 else -1
        override fun acl_get_entry(acl: Pointer, entryId: Int, entry: PointerByReference): Int {
            entryIds += entryId
            if (index == tags.size) { Native.setLastError(endError); return -1 }
            entry.value = Pointer((++index).toLong())
            return 0
        }
        override fun acl_get_tag_type(entry: Pointer, tag: IntByReference): Int {
            tag.value = tags[index - 1]
            return if (tagFailure) -1 else 0
        }
        override fun acl_free(acl: Pointer): Int { freed++; return 0 }
    }
}
