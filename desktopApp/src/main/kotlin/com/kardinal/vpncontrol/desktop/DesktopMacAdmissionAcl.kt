package com.kardinal.vpncontrol.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.IntByReference
import com.sun.jna.ptr.PointerByReference

/** Admission ancestry alone may carry valid deny-only ACLs: these cannot grant access beyond mode bits. */
internal object DesktopMacAdmissionAcl {
    internal interface Api : Library {
        fun acl_get_fd_np(fd: Int, type: Int): Pointer?
        fun acl_valid(acl: Pointer): Int
        fun acl_get_entry(acl: Pointer, entryId: Int, entry: PointerByReference): Int
        fun acl_get_tag_type(entry: Pointer, tag: IntByReference): Int
        fun acl_free(acl: Pointer): Int
    }
    private val native: Api by lazy { Native.load("System", Api::class.java) }
    fun inspect(fd: Int): MacAdmissionAcl = inspect(fd, native)
    internal fun inspect(fd: Int, api: Api): MacAdmissionAcl {
        Native.setLastError(0)
        val acl = api.acl_get_fd_np(fd, 0x100)
        if (acl == null) {
            require(Native.getLastError() == 2) { "Admission ACL unavailable" }
            return MacAdmissionAcl.EMPTY
        }
        try {
            require(api.acl_valid(acl) == 0) { "Invalid admission ACL" }
            var count = 0
            while (true) {
                val entry = PointerByReference()
                Native.setLastError(0)
                val result = api.acl_get_entry(acl, if (count == 0) 0 else -1, entry)
                if (result == -1 && Native.getLastError() == 22) {
                    return if (count == 0) MacAdmissionAcl.EMPTY else MacAdmissionAcl.DENY_ONLY
                }
                require(result == 0 && entry.value != null && count < 4096) { "Invalid admission ACL entry" }
                val tag = IntByReference()
                require(api.acl_get_tag_type(entry.value, tag) == 0 && tag.value == 2) {
                    "Permission-granting admission ACL"
                } // Darwin ACL_EXTENDED_DENY; all unknown and ALLOW entries fail closed.
                count++
            }
        } finally { check(api.acl_free(acl) == 0) }
    }
}
