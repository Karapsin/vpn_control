package com.kardinal.vpncontrol.desktop

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption

/** Conservative policy: extended ACLs require separate analysis, so accept only a valid empty ACL. */
internal object DesktopMacInstallJobAcl {
    internal interface Api : Library {
        fun acl_get_link_np(path: String, type: Int): Pointer?
        fun acl_get_fd_np(fd: Int, type: Int): Pointer?
        fun acl_valid(acl: Pointer): Int
        fun acl_get_entry(acl: Pointer, entryId: Int, entry: PointerByReference): Int
        fun acl_free(acl: Pointer): Int
    }
    private val native: Api by lazy { Native.load("System", Api::class.java) }
    fun requireAbsent(path: Path) = requireAbsent(path, native)
    fun requireAbsent(fd: Int) {
        Native.setLastError(0)
        val acl = native.acl_get_fd_np(fd, 0x100)
        if (acl == null) { require(Native.getLastError() == 2); return }
        requireEmpty(acl, native)
    }
    internal fun requireAbsent(path: Path, api: Api) {
        Native.setLastError(0)
        val acl = api.acl_get_link_np(path.toString(), 0x100)
        if (acl == null) {
            // Darwin filesec_get_property reports ENOENT for an absent ACL as well as a missing file.
            // Parent ancestry has already been checked; never treat a missing/link target as no ACL.
            require(Native.getLastError() == 2 && Files.exists(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path))
            return
        }
        requireEmpty(acl, api)
    }
    private fun requireEmpty(acl: Pointer, api: Api) {
        try {
            require(api.acl_valid(acl) == 0)
            Native.setLastError(0)
            val result = api.acl_get_entry(acl, 0, PointerByReference())
            // Darwin returns -1/EINVAL at the end (unlike the POSIX 0-at-end convention).
            require(result == -1 && Native.getLastError() == 22)
        } finally { check(api.acl_free(acl) == 0) }
    }
}
