package com.kardinal.vpncontrol.desktop

import java.nio.file.Path

/** Explicit authority selected before launch; a failed machine receipt never falls back to a user root. */
internal data class DesktopMacReceiptAuthority(val kind: DesktopMacInstallAuthority, val clientUid: Long, val root: Path) {
    val ownerUid: Long get() = if (kind == DesktopMacInstallAuthority.MACHINE) 0 else clientUid
    val directoryMode: Int get() = if (kind == DesktopMacInstallAuthority.MACHINE) 0x1ed else 0x1c0
    val statusMode: Int get() = if (kind == DesktopMacInstallAuthority.MACHINE) 0x1a4 else 0x180
    fun store(): DesktopInstallJobStore = DesktopInstallJobStore(DesktopMacInstallJobBackend(authority = this), root)
    init {
        require(clientUid in 1..0xfffffffeL && root.isAbsolute && root.normalize() == root)
        require(root.fileName.toString() == "vpn-control-install-jobs")
    }
    fun verify(info: MacAdmissionInfo, ancestry: Boolean, cancellation: Boolean, adminGroup: Long?) {
        val directory = info.mode and 0xf000 == 0x4000
        require(directory || info.mode and 0xf000 == 0x8000)
        require(!ancestry || directory)
        val expected = if (cancellation) clientUid else ownerUid
        require(info.uid == expected || ancestry && info.uid == 0L) { "Untrusted receipt owner" }
        require(info.acl == MacAdmissionAcl.EMPTY || ancestry && info.acl == MacAdmissionAcl.DENY_ONLY)
        val administrativeAncestor = ancestry && info.uid == 0L && info.gid == adminGroup && info.mode and 2 == 0
        val stickyAncestor = ancestry && info.uid == 0L && info.mode and 0x200 != 0
        require(info.mode and 0x12 == 0 || administrativeAncestor || stickyAncestor)
        if (!ancestry && (kind == DesktopMacInstallAuthority.USER_LOCAL || cancellation)) require(info.mode and 0x3f == 0)
        require(directory || info.links == 1L)
    }
    companion object {
        fun production(kind: DesktopMacInstallAuthority, native: MacInstallAdmissionNative = JnaMacInstallAdmission()): DesktopMacReceiptAuthority {
            val uid = native.currentUid()
            val root = if (kind == DesktopMacInstallAuthority.MACHINE) Path.of("/Library/Application Support/vpn-control-install-jobs")
                else native.homeDirectory().resolve("Library/Application Support/vpn-control-install-jobs")
            return DesktopMacReceiptAuthority(kind, uid, root)
        }
    }
}
