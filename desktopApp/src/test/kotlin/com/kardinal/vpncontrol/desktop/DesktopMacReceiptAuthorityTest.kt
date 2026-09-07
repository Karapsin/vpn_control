package com.kardinal.vpncontrol.desktop

import java.nio.file.Path
import kotlin.test.*

class DesktopMacReceiptAuthorityTest {
    private val local = DesktopMacReceiptAuthority(DesktopMacInstallAuthority.USER_LOCAL, 501,
        Path.of("/Users/test/Library/Application Support/vpn-control-install-jobs"))
    @Test fun localReceiptsRequireExplicitOwnerAndPrivateFinalPermissions() {
        local.verify(info(), false, false, 80)
        local.verify(info(mode = 0x8180), false, true, 80)
        local.verify(info(acl = MacAdmissionAcl.DENY_ONLY), true, false, 80)
        for (bad in listOf(info(uid = 502), info(uid = 0), info(mode = 0x41ed), info(acl = MacAdmissionAcl.DENY_ONLY)))
            assertFails { local.verify(bad, false, false, 80) }
        assertFails { local.verify(info(mode = 0x8180, links = 2), false, true, 80) }
    }
    @Test fun machineAuthorityCannotReadLocalOwnerReceiptsOrRelaxFinalRoot() {
        val machine = local.copy(kind = DesktopMacInstallAuthority.MACHINE)
        machine.verify(info(uid = 0, mode = 0x41ed), false, false, 80)
        machine.verify(info(uid = 0, mode = 0x41fd, gid = 80), true, false, 80)
        assertFails { machine.verify(info(), false, false, 80) }
        assertFails { machine.verify(info(uid = 0, mode = 0x41fd, gid = 80), false, false, 80) }
        assertFails { machine.verify(info(uid = 0, mode = 0x41fd, gid = 81), true, false, 80) }
        assertFails { machine.verify(info(uid = 0, mode = 0x8180), false, true, 80) }
    }
    private fun info(uid: Long = 501, mode: Int = 0x41c0, gid: Long = 20, links: Long = 1,
        acl: MacAdmissionAcl = MacAdmissionAcl.EMPTY) = MacAdmissionInfo(uid, mode, links, 0, 1, 1, gid, acl)
}
