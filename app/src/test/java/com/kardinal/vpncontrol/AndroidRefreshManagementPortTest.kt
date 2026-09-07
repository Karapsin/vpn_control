package com.kardinal.vpncontrol

import org.junit.Assert.*
import org.junit.Test

class AndroidRefreshManagementPortTest {
    @Test fun generatedVpnVerificationInboundIsTheActualManagementPort() {
        assertEquals(24680, androidRefreshManagementPort("""{"inbounds":[{"type":"tun","tag":"tun-in"},{"type":"mixed","tag":"active-verify-in","listen":"127.0.0.1","listen_port":24680}]}"""))
    }
    @Test fun customManagementInboundMustBeLoopbackMixedAndValid() {
        fun config(type: String = "mixed", listen: String = "127.0.0.1", port: Int = 24680) =
            """{"inbounds":[{"type":"$type","tag":"vpn-control-management","listen":"$listen","listen_port":$port}]}"""
        assertEquals(24680, androidRefreshManagementPort(config()))
        assertNull(androidRefreshManagementPort(config(listen = "0.0.0.0")))
        assertNull(androidRefreshManagementPort(config(type = "tun")))
        assertNull(androidRefreshManagementPort(config(port = 0)))
        assertNull(androidRefreshManagementPort("""{"inbounds":[]}"""))
    }
}
