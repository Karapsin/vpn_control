package com.kardinal.vpncontrol

import org.junit.Assert.*
import org.junit.Test

class AndroidControlTransfersTest {
    @Test fun onlyExactAppOrPermissionGrantedShellUidIsAuthorized() {
        AndroidControlAccess.authorize(10123, 10123, false)
        AndroidControlAccess.authorize(2000, 10123, true)
        for (uid in listOf(0, 1000, 10124, 102000)) {
            assertThrows(SecurityException::class.java) { AndroidControlAccess.authorize(uid, 10123, true) }
        }
        assertThrows(SecurityException::class.java) { AndroidControlAccess.authorize(2000, 10123, false) }
    }

    @Test fun uriParsingRejectsTraversalEncodingsExtraSegmentsAndAuthorityConfusion() {
        val authority = "com.kardinal.vpncontrol.control"
        val id = "00000000-0000-0000-0000-000000000001"
        val root = "content://$authority"
        assertEquals("requests" to id, AndroidControlAccess.parseUri("$root/requests/$id", authority))
        for (uri in listOf("$root/requests/../$id", "$root/requests/%2e%2e", "$root/results/$id?x=1",
            "$root/results/$id#fragment", "$root/results/$id/", "$root/results/%30$id",
            "content://user@$authority/results/$id", "content://$authority:80/results/$id",
            "file://$authority/results/$id", "$root.evil/results/$id")) {
            assertThrows(IllegalArgumentException::class.java) { AndroidControlAccess.parseUri(uri, authority) }
        }
    }

    @Test fun contentIsBoundedSequentialSingleWriteAndOwnedByCaller() {
        val transfers = AndroidControlTransfers(maxBytes = 4)
        val id = transfers.create(2000)
        assertThrows(SecurityException::class.java) { transfers.beginWrite(id, 10123) }
        transfers.beginWrite(id, 2000)
        assertThrows(IllegalStateException::class.java) { transfers.beginWrite(id, 2000) }
        assertThrows(IllegalArgumentException::class.java) { transfers.append(id, 2000, 1, byteArrayOf(1), 1) }
        assertEquals(4, transfers.append(id, 2000, 0, byteArrayOf(1, 2, 3, 4), 4))
        assertThrows(IllegalArgumentException::class.java) { transfers.append(id, 2000, 4, byteArrayOf(5), 1) }
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), transfers.finishWrite(id, 2000))
        assertEquals("pending", transfers.phase(id, 2000))
        assertThrows(IllegalStateException::class.java) { transfers.remove(id, 2000) }
        assertThrows(IllegalStateException::class.java) { transfers.resultSize(id, 2000) }
        assertThrows(IllegalArgumentException::class.java) { transfers.complete(id, 2000, ByteArray(5)) }
        transfers.complete(id, 2000, byteArrayOf(7, 8, 9))
        val output = ByteArray(4)
        assertEquals(2, transfers.read(id, 2000, 1, 4, output))
        assertArrayEquals(byteArrayOf(8, 9, 0, 0), output)
        assertThrows(SecurityException::class.java) { transfers.read(id, 10123, 0, 1, output) }
        assertEquals(0, transfers.read(id, 2000, Long.MAX_VALUE, 1, output))
        transfers.remove(id, 2000)
        assertThrows(IllegalStateException::class.java) { transfers.phase(id, 2000) }
    }

    @Test fun expiredTransfersFreeCapacityAndOpenHandlesCannotResurrectThem() {
        var now = 0L
        val transfers = AndroidControlTransfers(clockMillis = { now }, capacity = 1, ttlMillis = 10)
        val id = transfers.create(2000)
        transfers.beginWrite(id, 2000)
        assertThrows(IllegalStateException::class.java) { transfers.create(2000) }
        now = 10
        assertNotEquals(id, transfers.create(2000))
        assertThrows(IllegalStateException::class.java) { transfers.finishWrite(id, 2000) }
    }
}
