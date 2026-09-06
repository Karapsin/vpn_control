package com.kardinal.vpncontrol

import android.Manifest
import android.net.Uri
import androidx.test.platform.app.InstrumentationRegistry
import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Test

class AndroidControlProviderInstrumentedTest {
    @Test fun ownUidUsesBoundedContentStreamsWithoutVpnOrGui() = runBlocking {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val authority = context.packageName + ".control"
        val info = requireNotNull(context.packageManager.resolveContentProvider(authority, 0))
        assertTrue(info.exported)
        assertEquals(Manifest.permission.DUMP, info.readPermission)
        assertEquals(Manifest.permission.DUMP, info.writePermission)
        assertFalse(info.grantUriPermissions)
        val resolver = context.contentResolver
        val root = Uri.parse("content://$authority")
        val allocation = requireNotNull(resolver.call(root, "create", null, null))
        val id = requireNotNull(allocation.getString("id"))
        val request = ControlRequest("instrumentation", ControlCommand(ControlOperationId.CAPABILITIES))
        requireNotNull(resolver.openOutputStream(Uri.parse(allocation.getString("requestUri")), "w")).use {
            it.write(ControlProtocolCodec.encodeRequest(request).toByteArray(Charsets.UTF_8))
        }
        withTimeout(10_000) {
            while (resolver.call(root, "status", id, null)?.getString("state") != "complete") delay(10)
        }
        val response = requireNotNull(resolver.openInputStream(Uri.parse(allocation.getString("resultUri")))).use {
            ControlProtocolCodec.decodeResult(it.readBytes().toString(Charsets.UTF_8))
        }
        assertEquals(ControlCode.OK, response.code)
        assertEquals(request.requestId, response.requestId)
        resolver.call(root, "discard", id, null)
    }
}
