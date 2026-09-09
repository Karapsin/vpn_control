package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.*
import kotlin.test.*

class DesktopActionResultDataTest {
    @Test fun failedSearchRecoveryRetainsTypedCauseWithoutExceptionText() {
        assertEquals(mapOf("recoveryCode" to ControlValue.Text("ROLLBACK_FAILED")),
            DesktopActionResultData.decode(ControlOperationId.FIND_BEST, DesktopCliResponse.failure("ROLLBACK_FAILED")))
        for (response in listOf(DesktopCliResponse.success("ROLLBACK_FAILED"),
            DesktopCliResponse.failure("ROLLBACK_FAILED: PRIVATE_CONFIGURATION"),
            DesktopCliResponse.failure("ROLLBACK_FAILED", 130), DesktopCliResponse.failure("PRIVATE_EXCEPTION"))) {
            assertNull(DesktopActionResultData.decode(ControlOperationId.FIND_BEST, response))
        }
    }

    @Test fun refreshRetainsOnlyCorrelatedSourceOutcomesIncludingPartialFailures() {
        val json = """{"code":"PARTIAL_FAILURE","sources":[{"id":"a","ok":true,"locationCount":2},{"id":"b","ok":false,"locationCount":null}]}"""
        val response = DesktopCliResponse.failure(json)
        val values = assertNotNull(DesktopActionResultData.decode(ControlOperationId.SUBSCRIPTIONS_REFRESH, response))
        assertEquals(ControlValue.Text("PARTIAL_FAILURE"), values["code"])
        assertEquals(2, (values["sources"] as ControlValue.ArrayValue).values.size)
        for (invalid in listOf(json.replace("PARTIAL_FAILURE", "OK"), json.replace("\"b\"", "\"a\""),
            json.replace("\"id\":\"a\"", "\"id\":\"a\",\"source\":\"PRIVATE_URL\""),
            json.replace("\"locationCount\":null", "\"locationCount\":-1"),
            json.replace("\"locationCount\":2", "\"locationCount\":null"))) {
            assertFails { DesktopActionResultData.decode(ControlOperationId.SUBSCRIPTIONS_REFRESH, DesktopCliResponse.failure(invalid)) }
        }
        assertFails { DesktopActionResultData.decode(ControlOperationId.SUBSCRIPTIONS_REFRESH, DesktopCliResponse.success(json)) }
    }

    @Test fun benchmarkRetainsMeasuredFailureWithoutProfileContentOrInventedTiming() {
        val json = """{"code":"BENCHMARK_FAILED","committed":true,"id":"opaque","primaryStatus":"ok","secondaryStatus":"timeout","primaryTotalMs":12.5,"secondaryTotalMs":null}"""
        val values = assertNotNull(DesktopActionResultData.decode(ControlOperationId.LOCATIONS_BENCHMARK,
            DesktopCliResponse.failure(json)))
        assertEquals(ControlValue.BooleanValue(true), values["committed"])
        assertEquals(ControlValue.Text("ok"), values["primaryStatus"])
        assertEquals(ControlValue.Text("timeout"), values["secondaryStatus"])
        assertEquals(ControlValue.DecimalValue(12.5), values["primaryTotalMs"])
        assertEquals(ControlValue.Null, values["secondaryTotalMs"])
        for (invalid in listOf(json.replace("12.5", "-1"), json.replace("true", "false"),
            json.replace("\"id\":\"opaque\"", "\"id\":\"opaque\",\"detail\":\"PRIVATE_DETAIL\""))) {
            assertFails { DesktopActionResultData.decode(ControlOperationId.LOCATIONS_BENCHMARK, DesktopCliResponse.failure(invalid)) }
        }
        assertNull(DesktopActionResultData.decode(ControlOperationId.LOCATIONS_BENCHMARK, DesktopCliResponse.failure("PRIVATE_EXCEPTION")))
        assertNull(DesktopActionResultData.decode(ControlOperationId.ON, DesktopCliResponse.success(json)))
    }
}
