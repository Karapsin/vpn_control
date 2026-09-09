package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*

/** Retained measurements and source outcomes exclude profile content, URLs and exception text. */
internal object DesktopActionResultData {
    fun benchmark(id: String, measured: ProfileBenchmark): Map<String, ControlValue> {
        fun timing(value: Double?) = value?.takeIf { it.isFinite() && it >= 0 }
            ?.let(ControlValue::DecimalValue) ?: ControlValue.Null
        return mapOf(
            "id" to ControlValue.Text(id),
            "committed" to ControlValue.BooleanValue(true),
            "code" to ControlValue.Text(if (measured.testStatus == "ok") "OK" else "BENCHMARK_FAILED"),
            "primaryStatus" to ControlValue.Text(measured.primaryStatus),
            "secondaryStatus" to ControlValue.Text(measured.secondaryStatus),
            "primaryTotalMs" to timing(measured.primaryTotal),
            "secondaryTotalMs" to timing(measured.secondaryTotal),
        )
    }

    fun decode(operation: ControlOperationId, response: DesktopCliResponse): Map<String, ControlValue>? {
        // Preserve the known recovery failure separately from the outer runtime failure.
        // Arbitrary exceptions and profile contents are never retained as result data.
        if (operation == ControlOperationId.FIND_BEST && !response.success && response.exitCode == 1 &&
            response.message == "ROLLBACK_FAILED") {
            return mapOf("recoveryCode" to ControlValue.Text("ROLLBACK_FAILED"))
        }
        if (operation !in setOf(ControlOperationId.SUBSCRIPTIONS_REFRESH, ControlOperationId.LOCATIONS_BENCHMARK) ||
            !response.message.startsWith("{")) return null
        val values = ControlDocumentCodec.decodeValues(response.message)
        fun text(name: String) = (values.getValue(name) as ControlValue.Text).value
        if (operation == ControlOperationId.SUBSCRIPTIONS_REFRESH) {
            require(values.keys == setOf("code", "sources"))
            val sources = (values.getValue("sources") as ControlValue.ArrayValue).values.map {
                (it as ControlValue.ObjectValue).values.also { source ->
                    require(source.keys == setOf("id", "ok", "locationCount"))
                    require((source.getValue("id") as ControlValue.Text).value.isNotBlank())
                    require(source.getValue("ok") is ControlValue.BooleanValue)
                    val count = source.getValue("locationCount")
                    require(count == ControlValue.Null || count is ControlValue.IntegerValue && count.value >= 0)
                    require(source.getValue("ok") != ControlValue.BooleanValue(true) || count != ControlValue.Null)
                }
            }
            require(sources.map { it.getValue("id") }.distinct().size == sources.size)
            val succeeded = sources.count { (it.getValue("ok") as ControlValue.BooleanValue).value }
            val complete = succeeded == sources.size
            require(text("code") == if (complete) "OK" else if (succeeded > 0) "PARTIAL_FAILURE" else "REFRESH_FAILED")
            require(response.success == complete && response.exitCode == if (complete) 0 else 1)
        } else {
            require(values.keys == setOf("id", "committed", "code", "primaryStatus", "secondaryStatus", "primaryTotalMs", "secondaryTotalMs"))
            require(text("id").isNotBlank())
            require(text("primaryStatus").isNotBlank() && text("secondaryStatus").isNotBlank())
            require(values.getValue("committed") == ControlValue.BooleanValue(true))
            for (key in listOf("primaryTotalMs", "secondaryTotalMs")) {
                val value = values.getValue(key)
                require(value == ControlValue.Null || value is ControlValue.DecimalValue && value.value >= 0 ||
                    value is ControlValue.IntegerValue && value.value >= 0)
            }
            require(text("code") == if (response.success) "OK" else "BENCHMARK_FAILED")
            require(response.exitCode == if (response.success) 0 else 1)
        }
        return values
    }
}
