package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlRequest
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlValue
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.UUID
import java.util.concurrent.TimeoutException

/** Public ADB shell authority is paired with the provider's DUMP + Binder UID checks. */
internal class DesktopAndroidAdbClient(
    private val execute: (List<String>, ByteArray, Long) -> DesktopAdbProcessResult = DesktopAdbProcess()::execute,
) {
    fun request(request: ControlRequest, serial: String?, timeoutSeconds: Long): DesktopCliResponse {
        var knownOperationId = if (request.command.operation in setOf(ControlOperationId.OPERATIONS_WAIT,
                ControlOperationId.OPERATIONS_STATUS, ControlOperationId.OPERATIONS_CANCEL))
            (request.command.arguments["id"] as? ControlValue.Text)?.value else null
        var bytes = runCatching { ControlProtocolCodec.encodeRequest(request).toByteArray(Charsets.UTF_8) }
            .getOrElse { return desktopCliJsonFailure(ControlCode.INVALID_ARGUMENT, request.requestId) }
        if (timeoutSeconds < 0 || timeoutSeconds > Long.MAX_VALUE / 1000) {
            bytes.fill(0)
            return desktopCliJsonFailure(ControlCode.INVALID_ARGUMENT, request.requestId)
        }
        val started = System.nanoTime()
        fun remaining(): Long {
            if (timeoutSeconds == 0L) return Long.MAX_VALUE
            val left = timeoutSeconds * 1000 - (System.nanoTime() - started) / 1_000_000
            if (left <= 0) throw TimeoutException()
            return left
        }
        var selected: String? = null
        var transfer: String? = null
        var sent = false
        fun invoke(args: List<String>, input: ByteArray = byteArrayOf(), cleanup: Boolean = false): String {
            val response = execute(args, input, if (cleanup) 2000 else minOf(30_000L, remaining()))
            val error = strictUtf8(response.stderr)
            if (response.exitCode != 0 || error.isNotBlank()) {
                if ("SecurityException" in error || "PERMISSION_DENIED" in error) fail(ControlCode.PERMISSION_DENIED)
                fail(if (sent) ControlCode.OUTCOME_UNKNOWN else ControlCode.UNAVAILABLE)
            }
            return strictUtf8(response.stdout)
        }
        fun content(vararg args: String, input: ByteArray = byteArrayOf(), cleanup: Boolean = false): String =
            invoke(listOf("-s", requireNotNull(selected), "shell", "-T", "content") + args, input, cleanup)
        try {
            // Serial is passed to the local adb option, never interpolated in a remote command.
            val deviceResult = execute(listOf("devices"), byteArrayOf(), minOf(30_000L, remaining()))
            if (deviceResult.exitCode != 0) fail(ControlCode.UNAVAILABLE)
            selected = selectDevice(strictUtf8(deviceResult.stdout), serial)
            val created = bundle(content("call", "--uri", URI, "--method", "create"))
            val id = created["id"] ?: fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            if (!OPAQUE.matches(id) || runCatching { UUID.fromString(id).toString() }.getOrNull() != id) {
                fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            }
            // Do not trust returned paths: every shell token is fixed ASCII or canonical UUID.
            if (created.filterKeys { it != "controllerId" } != mapOf("id" to id, "requestUri" to "$URI/requests/$id", "resultUri" to "$URI/results/$id")) {
                fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            }
            transfer = id
            val owner = created["controllerId"]
            if (owner != null && (owner.isBlank() || owner.length > 256 || owner.any(Char::isISOControl))) {
                fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            }
            // Bind only an omitted mutation owner. An explicit old epoch must reach the
            // provider unchanged so that its atomic stale-owner check rejects the write.
            if (request.controllerId == null && request.command.operation in setOf(
                    ControlOperationId.SETTINGS_SET, ControlOperationId.SETTINGS_APPLY, ControlOperationId.SSH_KEY_IMPORT, ControlOperationId.SOURCE_SET, ControlOperationId.OFF,
                    ControlOperationId.SUBSCRIPTIONS_ADD, ControlOperationId.SUBSCRIPTIONS_UPDATE, ControlOperationId.SUBSCRIPTIONS_DELETE,
                    ControlOperationId.LOCATIONS_ADD, ControlOperationId.LOCATIONS_UPDATE, ControlOperationId.LOCATIONS_SELECT,
                    ControlOperationId.UPDATES_CHECK, ControlOperationId.UPDATES_DOWNLOAD, ControlOperationId.UPDATES_CANCEL, ControlOperationId.UPDATES_DISMISS,
                    ControlOperationId.ROUTING_SET, ControlOperationId.ROUTING_IMPORT, ControlOperationId.ROUTING_APPS_SET,
                    ControlOperationId.ROUTING_APPS_ADD, ControlOperationId.ROUTING_APPS_REMOVE, ControlOperationId.ROUTING_APPS_SELECT_ALL, ControlOperationId.ROUTING_APPS_CLEAR,
                    ControlOperationId.ON, ControlOperationId.RESTART, ControlOperationId.OPERATIONS_STATUS, ControlOperationId.OPERATIONS_WAIT,
                    ControlOperationId.OPERATIONS_LIST, ControlOperationId.OPERATIONS_CANCEL)) {
                if (owner == null) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                bytes.fill(0)
                bytes = ControlProtocolCodec.encodeRequest(request.copy(controllerId = owner)).toByteArray(Charsets.UTF_8)
            }
            sent = true
            if (content("write", "--uri", "$URI/requests/$id", input = bytes).isNotBlank()) {
                fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            }
            while (true) {
                val status = bundle(content("call", "--uri", URI, "--method", "status", "--arg", id))
                if (status.keys != setOf("state")) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                when (status["state"]) {
                    "complete" -> break
                    "writing", "pending" -> Thread.sleep(minOf(100L, remaining()))
                    else -> fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                }
            }
            val response = content("read", "--uri", "$URI/results/$id")
            var result = runCatching { ControlProtocolCodec.decodeResult(response) }.getOrElse { fail(ControlCode.INCOMPATIBLE_PROTOCOL) }
            if (result.requestId != request.requestId || result.controllerId.isNullOrBlank() ||
                request.controllerId != null && result.controllerId != request.controllerId && result.code != ControlCode.CONFLICT) {
                fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            }
            val runtimeCommand = request.command.operation in setOf(ControlOperationId.ON, ControlOperationId.OFF, ControlOperationId.RESTART)
            if ((runtimeCommand || request.command.operation == ControlOperationId.OPERATIONS_WAIT) && !result.final && result.operationId != null) {
                val operation = requireNotNull(result.operationId)
                knownOperationId = operation
                if (!OPAQUE.matches(operation)) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                val boundOwner = requireNotNull(result.controllerId)
                var launchedInteraction = false
                while (!result.final) {
                    if (request.interactive && !launchedInteraction) {
                        val interaction = bundle(content("call", "--uri", URI, "--method", "interaction", "--arg", operation))
                        when (interaction["state"]) {
                            "none" -> if (interaction.keys != setOf("state")) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                            "waiting" -> {
                                val token = interaction["token"] ?: fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                                if (interaction.keys != setOf("state", "token") || !OPAQUE.matches(token) ||
                                    !Regex("[A-Za-z0-9_-]{1,128}").matches(boundOwner)) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                                val startedActivity = invoke(listOf("-s", requireNotNull(selected), "shell", "-T", "am", "start", "-W",
                                    "-n", "com.kardinal.vpncontrol/.AndroidControlInteractionActivity", "--es", "token", token,
                                    "--es", "controllerId", boundOwner))
                                if (!Regex("(?m)^Status: ok\\r?$").containsMatchIn(startedActivity)) fail(ControlCode.OUTCOME_UNKNOWN)
                                launchedInteraction = true
                            }
                            else -> fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                        }
                    }
                    val phase = (result.data["phase"] as? ControlValue.Text)?.value
                    if (request.asynchronous && (!request.interactive || launchedInteraction || phase == "running")) break
                    Thread.sleep(minOf(100L, remaining()))
                    val query = ControlRequest(UUID.randomUUID().toString(),
                        com.kardinal.vpncontrol.model.ControlCommand(ControlOperationId.OPERATIONS_STATUS,
                            mapOf("id" to ControlValue.Text(operation))), controllerId = boundOwner)
                    val waitSeconds = if (timeoutSeconds == 0L) 0L else ((remaining() - 1) / 1000 + 1).coerceAtLeast(1)
                    val queried = this.request(query, selected, waitSeconds)
                    result = runCatching { ControlProtocolCodec.decodeResult(queried.message) }.getOrElse { fail(ControlCode.INCOMPATIBLE_PROTOCOL) }
                    if (result.code in setOf(ControlCode.OK, ControlCode.ACCEPTED) && result.operationId != operation)
                        fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                    if (result.code != ControlCode.ACCEPTED && !result.final) break
                }
                result = result.copy(requestId = request.requestId)
            }
            return DesktopCliResponse(result.ok, ControlProtocolCodec.encodeResult(result), result.exitCode)
        } catch (error: Exception) {
            val code = when (error) {
                is AdbFailure -> error.code
                is TimeoutException -> ControlCode.TIMEOUT
                is InterruptedException -> { Thread.currentThread().interrupt(); ControlCode.OUTCOME_UNKNOWN }
                else -> if (sent) ControlCode.OUTCOME_UNKNOWN else ControlCode.UNAVAILABLE
            }
            return desktopCliJsonFailure(code, request.requestId, knownOperationId)
        } finally {
            bytes.fill(0)
            // A pending request is not cancelled. Provider may return BUSY and expire it later.
            transfer?.let { id -> runCatching {
                content("call", "--uri", URI, "--method", "discard", "--arg", id, cleanup = true)
            } }
        }
    }

    companion object {
        private const val URI = "content://com.kardinal.vpncontrol.control"
        private val OPAQUE = Regex("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

        internal fun selectDevice(output: String, requested: String?): String {
            val lines = output.lineSequence().map(String::trim).filter(String::isNotEmpty).toList()
            if (lines.firstOrNull() != "List of devices attached") fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            val devices = lines.drop(1).map {
                val fields = it.split(Regex("\\s+"), limit = 3)
                if (fields.size < 2 || fields[0].any(Char::isISOControl)) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                fields[0] to fields[1]
            }
            if (devices.map { it.first }.distinct().size != devices.size) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            val authorized = devices.filter { it.second == "device" }.map { it.first }
            return if (requested == null) authorized.singleOrNull() ?: fail(ControlCode.UNAVAILABLE)
                else authorized.singleOrNull { it == requested } ?: fail(ControlCode.UNAVAILABLE)
        }

        private fun bundle(text: String): Map<String, String> {
            val match = Regex("Result: Bundle\\[\\{([^{}\\r\\n]*)}]").matchEntire(text.trim())
                ?: fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            val pairs = match.groupValues[1].split(", ").map {
                val fields = it.split('=', limit = 2)
                if (fields.size != 2) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
                fields[0] to fields[1]
            }
            if (pairs.map { it.first }.distinct().size != pairs.size) fail(ControlCode.INCOMPATIBLE_PROTOCOL)
            return pairs.toMap()
        }

        private fun strictUtf8(bytes: ByteArray): String = try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        } catch (_: Exception) { fail(ControlCode.INCOMPATIBLE_PROTOCOL) }

        private fun fail(code: ControlCode): Nothing = throw AdbFailure(code)
    }

    private class AdbFailure(val code: ControlCode) : Exception(code.wireName)
}
