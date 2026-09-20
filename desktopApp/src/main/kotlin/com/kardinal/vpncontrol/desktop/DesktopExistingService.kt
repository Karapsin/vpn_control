package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlDocumentCodec
import com.kardinal.vpncontrol.model.*
import java.util.UUID

/** Adopt a query-created owner without replacing it or replaying against a later owner. */
internal object DesktopExistingService {
    fun adopt(printLine: (String) -> Unit): Int {
        val path = DesktopWorkspacePaths.root().resolve("activation.port")
        val endpoint = try { DesktopControlEndpoint.read(path) } catch (_: Exception) {
            printLine("UNAVAILABLE"); return 2
        }
        val command = DesktopCliCommand.ControlServe(UUID.randomUUID().toString(), endpoint.controllerId)
        val response = DesktopActivationServer.requestCliCommandAtEndpoint(command, endpoint, 10_000)
        val result = runCatching { ControlDocumentCodec.decodeResult(response.message) }.getOrNull()
        if (result == null || result.controllerId != endpoint.controllerId || result.requestId != command.requestId) {
            printLine("OUTCOME_UNKNOWN"); return 2
        }
        if (!result.ok) { printLine(result.code.wireName); return result.exitCode }
        printLine("VPN Control is already running.")
        return 0
    }
}

internal fun DesktopCliCommand.ControlServe.valid(): Boolean =
    listOf(requestId, controllerId).all { it.isNotBlank() && it.length <= 256 && it.none { character -> character.code < 32 } }
