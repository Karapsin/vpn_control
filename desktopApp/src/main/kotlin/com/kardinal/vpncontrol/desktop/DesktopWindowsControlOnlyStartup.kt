package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlCliParser
import com.kardinal.vpncontrol.control.ControlCliParseResult
import com.kardinal.vpncontrol.control.ControlClientOptions
import com.kardinal.vpncontrol.model.ControlOperationId.*

/** Pure pre-admission classification. This role never starts an owner, runtime or GUI. */
internal object DesktopWindowsControlOnlyStartup {
    private fun strict(args: List<String>): ControlCliParseResult.Invocation? {
        val parsed = ControlCliParser.parse(args) as? ControlCliParseResult.Invocation ?: return null
        if (parsed.flags.isNotEmpty() || parsed.options.isNotEmpty() ||
            parsed.client.copy(json = false, controllerId = null, timeoutSeconds = 600) != ControlClientOptions()) return null
        if (parsed.positional.any { it.isBlank() || it.length > 256 || it.any { char -> char.code < 32 } }) return null
        return parsed
    }
    fun allowsPending(args: List<String>): Boolean = strict(args)?.operation in setOf(
        STATUS, UPDATES_STATUS, OPERATIONS_LIST, OPERATIONS_STATUS, OPERATIONS_CANCEL)
    fun isBlockingWait(args: List<String>): Boolean = strict(args)?.operation == OPERATIONS_WAIT

    fun execute(args: Array<String>, printLine: (String) -> Unit = ::desktopCliPrintLine,
        request: (DesktopCliCommand) -> DesktopCliResponse = DesktopActivationServer::requestCliCommand): Int {
        require(allowsPending(args.toList()))
        return DesktopCli.handleArgs(args, printLine = printLine, requestCommand = request,
            startHeadlessController = { DesktopCliResponse.failure("UNAVAILABLE", 2) }) ?: 2
    }
}
