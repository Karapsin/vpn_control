package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.*

/** Converts the parsed public command identically for every renderer and target. */
object ControlCliRequestBuilder {
    fun build(invocation: ControlCliParseResult.Invocation, requestId: String,
              readInput: (String) -> Result<String>, readQrImage: (String) -> Result<String>): Result<ControlRequest> = runCatching {
        require(invocation.flags.isEmpty())
        val names = ControlCliParser.schema(invocation.operation).positional
        val arguments = invocation.positional.mapIndexed { index, value -> names[index] to ControlValue.Text(value) }.toMap() +
            invocation.options.filterKeys { it !in setOf("--output", "--format") }.map { (option, value) ->
                val content = when (option) {
                    "--input" -> readInput(value).getOrThrow()
                    "--qr-image" -> readQrImage(value).getOrThrow()
                    else -> value
                }
                (if (option == "--qr-image") "input" else option.removePrefix("--")) to ControlValue.Text(content)
            }.toMap()
        if (invocation.operation in setOf(ControlOperationId.SETTINGS_SET, ControlOperationId.SETTINGS_APPLY))
            ControlSettingsLogic.parseRequestArguments(invocation.operation, arguments).getOrThrow()
        ControlRequest(requestId, ControlCommand(invocation.operation, arguments),
            interactive = invocation.client.interactive, asynchronous = invocation.client.asynchronous,
            controllerId = invocation.client.controllerId, ifRevision = invocation.client.ifRevision)
    }
}
