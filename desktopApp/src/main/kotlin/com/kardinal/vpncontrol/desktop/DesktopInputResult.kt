package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.ControlCode
import com.kardinal.vpncontrol.model.ControlCommand
import com.kardinal.vpncontrol.model.ControlOperationId
import com.kardinal.vpncontrol.model.ControlValue

internal fun desktopInputFailureCode(failure: Throwable): ControlCode =
    if (failure is OutOfMemoryError) ControlCode.UNAVAILABLE else ControlCode.INVALID_ARGUMENT

private fun <T> desktopTextInput(
    content: Result<String?>,
    onSuccess: (String) -> T,
    onFailure: (ControlCode) -> Unit,
): T? = content.fold(
    onSuccess = { text -> text?.let(onSuccess) },
    onFailure = { onFailure(desktopInputFailureCode(it)); null },
)

internal fun desktopImportContent(
    operation: ControlOperationId,
    content: Result<String?>,
    guardedAction: (ControlCommand) -> Unit,
    onFailure: (ControlCode) -> Unit,
) {
    desktopTextInput(content, onSuccess = { text ->
        guardedAction(ControlCommand(operation, mapOf("input" to ControlValue.Text(text))))
    }, onFailure = onFailure)
}

internal fun desktopSshKeyInput(
    content: Result<String?>,
    controllerId: String?,
    revision: Long,
    onFailure: (ControlCode) -> Unit,
): DesktopSshKeyImportAction? = desktopTextInput(content,
    onSuccess = { DesktopSshKeyImportAction(controllerId, revision, it) },
    onFailure = onFailure,
)
