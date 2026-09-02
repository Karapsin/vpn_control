package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.model.AppMode

internal suspend fun DesktopAppService.executeCliCommand(command: DesktopCliCommand): DesktopCliResponse {
    if (state.isBusy) {
        return DesktopCliResponse.failure("VPN Control is busy.")
    }
    return when (command) {
        DesktopCliCommand.On -> cliTurnOn()
        DesktopCliCommand.Off -> cliTurnOff()
        DesktopCliCommand.Status -> cliStatus()
        DesktopCliCommand.FindBest -> cliFindBest()
        is DesktopCliCommand.Select -> cliSelect(command.target)
    }
}

private fun DesktopAppService.cliStatus(): DesktopCliResponse {
    val mode = state.appMode.cliLabel()
    val stateLabel = if (state.isVpnRunning) "on" else "off"
    val selected = selectedDesktopLocation()?.name?.takeIf(String::isNotBlank)
    val suffix = selected?.let { "; selected: $it" }.orEmpty()
    return DesktopCliResponse.success("$mode is $stateLabel$suffix")
}

private suspend fun DesktopAppService.cliTurnOn(): DesktopCliResponse {
    if (state.isVpnRunning) {
        return DesktopCliResponse.success("${state.appMode.cliLabel()} is already on.")
    }
    val selectedLocation = selectedDesktopLocation()
        ?: return DesktopCliResponse.failure("Select a location first.")
    val result = startDesktopProxy(selectedLocation)
    return if (result.isSuccess) {
        DesktopCliResponse.success("${state.appMode.cliLabel()} started: ${selectedLocation.name}")
    } else {
        DesktopCliResponse.failure(result.exceptionOrNull()?.message ?: "Failed to start ${state.appMode.cliLabel()}.")
    }
}

private suspend fun DesktopAppService.cliTurnOff(): DesktopCliResponse {
    if (!state.isVpnRunning && !shouldResumeConnectionOnLaunch()) {
        return DesktopCliResponse.success("${state.appMode.cliLabel()} is already off.")
    }
    val mode = state.appMode
    val result = stopDesktopProxy()
    return if (result.isSuccess) {
        DesktopCliResponse.success("${mode.cliLabel()} stopped.")
    } else {
        DesktopCliResponse.failure(result.exceptionOrNull()?.message ?: "Failed to stop ${mode.cliLabel()}.")
    }
}

private suspend fun DesktopAppService.cliFindBest(): DesktopCliResponse {
    val result = findBestLocation()
    return if (result.isSuccess) {
        val selectedLocation = selectedDesktopLocation()
        val target = selectedLocation?.name?.takeIf(String::isNotBlank)
        DesktopCliResponse.success(
            if (target == null) {
                "Best location selected."
            } else {
                "Best location selected: $target"
            },
        )
    } else {
        DesktopCliResponse.failure(result.exceptionOrNull()?.message ?: "Failed to find the best location.")
    }
}

private fun DesktopAppService.cliSelect(target: String): DesktopCliResponse {
    val result = applyCliLocationSelection(target)
    return result.fold(
        onSuccess = { location ->
            DesktopCliResponse.success("Selected location: ${location.name}")
        },
        onFailure = { error ->
            DesktopCliResponse.failure(error.message ?: "Failed to select location.")
        },
    )
}

private fun AppMode.cliLabel(): String {
    return when (this) {
        AppMode.VPN -> "VPN"
        AppMode.PROXY_ONLY -> "Proxy"
    }
}
