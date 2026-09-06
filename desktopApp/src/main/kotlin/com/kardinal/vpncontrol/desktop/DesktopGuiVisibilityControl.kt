package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.ControlProtocolCodec
import com.kardinal.vpncontrol.model.*
import java.nio.file.Path
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext

/** Owner presentation lane: it has no runtime or configuration mutation capability. */
internal class DesktopGuiVisibilityControl(
    private val ownerId: String,
    private val metadata: () -> DesktopControlMetadata,
    private val registration: () -> String?,
    private val directory: Path = DesktopWorkspacePaths.root(),
    private val launch: (Path, String) -> ControlCode = ::launchDesktopFrontend,
    private val request: (DesktopCliCommand, Path) -> DesktopCliResponse = DesktopActivationServer::requestCliCommand,
    private val pause: suspend () -> Unit = { delay(100) },
    private val attempts: Int = 150,
) {
    private val mutex = Mutex()
    private val completed = LinkedHashMap<String, Pair<ControlOperationId, ControlResult>>()

    suspend fun execute(input: ControlRequest): DesktopCliResponse {
        fun result(code: ControlCode): ControlResult {
            val current = metadata()
            return ControlResult(ownerId, input.requestId, code, current.configurationRevision,
                restartRequired = current.restartRequired, final = code !in uncertainVisibilityCodes)
        }
        fun response(value: ControlResult) = DesktopCliResponse(value.ok, ControlProtocolCodec.encodeResult(value), value.code.exitCode)
        if (input.controllerId != ownerId) return response(result(ControlCode.CONFLICT))
        if (input.command.operation !in operations || input.command.arguments.isNotEmpty() || input.ifRevision != null ||
            input.asynchronous || input.interactive) return response(result(ControlCode.INVALID_ARGUMENT))
        if (!mutex.tryLock()) return response(result(ControlCode.BUSY))
        try {
            completed[input.requestId]?.let { (operation, previous) ->
                return response(if (operation == input.command.operation) previous else result(ControlCode.CONFLICT))
            }
            var frontend = registration()
            var code = ControlCode.OK
            if (frontend == null) {
                if (input.command.operation == ControlOperationId.GUI_HIDE) code = ControlCode.NOT_FOUND
                else {
                    code = withContext(Dispatchers.IO) { launch(directory, ownerId) }
                    if (code == ControlCode.OK) {
                        for (ignored in 0 until attempts) {
                            frontend = registration()
                            if (frontend != null) break
                            pause()
                        }
                        if (frontend == null) code = ControlCode.TIMEOUT
                    }
                }
            }
            if (code == ControlCode.OK) {
                val pinned = requireNotNull(frontend)
                val command = DesktopCliCommand.ControlSubmit(input.copy(controllerId = pinned,
                    command = ControlCommand(input.command.operation, mapOf("owner" to ControlValue.Text(ownerId)))), 3)
                val answer = withContext(Dispatchers.IO) { request(command, DesktopFrontendInstance.endpoint(directory)) }
                val decoded = runCatching { ControlProtocolCodec.decodeResult(answer.message) }.getOrNull()
                code = when {
                    registration() != pinned -> ControlCode.CONFLICT
                    decoded == null -> ControlCode.entries.firstOrNull { it.wireName == answer.message && it.exitCode == answer.exitCode }
                        ?: ControlCode.INCOMPATIBLE_PROTOCOL
                    decoded.controllerId != pinned -> ControlCode.CONFLICT
                    decoded.requestId != input.requestId || decoded.final != (decoded.code !in uncertainVisibilityCodes) || decoded.operationId != null ||
                        decoded.configurationRevision != 0L || decoded.restartRequired || decoded.data.isNotEmpty() || decoded.warnings.isNotEmpty() ||
                        decoded.ok != answer.success || decoded.code.exitCode != answer.exitCode -> ControlCode.INCOMPATIBLE_PROTOCOL
                    else -> decoded.code
                }
            }
            val terminal = result(code)
            // A lost response retries the same admitted action, never a replacement frontend.
            completed[input.requestId] = input.command.operation to terminal
            if (completed.size > 256) completed.remove(completed.keys.first())
            return response(terminal)
        } finally { mutex.unlock() }
    }

    companion object { val operations = setOf(ControlOperationId.GUI_SHOW, ControlOperationId.GUI_HIDE) }
}

internal const val DESKTOP_FRONTEND_OWNER_ARGUMENT = "--frontend-owner"
internal val uncertainVisibilityCodes = setOf(ControlCode.TIMEOUT, ControlCode.OUTCOME_UNKNOWN)

internal fun desktopFrontendLaunchCommand(ownerId: String, directory: Path,
    currentCommand: String? = ProcessHandle.current().info().command().orElse(null),
    packagedLauncher: String? = System.getProperty("jpackage.app-path"),
    classPath: String = System.getProperty("java.class.path"),
): List<String>? {
    val ownerCommand = DesktopHeadlessController.launchCommand(currentCommand, packagedLauncher, classPath) ?: return null
    // The builder's final argument selects owner mode. Only the known JVM-option slot
    // is removed; a literal classpath equal to either token must remain untouched.
    val launcher = ownerCommand.dropLast(1)
    val graphicalLauncher = if (ownerCommand.size == 6 && ownerCommand[1] == "-Djava.awt.headless=true")
        listOf(launcher.first()) + launcher.drop(2) else launcher
    return graphicalLauncher + listOf(DESKTOP_FRONTEND_OWNER_ARGUMENT, ownerId, "--state-dir", directory.toString())
}

private fun launchDesktopFrontend(directory: Path, ownerId: String): ControlCode {
    // Owner JVM is deliberately headless; inspect the inherited display environment, not its AWT flag.
    if (!isDesktopDisplayAvailable(isHeadless = false)) return ControlCode.UNAVAILABLE
    val command = desktopFrontendLaunchCommand(ownerId, directory) ?: return ControlCode.UNAVAILABLE
    return runCatching {
        ProcessBuilder(command).redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        ControlCode.OK
    }.getOrDefault(ControlCode.UNAVAILABLE)
}
