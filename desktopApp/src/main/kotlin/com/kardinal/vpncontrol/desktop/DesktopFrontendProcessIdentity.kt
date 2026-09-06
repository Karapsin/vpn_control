package com.kardinal.vpncontrol.desktop

import com.kardinal.vpncontrol.control.*
import com.kardinal.vpncontrol.model.*
import java.nio.file.Path
import java.util.UUID

/** Process identity proved by the fixed authenticated frontend endpoint, never supplied by an install caller. */
internal data class DesktopFrontendProcessIdentity(val registrationId: String, val pid: Long, val startedAtEpochMillis: Long) {
    init { require(UUID.fromString(registrationId).toString() == registrationId); require(pid > 0 && startedAtEpochMillis > 0) }

    fun isStillSameProcess(): Boolean = ProcessHandle.of(pid).orElse(null)?.let {
        it.isAlive && it.info().startInstant().orElse(null)?.toEpochMilli() == startedAtEpochMillis
    } == true

    override fun toString() = "DesktopFrontendProcessIdentity(registrationId=$registrationId, process=<redacted>)"

    companion object {
        fun current(registrationId: String): DesktopFrontendProcessIdentity {
            val process = ProcessHandle.current()
            return DesktopFrontendProcessIdentity(registrationId, process.pid(),
                requireNotNull(process.info().startInstant().orElse(null)).toEpochMilli())
        }

        fun response(command: DesktopCliCommand.ControlFrontendIdentityRead, registrationId: String): DesktopCliResponse {
            if (!command.valid()) return DesktopCliResponse.failure("INVALID_ARGUMENT")
            if (command.frontendId != registrationId) return DesktopCliResponse.failure("CONFLICT")
            val identity = runCatching { current(registrationId) }.getOrElse { return DesktopCliResponse.failure("UNAVAILABLE", 2) }
            return DesktopCliResponse.success(ControlProtocolCodec.encodeResult(ControlResult(registrationId,
                command.requestId, ControlCode.OK, 0, data = mapOf(
                    "pid" to ControlValue.IntegerValue(identity.pid),
                    "startedAtEpochMillis" to ControlValue.IntegerValue(identity.startedAtEpochMillis)))))
        }

        fun read(directory: Path, expectedRegistrationId: String,
            request: (DesktopCliCommand, Path) -> DesktopCliResponse = DesktopActivationServer::requestCliCommand,
            verifyProcess: (DesktopFrontendProcessIdentity) -> Boolean = ::matchesCurrentApplication,
        ): Result<DesktopFrontendProcessIdentity> = runCatching {
            val command = DesktopCliCommand.ControlFrontendIdentityRead(UUID.randomUUID().toString(), expectedRegistrationId)
            require(command.valid())
            val response = request(command, DesktopFrontendInstance.endpoint(directory))
            if (!response.success) throw ControlProtocolException(ControlCode.entries.firstOrNull {
                it.wireName == response.message && it.exitCode == response.exitCode
            } ?: ControlCode.UNAVAILABLE)
            val result = try { ControlProtocolCodec.decodeResult(response.message) }
                catch (_: Exception) { throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL) }
            if (result.controllerId != expectedRegistrationId) throw ControlProtocolException(ControlCode.CONFLICT)
            if (result.requestId != command.requestId || result.code != ControlCode.OK || !result.final || result.operationId != null ||
                result.configurationRevision != 0L || result.restartRequired || response.exitCode != 0 ||
                result.data.keys != setOf("pid", "startedAtEpochMillis"))
                throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL)
            val identity = try { DesktopFrontendProcessIdentity(expectedRegistrationId,
                (result.data.getValue("pid") as ControlValue.IntegerValue).value,
                (result.data.getValue("startedAtEpochMillis") as ControlValue.IntegerValue).value) }
                catch (_: Exception) { throw ControlProtocolException(ControlCode.INCOMPATIBLE_PROTOCOL) }
            if (!verifyProcess(identity)) throw ControlProtocolException(ControlCode.CONFLICT)
            identity
        }

        private fun matchesCurrentApplication(identity: DesktopFrontendProcessIdentity): Boolean = runCatching {
            if (!identity.isStillSameProcess()) return@runCatching false
            val current = ProcessHandle.current().info()
            val target = ProcessHandle.of(identity.pid).orElseThrow().info()
            val user = current.user().orElseThrow()
            require(target.user().orElseThrow() == user)
            require(Path.of(target.command().orElseThrow()).toRealPath() == Path.of(current.command().orElseThrow()).toRealPath())
            true
        }.getOrDefault(false)
    }
}

internal fun DesktopCliCommand.ControlFrontendIdentityRead.valid(): Boolean = runCatching {
    UUID.fromString(requestId).toString() == requestId && UUID.fromString(frontendId).toString() == frontendId
}.getOrDefault(false)
