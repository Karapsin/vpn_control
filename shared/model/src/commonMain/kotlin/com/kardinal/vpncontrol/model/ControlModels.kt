package com.kardinal.vpncontrol.model

/** Stable wire identifiers. Never derive these from Kotlin class or enum names. */
enum class ControlCode(val wireName: String, val exitCode: Int) {
    OK("OK", 0),
    ACCEPTED("ACCEPTED", 0),
    INVALID_ARGUMENT("INVALID_ARGUMENT", 1),
    NOT_FOUND("NOT_FOUND", 1),
    AMBIGUOUS_LOCATION("AMBIGUOUS_LOCATION", 1),
    READ_ONLY_SOURCE("READ_ONLY_SOURCE", 1),
    BUSY("BUSY", 1),
    CONFLICT("CONFLICT", 1),
    UNSUPPORTED("UNSUPPORTED", 1),
    INTERACTION_REQUIRED("INTERACTION_REQUIRED", 1),
    PERMISSION_DENIED("PERMISSION_DENIED", 1),
    PERSISTENCE_FAILED("PERSISTENCE_FAILED", 1),
    RUNTIME_FAILED("RUNTIME_FAILED", 1),
    CANCELLED("CANCELLED", 130),
    TIMEOUT("TIMEOUT", 2),
    OUTCOME_UNKNOWN("OUTCOME_UNKNOWN", 2),
    UNAVAILABLE("UNAVAILABLE", 2),
    INCOMPATIBLE_PROTOCOL("INCOMPATIBLE_PROTOCOL", 2),
}

/** Deliberate transport values; no dependency on serialization or platform APIs. */
sealed interface ControlValue {
    data object Null : ControlValue
    data class BooleanValue(val value: Boolean) : ControlValue
    data class IntegerValue(val value: Long) : ControlValue
    data class DecimalValue(val value: Double) : ControlValue {
        init { require(value.isFinite()) }
    }
    class Text(val value: String) : ControlValue {
        override fun equals(other: Any?): Boolean = other is Text && value == other.value
        override fun hashCode(): Int = value.hashCode()
        override fun toString(): String = "Text(<redacted>)"
    }
    data class ArrayValue(val values: List<ControlValue>) : ControlValue {
        override fun toString(): String = "ArrayValue(<redacted>)"
    }
    data class ObjectValue(val values: Map<String, ControlValue>) : ControlValue {
        override fun toString(): String = "ObjectValue(<redacted>)"
    }
}

/** Arguments contain content or opaque transfer IDs, never server-side filesystem paths. */
data class ControlCommand(
    val operation: ControlOperationId,
    val arguments: Map<String, ControlValue> = emptyMap(),
) {
    override fun toString(): String = "ControlCommand(operation=${operation.wireName}, arguments=<redacted>)"
}

data class ControlRequest(
    val requestId: String,
    val command: ControlCommand,
    val controllerId: String? = null,
    val ifRevision: Long? = null,
    val interactive: Boolean = false,
    val asynchronous: Boolean = false,
    val schemaVersion: Int = CONTROL_SCHEMA_VERSION,
) {
    init {
        require(requestId.isNotBlank())
        require(ifRevision == null || ifRevision >= 0)
        require(ifRevision == null || !controllerId.isNullOrBlank())
    }

    override fun toString(): String = "ControlRequest(<redacted>)"
}

/** Only sanitized messages/arguments belong here; explicit configuration data is opt-in. */
data class ControlResult(
    val controllerId: String?,
    val requestId: String,
    val code: ControlCode,
    val configurationRevision: Long,
    val message: String = "",
    val messageKey: String? = null,
    val messageArgs: List<String> = emptyList(),
    val final: Boolean = true,
    val operationId: String? = null,
    val restartRequired: Boolean = false,
    val data: Map<String, ControlValue> = emptyMap(),
    val warnings: List<String> = emptyList(),
    val schemaVersion: Int = CONTROL_SCHEMA_VERSION,
) {
    val ok: Boolean get() = code == ControlCode.OK || code == ControlCode.ACCEPTED
    val exitCode: Int get() = code.exitCode

    init {
        require(configurationRevision >= 0)
        require(code != ControlCode.ACCEPTED || (!final && !operationId.isNullOrBlank()))
    }

    override fun toString(): String = "ControlResult(code=${code.wireName}, final=$final, data=<redacted>)"
}

enum class ControlOperationPhase(val wireName: String, val terminal: Boolean) {
    QUEUED("queued", false),
    RUNNING("running", false),
    SUCCEEDED("succeeded", true),
    FAILED("failed", true),
    CANCELLING("cancelling", false),
    CANCELLED("cancelled", true),
    AWAITING_USER("awaiting-user", false),
}

data class ControlOperation(
    val id: String,
    val requestId: String,
    val operation: ControlOperationId,
    val phase: ControlOperationPhase,
    val cancellable: Boolean,
    val completedUnits: Long? = null,
    val totalUnits: Long? = null,
    val result: ControlResult? = null,
) {
    init {
        require(completedUnits == null || completedUnits >= 0)
        require(totalUnits == null || totalUnits >= 0)
        require(completedUnits == null || totalUnits == null || completedUnits <= totalUnits)
        require(!phase.terminal || (result != null && result.final && !cancellable))
        require(phase.terminal || result == null)
        require(phase != ControlOperationPhase.SUCCEEDED || result?.code == ControlCode.OK)
        require(phase != ControlOperationPhase.CANCELLED || result?.code == ControlCode.CANCELLED)
        require(phase != ControlOperationPhase.FAILED || result?.ok == false)
    }
}

enum class ControlPlatform { ANDROID, LINUX, WINDOWS, MACOS }

data class ControlCapability(
    val id: String,
    val supported: Boolean,
    val reasonCode: String? = null,
    val requiresInteraction: Boolean = false,
)

/** Identifiers only: summaries never carry profile links, runtime JSON, or credentials. */
data class ControlSnapshot(
    val controllerId: String,
    val configurationRevision: Long,
    val selectedLocationId: String?,
    val activeLocationId: String?,
    val configuredMode: AppMode,
    val activeMode: AppMode?,
    val runtimeId: String?,
    val runtimeStartedAt: Long?,
    val restartRequired: Boolean,
    val operations: List<ControlOperation> = emptyList(),
    val runtimeRunning: Boolean = activeMode != null,
)

const val CONTROL_SCHEMA_VERSION: Int = 1
