package com.kardinal.vpncontrol.control

import com.kardinal.vpncontrol.model.ControlCode

sealed interface ControlLocationResolution<out T> {
    data class Found<T>(val location: T) : ControlLocationResolution<T>
    data class Rejected(val code: ControlCode) : ControlLocationResolution<Nothing>
}

object ControlLocationSelection {
    /** Caller supplies the GUI's visible ordering, never a storage record's numeric ID. */
    fun <T> resolve(target: String, visible: List<T>, name: (T) -> String): ControlLocationResolution<T> {
        val matches = visible.filter { name(it) == target }
        if (matches.size > 1) return ControlLocationResolution.Rejected(ControlCode.AMBIGUOUS_LOCATION)
        matches.singleOrNull()?.let { return ControlLocationResolution.Found(it) }
        // Numeric names win above. A fallback index is strictly a positive decimal integer.
        val index = target.takeIf { it.isNotEmpty() && it.all { char -> char in '0'..'9' } }
            ?.toIntOrNull()?.takeIf { it > 0 }
        val location = index?.let { visible.getOrNull(it - 1) }
        return location?.let { ControlLocationResolution.Found(it) }
            ?: ControlLocationResolution.Rejected(ControlCode.NOT_FOUND)
    }
}
