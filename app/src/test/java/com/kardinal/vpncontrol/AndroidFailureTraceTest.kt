package com.kardinal.vpncontrol

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidFailureTraceTest {
    @Test fun formatterExcludesMessagesAndBoundsFramesAndCauses() {
        val secret = "credential://do-not-log"
        val leaf = IllegalArgumentException(secret).apply {
            stackTrace = Array(20) { StackTraceElement("fixture.Frame$it", "call$it", "private.kt", it) }
        }
        val middle = IllegalStateException(secret, leaf)
        val root = RuntimeException(secret, middle)
        val trace = AndroidFailureTrace.format("find-best.reconcile", root)

        assertFalse(trace.contains(secret))
        assertTrue(trace.contains("stage=find-best.reconcile"))
        assertTrue(trace.contains(RuntimeException::class.java.name))
        assertTrue(trace.contains(IllegalStateException::class.java.name))
        assertTrue(trace.contains(IllegalArgumentException::class.java.name))
        assertFalse(trace.contains("private.kt"))
        assertTrue(trace.count { it == '@' } <= 36)
    }

    @Test fun formatterBoundsLongCauseChainsAndProtectsAgainstCauseCycles() {
        var failure: Throwable = IllegalArgumentException("secret-0")
        repeat(5) { index -> failure = IllegalStateException("secret-$index", failure) }
        val limited = AndroidFailureTrace.format("fixture", failure)
        assertTrue(limited.contains("cause_limit"))
        assertTrue(limited.countOccurrences("cause[") == 4)

        val first = IllegalStateException("secret-cycle-first")
        val second = IllegalArgumentException("secret-cycle-second")
        first.initCause(second)
        second.initCause(first)
        val cycle = AndroidFailureTrace.format("fixture", first)
        assertTrue(cycle.contains("cause_cycle"))
        assertFalse(cycle.contains("secret-cycle"))
    }

    private fun String.countOccurrences(value: String): Int = windowed(value.length, 1).count { it == value }
}
