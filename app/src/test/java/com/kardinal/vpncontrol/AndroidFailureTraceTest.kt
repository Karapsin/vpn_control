package com.kardinal.vpncontrol

import android.system.ErrnoException
import org.junit.Assert.assertEquals
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

    @Test fun formatterEmitsBoundedErrnoWithoutFunctionOrExceptionMessages() {
        val secret = "https://user:password@example.test/path?private-key=secret"
        val errno = errnoFixture(111)
        val middle = java.net.ConnectException(secret).apply { initCause(errno) }
        val root = java.net.ConnectException(secret).apply { initCause(middle) }
        errno.initCause(root)

        val trace = AndroidFailureTrace.format("subscription-refresh.download", root)

        assertTrue(trace.contains("errno=111"))
        assertTrue(trace.contains("cause_cycle"))
        assertTrue(trace.countOccurrences("cause[") <= 4)
        listOf(secret, "user", "password", "example.test", "connect-private").forEach {
            assertFalse(trace.contains(it))
        }
    }

    @Test fun formatterOmitsOutOfRangeErrnoValues() {
        listOf(0, -1, 4096).forEach { value ->
            val trace = AndroidFailureTrace.format("fixture", errnoFixture(value))

            assertFalse("errno=$value must be omitted", trace.contains(" errno="))
        }
    }

    private fun errnoFixture(value: Int): ErrnoException = ErrnoException("connect-private", value).also { errno ->
        ErrnoException::class.java.getField("errno").apply { isAccessible = true }.setInt(errno, value)
        assertEquals(value, errno.errno)
    }

    private fun String.countOccurrences(value: String): Int = windowed(value.length, 1).count { it == value }
}
