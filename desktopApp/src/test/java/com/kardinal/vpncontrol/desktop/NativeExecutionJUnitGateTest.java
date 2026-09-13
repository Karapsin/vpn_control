package com.kardinal.vpncontrol.desktop;

import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** Keeps native evidence from accepting JUnit's successful-but-skipped result. */
public final class NativeExecutionJUnitGateTest {
    @Test
    public void assumptionSkipIsRejectedEvenThoughJUnitReportsSuccess() {
        Result junitResult = new JUnitCore().run(AssumptionFixture.class);

        assertTrue("JUnit itself reports an assumption skip as successful", junitResult.wasSuccessful());
        NativeExecutionJUnitGate.Execution execution = NativeExecutionJUnitGate.run(AssumptionFixture.class);

        assertFalse(execution.accepted());
        assertEquals(1, execution.runCount());
        assertEquals(0, execution.ignoredCount());
        assertEquals(0, execution.failureCount());
        assertEquals(1, execution.assumptionFailureCount());
    }

    @Test
    public void executedFixtureIsAccepted() {
        NativeExecutionJUnitGate.Execution execution = NativeExecutionJUnitGate.run(ExecutedFixture.class);

        assertTrue(execution.accepted());
        assertEquals(1, execution.runCount());
        assertEquals(0, execution.ignoredCount());
        assertEquals(0, execution.failureCount());
        assertEquals(0, execution.assumptionFailureCount());
    }

    @Test
    public void ignoredFixtureIsRejected() {
        NativeExecutionJUnitGate.Execution execution = NativeExecutionJUnitGate.run(IgnoredFixture.class);

        assertFalse(execution.accepted());
        assertEquals(0, execution.runCount());
        assertEquals(1, execution.ignoredCount());
        assertEquals(0, execution.failureCount());
        assertEquals(0, execution.assumptionFailureCount());
    }

    /** Explicitly selected by the gate; its nested name prevents normal test discovery. */
    public static final class AssumptionFixture {
        @Test
        public void nativePrerequisiteIsAbsent() {
            Assume.assumeTrue("fixture deliberately has no native prerequisite", false);
        }
    }

    /** Explicitly selected by the gate; its nested name prevents normal test discovery. */
    public static final class ExecutedFixture {
        @Test
        public void nativeCheckExecuted() {
            assertTrue(true);
        }
    }

    @Ignore("Fixture verifies that ignored JUnit selections cannot certify native evidence.")
    public static final class IgnoredFixture {
        @Test
        public void nativeCheckIsIgnored() {
            assertTrue(true);
        }
    }
}
