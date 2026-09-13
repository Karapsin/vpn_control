package com.kardinal.vpncontrol.desktop;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.List;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;

/**
 * Test-only native-evidence gate for JUnit 4 selections.
 *
 * <p>JUnit treats an assumption violation as a successful run. Native evidence must instead
 * require at least one executed test and reject every skipped, ignored, or failed selection.</p>
 */
public final class NativeExecutionJUnitGate {
    private NativeExecutionJUnitGate() {
    }

    public static Execution run(String className) throws ClassNotFoundException {
        return run(Class.forName(className));
    }

    public static Execution run(Class<?> testClass) {
        AtomicInteger assumptionFailures = new AtomicInteger();
        ConcurrentLinkedQueue<Failure> diagnostics = new ConcurrentLinkedQueue<>();
        JUnitCore core = new JUnitCore();
        core.addListener(new RunListener() {
            @Override
            public void testAssumptionFailure(Failure failure) {
                assumptionFailures.incrementAndGet();
                diagnostics.add(failure);
            }

            @Override
            public void testFailure(Failure failure) {
                diagnostics.add(failure);
            }
        });
        Result result = core.run(testClass);
        return new Execution(
            result.getRunCount(),
            result.getIgnoreCount(),
            result.getFailureCount(),
            assumptionFailures.get(),
            List.copyOf(diagnostics)
        );
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1 || args[0].trim().isEmpty()) {
            System.err.println("Usage: NativeExecutionJUnitGate <fully.qualified.TestClass>");
            System.exit(2);
            return;
        }
        Execution execution = run(args[0]);
        System.out.println(execution.json());
        if (execution.accepted()) {
            System.out.println("NATIVE_JUNIT_EXECUTION_GATE_OK");
            return;
        }
        System.err.println("NATIVE_JUNIT_EXECUTION_GATE_REJECTED");
        for (Failure failure : execution.diagnostics) {
            System.err.print(failure.getTrace());
        }
        System.exit(1);
    }

    public static final class Execution {
        private final int runCount;
        private final int ignoredCount;
        private final int failureCount;
        private final int assumptionFailureCount;
        private final List<Failure> diagnostics;

        private Execution(int runCount, int ignoredCount, int failureCount, int assumptionFailureCount,
                          List<Failure> diagnostics) {
            this.runCount = runCount;
            this.ignoredCount = ignoredCount;
            this.failureCount = failureCount;
            this.assumptionFailureCount = assumptionFailureCount;
            this.diagnostics = diagnostics;
        }

        public int runCount() {
            return runCount;
        }

        public int ignoredCount() {
            return ignoredCount;
        }

        public int failureCount() {
            return failureCount;
        }

        public int assumptionFailureCount() {
            return assumptionFailureCount;
        }

        public boolean accepted() {
            return runCount > 0 && ignoredCount == 0 && failureCount == 0 && assumptionFailureCount == 0;
        }

        public String json() {
            return "{\"runCount\":" + runCount
                + ",\"ignoredCount\":" + ignoredCount
                + ",\"failureCount\":" + failureCount
                + ",\"assumptionFailureCount\":" + assumptionFailureCount
                + ",\"accepted\":" + accepted() + "}";
        }
    }
}
