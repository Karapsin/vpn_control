import java.nio.file.Files;
import java.nio.file.Path;

/** Inert test-launch preflight. Compile into the frozen test bundle, never the application. */
public final class NativeJvmPreflight {
    public static void main(String[] args) throws Exception {
        if (args.length < 2 || Runtime.version().feature() < 17) {
            throw new IllegalArgumentException("Java 17+ and explicit dependency paths are required");
        }
        var self = ProcessHandle.current();
        var first = self.info();
        var second = ProcessHandle.of(self.pid()).orElseThrow().info();
        if (!first.user().orElseThrow().equals(second.user().orElseThrow()) ||
                !first.startInstant().orElseThrow().equals(second.startInstant().orElseThrow())) {
            throw new IllegalStateException("Native JVM user or generation is unavailable or inconsistent");
        }
        var image = Path.of(first.command().orElseThrow()).toRealPath();
        if (!Files.isSameFile(image, Path.of(args[0]).toRealPath())) {
            throw new IllegalStateException("Observed JVM image differs from the selected interpreter");
        }
        for (int i = 1; i < args.length; i++) {
            var dependency = Path.of(args[i]).toRealPath();
            if (Files.isDirectory(dependency)) {
                try (var entries = Files.newDirectoryStream(dependency)) {
                    entries.iterator().hasNext();
                }
            } else {
                try (var input = Files.newInputStream(dependency)) {
                    input.read();
                }
            }
        }
        System.out.println("VPN_CONTROL_JVM_PREFLIGHT_OK");
    }
}
